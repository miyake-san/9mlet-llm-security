"""Padrões de deployment seguro para LLMs (Doc 04, §6).

Implementa, de forma pura e offline, os três padrões de release gradual e
reversível consolidados pela engenharia moderna e adaptados a LLMs:

    * **Blue/Green** — dois ambientes idênticos; troca de tráfego atômica com
      rollback instantâneo (Doc 04, §6).
    * **Canary**     — libera a versão nova para uma fração pequena (ex.: 5%),
      coleta métricas de segurança/qualidade/custo, compara com SLOs e promove
      progressivamente — ou **reverte automaticamente** (Figura 3 do Doc 04).
    * **Shadow**     — roda a versão nova em paralelo, sem expô-la ao usuário,
      apenas para validar o comportamento com tráfego real.

No Azure, esses padrões combinam **Azure AI Foundry Deployments** com o **Azure
Front Door** (roteamento entre versões). Aqui o roteador é determinístico para
tornar a promoção/reversão reprodutível em laboratório.

Referência:
    Beyer et al. (2016). Site Reliability Engineering.
    Microsoft (2025). Azure AI Foundry / Azure Front Door. · Doc 04, §6.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from src.security.schemas import DeploymentStrategy, SLODefinition
from src.security.slo import rollback_decision


@dataclass
class RouteResult:
    """Para qual versão um request foi roteado e por quê."""

    version: str  # "blue" (estável) | "green" (candidata)
    strategy: str
    shadowed: bool = False  # em shadow, a green processa mas NÃO responde ao usuário


class TrafficRouter:
    """Roteia requests entre a versão estável (blue) e a candidata (green).

    O roteamento é **estável por chave** (hash do id do request): o mesmo usuário
    cai sempre no mesmo bucket, evitando experiência inconsistente durante o
    canary (Doc 04, §6). A fração canary é ajustada ao promover.
    """

    def __init__(
        self,
        strategy: DeploymentStrategy = DeploymentStrategy.CANARY,
        *,
        canary_percent: float = 5.0,
    ) -> None:
        self.strategy = strategy
        self.canary_percent = max(0.0, min(100.0, canary_percent))

    @staticmethod
    def _bucket(key: str) -> float:
        """Bucket determinístico em [0,100) a partir do hash do id do request."""
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return (int(digest[:8], 16) % 10_000) / 100.0

    def route(self, request_id: str) -> RouteResult:
        if self.strategy is DeploymentStrategy.BLUE_GREEN:
            # Antes da troca atômica, todo o tráfego fica no blue (0% no green).
            version = "green" if self.canary_percent >= 100.0 else "blue"
            return RouteResult(version=version, strategy=self.strategy.value)
        if self.strategy is DeploymentStrategy.SHADOW:
            # Usuário sempre vê o blue; o green processa em paralelo (shadow).
            return RouteResult(version="blue", strategy=self.strategy.value, shadowed=True)
        # Canary: a fração configurada vai para o green.
        version = "green" if self._bucket(request_id) < self.canary_percent else "blue"
        return RouteResult(version=version, strategy=self.strategy.value)

    def promote(self, to_percent: float) -> None:
        self.canary_percent = max(0.0, min(100.0, to_percent))


@dataclass
class CanaryStep:
    percent: float
    rollback: bool
    triggers: list[dict] = field(default_factory=list)
    promoted_to: float = 0.0


@dataclass
class CanaryOutcome:
    """Resultado da promoção canary: promovido a 100% ou revertido."""

    strategy: str
    steps: list[CanaryStep]
    final_percent: float
    rolled_back: bool

    @property
    def promoted(self) -> bool:
        return not self.rolled_back and self.final_percent >= 100.0

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "rolled_back": self.rolled_back,
            "promoted": self.promoted,
            "final_percent": self.final_percent,
            "steps": [
                {"percent": s.percent, "rollback": s.rollback, "triggers": s.triggers}
                for s in self.steps
            ],
        }


class CanaryController:
    """Promove progressivamente enquanto os SLOs críticos forem respeitados.

    A cada estágio (5% → 25% → 50% → 100%, por padrão) coleta os SLIs da versão
    candidata e aplica a fórmula de rollback (Doc 04, §6). Uma única violação
    crítica reverte imediatamente para a versão estável — sem espera humana.
    """

    DEFAULT_STAGES = (5.0, 25.0, 50.0, 100.0)

    def __init__(
        self, slo_defs: Sequence[SLODefinition], stages: Sequence[float] | None = None
    ) -> None:
        self.slo_defs = list(slo_defs)
        self.stages = tuple(stages) if stages else self.DEFAULT_STAGES

    def run(
        self,
        candidate_sli_by_stage: Mapping[float, Mapping[str, float]],
    ) -> CanaryOutcome:
        """Executa o canary; ``candidate_sli_by_stage`` mapeia % -> SLIs medidos."""
        router = TrafficRouter(DeploymentStrategy.CANARY, canary_percent=0.0)
        steps: list[CanaryStep] = []
        for percent in self.stages:
            router.promote(percent)
            slis = candidate_sli_by_stage.get(percent) or candidate_sli_by_stage.get(
                self.stages[0], {}
            )
            decision = rollback_decision(self.slo_defs, slis)
            if decision["rollback"]:
                steps.append(
                    CanaryStep(percent=percent, rollback=True, triggers=decision["triggers"])
                )
                router.promote(0.0)  # reversão imediata para o blue estável
                return CanaryOutcome(
                    strategy=DeploymentStrategy.CANARY.value,
                    steps=steps,
                    final_percent=0.0,
                    rolled_back=True,
                )
            steps.append(CanaryStep(percent=percent, rollback=False, promoted_to=percent))
        return CanaryOutcome(
            strategy=DeploymentStrategy.CANARY.value,
            steps=steps,
            final_percent=100.0,
            rolled_back=False,
        )
