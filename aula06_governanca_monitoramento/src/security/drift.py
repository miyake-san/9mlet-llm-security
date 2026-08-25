"""Detecção estatística de drift em LLMs (Aula 06).

Implementa, em **NumPy puro** (offline, reprodutível, sem scipy/sklearn), os
quatro testes discutidos no Doc 04 (§"Detecção estatística de drift", Tabela 2):

* **KS** — Kolmogorov-Smirnov de duas amostras (métricas escalares).
* **PSI** — Population Stability Index (crédito; faixas).
* **MMD** — Maximum Mean Discrepancy com kernel RBF (embeddings de prompts;
  Snippet 1 do Doc 04) + teste de permutação para o p-valor empírico.
* **Wasserstein** — distância 1-D (deslocamentos graduais de resposta).

Distingue os quatro tipos de drift (Doc 04, Figura 2): data, concept, prompt e
response. A interpretação é **operacional**: um sinal isolado pede investigação;
múltiplos sinais convergentes abrem incidente (Doc 04, §"leitura integrada").

O grupo opcional ``stats`` (scipy/scikit-learn) permite cross-validar estes
resultados nos notebooks, mas o núcleo do repo NÃO depende deles.

Referência:
    Gretton et al. (2012). A Kernel Two-Sample Test (MMD).
    Gama et al. (2014). A Survey on Concept Drift Adaptation.
    Doc 04, §"O que é drift" e §"Detecção estatística de drift".
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence

import numpy as np

from src.security.schemas import DriftMethod, DriftResult, DriftSeverity, DriftType

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
_EMBED_DIM = 64

# Defaults usados quando nenhum config (thresholds.yaml -> "drift") é passado.
DRIFT_DEFAULTS: dict = {
    "ks": {"alpha": 0.05},
    "psi": {"bins": 10, "moderate": 0.10, "severe": 0.25},
    "mmd": {"gamma": 1.0, "threshold": 0.010, "permutations": 200},
    "wasserstein": {"threshold": 0.15},
    "min_converging_signals": 2,
}


# --------------------------------------------------------------------------- #
# Embeddings determinísticos (hashing trick) — para MMD sobre prompts          #
# --------------------------------------------------------------------------- #
def embed(text: str, dim: int = _EMBED_DIM) -> np.ndarray:
    """Embedding determinístico por *hashing trick* (offline, sem modelos).

    Cada token é projetado num índice via hash e o vetor é L2-normalizado. Serve
    para exercitar o MMD sobre *embeddings* (Doc 04, Snippet 1) de forma
    reprodutível — não é qualidade de recuperação de produção.
    """
    vec = np.zeros(dim, dtype=float)
    for token in _TOKEN_RE.findall(text.lower()):
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)  # noqa: S324 (não-cripto)
        vec[h % dim] += 1.0
    norm = float(np.linalg.norm(vec)) or 1.0
    return vec / norm


def embed_matrix(texts: Sequence[str], dim: int = _EMBED_DIM) -> np.ndarray:
    """Matriz (n, dim) de embeddings determinísticos."""
    if not texts:
        return np.zeros((0, dim), dtype=float)
    return np.vstack([embed(t, dim) for t in texts])


# --------------------------------------------------------------------------- #
# KS — Kolmogorov-Smirnov de duas amostras (Doc 04: D = sup|F_ref - F_now|)     #
# --------------------------------------------------------------------------- #
def _kolmogorov_q(lam: float) -> float:
    """Cauda da distribuição de Kolmogorov: Q(λ)=2 Σ (-1)^{k-1} e^{-2k²λ²}."""
    if lam <= 0:
        return 1.0
    total = 0.0
    for k in range(1, 101):
        total += (-1) ** (k - 1) * math.exp(-2.0 * k * k * lam * lam)
    return max(0.0, min(1.0, 2.0 * total))


def ks_2samp(ref: Sequence[float], now: Sequence[float]) -> tuple[float, float]:
    """Estatística D e p-valor assintótico do KS de duas amostras.

    Equivale ao ``scipy.stats.ks_2samp`` (modo assintótico) usado no Snippet 2 do
    Doc 04, mas implementado em NumPy puro.
    """
    a = np.sort(np.asarray(ref, dtype=float))
    b = np.sort(np.asarray(now, dtype=float))
    n, m = a.size, b.size
    if n == 0 or m == 0:
        return 0.0, 1.0
    grid = np.concatenate([a, b])
    cdf_a = np.searchsorted(a, grid, side="right") / n
    cdf_b = np.searchsorted(b, grid, side="right") / m
    d = float(np.max(np.abs(cdf_a - cdf_b)))
    en = math.sqrt(n * m / (n + m))
    p = _kolmogorov_q((en + 0.12 + 0.11 / en) * d)
    return d, p


# --------------------------------------------------------------------------- #
# PSI — Population Stability Index (Doc 04: Σ (Q_i - P_i) ln(Q_i/P_i))          #
# --------------------------------------------------------------------------- #
def psi(ref: Sequence[float], now: Sequence[float], bins: int = 10, eps: float = 1e-6) -> float:
    """PSI com faixas por quantis da referência (convenção de crédito)."""
    a = np.asarray(ref, dtype=float)
    b = np.asarray(now, dtype=float)
    if a.size == 0 or b.size == 0:
        return 0.0
    edges = np.quantile(a, np.linspace(0, 1, bins + 1))
    edges = np.unique(edges)  # remove faixas degeneradas (ties)
    if edges.size < 2:
        return 0.0
    edges[0], edges[-1] = -np.inf, np.inf  # captura as caudas
    p = np.histogram(a, bins=edges)[0] / a.size  # P_i (referência)
    q = np.histogram(b, bins=edges)[0] / b.size  # Q_i (atual)
    p = np.clip(p, eps, None)
    q = np.clip(q, eps, None)
    return float(np.sum((q - p) * np.log(q / p)))


# --------------------------------------------------------------------------- #
# MMD — Maximum Mean Discrepancy com kernel RBF (Doc 04, Snippet 1)            #
# --------------------------------------------------------------------------- #
def _rbf_kernel(x: np.ndarray, y: np.ndarray, gamma: float) -> np.ndarray:
    """Matriz de kernel RBF k(x,y)=exp(-gamma·||x-y||²)."""
    xx = np.sum(x * x, axis=1)[:, None]
    yy = np.sum(y * y, axis=1)[None, :]
    d2 = xx + yy - 2.0 * (x @ y.T)
    np.maximum(d2, 0.0, out=d2)
    return np.exp(-gamma * d2)


def mmd2_rbf(x_ref: np.ndarray, x_now: np.ndarray, gamma: float = 1.0) -> float:
    """MMD² empírico com kernel RBF (mesma fórmula do Snippet 1 do Doc 04)."""
    if x_ref.size == 0 or x_now.size == 0:
        return 0.0
    k_rr = _rbf_kernel(x_ref, x_ref, gamma).mean()
    k_nn = _rbf_kernel(x_now, x_now, gamma).mean()
    k_rn = _rbf_kernel(x_ref, x_now, gamma).mean()
    return float(k_rr + k_nn - 2.0 * k_rn)


def mmd_permutation_test(
    x_ref: np.ndarray,
    x_now: np.ndarray,
    gamma: float = 1.0,
    n_perm: int = 200,
    seed: int = 42,
) -> tuple[float, float]:
    """MMD² observado + p-valor por teste de permutação (Gretton et al., 2012)."""
    observed = mmd2_rbf(x_ref, x_now, gamma)
    n = x_ref.shape[0]
    pooled = np.vstack([x_ref, x_now])
    rng = np.random.default_rng(seed)
    count = 0
    for _ in range(n_perm):
        rng.shuffle(pooled)
        if mmd2_rbf(pooled[:n], pooled[n:], gamma) >= observed:
            count += 1
    p_value = (count + 1) / (n_perm + 1)
    return observed, p_value


# --------------------------------------------------------------------------- #
# Wasserstein 1-D (Doc 04: esforço mínimo para transformar uma dist. na outra) #
# --------------------------------------------------------------------------- #
def wasserstein_1d(ref: Sequence[float], now: Sequence[float], normalize: bool = True) -> float:
    """Distância de Wasserstein-1 em 1-D: W1 = ∫ |F_ref - F_now| dx."""
    a = np.sort(np.asarray(ref, dtype=float))
    b = np.sort(np.asarray(now, dtype=float))
    if a.size == 0 or b.size == 0:
        return 0.0
    grid = np.sort(np.concatenate([a, b]))
    deltas = np.diff(grid)
    cdf_a = np.searchsorted(a, grid[:-1], side="right") / a.size
    cdf_b = np.searchsorted(b, grid[:-1], side="right") / b.size
    w = float(np.sum(np.abs(cdf_a - cdf_b) * deltas))
    if normalize:
        span = float(grid[-1] - grid[0])
        return w / span if span > 0 else 0.0
    return w


# --------------------------------------------------------------------------- #
# Detectores que retornam DriftResult                                          #
# --------------------------------------------------------------------------- #
def detect_scalar_drift(
    ref: Sequence[float],
    now: Sequence[float],
    method: DriftMethod,
    drift_type: DriftType,
    cfg: dict | None = None,
) -> DriftResult:
    """Drift de uma métrica escalar via KS, PSI ou Wasserstein."""
    cfg = cfg or DRIFT_DEFAULTS
    n_ref, n_now = len(list(ref)), len(list(now))

    if method is DriftMethod.KS:
        alpha = float(cfg.get("ks", {}).get("alpha", 0.05))
        d, p = ks_2samp(ref, now)
        drifted = p < alpha
        severity = (
            DriftSeverity.NONE
            if not drifted
            else DriftSeverity.SEVERE
            if d >= 0.30
            else DriftSeverity.MODERATE
        )
        return DriftResult(
            method=method,
            drift_type=drift_type,
            statistic=d,
            threshold=alpha,
            drifted=drifted,
            severity=severity,
            p_value=p,
            n_ref=n_ref,
            n_now=n_now,
            detail=f"KS D={d:.3f}, p={p:.4f} (alpha={alpha})",
        )

    if method is DriftMethod.PSI:
        pcfg = cfg.get("psi", {})
        moderate = float(pcfg.get("moderate", 0.10))
        severe = float(pcfg.get("severe", 0.25))
        value = psi(ref, now, bins=int(pcfg.get("bins", 10)))
        severity = (
            DriftSeverity.SEVERE
            if value >= severe
            else DriftSeverity.MODERATE
            if value >= moderate
            else DriftSeverity.NONE
        )
        return DriftResult(
            method=method,
            drift_type=drift_type,
            statistic=value,
            threshold=moderate,
            drifted=value >= moderate,
            severity=severity,
            n_ref=n_ref,
            n_now=n_now,
            detail=f"PSI={value:.3f} (moderate>={moderate}, severe>={severe})",
        )

    # Wasserstein
    thr = float(cfg.get("wasserstein", {}).get("threshold", 0.15))
    value = wasserstein_1d(ref, now)
    severity = (
        DriftSeverity.SEVERE
        if value >= 2 * thr
        else DriftSeverity.MODERATE
        if value >= thr
        else DriftSeverity.NONE
    )
    return DriftResult(
        method=DriftMethod.WASSERSTEIN,
        drift_type=drift_type,
        statistic=value,
        threshold=thr,
        drifted=value >= thr,
        severity=severity,
        n_ref=n_ref,
        n_now=n_now,
        detail=f"Wasserstein(norm)={value:.3f} (threshold={thr})",
    )


def detect_prompt_drift(
    ref_texts: Sequence[str],
    now_texts: Sequence[str],
    cfg: dict | None = None,
) -> DriftResult:
    """Prompt drift via MMD sobre embeddings (Doc 04, Snippet 1)."""
    cfg = cfg or DRIFT_DEFAULTS
    mcfg = cfg.get("mmd", {})
    gamma = float(mcfg.get("gamma", 1.0))
    thr = float(mcfg.get("threshold", 0.010))
    n_perm = int(mcfg.get("permutations", 200))
    alpha = float(cfg.get("ks", {}).get("alpha", 0.05))

    x_ref = embed_matrix(ref_texts)
    x_now = embed_matrix(now_texts)
    mmd2, p = mmd_permutation_test(x_ref, x_now, gamma=gamma, n_perm=n_perm)
    drifted = (mmd2 >= thr) or (p < alpha)
    severity = (
        DriftSeverity.SEVERE
        if mmd2 >= 2 * thr
        else DriftSeverity.MODERATE
        if drifted
        else DriftSeverity.NONE
    )
    return DriftResult(
        method=DriftMethod.MMD,
        drift_type=DriftType.PROMPT,
        statistic=mmd2,
        threshold=thr,
        drifted=drifted,
        severity=severity,
        p_value=p,
        n_ref=len(list(ref_texts)),
        n_now=len(list(now_texts)),
        detail=f"MMD²={mmd2:.4f}, p={p:.4f} (threshold={thr}, gamma={gamma})",
    )


def assess(results: Sequence[DriftResult], cfg: dict | None = None) -> dict:
    """Leitura INTEGRADA dos sinais (Doc 04): observar vs abrir incidente.

    Um sinal isolado pede investigação; múltiplos sinais convergentes elevam o
    caso a incidente (limiar ``min_converging_signals``).
    """
    cfg = cfg or DRIFT_DEFAULTS
    min_signals = int(cfg.get("min_converging_signals", 2))
    converging = [r for r in results if r.drifted]
    severe = [r for r in results if r.severity is DriftSeverity.SEVERE]
    if len(converging) >= min_signals or severe:
        decision = "incident"
    elif converging:
        decision = "observe"
    else:
        decision = "stable"
    return {
        "decision": decision,
        "converging_signals": len(converging),
        "severe_signals": len(severe),
        "min_converging_signals": min_signals,
        "drifted_methods": [r.method.value for r in converging],
    }


class DriftDetector:
    """Fachada de detecção de drift parametrizada por thresholds (Doc 04)."""

    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or DRIFT_DEFAULTS

    def data_drift(
        self, ref: Sequence[float], now: Sequence[float], method: DriftMethod = DriftMethod.KS
    ) -> DriftResult:
        return detect_scalar_drift(ref, now, method, DriftType.DATA, self.cfg)

    def response_drift(
        self,
        ref: Sequence[float],
        now: Sequence[float],
        method: DriftMethod = DriftMethod.WASSERSTEIN,
    ) -> DriftResult:
        return detect_scalar_drift(ref, now, method, DriftType.RESPONSE, self.cfg)

    def credit_stability(self, ref: Sequence[float], now: Sequence[float]) -> DriftResult:
        """PSI para estabilidade populacional (crédito)."""
        return detect_scalar_drift(ref, now, DriftMethod.PSI, DriftType.DATA, self.cfg)

    def prompt_drift(self, ref_texts: Sequence[str], now_texts: Sequence[str]) -> DriftResult:
        return detect_prompt_drift(ref_texts, now_texts, self.cfg)

    def assess(self, results: Sequence[DriftResult]) -> dict:
        return assess(results, self.cfg)
