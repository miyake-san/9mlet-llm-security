"""Testes de detecção de drift (Aula 06 — Doc 04, §"Detecção estatística").

Um drift CONHECIDO deve ser detectado (KS, PSI, MMD, Wasserstein) e a leitura
integrada deve elevá-lo a incidente; uma janela SEM drift não pode gerar alarme
(controle de falso positivo). Tudo determinístico (seeds fixas).
"""

from __future__ import annotations

import numpy as np

from src.security.drift import (
    DriftDetector,
    detect_prompt_drift,
    ks_2samp,
    mmd2_rbf,
    psi,
    wasserstein_1d,
)
from src.security.schemas import DriftMethod, DriftSeverity, DriftType

_TYPICAL = [
    "Qual a taxa do CDB do Aurora?",
    "Como emito um boleto de pagamento?",
    "Qual o horário da agência central?",
    "Quais as tarifas do pacote de serviços?",
    "Como simulo um empréstimo pessoal?",
    "Qual o limite do cartão de crédito?",
    "Como abro uma conta no banco?",
    "Qual o rendimento da poupança?",
]
_NEW_TOPICS = [
    "vcs tao com aurora cripto? como compro bitcoin no app",
    "manda ai como funciona o pix parcelado novo",
    "blz e o cashback do cartao black quanto rende",
    "tem staking de cripto pelo banco de vcs",
    "quero portabilidade de salario rapidão pelo open finance",
    "o buy now pay later cobra juros ai",
    "aurora cripto tem taxa de custodia responde rapido",
    "consigo antecipar o fgts pelo app novo",
]


def test_ks_detecta_deslocamento_de_media():
    rng = np.random.default_rng(1)
    ref = rng.normal(0.0, 1.0, 300)
    now = rng.normal(1.5, 1.0, 300)
    d, p = ks_2samp(ref, now)
    assert d > 0.3 and p < 0.05


def test_ks_sem_drift_nao_alarma():
    rng = np.random.default_rng(2)
    pool = rng.normal(0.0, 1.0, 600)
    _, p = ks_2samp(pool[:300], pool[300:])
    assert p >= 0.05


def test_psi_severo_em_shift_grande():
    rng = np.random.default_rng(3)
    ref = rng.normal(0.0, 1.0, 500)
    now = rng.normal(2.0, 1.0, 500)
    assert psi(ref, now, bins=10) >= 0.25


def test_wasserstein_cresce_com_o_shift():
    rng = np.random.default_rng(4)
    ref = rng.normal(0.0, 1.0, 400)
    near = rng.normal(0.1, 1.0, 400)
    far = rng.normal(3.0, 1.0, 400)
    assert wasserstein_1d(ref, far) > wasserstein_1d(ref, near)


def test_mmd_zero_para_conjuntos_identicos():
    x = np.vstack([np.ones(4), np.zeros(4)])
    assert abs(mmd2_rbf(x, x.copy())) < 1e-9


def test_prompt_drift_detecta_novos_topicos():
    result = detect_prompt_drift(_TYPICAL, _NEW_TOPICS)
    assert result.method is DriftMethod.MMD
    assert result.drift_type is DriftType.PROMPT
    assert result.drifted is True


def test_prompt_drift_sem_mudanca_de_vocabulario():
    # Mesmo multiset embaralhado => MMD² = 0, p = 1.0 (sem alarme).
    shuffled = list(reversed(_TYPICAL))
    result = detect_prompt_drift(_TYPICAL, shuffled)
    assert result.drifted is False
    assert result.severity is DriftSeverity.NONE


def test_detector_eleva_a_incidente_com_multiplos_sinais():
    rng = np.random.default_rng(5)
    detector = DriftDetector()
    results = [
        detector.prompt_drift(_TYPICAL, _NEW_TOPICS),
        detector.response_drift(
            rng.normal(220, 40, 200), rng.normal(320, 90, 200), method=DriftMethod.KS
        ),
        detector.response_drift(rng.normal(0.9, 0.05, 200), rng.normal(0.78, 0.12, 200)),
        detector.credit_stability(rng.normal(800, 150, 200), rng.normal(1300, 400, 200)),
    ]
    assessment = detector.assess(results)
    assert assessment["decision"] == "incident"
    assert assessment["converging_signals"] >= 2


def test_detector_estavel_sem_drift():
    rng = np.random.default_rng(6)
    detector = DriftDetector()
    pool_len = rng.normal(220, 40, 600)
    pool_g = rng.normal(0.9, 0.05, 600)
    results = [
        detector.prompt_drift(_TYPICAL, list(reversed(_TYPICAL))),
        detector.response_drift(pool_len[:300], pool_len[300:], method=DriftMethod.KS),
        detector.response_drift(pool_g[:300], pool_g[300:]),
    ]
    assert detector.assess(results)["decision"] == "stable"
