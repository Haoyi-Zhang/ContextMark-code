"""Closed-form composition bounds and exact finite arithmetic checks."""
from __future__ import annotations

import itertools
import math
import time
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class PrimitiveRates:
    eps_prf: float = 1e-9
    eps_rm: float = 2e-5
    delta_stab: float = 1e-5
    eps_nt: float = 5e-6
    delta_sep: float = 4e-6
    eps_uf: float = 1e-5
    eps_col: float = 5e-5
    eps_sig: float = 1e-9
    eps_hash: float = 1e-12

    def as_dict(self) -> dict[str, float]:
        return asdict(self)


def _cap(value: float) -> float:
    return min(1.0, max(0.0, value))


def _validate_probability(value: float, name: str) -> None:
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be a finite probability in [0,1]")


def theorem_bound(game: str, q: int, n: int, rates: PrimitiveRates, *, coalition_groups: int | None = None) -> float:
    if q < 0 or n < 0:
        raise ValueError("q and n must be nonnegative")
    for name, value in rates.as_dict().items():
        _validate_probability(value, name)
    chain = n * (rates.eps_sig + rates.eps_hash)
    if game == "removal":
        raw = rates.eps_prf + q * (rates.eps_rm + rates.delta_stab)
    elif game == "nontransfer":
        raw = rates.eps_prf + chain + min(q * rates.eps_nt, q * rates.delta_sep)
    elif game == "unforgeability":
        raw = rates.eps_prf + chain + q * rates.eps_uf
    elif game == "collusion":
        groups = q if coalition_groups is None else coalition_groups
        if groups < 0:
            raise ValueError("coalition group count must be nonnegative")
        raw = rates.eps_prf + groups * rates.eps_col + groups * rates.delta_stab
    else:
        raise ValueError(f"unknown game: {game}")
    return _cap(raw)


def adaptive_ledger_certificate(eps_prf: float, predictable_hazards: Iterable[float]) -> float:
    _validate_probability(eps_prf, "eps_prf")
    total = eps_prf
    for index, hazard in enumerate(predictable_hazards):
        _validate_probability(hazard, f"hazard[{index}]")
        total += hazard
    return _cap(total)


def first_hit_probability(hazards: Iterable[float]) -> float:
    survival = 1.0
    hit = 0.0
    for index, hazard in enumerate(hazards):
        _validate_probability(hazard, f"hazard[{index}]")
        hit += survival * hazard
        survival *= 1.0 - hazard
    return hit


def fixed_schedule_product(hazards: Iterable[float]) -> float:
    survival = 1.0
    for index, hazard in enumerate(hazards):
        _validate_probability(hazard, f"hazard[{index}]")
        survival *= 1.0 - hazard
    return 1.0 - survival


def evidence_conditioned_bound(
    risk_certificate: float,
    *,
    calibration_errors: Iterable[float] = (),
    key_switch_loss: float = 0.0,
) -> float:
    """Cap a nonnegative certificate plus probability-valued error terms.

    A first-hit certificate is an expectation of a sum of upper hazards.  It is
    therefore allowed to exceed one even though the resulting adversarial
    advantage is a probability.  Reject only negative or non-finite
    certificates, validate the actual probability terms, and cap once at the
    end.
    """
    if not math.isfinite(risk_certificate) or risk_certificate < 0.0:
        raise ValueError("risk_certificate must be finite and nonnegative")
    _validate_probability(key_switch_loss, "key_switch_loss")
    total = risk_certificate + key_switch_loss
    for index, error in enumerate(calibration_errors):
        _validate_probability(error, f"calibration_errors[{index}]")
        total += error
    return _cap(total)


def conditional_kernel_shift(calibrated_upper: float, likelihood_ratio: float, slack: float) -> float:
    """Historywise deployment hazard bridge ``rho * u + eta``."""
    _validate_probability(calibrated_upper, "calibrated_upper")
    if not math.isfinite(likelihood_ratio) or likelihood_ratio < 0:
        raise ValueError("likelihood_ratio must be finite and nonnegative")
    _validate_probability(slack, "slack")
    return _cap(likelihood_ratio * calibrated_upper + slack)


def closed_form_union(probabilities: Iterable[float]) -> float:
    survival = 1.0
    for index, probability in enumerate(probabilities):
        _validate_probability(probability, f"probability[{index}]")
        survival *= 1.0 - probability
    return 1.0 - survival


def enumerate_union_probability(probabilities: list[float]) -> tuple[float, int, float]:
    for index, probability in enumerate(probabilities):
        _validate_probability(probability, f"probability[{index}]")
    started = time.perf_counter_ns()
    total = 0.0
    states = 0
    for state in itertools.product((0, 1), repeat=len(probabilities)):
        mass = 1.0
        for bit, probability in zip(state, probabilities):
            mass *= probability if bit else 1.0 - probability
        if any(state):
            total += mass
        states += 1
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return total, states, elapsed_ms


def independent_model(game: str, q: int, n: int, rates: PrimitiveRates) -> float:
    probabilities: list[float] = [rates.eps_prf]
    if game == "removal":
        probabilities.extend([rates.eps_rm, rates.delta_stab] * q)
    elif game == "nontransfer":
        probabilities.extend([rates.eps_sig, rates.eps_hash] * n)
        probabilities.extend([min(rates.eps_nt, rates.delta_sep)] * q)
    elif game == "unforgeability":
        probabilities.extend([rates.eps_sig, rates.eps_hash] * n)
        probabilities.extend([rates.eps_uf] * q)
    elif game == "collusion":
        probabilities.extend([rates.eps_col, rates.delta_stab] * q)
    else:
        raise ValueError(f"unknown game: {game}")
    return closed_form_union(probabilities)


def query_caps(alpha: float, tau: float, rates: PrimitiveRates) -> dict[str, int | None]:
    if alpha < 0:
        raise ValueError("alpha must be nonnegative")
    _validate_probability(tau, "tau")
    if tau <= rates.eps_prf:
        raise ValueError("target probability must exceed the key-switch loss")
    remaining = tau - rates.eps_prf
    chain_per_query = alpha * (rates.eps_sig + rates.eps_hash)
    denominators = {
        "removal": rates.eps_rm + rates.delta_stab,
        "nontransfer": chain_per_query + min(rates.eps_nt, rates.delta_sep),
        "unforgeability": chain_per_query + rates.eps_uf,
        "collusion": rates.eps_col + rates.delta_stab,
    }
    return {
        game: (None if denominator == 0 else max(0, math.floor(remaining / denominator)))
        for game, denominator in denominators.items()
    }


def survival_weighted_certificate(actual_hazards: Iterable[float], upper_hazards: Iterable[float]) -> float:
    """Finite deterministic-schedule certificate under actual survival masses.

    Unlike the first-hit probability, this sum uses an upper bound at each
    opportunity.  It need not be below the product-envelope probability bound.
    """
    actual, upper = list(actual_hazards), list(upper_hazards)
    if len(actual) != len(upper):
        raise ValueError("hazard vectors must have the same length")
    survival, certificate = 1.0, 0.0
    for i, (p, u) in enumerate(zip(actual, upper)):
        _validate_probability(p, f"actual[{i}]")
        _validate_probability(u, f"upper[{i}]")
        if p > u:
            raise ValueError("upper hazard does not dominate actual hazard")
        certificate += survival * u
        survival *= 1.0 - p
    return certificate
