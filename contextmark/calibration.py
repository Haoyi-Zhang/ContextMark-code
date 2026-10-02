"""Exact binomial limits and optional-stopping diagnostics."""
from __future__ import annotations

import math
from functools import lru_cache
from typing import Iterable

from scipy.stats import beta


def spending_alpha(t: int, alpha: float) -> float:
    if t < 1:
        raise ValueError("t must be positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must lie in (0,1)")
    return alpha / (t * (t + 1))


@lru_cache(maxsize=None)
def clopper_pearson_upper(successes: int, trials: int, alpha: float) -> float:
    if trials < 1 or successes < 0 or successes > trials:
        raise ValueError("invalid binomial count")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must lie in (0,1)")
    if successes == trials:
        return 1.0
    return float(beta.ppf(1.0 - alpha, successes + 1, trials - successes))


def _crossing_probability(true_probability: float, horizon: int, alpha_at) -> float:
    if not 0.0 <= true_probability <= 1.0 or horizon < 1:
        raise ValueError("invalid probability or horizon")
    alive = [1.0]
    crossed = 0.0
    for t in range(1, horizon + 1):
        next_mass = [0.0] * (t + 1)
        for successes, mass in enumerate(alive):
            next_mass[successes] += mass * (1.0 - true_probability)
            next_mass[successes + 1] += mass * true_probability
        for successes in range(t + 1):
            upper = clopper_pearson_upper(successes, t, alpha_at(t))
            if true_probability > upper + 1e-14:
                crossed += next_mass[successes]
                next_mass[successes] = 0.0
        alive = next_mass
    return crossed


def repeated_look_noncoverage(true_probability: float, *, horizon: int = 64, alpha: float = 0.05) -> tuple[float, float]:
    fixed = _crossing_probability(true_probability, horizon, lambda _t: alpha)
    anytime = _crossing_probability(true_probability, horizon, lambda t: spending_alpha(t, alpha))
    return fixed, anytime


def coverage_grid(probabilities: Iterable[float], *, horizon: int = 64, alpha: float = 0.05) -> list[dict[str, float | int]]:
    rows = []
    for probability in probabilities:
        fixed, anytime = repeated_look_noncoverage(probability, horizon=horizon, alpha=alpha)
        rows.append({
            "true_probability": probability,
            "horizon": horizon,
            "family_alpha": alpha,
            "fixed_level_noncoverage": fixed,
            "anytime_noncoverage": anytime,
        })
    return rows


def equal_marginal_history_counterexample() -> dict[str, float | bool]:
    """Two histories with equal unconditional marginals but different conditional risk."""
    # Calibration: history and challenge are independent fair bits; failure iff equal.
    calibration_failure = 0.5
    # Deployment: scheduler chooses challenge equal to the observed history.
    deployment_failure = 1.0
    # Both challenge marginals remain uniform.
    return {
        "calibration_failure_probability": calibration_failure,
        "deployment_failure_probability": deployment_failure,
        "calibration_challenge_one_probability": 0.5,
        "deployment_challenge_one_probability": 0.5,
        "equal_unconditional_challenge_marginal": True,
        "historywise_conditional_domination_required": True,
    }
