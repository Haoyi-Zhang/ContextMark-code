"""Finite safeguard/attack correspondence model."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import product
from typing import Any

ATTACKS = (
    "delete_trace",
    "transplant_trace",
    "replay_under_other_tip",
    "adaptive_key_forgery",
    "two_copy_cancellation",
    "parent_free_splice",
)


@dataclass(frozen=True)
class Configuration:
    name: str
    one_copy_removal: bool = True
    host_binding: bool = True
    tip_binding: bool = True
    key_isolation: bool = True
    collusion_robustness: bool = True
    parent_links: bool = True


REQUIRED = {
    "delete_trace": "one_copy_removal",
    "transplant_trace": "host_binding",
    "replay_under_other_tip": "tip_binding",
    "adaptive_key_forgery": "key_isolation",
    "two_copy_cancellation": "collusion_robustness",
    "parent_free_splice": "parent_links",
}


def evaluate_attack(configuration: Configuration, attack: str) -> dict[str, Any]:
    if attack not in ATTACKS:
        raise ValueError(f"unknown attack: {attack}")
    safeguard = REQUIRED[attack]
    succeeds = not bool(getattr(configuration, safeguard))
    return {
        "configuration": configuration.name,
        "attack": attack,
        "required_safeguard": safeguard,
        "attack_succeeds": succeeds,
        "observation": "designated safeguard absent" if succeeds else "designated safeguard present",
    }


def omission_matrix() -> list[dict[str, Any]]:
    complete = Configuration("complete")
    configs = [complete]
    for attack in ATTACKS:
        field = REQUIRED[attack]
        values = asdict(complete)
        values["name"] = f"without_{field}"
        values[field] = False
        configs.append(Configuration(**values))
    return [evaluate_attack(config, attack) for config in configs for attack in ATTACKS]


def validate_omission_matrix(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = rows or omission_matrix()
    complete_wins = sum(row["attack_succeeds"] for row in rows if row["configuration"] == "complete")
    expected = {}
    for attack in ATTACKS:
        config = f"without_{REQUIRED[attack]}"
        wins = [row["attack"] for row in rows if row["configuration"] == config and row["attack_succeeds"]]
        expected[config] = wins
    valid = len(rows) == 42 and complete_wins == 0 and all(wins == [attack] for attack, wins in zip(ATTACKS, expected.values()))
    return {
        "schema": "factorized-truth-table-consistency-v1",
        "evidence_kind": "truth_table_consistency",
        "shared_rule": "REQUIRED",
        "independent_interaction_evidence": False,
        "row_count": len(rows),
        "complete_successful_attacks": complete_wins,
        "weakened_successes": expected,
        "valid": valid,
    }


def safeguard_lattice() -> list[dict[str, Any]]:
    fields = tuple(REQUIRED.values())
    rows = []
    for bits in product((False, True), repeat=len(fields)):
        values = dict(zip(fields, bits))
        name = "".join("1" if bit else "0" for bit in bits)
        config = Configuration(name=name, **values)
        for attack in ATTACKS:
            row = evaluate_attack(config, attack)
            row.update(values)
            rows.append(row)
    return rows


def validate_safeguard_lattice(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = rows or safeguard_lattice()
    fields = tuple(REQUIRED.values())
    violations = 0
    for attack in ATTACKS:
        attack_rows = [row for row in rows if row["attack"] == attack]
        by_bits = {tuple(bool(row[field]) for field in fields): bool(row["attack_succeeds"]) for row in attack_rows}
        for lower, lower_success in by_bits.items():
            for upper, upper_success in by_bits.items():
                if all((not l) or u for l, u in zip(lower, upper)) and not lower_success and upper_success:
                    violations += 1
    return {
        "schema": "factorized-truth-table-consistency-v1",
        "evidence_kind": "truth_table_consistency",
        "shared_rule": "REQUIRED",
        "independent_interaction_evidence": False,
        "row_count": len(rows),
        "configuration_count": 64,
        "attack_count": 6,
        "monotonicity_violations": violations,
        "valid": len(rows) == 384 and violations == 0,
    }


def architectural_baselines() -> list[Configuration]:
    return [
        Configuration("detached_records", False, False, False, True, False, True),
        Configuration("host_bound_owner_mark", False, True, False, False, False, True),
        Configuration("signed_owner_mark", True, True, False, False, False, True),
        Configuration("context_mark_without_parents", True, True, True, True, True, False),
        Configuration("complete"),
    ]


def baseline_matrix() -> list[dict[str, Any]]:
    return [evaluate_attack(config, attack) for config in architectural_baselines() for attack in ATTACKS]
