"""Module 12 - Genetic Security Engine.

Uses genetic algorithms to evolve defense strategies. Generates a population
of strategy candidates, evaluates their fitness against simulated attacks,
and breeds new generations of improved strategies.
"""

from __future__ import annotations

import copy
import logging
import random
import uuid
from typing import Any

from backend.app.models.database import store
from backend.app.schemas.common import DefenseStrategy

logger = logging.getLogger(__name__)

RULE_TYPES = ["block_ip_range", "rate_limit", "geo_block", "port_restrict",
              "payload_inspect", "protocol_whitelist", "time_based_access",
              "behavioral_lock", "honeypot_redirect", "adaptive_auth"]

PARAMETERS = {
    "block_ip_range": {"cidr": ["10.0.0.0/8", "172.16.0.0/12", "0.0.0.0/0"]},
    "rate_limit": {"max_rps": [10, 50, 100, 500, 1000]},
    "geo_block": {"countries": [["CN", "RU", "KP"], ["CN"], ["RU"], []]},
    "port_restrict": {"allowed_ports": [[80, 443], [22, 80, 443], [80, 443, 8080]]},
    "payload_inspect": {"max_size": [1024, 4096, 16384, 65536]},
    "protocol_whitelist": {"protocols": [["TCP", "UDP"], ["TCP"], ["TCP", "UDP", "ICMP"]]},
    "time_based_access": {"allowed_hours": [[8, 18], [0, 24], [6, 22]]},
    "behavioral_lock": {"sensitivity": [0.3, 0.5, 0.7, 0.9]},
    "honeypot_redirect": {"threshold": [0.5, 0.7, 0.85, 0.95]},
    "adaptive_auth": {"mfa_threshold": [0.3, 0.5, 0.7]},
}


class GeneticSecurityEngine:
    """Evolves defense strategies using genetic algorithms."""

    def __init__(
        self,
        population_size: int = 100,
        mutation_rate: float = 0.1,
    ) -> None:
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._population: list[DefenseStrategy] = []
        self._generation = 0
        self._best_strategy: DefenseStrategy | None = None

    def initialize_population(self) -> list[dict[str, Any]]:
        """Generate initial population of random defense strategies."""
        self._population = []
        for _ in range(self._population_size):
            num_rules = random.randint(3, 8)
            rules = []
            for _ in range(num_rules):
                rule_type = random.choice(RULE_TYPES)
                params = PARAMETERS.get(rule_type, {})
                rule = {"type": rule_type}
                for param_name, options in params.items():
                    rule[param_name] = random.choice(options)
                rules.append(rule)

            strategy = DefenseStrategy(
                strategy_id=uuid.uuid4().hex[:12],
                name=f"strategy-gen{self._generation}-{len(self._population)}",
                rules=rules,
                generation=self._generation,
            )
            self._population.append(strategy)

        return [s.model_dump() for s in self._population[:10]]

    def evaluate_fitness(
        self, attack_scenarios: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluate each strategy against attack scenarios."""
        if attack_scenarios is None:
            attack_scenarios = self._default_scenarios()

        for strategy in self._population:
            score = self._simulate_strategy(strategy, attack_scenarios)
            strategy.fitness_score = score

        self._population.sort(key=lambda s: s.fitness_score, reverse=True)
        self._best_strategy = self._population[0]

        store.set_strategies([s.model_dump() for s in self._population[:20]])

        return [
            {"name": s.name, "fitness": s.fitness_score, "rules": len(s.rules)}
            for s in self._population[:10]
        ]

    def evolve(self) -> dict[str, Any]:
        """Run one generation of evolution: select, crossover, mutate."""
        if not self._population:
            self.initialize_population()
            self.evaluate_fitness()

        self._generation += 1
        new_population: list[DefenseStrategy] = []

        # Elitism: keep top 10%
        elite_count = max(2, self._population_size // 10)
        new_population.extend(copy.deepcopy(self._population[:elite_count]))

        # Fill rest via crossover + mutation
        while len(new_population) < self._population_size:
            parent_a = self._tournament_select()
            parent_b = self._tournament_select()
            child = self._crossover(parent_a, parent_b)
            child = self._mutate(child)
            new_population.append(child)

        self._population = new_population
        self.evaluate_fitness()

        return {
            "generation": self._generation,
            "best_fitness": self._best_strategy.fitness_score if self._best_strategy else 0,
            "avg_fitness": sum(s.fitness_score for s in self._population) / len(self._population),
            "population_size": len(self._population),
        }

    def _tournament_select(self, k: int = 5) -> DefenseStrategy:
        tournament = random.sample(self._population, min(k, len(self._population)))
        return max(tournament, key=lambda s: s.fitness_score)

    def _crossover(self, a: DefenseStrategy, b: DefenseStrategy) -> DefenseStrategy:
        split = random.randint(1, min(len(a.rules), len(b.rules)) - 1) if min(len(a.rules), len(b.rules)) > 1 else 1
        child_rules = a.rules[:split] + b.rules[split:]
        return DefenseStrategy(
            strategy_id=uuid.uuid4().hex[:12],
            name=f"strategy-gen{self._generation}-{random.randint(0, 9999)}",
            rules=child_rules,
            generation=self._generation,
        )

    def _mutate(self, strategy: DefenseStrategy) -> DefenseStrategy:
        for i, rule in enumerate(strategy.rules):
            if random.random() < self._mutation_rate:
                rule_type = random.choice(RULE_TYPES)
                params = PARAMETERS.get(rule_type, {})
                new_rule = {"type": rule_type}
                for param_name, options in params.items():
                    new_rule[param_name] = random.choice(options)
                strategy.rules[i] = new_rule
        return strategy

    def _simulate_strategy(
        self, strategy: DefenseStrategy, scenarios: list[dict],
    ) -> float:
        """Score a strategy against simulated attacks (0-1)."""
        total_score = 0.0
        for scenario in scenarios:
            blocked = 0
            false_positives = 0
            for rule in strategy.rules:
                if self._rule_matches(rule, scenario):
                    if scenario.get("malicious", True):
                        blocked += 1
                    else:
                        false_positives += 1

            detection_rate = min(blocked / max(scenario.get("attack_count", 1), 1), 1.0)
            fp_penalty = false_positives * 0.1
            total_score += max(detection_rate - fp_penalty, 0.0)

        return total_score / max(len(scenarios), 1)

    @staticmethod
    def _rule_matches(rule: dict, scenario: dict) -> bool:
        """Simplified rule matching for fitness evaluation."""
        rule_type = rule.get("type", "")
        attack_type = scenario.get("attack_type", "")

        effectiveness = {
            "block_ip_range": {"port_scan": 0.7, "brute_force": 0.5},
            "rate_limit": {"brute_force": 0.9, "c2_beacon": 0.3},
            "port_restrict": {"port_scan": 0.8, "lateral_movement": 0.6},
            "payload_inspect": {"data_exfiltration": 0.8, "c2_beacon": 0.5},
            "behavioral_lock": {"brute_force": 0.7, "lateral_movement": 0.8},
            "honeypot_redirect": {"port_scan": 0.6, "data_exfiltration": 0.7},
        }

        prob = effectiveness.get(rule_type, {}).get(attack_type, 0.1)
        return random.random() < prob

    @staticmethod
    def _default_scenarios() -> list[dict[str, Any]]:
        return [
            {"attack_type": "port_scan", "malicious": True, "attack_count": 5},
            {"attack_type": "brute_force", "malicious": True, "attack_count": 3},
            {"attack_type": "data_exfiltration", "malicious": True, "attack_count": 2},
            {"attack_type": "c2_beacon", "malicious": True, "attack_count": 4},
            {"attack_type": "lateral_movement", "malicious": True, "attack_count": 3},
            {"attack_type": "normal_traffic", "malicious": False, "attack_count": 10},
        ]

    def get_best_strategy(self) -> dict[str, Any] | None:
        return self._best_strategy.model_dump() if self._best_strategy else None


genetic_engine = GeneticSecurityEngine()
