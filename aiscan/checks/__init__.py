"""Register van checks. Elke check is een functie die een Result teruggeeft."""
from __future__ import annotations

REGISTRY: dict = {}


def check(*ids):
    def deco(fn):
        for i in ids:
            REGISTRY[i] = fn
        return fn
    return deco


def load_all():
    # importeren registreert de checks
    from . import supply, secrets, agent, hygiene, ci, code, bundle, live, github, database  # noqa: F401
    return REGISTRY
