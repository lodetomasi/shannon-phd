"""CodeInject-Bench taxonomy.

A `Payload` is the smallest unit attackers can introduce in a target repository
to influence the AI pentester. Each payload is identified by:
  - vector: WHERE in the repo it lives (channel surface)
  - goal:   WHAT the attacker wants the pentester to do/not do
  - text:   the literal injection content
"""
from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Vector(str, Enum):
    CODE_COMMENT = "code-comment"
    I18N_STRING = "i18n-string"
    OPENAPI_DESCRIPTION = "openapi-description"
    PACKAGE_METADATA = "package-metadata"
    README = "readme"
    ERROR_MESSAGE_TEMPLATE = "error-message-template"


class Goal(str, Enum):
    SUPPRESS_FINDING = "suppress-finding"
    INJECT_FP = "inject-fp"
    REDIRECT_BROWSER = "redirect-browser"
    PROMPT_LEAK = "prompt-leak"


PAYLOAD_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


@dataclass(frozen=True)
class Payload:
    """One concrete adversarial payload."""
    payload_id: str
    vector: Vector
    goal: Goal
    text: str
    notes: str = ""

    def __post_init__(self) -> None:
        if not PAYLOAD_ID_RE.match(self.payload_id):
            raise ValueError(
                f"payload_id must be kebab-case lowercase, got: {self.payload_id!r}"
            )
        if not self.text.strip():
            raise ValueError("payload text must be non-empty")

    @property
    def klass(self) -> str:
        """The (vector, goal) pair = 'class' in the taxonomy. 24 classes total."""
        return f"{self.vector.value}::{self.goal.value}"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["vector"] = self.vector.value
        d["goal"] = self.goal.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Payload":
        return cls(
            payload_id=d["payload_id"],
            vector=Vector(d["vector"]),
            goal=Goal(d["goal"]),
            text=d["text"],
            notes=d.get("notes", ""),
        )


def all_classes() -> list[str]:
    """All 24 (vector × goal) classes in canonical order."""
    return [f"{v.value}::{g.value}" for v in Vector for g in Goal]


def load_library(path: Path) -> list[Payload]:
    """Load a payload library from JSON. Validates ids are unique."""
    with path.open(encoding="utf-8") as f:
        raw = json.load(f)
    payloads = [Payload.from_dict(item) for item in raw]
    seen: set[str] = set()
    for p in payloads:
        if p.payload_id in seen:
            raise ValueError(f"duplicate payload_id: {p.payload_id}")
        seen.add(p.payload_id)
    return payloads


def save_library(payloads: list[Payload], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([p.to_dict() for p in payloads], f, indent=2, sort_keys=True)
        f.write("\n")
