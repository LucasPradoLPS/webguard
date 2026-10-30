from dataclasses import asdict, dataclass, field
from typing import List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
PENALTY = {"critical": 30, "high": 20, "medium": 12, "low": 4, "info": 0}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    why: str  # the attack this control mitigates
    fix: str
    ref: str = ""
    evidence: str = ""


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)
    requests_made: int = 0
    duration: float = 0.0
    error: str = ""

    @property
    def score(self) -> int:
        return max(0, 100 - sum(PENALTY[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        for limit, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
            if s >= limit:
                return letter
        return "F"

    def counts(self) -> dict:
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        d["grade"] = self.grade
        d["counts"] = self.counts()
        return d
