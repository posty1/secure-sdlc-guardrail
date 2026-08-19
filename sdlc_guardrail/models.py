from dataclasses import asdict, dataclass


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
