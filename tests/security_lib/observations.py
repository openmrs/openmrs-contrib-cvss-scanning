from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class RuntimeObservation:
    source_repo: str
    source_pr: int
    candidate_risk_id: str
    test_name: str
    owasp_category: str
    cvss_profile: str

    login_event_observed: bool = False
    logout_event_observed: bool = False
    user_identifier_observed: bool = False
    timestamp_observed: bool = False
    outcome_status_observed: bool = False

    http_status_codes: List[int] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def add_status_code(self, status_code: int) -> None:
        self.http_status_codes.append(status_code)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_repo": self.source_repo,
            "source_pr": self.source_pr,
            "candidate_risk_id": self.candidate_risk_id,
            "test_name": self.test_name,
            "owasp_category": self.owasp_category,
            "cvss_profile": self.cvss_profile,
            "login_event_observed": self.login_event_observed,
            "logout_event_observed": self.logout_event_observed,
            "user_identifier_observed": self.user_identifier_observed,
            "timestamp_observed": self.timestamp_observed,
            "outcome_status_observed": self.outcome_status_observed,
            "http_status_codes": self.http_status_codes,
            "notes": self.notes,
            "raw_evidence": self.raw_evidence,
        }