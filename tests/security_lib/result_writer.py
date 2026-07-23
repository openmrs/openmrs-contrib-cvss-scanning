import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from tests.security_lib.observations import RuntimeObservation


def severity_from_score(score: float) -> str:
    """
    Convert a CVSS-style numeric score into a severity label.

    Matches the style used by the existing CVSS tests:
    - 9.0 to 10.0: CRITICAL
    - 7.0 to 8.9: HIGH
    - 4.0 to 6.9: MEDIUM
    - 0.1 to 3.9: LOW
    - 0.0: NONE
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def write_security_result(
    observation: RuntimeObservation,
    score_result: Dict[str, Any],
    output_path: str,
) -> Dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    cvss_score = score_result.get("cvss_score")
    if cvss_score is None:
        cvss_score = score_result.get("base_score", 0.0)

    cvss_vector = score_result.get("cvss_vector")
    if cvss_vector is None:
        cvss_vector = score_result.get("vector")

    severity_rating = score_result.get("severity_rating")
    if severity_rating is None:
        severity_rating = score_result.get("severity")

    if severity_rating is None:
        severity_rating = severity_from_score(float(cvss_score or 0.0))

    result = observation.to_dict()
    result.update({
        "security_status": score_result.get("security_status"),
        "cvss_score": cvss_score,
        "severity_rating": severity_rating,
        "cvss_vector": cvss_vector,
        "cvss_explanation": score_result.get("explanation"),
        "missing_fields": score_result.get("missing_fields", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"CVSS Base Score: {result['cvss_score']}")
    print(f"Severity Rating: {result['severity_rating']}")
    print(f"CVSS Vector: {result['cvss_vector']}")
    print(f"Security Status: {result['security_status']}")
    print(f"Result JSON: {path}")

    return result
