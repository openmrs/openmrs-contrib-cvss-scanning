import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from tests.security_lib.observations import RuntimeObservation


def write_security_result(
    observation: RuntimeObservation,
    score_result: Dict[str, Any],
    output_path: str,
) -> Dict[str, Any]:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    result = observation.to_dict()
    result.update({
        "security_status": score_result.get("security_status"),
        "cvss_score": score_result.get("cvss_score"),
        "cvss_vector": score_result.get("cvss_vector"),
        "cvss_explanation": score_result.get("explanation"),
        "missing_fields": score_result.get("missing_fields", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"CVSS Base Score: {result['cvss_score']}")
    print(f"CVSS Vector: {result['cvss_vector']}")
    print(f"Security Status: {result['security_status']}")
    print(f"Result JSON: {path}")

    return result