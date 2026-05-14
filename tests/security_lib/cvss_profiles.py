from typing import Dict, Any

from tests.security_lib.observations import RuntimeObservation


def score_authentication_event_integrity(observation: RuntimeObservation) -> Dict[str, Any]:
    missing_fields = []

    if not observation.login_event_observed:
        missing_fields.append("login_event")
    if not observation.logout_event_observed:
        missing_fields.append("logout_event")
    if not observation.user_identifier_observed:
        missing_fields.append("user_identifier")
    if not observation.timestamp_observed:
        missing_fields.append("timestamp")
    if not observation.outcome_status_observed:
        missing_fields.append("outcome_status")

    if not missing_fields:
        return {
            "security_status": "no_observed_gap",
            "cvss_score": 0.0,
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            "missing_fields": [],
            "explanation": "Required authentication security event evidence was observed.",
        }

    if "login_event" in missing_fields or "logout_event" in missing_fields:
        return {
            "security_status": "candidate_logging_gap_high",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:L/SA:N",
            "missing_fields": missing_fields,
            "explanation": "One or more core authentication security events were not observed at runtime.",
        }

    return {
        "security_status": "candidate_logging_gap_medium",
        "cvss_score": 3.7,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N",
        "missing_fields": missing_fields,
        "explanation": "Authentication events were observed, but some audit detail fields were missing.",
    }


def score_observation(observation: RuntimeObservation) -> Dict[str, Any]:
    if observation.cvss_profile == "authentication_event_integrity":
        return score_authentication_event_integrity(observation)

    return {
        "security_status": "unsupported_cvss_profile",
        "cvss_score": 0.0,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        "missing_fields": [],
        "explanation": f"Unsupported CVSS profile: {observation.cvss_profile}",
    }