"""
BDD test for Maven artifact PGP signing verification.
Tests that OpenMRS O3 distribution modules on JFrog have valid GPG signatures.

Add this file to: tests/data_integrity_failures/
Feature file: tests/data_integrity_failures/artifact_signing.feature
"""
import pytest
import pytest_bdd
import requests
import re

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
JFROG_BASE  = "https://openmrs.jfrog.io/artifactory"
JFROG_REPOS = ["modules", "releases"]

# O3 distribution backend modules to check
MODULES_TO_CHECK = [
    ("org.openmrs.module", "webservices.rest"),
    ("org.openmrs.module", "fhir2"),
    ("org.openmrs.module", "legacyui"),
    ("org.openmrs.module", "emrapi"),
    ("org.openmrs.module", "billing"),
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def browse_dir(url):
    """Get visible files from JFrog HTML directory listing.
    Visible = developer uploaded. Hidden = JFrog auto-generated.
    """
    try:
        r = requests.get(url, headers={"User-Agent": "openmrs-bdd-test/1.0"},
                         timeout=10)
        if r.status_code != 200:
            return []
        return re.findall(r'href="([^"/][^"?#]*)"', r.text)
    except Exception:
        return []


def get_latest_version(group_id, artifact_id):
    """Find the latest non-SNAPSHOT version of an artifact on JFrog."""
    group_path = group_id.replace(".", "/")
    for repo in JFROG_REPOS:
        url     = f"{JFROG_BASE}/{repo}/{group_path}/{artifact_id}/"
        entries = browse_dir(url)
        versions = [e.rstrip("/") for e in entries
                    if e.endswith("/") and "SNAPSHOT" not in e]
        if versions:
            try:
                versions.sort(
                    key=lambda v: [int(x) for x in re.findall(r"\d+", v)],
                    reverse=True)
            except Exception:
                versions.sort(reverse=True)
            return repo, versions[0]
    return None, None


def check_gpg_signature(group_id, artifact_id):
    """Check if artifact has a visible .asc file on JFrog."""
    repo, version = get_latest_version(group_id, artifact_id)
    if not repo:
        return False, f"{artifact_id} not found on JFrog"

    group_path = group_id.replace(".", "/")
    ver_url    = f"{JFROG_BASE}/{repo}/{group_path}/{artifact_id}/{version}/"
    visible    = browse_dir(ver_url)

    primary = [f for f in visible
               if any(f.endswith(e) for e in (".jar", ".pom", ".omod"))
               and not any(f.endswith(e) for e in (".sha1", ".md5", ".asc"))]

    has_asc = any((f + ".asc") in visible for f in primary)
    return has_asc, f"{artifact_id} v{version} on {repo}"


# ---------------------------------------------------------------------------
# BDD scenario
# ---------------------------------------------------------------------------

@pytest_bdd.scenario(
    'artifact_signing.feature',
    'OpenMRS modules should have GPG signatures on JFrog'
)
def test_modules_have_gpg_signatures():
    pass


@pytest_bdd.given("a list of O3 distribution backend modules")
def given_modules(module_results):
    pass


@pytest_bdd.when("the JFrog artifact repository is checked")
def when_jfrog_checked(module_results):
    for group_id, artifact_id in MODULES_TO_CHECK:
        has_asc, info = check_gpg_signature(group_id, artifact_id)
        module_results[artifact_id] = {
            "has_asc": has_asc,
            "info": info
        }


@pytest_bdd.then("each module should have a visible .asc signature file")
def then_modules_have_asc(module_results):
    failures = []
    for artifact_id, result in module_results.items():
        if not result["has_asc"]:
            failures.append(
                f"{artifact_id} ({result['info']}) has NO GPG .asc signature"
            )

    assert not failures, (
        f"The following modules are missing GPG signatures:\n"
        + "\n".join(failures)
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def module_results():
    return {}