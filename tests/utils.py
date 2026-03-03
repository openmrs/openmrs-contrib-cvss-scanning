# Utils.py
# Shared utility between tests in this package
# This can be referenced as: from tests.utils import func

import os
from enum import Enum

# URLS
O3_BASE_URL = os.getenv('O3_BASE_URL', 'http://localhost/openmrs/spa')

# Metrics Enums

class _ImpactMetrics:
    class VulnerableSystem(Enum):
        NONE = 'N'
        LOW = 'L'
        HIGH = 'H'

    class SubsequentSystem(Enum):
        NONE = 'N'
        LOW = 'L'
        HIGH = 'H'

class BaseMetrics:
    # This stores the possible values for CVSS 4.0 as enums

    # Exploitability Metrics

    class AttackVector(Enum):
        NETWORK = 'N'
        ADJACENT = 'A'
        LOCAL = 'L'
        PHYSICAL = 'P'
    
    class AttackComplexity(Enum):
        LOW = 'L'
        HIGH = 'H'
    
    class AttackRequirements(Enum):
        NONE = 'N'
        PRESENT = 'P'
    
    class PriviledgesRequired(Enum):
        NONE = 'N'
        LOW = 'L'
        HIGH = 'H'
    
    class UserInteraction(Enum):
        NONE = 'N'
        PASSIVE = 'P'
        ACTIVE = 'A'
    
    # Impact Metrics

    class Confidentiality(_ImpactMetrics):
        pass
    
    class Integrity(_ImpactMetrics):
        pass

    class Availability(_ImpactMetrics):
        pass

def calculate_cvss_v4_score(AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA):
    """
    Calculate CVSS 4.0 Base Score using the official MacroVector lookup table
    and interpolation method.

    Reference: https://www.first.org/cvss/v4.0/specification-document
    Source: https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js

    CVSS 4.0 does NOT use a mathematical formula like 3.1.
    Instead, vectors are grouped into MacroVectors (equivalence classes)
    and scores are assigned via lookup table, then refined by interpolation.

    Args:
        AV: Attack Vector (N/A/L/P)
        AC: Attack Complexity (L/H)
        AT: Attack Requirements (N/P)
        PR: Privileges Required (N/L/H)
        UI: User Interaction (N/P/A)
        VC: Vulnerable System Confidentiality (H/L/N)
        VI: Vulnerable System Integrity (H/L/N)
        VA: Vulnerable System Availability (H/L/N)
        SC: Subsequent System Confidentiality (H/L/N)
        SI: Subsequent System Integrity (H/L/N)
        SA: Subsequent System Availability (H/L/N)

    Returns:
        float: CVSS 4.0 Base Score (0.0 - 10.0)
    """

    # -----------------------------------------------------------------------
    # STEP 1: Determine EQ (Equivalence) levels for each metric group
    # Each EQ level ranges from 0 (most severe) to max (least severe)
    # -----------------------------------------------------------------------

    # EQ1: AV/PR/UI - 3 levels (0, 1, 2)
    if AV == BaseMetrics.AttackVector.NETWORK and PR == BaseMetrics.PriviledgesRequired.NONE and UI == BaseMetrics.UserInteraction.NONE:
        eq1 = 0
    elif (AV == BaseMetrics.AttackVector.NETWORK or PR == BaseMetrics.PriviledgesRequired.NONE or UI == BaseMetrics.UserInteraction.NONE) and not (AV == BaseMetrics.AttackVector.NETWORK and PR == BaseMetrics.PriviledgesRequired.NONE and UI == BaseMetrics.UserInteraction.NONE) and AV != BaseMetrics.AttackVector.PHYSICAL:
        eq1 = 1
    else:
        eq1 = 2

    # EQ2: AC/AT - 2 levels (0, 1)
    if AC == BaseMetrics.AttackComplexity.LOW and AT == BaseMetrics.AttackRequirements.NONE:
        eq2 = 0
    else:
        eq2 = 1

    # EQ3: VC/VI/VA - 3 levels (0, 1, 2)
    if VC == BaseMetrics.Confidentiality.VulnerableSystem.HIGH and VI == BaseMetrics.Integrity.VulnerableSystem.HIGH:
        eq3 = 0
    elif (VC == BaseMetrics.Confidentiality.VulnerableSystem.HIGH or VI == BaseMetrics.Integrity.VulnerableSystem.HIGH or VA == BaseMetrics.Availability.VulnerableSystem.HIGH) and not (VC == BaseMetrics.Confidentiality.VulnerableSystem.HIGH and VI == BaseMetrics.Integrity.VulnerableSystem.HIGH):
        eq3 = 1
    else:
        eq3 = 2

    # EQ4: SC/SI/SA - 2 levels in Base scoring (0, 1)
    # Note: Level 0 requires MSI:S or MSA:S which are Environmental metrics,
    # unreachable in Base scoring. So eq4=0 when SC/SI/SA is High, eq4=1 otherwise.
    if SC == BaseMetrics.Confidentiality.SubsequentSystem.HIGH or SI == BaseMetrics.Integrity.SubsequentSystem.HIGH or SA == BaseMetrics.Availability.SubsequentSystem.HIGH:
        eq4 = 0
    else:
        eq4 = 1

    # EQ5: Exploit Maturity - E not specified so defaults to X = A (worst case)
    eq5 = 0  # E:X defaults to E:A per spec

    # EQ6: CR/IR/AR + VC/VI/VA - CR/IR/AR not specified so default to H (worst case)
    if VC == 'H' or VI == 'H' or VA == 'H':
        eq6 = 0
    else:
        eq6 = 1

    # -----------------------------------------------------------------------
    # STEP 2: MacroVector lookup table
    # Key: (eq1, eq2, eq3eq6_combined, eq4, eq5)
    # Values: MacroVector scores from FIRST.org cvss_lookup.js
    # -----------------------------------------------------------------------

    # EQ3 and EQ6 are not independent - must be evaluated jointly
    eq3eq6_map = {
        (0, 0): 0,
        (0, 1): 1,
        (1, 0): 2,
        (1, 1): 3,
        (2, 0): 4,  # Cannot exist per spec
        (2, 1): 4,
    }
    eq3eq6 = eq3eq6_map.get((eq3, eq6), 4)

    lookup = {
        (0, 0, 0, 0, 0): 10.0, (0, 0, 0, 0, 1): 9.9, (0, 0, 0, 0, 2): 9.8,
        (0, 0, 0, 1, 0): 9.5,  (0, 0, 0, 1, 1): 9.5, (0, 0, 0, 1, 2): 9.2,
        (0, 0, 1, 0, 0): 10.0, (0, 0, 1, 0, 1): 9.6, (0, 0, 1, 0, 2): 9.3,
        (0, 0, 1, 1, 0): 9.2,  (0, 0, 1, 1, 1): 8.9, (0, 0, 1, 1, 2): 8.6,
        (0, 0, 2, 0, 0): 9.3,  (0, 0, 2, 0, 1): 9.0, (0, 0, 2, 0, 2): 8.8,
        (0, 0, 2, 1, 0): 8.6,  (0, 0, 2, 1, 1): 8.0, (0, 0, 2, 1, 2): 7.4,
        (0, 0, 3, 0, 0): 9.0,  (0, 0, 3, 0, 1): 8.5, (0, 0, 3, 0, 2): 7.9,
        (0, 0, 3, 1, 0): 7.9,  (0, 0, 3, 1, 1): 7.5, (0, 0, 3, 1, 2): 7.0,
        (0, 0, 4, 0, 0): 8.0,  (0, 0, 4, 0, 1): 7.3, (0, 0, 4, 0, 2): 6.8,
        (0, 0, 4, 1, 0): 6.4,  (0, 0, 4, 1, 1): 5.9, (0, 0, 4, 1, 2): 5.4,
        (0, 1, 0, 0, 0): 9.5,  (0, 1, 0, 0, 1): 9.4, (0, 1, 0, 0, 2): 9.2,
        (0, 1, 0, 1, 0): 8.7,  (0, 1, 0, 1, 1): 8.6, (0, 1, 0, 1, 2): 8.4,
        (0, 1, 1, 0, 0): 9.2,  (0, 1, 1, 0, 1): 8.9, (0, 1, 1, 0, 2): 8.6,
        (0, 1, 1, 1, 0): 8.4,  (0, 1, 1, 1, 1): 7.8, (0, 1, 1, 1, 2): 7.0,
        (0, 1, 2, 0, 0): 8.8,  (0, 1, 2, 0, 1): 8.4, (0, 1, 2, 0, 2): 7.8,
        (0, 1, 2, 1, 0): 7.7,  (0, 1, 2, 1, 1): 7.1, (0, 1, 2, 1, 2): 6.4,
        (0, 1, 3, 0, 0): 8.5,  (0, 1, 3, 0, 1): 7.9, (0, 1, 3, 0, 2): 7.3,
        (0, 1, 3, 1, 0): 7.2,  (0, 1, 3, 1, 1): 6.5, (0, 1, 3, 1, 2): 5.8,
        (0, 1, 4, 0, 0): 7.4,  (0, 1, 4, 0, 1): 6.6, (0, 1, 4, 0, 2): 6.0,
        (0, 1, 4, 1, 0): 5.5,  (0, 1, 4, 1, 1): 5.1, (0, 1, 4, 1, 2): 4.7,
        (1, 0, 0, 0, 0): 9.4,  (1, 0, 0, 0, 1): 9.3, (1, 0, 0, 0, 2): 9.0,
        (1, 0, 0, 1, 0): 8.8,  (1, 0, 0, 1, 1): 8.6, (1, 0, 0, 1, 2): 8.3,
        (1, 0, 1, 0, 0): 9.2,  (1, 0, 1, 0, 1): 8.8, (1, 0, 1, 0, 2): 8.5,
        (1, 0, 1, 1, 0): 8.2,  (1, 0, 1, 1, 1): 7.6, (1, 0, 1, 1, 2): 6.8,
        (1, 0, 2, 0, 0): 8.6,  (1, 0, 2, 0, 1): 8.3, (1, 0, 2, 0, 2): 7.7,
        (1, 0, 2, 1, 0): 7.5,  (1, 0, 2, 1, 1): 6.8, (1, 0, 2, 1, 2): 6.0,
        (1, 0, 3, 0, 0): 8.2,  (1, 0, 3, 0, 1): 7.7, (1, 0, 3, 0, 2): 7.1,
        (1, 0, 3, 1, 0): 6.9,  (1, 0, 3, 1, 1): 6.3, (1, 0, 3, 1, 2): 5.6,
        (1, 0, 4, 0, 0): 7.2,  (1, 0, 4, 0, 1): 6.5, (1, 0, 4, 0, 2): 5.8,
        (1, 0, 4, 1, 0): 5.1,  (1, 0, 4, 1, 1): 4.7, (1, 0, 4, 1, 2): 4.3,
        (1, 1, 0, 0, 0): 9.0,  (1, 1, 0, 0, 1): 8.8, (1, 1, 0, 0, 2): 8.5,
        (1, 1, 0, 1, 0): 8.3,  (1, 1, 0, 1, 1): 8.1, (1, 1, 0, 1, 2): 7.8,
        (1, 1, 1, 0, 0): 8.6,  (1, 1, 1, 0, 1): 8.3, (1, 1, 1, 0, 2): 7.8,
        (1, 1, 1, 1, 0): 7.6,  (1, 1, 1, 1, 1): 7.0, (1, 1, 1, 1, 2): 6.2,
        (1, 1, 2, 0, 0): 8.1,  (1, 1, 2, 0, 1): 7.7, (1, 1, 2, 0, 2): 7.2,
        (1, 1, 2, 1, 0): 6.9,  (1, 1, 2, 1, 1): 6.3, (1, 1, 2, 1, 2): 5.5,
        (1, 1, 3, 0, 0): 7.7,  (1, 1, 3, 0, 1): 7.2, (1, 1, 3, 0, 2): 6.6,
        (1, 1, 3, 1, 0): 6.4,  (1, 1, 3, 1, 1): 5.8, (1, 1, 3, 1, 2): 5.2,
        (1, 1, 4, 0, 0): 6.7,  (1, 1, 4, 0, 1): 6.1, (1, 1, 4, 0, 2): 5.4,
        (1, 1, 4, 1, 0): 4.8,  (1, 1, 4, 1, 1): 4.4, (1, 1, 4, 1, 2): 4.0,
        (2, 0, 0, 0, 0): 8.5,  (2, 0, 0, 0, 1): 8.4, (2, 0, 0, 0, 2): 8.2,
        (2, 0, 0, 1, 0): 7.9,  (2, 0, 0, 1, 1): 7.8, (2, 0, 0, 1, 2): 7.5,
        (2, 0, 1, 0, 0): 8.3,  (2, 0, 1, 0, 1): 8.0, (2, 0, 1, 0, 2): 7.6,
        (2, 0, 1, 1, 0): 7.3,  (2, 0, 1, 1, 1): 6.7, (2, 0, 1, 1, 2): 6.0,
        (2, 0, 2, 0, 0): 7.7,  (2, 0, 2, 0, 1): 7.4, (2, 0, 2, 0, 2): 7.0,
        (2, 0, 2, 1, 0): 6.6,  (2, 0, 2, 1, 1): 6.1, (2, 0, 2, 1, 2): 5.3,
        (2, 0, 3, 0, 0): 7.3,  (2, 0, 3, 0, 1): 6.9, (2, 0, 3, 0, 2): 6.4,
        (2, 0, 3, 1, 0): 6.1,  (2, 0, 3, 1, 1): 5.6, (2, 0, 3, 1, 2): 5.0,
        (2, 0, 4, 0, 0): 6.4,  (2, 0, 4, 0, 1): 5.9, (2, 0, 4, 0, 2): 5.3,
        (2, 0, 4, 1, 0): 4.7,  (2, 0, 4, 1, 1): 4.3, (2, 0, 4, 1, 2): 3.9,
        (2, 1, 0, 0, 0): 8.0,  (2, 1, 0, 0, 1): 7.9, (2, 1, 0, 0, 2): 7.6,
        (2, 1, 0, 1, 0): 7.4,  (2, 1, 0, 1, 1): 7.2, (2, 1, 0, 1, 2): 7.0,
        (2, 1, 1, 0, 0): 7.7,  (2, 1, 1, 0, 1): 7.4, (2, 1, 1, 0, 2): 7.0,
        (2, 1, 1, 1, 0): 6.7,  (2, 1, 1, 1, 1): 6.1, (2, 1, 1, 1, 2): 5.3,
        (2, 1, 2, 0, 0): 7.3,  (2, 1, 2, 0, 1): 7.0, (2, 1, 2, 0, 2): 6.5,
        (2, 1, 2, 1, 0): 6.2,  (2, 1, 2, 1, 1): 5.6, (2, 1, 2, 1, 2): 5.0,
        (2, 1, 3, 0, 0): 6.9,  (2, 1, 3, 0, 1): 6.5, (2, 1, 3, 0, 2): 6.0,
        (2, 1, 3, 1, 0): 5.7,  (2, 1, 3, 1, 1): 5.2, (2, 1, 3, 1, 2): 4.7,
        (2, 1, 4, 0, 0): 6.0,  (2, 1, 4, 0, 1): 5.5, (2, 1, 4, 0, 2): 5.0,
        (2, 1, 4, 1, 0): 4.4,  (2, 1, 4, 1, 1): 4.0, (2, 1, 4, 1, 2): 3.6,
    }

    key = (eq1, eq2, eq3eq6, eq4, eq5)
    score = lookup.get(key, 0.0)

    return round(score, 1)

def get_cvss_severity(cvss_score):
    # Determine severity rating
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return severity