"""Unit tests for Unified Risk Scoring Engine."""

import pytest
from app.risk.scorer import calculate_unified_risk_score


def test_unified_risk_formula_calculation():
    """Verifies proportional weights: URL (40%), Network (40%), IOC (+15), Temporal (+15)."""
    res = calculate_unified_risk_score(
        url_score_raw=50.0,       # 50% of 40 = 20.0
        network_score_raw=80.0,   # 80% of 40 = 32.0
        correlation_points=15.0,
        temporal_points=15.0,
    )

    # Expected: 20 + 32 + 15 + 15 = 82.0 -> CRITICAL
    assert res["url_component"] == 20.0
    assert res["network_component"] == 32.0
    assert res["correlation_component"] == 15.0
    assert res["temporal_component"] == 15.0
    assert res["final_risk_score"] == 82.0
    assert res["severity"] == "CRITICAL"


def test_risk_score_cap_at_100():
    """Verifies that risk score is strictly capped at 100."""
    res = calculate_unified_risk_score(
        url_score_raw=100.0,       # 40.0
        network_score_raw=100.0,   # 40.0
        correlation_points=15.0,   # 15.0
        temporal_points=15.0,      # 15.0 -> Sum 110.0 capped at 100.0
    )
    assert res["final_risk_score"] == 100.0
    assert res["severity"] == "CRITICAL"


def test_low_risk_calculation():
    """Verifies low risk tier (0-29)."""
    res = calculate_unified_risk_score(
        url_score_raw=15.0,       # 6.0
        network_score_raw=10.0,   # 4.0
        correlation_points=0.0,
        temporal_points=0.0,
    )
    assert res["final_risk_score"] == 10.0
    assert res["severity"] == "LOW"


def test_medium_risk_calculation():
    """Verifies medium risk tier (30-59)."""
    res = calculate_unified_risk_score(
        url_score_raw=60.0,       # 24.0
        network_score_raw=40.0,   # 16.0 -> 40.0
        correlation_points=0.0,
        temporal_points=0.0,
    )
    assert res["final_risk_score"] == 40.0
    assert res["severity"] == "MEDIUM"


def test_itemized_breakdown_structure():
    """Verifies explainable itemized breakdown list."""
    res = calculate_unified_risk_score(
        url_score_raw=50.0,
        network_score_raw=50.0,
        correlation_points=15.0,
        temporal_points=0.0,
    )
    assert len(res["contributing_factors"]) >= 3
    assert any(f["points"] == 20.0 for f in res["contributing_factors"])
