from app.measurement_manifest import manifest


def test_stage_b_identity_is_not_historical_live_acceptance():
    result = manifest()
    assert result["status"] == "manifest_only_no_measurement"
    assert result["settings"]["scout_schedule_mode"] in {"handlers", "round_robin"}
    assert "agent/scout_schedule.py" in result["implementation_sha256"]
    assert result["legacy_live_baseline_compatible"] is False
    assert all("key" not in k.lower() and "token" not in k.lower()
               for k in result["settings"] if k != "llm_max_output_tokens")
