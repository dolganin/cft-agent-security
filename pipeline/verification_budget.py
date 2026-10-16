"""Conservative settlement of sequential fixed-verifier HTTP reservations."""


def b05_http_ledger(records, check_exchanges):
    """Count preparation, controls, provisioning and readiness attempts exactly once."""
    if type(check_exchanges) is not int or check_exchanges < 0:
        raise ValueError("Invalid B05 check exchange count")
    total = check_exchanges
    counts = {phase: {} for phase in ("prepare", "control", "readiness")}
    controls = {}
    complete = type(check_exchanges) is int and check_exchanges > 0
    for row in records:
        phase, generation = row.get("phase"), row.get("generation")
        context = row.get("context") or {}
        if phase == "readiness":
            value = row.get("readiness_probe_attempts")
        elif phase in {"prepare", "control", "b05-provision"} and context:
            value = context.get("http_exchanges")
            complete = complete and context.get("status") == "ready"
        else:
            continue
        if type(value) is not int or value < 0:
            raise ValueError("Invalid B05 HTTP ledger count")
        if phase == "b05-provision":
            previous = controls.get(generation)
            complete = complete and previous is not None
            if previous is not None and value < previous:
                raise ValueError("B05 provisioning HTTP counter moved backwards")
            total += value - previous if previous is not None else value
        else:
            total += value
            counts[phase][generation] = counts[phase].get(generation, 0) + 1
            if phase == "control":
                controls[generation] = value
    complete = (complete and len(counts["prepare"]) == 2
        and set(counts["prepare"]) == set(counts["control"]) == set(counts["readiness"])
        and all(count == 1 for phases in counts.values() for count in phases.values()))
    return total, complete


def verification_http_charge(review):
    """Refund unused capacity only for a complete, trusted terminal fixture ledger."""
    reserved = review.get("requests_reserved", 0)
    if type(reserved) is not int or reserved < 0:
        raise ValueError("Invalid verifier HTTP reservation")
    if review.get("request_accounting_complete") is not True:
        return reserved
    observed = review.get("requests_observed")
    if type(observed) is not int or not 0 < observed <= reserved:
        raise ValueError("Complete verifier HTTP ledger is outside its reservation")
    if (review.get("origin") not in {"canonical_fixed_B05_verifier", "canonical_fixed_B06_verifier"}
            or review.get("executed") is not True
            or review.get("worker_cleanup_verified") is not True
            or review.get("status") not in {"confirmed", "rejected"}):
        return reserved
    return observed
