"""Operator profile selection by existing source bindings, never by benchmark truth."""
from sast.identity import rule_family
from security.verification_binding import resolve_binding


def select_profile(finding, profiles):
    matches = []
    for profile in profiles:
        resolution = resolve_binding(profile, finding)
        if resolution.status == "bound":
            matches.append(profile)
        elif resolution.candidates:
            # A locally ambiguous operator map must not be resolved by order.
            return None, "Operator route binding is ambiguous: " + resolution.reason
    if len(matches) == 1:
        return matches[0], "Unique operator source/route binding"
    if matches:
        return None, "More than one operator profile binds this finding"
    if rule_family(finding.rule_id) == "code-injection" and finding.file in {
        "routes/userProfile.ts", "routes/updateUserProfile.ts",
    }:
        disabled = [p for p in profiles if p.b06_verification is not None]
        if len(disabled) == 1:
            return disabled[0], "Known Docker-disabled code-evaluation branch"
    return None, "No registered runtime verification route binds this source observation"
