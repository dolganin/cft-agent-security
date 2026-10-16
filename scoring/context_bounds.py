"""Conservative CP intervals retain unknown facts instead of guessing them."""
from itertools import product

from schemas.architecture import ArchitectureContext
from scoring.service import ScoringService

EXTREMES = {
    "public_exposure": (False, True), "criticality": ("low", "high"),
    "databases": ([], ["unknown-database"]), "critical_paths": ([], ["unknown-critical-path"]),
    "authentication": ("admin", "none"), "blast_radius": ("isolated", "shared"),
}


def priority_bounds(context: ArchitectureContext):
    service = ScoringService()
    observed = service.score_context_priority(context)
    unknown = observed.unknown_inputs
    if any(name not in EXTREMES for name in unknown):
        raise ValueError("Unknown CP dimension has no reviewed scoring bounds")
    variants = []
    for values in product(*(EXTREMES[name] for name in unknown)):
        fields = context.model_dump()
        fields.update(dict(zip(unknown, values, strict=True)))
        fields["unknown_inputs"] = []
        variants.append(service.score_context_priority(ArchitectureContext.model_validate(fields)))
    levels = sorted({value.level for value in variants})
    return {"scheme": "context-priority.v0.1", "original_priority": observed.model_dump(),
            "minimum_score": min(value.score for value in variants),
            "maximum_score": max(value.score for value in variants), "possible_levels": levels,
            "level": levels[0] if len(levels) == 1 else None,
            "assessment_method": "deterministic_interval_over_unknown_context_facts",
            "unknown_inputs_preserved": unknown,
            "complete_numeric_assessment": observed.assessment_status == "assessed"}
