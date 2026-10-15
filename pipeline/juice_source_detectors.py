"""Bounded, source-only candidate detectors for the pinned Juice Shop corpus.

This module deliberately consumes :class:`RepositorySource`, rather than opening
repository paths itself.  The source reader is the trust boundary for the input
projection: it owns inventory selection, path containment, size limits, symlink
rejection, test/oracle exclusions and source-annotation redaction.

The output is still only a candidate.  A source pattern is not runtime Evidence,
an exploitability verdict, a severity assessment or a benchmark label.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from hashlib import sha256

from sast.identity import normalize_finding
from schemas.discovery import ProjectDiscoveryResult
from schemas.finding import Finding, FindingObservation
from tools.repository_source import RepositorySource

SOURCE = "juice_source_detector"
DEFAULT_MAX_CANDIDATES = 128


@dataclass(frozen=True)
class _Candidate:
    rule_id: str
    title: str
    description: str
    file: str
    line: int
    rationale: str
    evidence_files: tuple[str, ...] = ()


_CODE_COMMENT = re.compile(r"^\s*(?://|/\*|\*|#)")
_REQUEST_USER_ID = re.compile(r"\breq\.(?:body|query|params)\.UserId\b")
_MODEL_ACCESS = re.compile(
    r"\b(?:find(?:One|All|ByPk)|findOrCreate|create|build|update|destroy|"
    r"increment|decrement)\s*\("
)
_PATH_ID_QUERY = re.compile(
    r"\b(?:BasketModel|CardModel|AddressModel|OrderModel)\s*\.find(?:One|ByPk)\s*\("
)
_CAPTCHA_RESPONSE = re.compile(r"\bres\.json\(\s*(?:captcha|imageCaptcha)\s*\)")
_CAPTCHA_LOOKUP = re.compile(r"\b(?:CaptchaModel\.findOne|ImageCaptchaModel\.findAll)\s*\(")
_FORWARDED_IP = re.compile(
    r"\bkeyGenerator\b.*(?:X-Forwarded-For|x-forwarded-for|forwarded)"
)
_METRICS_RESPONSE = re.compile(r"\bres\.end\(\s*await\s+register\.metrics\(\)\s*\)")
_BALANCE_MUTATION = re.compile(
    r"\b(?:WalletModel|wallet)\.(?:increment|decrement|update)\s*\(.*\bbalance\s*:\s*req\.body\.balance"
)
_COUPON_INPUT = re.compile(r"\b(?:params\.coupon|decodeURIComponent\s*\()")
_OPTIONAL_CURRENT_PASSWORD = re.compile(r"\bif\s*\(\s*currentPassword\s*&&")
_PASSWORD_UPDATE = re.compile(r"\b\w+\.update\s*\(\s*\{\s*password\s*:")
_CLIENT_ROLE_ASSIGNMENT = re.compile(r"\bsetDataValue\(\s*['\"]role['\"]\s*,\s*role\s*\)")
_REVIEW_UPDATE = re.compile(r"\breviewsCollection\.update\s*\(")
_REQUEST_SELECTOR = re.compile(r"\b(?:_id|id)\s*:\s*req\.body\.id\b")
_REVIEW_OWNER_PREDICATE = re.compile(
    r"\b(?:author|UserId|userId|ownerId|owner)\s*:"
)
_FILE_ALLOWLIST = re.compile(r"\bendsWithAllowlistedFileType\s*\(")
_NULL_NORMALIZATION = re.compile(r"\bcutOffPoisonNullByte\s*\(\s*file\s*\)")
_SEND_FILE = re.compile(r"\bres\.sendFile\s*\(")
_BASKET_FIRST_SELECTOR = re.compile(r"\bbasketIds\s*\[\s*0\s*\]")
_BASKET_LAST_SELECTOR = re.compile(
    r"\bBasketId\s*:\s*basketIds\s*\[\s*basketIds\.length\s*-\s*1\s*\]"
)
_BASKET_DUPLICATE_REJECTION = re.compile(r"\bbasketIds\.length\s*>\s*1\b")
_BASKET_RAW_PARSE = re.compile(r"\bparseJsonCustom\s*\([^\n]*rawBody")
_TRUSTED_HTML = re.compile(r"\bsanitizer\.bypassSecurityTrustHtml\s*\(")
_QUERY_PARAM_SOURCE = re.compile(r"\b(?:this\.)?(?:route|activatedRoute)\.snapshot\.queryParams\b")
_PRODUCT_SOURCE_LOAD = re.compile(r"\bproductService\.search\s*\(")
_PRODUCT_TRUST_HELPER = re.compile(r"\btrustProductDescription\s*\(")
_USER_FIELDS_QUERY = re.compile(r"\breq\.query\??\.fields\b")
_USER_DYNAMIC_FIELD_READ = re.compile(r"\buser\??\.data\s*\[\s*field\b")
_USER_FIELD_ALLOWLIST = re.compile(
    r"\b(?:allowed|public|safe)[A-Za-z]*Fields\b|"
    r"\b(?:includes|has)\s*\(\s*field\s*\)"
)
_QUANTITY_COMPARISON = re.compile(r"\bproduct\.quantity\s*>=\s*quantity\b")
_QUANTITY_LOWER_BOUND = re.compile(
    r"(?:\bquantity\s*(?:<|<=|>=|>)\s*0\b|"
    r"\bmin\s*:\s*0\b|\bMath\.max\s*\(\s*0\s*,\s*quantity\b)"
)
_BASKET_QUANTITY_FIELD = re.compile(r"\bquantity\s*:\s*(?:DataTypes\.INTEGER|\{)")
_FINALE_RESOURCE = re.compile(r"\bfinale\.resource\s*\(\s*\{")
_AUTO_PRODUCT = re.compile(
    r"\bname\s*:\s*['\"]Product['\"]\s*,\s*exclude\s*:\s*\[\s*\]\s*,\s*model\s*:\s*ProductModel\b"
)
_PRODUCT_POST_CONTROL = re.compile(
    r"\bapp\.post\s*\(\s*['\"]\/api\/Products['\"].*\bsecurity\.\w+\s*\("
)
_PRODUCT_DELETE_CONTROL = re.compile(
    r"\bapp\.delete\s*\(\s*['\"]\/api\/Products\/:id['\"].*\bsecurity\.\w+\s*\("
)
_PRODUCT_PUT_ROUTE = re.compile(
    r"\bapp\.put\s*\(\s*['\"]\/api\/Products\/:id['\"]"
)
_PRODUCT_PUT_CONTROL = re.compile(
    r"\bapp\.put\s*\(\s*['\"]\/api\/Products\/:id['\"].*\bsecurity\.\w+\s*\("
)
_AUTO_FEEDBACK = re.compile(
    r"\bname\s*:\s*['\"]Feedback['\"]\s*,\s*exclude\s*:\s*\[\s*\]\s*,\s*model\s*:\s*FeedbackModel\b"
)
_FEEDBACK_FIELD = re.compile(r"^\s*UserId\s*:\s*\{")


def _is_code(line: str) -> bool:
    """Avoid treating a visible ordinary comment as an application signal."""

    return bool(line.strip()) and not _CODE_COMMENT.match(line)


def _nearby(lines: list[str], index: int, radius: int = 10) -> str:
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    return "\n".join(lines[start:end])


def _has_local_identity_guard(lines: list[str], index: int) -> bool:
    """Recognize an explicit local owner/authentication guard before a query.

    This is intentionally conservative.  Middleware in another file is not
    treated as proof that a handler is safe; the later Validator/runtime checks
    remain responsible for the actual claim.
    """

    preceding = "\n".join(lines[max(0, index - 12):index])
    return bool(re.search(
        r"authenticatedUsers|loggedInUser|isAuthorized\s*\(|appendUserId\s*\(|"
        r"(?:user|customer)\s*\.data\s*\.id|UserId\s*:\s*(?:user|customer)",
        preceding,
    ))


def _review_selector_has_owner_predicate(lines: list[str], index: int) -> bool:
    """Inspect only the first update argument, not later update/result fields."""

    for offset, line in enumerate(lines[index:index + 8]):
        if _REVIEW_OWNER_PREDICATE.search(line):
            return True
        if offset and re.search(r"\}\s*,", line):
            return False
    return False


def _candidate_id(candidate: _Candidate) -> str:
    identity = f"{candidate.rule_id}:{candidate.file}:{candidate.line}"
    return "juice-source-" + sha256(identity.encode("utf-8")).hexdigest()[:20]


def _normalise_candidate(
    candidate: _Candidate,
    source: RepositorySource,
    service_resolver: Callable[[str], str | None] | None,
) -> Finding:
    finding = Finding(
        id=_candidate_id(candidate),
        source=SOURCE,
        rule_id=candidate.rule_id,
        title="Unverified source candidate: " + candidate.title,
        description=(
            candidate.description
            + " This is a source condition only; runtime verification and Evidence are required."
        ),
        file=candidate.file,
        line_start=candidate.line,
        line_end=candidate.line,
        severity=None,
        service=service_resolver(candidate.file) if service_resolver else None,
    )
    return normalize_finding(
        finding,
        repository_root=source.root,
        service_resolver=service_resolver,
        observation=FindingObservation(
            source_id=finding.id,
            source=SOURCE,
            rule_id=candidate.rule_id,
            original_file=candidate.file,
            title=finding.title,
            description=finding.description,
            line_start=candidate.line,
            line_end=candidate.line,
            rationale=candidate.rationale,
            provenance_paths=list(dict.fromkeys((candidate.file, *candidate.evidence_files))),
            signal_type="code",
        ),
    )


def _deduplicate_candidates(candidates: Iterable[_Candidate]) -> list[_Candidate]:
    unique: dict[tuple[str, str, int], _Candidate] = {}
    for candidate in candidates:
        unique[(candidate.rule_id, candidate.file, candidate.line)] = candidate
    return sorted(unique.values(), key=lambda item: (item.file, item.line, item.rule_id))


def _collect_candidates(source: RepositorySource, max_candidates: int) -> list[_Candidate]:
    return _deduplicate_candidates([
        *_detect_access_candidates(source),
        *_detect_business_candidates(source),
        *_detect_captcha_candidates(source),
        *_detect_rate_and_data_candidates(source),
        *_detect_frontend_trust_candidates(source),
        *_detect_user_field_candidates(source),
        *_detect_quantity_candidates(source),
        *_detect_generated_api_candidates(source),
        *_detect_additional_source_candidates(source),
    ])[:max_candidates]


def _detect_access_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        lines = source.lines[file]
        for index, line in enumerate(lines):
            if not _is_code(line):
                continue
            if (
                _REQUEST_USER_ID.search(line)
                and _MODEL_ACCESS.search(line)
                and not _has_local_identity_guard(lines, index)
            ):
                candidates.append(_Candidate(
                    rule_id="juice.access-control.request-owned-record",
                    title="Request-controlled owner selector reaches a data operation",
                    description=(
                        "A request-owned UserId is used directly by a model data operation "
                        "without a preceding local identity/owner guard."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Trace the actor, owner and read/write controls before any verdict.",
                ))

            if (
                _PATH_ID_QUERY.search(line)
                and re.search(r"\bwhere\s*:\s*\{\s*id\b", line)
                and re.search(r"req\.params\.id", "\n".join(lines[max(0, index - 8):index + 1]))
                and not _has_local_identity_guard(lines, index)
            ):
                candidates.append(_Candidate(
                    rule_id="juice.access-control.path-selected-record",
                    title="Path-selected record is queried before a local owner guard",
                    description=(
                        "A route parameter is used as a record identity in a model query; "
                        "the source window does not show a preceding local owner check."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Bind the route to an owned fixture and independently read back controls.",
                ))

        # A write of a request-supplied author is a separate integrity signal.
        text = "\n".join(lines)
        if "reviewsCollection.insert" in text:
            for index, line in enumerate(lines):
                if _is_code(line) and re.search(r"\bauthor\s*:\s*req\.body\.author\b", line):
                    preceding = "\n".join(lines[max(0, index - 8):index])
                    if not re.search(r"if\s*\(.*author|res\.status\s*\(\s*403|return\s+res", preceding):
                        candidates.append(_Candidate(
                            rule_id="juice.access-control.request-authorship",
                            title="Request-supplied authorship is persisted",
                            description=(
                                "A review write persists the request author field without a local "
                                "deny/identity binding in the preceding source window."
                            ),
                            file=file,
                            line=index + 1,
                            rationale="Compare actor identity with the persisted owner and use a safe counterpart.",
                        ))
    return candidates


def _detect_business_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        lines = source.lines[file]
        text = "\n".join(lines)
        for index, line in enumerate(lines):
            if not _is_code(line):
                continue
            if _BALANCE_MUTATION.search(line):
                candidates.append(_Candidate(
                    rule_id="juice.business-logic.client-controlled-balance",
                    title="Client-controlled amount reaches a wallet mutation",
                    description=(
                        "The request balance value is passed directly to a wallet increment, "
                        "decrement or update operation."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Use an owned wallet fixture and verify the resulting balance with controls.",
                ))
            if _COUPON_INPUT.search(line) and "discountFromCoupon" in text:
                candidates.append(_Candidate(
                    rule_id="juice.business-logic.coupon-state",
                    title="Request coupon input drives discount state",
                    description=(
                        "A route coupon is decoded and evaluated before a basket coupon state "
                        "is updated; ownership and final-price invariants need verification."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Apply a valid/invalid coupon to an owned basket and read back final state.",
                ))
    return candidates


def _detect_captcha_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        lines = source.lines[file]
        text = "\n".join(lines)
        for index, line in enumerate(lines):
            if not _is_code(line):
                continue
            if (
                _CAPTCHA_RESPONSE.search(line)
                and re.search(r"\banswer\b(?:\s*[:=]|\s*[,}])", _nearby(lines, index, 20))
            ):
                candidates.append(_Candidate(
                    rule_id="juice.captcha.answer-disclosure",
                    title="CAPTCHA response includes its answer field",
                    description=(
                        "The response serializes a CAPTCHA object after an answer field is "
                        "constructed in the same source flow."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Verify the response contract without exposing or logging answer values.",
                ))
            if _CAPTCHA_LOOKUP.search(line) and not re.search(r"\.(?:destroy|remove)\s*\(", text):
                candidates.append(_Candidate(
                    rule_id="juice.captcha.replayable-verification",
                    title="CAPTCHA verification reads a challenge without consuming it",
                    description=(
                        "The source looks up a CAPTCHA challenge and has no destroy/remove "
                        "operation in the projected file."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Run two bounded submissions and verify a fresh-challenge control.",
                ))
    return candidates


def _detect_rate_and_data_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        lines = source.lines[file]
        text = "\n".join(lines)
        for index, line in enumerate(lines):
            if not _is_code(line):
                continue
            if _FORWARDED_IP.search(line) and "rateLimit" in text:
                candidates.append(_Candidate(
                    rule_id="juice.rate-limiting.forwarded-client-ip",
                    title="Rate-limit key trusts a forwarded client address",
                    description=(
                        "A rate-limit key generator reads a forwarded client-address header; "
                        "proxy trust and bounded repeated requests require verification."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Use a small precomputed request series and a trusted-IP control.",
                ))
            if _METRICS_RESPONSE.search(line):
                candidates.append(_Candidate(
                    rule_id="juice.sensitive-data.metrics-exposure",
                    title="Metrics endpoint returns the registry without a local auth guard",
                    description=(
                        "The handler serializes the metrics registry directly; endpoint exposure "
                        "and sensitive labels require an authenticated/control comparison."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Check anonymous and controlled access and inspect only redacted metric fields.",
                ))
    return candidates


def _detect_frontend_trust_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        if not file.startswith("frontend/"):
            continue
        lines = source.lines[file]
        text = "\n".join(lines)
        if not _TRUSTED_HTML.search(text):
            continue
        for index, line in enumerate(lines):
            if not _is_code(line) or not _TRUSTED_HTML.search(line):
                continue
            local_source = _nearby(lines, index, 12)
            if "queryParam" in line and _QUERY_PARAM_SOURCE.search(local_source):
                candidates.append(_Candidate(
                    rule_id="juice.xss.request-query-trusted-html",
                    title="Request query text is marked as trusted HTML",
                    description=(
                        "An Angular view flow reads a route query parameter and passes that "
                        "value directly to bypassSecurityTrustHtml."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Use a bounded encoded-markup control and verify rendered output without browser-side execution.",
                ))
            if (
                "description" in line
                and _PRODUCT_SOURCE_LOAD.search(text)
                and _PRODUCT_TRUST_HELPER.search(text)
            ):
                candidates.append(_Candidate(
                    rule_id="juice.xss.product-description-trusted-html",
                    title="Product description is marked as trusted HTML",
                    description=(
                        "Product data loaded through the product service is passed through a "
                        "bypassSecurityTrustHtml description flow."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Compare a bounded encoded description with a safe rendered-description control.",
                ))
    return candidates


def _detect_user_field_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        lines = source.lines[file]
        text = "\n".join(lines)
        if not _USER_FIELDS_QUERY.search(text) or _USER_FIELD_ALLOWLIST.search(text):
            continue
        for index, line in enumerate(lines):
            if _is_code(line) and _USER_DYNAMIC_FIELD_READ.search(line):
                candidates.append(_Candidate(
                    rule_id="juice.sensitive-data.client-selected-user-fields",
                    title="Client-selected user fields reach the response",
                    description=(
                        "A query fields parameter selects arbitrary attributes from the user "
                        "object without an explicit public-field allowlist in the projected handler."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Request a private-field control and compare it with an explicit public-field allowlist.",
                ))
                break
    return candidates


def _detect_quantity_candidates(source: RepositorySource) -> list[_Candidate]:
    model_file = next(
        (file for file in source.files if file.endswith("models/basketitem.ts")),
        None,
    )
    if model_file is None:
        return []
    model_text = "\n".join(source.lines[model_file])
    if not _BASKET_QUANTITY_FIELD.search(model_text):
        return []

    candidates: list[_Candidate] = []
    for file in source.files:
        if not file.endswith("routes/basketItems.ts"):
            continue
        lines = source.lines[file]
        text = "\n".join(lines)
        if _QUANTITY_LOWER_BOUND.search(text) or _QUANTITY_LOWER_BOUND.search(model_text):
            continue
        if "QuantityModel.findOne" not in text:
            continue
        for index, line in enumerate(lines):
            if _is_code(line) and _QUANTITY_COMPARISON.search(line):
                candidates.append(_Candidate(
                    rule_id="juice.business-logic.negative-quantity",
                    title="Inventory comparison lacks a non-negative quantity guard",
                    description=(
                        "The basket quantity flow compares inventory against a supplied quantity "
                        "while the projected route and BasketItem model show no non-negative lower bound."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Check negative, zero and positive quantities against an owned inventory control.",
                    evidence_files=(model_file,),
                ))
    return candidates


def _detect_generated_api_candidates(source: RepositorySource) -> list[_Candidate]:
    server_file = next(
        (file for file in source.files if file == "server.ts" or file.endswith("/server.ts")),
        None,
    )
    if server_file is None:
        return []
    server_lines = source.lines[server_file]
    active_lines = [
        (index, line) for index, line in enumerate(server_lines)
        if _is_code(line)
    ]
    server_text = "\n".join(line for _, line in active_lines)
    candidates: list[_Candidate] = []

    resource_lines = [
        index for index, line in active_lines
        if _FINALE_RESOURCE.search(line)
    ]
    if (
        resource_lines
        and _AUTO_PRODUCT.search(server_text)
        and _PRODUCT_POST_CONTROL.search(server_text)
        and _PRODUCT_DELETE_CONTROL.search(server_text)
        and not _PRODUCT_PUT_CONTROL.search(server_text)
    ):
        candidates.append(_Candidate(
            rule_id="juice.authorization.generated-product-put",
            title="Generated Product resource lacks an explicit PUT authorization control",
            description=(
                "The projected Finale resource generates Product endpoints while active POST "
                "and DELETE routes have security middleware but no active Product PUT authorization "
                "middleware is present. Commented-out route hints are excluded."
            ),
            file=server_file,
            line=resource_lines[0] + 1,
            rationale="Compare generated Product PUT access with the controlled POST and DELETE routes.",
        ))

    feedback_model_files = [
        file for file in source.files
        if file.endswith("models/feedback.ts")
        and "class Feedback" in "\n".join(source.lines[file])
        and "Feedback.init" in "\n".join(source.lines[file])
    ]
    if _AUTO_FEEDBACK.search(server_text):
        for file in feedback_model_files:
            for index, line in enumerate(source.lines[file]):
                if _is_code(line) and _FEEDBACK_FIELD.search(line):
                    candidates.append(_Candidate(
                        rule_id="juice.access-control.generated-feedback-user-id",
                        title="Generated Feedback resource exposes its UserId field",
                        description=(
                            "The Feedback model defines a writable UserId field and the projected "
                            "server registers that model in a generated resource without excluding the field."
                        ),
                        file=file,
                        line=index + 1,
                        rationale="Compare generated Feedback writes with a private-field exclusion control.",
                        evidence_files=(server_file,),
                    ))
    return candidates


def _detect_additional_source_candidates(source: RepositorySource) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for file in source.files:
        lines = source.lines[file]
        text = "\n".join(lines)

        password_guard_lines = [
            index for index, line in enumerate(lines)
            if _is_code(line) and _OPTIONAL_CURRENT_PASSWORD.search(line)
        ]
        if password_guard_lines and _PASSWORD_UPDATE.search(text):
            update_index = next(
                index for index, line in enumerate(lines)
                if _is_code(line) and _PASSWORD_UPDATE.search(line)
            )
            preceding_guards = [index for index in password_guard_lines if index < update_index]
            if not preceding_guards:
                continue
            guard_index = preceding_guards[0]
            candidates.append(_Candidate(
                rule_id="juice.authentication.optional-current-password",
                title="Password change accepts an optional current-password guard",
                description=(
                    "The projected password-change flow checks the current password only "
                    "when a request value is present before updating the password."
                ),
                file=file,
                line=guard_index + 1,
                rationale="Verify that omitting current-password is rejected before any password update.",
            ))

        for index, line in enumerate(lines):
            if _is_code(line) and _CLIENT_ROLE_ASSIGNMENT.search(line):
                candidates.append(_Candidate(
                    rule_id="juice.authorization.client-role-setter",
                    title="User role setter persists its caller-provided role",
                    description=(
                        "A model role setter writes its role parameter directly to the role field; "
                        "the server-assigned-role contract needs an independent check."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Register a bounded fixture and read back the server-assigned role.",
                ))

            if _REQUEST_SELECTOR.search(line) and _REVIEW_UPDATE.search(text):
                candidates.append(_Candidate(
                    rule_id="juice.nosql-injection.request-selector",
                    title="Request object id is passed directly as a review selector",
                    description=(
                        "A request body id is used directly in the selector of a review update; "
                        "scalar validation and operator-object handling need verification."
                    ),
                    file=file,
                    line=index + 1,
                    rationale="Use a scalar-valid and operator-shaped control with independent readback.",
                ))
                if not _review_selector_has_owner_predicate(lines, index):
                    candidates.append(_Candidate(
                        rule_id="juice.access-control.review-selector-without-owner",
                        title="Review update selector does not bind the authenticated owner",
                        description=(
                            "A review update selects by a request-controlled id without an owner "
                            "predicate in the projected selector window."
                        ),
                        file=file,
                        line=index + 1,
                        rationale="Compare owner and non-owner fixtures and require an owner-bound selector.",
                    ))

            if _BASKET_LAST_SELECTOR.search(line) and _BASKET_RAW_PARSE.search(text):
                preceding = lines[max(0, index - 24):index]
                has_first_selector = any(
                    _is_code(previous) and _BASKET_FIRST_SELECTOR.search(previous)
                    for previous in preceding
                )
                duplicate_rejected = any(
                    _is_code(previous) and _BASKET_DUPLICATE_REJECTION.search(previous)
                    for previous in preceding
                )
                same_selector = bool(_BASKET_FIRST_SELECTOR.search(line))
                if has_first_selector and not duplicate_rejected and not same_selector:
                    candidates.append(_Candidate(
                        rule_id="juice.access-control.inconsistent-basket-selector",
                        title="Basket ownership validation and persistence use different selectors",
                        description=(
                            "The projected basket flow validates the first parsed BasketId but "
                            "persists the last parsed BasketId, leaving duplicate-field handling "
                            "inconsistent between the guard and the saved record."
                        ),
                        file=file,
                        line=index + 1,
                        rationale="Submit duplicate BasketId controls and verify the saved owner-bound record.",
                    ))

        allowlist_indices = [
            index for index, line in enumerate(lines)
            if _is_code(line) and _FILE_ALLOWLIST.search(line)
        ]
        null_indices = [
            index for index, line in enumerate(lines)
            if _is_code(line) and _NULL_NORMALIZATION.search(line)
        ]
        send_indices = [
            index for index, line in enumerate(lines)
            if _is_code(line) and _SEND_FILE.search(line)
        ]
        if any(
            allowlist < normalize < send
            for allowlist in allowlist_indices
            for normalize in null_indices
            for send in send_indices
        ):
            normalize_index = next(
                normalize for normalize in null_indices
                if any(
                    allowlist < normalize < send
                    for allowlist in allowlist_indices
                    for send in send_indices
                )
            )
            candidates.append(_Candidate(
                rule_id="juice.file-validation.filename-normalization",
                title="Filename normalization follows the extension allowlist",
                description=(
                    "The projected file-serving flow applies null-byte filename normalization "
                    "after extension validation and before sendFile."
                ),
                file=file,
                line=normalize_index + 1,
                rationale="Check encoded-null and ordinary filename controls without host execution.",
            ))
    return candidates


class JuiceSourceDetector:
    """Run deterministic, bounded source detectors over a trusted projection."""

    def __init__(self, *, max_candidates: int = DEFAULT_MAX_CANDIDATES) -> None:
        if max_candidates < 1:
            raise ValueError("max_candidates must be positive")
        self.max_candidates = max_candidates

    def detect(
        self,
        source: RepositorySource,
        *,
        inventory: ProjectDiscoveryResult | None = None,
    ) -> list[Finding]:
        service_resolver = inventory.resolve_component if inventory else None
        candidates = _collect_candidates(source, self.max_candidates)
        return [
            _normalise_candidate(candidate, source, service_resolver)
            for candidate in candidates
        ]

    def scan(self, profile: object, source: RepositorySource) -> list[Finding]:
        """Preferred campaign-facing entry point: profile metadata, projected source."""

        resolver = getattr(profile, "resolve_service", None)
        service_resolver = resolver if callable(resolver) else None
        candidates = _collect_candidates(source, self.max_candidates)
        return [
            _normalise_candidate(candidate, source, service_resolver)
            for candidate in candidates
        ]


def detect_juice_source_findings(
    source: RepositorySource,
    *,
    inventory: ProjectDiscoveryResult | None = None,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> list[Finding]:
    """Convenience entry point for the production source-detector pass."""

    return JuiceSourceDetector(max_candidates=max_candidates).detect(source, inventory=inventory)


def scan(
    profile: object,
    source: RepositorySource,
    *,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> list[Finding]:
    """Campaign-facing convenience wrapper; it never opens target paths itself."""

    return JuiceSourceDetector(max_candidates=max_candidates).scan(profile, source)


def detect_juice_source_candidates(
    profile: object,
    source: RepositorySource,
    *,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> list[Finding]:
    """Stable descriptive alias for campaign integration."""

    return scan(profile, source, max_candidates=max_candidates)


__all__ = [
    "JuiceSourceDetector",
    "detect_juice_source_candidates",
    "detect_juice_source_findings",
    "scan",
]
