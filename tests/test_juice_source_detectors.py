from __future__ import annotations

from pathlib import Path

import pytest

from discovery.service import ProjectDiscovery
from pipeline.juice_source_detectors import (
    JuiceSourceDetector,
    detect_juice_source_candidates,
    detect_juice_source_findings,
    scan,
)
from schemas.discovery import ProjectDiscoveryResult
from schemas.target import TargetProfile
from tools.repository_source import RepositorySource


def _inventory(tmp_path: Path, files: dict[str, str]) -> ProjectDiscoveryResult:
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return ProjectDiscoveryResult(repository_root=tmp_path, project_files=list(files))


def _rules(findings):
    return {finding.rule_id for finding in findings}


def test_detector_emits_source_bound_unverified_access_candidates(tmp_path: Path):
    inventory = _inventory(tmp_path, {
        "routes/records.ts": """export async function get (req) {
  const row = await UserModel.findOne({ where: { UserId: req.body.UserId } })
  return row
}""",
        "routes/basket.ts": """export async function get (req) {
  const id = req.params.id
  const basket = await BasketModel.findOne({ where: { id } })
  return basket
}""",
    })

    findings = detect_juice_source_findings(
        RepositorySource(inventory),
        inventory=inventory,
    )

    assert _rules(findings) == {
        "juice.access-control.path-selected-record",
        "juice.access-control.request-owned-record",
    }
    assert all(finding.source == "juice_source_detector" for finding in findings)
    assert all(finding.severity is None for finding in findings)
    assert all(finding.provenance is not None for finding in findings)
    assert all(finding.provenance.anchor_status == "source_bound" for finding in findings)
    assert all(finding.provenance.observations[0].source == "juice_source_detector" for finding in findings)
    assert all("confirmed" not in finding.description.lower() for finding in findings)

    request_finding = next(
        finding for finding in findings
        if finding.rule_id == "juice.access-control.request-owned-record"
    )
    assert request_finding.file == "routes/records.ts"
    assert request_finding.line_start == 2
    assert request_finding.line_end == 2

    profile = TargetProfile.model_validate({
        "id": "pinned-juice",
        "services": {"api": {"root": "."}},
    })
    profile_findings = JuiceSourceDetector().scan(profile, RepositorySource(inventory))
    wrapper_findings = scan(profile, RepositorySource(inventory), max_candidates=8)
    alias_findings = detect_juice_source_candidates(profile, RepositorySource(inventory), max_candidates=8)
    assert {finding.service for finding in profile_findings} == {"api"}
    assert [finding.id for finding in wrapper_findings] == [finding.id for finding in profile_findings]
    assert [finding.id for finding in alias_findings] == [finding.id for finding in wrapper_findings]


def test_detector_covers_bounded_business_captcha_rate_and_metrics_signals(tmp_path: Path):
    inventory = _inventory(tmp_path, {
        "routes/business.ts": """const coupon = decodeURIComponent(params.coupon)
const discount = security.discountFromCoupon(coupon)
await basket.update({ coupon })
await WalletModel.increment({ balance: req.body.balance }, { where: { UserId: req.body.UserId } })""",
        "routes/captcha.ts": """const captcha = { captcha: expression, answer }
res.json(captcha)
const stored = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
if (stored && req.body.captcha === stored.answer) next()""",
        "server.ts": """const limiter = rateLimit({
  keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }
})
res.end(await register.metrics())""",
    })

    findings = detect_juice_source_findings(RepositorySource(inventory))
    assert _rules(findings) == {
        "juice.access-control.request-owned-record",
        "juice.business-logic.client-controlled-balance",
        "juice.business-logic.coupon-state",
        "juice.captcha.answer-disclosure",
        "juice.captcha.replayable-verification",
        "juice.rate-limiting.forwarded-client-ip",
        "juice.sensitive-data.metrics-exposure",
    }
    assert all(finding.provenance.anchor_status == "source_bound" for finding in findings)
    assert all(finding.line_start == finding.line_end for finding in findings)


def test_safe_counterparts_do_not_emit_the_same_source_signals(tmp_path: Path):
    inventory = _inventory(tmp_path, {
        "routes/safe.ts": """const user = security.authenticatedUsers.from(req)
const row = await UserModel.findOne({ where: { UserId: req.body.UserId } })
const id = req.params.id
const owner = security.authenticatedUsers.from(req)
const basket = await BasketModel.findOne({ where: { id } })
const coupon = trustedCoupon
const discount = security.discountFromCoupon(coupon)
const captcha = { expression, answer }
res.json({ captcha: captcha.expression })
const stored = await CaptchaModel.findOne({ where: { captchaId } })
if (stored && answer === stored.answer) await CaptchaModel.destroy({ where: { captchaId } })
const limiter = rateLimit({ keyGenerator ({ ip }) { return ip } })
res.end(await filteredMetrics())
await WalletModel.increment({ balance: 49 }, { where: { UserId: user.id } })""",
    })

    assert detect_juice_source_findings(RepositorySource(inventory)) == []


def test_additional_source_properties_match_and_safe_counterparts_do_not(tmp_path: Path):
    inventory = _inventory(tmp_path, {
        "routes/changePassword.ts": """const currentPassword = query.current
if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
  return res.status(401).send('wrong')
}
await user.update({ password: newPassword })""",
        "models/user.ts": """role: {
  set (role: string) {
    this.setDataValue('role', role)
  }
}""",
        "routes/updateProductReviews.ts": """db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } }
)""",
        "routes/basketItems.ts": """const result = utils.parseJsonCustom(req.rawBody)
const basketIds = []
const user = security.authenticatedUsers.from(req)
if (user && basketIds[0] && Number(user.bid) !== Number(basketIds[0])) {
  return res.status(401).send('invalid basket')
}
const basketItem = { BasketId: basketIds[basketIds.length - 1] }
await BasketItemModel.build(basketItem).save()""",
        "routes/fileServer.ts": """if (file && endsWithAllowlistedFileType(file)) {
  file = security.cutOffPoisonNullByte(file)
  res.sendFile(path.resolve('ftp/', file))
}""",
        "safe/changePassword.ts": """if (!currentPassword || security.hash(currentPassword) !== loggedInUser.data.password) {
  return res.status(401).send('wrong')
}
await user.update({ password: newPassword })""",
        "safe/user.ts": """set (role: string) {
  this.setDataValue('role', security.roles.customer)
}""",
        "safe/reviews.ts": """const id = typeof req.body.id === 'string' ? req.body.id : ''
const user = security.authenticatedUsers.from(req)
db.reviewsCollection.update(
  { _id: id, author: user.data.email },
  { $set: { message: req.body.message } }
)""",
        "safe/basketItems.ts": """const basketIds = []
const user = security.authenticatedUsers.from(req)
if (user && basketIds[0] && Number(user.bid) !== Number(basketIds[0])) {
  return res.status(401).send('invalid basket')
}
const basketItem = { BasketId: basketIds[0] }
await BasketItemModel.build(basketItem).save()""",
        "safe/basketDuplicate.ts": """const basketIds = []
if (basketIds.length > 1) {
  return res.status(400).send('duplicate basket')
}
if (user && basketIds[0] && Number(user.bid) !== Number(basketIds[0])) {
  return res.status(401).send('invalid basket')
}
const basketItem = { BasketId: basketIds[basketIds.length - 1] }
await BasketItemModel.build(basketItem).save()""",
        "safe/fileServer.ts": """file = security.cutOffPoisonNullByte(file)
if (file && endsWithAllowlistedFileType(file)) {
  res.sendFile(path.resolve('ftp/', file))
}""",
    })

    findings = detect_juice_source_findings(RepositorySource(inventory))
    assert _rules(findings) == {
        "juice.authentication.optional-current-password",
        "juice.authorization.client-role-setter",
        "juice.access-control.review-selector-without-owner",
        "juice.access-control.inconsistent-basket-selector",
        "juice.file-validation.filename-normalization",
        "juice.nosql-injection.request-selector",
    }
    assert {finding.file for finding in findings} == {
        "models/user.ts",
        "routes/basketItems.ts",
        "routes/changePassword.ts",
        "routes/fileServer.ts",
        "routes/updateProductReviews.ts",
    }
    assert all(finding.severity is None for finding in findings)
    assert all(finding.provenance.anchor_status == "source_bound" for finding in findings)


def test_final_production_source_extensions_require_cross_file_evidence(tmp_path: Path):
    vulnerable = _inventory(tmp_path / "vulnerable", {
        "frontend/src/app/search-result.component.ts": """const products = this.productService.search('')
this.trustProductDescription(products)
trustProductDescription (tableData) {
  tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
}
const queryParam = this.route.snapshot.queryParams.q
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)""",
        "routes/currentUser.ts": """const fieldsParam = req.query?.fields
const requestedFields = fieldsParam ? fieldsParam.split(',') : []
for (const field of requestedFields) {
  if (user?.data[field] !== undefined) response[field] = user.data[field]
}""",
        "routes/basketItems.ts": """const product = await QuantityModel.findOne({ where: { ProductId: id } })
if (product.quantity >= quantity) next()""",
        "models/basketitem.ts": """class BasketItem extends Model {
  quantity: DataTypes.INTEGER
}""",
        "models/feedback.ts": """class Feedback extends Model {}
Feedback.init({
  UserId: { type: DataTypes.INTEGER }
}, { sequelize })""",
        "server.ts": """app.post('/api/Products', security.isAuthorized())
// app.put('/api/Products/:id', security.isAuthorized())
app.delete('/api/Products/:id', security.denyAll())
const autoModels = [
  { name: 'Product', exclude: [], model: ProductModel },
  { name: 'Feedback', exclude: [], model: FeedbackModel }
]
finale.initialize({ app, sequelize: seq })
const resource = finale.resource({ model, endpoints })""",
    })

    findings = detect_juice_source_findings(RepositorySource(vulnerable))
    assert _rules(findings) == {
        "juice.xss.request-query-trusted-html",
        "juice.xss.product-description-trusted-html",
        "juice.sensitive-data.client-selected-user-fields",
        "juice.business-logic.negative-quantity",
        "juice.authorization.generated-product-put",
        "juice.access-control.generated-feedback-user-id",
    }
    assert {
        (finding.rule_id, finding.file, finding.line_start)
        for finding in findings
    } == {
        ("juice.xss.request-query-trusted-html", "frontend/src/app/search-result.component.ts", 7),
        ("juice.xss.product-description-trusted-html", "frontend/src/app/search-result.component.ts", 4),
        ("juice.sensitive-data.client-selected-user-fields", "routes/currentUser.ts", 4),
        ("juice.business-logic.negative-quantity", "routes/basketItems.ts", 2),
        ("juice.authorization.generated-product-put", "server.ts", 9),
        ("juice.access-control.generated-feedback-user-id", "models/feedback.ts", 3),
    }
    quantity_finding = next(
        finding for finding in findings
        if finding.rule_id == "juice.business-logic.negative-quantity"
    )
    assert quantity_finding.provenance.observations[0].provenance_paths == [
        "routes/basketItems.ts",
        "models/basketitem.ts",
    ]
    feedback_finding = next(
        finding for finding in findings
        if finding.rule_id == "juice.access-control.generated-feedback-user-id"
    )
    assert feedback_finding.provenance.observations[0].provenance_paths == [
        "models/feedback.ts",
        "server.ts",
    ]
    assert all(finding.severity is None for finding in findings)
    assert all(finding.provenance.anchor_status == "source_bound" for finding in findings)

    safe = _inventory(tmp_path / "safe", {
        "frontend/src/app/search-result.component.ts": """const products = this.productService.search('')
this.trustProductDescription(products)
trustProductDescription (tableData) {
  tableData[i].description = this.sanitizer.sanitize(SecurityContext.HTML, tableData[i].description)
}
const queryParam = this.route.snapshot.queryParams.q
this.searchValue = this.sanitizer.sanitize(SecurityContext.HTML, queryParam)""",
        "routes/currentUser.ts": """const allowedFields = ['id', 'email']
const fieldsParam = req.query?.fields
for (const field of fieldsParam.split(',')) {
  if (allowedFields.includes(field) && user?.data[field] !== undefined) response[field] = user.data[field]
}""",
        "routes/basketItems.ts": """const product = await QuantityModel.findOne({ where: { ProductId: id } })
if (quantity < 0) return res.status(400).send('invalid quantity')
if (product.quantity >= quantity) next()""",
        "models/basketitem.ts": """class BasketItem extends Model {
  quantity: { type: DataTypes.INTEGER, validate: { min: 0 } }
}""",
        "models/feedback.ts": """class Feedback extends Model {}
Feedback.init({
  UserId: { type: DataTypes.INTEGER }
}, { sequelize })""",
        "server.ts": """app.post('/api/Products', security.isAuthorized())
app.put('/api/Products/:id', security.isAuthorized())
app.delete('/api/Products/:id', security.denyAll())
const autoModels = [
  { name: 'Product', exclude: [], model: ProductModel },
  { name: 'Feedback', exclude: ['UserId'], model: FeedbackModel }
]
finale.initialize({ app, sequelize: seq })
const resource = finale.resource({ model, endpoints })""",
    })
    assert detect_juice_source_findings(RepositorySource(safe)) == []


def test_annotations_comments_and_reader_exclusions_are_not_detector_input(tmp_path: Path):
    inventory = _inventory(tmp_path, {
        "routes/visible.ts": """// detector text req.body.UserId must not be treated as code
// vuln-code-snippet hide-start source-only-marker
const hidden = await UserModel.findOne({ where: { UserId: req.body.UserId } })
// vuln-code-snippet hide-end source-only-marker
const visible = await UserModel.findOne({ where: { UserId: req.body.UserId } })""",
        "test/should-not-read.ts": "const row = await UserModel.findOne({ where: { UserId: req.body.UserId } })",
        "benchmark/oracle.ts": "const row = await UserModel.findOne({ where: { UserId: req.body.UserId } })",
    })
    oversized = tmp_path / "routes" / "oversized.ts"
    oversized.write_text("const row = await UserModel.findOne({ where: { UserId: req.body.UserId } })\n" + "x\n" * 70_000, encoding="utf-8")
    inventory.project_files.append("routes/oversized.ts")

    source = RepositorySource(inventory)
    findings = detect_juice_source_findings(source)

    assert source.files == ["routes/visible.ts"]
    assert len(findings) == 1
    assert findings[0].file == "routes/visible.ts"
    assert findings[0].line_start == 5


@pytest.mark.parametrize("target_relative", [
    "artifacts/benchmark-target/juice-shop",
])
def test_pinned_juice_shop_source_smoke(target_relative: str):
    root = Path(__file__).resolve().parents[1] / target_relative
    if not root.is_dir():
        pytest.skip("pinned Juice Shop source is not present in this checkout")

    inventory = ProjectDiscovery().discover(root)
    findings = detect_juice_source_findings(
        RepositorySource(inventory),
        inventory=inventory,
    )

    assert findings
    assert {finding.source for finding in findings} == {"juice_source_detector"}
    assert any(finding.rule_id.startswith("juice.access-control.") for finding in findings)
    assert any(finding.rule_id.startswith("juice.business-logic.") for finding in findings)
    assert any(finding.rule_id.startswith("juice.captcha.") for finding in findings)
    assert any(finding.rule_id == "juice.authentication.optional-current-password" for finding in findings)
    assert any(finding.rule_id == "juice.authorization.client-role-setter" for finding in findings)
    assert any(finding.rule_id == "juice.access-control.review-selector-without-owner" for finding in findings)
    assert any(finding.rule_id == "juice.access-control.inconsistent-basket-selector" for finding in findings)
    assert any(finding.rule_id == "juice.nosql-injection.request-selector" for finding in findings)
    assert any(finding.rule_id == "juice.file-validation.filename-normalization" for finding in findings)
    assert any(finding.rule_id == "juice.xss.request-query-trusted-html" for finding in findings)
    assert any(finding.rule_id == "juice.xss.product-description-trusted-html" for finding in findings)
    assert any(finding.rule_id == "juice.sensitive-data.client-selected-user-fields" for finding in findings)
    assert any(finding.rule_id == "juice.business-logic.negative-quantity" for finding in findings)
    assert any(finding.rule_id == "juice.authorization.generated-product-put" for finding in findings)
    assert any(finding.rule_id == "juice.access-control.generated-feedback-user-id" for finding in findings)
    assert all(finding.severity is None for finding in findings)
    assert all(finding.provenance.anchor_status == "source_bound" for finding in findings)
