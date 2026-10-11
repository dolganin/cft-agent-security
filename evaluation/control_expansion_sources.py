"""A03.1 manually scoped original source oracles, independent of model judgment."""
from evaluation.control_catalog import anchor
from fix_verification.workspace import safe_file

SPECS = [
    {"id":"JS-SAFE-AUTH-101", "family":"authentication", "root":"twofactor-disable-password-gate",
     "file":"routes/2fa.ts", "begin":"export async function disable", "end":None,
     "property":"The 2FA disable function rejects a password that differs from the authenticated cache's stored hash before clearing the TOTP secret.",
     "expressions":["if (user.password !== security.hash(password)) {", "throw new Error('Password doesnt match stored password')", "userModel.totpSecret = ''"],
     "endpoint":"POST /rest/2fa/disable", "scope":"source cached-password gate only; does not establish database reauthentication, cache freshness or hashing strength"},
    {"id":"JS-SAFE-FILE-101", "family":"file-validation", "root":"profile-upload-byte-signature-gate",
     "file":"routes/profileImageFileUpload.ts", "begin":"export function profileImageFileUpload", "end":None,
     "property":"The upload handler obtains type from buffer bytes and returns before file write for unknown or non-image detected type.",
     "expressions":["const uploadedFileType = await fileType.fromBuffer(buffer)", "if (uploadedFileType === undefined) {", "if (uploadedFileType === null || !uploadedFileType.mime.startsWith('image')) {", "await fs.writeFile(filePath, buffer)"],
     "endpoint":"POST /profile/image/file", "scope":"source acceptance gate only; no claim that every accepted image is harmless"},
    {"id":"JS-SAFE-PATH-101", "family":"path-traversal", "root":"profile-upload-server-selected-filename",
     "file":"routes/profileImageFileUpload.ts", "begin":"export function profileImageFileUpload", "end":None,
     "property":"The upload destination expression uses cached server user ID and detected type extension rather than the client filename.",
     "expressions":["const loggedInUser = security.authenticatedUsers.get(req.cookies.token)", "const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`", "await fs.writeFile(filePath, buffer)"],
     "endpoint":"POST /profile/image/file", "scope":"source filename construction only; no claim about arbitrary corrupted authentication cache"},
    {"id":"JS-SAFE-BIZ-101", "family":"business-logic", "root":"basket-quantity-stock-upper-bound",
     "file":"routes/basketItems.ts", "begin":"async function quantityCheck (", "end":None,
     "property":"For an existing stock row, the quantity check only calls next when requested quantity does not exceed stock; the alternative returns 400.",
     "expressions":["if (product.quantity >= quantity) {", "next()", "res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })"],
     "endpoint":"POST /api/BasketItems", "scope":"source upper-bound branch only; negative quantities remain vulnerable and are not a twin of JS-BIZ-001"},
]


def source_proof(target, spec):
    lines = safe_file(target, spec["file"]).read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(spec["begin"])]
    if len(starts) != 1:
        raise ValueError("Source function correspondence failed")
    start = starts[0]
    region = "\n".join(lines[start:])
    positions = [region.find(expression) for expression in spec["expressions"]]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise ValueError("Reviewed source control flow changed")
    # Exact branch bodies, not mere token absence, prove the early exits.
    if spec["id"] == "JS-SAFE-AUTH-101" and "if (user.password !== security.hash(password)) {\n      throw new Error('Password doesnt match stored password')\n    }" not in region:
        raise ValueError("Password rejection body changed")
    if spec["id"] == "JS-SAFE-FILE-101":
        for condition in spec["expressions"][1:3]:
            branch = region.split(condition, 1)[1].split("\n    }", 1)[0]
            if "return" not in branch or "next(new Error" not in branch:
                raise ValueError("File rejection does not exit")
    if spec["id"] == "JS-SAFE-BIZ-101" and "if (product.quantity >= quantity) { // enough in stock?\n      next()\n    } else {\n      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })\n    }" not in region:
        raise ValueError("Stock rejection branch changed")
    return {"oracle":"reviewed_exact_source_branch_v1", "scope":spec["scope"],
            "expressions":spec["expressions"], "anchor":anchor(target, spec["file"], start+1, len(lines)),
            "runtime_verdict":None}
