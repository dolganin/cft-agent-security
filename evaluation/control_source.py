"""Narrow reviewed source property; no runtime SQL verdict or model conclusion."""
from pathlib import Path

from evaluation.control_catalog import anchor, sha
from fix_verification.workspace import safe_file

FILE = "routes/address.ts"
EXPRESSION = "const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })"


def orm_proof(target: Path) -> dict:
    source = safe_file(target, FILE).read_text(encoding="utf-8").splitlines()
    matches = [number for number, line in enumerate(source, 1) if line.strip() == EXPRESSION]
    if len(matches) != 1:
        raise ValueError("Reviewed ORM expression changed")
    number = matches[0]
    if source[number - 3].strip() != "export function getAddressById () {":
        raise ValueError("Reviewed function scope changed")
    model = safe_file(target, "models/address.ts").read_bytes()
    if "} from 'sequelize'" not in model.decode() or "Address as AddressModel" not in model.decode():
        raise ValueError("ORM model provenance changed")
    return {"schema_version":"a03.source_proof.v1", "property":"address_id_is_orm_where_value",
            "anchor":anchor(target, FILE, number, number), "model_sha256":sha(model),
            "reviewed_expression":EXPRESSION, "proof_scope":"source construction only; no runtime injection verdict"}
