from discovery.express_routes import build_express_source_map, link_candidates_to_routes
from schemas.discovery import ProjectDiscoveryResult
from schemas.scout import CandidateFinding


def test_direct_express_routes_have_stable_anchors_and_imported_handlers(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/search.ts").write_text("export function search() {}\n")
    (tmp_path / "server.ts").write_text(
        "import express from 'express'\n"
        "import { search } from './routes/search'\n"
        "const app = express()\n"
        "app.use(authenticate)\n"
        "app.get('/search', search())\n"
        "app.post(dynamicPath, search())\n"
        "// app.get('/fake', handler)\n",
    )
    inventory = ProjectDiscoveryResult(
        repository_root=tmp_path, project_files=["server.ts", "routes/search.ts"],
    )
    result = build_express_source_map(inventory)
    assert len(result.routes) == 2
    route = result.routes[0]
    assert (route.file, route.line_start, route.method, route.path) == (
        "server.ts", 5, "get", "/search",
    )
    assert route.handler_files == ["routes/search.ts"]
    assert route.middleware_before
    assert result.dynamic_routes == 1
    assert result.routes[1].path is None
    assert result == build_express_source_map(inventory)

    candidate = CandidateFinding(
        rule_id="sql-injection", title="Candidate", description="Unverified",
        file="routes/search.ts", line_start=1, provenance_paths=["routes/search.ts"],
        rationale="Read handler; authorization remains unknown",
    )
    link = link_candidates_to_routes([candidate], result)[0]
    assert link["binding_status"] == "ambiguous"
    assert link["authorization_assessment"] == "unknown"


def test_source_map_does_not_treat_unrelated_get_calls_as_express(tmp_path):
    (tmp_path / "app.ts").write_text("const cache = new Cache()\ncache.get('/private')\n")
    result = build_express_source_map(ProjectDiscoveryResult(
        repository_root=tmp_path, project_files=["app.ts"],
    ))
    assert result.routes == []
