import pytest

from discovery.service import ProjectDiscovery


@pytest.mark.parametrize(('instructions', 'expected'), [
    ('EXPOSE 8000', 8000),
    ('EXPOSE 8000/tcp', 8000),
    ('EXPOSE 8000 9000', None),
    ('EXPOSE 99999', None),
    ('EXPOSE $PORT', None),
    ('EXPOSE 8000\nFROM scratch\nEXPOSE 9000', 9000),
])
def test_dockerfile_port_is_unique_literal_in_final_stage(tmp_path, instructions, expected):
    (tmp_path / 'Dockerfile').write_text('FROM scratch\n' + instructions + '\n')
    discovery = ProjectDiscovery()
    profile = discovery.build_profile(discovery.discover(tmp_path))
    assert next(iter(profile.services.values())).internal_port == expected
