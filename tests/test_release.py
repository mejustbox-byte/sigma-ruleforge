"""Exercise release publication with a fake HTTP service, without credentials."""

import importlib.util
import json
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "publish_release", ROOT / "scripts/publish_release.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Response:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.data).encode()


def setup_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", "mejustbox-byte/sigma-ruleforge")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GH_TOKEN", "synthetic-test-token")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="0.1.1"\n')
    (tmp_path / "dist").mkdir()
    for suffix in (".tar.gz", "-py3-none-any.whl"):
        (tmp_path / "dist" / ("sigma_ruleforge-0.1.1" + suffix)).write_bytes(b"synthetic artifact")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/RELEASE-0.1.1.md").write_text("Product release notes")


def test_publish_only_after_uploads(tmp_path, monkeypatch):
    setup_files(tmp_path, monkeypatch)
    calls = []

    def request(req, timeout):
        calls.append((req.get_method(), req.full_url, req.data))
        if req.get_method() == "GET":
            raise urllib.error.HTTPError(req.full_url, 404, "absent", {}, None)
        if (
            req.get_method() == "POST"
            and "/releases" in req.full_url
            and "/assets?" not in req.full_url
        ):
            payload = json.loads(req.data)
            assert payload["target_commitish"] == "a" * 40
            assert payload["draft"] is True
            return Response({"id": 123, "assets": []})
        if req.get_method() == "PATCH":
            assert len([c for c in calls if "/assets?" in c[1]]) == 3
            assert json.loads(req.data) == {"draft": False}
            return Response(
                {
                    "html_url": "https://github.com/mejustbox-byte/sigma-ruleforge/releases/tag/v0.1.1"
                }
            )
        return Response({"id": 456})

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", request)
    MODULE.main()
    assert (tmp_path / "dist/SHA256SUMS").read_text().count("\n") == 2
    assert calls[-1][0] == "PATCH"


def test_published_release_immutable(tmp_path, monkeypatch):
    setup_files(tmp_path, monkeypatch)
    calls = []

    def request(req, timeout):
        calls.append(req.get_method())
        return Response({"draft": False})

    monkeypatch.setattr(MODULE.urllib.request, "urlopen", request)
    MODULE.main()
    assert calls == ["GET"]


def test_release_branch_guard(tmp_path, monkeypatch):
    setup_files(tmp_path, monkeypatch)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/feature")
    with pytest.raises(SystemExit, match="upstream main"):
        MODULE.main()
