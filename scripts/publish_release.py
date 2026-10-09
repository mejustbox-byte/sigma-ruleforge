"""Publish checked build artifacts from the main-branch CI job only."""

import hashlib
import json
import os
import tomllib
import urllib.error
import urllib.request
from pathlib import Path


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if (
        repository != "mejustbox-byte/sigma-ruleforge"
        or os.environ["GITHUB_REF"] != "refs/heads/main"
    ):
        raise SystemExit("Release publication requires the upstream main branch")
    token = os.environ["GH_TOKEN"]
    commit = os.environ["GITHUB_SHA"]
    version = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    tag = "v" + version
    files = [
        Path("dist") / f"sigma_ruleforge-{version}{suffix}"
        for suffix in (".tar.gz", "-py3-none-any.whl")
    ]
    for path in files:
        if not path.is_file():
            raise SystemExit(f"Missing release artifact: {path.name}")
    checksum = Path("dist/SHA256SUMS")
    checksum.write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files),
        encoding="utf-8",
    )
    files.append(checksum)
    base = "https://api.github.com/repos/" + repository

    def request(url, method="GET", payload=None, content_type="application/json"):
        data = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": content_type,
            },
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read()
            return json.loads(body) if body else None

    try:
        release = request(base + "/releases/tags/" + tag)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        release = None
    if release and not release["draft"]:
        print(f"{tag} already published; immutable release artifacts retained")
        return
    if release and release["target_commitish"] != commit:
        raise SystemExit("Existing draft targets a different commit; refusing to replace it")
    notes = (Path("docs") / f"RELEASE-{version}.md").read_text(encoding="utf-8")
    if release is None:
        release = request(
            base + "/releases",
            "POST",
            {
                "tag_name": tag,
                "target_commitish": commit,
                "name": "Sigma RuleForge " + version,
                "body": notes,
                "draft": True,
                "prerelease": False,
            },
        )
    for asset in release.get("assets", []):
        request(base + f"/releases/assets/{asset['id']}", "DELETE")
    for path in files:
        url = f"https://uploads.github.com/repos/{repository}/releases/{release['id']}/assets?name={path.name}"
        request(url, "POST", path.read_bytes(), "application/octet-stream")
    published = request(base + f"/releases/{release['id']}", "PATCH", {"draft": False})
    print(published["html_url"])


if __name__ == "__main__":
    main()
