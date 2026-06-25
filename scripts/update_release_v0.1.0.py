"""Update the v0.1.0 GitHub release body from scripts/RELEASE_v0.1.0.md."""

from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_MD = ROOT / "scripts" / "RELEASE_v0.1.0.md"


def _token() -> str:
    result = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n",
        capture_output=True,
        text=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    raise RuntimeError("could not read GitHub token from git credential helper")


def main() -> None:
    token = _token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }
    lookup = urllib.request.Request(
        "https://api.github.com/repos/Nuqasm/Qcap/releases/tags/v0.1.0",
        headers=headers,
    )
    release = json.load(urllib.request.urlopen(lookup))
    payload = json.dumps(
        {
            "tag_name": "v0.1.0",
            "name": "qcap v0.1.0 — first public release",
            "body": RELEASE_MD.read_text(encoding="utf-8"),
        }
    ).encode("utf-8")
    update = urllib.request.Request(
        f"https://api.github.com/repos/Nuqasm/Qcap/releases/{release['id']}",
        data=payload,
        headers=headers,
        method="PATCH",
    )
    result = json.load(urllib.request.urlopen(update))
    print(f"release updated: {result['html_url']}")


if __name__ == "__main__":
    main()
