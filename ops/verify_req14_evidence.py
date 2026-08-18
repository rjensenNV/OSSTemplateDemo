#!/usr/bin/env python3
"""Replay frozen REQ-14 evidence against public GitHub files.

This is a bounded pre-collection verifier. It reads only repository metadata
and the exact pinned files named by the evidence contract; it never performs
discovery, clones a repository, mutates collector state, or publishes data.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector.catalog import (  # noqa: E402
    REQ14_DIRECT_LIBRARY_CANDIDATES,
    REQ14_EVIDENCE_CONTRACT,
)
from collector.scan import scan_repo  # noqa: E402
from collector.triage import triage_tree  # noqa: E402


def _gh(*arguments: str) -> str:
    result = subprocess.run(
        ["gh", "api", *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            result.stderr.strip()
            or "gh api failed: %s" % " ".join(arguments)
        )
    return result.stdout


def _safe_relative_path(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("unsafe evidence path: %r" % value)
    return relative


class GitHubEvidence:
    def __init__(self) -> None:
        self.repositories: dict[str, dict] = {}
        self.files: dict[tuple[str, str, str], bytes] = {}

    def repository(self, full_name: str) -> dict:
        if full_name not in self.repositories:
            payload = json.loads(_gh("repos/%s" % full_name))
            if (
                payload.get("visibility") != "public"
                or payload.get("private")
                or payload.get("fork")
                or payload.get("archived")
            ):
                raise RuntimeError(
                    "%s is not a public, non-fork, non-archived repository"
                    % full_name
                )
            self.repositories[full_name] = payload
        return self.repositories[full_name]

    def file(self, full_name: str, commit: str, path: str) -> bytes:
        key = (full_name, commit, path)
        if key in self.files:
            return self.files[key]
        self.repository(full_name)
        relative = _safe_relative_path(path)
        endpoint = "repos/%s/contents/%s?ref=%s" % (
            full_name,
            quote("/".join(relative.parts), safe="/"),
            commit,
        )
        payload = json.loads(_gh(endpoint))
        if payload.get("type") != "file":
            raise RuntimeError(
                "%s@%s:%s is not a regular file"
                % (full_name, commit, path)
            )
        try:
            content = base64.b64decode(
                payload["content"], validate=False
            )
        except (KeyError, ValueError) as exc:
            raise RuntimeError(
                "GitHub returned invalid content for %s@%s:%s"
                % (full_name, commit, path)
            ) from exc
        self.files[key] = content
        return content


def _fixture(path: str, content: bytes) -> tempfile.TemporaryDirectory:
    temporary = tempfile.TemporaryDirectory()
    checkout = Path(temporary.name)
    relative = _safe_relative_path(path)
    destination = checkout.joinpath(*relative.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    subprocess.run(
        ["git", "-C", str(checkout), "init", "-q", "-b", "main"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "Evidence Replay"],
        check=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout), "config", "user.email",
            "evidence-replay@example.invalid",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "add", "--", str(relative)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "commit", "-q", "-m", "pinned evidence"],
        check=True,
    )
    return temporary


def _records(selected_bands: set[str]):
    contract = REQ14_EVIDENCE_CONTRACT
    if "confirmed" in selected_bands:
        for library_id, entry in contract["libraries"].items():
            if entry["bands"]["confirmed"] != "evaluated":
                continue
            yield "confirmed", library_id, entry["public_positive"]
            for positive in entry.get(
                "additional_public_positives", ()
            ):
                yield "confirmed", library_id, positive
    for band in ("bundled", "targeted"):
        if band not in selected_bands:
            continue
        for library_id, certification in contract[
            "band_certifications"
        ][band]["libraries"].items():
            yield band, library_id, certification["public_positive"]


def _replay(
    github: GitHubEvidence,
    band: str,
    library: dict,
    positive: dict,
) -> None:
    content = github.file(
        positive["repository"],
        positive["commit"],
        positive["path"],
    )
    temporary = _fixture(positive["path"], content)
    try:
        checkout = Path(temporary.name)
        if band == "confirmed":
            triage = triage_tree(
                checkout,
                [library],
                full_name=positive["repository"],
            )
            if not triage.direct_files.get(library["id"]):
                raise AssertionError(
                    "confirmed replay produced no direct evidence"
                )
            return
        lower_only = dict(library)
        lower_only["classification_coverage"] = [band]
        result = scan_repo(
            positive["repository"],
            [lower_only],
            lambda _message: None,
            checkout=str(checkout),
            include_history=False,
        )
        actual = (
            (result or {}).get("libraries", {})
            .get(library["id"], {})
            .get("classification")
        )
        if actual != band:
            raise AssertionError(
                "expected %s, replay produced %r" % (band, actual)
            )
    finally:
        temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Replay exact pinned REQ-14 public evidence without collection"
        )
    )
    parser.add_argument(
        "--band",
        choices=("all", "confirmed", "bundled", "targeted"),
        default="all",
    )
    arguments = parser.parse_args()
    selected = (
        {"confirmed", "bundled", "targeted"}
        if arguments.band == "all"
        else {arguments.band}
    )
    libraries = {
        library["id"]: library
        for library in REQ14_DIRECT_LIBRARY_CANDIDATES
    }
    github = GitHubEvidence()
    failures = []
    verified = {band: 0 for band in selected}
    for band, library_id, positive in _records(selected):
        try:
            _replay(github, band, libraries[library_id], positive)
            verified[band] += 1
            print("ok\t%s\t%s\t%s" % (
                band, library_id, positive["repository"]
            ))
        except Exception as exc:
            failures.append((band, library_id, str(exc)))
            print(
                "FAIL\t%s\t%s\t%s" % (band, library_id, exc),
                file=sys.stderr,
            )
    summary = {
        "verified": verified,
        "repositories_checked": len(github.repositories),
        "pinned_files_checked": len(github.files),
        "failures": len(failures),
    }
    print(json.dumps(summary, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
