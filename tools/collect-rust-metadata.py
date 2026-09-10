#!/usr/bin/env python3
"""Collect the exact Linux Cargo licence closure for PNPd."""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess


NOTICE_PREFIXES = ("LICENSE", "COPYING", "NOTICE", "UNLICENSE")
FIRST_PARTY_CRATES = {"peios", "peios-sys", "pnpd"}
ROOTS = {"pnpd"}


def metadata() -> dict:
    output = subprocess.check_output(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-gnu",
        ]
    )
    return json.loads(output)


def reachable_packages(data: dict) -> list[dict]:
    packages = {package["id"]: package for package in data["packages"]}
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
    roots = {
        package["id"]
        for package in data["packages"]
        if package["source"] is None and package["name"] in ROOTS
    }
    seen: set[str] = set()
    pending = list(roots)
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] in (None, "normal", "build") for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return sorted((packages[item] for item in seen), key=lambda p: (p["name"], p["version"]))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--licence-root", required=True, type=pathlib.Path)
    args = parser.parse_args()

    args.licence_root.mkdir(parents=True, exist_ok=True)
    rows = ["crate\tversion\tdeclared-license\tsource\n"]
    for package in reachable_packages(metadata()):
        expression = package.get("license")
        if not expression:
            raise SystemExit(f"{package['name']} {package['version']} has no declared licence")
        source = package.get("source") or "workspace/path"
        rows.append(f"{package['name']}\t{package['version']}\t{expression}\t{source}\n")

        if package["name"] in FIRST_PARTY_CRATES:
            continue
        crate_root = pathlib.Path(package["manifest_path"]).parent
        notices = sorted(
            path
            for path in crate_root.iterdir()
            if path.is_file() and path.name.upper().startswith(NOTICE_PREFIXES)
        )
        if not notices:
            raise SystemExit(
                f"{package['name']} {package['version']} has no distributable licence notice"
            )
        destination = args.licence_root / f"{package['name']}-{package['version']}"
        destination.mkdir()
        for notice in notices:
            shutil.copyfile(notice, destination / notice.name)

    (args.licence_root / "crate-licenses.tsv").write_text("".join(rows), encoding="utf-8")


if __name__ == "__main__":
    main()
