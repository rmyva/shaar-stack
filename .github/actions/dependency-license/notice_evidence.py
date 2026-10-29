#!/usr/bin/env python3
"""CI-only collector of verbatim legal-material evidence from Cargo inputs.

This records evidence, not license conclusions, artifact coverage, or compliance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_SOURCE_MAP_BYTES = 8 * 1024 * 1024
MAX_SOURCE_FILES = 100_000
MAX_SOURCE_DIRECTORIES = 20_000
MAX_SOURCE_DEPTH = 64
MAX_COLLECTED_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024 * 1024
# Exact leading source bytes in the reviewed libp2p-dns 0.45.0 archive.
DNS_HEADER_BYTES = 1124
DNS_HEADER_SHA256 = "22375f95ada42f478cc29687320886b83f0d59971ac6968755c12f6d95e207ca"


class EvidenceError(ValueError):
    """Input evidence is missing, ambiguous, or unsafe."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lstat(path: Path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise EvidenceError(f"unsafe reparse/link path component: {path}")
    return info


def _check_chain(path: Path) -> Path:
    """Reject links in every existing component before resolving anything."""
    path = Path(os.path.abspath(path))
    for component in reversed((path, *path.parents)):
        try:
            info = _lstat(component)
        except EvidenceError:
            raise
        except OSError as exc:
            raise EvidenceError(f"missing/unreadable path component: {component}") from exc
        if not (stat.S_ISDIR(info.st_mode) or component == path and stat.S_ISREG(info.st_mode)):
            raise EvidenceError(f"unsafe path component: {component}")
    return path


def _source_root(path: Path, manifest_path: str) -> Path:
    raw = Path(path)
    _check_chain(raw)
    root = raw.resolve(strict=True)
    if not root.is_dir():
        raise EvidenceError("source root is not a directory")
    manifest = Path(manifest_path)
    _check_chain(manifest)
    if manifest.resolve(strict=True) != (root / "Cargo.toml").resolve(strict=True):
        raise EvidenceError("mapped source root does not contain metadata manifest_path")
    return root


def _candidate_kind(name: str) -> str | None:
    upper = name.upper()
    if upper.startswith(("LICENSE", "LICENCE", "COPYING")):
        return "license"
    if upper.startswith("NOTICE"):
        return "notice"
    if upper.startswith(("COPYRIGHT", "AUTHORS")):
        return "copyright"
    return None


def _read_material(path: Path, root: Path, remaining: int) -> dict:
    info = _lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise EvidenceError(f"unsafe legal-material entry: {path}")
    if path.stat().st_nlink > 1:
        raise EvidenceError(f"hard-linked legal-material entry: {path}")
    relative = path.relative_to(root).as_posix()
    if any(part in (".", "..") for part in PurePosixPath(relative).parts):
        raise EvidenceError("unsafe relative path")
    try:
        with path.open("rb") as stream:
            data = stream.read(min(MAX_FILE_BYTES, remaining) + 1)
        if len(data) > MAX_FILE_BYTES:
            raise EvidenceError(f"legal material exceeds size limit: {relative}")
        if len(data) > remaining:
            raise EvidenceError("total collected material exceeds size limit")
    except OSError as exc:
        raise EvidenceError(f"unreadable legal material: {relative}") from exc
    return {"path": relative, "sha256": _digest(data), "size": len(data), "bytes_hex": data.hex()}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, max_bytes: int):
    try:
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise EvidenceError(f"JSON input exceeds size limit: {path}")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid metadata/source map: {exc}") from exc


def collect(metadata_path: Path, source_map_path: Path, selected_ids: set[str] | None = None) -> tuple[dict, dict[str, Path]]:
    metadata = _load_json(metadata_path, MAX_METADATA_BYTES)
    source_map = _load_json(source_map_path, MAX_SOURCE_MAP_BYTES)
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    nodes = resolve.get("nodes") if isinstance(resolve, dict) else None
    if not isinstance(packages, list) or not isinstance(nodes, list) or not nodes:
        raise EvidenceError("Cargo metadata must contain packages and resolved nodes")
    if not isinstance(source_map, dict):
        raise EvidenceError("source map must map exact Cargo package IDs to source roots")
    by_id = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise EvidenceError("malformed Cargo package")
        if package["id"] in by_id:
            raise EvidenceError("duplicate Cargo package identity")
        by_id[package["id"]] = package
    node_ids = set()
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not isinstance(node.get("deps"), list):
            raise EvidenceError("malformed resolved graph node/edges")
        if node["id"] in node_ids:
            raise EvidenceError("duplicate resolved graph node")
        node_ids.add(node["id"])
        for edge in node["deps"]:
            if not isinstance(edge, dict) or not isinstance(edge.get("pkg"), str) or edge["pkg"] not in by_id:
                raise EvidenceError("malformed or dangling resolved graph edge")
            if not isinstance(edge.get("dep_kinds"), list):
                raise EvidenceError("malformed dependency edge kinds")
    if node_ids != set(by_id):
        raise EvidenceError("metadata package set does not exactly match resolved nodes")
    if set(source_map) != node_ids or any(not isinstance(v, str) for v in source_map.values()):
        raise EvidenceError("source map must cover exactly the resolved package IDs")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(workspace_members, list) or any(not isinstance(member, str) for member in workspace_members):
        raise EvidenceError("metadata must identify workspace_members")
    workspace_ids = set(workspace_members)
    if not workspace_ids.issubset(node_ids):
        raise EvidenceError("workspace member missing from resolved graph")

    if selected_ids is not None and (not selected_ids or not selected_ids.issubset(node_ids)):
        raise EvidenceError("selected package IDs are missing from metadata")
    entries, excluded_workspace = [], []
    roots_by_id = {}
    collected_bytes = 0
    # These counters are shared across every source tree visited by this collection.
    file_count = directory_count = 0
    for package_id in sorted(node_ids if selected_ids is None else selected_ids, key=lambda x: x.encode("utf-8")):
        package = by_id[package_id]
        if not isinstance(package.get("manifest_path"), str):
            raise EvidenceError("package lacks manifest_path")
        root = _source_root(Path(source_map[package_id]), package["manifest_path"])
        roots_by_id[package_id] = root
        if package_id in workspace_ids:
            excluded_workspace.append(package_id)
            continue
        license_expression = package.get("license")
        license_file = package.get("license_file")
        if not isinstance(package.get("name"), str) or not package["name"].strip():
            raise EvidenceError("package lacks a valid name")
        if not isinstance(package.get("version"), str) or not package["version"].strip():
            raise EvidenceError("package lacks a valid version")
        if package.get("source") is not None and (not isinstance(package["source"], str) or not package["source"].strip()):
            raise EvidenceError("package has an invalid source identity")
        if license_expression is not None and (not isinstance(license_expression, str) or not license_expression.strip()):
            raise EvidenceError("invalid package license declaration")
        if license_expression is None and license_file is None:
            raise EvidenceError("missing license declaration and license_file")
        if license_file is not None and (not isinstance(license_file, str) or not license_file):
            raise EvidenceError("invalid metadata license_file")
        files = []
        pending = [(root, 0)]
        while pending:
            current_path, depth = pending.pop()
            if depth > MAX_SOURCE_DEPTH:
                raise EvidenceError("source-tree depth exceeds limit")
            try:
                with os.scandir(current_path) as scan:
                    for entry in scan:
                        p = current_path / entry.name
                        if entry.is_dir(follow_symlinks=False):
                            info = _lstat(p)
                            directory_count += 1
                            if directory_count > MAX_SOURCE_DIRECTORIES:
                                raise EvidenceError("source-tree directory count exceeds limit")
                            if depth + 1 > MAX_SOURCE_DEPTH:
                                raise EvidenceError("source-tree depth exceeds limit")
                            if not stat.S_ISDIR(info.st_mode):
                                raise EvidenceError(f"unsafe source entry: {p}")
                            pending.append((p, depth + 1))
                            continue
                        file_count += 1
                        if file_count > MAX_SOURCE_FILES:
                            raise EvidenceError("source-tree file count exceeds limit")
                        info = _lstat(p)
                        if not stat.S_ISREG(info.st_mode):
                            raise EvidenceError(f"unsafe source entry: {p}")
                        kind = _candidate_kind(entry.name)
                        if kind is None:
                            continue
                        if info.st_size > MAX_FILE_BYTES:
                            relative = p.relative_to(root).as_posix()
                            raise EvidenceError(f"legal material exceeds size limit: {relative}")
                        if collected_bytes + info.st_size > MAX_COLLECTED_BYTES:
                            raise EvidenceError("total collected material exceeds size limit")
                        remaining = min(MAX_COLLECTED_BYTES - collected_bytes, MAX_FILE_BYTES)
                        material = _read_material(p, root, remaining)
                        collected_bytes += material["size"]
                        if collected_bytes > MAX_COLLECTED_BYTES:
                            raise EvidenceError("total collected material exceeds size limit")
                        if kind == "license" and material["size"] == 0:
                            raise EvidenceError(f"empty license candidate: {material['path']}")
                        material["kind"] = kind
                        files.append(material)
            except OSError as exc:
                raise EvidenceError("source-tree traversal failed") from exc
        if license_file is not None:
            if "\\\\" in license_file:
                raise EvidenceError("unsafe metadata license_file path")
            license_file_path = Path(license_file)
            if license_file_path.is_absolute():
                _check_chain(license_file_path)
                try:
                    explicit = license_file_path.resolve(strict=True)
                    relative_file = explicit.relative_to(root)
                except (OSError, ValueError) as exc:
                    raise EvidenceError("metadata license_file escapes source root") from exc
                rel = PurePosixPath(relative_file.as_posix())
            else:
                rel = PurePosixPath(license_file)
                if any(part in ("", ".", "..") for part in rel.parts):
                    raise EvidenceError("unsafe metadata license_file path")
                explicit = root.joinpath(*rel.parts)
                _check_chain(explicit)
                try:
                    explicit.resolve(strict=True).relative_to(root)
                except (OSError, ValueError) as exc:
                    raise EvidenceError("metadata license_file escapes source root") from exc
            if not explicit.is_file():
                raise EvidenceError("metadata license_file is missing")
            if all(f["path"] != rel.as_posix() for f in files):
                remaining = min(MAX_COLLECTED_BYTES - collected_bytes, MAX_FILE_BYTES)
                material = _read_material(explicit, root, remaining)
                if material["size"] == 0:
                    raise EvidenceError("metadata license_file is empty")
                collected_bytes += material["size"]
                material["kind"] = "license"
                files.append(material)
        # This one reviewed package carries its license in a source header, not a
        # license-named file. Retain the exact prefix, pinned independently of the
        # prepared code following it; never treat arbitrary source as a license.
        if (package["name"], package["version"], package.get("source"), license_expression) == ("libp2p-dns", "0.45.0", None, "MIT"):
            header_path = root / "src" / "lib.rs"
            _check_chain(header_path)
            material = _read_material(header_path, root, min(MAX_COLLECTED_BYTES - collected_bytes, MAX_FILE_BYTES))
            data = bytes.fromhex(material["bytes_hex"])
            header = data[:DNS_HEADER_BYTES]
            if len(header) != DNS_HEADER_BYTES or _digest(header) != DNS_HEADER_SHA256 or not data[DNS_HEADER_BYTES:].startswith(b"//!"):
                raise EvidenceError("reviewed DNS embedded license header missing or changed")
            if collected_bytes + len(header) > MAX_COLLECTED_BYTES:
                raise EvidenceError("total collected material exceeds size limit")
            collected_bytes += len(header)
            files.append({"path": "src/lib.rs", "kind": "license", "sha256": _digest(header),
                          "size": len(header), "bytes_hex": header.hex(),
                          "byte_range": [0, len(header)]})
        files.sort(key=lambda f: f["path"].encode("utf-8"))
        if not any(f["kind"] == "license" and f["size"] > 0 for f in files):
            raise EvidenceError(f"no license evidence for {package_id}")
        entries.append({"package_id": package_id, "name": package.get("name"), "version": package.get("version"), "source": package.get("source"), "declared_license_expression": license_expression, "metadata_license_file": license_file, "materials": files})
    return {"format": "cargo-notice-evidence-v1", "entries": entries,
            "excluded_workspace_package_ids": excluded_workspace,
            "limitations": ["Workspace packages are recorded as excluded identities; their project licensing is not collected by this third-party evidence collector.", "Evidence only: does not establish correctness, completeness, permission, or legal compliance.", "No SPDX parsing, alternative selection, copyright inference, artifact mapping, archive provenance, or prepared-source comparison is performed.", "Collected bytes are verbatim hex; absence of a discovered file is not evidence of absence of obligations.", "Cargo package IDs and source values are retained verbatim and may contain host-specific paths; output is deterministic only for identical metadata and mapped tree contents. The supplied source map is not independently proven to cover artifact contents."]}, roots_by_id


def _write_output(output: Path, data: bytes, inputs: list[Path], source_roots: list[Path]) -> None:
    output = Path(os.path.abspath(output))
    parent = _check_chain(output.parent)
    if output.exists() or output.is_symlink():
        raise EvidenceError("output already exists")
    output_resolved = output.resolve(strict=False)
    for candidate in inputs:
        if output_resolved == Path(candidate).resolve(strict=True):
            raise EvidenceError("output aliases input")
    for root in source_roots:
        resolved_root = Path(root).resolve(strict=True)
        if output_resolved == resolved_root or resolved_root in output_resolved.parents:
            raise EvidenceError("output is inside source root")
    fd, temporary = tempfile.mkstemp(prefix=".notice-evidence-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
    except OSError as exc:
        raise EvidenceError(f"atomic no-clobber output failed: {exc}") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_manifest(output_path: Path, manifest: dict, inputs: list[Path], roots: list[Path]) -> None:
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    output = bytearray()
    for chunk in encoder.iterencode(manifest):
        encoded = chunk.encode("utf-8")
        if len(output) + len(encoded) + 1 > MAX_MANIFEST_BYTES:
            raise EvidenceError("serialized manifest exceeds size limit")
        output.extend(encoded)
    output.extend(b"\n")
    _write_output(output_path, bytes(output), inputs, roots)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path, help="actual cargo metadata --format-version 1 JSON")
    parser.add_argument("source_map", type=Path, help="JSON object mapping exact package IDs to prepared source roots")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest, roots_by_id = collect(args.metadata, args.source_map)
    write_manifest(args.output, manifest, [args.metadata, args.source_map], list(roots_by_id.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
