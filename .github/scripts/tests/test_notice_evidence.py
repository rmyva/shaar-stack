"""CI-only contract tests for notice_evidence; never run as local project checks."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / "actions" / "dependency-license" / "notice_evidence.py"
spec = importlib.util.spec_from_file_location("notice_evidence", SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
selected_spec = importlib.util.spec_from_file_location("selected_evidence", SCRIPT.with_name("selected_evidence.py"))
selected = importlib.util.module_from_spec(selected_spec)
selected_spec.loader.exec_module(selected)


class NoticeEvidenceTests(unittest.TestCase):
    def fixture(self, root: Path, include_license: bool = True):
        source = root / "prepared"
        source.mkdir()
        if include_license:
            (source / "LICENSE-MIT").write_bytes(b" exact\r\nlicense\x00")
        (source / "NOTICE.txt").write_bytes(b"notice\xff")
        manifest = source / "Cargo.toml"
        manifest.write_text("[package]\\nname='pkg'\\nversion='1.0.0'\\n", encoding="utf-8")
        pkg_id = "registry+https://example.invalid#pkg@1.0.0"
        metadata = {"packages": [{"id": pkg_id, "name": "pkg", "version": "1.0.0", "source": "registry+https://example.invalid", "manifest_path": str(manifest), "license": "MIT OR Apache-2.0"}], "workspace_members": [], "resolve": {"nodes": [{"id": pkg_id, "deps": []}]}}
        m, s = root / "metadata.json", root / "sources.json"
        m.write_text(json.dumps(metadata), encoding="utf-8")
        s.write_text(json.dumps({pkg_id: str(source)}), encoding="utf-8")
        return pkg_id, m, s, source

    def test_selected_identity_matching_and_unsupported_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, source = self.fixture(root)
            data = json.loads(metadata.read_text(encoding="utf-8"))
            item = "pkg 1.0.0 registry+https://example.invalid"
            self.assertEqual(selected.select(data, {"package_ids": [item]}), {pkg_id})
            for bad in ("pkg 1.0.0 registry+https://other.invalid", "pkg 1.0.0 unsupported:source"):
                with self.assertRaises(selected.evidence.EvidenceError):
                    selected.select(data, {"package_ids": [bad]})
            data["packages"].append(dict(data["packages"][0], id="duplicate"))
            with self.assertRaisesRegex(selected.evidence.EvidenceError, "ambiguous"):
                selected.select(data, {"package_ids": [item]})
            result, _ = collector.collect(metadata, sources, {pkg_id})
            self.assertEqual(result["entries"][0]["package_id"], pkg_id)
            with self.assertRaisesRegex(collector.EvidenceError, "missing from metadata"):
                collector.collect(metadata, sources, {"missing"})

    def test_selected_subgraph_collects_path_and_git_but_not_excluded_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, _, source = self.fixture(root)
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["packages"][0]["source"] = None
            git_root = root / "git source"
            git_root.mkdir()
            (git_root / "Cargo.toml").write_text("manifest", encoding="utf-8")
            (git_root / "LICENSE").write_bytes(b"git license")
            git_source = "git+https://example.invalid/repo?rev=abc#abc"
            git_id = git_source + "#gitpkg@2.0.0"
            data["packages"].append(dict(data["packages"][0], id=git_id, name="gitpkg", version="2.0.0", source=git_source, manifest_path=str(git_root / "Cargo.toml")))
            excluded_root = root / "excluded"
            excluded_root.mkdir()
            (excluded_root / "Cargo.toml").write_text("manifest", encoding="utf-8")
            excluded_id = "excluded-id"
            data["packages"].append(dict(data["packages"][0], id=excluded_id, name="excluded", manifest_path=str(excluded_root / "Cargo.toml")))
            data["resolve"]["nodes"] = [
                {"id": pkg_id, "deps": [{"pkg": git_id, "dep_kinds": []}, {"pkg": excluded_id, "dep_kinds": []}]},
                {"id": git_id, "deps": []}, {"id": excluded_id, "deps": []},
            ]
            metadata.write_text(json.dumps(data), encoding="utf-8")
            path_item = "pkg 1.0.0 path+" + source.absolute().as_uri()
            git_item = "gitpkg 2.0.0 " + git_source
            listing = root / "list.json"
            listing.write_text("{}", encoding="utf-8")
            output, mapping = root / "evidence.json", root / "map.json"
            self.assertEqual(selected.select(data, {"package_ids": [path_item, git_item]}), {pkg_id, git_id})
            with self.assertRaisesRegex(selected.evidence.EvidenceError, "missing or ambiguous"):
                selected.select(data, {"package_ids": [git_item.replace("#abc", "#other")]})
            with mock.patch.object(selected.list_probe, "summarize", return_value={"package_ids": [path_item, git_item]}):
                selected.collect_selected(metadata, listing, output, mapping)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["selection"], {"kind": "cargo-deny-list", "package_count": 2})
            self.assertEqual({entry["package_id"] for entry in result["entries"]}, {pkg_id, git_id})
            self.assertEqual(set(json.loads(mapping.read_text(encoding="utf-8"))), {pkg_id, git_id, excluded_id})
            git_entry = next(entry for entry in result["entries"] if entry["package_id"] == git_id)
            self.assertEqual(bytes.fromhex(git_entry["materials"][0]["bytes_hex"]), b"git license")

    def test_preserves_exact_bytes_identity_and_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, _ = self.fixture(root)
            result, _ = collector.collect(metadata, sources)
            entry = result["entries"][0]
            self.assertEqual(entry["package_id"], pkg_id)
            self.assertEqual(entry["declared_license_expression"], "MIT OR Apache-2.0")
            by_name = {item["path"]: item for item in entry["materials"]}
            self.assertEqual(bytes.fromhex(by_name["LICENSE-MIT"]["bytes_hex"]), b" exact\r\nlicense\x00")
            self.assertEqual(bytes.fromhex(by_name["NOTICE.txt"]["bytes_hex"]), b"notice\xff")
            self.assertTrue(any("No SPDX parsing" in limitation for limitation in result["limitations"]))

    def test_empty_discovered_and_explicit_license_rejected(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                _, metadata, sources, source = self.fixture(root, not explicit)
                license_path = source / ("TERMS.txt" if explicit else "LICENSE-empty")
                license_path.write_bytes(b"")
                if explicit:
                    data = json.loads(metadata.read_text(encoding="utf-8"))
                    data["packages"][0]["license_file"] = "TERMS.txt"
                    metadata.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaisesRegex(collector.EvidenceError, "empty"):
                    collector.collect(metadata, sources)

    def test_duplicate_nested_metadata_and_source_map_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            metadata.write_text('{"outer":{"same":1,"same":2}}', encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "duplicate JSON key"):
                collector.collect(metadata, sources)
            metadata.write_text("{}", encoding="utf-8")
            sources.write_text('{"pkg":"one","pkg":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "duplicate JSON key"):
                collector.collect(metadata, sources)

    def test_reparse_attributes_rejected_by_helper_and_walk(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            directory = source / "junction-simulated"
            directory.mkdir()
            directory = directory.resolve(strict=True)
            real_lstat = Path.lstat
            def simulated_lstat(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                if path == directory:
                    class ReparseStat:
                        st_mode = info.st_mode
                        st_file_attributes = 0x400
                    return ReparseStat()
                return info
            with mock.patch.object(Path, "lstat", simulated_lstat):
                with self.assertRaisesRegex(collector.EvidenceError, "reparse"):
                    collector._lstat(directory)
                with self.assertRaisesRegex(collector.EvidenceError, "reparse"):
                    collector.collect(metadata, sources)

    def test_multi_package_permutation_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            second = root / "prepared-second"
            second.mkdir()
            (second / "Cargo.toml").write_text("manifest", encoding="utf-8")
            (second / "LICENSE").write_bytes(b"second")
            data = json.loads(metadata.read_text(encoding="utf-8"))
            pkg = dict(data["packages"][0], id="registry+https://example.invalid#other@2.0.0", name="other", manifest_path=str(second / "Cargo.toml"), version="2.0.0")
            data["packages"].append(pkg)
            data["resolve"]["nodes"].append({"id": pkg["id"], "deps": []})
            source_map = json.loads(sources.read_text(encoding="utf-8"))
            source_map[pkg["id"]] = str(second)
            metadata.write_text(json.dumps(data), encoding="utf-8")
            sources.write_text(json.dumps(source_map), encoding="utf-8")
            first = collector.collect(metadata, sources)[0]
            data["packages"].reverse()
            data["resolve"]["nodes"].reverse()
            metadata.write_text(json.dumps(data), encoding="utf-8")
            sources.write_text(json.dumps(dict(reversed(list(source_map.items())))), encoding="utf-8")
            self.assertEqual(first, collector.collect(metadata, sources)[0])

    def test_output_alias_symlink_and_existing_destination_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            with self.assertRaisesRegex(collector.EvidenceError, "already exists"):
                collector._write_output(metadata, b"bad", [metadata, sources], [source])
            link = root / "output-link"
            try:
                link.symlink_to(metadata)
            except (OSError, NotImplementedError):
                self.skipTest("file symlinks unavailable")
            with self.assertRaisesRegex(collector.EvidenceError, "already exists"):
                collector._write_output(link, b"bad", [metadata, sources], [source])

    def test_atomic_output_success_no_clobber_and_source_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            output = root / "evidence.json"
            collector._write_output(output, b"evidence", [metadata, sources], [source])
            self.assertEqual(output.read_bytes(), b"evidence")
            with self.assertRaisesRegex(collector.EvidenceError, "already exists"):
                collector._write_output(output, b"replacement", [metadata, sources], [source])
            with self.assertRaisesRegex(collector.EvidenceError, "inside source root"):
                collector._write_output(source / "LICENSE-overwrite", b"bad", [metadata, sources], [source])
            self.assertFalse((source / "LICENSE-overwrite").exists())

    def test_output_hardlink_alias_and_cleanup_on_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            hardlink = root / "metadata-hardlink"
            try:
                hardlink.hardlink_to(metadata)
            except (OSError, NotImplementedError):
                self.skipTest("hard links unavailable")
            with self.assertRaisesRegex(collector.EvidenceError, "output already exists"):
                collector._write_output(hardlink, b"bad", [metadata, sources], [source])
            def fail_link(src, dst):
                raise OSError("simulated link failure")
            with mock.patch.object(collector.os, "link", fail_link):
                with self.assertRaisesRegex(collector.EvidenceError, "no-clobber"):
                    collector._write_output(root / "failed.json", b"bad", [metadata, sources], [source])
            self.assertFalse((root / "failed.json").exists())
            self.assertEqual(list(root.glob(".notice-evidence-*")), [])

    def test_reviewed_dns_embedded_header_is_required_and_verbatim(self):
        header = (b'// Copyright 2018 Parity Technologies (UK) Ltd.\n'
                  b'//\n'
                  b'// Permission is hereby granted, free of charge, to any person obtaining a\n'
                  b'// copy of this software and associated documentation files (the "Software"),\n'
                  b'// to deal in the Software without restriction, including without limitation\n'
                  b'// the rights to use, copy, modify, merge, publish, distribute, sublicense,\n'
                  b'// and/or sell copies of the Software, and to permit persons to whom the\n'
                  b'// Software is furnished to do so, subject to the following conditions:\n'
                  b'//\n'
                  b'// The above copyright notice and this permission notice shall be included in\n'
                  b'// all copies or substantial portions of the Software.\n'
                  b'//\n'
                  b'// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS\n'
                  b'// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n'
                  b'// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n'
                  b'// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n'
                  b'// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n'
                  b'// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER\n'
                  b'// DEALINGS IN THE SOFTWARE.\n\n')
        for name, version, reviewed_header in (
            ("libp2p-dns", "0.45.0", header),
            ("libp2p-kad", "0.49.0", header),
            ("libp2p-swarm", "0.48.0", header.replace(b"Copyright 2018", b"Copyright 2019")),
            ("libp2p-relay", "0.22.0", header.replace(b"Copyright 2018 Parity Technologies (UK) Ltd.\n", b"Copyright 2019 Parity Technologies (UK) Ltd.\n// Copyright 2021 Protocol Labs.\n")),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                _, metadata, sources, source = self.fixture(root, False)
                data = json.loads(metadata.read_text(encoding="utf-8"))
                data["packages"][0].update(name=name, version=version, source=None, license="MIT")
                metadata.write_text(json.dumps(data), encoding="utf-8")
                src = source / "src"
                src.mkdir()
                lib = src / "lib.rs"
                lib.write_bytes(reviewed_header + b'//! docs\nmodified code')
                entry = collector.collect(metadata, sources)[0]["entries"][0]
                material = next(item for item in entry["materials"] if item["kind"] == "license")
                self.assertEqual(bytes.fromhex(material["bytes_hex"]), reviewed_header)
                self.assertEqual(material["byte_range"], [0, len(reviewed_header)])
                lib.write_bytes(reviewed_header[:-2] + b'x\n//! docs')
                with self.assertRaisesRegex(collector.EvidenceError, "header missing or changed"):
                    collector.collect(metadata, sources)
                lib.write_bytes(reviewed_header + b'not docs')
                with self.assertRaisesRegex(collector.EvidenceError, "header missing or changed"):
                    collector.collect(metadata, sources)
                lib.unlink()
                with self.assertRaises(collector.EvidenceError):
                    collector.collect(metadata, sources)
                lib.write_bytes(reviewed_header + b'//! docs')
                for field, value in (("name", "other"), ("version", "0.0.0"), ("source", "registry+https://example.invalid"), ("license", "Apache-2.0")):
                    changed = json.loads(json.dumps(data))
                    changed["packages"][0][field] = value
                    metadata.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaisesRegex(collector.EvidenceError, "no license evidence"):
                        collector.collect(metadata, sources)

    def test_missing_license_or_source_map_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root, False)
            with self.assertRaisesRegex(collector.EvidenceError, "no license evidence"):
                collector.collect(metadata, sources)
            sources.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "exactly"):
                collector.collect(metadata, sources)

    def test_source_substitution_and_bad_edges_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            other = root / "substitute"
            other.mkdir()
            (other / "Cargo.toml").write_text("manifest", encoding="utf-8")
            source_map = json.loads(sources.read_text(encoding="utf-8"))
            sources.write_text(json.dumps({next(iter(source_map)): str(other)}), encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "manifest_path"):
                collector.collect(metadata, sources)
            sources.write_text(json.dumps(source_map), encoding="utf-8")
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["resolve"]["nodes"][0]["deps"] = [{"pkg": "dangling", "dep_kinds": []}]
            metadata.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "dangling"):
                collector.collect(metadata, sources)

    def test_linked_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            alias = root / "linked-root"
            try:
                alias.symlink_to(source, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            mapping = json.loads(sources.read_text(encoding="utf-8"))
            mapping[next(iter(mapping))] = str(alias)
            sources.write_text(json.dumps(mapping), encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "reparse/link"):
                collector.collect(metadata, sources)

    def test_hardlinked_material_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            try:
                (source / "LICENSE-copy").hardlink_to(source / "LICENSE-MIT")
            except (OSError, NotImplementedError):
                self.skipTest("hard links unavailable")
            with self.assertRaisesRegex(collector.EvidenceError, "hard-linked legal-material"):
                collector.collect(metadata, sources)

    def test_workspace_root_protects_manifest_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, source = self.fixture(root, False)
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["workspace_members"] = [pkg_id]
            metadata.write_text(json.dumps(data), encoding="utf-8")
            manifest, roots = collector.collect(metadata, sources)
            self.assertIn(pkg_id, roots)
            output = source / "evidence.json"
            with self.assertRaisesRegex(collector.EvidenceError, "inside source root"):
                collector.write_manifest(output, manifest, [metadata, sources], list(roots.values()))
            self.assertFalse(output.exists())

    def test_selected_source_map_rejects_source_and_output_aliases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, _, source = self.fixture(root)
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["workspace_members"] = [pkg_id]
            metadata.write_text(json.dumps(data), encoding="utf-8")
            listing = root / "list.json"
            listing.write_text("{}", encoding="utf-8")
            summary = {"package_ids": ["pkg 1.0.0 registry+https://example.invalid"]}
            with mock.patch.object(selected.list_probe, "summarize", return_value=summary):
                with self.assertRaisesRegex(selected.evidence.EvidenceError, "inside source root"):
                    selected.collect_selected(metadata, listing, root / "output.json", source / "map.json")
                with self.assertRaisesRegex(selected.evidence.EvidenceError, "aliases output"):
                    selected.collect_selected(metadata, listing, root / "same.json", root / "same.json")
            self.assertFalse((source / "map.json").exists())
            self.assertFalse((root / "same.json").exists())

    def test_workspace_packages_are_recorded_as_excluded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, _ = self.fixture(root, False)
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["packages"][0]["source"] = None
            data["packages"][0]["license"] = None
            data["workspace_members"] = [pkg_id]
            metadata.write_text(json.dumps(data), encoding="utf-8")
            result = collector.collect(metadata, sources)[0]
            self.assertEqual(result["entries"], [])
            self.assertEqual(result["excluded_workspace_package_ids"], [pkg_id])

    def test_explicit_relative_license_file_preserves_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root, False)
            explicit = source / "legal" / "TERMS.txt"
            explicit.parent.mkdir()
            explicit.write_bytes(b"terms\r\n\x00")
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["packages"][0]["license_file"] = "legal/TERMS.txt"
            metadata.write_text(json.dumps(data), encoding="utf-8")
            entry = collector.collect(metadata, sources)[0]["entries"][0]
            item = next(item for item in entry["materials"] if item["path"] == "legal/TERMS.txt")
            self.assertEqual(bytes.fromhex(item["bytes_hex"]), b"terms\r\n\x00")

    def test_explicit_license_file_outside_workspace_is_collected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, source = self.fixture(root, False)
            explicit = source / "legal" / "TERMS-THIRD-PARTY.txt"
            explicit.parent.mkdir()
            explicit.write_bytes(b"third-party terms\r\n")
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["packages"][0]["license"] = None
            data["packages"][0]["license_file"] = str(explicit)
            data["workspace_members"] = []
            metadata.write_text(json.dumps(data), encoding="utf-8")
            result, _ = collector.collect(metadata, sources)
            self.assertEqual(len(result["entries"]), 1)
            entry = result["entries"][0]
            self.assertEqual(entry["package_id"], pkg_id)
            self.assertEqual(entry["metadata_license_file"], str(explicit))
            self.assertIsNone(entry["declared_license_expression"])
            material = next(item for item in entry["materials"] if item["path"] == "legal/TERMS-THIRD-PARTY.txt")
            self.assertEqual(bytes.fromhex(material["bytes_hex"]), b"third-party terms\r\n")
            self.assertEqual(result["excluded_workspace_package_ids"], [])

    def test_explicit_license_file_for_workspace_without_license_expression(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root, False)
            explicit = source / "legal" / "COPYING-THIRD-PARTY"
            explicit.parent.mkdir()
            explicit.write_bytes(b"workspace terms\r\n")
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["packages"][0]["source"] = None
            data["packages"][0]["license"] = None
            data["packages"][0]["license_file"] = str(explicit)
            data["workspace_members"] = [data["packages"][0]["id"]]
            metadata.write_text(json.dumps(data), encoding="utf-8")
            result, _ = collector.collect(metadata, sources)
            self.assertEqual(result["entries"], [])

    def test_deterministic_material_order(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            (source / "LICENSE-Z").write_bytes(b"z")
            (source / "LICENSE-A").write_bytes(b"a")
            result, _ = collector.collect(metadata, sources)
            names = [item["path"] for item in result["entries"][0]["materials"]]
            self.assertEqual(names, sorted(names, key=lambda name: name.encode("utf-8")))

    def test_symlink_material_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            link = source / "NOTICE-link"
            try:
                link.symlink_to(source / "NOTICE.txt")
            except (OSError, NotImplementedError):
                self.skipTest("file symlinks unavailable")
            with self.assertRaisesRegex(collector.EvidenceError, "reparse/link"):
                collector.collect(metadata, sources)

    def test_rejects_incomplete_resolved_graph(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["resolve"]["nodes"] = []
            metadata.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(collector.EvidenceError, "resolved nodes"):
                collector.collect(metadata, sources)

    def test_material_size_limit_inclusive_and_exceeded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root, False)
            (source / "NOTICE.txt").unlink()
            with mock.patch.object(collector, "MAX_FILE_BYTES", 8), mock.patch.object(collector, "MAX_COLLECTED_BYTES", 64):
                license_path = source / "LICENSE-boundary"
                license_path.write_bytes(b"x" * 8)
                result, _ = collector.collect(metadata, sources)
                self.assertEqual(result["entries"][0]["materials"][0]["size"], 8)
                license_path.write_bytes(b"x" * 9)
                with self.assertRaisesRegex(collector.EvidenceError, "size limit"):
                    collector.collect(metadata, sources)

    def test_total_material_limit_inclusive_and_exceeded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root, False)
            (source / "NOTICE.txt").unlink()
            with mock.patch.object(collector, "MAX_COLLECTED_BYTES", 16), mock.patch.object(collector, "MAX_FILE_BYTES", 16):
                (source / "LICENSE-one").write_bytes(b"12345678")
                (source / "LICENSE-two").write_bytes(b"abcdefgh")
                collector.collect(metadata, sources)
                (source / "LICENSE-three").write_bytes(b"x")
                with self.assertRaisesRegex(collector.EvidenceError, "total collected material"):
                    collector.collect(metadata, sources)

    def test_input_byte_limits_with_mocked_small_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            metadata_limit = len(metadata.read_bytes())
            source_limit = len(sources.read_bytes())
            with mock.patch.object(collector, "MAX_METADATA_BYTES", metadata_limit), mock.patch.object(collector, "MAX_SOURCE_MAP_BYTES", source_limit):
                for path, limit in ((metadata, metadata_limit), (sources, source_limit)):
                    original = path.read_bytes()
                    exact = original + b" " * (limit - len(original))
                    path.write_bytes(exact)
                    collector.collect(metadata, sources)
                    path.write_bytes(exact + b" ")
                    with self.assertRaisesRegex(collector.EvidenceError, "size limit"):
                        collector.collect(metadata, sources)
                    path.write_bytes(original)

    def test_source_tree_count_and_depth_limits_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            with mock.patch.object(collector, "MAX_SOURCE_FILES", 3):
                collector.collect(metadata, sources)
                (source / "ordinary-one").touch()
                with self.assertRaisesRegex(collector.EvidenceError, "file count exceeds"):
                    collector.collect(metadata, sources)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            with mock.patch.object(collector, "MAX_SOURCE_DEPTH", 2):
                (source / "d").mkdir()
                (source / "d" / "d").mkdir()
                collector.collect(metadata, sources)
                (source / "d" / "d" / "d").mkdir()
                with self.assertRaisesRegex(collector.EvidenceError, "depth exceeds"):
                    collector.collect(metadata, sources)

    def test_global_material_limit_across_packages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, source = self.fixture(root, False)
            (source / "NOTICE.txt").unlink()
            second = root / "prepared-second"
            second.mkdir()
            (second / "Cargo.toml").write_text("manifest", encoding="utf-8")
            (second / "LICENSE").write_bytes(b"12345678")
            (source / "LICENSE").write_bytes(b"abcdefgh")
            data = json.loads(metadata.read_text(encoding="utf-8"))
            other_id = pkg_id + "-other"
            data["packages"].append(dict(data["packages"][0], id=other_id, name="other", manifest_path=str(second / "Cargo.toml")))
            data["resolve"]["nodes"].append({"id": other_id, "deps": []})
            metadata.write_text(json.dumps(data), encoding="utf-8")
            mapping = json.loads(sources.read_text(encoding="utf-8"))
            mapping[other_id] = str(second)
            sources.write_text(json.dumps(mapping), encoding="utf-8")
            with mock.patch.object(collector, "MAX_COLLECTED_BYTES", 15), mock.patch.object(collector, "MAX_FILE_BYTES", 8):
                with self.assertRaisesRegex(collector.EvidenceError, "total collected material"):
                    collector.collect(metadata, sources)

    def test_incremental_directory_limit_and_manifest_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, source = self.fixture(root)
            (source / "dir-a").mkdir()
            with mock.patch.object(collector, "MAX_SOURCE_DIRECTORIES", 1):
                collector.collect(metadata, sources)
                (source / "dir-b").mkdir()
                with self.assertRaisesRegex(collector.EvidenceError, "directory count exceeds"):
                    collector.collect(metadata, sources)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            args = mock.Mock(metadata=metadata, source_map=sources, output=root / "out.json")
            with mock.patch.object(collector.argparse.ArgumentParser, "parse_args", return_value=args), \
                 mock.patch.object(collector, "MAX_MANIFEST_BYTES", 128), \
                 mock.patch.object(collector, "_write_output") as output:
                with self.assertRaisesRegex(collector.EvidenceError, "manifest exceeds"):
                    collector.main()
                output.assert_not_called()
    def test_global_source_file_and_directory_limits_across_packages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg_id, metadata, sources, source = self.fixture(root)
            second = root / "prepared-second"
            second.mkdir()
            (second / "Cargo.toml").write_text("manifest", encoding="utf-8")
            (second / "LICENSE").write_bytes(b"second")
            (second / "ordinary-extra").touch()
            (source / "dir-one").mkdir()
            (second / "dir-one").mkdir()
            data = json.loads(metadata.read_text(encoding="utf-8"))
            other_id = pkg_id + "-other"
            data["packages"].append(dict(data["packages"][0], id=other_id, name="other", manifest_path=str(second / "Cargo.toml")))
            data["resolve"]["nodes"].append({"id": other_id, "deps": []})
            metadata.write_text(json.dumps(data), encoding="utf-8")
            mapping = json.loads(sources.read_text(encoding="utf-8"))
            mapping[other_id] = str(second)
            sources.write_text(json.dumps(mapping), encoding="utf-8")
            with mock.patch.object(collector, "MAX_SOURCE_FILES", 6), mock.patch.object(collector, "MAX_SOURCE_DIRECTORIES", 2):
                collector.collect(metadata, sources)
                (second / "ordinary-extra-2").touch()
                with self.assertRaisesRegex(collector.EvidenceError, "file count exceeds"):
                    collector.collect(metadata, sources)
                (second / "ordinary-extra-2").unlink()
                (second / "dir-two").mkdir()
                with self.assertRaisesRegex(collector.EvidenceError, "directory count exceeds"):
                    collector.collect(metadata, sources)

    def test_manifest_serialized_byte_limit_inclusive_and_exceeded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            manifest, _ = collector.collect(metadata, sources)
            exact_size = len(json.dumps(manifest, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")) + 1
            args = mock.Mock(metadata=metadata, source_map=sources, output=root / "out.json")
            with mock.patch.object(collector.argparse.ArgumentParser, "parse_args", return_value=args), mock.patch.object(collector, "MAX_MANIFEST_BYTES", exact_size):
                self.assertEqual(collector.main(), 0)
            self.assertEqual(args.output.stat().st_size, exact_size)
            args.output.unlink()
            with mock.patch.object(collector.argparse.ArgumentParser, "parse_args", return_value=args), mock.patch.object(collector, "MAX_MANIFEST_BYTES", exact_size - 1), mock.patch.object(collector, "_write_output") as output:
                with self.assertRaisesRegex(collector.EvidenceError, "manifest exceeds"):
                    collector.main()
                output.assert_not_called()
            self.assertFalse(args.output.exists())

    def test_json_main_writes_deterministic_serialized_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, metadata, sources, _ = self.fixture(root)
            output_path = root / "evidence.json"
            args = mock.Mock(metadata=metadata, source_map=sources, output=output_path)
            with mock.patch.object(collector.argparse.ArgumentParser, "parse_args", return_value=args):
                self.assertEqual(collector.main(), 0)
            serialized = output_path.read_bytes()
            parsed = json.loads(serialized)
            self.assertEqual(parsed["format"], "cargo-notice-evidence-v1")
            self.assertTrue(serialized.endswith(b"\n"))
            expected = json.dumps(parsed, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n"
            self.assertEqual(serialized, expected)


if __name__ == "__main__":
    unittest.main()
