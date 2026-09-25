"""tools/patch_lambda_zip.py must change ONLY the handler entry (including in zips with Windows backslash paths)."""
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import patch_lambda_zip as plz  # noqa: E402


def _make_zip(path, with_handler=True):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        if with_handler:
            z.writestr("lambda_agent_worker.py", b"OLD HANDLER")
        z.writestr("requests\\__init__.py", b"# backslash path, as PowerShell Compress-Archive writes it")
        z.writestr("certifi/cacert.pem", b"PEM" * 100)


def test_only_the_handler_entry_changes(tmp_path):
    src, out, handler = tmp_path / "in.zip", tmp_path / "sub" / "out.zip", tmp_path / "lambda_agent_worker.py"
    _make_zip(src)
    handler.write_bytes(b"NEW HANDLER")
    copied, old_sha, new_sha = plz.patch(str(src), str(handler), str(out))
    assert copied == 2 and old_sha != new_sha
    with zipfile.ZipFile(src) as a, zipfile.ZipFile(out) as b:
        assert [i.filename for i in a.infolist()] == [i.filename for i in b.infolist()]   # same names, same order
        for info in a.infolist():
            if info.filename == "lambda_agent_worker.py":
                assert b.read(info.filename) == b"NEW HANDLER"
            else:
                assert b.read(info.filename) == a.read(info.filename)
    with zipfile.ZipFile(src) as a:
        assert a.read("lambda_agent_worker.py") == b"OLD HANDLER"      # input untouched


def test_refuses_when_the_handler_is_not_in_the_zip(tmp_path):
    src, handler = tmp_path / "in.zip", tmp_path / "lambda_agent_worker.py"
    _make_zip(src, with_handler=False)
    handler.write_bytes(b"NEW")
    with pytest.raises(ValueError, match="no root-level entry"):
        plz.patch(str(src), str(handler), str(tmp_path / "out.zip"))


def test_cli_refuses_to_overwrite_the_input(tmp_path):
    src, handler = tmp_path / "in.zip", tmp_path / "lambda_agent_worker.py"
    _make_zip(src)
    handler.write_bytes(b"NEW")
    sys.argv = ["patch_lambda_zip.py", "--zip", str(src), "--handler", str(handler), "--out", str(src)]
    assert plz.main() == 2
