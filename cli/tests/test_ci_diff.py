"""Unified-diff parsing for the CI gate."""
from seqr.ci.diff import parse_unified_diff

SIMPLE = """\
diff --git a/src/auth.py b/src/auth.py
index 111..222 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,2 +10,3 @@ def sign():
 context line
-old_removed_line
+new_line_11
+new_line_12
@@ -40,0 +42,1 @@
+new_line_42
"""


def test_parses_added_line_numbers_per_file():
    added = parse_unified_diff(SIMPLE)
    assert added == {"src/auth.py": {11, 12, 42}}


def test_removed_lines_do_not_advance_new_counter():
    # The removed line between context(10) and additions must not shift 11/12.
    added = parse_unified_diff(SIMPLE)
    assert 11 in added["src/auth.py"] and 12 in added["src/auth.py"]


def test_new_file_dev_null_source():
    diff = """\
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+import rsa
+rsa.newkeys(2048)
"""
    assert parse_unified_diff(diff) == {"new.py": {1, 2}}


def test_deleted_file_is_skipped():
    diff = """\
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-import rsa
-rsa.newkeys(2048)
"""
    assert parse_unified_diff(diff) == {}


def test_multiple_files():
    diff = """\
--- a/x.py
+++ b/x.py
@@ -1,0 +1,1 @@
+a
--- a/y/z.py
+++ b/y/z.py
@@ -5,0 +6,1 @@
+b
"""
    assert parse_unified_diff(diff) == {"x.py": {1}, "y/z.py": {6}}
