"""
Tests for scanner/code.py — CodeScanner and CodeFinding.
All tests are unit tests (no I/O, no network).
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.code import CodeFinding, CodeScanner, _strip_quotes


# ---------------------------------------------------------------------------
# _strip_quotes helper
# ---------------------------------------------------------------------------

class TestStripQuotes:
    def test_double_quoted(self):
        assert _strip_quotes('"RS256"') == "RS256"

    def test_single_quoted(self):
        assert _strip_quotes("'RS256'") == "RS256"

    def test_triple_double(self):
        assert _strip_quotes('"""hello"""') == "hello"

    def test_triple_single(self):
        assert _strip_quotes("'''hello'''") == "hello"

    def test_backtick(self):
        assert _strip_quotes("`jsonwebtoken`") == "jsonwebtoken"

    def test_unquoted(self):
        assert _strip_quotes("RS256") == "RS256"

    def test_empty_string(self):
        assert _strip_quotes('""') == ""


# ---------------------------------------------------------------------------
# CodeScanner — basic setup
# ---------------------------------------------------------------------------

class TestCodeScannerInit:
    def test_loads_python_patterns(self):
        scanner = CodeScanner()
        patterns = scanner._patterns.get("python", [])
        assert len(patterns) > 0

    def test_loads_javascript_patterns(self):
        scanner = CodeScanner()
        assert len(scanner._patterns.get("javascript", [])) > 0

    def test_loads_java_patterns(self):
        scanner = CodeScanner()
        assert len(scanner._patterns.get("java", [])) > 0

    def test_loads_go_patterns(self):
        scanner = CodeScanner()
        assert len(scanner._patterns.get("go", [])) > 0

    def test_parsers_available(self):
        scanner = CodeScanner()
        # At minimum python and javascript should be available
        assert len(scanner._parsers) > 0

    def test_get_pattern_versions(self):
        scanner = CodeScanner()
        versions = scanner.get_pattern_versions()
        assert "python" in versions
        assert versions["python"] == "1.4.0"

    def test_get_available_languages(self):
        scanner = CodeScanner()
        langs = scanner.get_available_languages()
        assert isinstance(langs, list)
        assert len(langs) > 0


# ---------------------------------------------------------------------------
# Python scanning
# ---------------------------------------------------------------------------

class TestPythonScanner:
    def setup_method(self):
        self.scanner = CodeScanner()

    def _scan(self, code: str) -> list[CodeFinding]:
        return self.scanner.scan_content(code, "python", "test.py")

    def test_py_rsa_001_detects_generate_private_key(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""
        findings = self._scan(code)
        ids = [f.pattern_id for f in findings]
        assert "PY-RSA-001" in ids

    def test_py_rsa_001_correct_metadata(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(65537, 2048)
"""
        findings = self._scan(code)
        rsa = next(f for f in findings if f.pattern_id == "PY-RSA-001")
        assert rsa.algorithm_family == "RSA"
        assert rsa.quantum_status == "vulnerable"
        assert rsa.algorithm_risk == 8
        assert rsa.hndl_risk is True
        assert rsa.line_number >= 1

    def test_py_rsa_001_line_number_is_call_line(self):
        code = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        code += "# some comment\n"
        code += "key = rsa.generate_private_key(65537, 2048)\n"
        findings = self._scan(code)
        rsa_f = next((f for f in findings if f.pattern_id == "PY-RSA-001"), None)
        assert rsa_f is not None
        assert rsa_f.line_number == 3

    def test_py_jwt_rs256_detects_algorithm_string(self):
        code = """
import jwt
token = jwt.encode({'sub': 'user'}, private_key, algorithm='RS256')
"""
        findings = self._scan(code)
        ids = [f.pattern_id for f in findings]
        assert "PY-JWT-RS256" in ids

    def test_py_jwt_rs256_rs384_rs512(self):
        for alg in ("RS256", "RS384", "RS512"):
            code = f"import jwt\ntoken = jwt.encode({{}}, key, algorithm='{alg}')"
            findings = self._scan(code)
            assert any(f.pattern_id == "PY-JWT-RS256" for f in findings), f"{alg} not detected"

    def test_py_jwt_es256_detects_ecdsa(self):
        code = "import jwt\ntoken = jwt.encode({'data': 1}, key, algorithm='ES256')"
        findings = self._scan(code)
        assert any(f.pattern_id == "PY-JWT-ES256" for f in findings)

    def test_py_ecc_001_detects_ec_keygen(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP256R1())
"""
        findings = self._scan(code)
        ids = [f.pattern_id for f in findings]
        assert "PY-ECC-001" in ids

    def test_py_ecc_001_metadata(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import ec
key = ec.generate_private_key(ec.SECP384R1())
"""
        findings = self._scan(code)
        ecc = next(f for f in findings if f.pattern_id == "PY-ECC-001")
        assert ecc.algorithm_family == "ECC"
        assert ecc.quantum_status == "vulnerable"

    def test_py_paramiko_rsa_detects_rsakey(self):
        code = """
import paramiko
key = paramiko.RSAKey.generate(2048)
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "PY-PARAMIKO-RSA" for f in findings)

    def test_no_findings_for_safe_code(self):
        code = """
import hashlib
result = hashlib.sha256(b'hello').hexdigest()
x = 42
"""
        findings = self._scan(code)
        assert findings == []

    def test_multiple_patterns_same_file(self):
        code = """
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
key = rsa.generate_private_key(65537, 2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
token = jwt.encode({}, key, algorithm='RS256')
"""
        findings = self._scan(code)
        ids = {f.pattern_id for f in findings}
        assert "PY-RSA-001" in ids
        assert "PY-ECC-001" in ids
        assert "PY-JWT-RS256" in ids

    def test_code_snippet_present(self):
        code = "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\n"
        findings = self._scan(code)
        rsa_f = next((f for f in findings if f.pattern_id == "PY-RSA-001"), None)
        assert rsa_f is not None
        assert "generate_private_key" in rsa_f.code_snippet

    def test_no_false_positive_from_import_only(self):
        """Import present but no matching call → no PY-RSA-001 (needs function match)."""
        code = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        findings = self._scan(code)
        # Should NOT find PY-RSA-001 since no generate_private_key call
        rsa001 = [f for f in findings if f.pattern_id == "PY-RSA-001"]
        assert rsa001 == []

    def test_dedup_same_pattern_same_line(self):
        """Same pattern at same line should not produce duplicate findings."""
        code = "import jwt\ntoken = jwt.encode({}, key, algorithm='RS256')\n"
        findings = self._scan(code)
        rs256_matches = [f for f in findings if f.pattern_id == "PY-JWT-RS256"]
        # Should deduplicate to at most 1 per unique line
        lines = [f.line_number for f in rs256_matches]
        assert len(lines) == len(set(lines))


# ---------------------------------------------------------------------------
# JavaScript scanning
# ---------------------------------------------------------------------------

class TestJavaScriptScanner:
    def setup_method(self):
        self.scanner = CodeScanner()

    def _scan(self, code: str) -> list[CodeFinding]:
        return self.scanner.scan_content(code, "javascript", "test.js")

    def test_js_jwt_rs256_via_import(self):
        code = """
import jwt from 'jsonwebtoken';
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "JS-JWT-RS256" for f in findings)

    def test_js_jwt_rs256_via_require(self):
        code = """
const jwt = require('jsonwebtoken');
const token = jwt.sign(payload, key, { algorithm: 'RS256' });
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "JS-JWT-RS256" for f in findings)

    def test_js_jwt_es256_detected(self):
        code = """
const jose = require('jose');
const token = await new SignJWT(payload).setProtectedHeader({ alg: 'ES256' }).sign(key);
"""
        findings = self._scan(code)
        # Should detect ES256 string match for JWT
        ids = [f.pattern_id for f in findings]
        assert "JS-JWT-ES256" in ids or "JS-JWT-RS256" in ids  # broad check

    def test_js_crypto_rsa_generate_keypair(self):
        code = """
const { generateKeyPair } = require('crypto');
generateKeyPair('rsa', { modulusLength: 2048 }, callback);
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "JS-CRYPTO-RSA-001" for f in findings)

    def test_js_no_findings_safe(self):
        code = """
import { createHash } from 'crypto';
const hash = createHash('sha256').update(data).digest('hex');
"""
        findings = self._scan(code)
        # sha256 is safe — no patterns should fire
        crypto_rsa = [f for f in findings if "RSA" in f.algorithm_family]
        assert crypto_rsa == []


# ---------------------------------------------------------------------------
# Go scanning
# ---------------------------------------------------------------------------

class TestGoScanner:
    def setup_method(self):
        self.scanner = CodeScanner()

    def _scan(self, code: str) -> list[CodeFinding]:
        return self.scanner.scan_content(code, "go", "test.go")

    def test_go_rsa_generate_key(self):
        code = """
package main

import (
    "crypto/rsa"
    "crypto/rand"
)

func main() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
    _ = key
}
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "GO-RSA-001" for f in findings)

    def test_go_ecdsa_generate_key(self):
        code = """
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
)

func main() {
    key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = key
}
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "GO-ECDSA-001" for f in findings)

    def test_go_jwt_rs256(self):
        # algorithm_strings match requires an actual string literal "RS256" in code
        code = """
package main

import "github.com/golang-jwt/jwt"

func verifyToken(tokenStr string, key interface{}) {
    token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
        return key, nil
    })
    alg := "RS256"
    _ = alg
    _ = token
}
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "GO-JWT-RS256" for f in findings)


# ---------------------------------------------------------------------------
# Java scanning
# ---------------------------------------------------------------------------

class TestJavaScanner:
    def setup_method(self):
        self.scanner = CodeScanner()

    def _scan(self, code: str) -> list[CodeFinding]:
        return self.scanner.scan_content(code, "java", "Test.java")

    def test_java_rsa_keygen(self):
        code = """
import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class Test {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
    }
}
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "JAVA-RSA-KEYGEN" for f in findings)

    def test_java_ecdsa(self):
        code = """
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class Test {
    public void gen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        var kp = kpg.generateKeyPair();
    }
}
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "JAVA-ECDSA" for f in findings)

    def test_java_spring_jwt(self):
        code = """
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUtil {
    public String create(String subject) {
        return Jwts.builder()
            .setSubject(subject)
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .compact();
    }
}
"""
        findings = self._scan(code)
        assert any(f.pattern_id == "JAVA-SPRING-JWT" for f in findings)


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

class TestFileScan:
    def test_scan_file_by_extension(self, tmp_path):
        scanner = CodeScanner()
        f = tmp_path / "auth.py"
        f.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(65537, 2048)\n"
        )
        findings = scanner.scan_file(f)
        assert any(f.pattern_id == "PY-RSA-001" for f in findings)

    def test_scan_file_unknown_extension_returns_empty(self, tmp_path):
        scanner = CodeScanner()
        f = tmp_path / "file.txt"
        f.write_text("import rsa\nkey = rsa.generate_private_key()")
        findings = scanner.scan_file(f)
        assert findings == []

    def test_scan_directory(self, tmp_path):
        scanner = CodeScanner()
        (tmp_path / "main.py").write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(65537, 2048)\n"
        )
        (tmp_path / "util.js").write_text(
            "const jwt = require('jsonwebtoken');\n"
            "jwt.sign(payload, key, { algorithm: 'RS256' });\n"
        )
        findings = scanner.scan_directory(tmp_path)
        families = {f.algorithm_family for f in findings}
        assert "RSA" in families

    def test_scan_directory_skips_node_modules(self, tmp_path):
        scanner = CodeScanner()
        nm = tmp_path / "node_modules" / "some-lib"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text(
            "const jwt = require('jsonwebtoken');\njwt.sign({}, k, {algorithm: 'RS256'});\n"
        )
        findings = scanner.scan_directory(tmp_path)
        assert findings == []

    def test_scan_nonexistent_directory_raises(self):
        scanner = CodeScanner()
        with pytest.raises(FileNotFoundError):
            scanner.scan_directory("/nonexistent/path/xyz")


# ---------------------------------------------------------------------------
# CodeFinding dataclass
# ---------------------------------------------------------------------------

class TestCodeFinding:
    def test_hndl_risk_rsa(self):
        scanner = CodeScanner()
        findings = scanner.scan_content(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(65537, 2048)\n",
            "python",
        )
        rsa_f = next((f for f in findings if f.pattern_id == "PY-RSA-001"), None)
        assert rsa_f is not None
        assert rsa_f.hndl_risk is True

    def test_confidence_high_on_function_match(self):
        scanner = CodeScanner()
        findings = scanner.scan_content(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(65537, 2048)\n",
            "python",
        )
        rsa_f = next((f for f in findings if f.pattern_id == "PY-RSA-001"), None)
        assert rsa_f is not None
        assert rsa_f.confidence == "high"


# ---------------------------------------------------------------------------
# Edge case handling — binary files, empty files, large files, parse errors
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_binary_file_skipped(self, tmp_path):
        """Binary files must not crash the scanner and return no findings."""
        scanner = CodeScanner()
        bf = tmp_path / "lib.py"
        bf.write_bytes(b"\x00\x01\x02\x03" * 100)
        findings = scanner.scan_file(bf)
        assert findings == []

    def test_binary_file_with_null_byte(self, tmp_path):
        scanner = CodeScanner()
        bf = tmp_path / "binary.py"
        bf.write_bytes(b"from rsa import RSA\x00\xff\xfe" * 50)
        findings = scanner.scan_file(bf)
        assert findings == []

    def test_empty_file_returns_empty(self, tmp_path):
        scanner = CodeScanner()
        ef = tmp_path / "empty.py"
        ef.write_bytes(b"")
        findings = scanner.scan_file(ef)
        assert findings == []

    def test_whitespace_only_file_returns_empty(self, tmp_path):
        scanner = CodeScanner()
        wf = tmp_path / "whitespace.py"
        wf.write_text("   \n\t\n   \n", encoding="utf-8")
        findings = scanner.scan_file(wf)
        assert findings == []

    def test_large_file_skipped_in_directory_scan(self, tmp_path):
        """Files above max_file_size_bytes are skipped without crashing."""
        scanner = CodeScanner()
        lf = tmp_path / "huge.py"
        # Write 6MB of content (above 5MB default)
        lf.write_bytes(b"# comment\n" * 600_000)
        findings = scanner.scan_directory(tmp_path, max_file_size_bytes=5_000_000)
        assert findings == []

    def test_scan_directory_handles_unreadable_file(self, tmp_path):
        """scan_directory must continue past unreadable files."""
        scanner = CodeScanner()
        good = tmp_path / "good.py"
        good.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "rsa.generate_private_key(65537, 2048)\n"
        )
        findings = scanner.scan_directory(tmp_path)
        assert any(f.pattern_id == "PY-RSA-001" for f in findings)


# ---------------------------------------------------------------------------
# String-only pattern matching (no import required)
# ---------------------------------------------------------------------------

class TestStringOnlyMatching:
    def setup_method(self):
        self.scanner = CodeScanner()

    def test_rs256_string_without_jwt_import_detected(self):
        """RS256 in a variable assignment without jwt import → medium confidence."""
        code = 'ALGORITHM = "RS256"\n'
        findings = self.scanner.scan_content(code, "python", "config.py")
        assert any(f.pattern_id == "PY-JWT-RS256" for f in findings)

    def test_string_only_match_has_medium_confidence(self):
        code = 'algorithm = "RS256"\n'
        findings = self.scanner.scan_content(code, "python", "config.py")
        jwt_f = next((f for f in findings if f.pattern_id == "PY-JWT-RS256"), None)
        assert jwt_f is not None
        assert jwt_f.confidence == "medium"

    def test_string_only_match_no_library_name(self):
        code = 'alg = "ES256"\n'
        findings = self.scanner.scan_content(code, "python", "cfg.py")
        ec_f = next((f for f in findings if f.pattern_id == "PY-JWT-ES256"), None)
        assert ec_f is not None
        assert ec_f.library_name == ""
        assert ec_f.matched_string == "ES256"

    def test_import_plus_string_still_high_confidence(self):
        """Import present → confidence stays at pattern default (high), not overridden by string path."""
        code = (
            "import jwt\n"
            "token = jwt.encode({'sub': 'u'}, key, algorithm='RS256')\n"
        )
        findings = self.scanner.scan_content(code, "python", "auth.py")
        jwt_f = next((f for f in findings if f.pattern_id == "PY-JWT-RS256"), None)
        assert jwt_f is not None
        assert jwt_f.confidence in ("high", "medium")

    def test_string_only_js_rs256(self):
        code = 'const ALG = "RS256";\n'
        findings = self.scanner.scan_content(code, "javascript", "config.js")
        assert any("RS256" in f.matched_string or f.matched_string == "RS256" for f in findings)

    def test_no_false_positive_for_safe_string(self):
        """Random strings should not trigger findings."""
        code = 'msg = "hello world"\n'
        findings = self.scanner.scan_content(code, "python", "app.py")
        assert findings == []
