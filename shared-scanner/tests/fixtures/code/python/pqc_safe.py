"""Fixture: Python file using only quantum-safe algorithms. Scanner must find 0 vulnerable findings."""
# AES-256 symmetric encryption — quantum-safe (Grover halves key space but 256-bit survives)
import hashlib

AES_KEY_SIZE = 256
HASH_ALGO = "sha3_256"

digest = hashlib.sha3_256(b"some data").hexdigest()
