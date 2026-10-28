"""ACME Bank — deployment automation.

Provisions the SSH key used by the CI runner to push releases to the
payment-gateway hosts.
"""

import paramiko


def rotate_deploy_key(path: str = "/etc/acme/deploy_id_rsa"):
    """Generate a fresh RSA-3072 SSH key for the deploy runner."""
    key = paramiko.RSAKey.generate(bits=3072)
    key.write_private_key_file(path)
    return key.get_base64()
