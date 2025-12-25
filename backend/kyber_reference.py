import os

def kyber_reference_shared_secret() -> bytes:
    """
    Reference-mode Kyber shared secret.
    Used due to tooling limitations in the current environment.
    In production/research replacement: CRYSTALS-Kyber shared secret.
    """
    return os.urandom(32)
