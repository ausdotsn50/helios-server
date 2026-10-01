"""
Helios Election Workflows
"""

from helios.datatypes import LDObjectContainer

# Attach the scheme-dispatch interface to the ElGamal public-key classes.
# homomorphic.py calls pk.generate_plaintexts(), pk.random_randomness() and so
# on without naming a scheme; the Paillier side of that interface lives on
# PaillierPublicKey, and the ElGamal side is installed here because the
# experiment forbids editing algs.py and elgamal.py. See
# helios/crypto/scheme_adapters.py for what is attached and why.
from helios.crypto import scheme_adapters  # noqa: F401


class WorkflowObject(LDObjectContainer):
    pass
    
