import hashlib


def hash(toHash: str, algorithm):
    """
    Hashes the input string with the algorithm given.
    algorithm must be in hashlib.algorithms_available.
    """
    hasher = hashlib.new(algorithm)
    hasher.update(toHash)
    return hasher.hexdigest()
