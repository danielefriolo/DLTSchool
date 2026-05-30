import hashlib
import random
import secp256k1

PRIME_FIELD = secp256k1.FE.SIZE
GENERATOR_POINT = secp256k1.G
CYCLIC_PRIME_ORDER = secp256k1.GE.ORDER

def check_type(data, type):
    if not isinstance(data, type):
        raise TypeError(f"data must be of type '{type}'")

def convert_to_bytes(data):
    if isinstance(data, int):
        bits_per_byte = 8
        num_bits = data.bit_length()
        # Calculate the number of bytes needed to represent the integer
        num_bytes = (num_bits + bits_per_byte - 1) // bits_per_byte
        return data.to_bytes(num_bytes, byteorder='big')
    elif isinstance(data, str):
        return data.encode('utf-8')  # Using UTF-8 encoding for consistency
    raise TypeError(f"Unsupported type {type(data)}.")

def compute_sha256_hash(data):
    check_type(data, bytes)
    # Compute the SHA-256 hash of some bytes of data
    return hashlib.sha256(data).digest()

def convert_bytes_to_int(data):
    check_type(data, bytes)
    # Convert some bytes to its integer representation using big-endian byte order
    return int.from_bytes(data, 'big')

def generate_random_number(begin, end):
    return random.randrange(begin, end)

def generate_pair():
    sk = generate_random_number(1, CYCLIC_PRIME_ORDER)
    return sk*GENERATOR_POINT,sk

def verify_schnorr(signature, pubkey, message):
        A, s = signature
        # Compute the SHA-256 hash of the message
        message_hash = compute_sha256_hash(message)

        # Extract the x-coordinate of R and reduce it modulo the order of the group
        a = convert_to_bytes(int(A.x) % CYCLIC_PRIME_ORDER)

        # Compute the challenge e = H(r || pubkey || message_hash)
        c = compute_sha256_hash(a + convert_to_bytes(int(pubkey.x)) + message_hash)
        c_int = convert_bytes_to_int(c)

        # Verify the signature: check if s * G == A + c * pubkey
        P = s * GENERATOR_POINT
        Q = A + (c_int * pubkey)

        return P.x == Q.x and P.y == Q.y


def generate_signature_schnorr(sk, message, r):

    # Compute A = r * G
    A = r * GENERATOR_POINT

    # Recompute pk from sk
    pk = sk * GENERATOR_POINT

    # Extract the x-coordinate of A
    a = convert_to_bytes(int(A.x) % CYCLIC_PRIME_ORDER)
    # Compute the SHA-256 hash of the message
    message_hash = compute_sha256_hash(message)

    # Compute the challenge e = H(a || pubkey || message_hash)
    c = compute_sha256_hash(a + convert_to_bytes(int(pk.x)) + message_hash)
    c_int = convert_bytes_to_int(c)

    # Calculate the signature component s = k + e * privkey mod CYCLIC_PRIME_ORDER
    s = (r + c_int * sk) % CYCLIC_PRIME_ORDER

     # Return the signature components (R, s)
    return A, s

def generate_stealth_pk(pk2):
    ...
    return (r,pkS)

def retrieve_stealth_sk(pk2,sk2, pkS, sig):
    ...
    if  ..:
        return
    return False


def verify_schnorr(signature, pubkey, message):
        A, s = signature
        # Compute the SHA-256 hash of the message
        message_hash = compute_sha256_hash(message)

        # Extract the x-coordinate of R and reduce it modulo the order of the group
        a = convert_to_bytes(int(A.x) % CYCLIC_PRIME_ORDER)

        # Compute the challenge e = H(r || pubkey || message_hash)
        c = compute_sha256_hash(a + convert_to_bytes(int(pubkey.x)) + message_hash)
        c_int = convert_bytes_to_int(c)

        # Verify the signature: check if s * G == A + c * pubkey
        P = s * GENERATOR_POINT
        Q = A + (c_int * pubkey)

        return P.x == Q.x and P.y == Q.y



def verification_test_schnorr(signature, pubkey, message_bytes):
    A, s = signature
    # Test 1: verifies the malleated signature s+1
    is_valid_modified_s = verify_schnorr((A, (s+1) % CYCLIC_PRIME_ORDER), pubkey, message_bytes)
    print(f"Modified s+1 Signature valid: {is_valid_modified_s}")

    # Test 2: verifies the malleated signature -s
    is_valid_modified_neg_s = verify_schnorr((A, (-s % CYCLIC_PRIME_ORDER)), pubkey, message_bytes)
    print(f"Modified -s Signature valid: {is_valid_modified_neg_s}")

    # Test 3: use Wrong R
    A_wrong =  generate_random_number(1, CYCLIC_PRIME_ORDER) * GENERATOR_POINT
    is_valid_wrong_A = verify_schnorr((A_wrong, s), pubkey, message_bytes)
    print(f"Wrong A part of Signature valid: {is_valid_wrong_A}")

    # Test 4: verify correct signature
    is_valid = verify_schnorr(signature, pubkey, message_bytes)
    print(f"Actual Signature is valid: {is_valid}")


def verification_test_stealth():
    pk1, sk1 = generate_pair()
    pk2, sk2 = generate_pair()
    r, pkS = generate_stealth_pk(pk2)
    message_bytes = convert_to_bytes(int(pk2.x) % CYCLIC_PRIME_ORDER)
    sig = generate_signature_schnorr(sk1, message_bytes, r)
    verification_test_schnorr(sig, pk1, message_bytes)

    skS = retrieve_stealth_sk(pk2, sk2, pkS, sig)
    if skS == False: print(f"Stealth Signature failed to reconstruct, secret key does not match public key.")
    P = skS * GENERATOR_POINT
    if P.x == pkS.x and P.y == pkS.y:  print(f"Stealth Signature Correctly reconstrtucted")
    else: print(f"Stealth Signature failed to reconstruct")

if __name__ == "__main__":
    verification_test_stealth()





