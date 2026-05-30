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

class KeyPair:
    def __init__(self):
        # Initialize the private key as a random number between 1 and the cyclic prime order
        self.privkey = generate_random_number(1, CYCLIC_PRIME_ORDER)
        # Compute the corresponding public key by multiplying the private key with the generator point
        self.pubkey = self.privkey * GENERATOR_POINT

    def get_pubkey(self):
        return self.pubkey

    def generate_signature_schnorr(self, message):
        # Generate an ephemeral key (k)
        ephemeral_key = generate_random_number(1, CYCLIC_PRIME_ORDER)

        # Compute A = r * G
        A = ephemeral_key * GENERATOR_POINT

        # Extract the x-coordinate of R
        a = convert_to_bytes(int(A.x) % CYCLIC_PRIME_ORDER)

        # Compute the SHA-256 hash of the message
        message_hash = compute_sha256_hash(message)

        # Compute the challenge e = H(a || pubkey || message_hash)
        c = compute_sha256_hash(a + convert_to_bytes(int(self.pubkey.x)) + message_hash)
        c_int = convert_bytes_to_int(c)

        # Calculate the signature component s = k + e * privkey mod CYCLIC_PRIME_ORDER
        s = (ephemeral_key + c_int * self.privkey) % CYCLIC_PRIME_ORDER

        # Return the signature components (R, s)
        return A, s

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


def generate_DKG_cont():
   ...
    return (pk_cont,sk_cont)

def gen_share(pk1,pk2, sk_cont):
    ...
    return (pk, sk_share)


#generate first round values, r which is secret, and A = r * G
def generate_partial_A_com():
    ...
    return (r,A,h)

def partial_A_check(A,h):
    ...
    return ?? == ??

def generate_sig_share(A1,A2,pk,r,message,sk):
   ...
    return A, s

def aggregate_signatures(sig1,sig2,A1,h1,A2,h2):
    ...
    return A1, s12

def generate_sig_share(A1,A2,pk,r,message,sk):
    ...
    return A, s

def verification_test_schnorr(signature, pubkey, message_bytes):

    print("Schnorr Signature Verification test")
    if signature == False:
        print("Wrong hashes")
        return
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


if __name__ == "__main__":


    # Initialize key pair and message
    key1 = KeyPair()
    key2 = KeyPair()
    message = "Hello World"
    message_bytes = convert_to_bytes(message)
    # Schnorr Signature Test
    schnorr_signature = key1.generate_signature_schnorr(message_bytes)
    verification_test_schnorr(schnorr_signature, key1.get_pubkey(), message_bytes)

    #TSig test

    #DKG contribute generation for party 1
    (pk1,sk1) = generate_DKG_cont()

    #DKG contribute generation for party 2
    (pk2, sk2) = generate_DKG_cont()

    #key share generation of party 1
    (pk, sk1) = gen_share(pk1,pk2,sk1)

    #key share generation of party 2
    (pk, sk2) = gen_share(pk1, pk2, sk2)

    #Party 1 generate his commitment
    (r1,A1,h1) = generate_partial_A_com()

    #Party 2 generate his commitment
    (r2,A2,h2) = generate_partial_A_com()


    # Party 1 generates the second round
    sig1 = generate_sig_share(A1,A2, pk,r1,message_bytes,sk1)

    # Party 2 generates the second round
    sig2 = generate_sig_share(A1, A2, pk, r2, message_bytes, sk2)

    # Aggregate signatures
    sig = aggregate_signatures(sig1,sig2,A1,h1,A2,h2)
    verification_test_schnorr(sig, pk, message_bytes)



