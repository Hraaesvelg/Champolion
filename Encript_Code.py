import os
import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


def create_permanent_key():
    identity_private = Ed25519PrivateKey.generate()
    return identity_private

def recreate_private_hex(private_hex):
    x_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    x_public = x_private.public_key()
    return x_private, x_public

def get_private_hex(identity_key):
    # Private key bytes
    private_hex = identity_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    return private_hex



def save_encrypted_file(filename, encrypted_file_bytes):
    enc_filename = filename + ".enc"
    with open(enc_filename, "wb") as f:
        f.write(encrypted_file_bytes)
    print(f"File '{filename}' encrypted successfully as '{enc_filename}'!")

def decrypt_file(encrypted_blob, master_key):
    """
    Decrypts encrypted bytes using the master key.
    Restores original file with correct name and extension.
    """

    offset = 0

    # ---------- Parse header ----------
    header_len = int.from_bytes(encrypted_blob[offset:offset+4], "big")
    offset += 4

    header_bytes = encrypted_blob[offset:offset+header_len]
    offset += header_len

    header = json.loads(header_bytes.decode())

    # ---------- Parse crypto material ----------
    data_nonce = encrypted_blob[offset:offset+12]
    offset += 12

    eph_public_bytes = encrypted_blob[offset:offset+32]
    offset += 32

    wrap_nonce = encrypted_blob[offset:offset+12]
    offset += 12

    wrapped_eph_private = encrypted_blob[offset:offset+48]
    offset += 48

    ciphertext = encrypted_blob[offset:]

    # ---------- Recreate ephemeral public key ----------
    eph_public = X25519PublicKey.from_public_bytes(eph_public_bytes)

    # ---------- Derive wrapping key ----------
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ephemeral-key-wrapping"
    ).derive(master_key)

    # ---------- Unwrap ephemeral private key ----------
    aesgcm_wrap = AESGCM(wrapping_key)
    eph_private_bytes = aesgcm_wrap.decrypt(
        wrap_nonce,
        wrapped_eph_private,
        None
    )

    eph_private = X25519PrivateKey.from_private_bytes(eph_private_bytes)

    # ---------- Re-derive file key ----------
    shared_secret = eph_private.exchange(eph_public)

    file_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-encryption"
    ).derive(shared_secret)

    # ---------- Decrypt file ----------
    aesgcm_file = AESGCM(file_key)
    plaintext = aesgcm_file.decrypt(data_nonce, ciphertext, None)

    # ---------- Restore file ----------
    restored_name = header["filename"] + header["extension"]
    with open(restored_name, "wb") as f:
        f.write(plaintext)

    return restored_name

def encrypt_file(file_path, master_key):
    """
    Encrypts a file using a master key.
    Returns encrypted bytes ready to be stored.
    """

    # ---------- Read file ----------
    with open(file_path, "rb") as f:
        plaintext = f.read()

    filename, extension = os.path.splitext(os.path.basename(file_path))

    header = {
        "filename": filename,
        "extension": extension,
        "size": len(plaintext)
    }
    header_bytes = json.dumps(header).encode()
    header_len = len(header_bytes).to_bytes(4, "big")

    # ---------- Generate ephemeral X25519 keypair ----------
    eph_private = X25519PrivateKey.generate()
    eph_public = eph_private.public_key()

    # ---------- Derive file encryption key ----------
    shared_secret = eph_private.exchange(eph_public)

    file_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-encryption"
    ).derive(shared_secret)

    # ---------- Encrypt file ----------
    data_nonce = os.urandom(12)
    aesgcm_file = AESGCM(file_key)
    ciphertext = aesgcm_file.encrypt(data_nonce, plaintext, None)

    # ---------- Derive wrapping key from master key ----------
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ephemeral-key-wrapping"
    ).derive(master_key)

    # ---------- Wrap ephemeral private key ----------
    wrap_nonce = os.urandom(12)
    aesgcm_wrap = AESGCM(wrapping_key)
    wrapped_eph_private = aesgcm_wrap.encrypt(
        wrap_nonce,
        eph_private.private_bytes_raw(),
        None
    )

    # ---------- Final file format ----------
    encrypted_blob = (
            header_len +
            header_bytes +
            data_nonce +
            eph_public.public_bytes_raw() +
            wrap_nonce +
            wrapped_eph_private +
            ciphertext
    )

    return encrypted_blob