import oqs
from pprint import pprint
import os

print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())
print("Enabled signature mechanisms:")
sigs = oqs.get_enabled_sig_mechanisms()
pprint(sigs, compact=True)

message = "This is the message to signййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййййй".encode()

sigalg = "Falcon-padded-1024"

seed_hex = "38f2588f212b4618b1f63370bc2ee6803f43565244444db5d7ab9cad1a4cc3674324a0267be1ffb5cb9d54450fe251"
seed = bytes.fromhex(seed_hex)
print("\nSeed (hex):", seed.hex())

with oqs.Signature(sigalg) as signer:
    with oqs.Signature(sigalg) as verifier:
        print("\nSignature details:")
        pprint(signer.details)

        signer_public_key = signer.generate_keypair_from_fseed(seed)
        secret_key = signer.export_secret_key()

        # Проверяем размеры ключей
        #assert len(signer_public_key) == 897, f"Unexpected public key length: {len(signer_public_key)}"
        #assert len(secret_key) == 1281, f"Unexpected secret key length: {len(secret_key)}"

        print("Signer public key (hex):", signer_public_key.hex())
        print("Signer secret key (hex):", secret_key.hex())

        signature = signer.sign(message)

        # Проверяем длину подписи
        #assert len(signature) <= 666, f"Unexpected signature length: {len(signature)}"

        print("Generated signature (hex):", signature.hex())

        is_valid = verifier.verify(message, signature, signer_public_key)
        print("\nValid signature?", is_valid)