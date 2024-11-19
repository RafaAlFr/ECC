from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Gerar chaves pública e privada ECC
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Salvar chaves em arquivos
def save_key_to_file(key, filename, is_private=False):
    with open(filename, "wb") as file:
        if is_private:
            file.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        else:
            file.write(
                key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

# Carregar chaves de arquivos
def load_private_key_from_file(filename):
    with open(filename, "rb") as file:
        return serialization.load_pem_private_key(file.read(), password=None)

def load_public_key_from_file(filename):
    with open(filename, "rb") as file:
        return serialization.load_pem_public_key(file.read())

def create_shared_key(private_key, peer_public_key):
    
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    # Derivar uma chave com HKDF
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"ECDH shared key",
    ).derive(shared_key)
    return derived_key

# Criptografia simétrica usando AES-GCM
def encrypt_data(key, plaintext):
    iv = os.urandom(12)  # Vetor de inicialização (nonce)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

# Descriptografia simétrica usando AES-GCM
def decrypt_data(key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")

if __name__ == "__main__":
    private_key_user1, public_key_user1 = generate_keys()

    # Salvar as chaves
    save_key_to_file(private_key_user1, "private_key.pem", is_private=True)
    save_key_to_file(public_key_user1, "public_key.pem")

    shared_key_user1 = create_shared_key(private_key_user1, public_key_user1)

    assert shared_key_user1 == shared_key_user1  

    # Dados para criptografar
    message = "Mensagem secreta usando ECC!"

    # Criptografar os dados
    iv, ciphertext, tag = encrypt_data(shared_key_user1, message)
    print("Mensagem criptografada:", ciphertext)

    # Descriptografar os dados
    decrypted_message = decrypt_data(shared_key_user1, iv, ciphertext, tag)
    print("Mensagem descriptografada:", decrypted_message)
