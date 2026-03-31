import os
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def deriva_chiave_da_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

if os.path.exists("secret.key"):
    print("ATTENZIONE: secret.key esiste gia'.")
    print("Se continui, verra' generata una NUOVA chiave e le password salvate non saranno piu' leggibili.")
    risposta = input("Vuoi continuare? (s/n): ").strip().lower()
    if risposta != "s":
        print("Operazione annullata.")
        exit()

# Genera la Fernet key
fernet_key = Fernet.generate_key()

# Chiedi la master password
while True:
    master = getpass.getpass("Crea la tua master password: ")
    if len(master) < 4:
        print("La master password deve avere almeno 4 caratteri.")
        continue
    conferma = getpass.getpass("Conferma la master password: ")
    if master != conferma:
        print("Le password non coincidono. Riprova.")
        continue
    break

# Genera un salt casuale e cifra la Fernet key con la master password
salt = os.urandom(16)
chiave_derivata = deriva_chiave_da_password(master, salt)
cipher_master = Fernet(chiave_derivata)
fernet_key_cifrata = cipher_master.encrypt(fernet_key)

# Salva: salt (16 bytes) + fernet key cifrata
with open("secret.key", "wb") as f:
    f.write(salt + fernet_key_cifrata)

print("Chiave generata e protetta con master password.")
print("secret.key e' ora cifrato. Senza la master password non e' leggibile.")