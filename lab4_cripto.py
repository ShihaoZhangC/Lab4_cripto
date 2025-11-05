# Bloque 1: Importaciones y tamaños de clave/IV 
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

AES_KEY, AES_BLOCK = 32, 16
DES_KEY, DES_BLOCK = 8, 8
TDES_KEY2, TDES_KEY3, TDES_BLOCK = 16, 24, 8

# Bloque 2: Solicita datos de entrada desde la terminal 
print("Ingrese los datos correspondientes:")
alg = input("Ingrese el algoritmo [DES / 3DES / AES-256]: ").strip().upper()
key_str = input("Ingrese la Key (texto o 0xHEX): ")
iv_str = input("Ingrese el IV (texto o 0xHEX): ")
text_str = input("Ingrese el Texto a cifrar: ")

# Bloque 3: Conversión y ajuste de tamaños de clave e IV 
def parse_bytes(s: str) -> bytes:
    if s.lower().startswith("0x"):
        return bytes.fromhex(s[2:].replace(" ", ""))
    return s.encode("utf-8")

def ajustar(b: bytes, tam: int) -> bytes:
    if len(b) < tam:
        return b + get_random_bytes(tam - len(b))
    elif len(b) > tam:
        return b[:tam]
    return b

key_in = parse_bytes(key_str)
iv_in = parse_bytes(iv_str)

if alg == "DES":
    key, iv = ajustar(key_in, DES_KEY), ajustar(iv_in, DES_BLOCK)
elif alg == "3DES":
    tam = TDES_KEY3 if len(key_in) != TDES_KEY2 else TDES_KEY2
    key = DES3.adjust_key_parity(ajustar(key_in, tam))
    iv = ajustar(iv_in, TDES_BLOCK)
else:  # AES-256
    key, iv = ajustar(key_in, AES_KEY), ajustar(iv_in, AES_BLOCK)

print("\n--- Parámetros ajustados ---")
print(f"Key ({len(key)} bytes): 0x{key.hex()}")
print(f"IV  ({len(iv)} bytes): 0x{iv.hex()}")

# Bloque 4: Cifrado y descifrado CBC 
def construir_cifrador(alg, key, iv):
    if alg == "DES":
        return DES.new(key, DES.MODE_CBC, iv)
    if alg == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv)
    return AES.new(key, AES.MODE_CBC, iv)

texto_bytes = text_str.encode("utf-8")
cipher = construir_cifrador(alg, key, iv)
ciphertext = cipher.encrypt(pad(texto_bytes, cipher.block_size))

print("\n--- Resultado del cifrado ---")
print(f"Ciphertext (HEX): 0x{ciphertext.hex()}")
print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
