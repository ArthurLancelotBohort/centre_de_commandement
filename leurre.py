import hashlib
import sys

ENCRYPTED_FLAG = bytes([95, 155, 70, 104, 101, 45, 121, 211, 178, 131, 172, 139, 212, 2, 199, 69, 8, 23, 244, 156, 104, 227, 149, 90, 99, 158, 251, 155, 177, 161, 31, 232, 147, 167, 8, 43, 155, 232, 88, 200, 47, 46, 49, 22, 49, 196, 221, 74, 69, 119, 93, 51, 230, 105, 161, 105, 57, 215, 205, 166, 214, 198, 144, 89, 171, 73, 1, 169, 202, 20, 154, 182, 30, 178, 214, 64, 113, 51, 17, 62, 169, 1, 29])

def _mangle(b, k, i):
    return b ^ k[i % len(k)] ^ ((i * 31) & 0xff)

def _derive(material):
    h = hashlib.sha256(material.encode()).digest()
    return (
        h[:16],
        h[16:],
        h[::-1]
    )

def _decode(blob, keys):
    out = bytearray(len(blob))
    k1, k2, k3 = keys

    for i in range(len(blob)):
        v = blob[i]
        v = _mangle(v, k1, i)
        v = _mangle(v, k2, len(blob) - i - 1)
        v = _mangle(v, k3, i >> 1)
        out[i] = v

    return bytes(out)

def normalize(d):
    return "|".join([
        d["ip"],
        d["user"],
        d["password"],
        d["github"],
        d["discord"],
        d["phrase"]
    ]).lower()

def main():
    print("ℹ️ Tous les champs sont EN MINUSCULE UNIQUEMENT\n")
    print("ℹ️ SI TU ES BLOQUE CONTACTE PERCEVAL, Y'A UN ELEMENT QUI PEUX BLOQUER\n")

    data = {
        "ip": input("IP VPS: ").strip(),
        "user": input("User VPS: ").strip(),
        "password": input("Password VPS: ").strip(),
        "github": input("Nom GitHub: ").strip(),
        "discord": input("Nom Discord: ").strip(),
        "phrase": input("Phrase secrète: ").strip(),
    }

    material = normalize(data)
    keys = _derive(material)

    try:
        flag = _decode(ENCRYPTED_FLAG, keys).decode()
        if flag.startswith("KAHO{") and flag.endswith("}"):
            print("\n🏆 Félicitation, voici le FLAG :", flag)
        else:
            print("\n❌ Informations incorrectes. Contacte Perceval ou réessaye")
            sys.exit(1)
    except Exception:
        print("\n❌ Informations incorrectes. Contacte Perceval ou réessaye")
        sys.exit(1)

if __name__ == "__main__":
    main()
