root@vps117107:~# cat test_flag_2.py 
import hashlib
import sys

ENCRYPTED_FLAG = bytes([
231, 164, 214, 232, 148, 104, 239, 215, 98, 187, 75, 226, 210, 232, 154, 199, 191, 171, 7, 130, 28, 83, 47, 75, 228, 138, 231, 1, 189, 242, 129, 38, 169, 89, 250, 61, 255, 148, 119, 4, 74, 214, 64, 7, 170, 223, 160, 41, 193, 62, 239, 20, 95, 143, 191, 86, 146, 25, 237, 69, 87
])


def vigenere_decode(data: bytes, key: str) -> bytes:
    key = key.encode()
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = (b - key[i % len(key)]) & 0xff
    return bytes(out)


def _mangle(b, k, i):
    return b ^ k[i % len(k)] ^ ((i * 31) & 0xff)


def _derive(material):
    h = hashlib.sha256(material.encode()).digest()
    return h[:16], h[16:], h[::-1]


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
        d["phrase"],
        d["vigenere"]
    ]).lower()


def main():
    print("ℹ️ Tous les champs sont normalisés automatiquement\n")

    data = {
        "ip": input("IP VPS: ").strip(),
        "user": input("User VPS: ").strip(),
        "password": input("Password VPS: ").strip(),
        "github": input("Nom GitHub: ").strip(),
        "discord": input("Nom Discord: ").strip(),
        "phrase": input("Phrase secrète: ").strip(),
        "vigenere": input("Clé Vigenère: ").strip(),
    }

    material = normalize(data)
    keys = _derive(material)

    try:
        stage1 = vigenere_decode(ENCRYPTED_FLAG, data["vigenere"])
        flag = _decode(stage1, keys).decode()

        if flag.startswith("KAHO{") and flag.endswith("}"):
            print("\n🏆 FLAG :", flag)
        else:
            print("\n❌ Informations incorrectes.")
            sys.exit(1)

    except Exception:
        print("\n❌ Informations incorrectes.")
        sys.exit(1)


if __name__ == "__main__":
    main()
