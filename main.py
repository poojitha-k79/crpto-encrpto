import os
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import boto3
import unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === Custom Unicode alphabet (ancient languages + emojis) ===
ANCIENT_EMOJI_ALPHABET = [
    "ʘ", "ᒣ", "ᓀ", "ᓇ", "ᓯ", "ᔭ", "ᔾ", "ᖠ", "ᖫ", "ᖳ", "ᘓ", "ᘝ",
    "𐍈", "𐌰", "𐍃", "𐍄", "☥", "⚜️", "💫", "🌙", "🔥", "🪶", "💎", "✨",
    "🌺", "🌸", "🌀", "🎭", "🪷", "🐚", "🔮", "🕊️"
]

KEY_FILE = "master_key.bin"


def ensure_key() -> bytes:
    """Create/read 32-byte AES key"""
    if not os.path.exists(KEY_FILE):
        key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    with open(KEY_FILE, "rb") as f:
        key = f.read()
    return key


def bytes_to_symbols(data: bytes) -> str:
    """Map bytes to symbols in custom alphabet"""
    out = []
    for b in data:
        hi = (b >> 4) & 0xF
        lo = b & 0xF
        out.append(ANCIENT_EMOJI_ALPHABET[hi])
        out.append(ANCIENT_EMOJI_ALPHABET[lo])
    return "".join(out)


def symbols_to_bytes(s: str) -> bytes:
    rev = {ch: i for i, ch in enumerate(ANCIENT_EMOJI_ALPHABET)}
    glyphs = list(s)
    if len(glyphs) % 2 != 0:
        raise ValueError("Corrupted ciphertext symbols")
    out = bytearray()
    for i in range(0, len(glyphs), 2):
        hi = rev[glyphs[i]]
        lo = rev[glyphs[i + 1]]
        out.append((hi << 4) | lo)
    return bytes(out)


def encrypt_text(plaintext: str, key: bytes) -> str:
    norm = unicodedata.normalize("NFC", plaintext)
    data = norm.encode("utf-8")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, None)
    encoded = bytes_to_symbols(nonce + ct)
    return "ALGv2$" + encoded


def decrypt_text(ciphertext: str, key: bytes) -> str:
    if not ciphertext.startswith("ALGv2$"):
        raise ValueError("Invalid header")
    s = ciphertext.split("$", 1)[1]
    blob = symbols_to_bytes(s)
    nonce, ct = blob[:12], blob[12:]
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


# ===== AWS Bedrock integration =====
def filter_sense_text_bedrock(lines):
    """Use Bedrock LLM to pick only 'meaningful' sentences"""
    try:
        bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
        prompt = "Filter out only meaningful or coherent sentences from this list:\n" + "\n".join(lines)
        response = bedrock.invoke_model(
            modelId="anthropic.claude-3-sonnet-20240229-v1:0",
            body=json.dumps({"inputText": prompt})
        )
        data = json.loads(response["body"].read())
        return data.get("outputText", "").strip().splitlines()
    except Exception as e:
        return [f"[LLM unavailable: {e}]"]


# ====== HTTP Backend ======
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = parse_qs(body)
        key = ensure_key()

        if self.path == "/encrypt":
            plaintext = data.get("text", [""])[0]
            encrypted = encrypt_text(plaintext, key)
            self.respond({"encrypted": encrypted})

        elif self.path == "/decrypt":
            ciphertext = data.get("hash", [""])[0]
            try:
                text = decrypt_text(ciphertext, key)
                lines = [l for l in text.splitlines() if l.strip()]
                sense = filter_sense_text_bedrock(lines)
                self.respond({"decrypted": lines, "sense_full": sense})
            except Exception as e:
                self.respond({"error": str(e)})

    def respond(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = 8000
    print(f"Server running on http://localhost:{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
