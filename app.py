# -*- coding: utf-8 -*-
# Access Token → JWT — WITH RESPONSE DECRYPT
# MADE BY NOVRA (fixed by Kanha)

import json
import time
import base64
import requests
import urllib3
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

RELEASE_VERSION = "OB55"
CLIENT_VERSION = "1.132.9"
UNITY_VERSION = "2018.4.12f1"

USER_AGENT_UNITY = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"

MAJOR_LOGIN_URLS = [
    "https://loginbp.ppmainecoonghj.com/MajorLogin",
    "https://loginbp.ggpolarbear.com/MajorLogin",
    "https://loginbp.ggblueshark.com/MajorLogin",
]

FF_NICKNAME_XOR_SECRET = b"1e5898ccb8dfdd921f9bdea848768b64a201"


# ═══════════════════════════════════════════════════════
# CRYPTO
# ═══════════════════════════════════════════════════════
def encrypt_aes(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def decrypt_aes(enc_data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        dec = cipher.decrypt(enc_data)
        try:
            dec = unpad(dec, AES.block_size)
        except Exception:
            dec = dec.rstrip(b'\x00')
        return dec
    except Exception:
        return None


def decode_ff_nickname(encoded_nick):
    if not encoded_nick or encoded_nick == "N/A":
        return ""
    try:
        raw = base64.b64decode(encoded_nick)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ FF_NICKNAME_XOR_SECRET[i % len(FF_NICKNAME_XOR_SECRET)])
        text = dec.decode("utf-8", errors="ignore")
        if text and any(c.isprintable() for c in text):
            return text
    except Exception:
        pass
    return encoded_nick


def decode_jwt_payload(jwt_token):
    try:
        parts = jwt_token.strip().split(".")
        if len(parts) < 2:
            return {}
        seg = parts[1]
        seg += "=" * ((4 - len(seg) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def extract_jwt_info(jwt_token):
    payload = decode_jwt_payload(jwt_token)
    if not payload:
        return {"valid": False}

    raw_name = payload.get("nickname") or payload.get("nick_name") or ""
    clean_name = decode_ff_nickname(raw_name)

    return {
        "valid": True,
        "account_id": str(payload.get("account_id") or payload.get("uid", "")),
        "region": payload.get("lock_region") or payload.get("noti_region") or payload.get("region", ""),
        "nickname": clean_name,
        "exp": payload.get("exp"),
        "client_version": payload.get("client_version"),
        "release_version": payload.get("release_version"),
        "raw_payload": payload,
    }


# ═══════════════════════════════════════════════════════
# PROTOBUF
# ═══════════════════════════════════════════════════════
def encode_varint(n):
    if n < 0:
        n = n & 0xFFFFFFFFFFFFFFFF
    out = b''
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            break
    return out


def field_varint(fn, val):
    return encode_varint((fn << 3) | 0) + encode_varint(val)


def field_bytes(fn, val):
    if isinstance(val, str):
        val = val.encode("utf-8")
    return encode_varint((fn << 3) | 2) + encode_varint(len(val)) + val


# ═══════════════════════════════════════════════════════
# PAYLOAD
# ═══════════════════════════════════════════════════════
def build_major_login(open_id, access_token, platform_id):
    p = b''
    p += field_bytes(3, "2026-10-15 12:00:00")
    p += field_bytes(4, "free fire")
    p += field_varint(5, platform_id)
    p += field_bytes(7, CLIENT_VERSION)
    p += field_bytes(8, "Android OS 13 / API-33 (TP1A.220624.014)")
    p += field_bytes(9, "Handheld")
    p += field_bytes(10, "Telkomsel")
    p += field_bytes(11, "WIFI")
    p += field_varint(12, 1080)
    p += field_varint(13, 2400)
    p += field_bytes(14, "420")
    p += field_bytes(15, "ARM64 FP ASIMD AES VMH | 2865 | 8")
    p += field_varint(16, 5653)
    p += field_bytes(17, "Adreno (TM) 730")
    p += field_bytes(18, "OpenGL ES 3.2 v1.r49p1")
    p += field_bytes(19, "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57")
    p += field_bytes(20, "182.5.135.225")
    p += field_bytes(21, "en")
    p += field_bytes(22, open_id)
    p += field_bytes(23, str(platform_id))
    p += field_bytes(24, "Handheld")
    p += field_bytes(25, "Xiaomi 2409BRN2CY")
    p += field_bytes(26, "ID")
    p += field_bytes(29, access_token)
    p += field_varint(30, 1)
    p += field_bytes(41, "Telkomsel")
    p += field_bytes(42, "4G")
    p += field_bytes(57, "7428b253defc164018c604a1ebbfebdf")
    p += field_varint(60, 109278)
    p += field_varint(61, 55402)
    p += field_varint(62, 868)
    p += field_varint(64, 55927)
    p += field_varint(65, 109278)
    p += field_varint(66, 55927)
    p += field_varint(67, 109278)
    p += field_varint(73, 2)
    p += field_bytes(74, "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64")
    p += field_varint(76, 1)
    p += field_bytes(77, "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk")
    p += field_varint(78, 3)
    p += field_varint(79, 2)
    p += field_bytes(81, "64")
    p += field_bytes(83, "2019121229")
    p += field_varint(85, 3)
    p += field_bytes(86, "OpenGLES2")
    p += field_varint(87, 8191)
    p += field_bytes(88, str(platform_id))
    p += field_bytes(90, "Cirebon")
    p += field_bytes(91, "JB")
    p += field_bytes(92, "14466")
    p += field_bytes(93, "android")
    p += field_bytes(95, "111207")
    p += field_bytes(96, '{"cur_rate":[60,90,120],"support_etc2":false}')
    p += field_varint(97, 1)
    p += field_varint(98, 1)
    p += field_bytes(99, str(platform_id))
    p += field_bytes(100, str(platform_id))
    p += field_bytes(103, "1")
    p += field_bytes(104, "52837")
    p += field_bytes(105, "1")
    p += field_bytes(106, "https://dl.gmc.freefiremobile.com/live/ABHotUpdates/|https://core-gmc.freefiremobile.com/live/ABHotUpdates/|211c933168f55902c7dfbfd8c4e2957d")
    p += field_bytes(107, "1.3fb8adbf45f44ce9")
    return p


# ═══════════════════════════════════════════════════════
# RESPONSE PARSER — WITH DECRYPT
# ═══════════════════════════════════════════════════════
def _scan_proto(raw, result):
    try:
        i = 0
        n = len(raw)
        while i < n:
            tag = 0
            shift = 0
            while i < n:
                b = raw[i]
                i += 1
                tag |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7

            fn = tag >> 3
            wt = tag & 0x07

            if wt == 0:
                val = 0
                shift = 0
                while i < n:
                    b = raw[i]
                    i += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                if fn == 1 and not result["account_id"]:
                    result["account_id"] = str(val)

            elif wt == 2:
                length = 0
                shift = 0
                while i < n:
                    b = raw[i]
                    i += 1
                    length |= (b & 0x7F) << shift
                    if not (b & 0x80):
                        break
                    shift += 7
                data = raw[i:i+length]
                i += length

                if fn == 2 and not result["region"]:
                    try:
                        result["region"] = data.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass
                elif fn == 8 and not result["token"]:
                    try:
                        t = data.decode('utf-8', errors='ignore')
                        if t.startswith("eyJ"):
                            result["token"] = t
                    except Exception:
                        pass
                elif fn == 10 and not result["server_url"]:
                    try:
                        u = data.decode('utf-8', errors='ignore').strip()
                        if u.startswith("http"):
                            result["server_url"] = u
                    except Exception:
                        pass
                elif fn == 22 and not result["key"]:
                    result["key"] = data.hex()
                elif fn == 23 and not result["iv"]:
                    result["iv"] = data.hex()

            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
    except Exception:
        pass


def parse_majorlogin_response(raw):
    """
    Multi-strategy:
    1. Direct scan
    2. Decrypt → scan
    3. Decrypt → find JWT
    4. Direct find JWT
    """
    result = {
        "account_id": None, "region": None, "token": None,
        "server_url": None, "key": None, "iv": None,
    }

    if not raw or len(raw) < 10:
        return result

    # 1. Direct scan
    _scan_proto(raw, result)
    if result["token"]:
        print(f"  └─ Parsed (direct)")
        return result

    # 2. Decrypt → scan
    dec = decrypt_aes(raw)
    if dec:
        print(f"  └─ Decrypted len={len(dec)}")
        _scan_proto(dec, result)
        if result["token"]:
            print(f"  └─ Parsed (decrypted proto)")
            return result

        # 3. Decrypt → find JWT string
        idx = dec.find(b"eyJhbGciOi")
        if idx != -1:
            end = idx
            valid = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.'
            while end < len(dec) and dec[end] in valid:
                end += 1
            result["token"] = dec[idx:end].decode('latin-1', errors='ignore')
            print(f"  └─ Parsed (decrypted JWT string)")
            return result

        # Print decrypted hex for debug
        print(f"  └─ Decrypted hex: {dec.hex()[:200]}")

    # 4. Direct JWT string search
    idx = raw.find(b"eyJhbGciOi")
    if idx != -1:
        end = idx
        valid = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.'
        while end < len(raw) and raw[end] in valid:
            end += 1
        result["token"] = raw[idx:end].decode('latin-1', errors='ignore')
        print(f"  └─ Parsed (raw JWT string)")
        return result

    return result


# ═══════════════════════════════════════════════════════
# MAJORLOGIN
# ═══════════════════════════════════════════════════════
def try_major_login(open_id, access_token, platform_id, server_url):
    payload = build_major_login(open_id, access_token, platform_id)
    encrypted = encrypt_aes(payload)

    headers = {
        "User-Agent": USER_AGENT_UNITY,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": "1789534056",
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "Releaseversion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": UNITY_VERSION,
        "PlAy_VeR": "1.132.1",
        "Ob_VeR": RELEASE_VERSION,
    }

    try:
        r = requests.post(server_url, data=encrypted, headers=headers, verify=False, timeout=15)
        print(f"[MajorLogin] {server_url.split('/')[2]} | plat={platform_id} | HTTP {r.status_code} | len={len(r.content)}")

        if r.status_code != 200:
            try:
                err = r.content.decode('utf-8', errors='ignore')[:150]
                print(f"  └─ {err}")
            except Exception:
                pass
            return None

        result = parse_majorlogin_response(r.content)
        if result["token"]:
            print(f"  └─ ✅ JWT | UID={result['account_id']} | region={result['region']}")
            return result
        else:
            print(f"  └─ ⚠️ No JWT — raw hex: {r.content.hex()[:150]}")
    except Exception as e:
        print(f"  └─ Exception: {e}")
    return None


# ═══════════════════════════════════════════════════════
# OAUTH
# ═══════════════════════════════════════════════════════
def oauth_inspect(access_token):
    try:
        r = requests.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            headers={
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "close",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "100067.connect.garena.com",
                "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            },
            timeout=10, verify=False
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if "error" in data:
            return None
        return data
    except Exception as e:
        print(f"[OAuth] Exception: {e}")
        return None


# ═══════════════════════════════════════════════════════
# FLASK
# ═══════════════════════════════════════════════════════
app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "FF Access Token → JWT",
        "usage": "/NOVRA?access_token=YOUR_TOKEN",
        "developer": {
            "api_owner": "unknown.ix",
            "discord": "discord.gg/darZu2uTze",
            "from": "nepal",
        }
    })


@app.route("/NOVRA", methods=["GET"])
def novra_endpoint():
    access_token = request.args.get("access_token")
    if not access_token:
        return jsonify({"success": False, "error": "Missing 'access_token'"}), 400

    print(f"\n{'='*60}")
    print(f"[NOVRA] Token: {access_token[:20]}...")
    print(f"{'='*60}")

    oauth = oauth_inspect(access_token)
    if not oauth:
        return jsonify({"success": False, "error": "OAuth inspect failed"}), 400

    open_id = oauth.get("open_id")
    platform_from_token = oauth.get("platform", 4)
    uid_from_token = oauth.get("uid")

    if not open_id:
        return jsonify({"success": False, "error": "No open_id"}), 400

    print(f"[OAuth] open_id={open_id} | platform={platform_from_token} | uid={uid_from_token}")

    platform_order = [platform_from_token, 4, 8, 1, 2, 3, 6]
    seen = set()
    platform_order = [p for p in platform_order if not (p in seen or seen.add(p))]

    for srv in MAJOR_LOGIN_URLS:
        for plat in platform_order:
            result = try_major_login(open_id, access_token, plat, srv)
            if result and result["token"]:
                jwt_info = extract_jwt_info(result["token"])

                final_uid = result["account_id"] or jwt_info.get("account_id") or str(uid_from_token)
                final_region = result["region"] or jwt_info.get("region") or "BD"

                return jsonify({
                    "success": True,
                    "uid": final_uid,
                    "region": final_region,
                    "nickname": jwt_info.get("nickname"),
                    "level": 0,
                    "likes": 0,
                    "prime_level": 0,
                    "login_method": "access token",
                    "jwt": result["token"],
                    "server": result["server_url"],
                    "platform_used": plat,
                    "login_server": srv.split('/')[2],
                    "open_id": open_id,
                    "jwt_info": {
                        "account_id": jwt_info.get("account_id"),
                        "region": jwt_info.get("region"),
                        "nickname": jwt_info.get("nickname"),
                        "exp": jwt_info.get("exp"),
                        "client_version": jwt_info.get("client_version"),
                        "release_version": jwt_info.get("release_version"),
                    },
                    "developer": {
                        "api_owner": "unknown.ix",
                        "discord": "discord.gg/darZu2uTze",
                        "from": "nepal",
                    }
                })

    return jsonify({
        "success": False,
        "error": "MajorLogin failed — all platforms/servers tried",
        "open_id": open_id,
        "platform_from_token": platform_from_token,
        "uid_from_token": uid_from_token,
        "developer": {
            "api_owner": "unknown.ix",
            "discord": "discord.gg/darZu2uTze",
            "from": "nepal",
        }
    }), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)