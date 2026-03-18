"""MQTT-Fix Test basierend auf APK-Analyse MySkoda 8.8.0.

Entscheidende Erkenntnis: APK überschreibt "android-app" Username
mit Wert aus Room-DB (ur0/c Coroutine). Wahrscheinlich User-ID.

APK-Referenzen:
- ac0/w.smali:2458-2507: setUserName(ur0/c result) - NICHT dc0/e.c
- ac0/w.smali:2512-2586: setPassword(accessToken bytes)
- ac0/w.smali:2591-2740: UserProperties auth_method + auth_credentials
- ec0/d.smali: TOTP(SHA256(token), epoch/30, HMAC-SHA256, mod 10^6)
- ec0/b.smali:348: ssl://mqtt.messagehub.de:8883
- remote_config_defaults.xml: keepalive=15, sessionExpiry=10, cleanStart=true
"""

import json
import ssl
import uuid
import time
import hashlib
import hmac
import struct
import urllib.request


# ===== CONFIGURATION =====
REFRESH_TOKEN = "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0OTIwNTQwZC1kYjc4LTRiNDktODNlNy05MGMwMDYyNTUxMzAiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc4OTMyMDAwMCwiaWF0IjoxNzczNzY4MDAwLCJqdGkiOiIzMmU3MzU3MC0wZTE0LTQ2ZTgtOWQ1Ni1hNjY0ZGRiN2RlNjQifQ.yFuH9ZAFkN5QsBZfiE3WoF9rRXgIIFaBFjL0IpTxM_h_4Q6gORsLl7Q4kHZLcwyXY5fdkDebpG99nF26DLuj-BcDS3WuunXJX3wfxm2TSzj_gEJXB-iztGOwI9rv91eYBRaz701xtxpthufY-W1Kwo9voFw3WY9a8t4fDelOSs4IxWFVpeEKFIqLO3IDT24_T2SS4oChZhGCf-gigMjc5Rh5h5VinEF7hl3o_DqIdcvTBioRs0waaulgEC9a2AiAi4WI6o5yGX8xY_ekDox9LkFGlk-iIgdAwnuXYkFTWOXINHhgu_fN-0GDZ4PAGSb6TYJ61kp__fDYmvx9NijdzT6PzVfIYPWl_zOSiAvg3V576Gx-eo7LDMK2qWpF3oIkIMtFuvXCkZr_gt1VDzt792Qs9n4f87ySNPMlGQrLoIPzLYzJNwhsmRgbo8peYryy7YoNuX8JbWbNv4togNIKMVgjhUeabXU_aCSWYzZaHX7UYvXOYur_VVO5_dBwXrQs1tSHXkBfQqaFvEVGMMu7BK_t0cH-kTZ4AMleiLMi1Sc8iLlIOET6fh5QYBfdYHBd1a-o6Pw-Wnzz0ZD2Wg9fvQqh3UhiK6lRbvSxTYE1t4Ds_BRhUFuT82_z6xKI3HK5L5pByCLOopl0nP7l6Coz-hneEYktKsYKNIM4ijH4Z6I"
USER_ID = "4920540d-db78-4b49-83e7-90c006255130"
VIN = "TMBJC7NY6TF092607"

MQTT_BROKER = "mqtt.messagehub.de"
MQTT_PORT = 8883


def refresh_tokens():
    url = "https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT"
    data = json.dumps({"token": REFRESH_TOKEN}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def compute_totp(token):
    """TOTP exakt wie APK ec0/d.smali."""
    secret = hashlib.sha256(token.encode()).digest()
    counter = int(time.time()) // 30
    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(secret, counter_bytes, hashlib.sha256).digest()
    offset = h[-1] & 0x0F
    code = ((h[offset] & 0x7F) << 24 | (h[offset+1] & 0xFF) << 16 |
            (h[offset+2] & 0xFF) << 8 | (h[offset+3] & 0xFF))
    return str(code % 1_000_000).zfill(6)


def try_connect(label, version, username, password, client_id, keepalive=15,
                clean=True, session_expiry=10, user_properties=None):
    import paho.mqtt.client as paho_mqtt

    result = {"label": label, "status": "TIMEOUT"}

    if version == 5:
        client = paho_mqtt.Client(
            paho_mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=paho_mqtt.MQTTv5,
        )
    else:
        client = paho_mqtt.Client(
            paho_mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=paho_mqtt.MQTTv311,
            clean_session=clean,
        )

    client.username_pw_set(username=username, password=password)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)

    def on_connect(client, userdata, flags, rc, props=None):
        rc_val = int(rc) if hasattr(rc, '__int__') else rc
        rc_name = str(rc)
        if rc_val == 0:
            result["status"] = "OK"
            print(f"  [{label}] *** CONNECTED *** rc=0 ({rc_name})")
        else:
            result["status"] = f"rc={rc_val} ({rc_name})"
            print(f"  [{label}] REJECTED rc={rc_val} ({rc_name})")
        client.disconnect()

    client.on_connect = on_connect

    connect_props = None
    if version == 5:
        from paho.mqtt.properties import Properties
        from paho.mqtt.packettypes import PacketTypes
        connect_props = Properties(PacketTypes.CONNECT)
        connect_props.SessionExpiryInterval = session_expiry
        if user_properties:
            connect_props.UserProperty = list(user_properties.items())

    try:
        if version == 5:
            client.connect(MQTT_BROKER, MQTT_PORT, keepalive=keepalive,
                           clean_start=clean, properties=connect_props)
        else:
            client.connect(MQTT_BROKER, MQTT_PORT, keepalive=keepalive)
    except Exception as e:
        result["status"] = str(e)[:60]
        print(f"  [{label}] Exception: {e}")
        return result

    deadline = time.time() + 10
    while time.time() < deadline and result["status"] == "TIMEOUT":
        client.loop(timeout=0.5)

    if result["status"] == "TIMEOUT":
        print(f"  [{label}] TIMEOUT")

    try:
        client.disconnect()
    except Exception:
        pass
    return result


def main():
    print("MySkoda MQTT Fix-Test (basierend auf APK-Analyse)")
    print(f"Time: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

    tokens = refresh_tokens()
    at = tokens["accessToken"]
    idt = tokens["idToken"]

    # sub aus dem JWT extrahieren (= User-ID)
    import base64
    payload = json.loads(base64.urlsafe_b64decode(at.split(".")[1] + "=="))
    jwt_sub = payload["sub"]
    print(f"JWT sub (User-ID): {jwt_sub}")
    print(f"Config USER_ID:    {USER_ID}")
    print(f"Match: {jwt_sub == USER_ID}")

    totp_at = compute_totp(at)
    totp_idt = compute_totp(idt)
    print(f"TOTP(access): {totp_at}  TOTP(id): {totp_idt}")
    print("---\n")

    # APK Remote Config defaults: keepalive=15, sessionExpiry=10, cleanStart=true, dynamicClientId=true
    results = []

    combos = [
        # ===========================================================
        # NEUE TESTS: Username = User-ID (aus APK ur0/c Coroutine)
        # ===========================================================

        # 1. APK-exakt: u=userId, p=accessToken, v5, TOTP(accessToken)
        {
            "label": "APK: u=userId p=AT TOTP(AT)",
            "version": 5,
            "username": USER_ID,
            "password": at,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "session_expiry": 10,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_at},
        },
        # 2. u=userId, p=AT, v5, TOTP(idToken)
        {
            "label": "APK: u=userId p=AT TOTP(IDT)",
            "version": 5,
            "username": USER_ID,
            "password": at,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "session_expiry": 10,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_idt},
        },
        # 3. u=userId, p=AT, v5, OHNE TOTP
        {
            "label": "APK: u=userId p=AT noTOTP",
            "version": 5,
            "username": USER_ID,
            "password": at,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "session_expiry": 10,
        },
        # 4. u=userId, p=AT, v3.1.1
        {
            "label": "v311: u=userId p=AT",
            "version": 311,
            "username": USER_ID,
            "password": at,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 60,
        },
        # 5. u=userId mit Id-Prefix, p=AT, v5, TOTP
        {
            "label": "APK: u=userId Id-prefix TOTP",
            "version": 5,
            "username": USER_ID,
            "password": at,
            "client_id": f"Id{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "session_expiry": 10,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_at},
        },

        # ===========================================================
        # Username = Email (auch plausibel aus Room DB)
        # ===========================================================
        # 6. u=email, p=AT, v5, TOTP
        {
            "label": "APK: u=email p=AT TOTP",
            "version": 5,
            "username": "info@softwareloesungen-stein.de",
            "password": at,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "session_expiry": 10,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_at},
        },

        # ===========================================================
        # Kontrolltests (bekannt: scheitern)
        # ===========================================================
        # 7. HA-Stil Kontrolle: android-app
        {
            "label": "CTRL: android-app v311",
            "version": 311,
            "username": "android-app",
            "password": at,
            "client_id": f"Id{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 60,
        },
        # 8. APK-exakt aber u=accessToken (bisheriger Versuch)
        {
            "label": "CTRL: u=AT p=AT TOTP",
            "version": 5,
            "username": at,
            "password": at,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "session_expiry": 10,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_at},
        },
    ]

    for combo in combos:
        label = combo.pop("label")
        version = combo.pop("version")
        r = try_connect(label, version, **combo)
        results.append({"label": label, **r})
        time.sleep(0.5)

    print("\n=== ZUSAMMENFASSUNG ===")
    for r in results:
        s = r["status"]
        if s == "OK":
            tag = "*** OK ***"
        elif "Banned" in s or "banned" in s.lower():
            tag = "BANNED"
        elif "Not authorized" in s:
            tag = "NOT_AUTH"
        elif "TIMEOUT" in s:
            tag = "TIMEOUT"
        else:
            tag = s[:30]
        print(f"  {tag:<14} {r['label']}")


if __name__ == "__main__":
    main()
