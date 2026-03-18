"""Exakte Kopie der HA myskoda MQTT-Verbindung (mqtt.py Zeilen 127-187).

Nutzt paho-mqtt direkt (wie aiomqtt unter der Haube).
Testet verschiedene Protokollversionen und Credential-Kombinationen.
"""

import json
import ssl
import uuid
import time
import hashlib
import hmac
import struct
import urllib.request

# ===== CONFIGURATION (gleich wie testMqtt.js) =====
REFRESH_TOKEN = "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0OTIwNTQwZC1kYjc4LTRiNDktODNlNy05MGMwMDYyNTUxMzAiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc4OTMyMDAwMCwiaWF0IjoxNzczNzY4MDAwLCJqdGkiOiIzMmU3MzU3MC0wZTE0LTQ2ZTgtOWQ1Ni1hNjY0ZGRiN2RlNjQifQ.yFuH9ZAFkN5QsBZfiE3WoF9rRXgIIFaBFjL0IpTxM_h_4Q6gORsLl7Q4kHZLcwyXY5fdkDebpG99nF26DLuj-BcDS3WuunXJX3wfxm2TSzj_gEJXB-iztGOwI9rv91eYBRaz701xtxpthufY-W1Kwo9voFw3WY9a8t4fDelOSs4IxWFVpeEKFIqLO3IDT24_T2SS4oChZhGCf-gigMjc5Rh5h5VinEF7hl3o_DqIdcvTBioRs0waaulgEC9a2AiAi4WI6o5yGX8xY_ekDox9LkFGlk-iIgdAwnuXYkFTWOXINHhgu_fN-0GDZ4PAGSb6TYJ61kp__fDYmvx9NijdzT6PzVfIYPWl_zOSiAvg3V576Gx-eo7LDMK2qWpF3oIkIMtFuvXCkZr_gt1VDzt792Qs9n4f87ySNPMlGQrLoIPzLYzJNwhsmRgbo8peYryy7YoNuX8JbWbNv4togNIKMVgjhUeabXU_aCSWYzZaHX7UYvXOYur_VVO5_dBwXrQs1tSHXkBfQqaFvEVGMMu7BK_t0cH-kTZ4AMleiLMi1Sc8iLlIOET6fh5QYBfdYHBd1a-o6Pw-Wnzz0ZD2Wg9fvQqh3UhiK6lRbvSxTYE1t4Ds_BRhUFuT82_z6xKI3HK5L5pByCLOopl0nP7l6Coz-hneEYktKsYKNIM4ijH4Z6I"
USER_ID = "4920540d-db78-4b49-83e7-90c006255130"
VIN = "TMBJC7NY6TF092607"

MQTT_BROKER = "mqtt.messagehub.de"
MQTT_PORT = 8883


def refresh_tokens():
    """Token refresh exakt wie HA myskoda (authorization.py)."""
    url = "https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT"
    data = json.dumps({"token": REFRESH_TOKEN}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        tokens = json.loads(resp.read())
    print(f"Token refresh OK - accessToken expires: {tokens['accessToken'][:40]}...")
    return tokens


def compute_totp(token):
    """TOTP aus APK ec0/d.smali: SHA-256(token) als Secret, HMAC-SHA256, mod 10^6."""
    secret = hashlib.sha256(token.encode()).digest()
    counter = int(time.time()) // 30
    counter_bytes = struct.pack(">Q", counter)
    h = hmac.new(secret, counter_bytes, hashlib.sha256).digest()
    offset = h[-1] & 0x0F
    code = ((h[offset] & 0x7F) << 24 | (h[offset+1] & 0xFF) << 16 |
            (h[offset+2] & 0xFF) << 8 | (h[offset+3] & 0xFF))
    return str(code % 1_000_000).zfill(6)


def try_connect(label, version, username, password, client_id, keepalive=60,
                clean=True, properties=None, user_properties=None):
    """Einzelner MQTT-Verbindungsversuch mit paho-mqtt."""
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
        # paho v2: rc ist ein ReasonCode-Objekt
        rc_val = int(rc) if hasattr(rc, '__int__') else rc
        rc_name = str(rc)
        if rc_val == 0:
            result["status"] = "OK"
            print(f"  [{label}] *** CONNECTED *** rc=0 ({rc_name})")
        else:
            result["status"] = f"REJECTED rc={rc_val} ({rc_name})"
            print(f"  [{label}] REJECTED rc={rc_val} ({rc_name})")
        client.disconnect()

    def on_connect_fail(client, userdata):
        result["status"] = "CONNECT_FAIL"
        print(f"  [{label}] Connect failed")

    client.on_connect = on_connect
    client.on_connect_fail = on_connect_fail

    connect_props = None
    if version == 5:
        from paho.mqtt.properties import Properties
        from paho.mqtt.packettypes import PacketTypes
        connect_props = Properties(PacketTypes.CONNECT)
        connect_props.SessionExpiryInterval = 10
        if clean:
            pass  # clean_start=True is default for v5
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

    # Loop mit Timeout
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


async def try_aiomqtt(label, access_token):
    """Test mit aiomqtt exakt wie HA myskoda mqtt.py."""
    import aiomqtt
    import asyncio

    app_uuid = uuid.uuid4()
    client_id = f"Id{app_uuid}#{uuid.uuid4()}"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()

    result = {"label": label, "status": "TIMEOUT"}

    try:
        client = aiomqtt.Client(
            hostname=MQTT_BROKER,
            port=MQTT_PORT,
            identifier=client_id,
            tls_context=context,
            keepalive=60,
            clean_session=True,
        )
        # Exakt wie HA: username_pw_set via paho internals
        client._client.username_pw_set(username="android-app", password=access_token)

        async with asyncio.timeout(10):
            async with client:
                result["status"] = "OK"
                print(f"  [{label}] *** CONNECTED ***")
    except aiomqtt.MqttError as e:
        result["status"] = f"MqttError: {e}"
        print(f"  [{label}] MqttError: {e}")
    except asyncio.TimeoutError:
        print(f"  [{label}] TIMEOUT")
    except Exception as e:
        result["status"] = str(e)[:60]
        print(f"  [{label}] Exception: {e}")

    return result


def main():
    import asyncio

    print("MySkoda MQTT Test (Python/paho+aiomqtt - exakte HA-Kopie)")
    print(f"Time: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

    tokens = refresh_tokens()
    access_token = tokens["accessToken"]
    id_token = tokens["idToken"]

    totp_access = compute_totp(access_token)
    totp_id = compute_totp(id_token)
    print(f"TOTP(access): {totp_access}  TOTP(id): {totp_id}  Epoch/30: {int(time.time())//30}")
    print("---")

    # Client ID exakt wie HA: "Id" + uuid4() + "#" + uuid4()
    app_uuid = uuid.uuid4()

    combos = [
        # === 1. EXAKTE HA-Kopie: username="android-app", password=accessToken, v3.1.1 ===
        {
            "label": "HA-EXAKT v3.1.1: android-app",
            "version": 311,
            "username": "android-app",
            "password": access_token,
            "client_id": f"Id{app_uuid}#{uuid.uuid4()}",
            "keepalive": 60,
            "clean": True,
        },
        # === 2. HA-Kopie aber mit MQTTv5 ===
        {
            "label": "HA v5: android-app",
            "version": 5,
            "username": "android-app",
            "password": access_token,
            "client_id": f"Id{app_uuid}#{uuid.uuid4()}",
            "keepalive": 60,
            "clean": True,
        },
        # === 3. HA v5 + TOTP ===
        {
            "label": "HA v5 + TOTP",
            "version": 5,
            "username": "android-app",
            "password": access_token,
            "client_id": f"Id{app_uuid}#{uuid.uuid4()}",
            "keepalive": 60,
            "clean": True,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_access},
        },
        # === 4. APK-Stil v5: u=accessToken p=accessToken + TOTP ===
        {
            "label": "APK v5: u=access p=access TOTP",
            "version": 5,
            "username": access_token,
            "password": access_token,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 15,
            "clean": True,
            "user_properties": {"auth_method": "totp_v1", "auth_credentials": totp_access},
        },
        # === 5. v3.1.1 ohne Id-Prefix ===
        {
            "label": "v3.1.1: android-app OHNE Id",
            "version": 311,
            "username": "android-app",
            "password": access_token,
            "client_id": f"{uuid.uuid4()}#{uuid.uuid4()}",
            "keepalive": 60,
            "clean": True,
        },
        # === 6. v3.1.1 mit accessToken als username ===
        {
            "label": "v3.1.1: u=access p=access",
            "version": 311,
            "username": access_token,
            "password": access_token,
            "client_id": f"Id{app_uuid}#{uuid.uuid4()}",
            "keepalive": 60,
            "clean": True,
        },
    ]

    results = []
    for combo in combos:
        label = combo.pop("label")
        version = combo.pop("version")
        r = try_connect(label, version, **combo)
        results.append(r)
        time.sleep(0.5)

    # === 7. AIOMQTT exakt wie HA myskoda ===
    print("\n--- aiomqtt Test (exakt wie HA) ---")
    r = asyncio.run(try_aiomqtt("aiomqtt HA-EXAKT", access_token))
    results.append(r)

    print("\n=== ZUSAMMENFASSUNG ===")
    for r in results:
        s = r["status"]
        tag = "*** OK ***" if s == "OK" else "BANNED" if "Banned" in s or "banned" in s.lower() else "NOT_AUTH" if "Not authorized" in s else "TIMEOUT" if "TIMEOUT" in s else s[:40]
        print(f"  {tag:<14} {r['label']}")


if __name__ == "__main__":
    main()
