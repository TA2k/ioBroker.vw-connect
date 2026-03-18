"""MQTT Subscribe-Test: Verbindung + Topic-Subscription.

Bestätigte Parameter:
- username = userId (NICHT "android-app")
- password = accessToken
- KEIN TOTP (verursacht Ablehnung)
- v5 oder v3.1.1 funktioniert
"""

import json
import ssl
import uuid
import time
import urllib.request

REFRESH_TOKEN = "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0OTIwNTQwZC1kYjc4LTRiNDktODNlNy05MGMwMDYyNTUxMzAiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc4OTMyMDAwMCwiaWF0IjoxNzczNzY4MDAwLCJqdGkiOiIzMmU3MzU3MC0wZTE0LTQ2ZTgtOWQ1Ni1hNjY0ZGRiN2RlNjQifQ.yFuH9ZAFkN5QsBZfiE3WoF9rRXgIIFaBFjL0IpTxM_h_4Q6gORsLl7Q4kHZLcwyXY5fdkDebpG99nF26DLuj-BcDS3WuunXJX3wfxm2TSzj_gEJXB-iztGOwI9rv91eYBRaz701xtxpthufY-W1Kwo9voFw3WY9a8t4fDelOSs4IxWFVpeEKFIqLO3IDT24_T2SS4oChZhGCf-gigMjc5Rh5h5VinEF7hl3o_DqIdcvTBioRs0waaulgEC9a2AiAi4WI6o5yGX8xY_ekDox9LkFGlk-iIgdAwnuXYkFTWOXINHhgu_fN-0GDZ4PAGSb6TYJ61kp__fDYmvx9NijdzT6PzVfIYPWl_zOSiAvg3V576Gx-eo7LDMK2qWpF3oIkIMtFuvXCkZr_gt1VDzt792Qs9n4f87ySNPMlGQrLoIPzLYzJNwhsmRgbo8peYryy7YoNuX8JbWbNv4togNIKMVgjhUeabXU_aCSWYzZaHX7UYvXOYur_VVO5_dBwXrQs1tSHXkBfQqaFvEVGMMu7BK_t0cH-kTZ4AMleiLMi1Sc8iLlIOET6fh5QYBfdYHBd1a-o6Pw-Wnzz0ZD2Wg9fvQqh3UhiK6lRbvSxTYE1t4Ds_BRhUFuT82_z6xKI3HK5L5pByCLOopl0nP7l6Coz-hneEYktKsYKNIM4ijH4Z6I"
USER_ID = "4920540d-db78-4b49-83e7-90c006255130"
VIN = "TMBJC7NY6TF092607"


def refresh_tokens():
    url = "https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT"
    data = json.dumps({"token": REFRESH_TOKEN}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def main():
    import paho.mqtt.client as paho_mqtt
    from paho.mqtt.properties import Properties
    from paho.mqtt.packettypes import PacketTypes

    print("MySkoda MQTT Subscribe-Test")
    print(f"Time: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")

    tokens = refresh_tokens()
    at = tokens["accessToken"]
    print("Token refresh OK")

    client_id = f"{uuid.uuid4()}#{uuid.uuid4()}"
    print(f"ClientId: {client_id}")
    print(f"Username: {USER_ID}")
    print(f"VIN: {VIN}")

    # HA myskoda Topics (aus const.py)
    operation_topics = [
        "air-conditioning", "charging", "departure", "vehicle-access",
        "vehicle-services-backup", "vehicle-wakeup", "charging-profiles",
    ]
    service_topics = [
        "air-conditioning", "charging", "departure",
        "vehicle-status/access", "vehicle-status/lights", "vehicle-status/odometer",
    ]
    vehicle_topics = ["connection-status-update", "ignition-status"]
    account_topics = ["privacy"]

    topics = []
    for t in operation_topics:
        topics.append(f"{USER_ID}/{VIN}/operation-request/{t}")
    for t in service_topics:
        topics.append(f"{USER_ID}/{VIN}/service-event/{t}")
    for t in vehicle_topics:
        topics.append(f"{USER_ID}/{VIN}/vehicle-event/{t}")
    for t in account_topics:
        topics.append(f"{USER_ID}/{VIN}/account-event/{t}")

    # Auch Wildcard-Topic testen
    topics.append(f"{USER_ID}/{VIN}/#")

    client = paho_mqtt.Client(
        paho_mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=paho_mqtt.MQTTv5,
    )
    client.username_pw_set(username=USER_ID, password=at)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)

    def on_connect(client, userdata, flags, rc, props=None):
        rc_val = int(rc) if hasattr(rc, '__int__') else rc
        if rc_val == 0:
            print(f"*** CONNECTED *** rc=0")
            # Subscribe to all topics
            for topic in topics:
                sub_props = Properties(PacketTypes.SUBSCRIBE)
                client.subscribe(topic, qos=1, properties=sub_props)
                print(f"  Subscribed: {topic}")
        else:
            print(f"REJECTED rc={rc_val} ({rc})")

    def on_message(client, userdata, msg):
        print(f"\n=== MESSAGE ===")
        print(f"  Topic: {msg.topic}")
        print(f"  QoS: {msg.qos}")
        try:
            payload = json.loads(msg.payload.decode())
            print(f"  Payload: {json.dumps(payload, indent=2)[:500]}")
        except Exception:
            print(f"  Payload (raw): {msg.payload[:200]}")

    def on_subscribe(client, userdata, mid, rc_list, props=None):
        print(f"  Subscribe ACK mid={mid} rc={rc_list}")

    def on_disconnect(client, userdata, flags, rc, props=None):
        print(f"Disconnected rc={rc}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    client.on_disconnect = on_disconnect

    connect_props = Properties(PacketTypes.CONNECT)
    connect_props.SessionExpiryInterval = 10

    print(f"\nConnecting to mqtt.messagehub.de:8883...")
    client.connect("mqtt.messagehub.de", 8883, keepalive=15,
                    clean_start=True, properties=connect_props)

    print("Listening for 30 seconds...")
    deadline = time.time() + 30
    while time.time() < deadline:
        client.loop(timeout=1.0)

    print("\nDone. Disconnecting.")
    client.disconnect()


if __name__ == "__main__":
    main()
