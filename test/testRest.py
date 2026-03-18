"""Test der MySkoda REST-API Endpoints (exakt wie HA myskoda rest_api.py)."""

import json
import time
import urllib.request

REFRESH_TOKEN = "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0OTIwNTQwZC1kYjc4LTRiNDktODNlNy05MGMwMDYyNTUxMzAiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc4OTMyMDAwMCwiaWF0IjoxNzczNzY4MDAwLCJqdGkiOiIzMmU3MzU3MC0wZTE0LTQ2ZTgtOWQ1Ni1hNjY0ZGRiN2RlNjQifQ.yFuH9ZAFkN5QsBZfiE3WoF9rRXgIIFaBFjL0IpTxM_h_4Q6gORsLl7Q4kHZLcwyXY5fdkDebpG99nF26DLuj-BcDS3WuunXJX3wfxm2TSzj_gEJXB-iztGOwI9rv91eYBRaz701xtxpthufY-W1Kwo9voFw3WY9a8t4fDelOSs4IxWFVpeEKFIqLO3IDT24_T2SS4oChZhGCf-gigMjc5Rh5h5VinEF7hl3o_DqIdcvTBioRs0waaulgEC9a2AiAi4WI6o5yGX8xY_ekDox9LkFGlk-iIgdAwnuXYkFTWOXINHhgu_fN-0GDZ4PAGSb6TYJ61kp__fDYmvx9NijdzT6PzVfIYPWl_zOSiAvg3V576Gx-eo7LDMK2qWpF3oIkIMtFuvXCkZr_gt1VDzt792Qs9n4f87ySNPMlGQrLoIPzLYzJNwhsmRgbo8peYryy7YoNuX8JbWbNv4togNIKMVgjhUeabXU_aCSWYzZaHX7UYvXOYur_VVO5_dBwXrQs1tSHXkBfQqaFvEVGMMu7BK_t0cH-kTZ4AMleiLMi1Sc8iLlIOET6fh5QYBfdYHBd1a-o6Pw-Wnzz0ZD2Wg9fvQqh3UhiK6lRbvSxTYE1t4Ds_BRhUFuT82_z6xKI3HK5L5pByCLOopl0nP7l6Coz-hneEYktKsYKNIM4ijH4Z6I"
USER_ID = "4920540d-db78-4b49-83e7-90c006255130"
VIN = "TMBJC7NY6TF092607"

BASE_URL = "https://mysmob.api.connect.skoda-auto.cz/api"


def refresh_tokens():
    url = "https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT"
    data = json.dumps({"token": REFRESH_TOKEN}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def api_get(path, token):
    """GET request exakt wie HA rest_api.py: nur Authorization Bearer header."""
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = body
            return resp.status, data
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200]
        return e.code, body


def main():
    print("MySkoda REST-API Test")
    print(f"Time: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"VIN: {VIN}")
    print(f"User: {USER_ID}")

    tokens = refresh_tokens()
    access_token = tokens["accessToken"]
    print(f"Token refresh OK\n---")

    endpoints = [
        ("/v1/users", "User Info"),
        (f"/v2/garage?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4", "Garage"),
        (f"/v2/garage/vehicles/{VIN}?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4", "Vehicle Info"),
        (f"/v2/vehicle-status/{VIN}", "Vehicle Status"),
        (f"/v2/vehicle-status/{VIN}/driving-range", "Driving Range"),
        (f"/v1/charging/{VIN}", "Charging"),
        (f"/v2/air-conditioning/{VIN}", "Air Conditioning"),
        (f"/v1/maps/positions?vin={VIN}", "Positions"),
        (f"/v3/maps/positions/vehicles/{VIN}/parking", "Parking Position"),
        (f"/v3/vehicle-maintenance/vehicles/{VIN}", "Maintenance"),
        (f"/v1/vehicle-health-report/warning-lights/{VIN}", "Health"),
        (f"/v2/connection-status/{VIN}/readiness", "Connection Status"),
    ]

    results = []
    for path, label in endpoints:
        status, data = api_get(path, access_token)
        ok = 200 <= status < 300

        # Kurzfassung der Daten
        if ok and isinstance(data, dict):
            summary = ", ".join(f"{k}" for k in list(data.keys())[:6])
            if len(data.keys()) > 6:
                summary += f" (+{len(data.keys())-6} more)"
        elif ok:
            summary = str(data)[:80]
        else:
            summary = str(data)[:120]

        tag = "OK" if ok else f"ERR {status}"
        print(f"  [{tag:>7}] {label:<22} {summary}")
        results.append({"label": label, "status": status, "data": data})

    # Detail-Ausgabe für interessante Endpoints
    print("\n=== DETAILS ===")
    for r in results:
        if r["status"] != 200:
            continue
        if r["label"] in ("Charging", "Driving Range", "Vehicle Status", "Connection Status"):
            print(f"\n--- {r['label']} ---")
            print(json.dumps(r["data"], indent=2, ensure_ascii=False)[:800])


if __name__ == "__main__":
    main()
