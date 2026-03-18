"""Test ALLER ioBroker vw-connect Skoda-Endpoints vs. HA myskoda Endpoints."""

import json
import time
import urllib.request

REFRESH_TOKEN = "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI0OTIwNTQwZC1kYjc4LTRiNDktODNlNy05MGMwMDYyNTUxMzAiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc4OTMyMDAwMCwiaWF0IjoxNzczNzY4MDAwLCJqdGkiOiIzMmU3MzU3MC0wZTE0LTQ2ZTgtOWQ1Ni1hNjY0ZGRiN2RlNjQifQ.yFuH9ZAFkN5QsBZfiE3WoF9rRXgIIFaBFjL0IpTxM_h_4Q6gORsLl7Q4kHZLcwyXY5fdkDebpG99nF26DLuj-BcDS3WuunXJX3wfxm2TSzj_gEJXB-iztGOwI9rv91eYBRaz701xtxpthufY-W1Kwo9voFw3WY9a8t4fDelOSs4IxWFVpeEKFIqLO3IDT24_T2SS4oChZhGCf-gigMjc5Rh5h5VinEF7hl3o_DqIdcvTBioRs0waaulgEC9a2AiAi4WI6o5yGX8xY_ekDox9LkFGlk-iIgdAwnuXYkFTWOXINHhgu_fN-0GDZ4PAGSb6TYJ61kp__fDYmvx9NijdzT6PzVfIYPWl_zOSiAvg3V576Gx-eo7LDMK2qWpF3oIkIMtFuvXCkZr_gt1VDzt792Qs9n4f87ySNPMlGQrLoIPzLYzJNwhsmRgbo8peYryy7YoNuX8JbWbNv4togNIKMVgjhUeabXU_aCSWYzZaHX7UYvXOYur_VVO5_dBwXrQs1tSHXkBfQqaFvEVGMMu7BK_t0cH-kTZ4AMleiLMi1Sc8iLlIOET6fh5QYBfdYHBd1a-o6Pw-Wnzz0ZD2Wg9fvQqh3UhiK6lRbvSxTYE1t4Ds_BRhUFuT82_z6xKI3HK5L5pByCLOopl0nP7l6Coz-hneEYktKsYKNIM4ijH4Z6I"
VIN = "TMBJC7NY6TF092607"
BASE = "https://mysmob.api.connect.skoda-auto.cz/api"


def refresh_tokens():
    url = f"{BASE}/v1/authentication/refresh-token?tokenType=CONNECT"
    data = json.dumps({"token": REFRESH_TOKEN}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def api_get(url, token, params=None):
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:300]
        return e.code, body


def main():
    print("ioBroker vw-connect Skoda Endpoint Test")
    print(f"Time: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"VIN: {VIN}\n")

    tokens = refresh_tokens()
    at = tokens["accessToken"]
    print("Token refresh OK\n")

    # === ioBroker Endpoints (aus main.js:3764-3805) ===
    # URL-Muster: BASE/{version}/{path}/{vin}{postfix}
    iobroker_endpoints = [
        {"path": "trip-statistics", "version": "v1", "postfix": "", "params": {"offset": "0", "offsetType": "WEEK", "timezone": "Europe/Berlin"}, "name": "tripsWeek"},
        {"path": "trip-statistics", "version": "v1", "postfix": "", "params": {"offset": "0", "offsetType": "YEAR", "timezone": "Europe/Berlin"}, "name": "tripsYear"},
        {"path": "vehicle-maintenance/vehicles", "version": "v3", "postfix": ""},
        {"path": "air-conditioning", "version": "v2", "postfix": ""},
        {"path": "air-conditioning", "version": "v2", "postfix": "/active-ventilation", "name": "ventilation"},
        {"path": "air-conditioning", "version": "v2", "postfix": "/auxiliary-heating", "name": "auxiliary-heating"},
        {"path": "air-conditioning", "version": "v1", "postfix": "/settings", "name": "ac-settings-v1"},
        {"path": "charging", "version": "v1", "postfix": ""},
        {"path": "charging", "version": "v1", "postfix": "/settings", "name": "charging-settings"},
        {"path": "vehicle-status", "version": "v2", "postfix": ""},
        {"path": "maps/positions/vehicles", "version": "v3", "postfix": "/parking", "name": "position"},
        {"path": "vehicle-status", "version": "v2", "postfix": "/driving-range"},
        {"path": "vehicle-maintenance/vehicles", "version": "v3", "postfix": "/report", "name": "maintenance-report"},
        {"path": "fueling/sessions", "version": "v2", "postfix": "", "name": "fueling-sessions"},
        {"path": "fueling/sessions", "version": "v2", "postfix": "/state", "name": "fueling-state"},
        {"path": "fueling/locations", "version": "v2", "postfix": "", "name": "fueling-locations"},
        {"path": "fueling/sessions", "version": "v2", "postfix": "/latest", "name": "fueling-latest"},
        {"path": "vehicle-information", "version": "v1", "postfix": ""},
    ]

    # === HA myskoda Endpoints (aus rest_api.py) die NICHT im ioBroker sind ===
    ha_extra_endpoints = [
        {"label": "HA: users", "url": f"{BASE}/v1/users"},
        {"label": "HA: garage", "url": f"{BASE}/v2/garage?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4"},
        {"label": "HA: vehicle-info", "url": f"{BASE}/v2/garage/vehicles/{VIN}?connectivityGenerations=MOD1&connectivityGenerations=MOD2&connectivityGenerations=MOD3&connectivityGenerations=MOD4"},
        {"label": "HA: positions", "url": f"{BASE}/v1/maps/positions?vin={VIN}"},
        {"label": "HA: health", "url": f"{BASE}/v1/vehicle-health-report/warning-lights/{VIN}"},
        {"label": "HA: connection-status", "url": f"{BASE}/v2/connection-status/{VIN}/readiness"},
        {"label": "HA: departure-timers", "url": f"{BASE}/v1/vehicle-automatization/{VIN}/departure/timers?deviceDateTime=2026-03-17T18:00:00Z"},
    ]

    print("=== ioBroker Endpoints (main.js:3764) ===")
    for ep in iobroker_endpoints:
        url = f"{BASE}/{ep['version']}/{ep['path']}/{VIN}{ep['postfix']}"
        label = ep.get("name", ep["path"] + ep["postfix"])
        status, data = api_get(url, at, ep.get("params"))

        if 200 <= status < 300:
            if isinstance(data, dict):
                keys = ", ".join(list(data.keys())[:5])
            else:
                keys = str(data)[:60]
            print(f"  [  {status}] {label:<25} {keys}")
        else:
            short = str(data)[:100] if isinstance(data, str) else json.dumps(data)[:100]
            print(f"  [{status}] {label:<25} {short}")

    print("\n=== HA-exklusive Endpoints ===")
    for ep in ha_extra_endpoints:
        status, data = api_get(ep["url"], at)
        if 200 <= status < 300:
            if isinstance(data, dict):
                keys = ", ".join(list(data.keys())[:5])
            else:
                keys = str(data)[:60]
            print(f"  [  {status}] {ep['label']:<25} {keys}")
        else:
            short = str(data)[:100] if isinstance(data, str) else json.dumps(data)[:100]
            print(f"  [{status}] {ep['label']:<25} {short}")


if __name__ == "__main__":
    main()
