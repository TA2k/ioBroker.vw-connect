const mqtt = require("mqtt");
const crypto = require("crypto");

// ===== APK SOURCE REFERENCES (MySkoda 8.8.0) =====
// Broker URL "ssl://mqtt.messagehub.de:8883":  smali_classes2/ec0/b.smali line 348
// Client ID format "{appInstallId}#{uuid}":    smali_classes2/ec0/b.smali lines 207-248, xl0/j.smali (app_installation_id)
// Client ID "Id" prefix variant:               HA myskoda mqtt.py line 131: "Id" + APP_UUID + "#" + uuid4()
// MQTT v5, keepalive=15, sessionExpiry=10, cleanStart=true: res/xml/remote_config_defaults.xml
// Username = token from provider chain:        smali_classes2/ac0/w.smali lines 2419-2507 (setUserName)
//   Provider chain: zr0/a.smali -> ur0/g.smali -> ti0/a (token store)
//   ur0/g.smali method b() -> ur0/c.smali invokeSuspend -> fetches from ti0/a then returns ur0/h.a (token)
//   HYPOTHESIS: username could be idToken (ic0/p.smali has TWO StateFlows: field e=accessToken via lc0/a, field f=another token via lc0/d)
// Password = accessToken:                      smali_classes2/ac0/w.smali lines 2512-2586 (setPassword), ic0/p.smali method b() returns field e
// TOTP algorithm:                              smali_classes2/ec0/d.smali
//   secret = SHA-256(accessToken), counter = epoch/30, HMAC-SHA256(secret, counter), dynamic truncation mod 10^6
// UserProperties auth_method + auth_credentials: smali_classes2/ac0/w.smali lines 2591-2740
// Token storage keys:                          smali_classes2/kc0/b.smali line 280 (connect_refresh_token), line 308 (connect_id_token)
// BFF base URL:                                smali_classes2/am0/f.smali "https://emea.bff.cariad.digital"
// User-Agent:                                  smali_classes2/dm0/b.smali "MySkoda/Android/8.8.0/251215002"
// API Key:                                     smali_classes2/uc0/c.smali "44a86edb-41fc-43e1-8bbe-42d3c18919c3"
// OAuth client ID:                             smali_classes2/ic0/a.smali "7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com"

// ===== CONFIGURATION =====
const REFRESH_TOKEN = "eyJraWQiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiYTEzZDBhNS0wZmZlLTQ3YTEtYWViOC1iZjA2Zjg0ZGY1M2MiLCJhdWQiOiI3ZjA0NWVlZS03MDAzLTQzNzktOTk2OC05MzU1ZWQyYWRiMDZAYXBwc192dy1kaWxhYl9jb20iLCJhY3IiOiJodHRwczovL2lkZW50aXR5LnZ3Z3JvdXAuaW8vYXNzdXJhbmNlL2xvYS0yIiwic2NwIjoiYWRkcmVzcyBiYWRnZSBiaXJ0aGRhdGUgY2FycyBkcml2ZXJzTGljZW5zZSBkZWFsZXJzIGVtYWlsIG1pbGVhZ2UgbWJiIG5hdGlvbmFsSWRlbnRpZmllciBvcGVuaWQgcGhvbmUgcHJvZmVzc2lvbiBwcm9maWxlIHZpbiIsImFhdCI6ImlkZW50aXR5a2l0IiwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS52d2dyb3VwLmlvIiwianR0IjoicmVmcmVzaF90b2tlbiIsImV4cCI6MTc4OTI5OTI4MiwiaWF0IjoxNzczNzQ3MjgyLCJqdGkiOiIwZTA1Zjg4Zi00YTkzLTQ3NWQtODFiOS1iNTYwN2RiMzgyNzkifQ.eelkQ5GOdKP8xS63a2rQNqHQszi_GxawEQxk1lUe32U6gvQ9G6QtpJSyOVWeCXZnD1gYGmeC6CiikQHFJi3_bZNPX03LC531hUmcNrc0V6RXbRHrTS6XDyIRWaydvQ9_oAF4qvDI8FFaTvNJv_P--wGIfESZjaw-feP4523p-Cxt3kcbtRETL5QymSPgH-q3X7AmG7VsxFm5927lGKY-llE4I9Y8_cvNATkJZ7GfYsEld66GlF9fyDwGeJZ1nUwmOYHLpdE17QK3jakVYCGdTx5kLUNzwTJJ5fyiJNQZ1hHtXfAIR15MTgQlX5oW9z2CDYRSDOZmo0BpKql2IFognvRXkmE-UCbL6nN6GQI9ZRfZPqGUeNK5YPbq1-7mu4sUdzY0coEZoYV74mVfUm_MBwGeXMykFqHrITSVIRLA0m1wdo9nPgIpKV_mXnhzjfZ6O_G2sbXNCLoQX7_dODgUJKu_PhPEFqKxjyGHh_7aJo2w3oja5Ea2QotYnhsdcioRUBQDF1ZHvQCdmNmLPokV12tR-D8ttUyMNwQKGup50GoUfwa1j8V-d82ENaWPcmzhe1aaNqLqFvqpWSPGo8HAfDS9jx6Btur1oQxTNVpxDCIzYhwyG-PqKbGK1JezWLI-4zo5C_kD0411hT-QO18PoGDXIVGTxMEgPxMjppjzx-o";
const USER_ID = "ba13d0a5-0ffe-47a1-aeb8-bf06f84df53c";
const VIN = "TMBAN0NZ5RC027588";

// ===== Token Refresh =====
// main.js:4691-4719, ic0/a.smali (client_id)
// HA myskoda: mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT
// JSON body: {"token": refreshToken}, Response: {accessToken, refreshToken, idToken}
async function refreshTokens() {
  const res = await fetch("https://mysmob.api.connect.skoda-auto.cz/api/v1/authentication/refresh-token?tokenType=CONNECT", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: REFRESH_TOKEN }),
  });
  if (!res.ok) throw new Error(`Token refresh failed: ${res.status} ${await res.text()}`);
  const data = await res.json();
  const exp = JSON.parse(Buffer.from(data.accessToken.split(".")[1], "base64url").toString()).exp;
  console.log("Token refresh OK - expires:", new Date(exp * 1000).toISOString());
  return data; // {accessToken, refreshToken, idToken}
}

// ===== TOTP Calculation (from APK 8.8.0 ec0/d.smali) =====
function computeTotp(accessToken) {
    const secret = crypto.createHash("sha256").update(accessToken, "utf-8").digest();
    const epochSeconds = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epochSeconds / 30);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigInt64BE(BigInt(counter));
    const hmac = crypto.createHmac("sha256", secret).update(counterBuffer).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return (code % 1000000).toString().padStart(6, "0");
}

function tryConnect(label, opts) {
    return new Promise((resolve) => {
        const client = mqtt.connect("mqtts://mqtt.messagehub.de:8883", {
            reconnectPeriod: 0,
            connectTimeout: 8000,
            ...opts,
        });
        const timeout = setTimeout(() => {
            console.log(`  [${label}] TIMEOUT`);
            client.end(true);
            resolve("TIMEOUT");
        }, 8000);
        client.on("connect", (connack) => {
            clearTimeout(timeout);
            console.log(`  [${label}] *** CONNECTED *** rc=${connack?.reasonCode}`);
            client.end(true);
            resolve("OK");
        });
        client.on("error", (err) => {
            clearTimeout(timeout);
            const msg = err.message || String(err);
            console.log(`  [${label}] ${msg}`);
            client.end(true);
            resolve(msg);
        });
    });
}

async function main() {
    console.log("MySkoda MQTT Trial & Error");
    console.log("Time:", new Date().toISOString());

    // Frische Tokens holen via refresh_token
    const tokens = await refreshTokens();
    const ACCESS_TOKEN = tokens.accessToken;
    const ID_TOKEN = tokens.idToken;

    const totp = computeTotp(ACCESS_TOKEN);
    const totpFromId = computeTotp(ID_TOKEN);
    console.log("TOTP(access):", totp, "TOTP(id):", totpFromId, "Epoch/30:", Math.floor(Date.now() / 1000 / 30));
    console.log("---");

    // ec0/b.smali:207-248: clientId = "{appInstallId}#{uuid}"
    const clientId = () => `${crypto.randomUUID()}#${crypto.randomUUID()}`;
    const results = [];

    const combos = [
        // === 1. APK dc0/d: user=accessToken, pass=accessToken, TOTP(access) ===
        // ac0/w.smali:2507 setUserName, :2528-2586 setPassword, :2591-2740 UserProperties
        { label: "APK: u=access p=access TOTP",
          opts: { protocolVersion: 5, username: ACCESS_TOKEN, password: Buffer.from(ACCESS_TOKEN, "utf-8"),
                  clientId: clientId(), clean: true, keepalive: 15,
                  properties: { sessionExpiryInterval: 10, userProperties: { auth_method: "totp_v1", auth_credentials: totp } } } },

        // === 2. Ohne TOTP - falls TOTP serverseitig nicht enforced ===
        { label: "APK: u=access p=access noTOTP",
          opts: { protocolVersion: 5, username: ACCESS_TOKEN, password: Buffer.from(ACCESS_TOKEN, "utf-8"),
                  clientId: clientId(), clean: true, keepalive: 15,
                  properties: { sessionExpiryInterval: 10 } } },

        // === 3. dc0/d.c = "android-app" als initialer username (nicht überschrieben?) ===
        // dc0/d.smali:20 setzt dc0/e.c = "android-app"
        // v3.1.1 um BANNED bei v5 zu vermeiden
        { label: "v3.1.1: u=android-app p=access",
          opts: { protocolVersion: 4, username: "android-app", password: ACCESS_TOKEN,
                  clientId: clientId(), keepalive: 60 } },

        // === 4. idToken als username, TOTP aus accessToken ===
        { label: "APK: u=idToken p=access TOTP(a)",
          opts: { protocolVersion: 5, username: ID_TOKEN, password: Buffer.from(ACCESS_TOKEN, "utf-8"),
                  clientId: clientId(), clean: true, keepalive: 15,
                  properties: { sessionExpiryInterval: 10, userProperties: { auth_method: "totp_v1", auth_credentials: totp } } } },

        // === 5. idToken als username, TOTP aus idToken ===
        { label: "APK: u=idToken p=access TOTP(id)",
          opts: { protocolVersion: 5, username: ID_TOKEN, password: Buffer.from(ACCESS_TOKEN, "utf-8"),
                  clientId: clientId(), clean: true, keepalive: 15,
                  properties: { sessionExpiryInterval: 10, userProperties: { auth_method: "totp_v1", auth_credentials: totpFromId } } } },

        // === 6. Skoda-native dc0/c Pfad: leerer username, leeres password ===
        // dc0/c: dc0/e(serverUri="", clientId, token="") -> ac0/w.smali:2352 username="", :2395 pass=""
        // Könnte per Firebase Remote Config aktiviert sein (cm0/b.g ordinal 3)
        { label: "dc0/c: u=empty p=empty",
          opts: { protocolVersion: 5, username: "", password: Buffer.from("", "utf-8"),
                  clientId: clientId(), clean: true, keepalive: 15,
                  properties: { sessionExpiryInterval: 10 } } },

        // === 7. dc0/c + TOTP ===
        { label: "dc0/c: u=empty p=empty TOTP",
          opts: { protocolVersion: 5, username: "", password: Buffer.from("", "utf-8"),
                  clientId: clientId(), clean: true, keepalive: 15,
                  properties: { sessionExpiryInterval: 10, userProperties: { auth_method: "totp_v1", auth_credentials: totp } } } },

        // === 8. HA-Stil: android-app + Id-prefix + TOTP ===
        { label: "HA: android-app Id-prefix TOTP",
          opts: { protocolVersion: 5, username: "android-app", password: Buffer.from(ACCESS_TOKEN, "utf-8"),
                  clientId: `Id${crypto.randomUUID()}#${crypto.randomUUID()}`, clean: true, keepalive: 60,
                  properties: { sessionExpiryInterval: 10, userProperties: { auth_method: "totp_v1", auth_credentials: totp } } } },
    ];

    for (const { label, opts } of combos) {
        const res = await tryConnect(label, opts);
        results.push({ label, res });
        await new Promise((r) => setTimeout(r, 500));
    }

    console.log("\n=== SUMMARY ===");
    for (const { label, res } of results) {
        const short = res.includes("Banned") ? "BANNED" : res.includes("Not authorized") ? "NOT_AUTH" : res.includes("TIMEOUT") ? "TIMEOUT" : res === "OK" ? "*** OK ***" : res.substring(0, 40);
        console.log(`  ${short.padEnd(12)} ${label}`);
    }
}

main();
