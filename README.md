![Logo](admin/vw-connect.png)

# ioBroker.vw-connect

[![NPM version](http://img.shields.io/npm/v/iobroker.vw-connect.svg)](https://www.npmjs.com/package/iobroker.vw-connect)
[![Downloads](https://img.shields.io/npm/dm/iobroker.vw-connect.svg)](https://www.npmjs.com/package/iobroker.vw-connect)
[![Dependency Status](https://img.shields.io/david/ta2k/iobroker.vw-connect.svg)](https://david-dm.org/ta2k/iobroker.vw-connect)
[![Known Vulnerabilities](https://snyk.io/test/github/ta2k/ioBroker.vw-connect/badge.svg)](https://snyk.io/test/github/ta2k/ioBroker.vw-connect)

[![NPM](https://nodei.co/npm/iobroker.vw-connect.png?downloads=true)](https://nodei.co/npm/iobroker.vw-connect/)

**Tests:**: [![Travis-CI](http://img.shields.io/travis/ta2k/ioBroker.vw-connect/master.svg)](https://travis-ci.org/ta2k/ioBroker.vw-connect)

## vw-connect adapter for ioBroker

Adapter for VW We Connect, We Connect ID (now via the EU Data Act portal), We Charge, myAudi, Skoda Connect, Seat Connect and We Connect Go

Please update your system on Node 10.
<https://forum.iobroker.net/topic/22867/how-to-node-js-f%C3%BCr-iobroker-richtig-updaten>

## VW ID via EU Data Act portal (since v0.9.0)

Volkswagen retired the WeConnect/MBB API for ID-series vehicles. The adapter now consumes the **continuous 15-minute datasets** that VW publishes via the EU Data Act portal at <https://eu-data-act.drivesomethinggreater.com>. Your data shows up under `<vin>.statuseudata.*` (snake_case dotted names like `battery_state_report.soc`, `mileage.value`, `parking_brake`, `charging_state_report.current_charge_state` and friends).

### Prerequisite — enable a continuous data request once

The adapter only **downloads** datasets the portal generates; it cannot create the data request for you. You have to do that **once in a browser** before adding the adapter:

1. Open <https://eu-data-act.drivesomethinggreater.com/> and **log in with your Volkswagen ID** (same email/password you use in the Volkswagen App).
2. Go to **Data clusters → Vehicle overview**.
3. Click **Connect your car** if your VIN isn't already listed and follow the on-screen pairing/consent steps.
4. Klicke **Benutzerdefinierte Daten anfragen** ("Get customised data"). Hinweis vom Portal: es kann immer nur eine benutzerdefinierte Datenanfrage gleichzeitig aktiv sein.
5. **Vereinbarung gemäß Artikel 4 EU Data Act** ankreuzen ("Ich bestätige, dass ich die Vereinbarung gemäß Artikel 4 EU Data Act gelesen und akzeptiert habe.") → **Weiter**.
6. **Data Cluster auswählen**: **All data** anhaken ("All EU Data Act relevant data points"). Andere Cluster nur wenn du gezielt einschränken willst — picking only some restricts what `<vin>.statuseudata.*` will contain.
7. **Name des Datenpakets** vergeben (frei wählbar, z.B. "ioBroker"). Erscheint später als `_dataset_name`-Prefix in den Filenames.
8. **Frequenz wählen**: **Alle 15 Minuten**. Andere Optionen (täglich) liefern nicht genug Auflösung für Live-Werte.
9. **Dauer**: **Kein Enddatum** (fortlaufend ohne Enddatum).
10. Anfrage absenden. Wait for datasets to start appearing in the portal's data delivery list — typically **15 minutes to a few hours**. The first batch may show up as `*_no_content_found.zip` until your car wakes up. Force-syncing the car via the Volkswagen app or driving once kicks the producer side awake.

### Configure the adapter

In the adapter settings select **VW ID / Volkswagen App (EU Data Act portal)** as type, enter the same email/password you used on the portal, save. Polling defaults are sane — the adapter checks the listing every minute and only downloads when a new ZIP appears (so 14 of 15 cycles short-circuit on the filename cache).

Object tree per VIN:

```
<vin>.general.vin
<vin>.general.nickname
<vin>.statuseudata.battery_state_report.soc          (= 58 %)
<vin>.statuseudata.battery_state_report.charge_power (= 0.0 kW)
<vin>.statuseudata.charging_state_report.current_charge_state
<vin>.statuseudata.mileage.value
<vin>.statuseudata.parking_brake
<vin>.statuseudata.locked
<vin>.statuseudata._dataset_name
<vin>.statuseudata._dataset_created_on
... and many more (which exact fields depend on the Data Clusters you ticked on the portal)
```

### Troubleshooting

- **No vehicles found** in the adapter logs: you skipped the portal-side setup. Open <https://eu-data-act.drivesomethinggreater.com/>, log in, and connect your car (steps above).
- **HTTP 400 from the data delivery endpoint**: the portal hasn't finished provisioning your continuous data request yet — can take a couple of hours after activation. Adapter retries automatically.
- **`<vin>.statuseudata` channel is missing**: the portal has no content datasets yet. Force-sync the car via the VW app, or just drive once.
- **Stale values**: the portal merges several report snapshots into one flat array per dataset. Where the same field appears multiple times with different values, the adapter deterministically picks the entry with the smallest UUID (stable across refreshes — same approach as the home-assistant integration).
- **Reference implementation** (Home Assistant, Python): <https://github.com/mikrohard/hass-vw-eu-data-act>

## Usage

Use the state under remote control to control your car remotely.
Normale refresh is the polling interval to receive data from the VAG Cloud
Force refresh is for non E-Cars to enforce a refresh this number is limited by VAG until the car is turn on again.
Trip data is only available for non E-Cars.

You can set climatisaton temperature in
.climater.settings.targetTemperature.content

## Discussion and Questions

<https://forum.iobroker.net/topic/26438/test-adapter-vw-connect-für-vw-id-audi-seat-skoda>

## Status fields Explanation

### List of entries

```

```
### 0.9.0 (2026-05-30)

- VW ID flow migrated to the EU Data Act portal (`eu-data-act.drivesomethinggreater.com`). Status data is now under `<vin>.statuseudata.*`. Requires a continuous 15-min data request set up once on the portal — see "VW ID via EU Data Act portal" above.

### 0.8.8 (2026-05-28)

- fix audi and vw login

### 0.8.7 (2026-05-27)
- fix audi login

### 0.8.6 (2026-05-27)
- fix id login

### 0.8.5 (2026-05-24)
- fix cupra

### 0.8.4 (2026-05-14)
- disable skoda mqtt

### 0.8.3 (2026-05-10)
- fix skoda mqtt

### 0.8.1 (2026-05-06)
- fix skoda mqtt

### 0.8.0 (2026-04-13)
- fix for seat cupra

### 0.7.16 (2026-03-18)
- fix myskoda mqtt connection

### 0.7.15 (2025-11-26)
- fix vw refresh token

### 0.7.14 (2025-11-25)
- fix vw id login

### 0.7.13 (2025-11-09)
- fix for skoda login

### 0.7.12 (2025-05-05)

- fix for skoda refresh token
- fix for ventilation activation
- add new not supported endpoints

### 0.7.9 (2025-03-20)

- fix for id wall charger

### 0.7.7 (2025-03-02)

- fix for skoda auxiliaryheating and duration
- fix for skoda lock/unlock

### 0.7.6 (2025-02-28)

- fix for charging status updates only at startup
- fix for skoda ismoving state

### 0.7.3 (2025-02-26)

- fix for set setTemperature
- fix for Skoda unlock lock

### 0.7.0 (2025-02-25)

- fix for skoda and seat
- State structure changed completly please delete old states under Objects

### 0.6.1 (2024-10-01)

- fix for skoda login

### 0.6.0 (2024-04-11)

- add additonal cupra states

### 0.5.4 (2024-03-17)

- fix door window states

### 0.4.1

- Fix VW Status Update

### 0.0.65

- Fix Cupra login

### 0.0.63

- Fix VW/Skoda etron login

### 0.0.62

- Fix Audi etron login

### 0.0.61

- Fix ID login

### 0.0.60

- Minor improvements. WeCharge Minimum interval is now 15 minutes

### 0.0.55

- fix id status update

### 0.0.51

- fix audi etron login

### 0.0.48

- fix login, fix audi update, add limit for wallbox

### 0.0.43

- increase refresh token timeouts

### 0.0.42

- fix skoda login

### 0.0.40

- add climate v3 for newer cars. Add Powerpass and Seat Elli

### 0.0.39

- fix id login

### 0.0.36

- add Skoda Enyaq support

### 0.0.35

- add nodeJS v10 compatibility

### 0.0.34

- add auto accept of new privacy consent

### 0.0.32

- correct selection of last recent trips

### 0.0.31

- enable multiple selection of trip types

### 0.0.30

- fix mutiple car problem, add VWv2 mode at the moment there is no different between VW and VWv2

### 0.0.29

- fix skoda refreshToken, smaller improvements

### 0.0.26

- bugfixes

### 0.0.25

- add we charge

### 0.0.24

- add remote state update

### 0.0.23

- add Seat and new climatisation v2

### 0.0.22

- calculate outside temperatur in °C also for Skoda and Audi

### 0.0.21

- add remotes for id

### 0.0.20

- fix audi login, add ID login

### 0.0.19

- save status objects in state by id instead of consecutive numbers

### 0.0.18

- fix battery status for 2020 models

### 0.0.17

- add support for 2020 models

### 0.0.16

- fix js.controller 3 problems

### 0.0.11

- fix audi bug with multiple vehicles
- hide status update error if feature is not available

## License

MIT License

Copyright (c) 2019-2030 ta2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
