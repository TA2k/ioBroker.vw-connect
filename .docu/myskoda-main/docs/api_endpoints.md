# API endpoints

##### Command to sort API endpoints table
```sh
head -n 9 docs/api_endpoints.md && tail -n +10 docs/api_endpoints.md | sort --field-separator=\| --key=4
```

| Source  | Method | Endpoint                                                                   | Used? | Remarks |
| ------- | ------ | -------------------------------------------------------------------------- | ----- | ------- |
| prior98 | POST   | api/v1/authentication/exchange-authorization-code                          | ✅     |         |
| prior98 | POST   | api/v1/authentication/refresh-token                                        | ✅     |         |
| sonar98 | POST   | api/v1/authentication/revoke-token                                         |       |         |
| prior98 | GET    | api/v1/charging/{vin}                                                      | ✅     |         |
| sonar98 | PUT    | api/v1/charging/{vin}/battery-support                                      |       |         |
| sonar98 | GET    | api/v1/charging/{vin}/certificates                                         |       | <pre lang="json"> {"certificates":[{"id":"","issuer":"ELLI","state":"ORDERED"}]}</pre> |
| sonar98 | DELETE | api/v1/charging/{vin}/certificates/{certificateId}                         |       |         |
| sonar98 | POST   | api/v1/charging/{vin}/certificates/{certificateId}                         |       |         |
| lglerup | GET    | api/v1/charging/{vin}/history                                              | ✅     |         |
| lglerup | GET    | api/v1/charging/{vin}/history/export                                       |       |         |
| lglerup | POST   | api/v1/charging/{vin}/profiles                                             |       |         |
| sonar98 | GET    | api/v1/charging/{vin}/profiles                                             |       | <pre lang="json"> {'chargingProfiles': [{'id': 1, 'name': 'testloc', 'settings': {'maxChargingCurrent': 'MAXIMUM', 'minBatteryStateOfCharge': {'minimumBatteryStateOfChargeInPercent': 0}, 'targetStateOfChargeInPercent': 80, 'autoUnlockPlugWhenCharged': 'OFF'}, 'preferredChargingTimes': [{'id': 1, 'enabled': False, 'startTime': '22:00', 'endTime': '06:00'}, {'id': 2, 'enabled': False, 'startTime': '22:00', 'endTime': '06:00'}, {'id': 3, 'enabled': False, 'startTime': '22:00', 'endTime': '06:00'}, {'id': 4, 'enabled': False, 'startTime': '22:00', 'endTime': '06:00'}], 'timers': [{'id': 1, 'enabled': False, 'time': '07:00', 'type': 'RECURRING', 'recurringOn': ['MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY']}, {'id': 2, 'enabled': False, 'time': '09:00', 'type': 'RECURRING', 'recurringOn': ['SATURDAY', 'SUNDAY']}, {'id': 3, 'enabled': False, 'time': '07:00', 'type': 'RECURRING', 'recurringOn': ['MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY']}]}], 'carCapturedTimestamp': '2025-03-25T08:23:15.128Z'} </pre> |
| sonar98 | PUT    | api/v1/charging/{vin}/profiles/{id}                                        |       |         |
| sonar98 | PUT    | api/v1/charging/{vin}/set-auto-unlock-plug                                 | ✅     |         |
| prior98 | PUT    | api/v1/charging/{vin}/set-care-mode                                        | ✅     |         |
| prior98 | PUT    | api/v1/charging/{vin}/set-charge-limit                                     | ✅     |         |
| prior98 | PUT    | api/v1/charging/{vin}/set-charge-mode                                      | ✅     |         |
| sonar98 | PUT    | api/v1/charging/{vin}/set-charging-current                                 | ✅     |         |
| prior98 | POST   | api/v1/charging/{vin}/start                                                | ✅     |         |
| prios98 | POST   | api/v1/charging/{vin}/stop                                                 | ✅     |         |
| sonar98 | GET    | api/v1/discover-news                                                       |       | <pre lang="json"> {"data":[{"text":"Redacted newstext in article. \uD83E\uDD29\n#skodanl","media":[{"type":"VIDEO","url":"https://url-redacted/", originalPostUrl":"https://url-redacted/"},{"text":"\uD835\uDDD7\uD835\uDDF2 \uD835\uDDFB\uD835\uDDF6\uD835\uDDF2\uD835\uDE02\uD835\uDE04\uD835\uDDF2 \uD835\uDDD8\uD835\uDDF9\uD835\uDDFF\uD835\uDDFC\uD835\uDDFE. \uD835\uDDD8\uD835\uDDFF\uD835\uDE03\uD835\uDDEE\uD835\uDDEE\uD835\uDDFF ‘\uD835\uDDFA \uD835\uDDFB\uD835\uDE02 \uD835\uDE07\uD835\uDDF2\uD835\uDDF9\uD835\uDDF3.\nRest is redacted","media":[{"type":"VIDEO","url":"https://url-redacted-again/"}],"originalPostUrl":"https://more-redaction-here/","publishedAt":"2025-03-10T12:13:50Z"}}],"paging":{"pageNumber":0,"hasNextPage":false}}</pre> |
| sonar98 | POST   | api/v1/feedbacks                                                           |       |         |
| sonar98 | GET    | api/v1/maps/image                                                          |       |         |
| sonar98 | GET    | api/v1/maps/nearby-places                                                  |       |         |
| sonar98 | GET    | api/v1/maps/place                                                          |       |         |
| sonar98 | GET    | api/v1/maps/places/charging-stations                                       |       |         |
| sonar98 | POST   | api/v1/maps/places/favourites                                              |       |         |
| sonar98 | GET    | api/v1/maps/places/favourites                                              |       | <pre lang="json"> {"places":[{"type":"LOCATION","id":"67a13f8ca5798575d11cb638","placeDetail":{"placeId":"ChIJB0P0r6mWxkcRmrhc7bHaO0Q","gpsCoordinates":{"latitude":51.6503222,"longitude":5.0469573},"formattedAddress":"Europalaan 1, 5171 KW Kaatsheuvel, Nederland","name":"Efteling"}}],"errors":[]}</pre> |
| sonar98 | DELETE | api/v1/maps/places/favourites/{id}                                         |       |         |
| sonar98 | PUT    | api/v1/maps/places/favourites/{id}                                         |       |         |
| sonar98 | GET    | api/v1/maps/places/predictions                                             |       |         |
| sonar98 | GET    | api/v1/maps/places/{id}                                                    |       |         |
| sonar98 | GET    | api/v1/maps/places/{id}/travel-data                                        |       |         |
| prior98 | GET    | api/v1/maps/positions                                                      | ✅     |         |
| sonar98 | POST   | api/v1/maps/route                                                          |       |         |
| sonar98 | POST   | api/v1/maps/route-url                                                      |       |         |
| sonar98 | PUT    | api/v1/maps/{vin}/route                                                    |       |         |
| sonar98 | GET    | api/v1/notifications                                                       |       | <pre lang="json"> {"notifications":[{"title":"De MyŠkoda app is vernieuwd!","body":"Ontdek de verbeteringen en nieuwe functionaliteiten voor je Enyaq. Download de app nu!","sendDate":"2023-05-10T13:20:35.218Z","category":"ADHOC","vin":"MYVIN","links":[]},{"title":"De MyŠkoda app is vernieuwd!","body":"Ontdek de verbeteringen en nieuwe functionaliteiten voor je Enyaq. Download de app nu!","sendDate":"2023-05-09T07:31:03.545Z","category":"ADHOC","vin":"MYVIN","links":[]}]}</pre> |
| sonar98 | PUT    | api/v1/notifications-subscriptions/{id}                                    |       |         |
| sonar98 | GET    | api/v1/notifications-subscriptions/{id}/settings                           |       |         |
| sonar98 | POST   | api/v1/notifications-subscriptions/{id}/settings                           |       |         |
| sonar98 | GET    | api/v1/ordered-vehicle-information/{commissionId}/equipment                |       |         |
| sonar98 | GET    | api/v1/ordered-vehicle-information/{commissionId}/todos                    |       |         |
| sonar98 | GET    | api/v1/parking/locations/{locationId}/price                                |       |         |
| sonar98 | GET    | api/v1/parking/payment-url                                                 |       |         |
| sonar98 | POST   | api/v1/parking/sessions                                                    |       |         |
| sonar98 | GET    | api/v1/parking/sessions/mine                                               |       |         |
| sonar98 | DELETE | api/v1/parking/sessions/{sessionId}                                        |       |         |
| sonar98 | POST   | api/v1/predictive-maintenance/vehicles/{vin}/appointment                   |       |         |
| sonar98 | PUT    | api/v1/predictive-maintenance/vehicles/{vin}/setting                       |       |         |
| sonar98 | POST   | api/v1/report                                                              |       |         |
| sonar98 | GET    | api/v1/service-partners                                                    |       |         |
| sonar98 | GET    | api/v1/service-partners/{servicePartnerId}/encoded-url                     |       |         |
| sonar98 | GET    | api/v1/shop/cubic-link                                                     |       |         |
| sonar98 | GET    | api/v1/shop/loyalty-products                                               |       |         |
| sonar98 | POST   | api/v1/shop/loyalty-products/{productCode}                                 |       |         |
| sonar98 | GET    | api/v1/shop/loyalty-products/{productCode}/image                           |       |         |
| sonar98 | GET    | api/v1/shop/subscriptions                                                  |       |         |
| sonar98 | POST   | api/v1/spin                                                                |       |         |
| sonar98 | PUT    | api/v1/spin                                                                |       |         |
| sonar98 | GET    | api/v1/spin/status                                                         |       | <pre lang="json"> {"remainingTries":3,"lockedWaitingTimeInSeconds":0,"state":"DEFINED"}</pre> |
| sonar98 | POST   | api/v1/spin/verify                                                         | ✅     |         |
| prior98 | GET    | api/v1/trip-statistics/{vin}                                               | ✅     |         |
| sonar98 | GET    | api/v1/trip-statistics/{vin}/fuel-prices                                   |       |         |
| sonar98 | POST   | api/v1/trip-statistics/{vin}/fuel-prices                                   |       |         |
| sonar98 | DELETE | api/v1/trip-statistics/{vin}/fuel-prices/{fuelPriceId}                     |       |         |
| sonar98 | PUT    | api/v1/trip-statistics/{vin}/fuel-prices/{fuelPriceId}                     |       |         |
| lglerup | GET    | api/v1/trip-statistics/{vin}/single-trips                                  |       |         |
| lglerup | GET    | api/v1/trip-statistics/{vin}/single-trips/export                           |       |         |
| sonar98 | DELETE | api/v1/users                                                               |       |         |
| prior98 | GET    | api/v1/users                                                               | ✅     |         |
| sonar98 | POST   | api/v1/users/agent-id                                                      |       |         |
| sonar98 | GET    | api/v1/users/consents                                                      |       | <pre lang="json"> {"legalDocumentConsent":{"consented":true,"termsAndConditionsLink":"https://skodaid.vwgroup.io/terms-and-conditions?ui_locale=en","dataPrivacyLink":"https://skodaid.vwgroup.io/data-privacy?ui_locale=en"}}</pre> |
| sonar98 | PUT    | api/v1/users/consents/legal-document                                       |       |         |
| sonar98 | PUT    | api/v1/users/consents/marketing                                            |       |         |
| sonar98 | GET    | api/v1/users/consents/{consentId}                                          |       |         |
| sonar98 | PUT    | api/v1/users/consents/{consentId}                                          |       |         |
| sonar98 | DELETE | api/v1/users/me/account/parking                                            |       |         |
| sonar98 | GET    | api/v1/users/me/account/parking                                            |       |         |
| sonar98 | PUT    | api/v1/users/me/account/parking                                            |       |         |
| sonar98 | DELETE | api/v1/users/me/account/parking/cards/{cardId}                             |       |         |
| sonar98 | PATCH  | api/v1/users/me/account/parking/cards/{cardId}                             |       |         |
| sonar98 | GET    | api/v1/users/me/account/parking/summary                                    |       |         |
| sonar98 | PUT    | api/v1/users/me/account/parking/vehicles                                   |       |         |
| sonar98 | DELETE | api/v1/users/me/account/parking/vehicles/{id}                              |       |         |
| sonar98 | GET    | api/v1/users/pay-to-services/supported-countries                           |       | <pre lang="json"> {"userCountry":"NL","payToPark":{"supportedInUserCountry":true,"supportedCountries":["AT","BE","CH","CZ","DE","DK","ES","FI","FR","HU","IT","NL","NO","PT","SE","SI"]},"payToFuel":{"supportedInUserCountry":false,"supportedCountries":["AT","BE","CH","CZ","DE","DK","ES","LU","PT"]}}</pre> |
| sonar98 | PUT    | api/v1/users/preferences                                                   |       |         |
| sonar98 | GET    | api/v1/users/preferences                                                   |       | <pre lang="json"> {"unitId":"METRIC","theme":"AUTOMATIC","automaticWakeUp":false}</pre> |
| sonar98 | PUT    | api/v1/users/preferred-contact-channel                                     |       |         |
| sonar98 | GET    | api/v1/users/{id}/identities                                               |       |         |
| sonar98 | GET    | api/v1/users/{id}/profile-picture                                          |       |         |
| sonar98 | POST   | api/v1/users/{user_id}/vehicles/{vin}/check                                |       |         |
| prior98 | POST   | api/v1/vehicle-access/{vin}/honk-and-flash                                 | ✅     |         |
| sonar98 | POST   | api/v1/vehicle-access/{vin}/lock                                           | ✅     |         |
| sonar98 | POST   | api/v1/vehicle-access/{vin}/unlock                                         | ✅     |         |
| sonar98 | GET    | api/v1/vehicle-automatization/{vin}/departure/timers                       | ✅     |         |
| sonar98 | POST   | api/v1/vehicle-automatization/{vin}/departure/timers                       | ✅     |         |
| sonar98 | POST   | api/v1/vehicle-automatization/{vin}/departure/timers/settings              | ✅     |         |
| prior98 | GET    | api/v1/vehicle-health-report/warning-lights/{vin}                          | ✅     |         |
| sonar98 | GET    | api/v1/vehicle-information/{vin}                                           |       | <pre lang="json"> {"devicePlatform":"WCAR","vehicleSpecification":{"title":"Škoda Enyaq","manufacturingDate":"2021-04-08","model":"Enyaq","modelYear":"2021","body":"SUV","systemCode":"UNKNOWN","systemModelId":"5AZJJ2","maxChargingPowerInKW":125,"battery":{"capacityInKWh":77},"engine":{"type":"iV","powerInKW":150},"gearbox":{"type":"E1H"}},"renders":[],"compositeRenders":[{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080dayvext_side1080.png","viewPoint":"EXTERIOR_SIDE","type":"REAL","order":0}],"viewType":"UNMODIFIED_EXTERIOR_SIDE"}]}</pre> |
| sonar98 | POST   | api/v1/vehicle-information/{vin}/certificates                              |       |         |
| sonar98 | GET    | api/v1/vehicle-information/{vin}/certificates/{certificateId}              |       |         |
| sonar98 | GET    | api/v1/vehicle-information/{vin}/equipment                                 |       | <pre lang="json">{"equipment":[{"name":"Multifunctional steering wheel and Digital Cockpit","description":"Your car is equipped with a multifunctional steering wheel and digital cockpit.","videoUrl":"https://player.vimeo.com/video/878185910?h=d9f46e4c61","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_01_SteeringWheelCockpit_thb"},{"name":"Front Assist and Turn Assist","description":"Your car is equipped with a front assist and turn assist.","videoUrl":"https://player.vimeo.com/video/877923096?h=d92e6159f9","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_14_FrontAssistTurningAssist_thb"},{"name":"Head-Up Display","description":"Your car is equipped with an augmented reality head-up display.","videoUrl":"https://player.vimeo.com/video/877932413?h=60d3a33d8f","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_06_HeadUpDisplay_thb"},{"name":"Infotainment display with navigation","description":"Your car is equipped with an Infotainment display with new navigation.","videoUrl":"https://player.vimeo.com/video/877936165?h=ba1dec507f","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_05_InfotainmentDisplay_thb"},{"name":"Full LED Matrix headlights","description":"Your car is equipped with a full LED matrix beam headlights.","videoUrl":"https://player.vimeo.com/video/878018636?h=b4cfd8d40b","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_09_MatrixBeamHeadlights_thb"},{"name":"Side Assist","description":"Your car is equipped with a side assist.","videoUrl":"https://player.vimeo.com/video/878184722?h=cb488571c6","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_15_SideAssist_thb"},{"name":"Lane Assist ","description":"Your car is equipped with an adaptive lane assist.","videoUrl":"https://player.vimeo.com/video/888627228?h=22ed8c5108","videoThumbnailUrl":"https://go.skoda.eu/ENYAQ_2021_02_AdaptiveLaneAssist_thb"}]}</pre> |
| sonar98 | GET    | api/v1/vehicle-information/{vin}/renders                                   |       | <pre lang="json">{"renders":[],"compositeRenders":[{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080studiovint_boot1080.png","viewPoint":"INTERIOR_BOOT","type":"REAL","order":0}],"viewType":"UNMODIFIED_INTERIOR_BOOT"},{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080dayvext_rear1080.png","viewPoint":"EXTERIOR_REAR","type":"REAL","order":0}],"viewType":"UNMODIFIED_EXTERIOR_REAR"},{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080studiovint_side1080.png","viewPoint":"INTERIOR_SIDE","type":"REAL","order":0}],"viewType":"UNMODIFIED_INTERIOR_SIDE"},{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080dayvext_front1080.png","viewPoint":"EXTERIOR_FRONT","type":"REAL","order":0}],"viewType":"UNMODIFIED_EXTERIOR_FRONT"},{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080dayvext_side1080.png","viewPoint":"EXTERIOR_SIDE","type":"REAL","order":0}],"viewType":"UNMODIFIED_EXTERIOR_SIDE"},{"layers":[{"url":"https://iprenders.blob.core.windows.net/base5azs21200210/F6F6GPQtW9TAD7-cRLexStAC9HkqZiEy5n-PmosHKDiLh7U62wcV0ft94bRkFx-brBXkRgCUwxmWuHJPNMqn-19201080studiovint_front1080.png","viewPoint":"INTERIOR_FRONT","type":"REAL","order":0}],"viewType":"UNMODIFIED_INTERIOR_FRONT"}]} |
| lglerup | GET    | api/v1/vehicle-information/{vin}/software-version/update-status            |       |         |
| sonar98 | POST   | api/v1/vehicle-services-backups                                            |       |         |
| sonar98 | GET    | api/v1/vehicle-services-backups                                            |       | Contains privacy sensitive settings, redacted, but API response is JSON |
| sonar98 | DELETE | api/v1/vehicle-services-backups/{id}                                       |       |         |
| sonar98 | POST   | api/v1/vehicle-services-backups/{id}/apply                                 |       |         |
| prior98 | POST   | api/v1/vehicle-wakeup/{vin}                                                | ✅     |         |
| EnergyX | GET    | api/v2/air-conditioning/{vin}                                              | ✅     |         |
| EnergyX | GET    | api/v2/air-conditioning/{vin}/active-ventilation                           |       | <pre lang="json"> {"state":"INVALID","durationInSeconds":600,"timers":[],"errors":[{"type":"UNAVAILABLE_CLIMA_INFORMATION"}]}</pre> |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/active-ventilation/start                     | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/active-ventilation/stop                      | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/active-ventilation/timers                    |       |         |
| EnergyX | GET    | api/v2/air-conditioning/{vin}/auxiliary-heating                            | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/auxiliary-heating/start                      | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/auxiliary-heating/stop                       | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/auxiliary-heating/timers                     | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/settings/ac-at-unlock                        | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/settings/ac-without-external-power           | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/settings/seats-heating                       | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/settings/target-temperature                  | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/settings/windows-heating                     | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/start                                        | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/start-window-heating                         | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/stop                                         | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/stop-window-heating                          | ✅     |         |
| EnergyX | POST   | api/v2/air-conditioning/{vin}/timers                                       | ✅     |         |
| EnergyX | GET    | api/v2/car-configurator/url                                                |       |         |
| lglerup | GET    | api/v2/connection-status/{vin}/readiness                                   | ✅     | <pre lang="json"> {'unreachable': False, 'inMotion': False, 'batteryProtectionLimitOn': False} </pre> |
| EnergyX | POST   | api/v2/consents                                                            |       |         |
| lglerup | GET    | api/v2/consents/accessibility-statement                                    |       |         |
| EnergyX | PATCH  | api/v2/consents/eprivacy/{vin}                                             |       |         |
| EnergyX | GET    | api/v2/consents/eprivacy/{vin}                                             |       | <pre lang="json"> {"consented":false,"link":"https://www.skoda-auto.com/other/eprivacy-nl"}</pre> |
| EnergyX | PATCH  | api/v2/consents/location-access                                            |       |         |
| EnergyX | GET    | api/v2/consents/location-access                                            |       | <pre lang="json"> {"consented":false,"termsAndConditionsLink":"https://skodaid.vwgroup.io/terms-and-conditions?ui_locale=nl","dataPrivacyLink":"https://skodaid.vwgroup.io/data-privacy?ui_locale=nl"}</pre> |
| lglerup | GET    | api/v2/consents/loyalty-program                                            |       |         |
| lglerup | PATCH  | api/v2/consents/loyalty-program                                            |       |         |
| lglerup | GET    | api/v2/consents/mandatory                                                  |       | <pre lang="json"> {'consented': True} </pre> |
| lglerup | PATCH  | api/v2/consents/mandatory                                                  |       |         |
| EnergyX | PATCH  | api/v2/consents/marketing                                                  |       |         |
| EnergyX | GET    | api/v2/consents/marketing                                                  |       | <pre lang="json"> {"consented":false,"title":"Marketingtoestemming voor Škoda Auto a.s.","text":"Ik geef hierbij toestemming voor het verwerken van mijn identiteits- en contactinformatie en gebruiksgegevens voor producten en diensten met als doel het mij toesturen van aanbiedingen van producten en diensten van Škoda Auto, inclusief informatie over evenementen, prijsvragen en nieuwsbrieven. De toestemming is 5 jaar geldig.\n\nMeer informatie over gegevensverwerking, inclusief uw recht om de toestemming in te trekken, vindt u [hier](https://www.skoda-auto.com/other/memorandum-marketing-nl)."}</pre> |
| EnergyX | GET    | api/v2/consents/required                                                   |       |         |
| EnergyX | GET    | api/v2/consents/terms-of-use                                               |       | <pre lang="json"> {"termsAndConditionsLink":"https://skodaid.vwgroup.io/terms-and-conditions?ui_locale=nl","dataPrivacyLink":"https://skodaid.vwgroup.io/data-privacy?ui_locale=nl"}</pre> |
| EnergyX | PATCH  | api/v2/consents/third-party-offers                                         |       |         |
| EnergyX | GET    | api/v2/consents/third-party-offers                                         |       | <pre lang="json"> {"consented":false,"text":"Ik geef hierbij toestemming voor het delen van mijn:\n\n- identiteitsgegevens\n- contactgegevens\n- gebruiksgegevens voor producten en diensten   \n\nmet derde partijen. Op basis van deze toestemming mogen Škoda Auto a.s. of deze derde partijen zelf mij aanbiedingen voor producten en diensten sturen, inclusief informatie over evenementen, prijsvragen en nieuwsbrieven van deze derde partijen.\n\nDeze derde partijen omvatten uw favoriete dealer en servicepartner, importeur verantwoordelijk voor de markt, bedrijven van Volkswagen Financial Services Group die werkzaam zijn in de markt en de digitale service- en technologie-hub Škoda X s.r.p. De toestemming is 5 jaar geldig.\n\nMeer informatie over gegevensverwerking, inclusief uw recht om de toestemming in te trekken, is te vinden in het [Privacybeleid](https://www.skoda-auto.com/other/memorandum-marketing-nl)."}</pre> |
| EnergyX | PUT    | api/v2/consents/{id}                                                       |       |         |
| EnergyX | GET    | api/v2/dealers/{dealerId}                                                  |       |         |
| lglerup | POST   | api/v2/feedbacks                                                           |       |         |
| EnergyX | GET    | api/v2/fueling/locations/{locationId}                                      |       |         |
| EnergyX | GET    | api/v2/fueling/sessions                                                    |       |         |
| EnergyX | POST   | api/v2/fueling/sessions                                                    |       |         |
| EnergyX | GET    | api/v2/fueling/sessions/latest                                             |       |         |
| EnergyX | GET    | api/v2/fueling/sessions/{sessionId}                                        |       |         |
| EnergyX | GET    | api/v2/fueling/sessions/{sessionId}/state                                  |       |         |
| EnergyX | GET    | api/v2/garage                                                              | ✅     |         |
| EnergyX | GET    | api/v2/garage/first-vehicle                                                |       |         |
| EnergyX | GET    | api/v2/garage/initial-vehicle                                              |       | Same content as api/v2/garage/vehicles/{vin} of the first vehicle |
| EnergyX | GET    | api/v2/garage/vehicles/ordered/{commissionId}                              |       |         |
| EnergyX | DELETE | api/v2/garage/vehicles/{vin}                                               |       |         |
| EnergyX | PATCH  | api/v2/garage/vehicles/{vin}                                               |       |         |
| EnergyX | GET    | api/v2/garage/vehicles/{vin}                                               | ✅     |         |
| EnergyX | POST   | api/v2/garage/vehicles/{vin}/capabilities/change-user-capability           |       |         |
| lglerup | GET    | api/v2/garage/vehicles/{vin}/fleet                                         |       | <pre lang="json"> {'partOfFleet': False} </pre> |
| EnergyX | PUT    | api/v2/garage/vehicles/{vin}/license-plate                                 |       |         |
| EnergyX | GET    | api/v2/garage/vehicles/{vin}/users/guests                                  |       | <pre lang="json"> {"users":[{"id":"XXXXX-64c0-43d8-9dbd-f82c11ac8df8","firstName":"Joe","lastName":"Guest","nickname":"JG","email":"joe.guest@skodacars.rule.io","profilePictureUrl":"https://mysmob.api.connect.skoda-auto.cz/....","knownToVehicle":true,"hasConsent":true}]}</pre> |
| EnergyX | GET    | api/v2/garage/vehicles/{vin}/users/guests/count                            |       | <pre lang="json"> {"count":1}</pre> |
| EnergyX | DELETE | api/v2/garage/vehicles/{vin}/users/guests/{id}                             |       |         |
| EnergyX | GET    | api/v2/garage/vehicles/{vin}/users/primary                                 |       | Same format as single guest from api/v2/garage/vehicles/{vin}/users/guests |
| lglerup | GET    | api/v2/loyalty-program/details                                             |       | <pre lang="json"> {'name': 'MyŠkoda Club', 'rewardsAvailable': False} </pre> |
| EnergyX | POST   | api/v2/loyalty-program/members                                             |       |         |
| EnergyX | DELETE | api/v2/loyalty-program/members/{id}                                        |       |         |
| EnergyX | GET    | api/v2/loyalty-program/members/{id}                                        |       |         |
| lglerup | PATCH  | api/v2/loyalty-program/members/{id}                                        |       |         |
| lglerup | GET    | api/v2/loyalty-program/members/{id}/badges                                 |       |         |
| lglerup | GET    | api/v2/loyalty-program/members/{id}/badges/{badgeId}                       |       |         |
| lglerup | POST   | api/v2/loyalty-program/members/{id}/badges/{badgeId}/collect-badge         |       |         |
| EnergyX | GET    | api/v2/loyalty-program/members/{id}/challenges                             |       |         |
| EnergyX | DELETE | api/v2/loyalty-program/members/{id}/challenges/{challengeId}/enrollment    |       |         |
| EnergyX | PUT    | api/v2/loyalty-program/members/{id}/challenges/{challengeId}/enrollment    |       |         |
| EnergyX | POST   | api/v2/loyalty-program/members/{id}/daily-check-in                         |       |         |
| lglerup | GET    | api/v2/loyalty-program/members/{id}/games                                  |       |         |
| lglerup | PUT    | api/v2/loyalty-program/members/{id}/games/{gameId}/enrollment              |       |         |
| EnergyX | GET    | api/v2/loyalty-program/members/{id}/rewards                                |       |         |
| EnergyX | POST   | api/v2/loyalty-program/members/{id}/rewards                                |       |         |
| EnergyX | GET    | api/v2/loyalty-program/members/{id}/transactions                           |       |         |
| EnergyX | GET    | api/v2/loyalty-program/salesforce-contacts/{id}                            |       |         |
| EnergyX | GET    | api/v2/manuals/url                                                         |       |         |
| EnergyX | GET    | api/v2/maps/charging-stations/{id}/prices                                  |       |         |
| EnergyX | POST   | api/v2/maps/nearby-places                                                  |       |         |
| EnergyX | GET    | api/v2/maps/places/{id}                                                    |       |         |
| EnergyX | POST   | api/v2/maps/route                                                          |       |         |
| EnergyX | PUT    | api/v2/maps/{vin}/route                                                    |       |         |
| lglerup | GET    | api/v2/shop/cubic-link                                                     |       |         |
| lglerup | GET    | api/v2/shop/loyalty-products                                               |       |         |
| lglerup | POST   | api/v2/shop/loyalty-products/{productCode}                                 |       |         |
| lglerup | GET    | api/v2/shop/loyalty-products/{productCode}/image                           |       |         |
| lglerup | GET    | api/v2/shop/subscriptions                                                  |       |         |
| lglerup | POST   | api/v2/shop/subscriptions/{vin}/order                                      |       |         |
| lglerup | POST   | api/v2/test-drives                                                         |       |         |
| EnergyX | GET    | api/v2/test-drives/dealers                                                 |       |         |
| EnergyX | GET    | api/v2/test-drives/form-definition                                         |       |         |
| EnergyX | GET    | api/v2/vehicle-status/render                                               |       |         |
| EnergyX | GET    | api/v2/vehicle-status/{vin}                                                | ✅     |         |
| EnergyX | GET    | api/v2/vehicle-status/{vin}/driving-range                                  | ✅     |         |
| lglerup | GET    | api/v2/vehicle-status/{vin}/driving-score                                  |       |         |
| EnergyX | GET    | api/v2/widgets/vehicle-status/{vin}                                        |       | <pre lang="json"> {"vehicle":{"name":"REDACTED","licensePlate":"REDACTED","renderUrl":"https://mspgwlivestorage.blob.core.windows.net/widget-renders/XXXX.png?etag=YYYY"},"vehicleStatus":{"doorsLocked":"CLOSED","drivingRangeInKm":121},"chargingStatus":{"stateOfChargeInPercent":35,"remainingTimeToFullyChargedInMinutes":0},"parkingPosition":{"state":"PARKED","maps":{"lightMapUrl":"https://mysmob.api.connect.skoda-auto.cz/api/v1/maps/image?latitude=xxxxx&longitude=yyyyx&width=533&height=400&zoom=17"},"gpsCoordinates":{"latitude":xxxx,"longitude":yyyy},"formattedAddress":"Street 1, Town"}}</pre> |
| lglerup | GET    | api/v3/car-configurator/url                                                |       |         |
| EnergyX | GET    | api/v3/maps/image                                                          |       |         |
| EnergyX | POST   | api/v3/maps/nearby-places                                                  |       |         |
| lglerup | GET    | api/v3/maps/offers                                                         |       |         |
| lglerup | POST   | api/v3/maps/offers/analytics                                               |       |         |
| lglerup | POST   | api/v3/maps/offers/{id}/redemption                                         |       |         |
| lglerup | GET    | api/v3/maps/places                                                         |       |         |
| EnergyX | POST   | api/v3/maps/places/favourites                                              |       |         |
| EnergyX | GET    | api/v3/maps/places/favourites                                              |       | <pre lang="json"> {"places":[{"type":"LOCATION","id":"67a13f8ca5798575d11cb638","placeDetail":{"placeId":"ChIJB0P0r6mWxkcRmrhc7bHaO0Q","gpsCoordinates":{"latitude":51.6503222,"longitude":5.0469573},"formattedAddress":"Europalaan 1, 5171 KW Kaatsheuvel, Nederland","name":"Efteling"}}],"errors":[]}</pre> |
| EnergyX | DELETE | api/v3/maps/places/favourites/{id}                                         |       |         |
| EnergyX | PUT    | api/v3/maps/places/favourites/{id}                                         |       |         |
| lglerup | GET    | api/v3/maps/places/predictions                                             |       |         |
| EnergyX | GET    | api/v3/maps/places/{id}                                                    |       |         |
| lglerup | GET    | api/v3/maps/positions/vehicles/{vin}/parking                               |       |         |
| lglerup | POST   | api/v3/maps/recommendations/charging-stations                              |       |         |
| lglerup | POST   | api/v3/maps/route                                                          |       |         |
| lglerup | PUT    | api/v3/maps/{vin}/route                                                    |       |         |
| EnergyX | GET    | api/v3/vehicle-maintenance/service-partners                                |       |         |
| EnergyX | GET    | api/v3/vehicle-maintenance/service-partners/{servicePartnerId}             |       |         |
| EnergyX | GET    | api/v3/vehicle-maintenance/service-partners/{servicePartnerId}/encoded-url |       |         |
| EnergyX | GET    | api/v3/vehicle-maintenance/vehicles/{vin}                                  | ✅     |         |
| EnergyX | GET    | api/v3/vehicle-maintenance/vehicles/{vin}/report                           | ✅     | <pre lang="json"> {"capturedAt":"2025-03-19T07:33:41.681Z","inspectionDueInDays":84,"mileageInKm":91870}</pre> |
| EnergyX | POST   | api/v3/vehicle-maintenance/vehicles/{vin}/service-booking                  |       |         |
| EnergyX | DELETE | api/v3/vehicle-maintenance/vehicles/{vin}/service-partner                  |       |         |
| EnergyX | PUT    | api/v3/vehicle-maintenance/vehicles/{vin}/service-partner                  |       |         |
