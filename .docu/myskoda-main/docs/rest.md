## Unimplemented routes

### Update charging location

**METHOD:** `PUT`
**URL:** `https://mysmob.api.connect.skoda-auto.cz/api/v1/charging/{vin}/profiles/{id}`
**JSON:**

```json
{
    "id": 1,
    "name": "Home",
    "preferredChargingTimes": [
        {
            "enabled": true,
            "endTime": "18:00",
            "id": 1,
            "startTime": "09:00"
        },
        {
            "enabled": false,
            "endTime": "06:00",
            "id": 2,
            "startTime": "22:00"
        },
        {
            "enabled": false,
            "endTime": "06:00",
            "id": 3,
            "startTime": "22:00"
        },
        {
            "enabled": false,
            "endTime": "06:00",
            "id": 4,
            "startTime": "22:00"
        }
    ],
    "settings": {
        "autoUnlockPlugWhenCharged": "PERMANENT",
        "maxChargingCurrent": "MAXIMUM",
        "minBatteryStateOfCharge": {
            "enabled": true,
            "minimumBatteryStateOfChargeInPercent": 40
        },
        "targetStateOfChargeInPercent": 90
    },
    "timers": [
        {
            "enabled": false,
            "id": 1,
            "recurringOn": [
                "MONDAY",
                "TUESDAY",
                "WEDNESDAY",
                "THURSDAY",
                "FRIDAY"
            ],
            "time": "07:00",
            "type": "RECURRING"
        },
        {
            "enabled": false,
            "id": 2,
            "recurringOn": [
                "SATURDAY",
                "SUNDAY"
            ],
            "time": "09:00",
            "type": "RECURRING"
        },
        {
            "enabled": false,
            "id": 3,
            "recurringOn": [
                "MONDAY",
                "TUESDAY",
                "WEDNESDAY",
                "THURSDAY",
                "FRIDAY",
                "SATURDAY",
                "SUNDAY"
            ],
            "time": "07:00",
            "type": "RECURRING"
        }
    ]
}
```

### Get charging locations

**METHOD:** `GET`
**URL:** `https://mysmob.api.connect.skoda-auto.cz/api/v1/charging/{vin}/profiles`
**JSON:**

```json
{
    "carCapturedTimestamp": "2024-09-17T16:12:54.076Z",
    "chargingProfiles": [
        {
            "id": 1,
            "name": "Home",
            "preferredChargingTimes": [
                {
                    "enabled": true,
                    "endTime": "18:00",
                    "id": 1,
                    "startTime": "09:00"
                },
                {
                    "enabled": false,
                    "endTime": "06:00",
                    "id": 2,
                    "startTime": "22:00"
                },
                {
                    "enabled": false,
                    "endTime": "06:00",
                    "id": 3,
                    "startTime": "22:00"
                },
                {
                    "enabled": false,
                    "endTime": "06:00",
                    "id": 4,
                    "startTime": "22:00"
                }
            ],
            "settings": {
                "autoUnlockPlugWhenCharged": "PERMANENT",
                "maxChargingCurrent": "MAXIMUM",
                "minBatteryStateOfCharge": {
                    "minimumBatteryStateOfChargeInPercent": 40
                },
                "targetStateOfChargeInPercent": 90
            },
            "timers": [
                {
                    "enabled": false,
                    "id": 1,
                    "recurringOn": [
                        "MONDAY",
                        "TUESDAY",
                        "WEDNESDAY",
                        "THURSDAY",
                        "FRIDAY"
                    ],
                    "time": "07:00",
                    "type": "RECURRING"
                },
                {
                    "enabled": false,
                    "id": 2,
                    "recurringOn": [
                        "SATURDAY",
                        "SUNDAY"
                    ],
                    "time": "09:00",
                    "type": "RECURRING"
                },
                {
                    "enabled": false,
                    "id": 3,
                    "recurringOn": [
                        "MONDAY",
                        "TUESDAY",
                        "WEDNESDAY",
                        "THURSDAY",
                        "FRIDAY",
                        "SATURDAY",
                        "SUNDAY"
                    ],
                    "time": "07:00",
                    "type": "RECURRING"
                }
            ]
        }
    ]
}
```

### Get ordered vehicle details

**METHOD:** `GET`
**URL:** `https://mysmob.api.connect.skoda-auto.cz/api/v2/garage/vehicles/ordered/{commissionId}`
**JSON:**

```json
{
    "commissionId": "123456-123-2025",
    "name": "Enyaq",
    "activationState": "DISABLED",
    "orderStatus": "ORDER_CONFIRMED",
    "checkPoints": [
        {
            "status": "ORDER_CONFIRMED"
        },
        {
            "status": "IN_PRODUCTION"
        },
        {
            "status": "IN_DELIVERY"
        },
        {
            "status": "TO_HANDOVER"
        }
    ],
    "renders": [],
    "compositeRenders": [],
    "vehicleSpecification": {
        "model": "Škoda Enyaq",
        "trimLevel": "85",
        "exteriorColour": "Olibo Green",
        "interiorColour": "Loft",
        "battery": {
            "capacityInKWh": 77
        },
        "wltpConsumption": {}
    },
    "dealer": {
        "servicePartnerId": "DNKC00409"
    },
    "errors": [
        {
            "type": "MISSING_RENDER",
            "description": "Getting render of view point {interior_front} for vehicle commission ID {123456-123-2025} failed with message {404 Not Found from GET http://render-service/api/v1/renders/ordered-vehicles/123456-123-2025}"
        },
        {
            "type": "MISSING_RENDER",
            "description": "Getting render of view point {exterior_front} for vehicle commission ID {123456-123-2025} failed with message {404 Not Found from GET http://render-service/api/v1/renders/ordered-vehicles/123456-123-2025}"
        },
        {
            "type": "MISSING_RENDER",
            "description": "Getting render of view point {interior_boot} for vehicle commission ID {123456-123-2025} failed with message {404 Not Found from GET http://render-service/api/v1/renders/ordered-vehicles/123456-123-2025}"
        },
        {
            "type": "MISSING_RENDER",
            "description": "Getting render of view point {interior_side} for vehicle commission ID {123456-123-2025} failed with message {404 Not Found from GET http://render-service/api/v1/renders/ordered-vehicles/123456-123-2025}"
        },
        {
            "type": "MISSING_RENDER",
            "description": "Getting render of view point {exterior_rear} for vehicle commission ID {123456-123-2025} failed with message {404 Not Found from GET http://render-service/api/v1/renders/ordered-vehicles/123456-123-2025}"
        },
        {
            "type": "MISSING_RENDER",
            "description": "Getting render of view point {exterior_side} for vehicle commission ID {123456-123-2025} failed with message {404 Not Found from GET http://render-service/api/v1/renders/ordered-vehicles/123456-123-2025}"
        }
    ]
}
```