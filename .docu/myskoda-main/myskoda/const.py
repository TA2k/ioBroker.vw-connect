"""Common constants."""

# Client id extracted from the MySkoda Android app.
CLIENT_ID = "7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com"
REDIRECT_URI = "myskoda://redirect/login/"

BASE_URL_SKODA = "https://mysmob.api.connect.skoda-auto.cz"
BASE_URL_IDENT = "https://identity.vwgroup.io"

MQTT_BROKER_HOST = "mqtt.messagehub.de"
MQTT_BROKER_PORT = 8883


MQTT_OPERATION_TIMEOUT = 10 * 60  #  10 minutes
MQTT_OPERATION_TOPICS = [
    "air-conditioning/set-air-conditioning-at-unlock",
    "air-conditioning/set-air-conditioning-seats-heating",
    "air-conditioning/set-air-conditioning-timers",
    "air-conditioning/set-air-conditioning-without-external-power",
    "air-conditioning/set-target-temperature",
    "air-conditioning/start-stop-air-conditioning",
    "auxiliary-heating/start-stop-auxiliary-heating",
    "air-conditioning/start-stop-window-heating",
    "air-conditioning/windows-heating",
    "charging/start-stop-charging",
    "charging/update-battery-support",
    "charging/update-auto-unlock-plug",
    "charging/update-care-mode",
    "charging/update-charge-limit",
    "charging/update-charge-mode",
    "charging/update-charging-profiles",
    "charging/update-charging-current",
    "departure/update-departure-timers",
    "departure/update-minimal-soc",
    "vehicle-access/honk-and-flash",
    "vehicle-access/lock-vehicle",
    "vehicle-services-backup/apply-backup",
    "vehicle-wakeup/wakeup",
]

MQTT_SERVICE_EVENT_TOPICS = [
    "air-conditioning",
    "charging",
    "departure",
    "vehicle-status/access",
    "vehicle-status/lights",
    "vehicle-status/odometer",
]

MQTT_VEHICLE_EVENT_TOPICS = [
    "vehicle-connection-status-update",
    "vehicle-ignition-status",
]

MQTT_ACCOUNT_EVENT_TOPICS = [
    "account-event/privacy",
]
MQTT_KEEPALIVE = 60
MQTT_RECONNECT_DELAY = 5
MQTT_MAX_RECONNECT_DELAY = 600
MQTT_FAST_RETRY = 10
MAX_RETRIES = 5


CACHE_USER_ENDPOINT_IN_HOURS = 6
CACHE_VEHICLE_HEALTH_IN_HOURS = 6

REQUEST_TIMEOUT_IN_SECONDS = 300
DEFAULT_DEBOUNCE_WAIT_SECONDS = 10.0
OPERATION_REFRESH_DELAY_SECONDS = 5.0
