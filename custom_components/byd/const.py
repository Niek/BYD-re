"""Constants for the BYD integration."""

DOMAIN = "byd"
PLATFORMS = [
    "sensor",
    "binary_sensor",
    "device_tracker",
    "lock",
    "cover",
    "climate",
    "switch",
    "siren",
    "light",
]

CONF_COUNTRY_CODE = "country_code"
CONF_SERVER_REGION = "server_region"
CONF_BASE_URL = "base_url"
CONF_VIN = "vin"

DEFAULT_COUNTRY_CODE = "NL"
DEFAULT_SERVER_REGION = "-eu"
DEFAULT_SCAN_INTERVAL = 60

ATTR_RAW = "raw"
