"""Methods for anonymizing data from the API."""

import re

ACCESS_TOKEN = "eyJ0eXAiOiI0ODEyODgzZi05Y2FiLTQwMWMtYTI5OC0wZmEyMTA5Y2ViY2EiLCJhbGciOiJSUzI1NiJ9"  # noqa: S105
USER_ID = "b8bc126c-ee36-402b-8723-2c1c3dff8dec"
VIN = "TMOCKAA0AA000000"
VIN_REGEX = re.compile(r"TMB\w{14}")
ADDRESS = {
    "city": "Example City",
    "street": "Example Avenue",
    "houseNumber": "15",
    "zipCode": "54321",
    "countryCode": "DEU",
}
SERVICE_PARTNER_ID = "DEU11111"
PARTNER_NUMBER = "1111"
PARTNER_NAME = "Example Service Partner"
LOCATION = {
    "latitude": 53.470636,
    "longitude": 9.689872,
}
EMAIL = "user@example.com"
PHONE = "+49 1234 567890"
VEHICLE_NAME = "Example Car"
LICENSE_PLATE = "HH AA 1234"
URL = "https://example.com"
FIRST_NAME = "John"
LAST_NAME = "Dough"
NICKNAME = "Johnny D."
PROFILE_PICTURE_URL = "https://example.com/profile.jpg"
DATE_OF_BIRTH = "2000-01-01"

SERVICE_PARTNER = {
    "name": PARTNER_NAME,
    "partnerNumber": PARTNER_NUMBER,
    "id": SERVICE_PARTNER_ID,
    "contact": {
        "phone": PHONE,
        "url": URL,
        "email": EMAIL,
    },
    "address": ADDRESS,
    "location": LOCATION,
}
FORMATTED_ADDRESS = "1600 Pennsylvania Ave NW, Washington, DC 20500, USA"
PROFILE_NAME = "Example Profile"


def anonymize_info(data: dict) -> dict:
    """Anonymize select parts if the input from the info dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    data["vin"] = VIN
    data["name"] = VEHICLE_NAME
    if "licensePlate" in data:
        data["licensePlate"] = LICENSE_PLATE
    if "servicePartner" in data:
        data["servicePartner"]["servicePartnerId"] = SERVICE_PARTNER_ID
    return data


def anonymize_maintenance(data: dict) -> dict:
    """Anonymize select parts if the input from the maintenance dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    if "preferredServicePartner" in data:
        data["preferredServicePartner"].update(SERVICE_PARTNER)
    if "predictiveMaintenance" in data:
        data["predictiveMaintenance"]["setting"]["email"] = EMAIL
        data["predictiveMaintenance"]["setting"]["phone"] = PHONE
    for booking in data.get("customerService", {}).get("bookingHistory", []):
        booking["servicePartner"].update(SERVICE_PARTNER)
    for booking in data.get("customerService", {}).get("activeBookings", []):
        booking["servicePartner"].update(SERVICE_PARTNER)
    return data


def anonymize_charging(data: dict) -> dict:
    """Anonymize select parts if the input from the charging dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_chargingprofiles(data: dict) -> dict:
    """Anonymize select parts if the input from the chargingprofiles dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    if len(data["chargingProfiles"]) >= 1:
        for profile in data["chargingProfiles"]:
            profile["name"] = PROFILE_NAME
            if "location" in profile:
                profile["location"] = LOCATION
    if "currentVehiclePositionProfile" in data:
        data["currentVehiclePositionProfile"]["name"] = PROFILE_NAME
    return data


def anonymize_status(data: dict) -> dict:
    """Anonymize select parts if the input from the status dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_air_conditioning(data: dict) -> dict:
    """Anonymize select parts if the input from the air_conditioning dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_auxiliary_heating(data: dict) -> dict:
    """Anonymize select parts if the input from the auxiliary_heating dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_departure_timers(data: dict) -> dict:
    """Anonymize select parts if the input from the departure timers dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_positions(data: dict) -> dict:
    """Anonymize select parts if the input from the positions dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    if "positions" in data:
        for position in data["positions"]:
            position["gpsCoordinates"] = LOCATION
            position["address"] = ADDRESS
    return data


def anonymize_parking_position(data: dict) -> dict:
    """Anonymize select parts if the input from the parking_position dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    if "parkingPosition" in data:
        data["parkingPosition"]["gpsCoordinates"] = LOCATION
    if "formattedAddress" in data:
        data["formattedAddress"] = FORMATTED_ADDRESS
    return data


def anonymize_driving_range(data: dict) -> dict:
    """Anonymize select parts if the input from the driving_range dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_trip_statistics(data: dict) -> dict:
    """Anonymize select parts if the input from the trip_statistics dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_single_trip_statistics(data: dict) -> dict:
    """Anonymize select parts if the input from the single_trip_statistics dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_vehicle_connection_status(data: dict) -> dict:
    """Anonymize select parts if the input from the vehicle_connection_status dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_health(data: dict) -> dict:
    """Anonymize select parts if the input from the health dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    return data


def anonymize_user(data: dict) -> dict:
    """Anonymize select parts if the input from the user dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    data["email"] = EMAIL
    data["firstName"] = FIRST_NAME
    data["lastName"] = LAST_NAME
    data["nickname"] = NICKNAME
    data["profilePictureUrl"] = PROFILE_PICTURE_URL
    data["dateOfBirth"] = DATE_OF_BIRTH
    data["phone"] = PHONE

    return data


def anonymize_garage_entry(data: dict) -> dict:
    """Anonymize select parts if the input from the vehicle dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    data["vin"] = VIN
    data["name"] = VEHICLE_NAME
    return data


def anonymize_garage(data: dict) -> dict:
    """Anonymize select parts if the input from the garage dict.

    Args:
        data: input dictionary

    Returns:
        dict
    """
    if "vehicles" in data:
        data["vehicles"] = [anonymize_garage_entry(vehicle) for vehicle in data["vehicles"]]
    return data


def anonymize_url(url: str) -> str:
    """Anonymize a VIN found in a URL.

    Args:
        url: input URL string

    Returns:
        str: URL string with any VIN anonymized
    """
    return VIN_REGEX.sub(VIN, url)
