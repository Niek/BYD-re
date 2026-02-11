"""pybyd exceptions."""


class BydError(Exception):
    """Base exception for pybyd."""


class BydApiError(BydError):
    """BYD API error."""


class BydAuthenticationError(BydApiError):
    """Authentication failure."""


class BydRemoteControlError(BydApiError):
    """Remote command failure."""
