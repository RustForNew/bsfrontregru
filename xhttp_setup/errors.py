class InstallerError(RuntimeError):
    """Expected, user-facing installer failure."""


class ValidationError(InstallerError):
    """Invalid input or unsafe state."""


class VerificationError(InstallerError):
    """A post-apply check failed."""


class TLSVerificationError(VerificationError):
    """The peer certificate or its exact pin did not match policy."""


class HTTPSResponseError(VerificationError):
    """HTTPS request bytes were sent but no valid status line was received."""
