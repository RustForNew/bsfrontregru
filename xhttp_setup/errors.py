class InstallerError(RuntimeError):
    """Expected, user-facing installer failure."""


class ValidationError(InstallerError):
    """Invalid input or unsafe state."""


class VerificationError(InstallerError):
    """A post-apply check failed."""
