from .cloud import CLOUD_PATTERNS
from .tokens import TOKEN_PATTERNS
from .database import DATABASE_PATTERNS
from .payment import PAYMENT_PATTERNS
from .auth import AUTH_PATTERNS
from .generic import GENERIC_PATTERNS

PATTERNS = (
    CLOUD_PATTERNS +
    TOKEN_PATTERNS +
    DATABASE_PATTERNS +
    PAYMENT_PATTERNS +
    AUTH_PATTERNS +
    GENERIC_PATTERNS
)

__all__ = ["PATTERNS"]