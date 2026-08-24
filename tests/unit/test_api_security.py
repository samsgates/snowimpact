import hashlib
import hmac

from snowimpact.api.app import verify_github_signature
from snowimpact.core.settings import get_settings


def test_signature_false_without_config():
    get_settings.cache_clear()
    assert verify_github_signature(b"{}", "sha256=bad") is False
