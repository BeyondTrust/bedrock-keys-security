"""AWS Bedrock Security Toolkit"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bedrock-keys-security")
except PackageNotFoundError:
    __version__ = "unknown"

from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.core.scanner import PhantomUserScanner

__all__ = ["BedrockKeyDecoder", "PhantomUserScanner", "__version__"]
