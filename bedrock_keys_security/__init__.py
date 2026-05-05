"""AWS Bedrock Security Toolkit"""

__version__ = "1.1.0"

from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.core.scanner import PhantomUserScanner

__all__ = ["BedrockKeyDecoder", "PhantomUserScanner", "__version__"]
