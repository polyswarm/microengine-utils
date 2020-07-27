from typing import ClassVar

class BaseMicroengineError(Exception):
    pass


class BaseScanError(BaseMicroengineError):
    event_name: 'ClassVar[str]'
    """Scanning-triggered exception"""
    def __init_subclass__(cls):
        super().__init_subclass__()
        exc_name = cls.__name__
        if exc_name.endswith('ScanError'):
            exc_name = exc_name[:exc_name.rindex('ScanError')]
        cls.event_name = exc_name.lower()


class UnprocessableScanError(BaseScanError):
    """Unrecognized or illegal microengine output"""


class CalledProcessScanError(BaseScanError):
    """Microengine process has failed"""


class FileSkippedScanError(BaseScanError):
    """Microengine skipped scanning this file"""


class IllegalFileTypeScanError(FileSkippedScanError):
    """Microengine doesn't scan artifacts of this type"""


class EncryptedFileScanError(FileSkippedScanError):
    """File cannot be decrypted"""


class CorruptFileScanError(FileSkippedScanError):
    """File is corrupted, cannot scan"""


class HighCompressionScanError(FileSkippedScanError):
    """File is suspiciously compressed, either because of a huge number of
    files or enormous decompressed size"""


class ServerNotReadyScanError(BaseScanError):
    """The server reported it isn't ready to handle files"""


class BaseSignatureError(BaseMicroengineError):
    """An error occurred while reading, loading or updating signatures"""


class SignatureLoadError(BaseSignatureError):
    """Scanner couldn't load the engine's signatures"""


class SignatureUpdateError(BaseSignatureError):
    """An error occurred while updating signatures"""


class MalformedUpdateError(SignatureUpdateError):
    """Signature update contains malformed definitions"""
