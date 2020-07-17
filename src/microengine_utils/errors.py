from .scanner import EngineConfig


class BaseMicroengineError(Exception):
    pass


class BaseScanError(BaseMicroengineError):
    """Scanning-triggered exception"""
    @property
    def event_name(self):
        name, *_ = type(self).__name__.partition('ScanError')
        return ''.join(c + '_' if c.isupper() else '' for c in name)


class UnprocessableScanError(BaseScanError):
    """Unrecognized or illegal microengine output"""


class CalledProcessScanError(BaseScanError):
    """Microengine process has failed"""


class SkippedFileScanError(BaseScanError):
    """Microengine skipped scanning this file"""


class IllegalFileTypeScanError(FileSkippedScanError):
    """Microengine doesn't scan artifacts of this type"""
    def __init__(self, file_type=None, **kwargs):
        if isinstance(file_type, str):
            kwargs.set_default('file_type', file_type)
        return super().__init__(kwargs)


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
