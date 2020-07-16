class BaseScanError(Exception):
    """Scanning-triggered exception"""
    @property
    def event_name(self):
        e = type(self).__name__
        return e[:e.rindex('ScanError')] if e.endswith('ScanError') else e


class MalformedResponseScanError(BaseScanError):
    """Couldn't parse scanner output"""
    def __init__(self, output):
        self.output = output
        super().__init__(output)


class TimeoutScanError(BaseScanError):
    """The scan didn't complete before the timeout"""


class CalledProcessScanError(BaseScanError):
    """The scanner process has failed"""
    def __init__(self, cmd, reason):
        super().__init__(cmd, reason)


class CommandNotFoundScanError(BaseScanError):
    """Scanner binary not found"""
    def __init__(self, cmd):
        super().__init__(cmd)


class FileSkippedScanError(BaseScanError):
    """Scanner requested to skip this file"""


class IllegalFileTypeScanError(FileSkippedScanError):
    """Scanner requested to skip this File"""


class FileEncryptedScanError(FileSkippedScanError):
    """File cannot be decrypted"""


class FileCorruptedScanError(FileSkippedScanError):
    """File is corrupted, cannot scan"""


class HighCompressionScanError(FileSkippedScanError):
    """File is suspiciously compressed, either because of a huge number of
    files or enormous decompressed size"""


class SignaturesMissingError(BaseScanError):
    """Scanner couldn't find signature / models"""


class MalformedSignaturesScanError(BaseScanError):
    """Couldn't load signature definitions"""


class ServerNotReady(BaseScanError):
    """The server reported it isn't ready to handle files"""


class ServerTransportError(BaseScanError):
    """Problem with network connection, http request or server state"""


class SignatureUpdateError(Exception):
    """An error occurred while updating signatures"""


class TransportEngineUpdateError(SignatureUpdateError):
    """An error occurred while transporting signature updates"""


class MalformedEngineUpdateError(SignatureUpdateError):
    """Signature update contains malformed definitions"""
