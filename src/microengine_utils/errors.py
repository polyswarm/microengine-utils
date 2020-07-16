from polyswarmartifact.schema.scan_metadata import Verdict
from polyswarmclient import ScanResult
import datadog


class BaseScanError(Exception):
    """Scanning-triggered exception"""
    @property
    def event_name(self):
        e = type(self).__name__
        return e[:e.rindex('ScanError')].lower()


class MalformedResponseScanError(BaseScanError):
    """Couldn't parse scanner output"""
    def __init__(self, output):
        self.output = output


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


class TimeoutScanError(BaseScanError):
    """The scan didn't complete before the timeout"""


class CalledProcessScanError(BaseScanError):
    pass


# File Scanners


class FileOpenFailScanError(BaseScanError):
    """Scanner could not open the file requested"""


class SignaturesMissingError(BaseScanError):
    """Scanner couldn't find signature / models"""


class SignatureUpdateError(Exception):
    """An error occurred while updating signatures"""


class MalformedSignaturesScanError(SignatureUpdateError):
    """Couldn't load signature definitions"""


class TransportEngineUpdateError(SignatureUpdateError):
    """An error occurred while transporting signature updates"""


class MalformedEngineUpdateError(SignatureUpdateError):
    """Signature update contains malformed definitions"""


# Daemons & API Scanners


class ScannerNotFoundError(BaseScanError):
    """Scanner couldn't find signature / models"""


class ServerNotReady(BaseScanError):
    """The server reported it isn't ready to handle files"""


class ServerTransportError(BaseScanError):
    """Problem with network connection, http request or server state"""
