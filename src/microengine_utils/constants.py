import platform
import os

# Configure Datadog metric keys for use in the application
HTTP_REQUEST = 'microengine.http'
HTTP_RESPONSE_TIMER = 'microengine.request.time'
SCAN_SUCCESS = 'microengine.scan.success'
SCAN_FAIL = 'microengine.scan.fail'
SCAN_EXPIRED = 'microengine.scan.expired'
SCAN_TYPE_VALID = 'microengine.scan.valid-type'
SCAN_TYPE_INVALID = 'microengine.scan.invalid-type'
SCAN_NO_RESULT = 'microengine.scan.no-result'
SCAN_TIME = 'microengine.scan.time'
SCAN_VERDICT = 'microengine.scan.verdict'

WINE_EXE = '/usr/bin/wine'

PLATFORM_OS = 'Windows' if platform.platform() == 'Windows' else 'Unix'
PLATFORM_MACHINE = platform.machine()

INSTALL_DIR = os.getenv(
    'MICROENGINE_INSTALL_DIR',
    'C:\\microengine\\' if PLATFORM_OS == 'Windows' else '/usr/src/app',
)

VENDOR_DIR = os.getenv(
    'MICROENGINE_VENDOR_DIR',
    os.path.joinpath(INSTALL_DIR, 'vendor/'),
)
