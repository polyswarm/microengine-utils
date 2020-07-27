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

WINE_EXE = os.getenv('WINEPATH', '/usr/bin/wine')
DATADOG_API_KEY = os.getenv('DATADOG_API_KEY')
DATADOG_APP_KEY = os.getenv('DATADOG_APP_KEY')

PLATFORM_MACHINE = platform.machine()
PLATFORM_OS = 'Windows' if platform.platform() == 'Windows' else 'Unix'

if PLATFORM_OS == 'Windows':
    OS_TYPE = 'windows'
elif os.path.exists(WINE_EXE):
    OS_TYPE = 'wine'
else:
    OS_TYPE = 'linux'

def engenv(name, default=None):
    return os.getenv('MICROENGINE_' + name, default)

INSTALL_DIR = engenv(
    'INSTALL_DIR',
    'C:\\microengine\\' if PLATFORM_OS == 'Windows' else '/usr/src/app',
)

VENDOR_DIR = engenv('VENDOR_DIR', os.path.join(INSTALL_DIR, 'vendor/'))
ENGINE_NAME = engenv('NAME')
ENGINE_CMD = engenv('CMD_EXE')
SIGNATURE_DIR = engenv('SIGNATURE_DIR')
