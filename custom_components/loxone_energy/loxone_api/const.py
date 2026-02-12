"""Constants for the Loxone WebSocket API."""

# WebSocket
WS_PATH = "/ws/rfc6455"
WS_PROTOCOL = "remotecontrol"

# Commands
CMD_GET_PUBLIC_KEY = "jdev/sys/getPublicKey"
CMD_KEY_EXCHANGE = "jdev/sys/keyexchange/{}"
CMD_GET_KEY2 = "jdev/sys/getkey2/{}"
CMD_AUTHENTICATE = "jdev/sys/authenticate/{}"
CMD_GET_TOKEN = "jdev/sys/getjwt/{}/{}/{}"
CMD_REFRESH_TOKEN = "jdev/sys/refreshjwt/{}/{}"
CMD_ENCRYPT = "jdev/sys/enc/{}"
CMD_ENABLE_STATUS_UPDATE = "jdev/sps/enablebinstatusupdate"
CMD_GET_STRUCTURE = "data/LoxAPP3.json"
CMD_KEEPALIVE = "keepalive"

# Binary message types
MSG_TYPE_TEXT = 0
MSG_TYPE_BINARY = 1
MSG_TYPE_VALUE_STATES = 2
MSG_TYPE_TEXT_STATES = 3
MSG_TYPE_DAYTIMER_STATES = 4
MSG_TYPE_OUT_OF_SERVICE = 5
MSG_TYPE_KEEPALIVE = 6
MSG_TYPE_WEATHER_STATES = 7

# Binary header
HEADER_LENGTH = 8
HEADER_MARKER = 0x03

# Info flags
INFO_FLAG_ESTIMATED = 0x01
INFO_FLAG_MORE_DATA = 0x80

# Value state entry: 16-byte UUID + 8-byte float64 = 24 bytes
VALUE_STATE_ENTRY_SIZE = 24

# Keepalive interval (seconds)
KEEPALIVE_INTERVAL = 60

# Reconnect backoff (seconds)
RECONNECT_MIN = 5
RECONNECT_MAX = 300

# Token permissions
TOKEN_PERMISSION = 2  # App permission
TOKEN_UUID = "6374616c-6f78-656e-6572-677968617373"  # "ctloxenergyhass" as UUID
TOKEN_INFO = "LoxoneEnergy-HA"
