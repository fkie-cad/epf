BIG_ENDIAN = ">"
LITTLE_ENDIAN = "<"

ERR_CONN_FAILED_TERMINAL = "Cannot connect to target; target presumed down. Stopping test run. Note: This likely " \
                           "indicates a failure caused by the previous test case. "

# ERR_CONN_FAILED = "Cannot connect to target; target presumed down. Note: This likely " \
#                   "indicates a failure caused by the previous test case. "

# ERR_CONN_FAILED_RETRY = "Cannot connect to target; Retrying... "

# ERR_CONN_ABORTED = "Target connection lost (socket error: {socket_errno} {socket_errmsg}): You may have a " \
#                    "network issue, or an issue with firewalls or anti-virus. Try " \
#                    "disabling your firewall."

# ERR_CONN_RESET = "Target connection reset."

ERR_CONN_RESET_FAIL = "Target connection reset -- considered a failure case when triggered from post_send"

ERR_CONN_TIMEOUT = 'Timeout'

# Styles for other
STYLE = {
    'host': 'DeepSkyBlue bold',
    'port': 'DeepSkyBlue bold',
    'testn': 'gold bold',
    'bttestn': 'bg:gold bold',
    'red': 'red',
    'redb': 'red bold',
    'bottom-toolbar': 'darkslategray bg:white',
    'w': 'bg:white nobold',

    # Message types
    'error': 'bold bg:red fg:white',
    'fail': 'bold red',
    'test_case': 'bold gold',
    'step': 'bold violet',
    'send': 'cyan',
    'receive': 'cyan',
    'pass': 'bold green',
    'warning': 'bold orange',

    }

# ------ AFL Instrumentation ------
# AFL instrumentation environment variable (set in #define within AFL)
INSTR_AFL_ENV = "__AFL_SHM_ID"
# Size of SHM to be allocated. Is defined by MAP_SIZE and MAP_SIZE_POW2 in AFL, so we do it as well.
# Whole SHM should, in a best case scenario, fully fit into higher layer CPU caches. Thus, it defaults to
# 1 << 16 = 64 Kibibytes! Be aware: smaller map sizes increases the likelihood of collisions within
# the instrumentation, with falsifies insights
INSTR_AFL_MAP_SIZE_POW2 = 16
INSTR_AFL_MAP_SIZE = 1 << INSTR_AFL_MAP_SIZE_POW2

TRACE = False
SPOT_MUT = 0.8
BATCH = False

SHM_OVERWRITE = ""
SHM_POSIX = False
