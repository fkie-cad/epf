import attr


class EPFError(Exception):
    pass


class EPFRestartFailedError(EPFError):
    pass


class EPFTargetConnectionFailedError(EPFError):
    pass


class EPFPaused(EPFError):
    pass


class EPFTestCaseAborted(EPFError):
    pass


class EPFTargetConnectionReset(EPFError):
    pass


class EPFTargetRecvTimeout(EPFError):
    pass


@attr.s
class EPFTargetConnectionAborted(EPFError):
    """
    Raised on `errno.ECONNABORTED`.
    """
    socket_errno = attr.ib()
    socket_errmsg = attr.ib()


class EPFRpcError(EPFError):
    pass


class EPFRuntimeError(Exception):
    pass


class SizerNotUtilizedError(Exception):
    pass


class MustImplementException(Exception):
    pass
