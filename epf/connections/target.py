from ..ip_constants import DEFAULT_MAX_RECV
from copy import deepcopy


class Target(object):
    """Target descriptor container.

    Takes an ITargetConnection and wraps send/recv


    Example:
        tcp_target = Target(SocketConnection(host='127.0.0.1', port=17971))

    Args:
        connection (itarget_connection.ITargetConnection): Connection to system under test.
    """

    def __init__(self, connection):

        self.target_connection = connection

    def close(self):
        """
        Close connection to the target.

        :return: None
        """
        self.target_connection.close()

    def open(self):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        self.target_connection.open()

    def recv(self, max_bytes: int = DEFAULT_MAX_RECV):
        """
        Receive up to max_bytes data from the target.

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """

        data = self.target_connection.recv(max_bytes=max_bytes)

        return data

    def recv_all(self, max_bytes: int = DEFAULT_MAX_RECV):
        """
        Receive up to max_bytes data from the target. Trying to receive everything

        Args:
            max_bytes (int): Maximum number of bytes to receive.

        Returns:
            Received data.
        """
        data = self.target_connection.recv_all(max_bytes=max_bytes)

        return data

    def send(self, data):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            None
        """
        num_sent = self.target_connection.send(data=data)

