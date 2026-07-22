from abc import ABC, abstractmethod

from pydivert import WinDivert, Packet

# Buffer size for WinDivert recv; matches the socket read size in main.py.
RECV_BUFFER_SIZE = 65575


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.w: WinDivert = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet):
        raise NotImplementedError

    def run(self):
        with self.w:
            while True:
                packet = self.w.recv(RECV_BUFFER_SIZE)
                self.inject(packet)
