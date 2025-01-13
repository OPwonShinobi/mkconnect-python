__author__ = "OPWonShinobi"
__version__ = "0.1"

import sys

sys.path.append("MouldKing")
from MouldKing.MouldKingCrypt3 import MouldKingCrypt3

class MouldKing_Hub_3() :
    """
    class handling a MouldKing 3.0 Hub
    """
    def __init__(self):
        pass

    def GetDefaultId(self) -> list:
        return [0x03, 0x44]
    def SetCmdChecksum(self, cmd: list) -> None:
        checksum = 0
        for b in cmd[:6]:
            checksum ^= b
        cmd[6] = checksum

    # format [0xaa,<ID, 2 bytes>,0x80, 0x80, 0x00, chksm,0x55]
    def GetConnPacket(self, idBytes: list) -> bytes:
        datagram = [0xaa, idBytes[0], idBytes[1], 0x80, 0x80, 0x00, 0x00, 0x55]
        self.SetCmdChecksum(datagram)
        return bytes(datagram)
    def GetConnPacketWithDefaultId(self) -> bytes:
        return self.GetConnPacket(self.GetDefaultId())

    # format [0x66,<ID, 2 bytes>,<b >, <a >, 0x00, chksm,0x99]
    def GetCmdPacket(self, aMotorDir: int, bMotorDir: int, id: list) -> bytes:
        abValues = self.GetABMotorValues(aMotorDir, bMotorDir)
        datagram = [0x66, id[0], id[1], abValues[0], abValues[1], 0x00, 0x00, 0x99]
        self.SetCmdChecksum(datagram)
        return bytes(datagram)
    def GetCmdPacketWithDefaultId(self, aMotorDir: int, bMotorDir: int) -> bytes:
        return self.GetCmdPacket(aMotorDir, bMotorDir, self.GetDefaultId())

    def GetABMotorValues(self, aMotorDir: int, bMotorDir: int) -> list:
        if not -1 <= aMotorDir <= 1:
            raise ValueError("Invalid A motor input. Must be one of <-1, 0, 1>.")
        if not -1 <= bMotorDir <= 1:
            raise ValueError("Invalid B motor input. Must be one of <-1, 0, 1>.")
        # same dir
        if aMotorDir == bMotorDir:
            match aMotorDir:
                case 0:
                    return [0x80, 0x80]
                case 1:
                    return [0x80, 0x01]
                case -1:
                    return [0x80, 0xff]
        # opp dir
        if aMotorDir == -bMotorDir:
            match aMotorDir:
                case 1:
                    return [0xff, 0x80]
                case -1:
                    return [0x01, 0x80]
        # 1 side stopped
        if aMotorDir == 0:
            match bMotorDir:
                case 1:
                    return [0xdb, 0x44]
                case -1:
                    return [0xdb, 0xbd]
        if bMotorDir == 0:
            match aMotorDir:
                case 1:
                    return [0x38, 0x44]
                case -1:
                    return [0x38, 0xbd]
