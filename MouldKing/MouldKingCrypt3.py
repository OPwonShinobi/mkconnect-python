__author__ = "J0EK3R"
__editor__ = "OPWonShinobi"
__version__ = "0.2"

class MouldKingCrypt3 :
    #Copied the utility methods + members from MouldKingCrypt, made everything public, easier to debug in pycharm
    Array_C1C2C3C4C5 = bytes([0xC1, 0xC2, 0xC3, 0xC4, 0xC5])

    @staticmethod
    def Crypt(rawDataArray: bytes) -> bytes:
        step1 = bytearray(15)
        step1[:5] = [163, 35, 195, 67, 131]
        step1[5:13] = rawDataArray
        checksum = MouldKingCrypt3.calc_checksum_from_arrays(MouldKingCrypt3.Array_C1C2C3C4C5, rawDataArray)
        step1[13] = (checksum & 255)
        step1[14] = ((checksum >> 8) & 255)

        output1 = MouldKingCrypt3.crypt_array(step1.copy(), MouldKingCrypt3.create_magic_array(63, 7))

        step2 = bytearray(33)
        #step2[:15] = all 0s
        step2[18:] = output1
        step2[15:18] = [142, 240, 170] #possible exists another way to get these magic numbers, possibly using Array_C1C2C3C4C5?, good enough for now
        output2 = MouldKingCrypt3.crypt_array(step2.copy(), MouldKingCrypt3.create_magic_array(37, 7))
        return output2[15:]

    @staticmethod
    def create_magic_array(magic_number: int, size: int) -> bytes:
        magic_array = [0] * size
        magic_array[0] = 1

        for index in range(1, 7):
            magic_array[index] = (magic_number >> (6 - index)) & 1

        return magic_array

    @staticmethod
    def revert_bits_byte(value: int) -> int:
        result = 0
        for index_bit in range(8):
            if ((1 << index_bit) & value) != 0:
                result = result | (1 << (7 - index_bit))
        return result

    @staticmethod
    def revert_bits_int(value: int) -> int:
        result = 0
        for index_bit in range(16):
            if ((1 << index_bit) & value) != 0:
                result |= 1 << (15 - index_bit)
        return 65535 & result

    @staticmethod
    def crypt_array(byte_array: bytes, magic_number_array: bytes) -> bytes:
        # foreach byte of array
        for index_byte in range(len(byte_array)):
            current_byte = byte_array[index_byte]
            current_result = 0
            # foreach bit in byte
            for index_bit in range(8):
                current_result += (((current_byte >> index_bit) & 1) ^ MouldKingCrypt3.shift_magic_array(magic_number_array)) << index_bit
            byte_array[index_byte] = current_result & 255
        return byte_array

    @staticmethod
    def calc_checksum_from_arrays(first_array: bytes, second_array: bytes) -> int:
        result = 65535
        for first_array_index in range(len(first_array)):
            result = (result ^ (first_array[(len(first_array) - 1) - first_array_index] << 8)) & 65535
            for index_bit in range(8):
                current_result = result & 32768
                result <<= 1
                if current_result != 0:
                    result ^= 4129

        for current_byte in second_array:
            result = ((MouldKingCrypt3.revert_bits_byte(current_byte) << 8) ^ result) & 65535
            for index_bit in range(8):
                current_result = result & 32768
                result <<= 1
                if current_result != 0:
                    result ^= 4129

        return MouldKingCrypt3.revert_bits_int(result) ^ 65535

    @staticmethod
    def shift_magic_array(i_arr: bytes) -> bytes:
        r1 = i_arr[3] ^ i_arr[6]
        i_arr[3] = i_arr[2]
        i_arr[2] = i_arr[1]
        i_arr[1] = i_arr[0]
        i_arr[0] = i_arr[6]
        i_arr[6] = i_arr[5]
        i_arr[5] = i_arr[4]
        i_arr[4] = r1
        return i_arr[0]

    #loosely based on MouldKingCrypt.Decrypt(), same checksum logic used it, seemed to match up to data captured from nrf connect
    #Worked off assumption of 0x01:reverse, 0x80:stopped, 0xFF:forward
    @staticmethod
    def Decrypt(encryptedData: bytes) -> bytes:
        if len(encryptedData) != 18:
            raise ValueError("Invalid encrypted data length. Must be 18 bytes.")
        #39-6 = 33 for connect dgrams, 39-4 = 35 for ctrl dgrams
        #add 15 bytes of value 0x00 to front, must become size of 33
        step1 = bytearray(33)
        # collect first 14 bytes from input to use as last 18 bytes, remove last 5 bytes from input, which holds chksum only.
        # *18 must be extended till sequential indexes start coming
        for i in range(len(encryptedData)):
            step1[15 + i] = encryptedData[i]
        output1 = MouldKingCrypt3.crypt_array(step1.copy(), MouldKingCrypt3.create_magic_array(37, 7))
        # collect final bytes (18 -> 33)
        step2 = output1[18:]
        output2 = MouldKingCrypt3.crypt_array(step2.copy(), MouldKingCrypt3.create_magic_array(63, 7))

        decryptedData = output2[5:13]
        checkSumP1 = output2[-1]
        checkSumP2 = output2[-2]
        verifyChecksum = MouldKingCrypt3.calc_checksum_from_arrays(MouldKingCrypt3.Array_C1C2C3C4C5, decryptedData)
        if (verifyChecksum & 255) != checkSumP2:
            raise ValueError("Checksum validation failed")
        if ((verifyChecksum >> 8) & 255) != checkSumP1:
            raise ValueError("Checksum validation failed")
        return decryptedData

    @staticmethod
    def testCheckSum(checksum: int) -> list:
        return [checksum & 255, (checksum >> 8) & 255]
