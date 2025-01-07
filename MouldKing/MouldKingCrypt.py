__author__ = "J0EK3R"
__version__ = "0.1"

class MouldKingCrypt :
    """
    class with static methods to do MouldKing encryption
    """

    # static class variables
    __Array_C1C2C3C4C5 = bytes([0xC1, 0xC2, 0xC3, 0xC4, 0xC5])

    @staticmethod
    def CreateTelegramForHCITool(manufacturerId: bytes, rawDataArray: bytes) -> bytes:
        """
        Create input data for hcitool 
        """
        cryptedArray = MouldKingCrypt.Crypt(rawDataArray)
        cryptedArrayLen = len(cryptedArray)
        
        resultArray = bytearray(8 + cryptedArrayLen)
        resultArray[0] = cryptedArrayLen + 7 # len
        resultArray[1] = 0x02                 # flags
        resultArray[2] = 0x01
        resultArray[3] = 0x02
        resultArray[4] = cryptedArrayLen + 3 # len
        resultArray[5] = 0xFF                # type manufacturer specific
        resultArray[6] = manufacturerId[1]   # companyId
        resultArray[7] = manufacturerId[0]   # companyId
        for index in range(cryptedArrayLen):
            resultArray[index + 8] = cryptedArray[index]

        return ' '.join(f'{x:02x}' for x in resultArray)

    @staticmethod
    def Crypt(rawDataArray: bytes) -> bytes:
        """
        do the MouldKing encryption for the given byte-array and return the resulting byte-array 
        """

        targetArrayLength = len(MouldKingCrypt.__Array_C1C2C3C4C5) + len(rawDataArray) + 20

        targetArray = bytearray(targetArrayLength)
        targetArray[15] = 113 # 0x71
        targetArray[16] = 15  # 0x0f
        targetArray[17] = 85  # 0x55

        # copy firstDataArray reverse into targetArray with offset 18
        for index in range(len(MouldKingCrypt.__Array_C1C2C3C4C5)):
            targetArray[index + 18] = MouldKingCrypt.__Array_C1C2C3C4C5[(len(MouldKingCrypt.__Array_C1C2C3C4C5) - index) - 1]

        # copy rawDataArray into targetArray with offset 18 + len(MouldKingCrypt.__Array_C1C2C3C4C5)
        for index in range(len(rawDataArray)):
            targetArray[18 + len(MouldKingCrypt.__Array_C1C2C3C4C5) + index] = rawDataArray[index]

        # crypt bytes from position 15 to 22
        for index in range(15, len(MouldKingCrypt.__Array_C1C2C3C4C5) + 18):
            targetArray[index] = MouldKingCrypt.__revert_bits_byte(targetArray[index])

        # calc checksum und copy to array
        checksum = MouldKingCrypt.__calc_checksum_from_arrays(MouldKingCrypt.__Array_C1C2C3C4C5, rawDataArray)
        targetArray[len(MouldKingCrypt.__Array_C1C2C3C4C5) + 18 + len(rawDataArray) + 0] = (checksum & 255)
        targetArray[len(MouldKingCrypt.__Array_C1C2C3C4C5) + 18 + len(rawDataArray) + 1] = ((checksum >> 8) & 255)

        # crypt bytes from offset 18 to the end with magicNumberArray_63
        magicNumberArray_63 = MouldKingCrypt.__create_magic_array(63, 7)
        tempArray = bytearray(targetArrayLength - 18)
        for index in range(len(tempArray)):
            tempArray[index] = targetArray[index + 18]

        MouldKingCrypt.__crypt_array(tempArray, magicNumberArray_63)
        targetArray[18:] = tempArray

        # crypt complete array with magicNumberArray_37
        magicNumberArray_37 = MouldKingCrypt.__create_magic_array(37, 7)
        MouldKingCrypt.__crypt_array(targetArray, magicNumberArray_37)

        # resulting advertisement array has a length of constant 24 bytes
        telegramArray = bytearray(24)

        lengthResultArray = len(MouldKingCrypt.__Array_C1C2C3C4C5) + len(rawDataArray) + 5
        telegramArray[:lengthResultArray] = targetArray[15:15 + lengthResultArray]

        # fill rest of array
        for index in range(lengthResultArray, len(telegramArray)):
            telegramArray[index] = index + 1

        return telegramArray

    @staticmethod
    def Decrypt(encryptedData: bytes) -> bytes:
        if len(encryptedData) != 24:
            raise ValueError("Invalid encrypted data length. Must be 24 bytes.")
        # find how many bytes at end is sequential, ie how many is filler
        dataLen = len(encryptedData)
        sequentialCnt = 1
        for i in range(dataLen):
            if encryptedData[dataLen - i - 1] - 1 == encryptedData[dataLen - i - 2]:
                sequentialCnt += 1
            else:
                break
        # 39-6 = 33 for connect dgrams, 39-4 = 35 for ctrl dgrams
        # add 15 bytes of value 0x00 to front, must become size of 33
        step1 = bytearray(39 - sequentialCnt)
        # collect first 18* bytes from input to use as last 18 bytes, remove last 5 bytes from input, which holds idx+1 only.
        # *18 must be extended till sequential indexes start coming
        for i in range(len(encryptedData) - sequentialCnt):
            step1[15 + i] = encryptedData[i]
        output1 = MouldKingCrypt.__crypt_array(step1.copy(), MouldKingCrypt.__create_magic_array(37, 7))
        # collect final bytes (18 -> 33)
        step2 = output1[18:]
        output2 = MouldKingCrypt.__crypt_array(step2.copy(), MouldKingCrypt.__create_magic_array(63, 7))

        decryptedData = output2[5:-2]
        checkSum1 = output2[-1]
        checkSum2 = output2[-2]
        verifyChecksum = MouldKingCrypt.__calc_checksum_from_arrays(MouldKingCrypt.__Array_C1C2C3C4C5, decryptedData)
        if (verifyChecksum & 255) != checkSum2:
            raise ValueError("Checksum validation failed")
        if ((verifyChecksum >> 8) & 255) != checkSum1:
            raise ValueError("Checksum validation failed")
        return decryptedData

    @staticmethod
    def __create_magic_array(magic_number: int, size: int) -> bytes:
        magic_array = [0] * size
        magic_array[0] = 1

        for index in range(1, 7):
            magic_array[index] = (magic_number >> (6 - index)) & 1

        return magic_array

    @staticmethod
    def __revert_bits_byte(value: int) -> int:
        result = 0
        for index_bit in range(8):
            if ((1 << index_bit) & value) != 0:
                result = result | (1 << (7 - index_bit))
        return result

    @staticmethod
    def __revert_bits_int(value: int) -> int:
        result = 0
        for index_bit in range(16):
            if ((1 << index_bit) & value) != 0:
                result |= 1 << (15 - index_bit)
        return 65535 & result

    @staticmethod
    def __crypt_array(byte_array: bytes, magic_number_array: bytes) -> bytes:
        # foreach byte of array
        for index_byte in range(len(byte_array)):
            current_byte = byte_array[index_byte]
            current_result = 0
            # foreach bit in byte
            for index_bit in range(8):
                current_result += (((current_byte >> index_bit) & 1) ^ MouldKingCrypt.__shift_magic_array(magic_number_array)) << index_bit
            byte_array[index_byte] = current_result & 255
        return byte_array

    @staticmethod
    def __calc_checksum_from_arrays(first_array: bytes, second_array: bytes) -> int:
        result = 65535
        for first_array_index in range(len(first_array)):
            result = (result ^ (first_array[(len(first_array) - 1) - first_array_index] << 8)) & 65535
            for index_bit in range(8):
                current_result = result & 32768
                result <<= 1
                if current_result != 0:
                    result ^= 4129

        for current_byte in second_array:
            result = ((MouldKingCrypt.__revert_bits_byte(current_byte) << 8) ^ result) & 65535
            for index_bit in range(8):
                current_result = result & 32768
                result <<= 1
                if current_result != 0:
                    result ^= 4129

        return MouldKingCrypt.__revert_bits_int(result) ^ 65535

    @staticmethod
    def __shift_magic_array(i_arr: bytes) -> bytes:
        r1 = i_arr[3] ^ i_arr[6]
        i_arr[3] = i_arr[2]
        i_arr[2] = i_arr[1]
        i_arr[1] = i_arr[0]
        i_arr[0] = i_arr[6]
        i_arr[6] = i_arr[5]
        i_arr[5] = i_arr[4]
        i_arr[4] = r1
        return i_arr[0]

