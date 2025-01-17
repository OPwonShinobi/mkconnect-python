import sys
sys.path.append("MouldKing")
from MouldKing.MouldKingCrypt import MouldKingCrypt

telegram_connect_educiro_enc = [0x6D,0xB6,0x43,0xCF,0x7E,0x8F,0x47,0x11,0x4F,0x1E,0xBA,0x38,0xD1,0xFA,0xC7,0xE1,0xE8,0x46]

telegram_connect = [0x6D, 0x7B, 0xA7, 0x80, 0x80, 0x80, 0x80, 0x92]
telegram_connect_enc = [0x6d,0xb6,0x43,0xcf,0x7e,0x8f,0x47,0x11,0x88,0x66,0x59,0x38,0xd1,0x7a,0xaa,0x26,0x49,0x5e,0x13,0x14,0x15,0x16,0x17,0x18]
telegram_connect_unenc = [0x8e,0xf0,0xaa,0xa3,0x23,0xc3,0x43,0x83,0x6d,0x7b,0xa7,0x80,0x80,0x80,0x80,0x92,0xae,0x8a,0x13,0x14,0x15,0x16,0x17,0x18]

telegram_base_device_a_enc = [0x6d,0xb6,0x43,0xcf,0x7e,0x8f,0x47,0x11,0x84,0x66,0x59,0x38,0xd1,0x7a,0xaa,0x34,0x67,0x4a,0x55,0xbf,0x15,0x16,0x17,0x18]
telegram_base_device_a = [0x61, 0x7B, 0xA7, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x9E]
# telegram_base_device_b = [0x62, 0x7B, 0xA7, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x9D]
# telegram_base_device_c = [0x63, 0x7B, 0xA7, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x9C]
# 6d b6 43 cf 7e 8f 47 11 88 66 59 38 d1 7a aa 26 49 5e 13 14 15 16 17 18
# 6db643cf7e8f471188665938d17aaa26495e131415161718 (enc)
# 8ef0aaa323c343836d7ba78080808092ae8a131415161718 (padded but unenc), notice 6d7ba78080808092 is at idx 8 -> 15

# result = MouldKingCrypt.Crypt(telegram_base_device_a)
result = MouldKingCrypt.Decrypt(telegram_base_device_a_enc)

if result is not None:
    print('0x' + ',0x'.join(f'{x:02x}' for x in result))
else:
    print("no result")