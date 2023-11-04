import base64
import hashlib
import random
import struct

from Crypto.Cipher import AES
from pysmx.SM3 import SM3

from com.xargus1128 import xa_pb2

unpad = lambda s: s[: -ord(s[len(s) - 1:])]
pad = lambda s: s + (chr((16 - (len(s) % 16))).encode() * (16 - (len(s) % 16)))


class Argus:
    sign_key = (b'\x8e\xbd\xfa8\x06\xec\xc5\xce\xe7\x94#\xe6\x02\x9e\xd8%@\xbc"\x18\xbb~'
                b'\xae\xf7\x1c\xb6\x91\xf7\xaa\x8a\xa2\xf5')

    def __init__(self, ):
        self.xa_pb: bytes | None = None
        self.apd = []

    def gen_xa_pb(self, khronos: int, queryHash: bytes, bodyHash: bytes,
                  device_id: str, license_id: str, app_version: str,
                  sdk_version_str, sdk_version, sec_device_id, call_type, sign_count, report_count,
                  setting_count) -> bytes:
        def calc_protobuf3(d):
            high = (d << 1) & 0xFFFFFFFF
            return high ^ (d >> 31)

        xa_pb = xa_pb2.GenerateObj()  # type:ignore
        xa_pb.magic = 1077940818
        xa_pb.version = 2
        xa_pb.random = calc_protobuf3(random.randint(0x10000000, 0x8FFFFFFF))
        # xa_pb.random = 2904324654
        xa_pb.msAppId = "1128"
        xa_pb.deviceId = device_id
        xa_pb.licenseId = license_id
        xa_pb.appVersion = app_version
        xa_pb.sdkVersionStr = sdk_version_str
        xa_pb.sdkVersion = sdk_version

        # root检测
        xa_pb.envCode = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        xa_pb.platform = 0  # 安卓-0 IOS-1
        xa_pb.createTime = khronos << 1
        # xa_pb.createTime = 3396616762

        self.apd.append(bodyHash[0])
        self.apd.append(queryHash[0])
        xa_pb.bodyHash = bodyHash
        xa_pb.queryHash = queryHash

        action_record = xa_pb2.ActionRecord()  # type:ignore
        # unknown_fields = xa_pb2.UnknownFields()

        action_record.signCount = sign_count
        # action_record.reportCount = random.randint(10000, 100000)
        action_record.reportCount = report_count
        action_record.settingCount = setting_count

        # action_record.reportFailCount = random.randint(0, 3)
        # action_record.memoizedIsInitialized = -1
        # action_record.unknownFields.CopyFrom(unknown_fields)
        # action_record.memoizedSize = -1
        # action_record.memoizedHashCode = 0

        # action_record.signCount = 506
        # action_record.reportCount = 2
        # action_record.settingCount = 1388734

        xa_pb.actionRecord.CopyFrom(action_record)

        xa_pb.secDeviceToken = sec_device_id
        xa_pb.isAppLicense = xa_pb.createTime
        xa_pb.pskVersion = 'none'
        xa_pb.callType = call_type

        result = xa_pb.SerializeToString()

        # print(result.hex())
        self.xa_pb = result
        return result

    @staticmethod
    def _encrypt_random(key):
        A = 0
        T = 0
        for i in range(0, len(key), 2):
            B = key[i] ^ A
            C = (T >> 0x3) & 0xFFFFFFFF
            D = C ^ B
            E = D ^ T
            F = (E >> 0x5) & 0xFFFFFFFF
            G = (E << 0xB) & 0xFFFFFFFF
            H = key[i + 1] | G
            I = F ^ H
            J = I ^ E
            T = ~J & 0xFFFFFFFF
            # A = (T << 7) & 0xFFFFFFFF
            return T

    def _eor_data(self, key, data):
        rdm_list = self._encrypt_random(key)
        rdm_list = struct.pack(">I", rdm_list)
        for i in range(len(data)):
            data[i] ^= rdm_list[i % 4]
        return data

    def _gen_key(self, rdm):
        def bfi(rd, rn, lsb, width):
            ls = 0xFFFFFFFF >> (32 - width)
            rn = (rn & ls) << lsb
            ls = ~(ls << lsb)
            rd = rd & ls
            rd = rd | rn
            return rd

        data = (
                list(self.sign_key[:16])
                + list(self.sign_key[16:])
                + list(struct.pack("<I", rdm))
                + list(self.sign_key[:16])
                + list(self.sign_key[16:])
        )

        sm3 = SM3()
        sm3.update(bytes(data))
        res = sm3.hexdigest()

        res_list = []
        for i in range(0, len(res), 2):
            res_list.append(int(res[i: i + 2], 16))
        sm3_list = []
        for i in range(0, len(res_list), 4):
            c = struct.unpack("<I", bytes(res_list[i: i + 4]))
            sm3_list.append(c[0])
        res_list = res_list[:8]
        for i in range(0x47):
            t = i % 0x3E
            off = (0x20 - t) & 0xFF
            A = (0x3DC94C3A << off) & 0xFFFFFFFF
            B = ((0x46D678B >> t) & 0xFFFFFFFF) | A
            off_1 = t - 0x20
            if off_1 >= 0:
                B = 0x3DC94C3A >> off_1
            H = (sm3_list[6] >> 3) & 0xFFFFFFFF
            H |= (sm3_list[7] << 29) & 0xFFFFFFFF
            # print(hex(H), hex(sm3_list[2]))
            C = H ^ sm3_list[2]
            # bfi = (B & 1) | 0xFFFFFFFD
            bfi_v = bfi(B, 0x7FFFFFFE, 1, 0x1F)
            D = bfi_v ^ sm3_list[0] ^ C
            H = (sm3_list[7] >> 3) & 0xFFFFFFFF
            H |= (sm3_list[6] << 29) & 0xFFFFFFFF
            # print("H==========", hex(H))
            E = H ^ sm3_list[3]
            # 根据E判断是否进位
            if E & 1:
                B = (C >> 1) | 0x80000000
            else:
                B = C >> 1
            H = (C << 31) & 0xFFFFFFFF
            F = (E >> 1) | H
            G = F ^ sm3_list[1] ^ E
            A = ~G & 0xFFFFFFFF
            F = D ^ B
            for j in range(6):
                sm3_list[j] = sm3_list[j + 2]
            sm3_list[6] = F
            sm3_list[7] = A
            for j in range(2):
                for d in list(struct.pack("<I", sm3_list[j])):
                    res_list.append(d)

        return res_list

    @staticmethod
    def _block_encrypt(block, key):
        sm3_list = []
        for i in range(0, len(key), 4):
            c = struct.unpack("<I", bytes(key[i: i + 4]))
            sm3_list.append(c[0])
        # print(sm3_list)
        for i in range(len(sm3_list)):
            t = i % 4
            AA = (block[3 - t] >> 0x18) | ((block[(2 + t) % 4] << 0x08) & 0xFFFFFFFF)
            BB = ((block[(2 + t) % 4] << 0x1) & 0xFFFFFFFF) | (block[3 - t] >> 0x1F)
            CC = AA & BB
            DD = block[t] ^ CC
            EE = (block[3 - t] >> 0x1E) | ((block[(2 + t) % 4] << 0x02) & 0xFFFFFFFF)
            block[t] = sm3_list[i] ^ DD ^ EE
        res_list = []
        for i in range(4):
            res_list += struct.pack("<I", block[i])
        return res_list

    @staticmethod
    def _aes_encrypt(ciphertext, key, iv):
        text = ciphertext
        text = pad(text)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        de_text = cipher.encrypt(text)
        return de_text

    def encrypt(self):
        if not self.xa_pb:
            print("请先填充gen_xa_pb")
            return

        # rdm = 0x37076aa5
        rdm = random.randint(0x10000000, 0xFFFFFFFF)
        res = []
        enc_key = self._gen_key(rdm)
        proto = pad(self.xa_pb)

        for i in range(0, len(proto), 16):
            data = []
            for j in range(i, i + 16, 4):
                c = struct.unpack("<I", bytes(proto[j: j + 4]))
                data.append(c[0])

            res += self._block_encrypt(data, enc_key)

        random_arr = list(struct.pack("<I", rdm))
        key = random_arr[2:4]
        b64_header = random_arr[0:2]

        res = res[::-1]
        res += [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0][::-1]  # root检测
        res = self._eor_data(key, res)
        res += key

        headers = [
            0x35,  # 固定
            random.randint(0x10, 0xFF),
            random.randint(0x10, 0xFF),
            random.randint(0x10, 0xFF),
            random.randint(0x10, 0xFF),  # 随机
            0x00,
            # self._apd[0] & 0x3f, self._apd[1] & 0x3f,         # 0x2F, 0x05, 好像是某个值
            self.apd[0] & 0x3F,
            0x02,  # 0x2F, 0x05, 好像是某个值 0x0f 和protobuf10 有关
            0x18,
        ]
        headers += res

        aes_key = hashlib.md5(self.sign_key[:16]).digest()
        aes_iv = hashlib.md5(self.sign_key[16:]).digest()

        res = self._aes_encrypt(bytes(headers), aes_key, aes_iv)
        content = bytes(b64_header) + res
        return base64.b64encode(content).decode()

    @staticmethod
    def parse_xa_pb(pb_bytes: bytes) -> dict:
        def pb2dict(obj):
            """
            Takes a ProtoBuf Message obj and convertes it to a dict.
            """
            adict = {}
            if not obj.IsInitialized():
                return None

            for field in obj.DESCRIPTOR.fields:
                if not getattr(obj, field.name):
                    continue
                from google.protobuf.descriptor import FieldDescriptor
                if not field.label == FieldDescriptor.LABEL_REPEATED:
                    if not field.type == FieldDescriptor.TYPE_MESSAGE:
                        adict[field.name] = getattr(obj, field.name)
                    else:
                        value = pb2dict(getattr(obj, field.name))
                        if value:
                            adict[field.name] = value
                else:
                    if field.type == FieldDescriptor.TYPE_MESSAGE:
                        adict[field.name] = [pb2dict(v) for v in getattr(obj, field.name)]
                    else:
                        adict[field.name] = [v for v in getattr(obj, field.name)]
            return adict

        unpad = lambda s: s[: -ord(s[len(s) - 1:])]

        xa_pb = xa_pb2.GenerateObj()  # type:ignore
        xa_pb.ParseFromString(unpad(pb_bytes))

        xa_pb = pb2dict(xa_pb)
        # for key, value in xa_pb.items():
        #     print(key, value)

        xa_pb['envCode'] = xa_pb['envCode'].hex()
        xa_pb['bodyHash'] = xa_pb['bodyHash'].hex()
        xa_pb['queryHash'] = xa_pb['queryHash'].hex()

        if pskHash := xa_pb.get('pskHash'):
            xa_pb['pskHash'] = pskHash.hex()
        if pskCalHash := xa_pb.get('pskCalHash'):
            xa_pb['pskCalHash'] = pskCalHash.hex()

        return xa_pb

    def decrypt(self, x_argus: str):
        def restore_eor_data(key, data):
            rdm_list = self._encrypt_random(key)
            rdm_list = struct.pack(">I", rdm_list)
            restored_data = bytearray(len(data))

            for i in range(len(data)):
                restored_data[i] = data[i] ^ rdm_list[i % 4]

            return restored_data

        def decrypt(encrypted_result, key):
            sm3_list = []
            for i in range(0, len(key), 4):
                c = struct.unpack("<I", bytes(key[i: i + 4]))
                sm3_list.append(c[0])

            proto = []  # encrypted_result
            for j in range(0, len(encrypted_result), 4):
                c = struct.unpack("<I", bytes(encrypted_result[j:j + 4]))
                proto.append(c[0])

            for i in range(len(sm3_list)):
                i = (len(sm3_list) - i - 1)
                # print(i, proto)
                t = i % 4
                AA = (proto[3 - t] >> 0x18) | ((proto[(2 + t) % 4] << 0x08) & 0xFFFFFFFF)
                BB = ((proto[(2 + t) % 4] << 0x1) & 0xFFFFFFFF) | (proto[3 - t] >> 0x1F)
                CC = AA & BB
                DD = proto[t] ^ CC
                EE = (proto[3 - t] >> 0x1E) | ((proto[(2 + t) % 4] << 0x02) & 0xFFFFFFFF)
                proto[t] = sm3_list[i] ^ DD ^ EE
            # print(proto)
            return proto

        raw_data = base64.b64decode(x_argus)
        b64_header = raw_data[:2]

        # 随机的头
        print('b64_header ---> ', b64_header)
        raw_data = raw_data[2:]

        aes_key = hashlib.md5(self.sign_key[:16]).digest()
        aes_iv = hashlib.md5(self.sign_key[16:]).digest()

        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        de_text = cipher.decrypt(raw_data)
        de_text = unpad(de_text)

        headers = de_text[:9]
        print('headers ---> ', [hex(x) for x in headers])

        de_text = de_text[9:]

        eor_key = de_text[-2:]
        de_text = de_text[:-2]

        de_text = restore_eor_data(eor_key, de_text)

        eor_pad = de_text[-8:]
        print('enc_pad ---> ', [hex(x) for x in eor_pad])
        # 转置
        de_text = de_text[:-8][::-1]

        rdm = struct.unpack("<I", bytes(b64_header + eor_key))[0]
        enc_key = self._gen_key(rdm)

        raw_pb = b''
        for i in range(0, len(de_text), 16):
            encrypt = de_text[i:i + 16]
            un_encrypt = decrypt(encrypt, enc_key)
            for _ in un_encrypt:
                # print(struct.pack("<I", _))
                raw_pb += struct.pack("<I", _)

        print('decrypt pb hex ---> ', raw_pb.hex())
        pb = self.parse_xa_pb(raw_pb)
        print(pb)
