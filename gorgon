import hashlib
import json
import time


class Gorgon:
    # 修改data类型为str和bytes
    def __init__(self, params: str, unix: int, data: str | bytes = None, cookies: str = None) -> None:
        self.unix = unix
        self.params = params
        self.data = data
        self.cookies = cookies

    # 修改data类型为str和bytes
    def hash(self, data: str | bytes) -> str:
        if type(data) is bytes:
            return str(hashlib.md5(data).hexdigest())
        else:
            return str(hashlib.md5(data.encode()).hexdigest())

    def get_base_string(self) -> str:
        base_str = self.hash(self.params)
        base_str = (
            base_str + self.hash(self.data) if self.data else base_str + str("0" * 32)
        )
        base_str = (
            base_str + self.hash(self.cookies)
            if self.cookies
            else base_str + str("0" * 32)
        )
        return base_str

    def get_value(self) -> dict:
        return self.encrypt(self.get_base_string())

    def encrypt(self, data: str) -> json:
        len = 0x14
        key = [
            0xDF,
            0x77,
            0xB9,
            0x40,
            0xB9,
            0x9B,
            0x84,
            0x83,
            0xD1,
            0xB9,
            0xCB,
            0xD1,
            0xF7,
            0xC2,
            0xB9,
            0x85,
            0xC3,
            0xD0,
            0xFB,
            0xC3,
        ]
        param_list = []
        for i in range(0, 12, 4):
            temp = data[8 * i: 8 * (i + 1)]
            for j in range(4):
                H = int(temp[j * 2: (j + 1) * 2], 16)
                param_list.append(H)
        param_list.extend([0x0, 0x6, 0xB, 0x1C])
        H = int(hex(int(self.unix)), 16)
        param_list.append((H & 0xFF000000) >> 24)
        param_list.append((H & 0x00FF0000) >> 16)
        param_list.append((H & 0x0000FF00) >> 8)
        param_list.append((H & 0x000000FF) >> 0)
        eor_result_list = []
        for A, B in zip(param_list, key):
            eor_result_list.append(A ^ B)
        for i in range(len):
            C = self.reverse(eor_result_list[i])
            D = eor_result_list[(i + 1) % len]
            E = C ^ D
            F = self.rbit_algorithm(E)
            H = ((F ^ 0xFFFFFFFF) ^ len) & 0xFF
            eor_result_list[i] = H
        result = ""

        for param in eor_result_list:
            result += self.hex_string(param)

        return {
            "x-ss-req-ticket": str(int(self.unix * 1000)),
            "x-khronos": str(int(self.unix)),
            "x-gorgon": f"0404b0d30000{result}"
        }

    def rbit_algorithm(self, num):
        result = ""
        tmp_string = bin(num)[2:]
        while len(tmp_string) < 8:
            tmp_string = "0" + tmp_string
        for i in range(0, 8):
            result = result + tmp_string[7 - i]
        return int(result, 2)

    def hex_string(self, num):
        tmp_string = hex(num)[2:]
        if len(tmp_string) < 2:
            tmp_string = "0" + tmp_string
        return tmp_string

    def reverse(self, num):
        tmp_string = self.hex_string(num)
        return int(tmp_string[1:] + tmp_string[:1], 16)


def main():
    def test_str_data():
        params = 'aweme_id=7277398346103328058&cursor=0&count=20&address_book_access=2&gps_access=2&forward_page_type=1&channel_id=0&city=440100&hotsoon_filtered_count=0&hotsoon_has_more=0&follower_count=0&is_familiar=0&page_source=0&user_avatar_shrink=64_64&aweme_author=MS4wLjABAAAA1edgaCuAnMvrS6zhTpLMnwQIk39kngyeeWaS-XViaIc&item_type=0&manifest_version_code=160409&_rticket=1698305971445&app_type=normal&iid=3828917516401031&is_android_pad=0&channel=googlePlay&device_type=Pixel+4&language=zh&cpu_support64=true&host_abi=arm64-v8a&resolution=1080*2214&openudid=bae463c2f0481673&update_version_code=16409909&cdid=44177971-e3b7-49a0-aa3a-f6f25066462e&appTheme=light&minor_status=0&os_api=33&dpi=440&ac=wifi&package=com.ss.android.ugc.aweme.mobile&device_id=2773384256826104&os=android&os_version=13&version_code=160409&app_name=aweme&version_name=16.4.9&device_brand=google&ssmix=a&device_platform=android&aid=1128&ts=1698305971'
        unix = int(time.time())
        payload = 'aaa'
        cookie = ''

        xa = Gorgon(params, unix, payload, cookie).get_value()
        print(xa)

    def test_bytes_data():
        params = 'aweme_id=7277398346103328058&cursor=0&count=20&address_book_access=2&gps_access=2&forward_page_type=1&channel_id=0&city=440100&hotsoon_filtered_count=0&hotsoon_has_more=0&follower_count=0&is_familiar=0&page_source=0&user_avatar_shrink=64_64&aweme_author=MS4wLjABAAAA1edgaCuAnMvrS6zhTpLMnwQIk39kngyeeWaS-XViaIc&item_type=0&manifest_version_code=160409&_rticket=1698305971445&app_type=normal&iid=3828917516401031&is_android_pad=0&channel=googlePlay&device_type=Pixel+4&language=zh&cpu_support64=true&host_abi=arm64-v8a&resolution=1080*2214&openudid=bae463c2f0481673&update_version_code=16409909&cdid=44177971-e3b7-49a0-aa3a-f6f25066462e&appTheme=light&minor_status=0&os_api=33&dpi=440&ac=wifi&package=com.ss.android.ugc.aweme.mobile&device_id=2773384256826104&os=android&os_version=13&version_code=160409&app_name=aweme&version_name=16.4.9&device_brand=google&ssmix=a&device_platform=android&aid=1128&ts=1698305971'
        unix = int(time.time())
        cookie = ''
        with open('../bin/device_register', 'rb') as file:
            # with open('../bin/package', 'rb') as file:
            payload = file.read()
        xa = Gorgon(params, unix, payload, cookie).get_value()
        print(xa)

    # test_str_data()
    test_bytes_data()


if __name__ == '__main__':
    main()
