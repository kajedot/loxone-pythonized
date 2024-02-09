import asyncio
import hashlib
import base64
import hmac
import os
import urllib.parse
import uuid

import pbkdf2
from Crypto.Cipher import PKCS1_v1_5
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.PublicKey import RSA
import requests
import re
import logging
import websockets
import json
from Cryptodome.Util.Padding import pad

logging.basicConfig(level=logging.INFO)


class Miniserver:
    def __init__(self, input_queue):
        self.input_queue = input_queue

        self.session_key_from_server = None
        self.user_salt = None
        self.websocket = None

        self.uuid = str(uuid.uuid4())
        self.client_info = "Python%20Client%20X"

        self.server_serial_number = os.getenv("MINISERVER_SN")
        self.user_name = os.getenv("MINISERVER_USER")
        self.user_password = os.getenv("MINISERVER_PASSWD")

        self.aes_block_size = 16
        self.salt_len = self.aes_block_size
        self.salt = self.gen_salt()
        self.aes256_key = self.gen_aes256_key(self.uuid)
        self.aes_cipher = self.gen_aes_cipher()
        self.iv = self.gen_iv()

        self.ip, self.port = self.check_ip_and_port(self.server_serial_number)
        self.hostname = self.create_hostname(self.ip, self.server_serial_number)

        if not self.is_reachable():
            Exception("Miniserver is not available with a valid cert (httpsStatus other than 1)")

        self.server_public_key = self.fetch_public_key()

        self.encrypted_session_key = self.encrypt_rsa(f"{self.bytes2hex(self.aes256_key)}:{self.bytes2hex(self.iv)}",
                                                      self.server_public_key)
        self.run_websocket()

    def gen_salt(self) -> bytes:
        return get_random_bytes(self.salt_len)

    def gen_aes256_key(self, password: str) -> bytes:
        return pbkdf2.PBKDF2(password, self.salt, iterations=50).read(32)

    def gen_aes_cipher(self):
        return AES.new(self.aes256_key, AES.MODE_CBC)

    def gen_iv(self) -> bytes:
        return self.aes_cipher.iv

    def encrypt_aes(self, text: str) -> bytes:
        ciphertext = self.aes_cipher.encrypt(pad(text.encode('utf-8'), self.aes_block_size, style="x923"))  # TODO: padding sometimes not working with the first command:(
        return ciphertext

    def is_reachable(self) -> bool:
        value = self.fetch_https_response("/jdev/cfg/apiKey")
        https_status = re.search(r"'httpsStatus':(\d+)", value).group(1)  # field is string, not JSON
        if https_status == "1":
            logging.info(f"Miniserver is available with a valid certificate (httpsStatus: {https_status})")
            return True
        else:
            logging.error(f"Miniserver is not available or has invalid certificate "
                          f"(httpsStatus: {https_status})\nResponse value: {value}")
            return False

    def fetch_public_key(self) -> bytes:
        """ Fetches X.509 encoded public key in PEM format """
        fetched_key = self.fetch_https_response("/jdev/sys/getPublicKey")
        no_header_footer_key = fetched_key[27:763]
        formatted_key = f"-----BEGIN CERTIFICATE-----\n{no_header_footer_key}\n-----END CERTIFICATE-----\n"
        logging.debug("Servers pub key: " + formatted_key)
        return formatted_key.encode()

    def fetch_https_response(self, path):
        url = f"https://{self.hostname}:{self.port}{path}"
        logging.info(f"Sent HTTPS Request: {url}")
        response = requests.get(url)
        logging.debug(f"Fetched response: {response.text}")
        json_response = response.json()
        code = json_response['LL']['Code']
        if code == "200":
            value = json_response['LL']['value']
            return value
        else:
            logging.error(f"Wrong response code: {json_response}")
            Exception("Response code other than 200")

    def run_websocket(self):
        asyncio.run(self.websocket_handler())

    async def websocket_handler(self):
        url = f"wss://{self.hostname}:{self.port}/ws/rfc6455"
        async with websockets.connect(url, subprotocols=["remotecontrol"]) as self.websocket:
            await asyncio.create_task(self.websocket_authenticate())

            await asyncio.create_task(self.send_from_queue())

    async def websocket_authenticate(self):
        await self.exchange_keys()
        await self.auth_user()

    async def exchange_keys(self):
        resp = await self.ws_send_command(f"jdev/sys/keyexchange/{self.encrypted_session_key}")
        self.session_key_from_server = resp['value']

    async def auth_user(self):
        resp = await self.ws_send_command(f"jdev/sys/getkey2/{self.user_name}")
        val = resp['value']

        self.user_salt = val['salt']
        hash_alg = val['hashAlg']
        user_key = bytes.fromhex(val['key'])

        if hash_alg == "SHA256":
            to_hash = f"{self.user_password}:{self.user_salt}"
            pw_hash = hashlib.sha256(to_hash.encode()).hexdigest().upper()
            user_hash = hmac.new(user_key, f"{self.user_name}:{pw_hash}".encode(), hashlib.sha256).hexdigest()

            await self.ws_send_command(f"jdev/sys/getjwt/{user_hash}/{self.user_name}/4/{self.uuid}/{self.client_info}")

            logging.info(f"User {self.user_name} authenticated correctly")

        elif hash_alg == "SHA1":
            to_hash = f"{self.user_password}:{self.user_salt}"
            pw_hash = hashlib.sha1(to_hash.encode()).hexdigest().upper()
            user_hash = hmac.new(user_key, f"{self.user_name}:{pw_hash}".encode(), hashlib.sha1).hexdigest()

            await self.ws_send_command(f"jdev/sys/getjwt/{user_hash}/{self.user_name}/4/{self.uuid}/{self.client_info}")

            logging.info(f"User {self.user_name} authenticated correctly")
        else:
            logging.error("User authentication: unsupported hashing format (other than SHA256)")
            raise NotImplementedError

    """ Sends commands from the queue """
    async def send_from_queue(self):
        while True:
            if not self.input_queue.empty():
                await self.ws_send_command(self.input_queue.get())

    async def secret_command(self, command: str) -> (int, str):
        logging.info(f"ENC>: {command}")
        aes_command = self.encrypt_aes(f"salt/{self.salt}/{command}")  # Space because of padding
        cipher = base64.standard_b64encode(aes_command)
        enc_cipher = urllib.parse.quote(cipher)
        resp = await self.ws_send_command(f"jdev/sys/enc/{enc_cipher}")
        return resp

    async def ws_send_command(self, command) -> dict:
        logging.info(f">>>>: {command}")
        await self.websocket.send(command)
        try:
            resp = await asyncio.wait_for(self.command_response_loop(command), timeout=30)
            return resp
        except TimeoutError:
            logging.error(f"Waited too long for response of the command: {command}")

    async def command_response_loop(self, command):
        loop = True
        while loop:
            message = await self.websocket.recv()
            logging.info(f"<<<<: {message}")
            if message[0] == "{":
                message_json = json.loads(message)

                code = self.find_code_in_response(message_json)

                if code == 200:
                    if self.command_in_response(command, message_json):
                        return {'code': code, 'value': message_json['LL']['value'],
                                'outputs': self.parse_outputs(message_json)}
                else:
                    logging.error(f"Websocket response code {code}: {message_json}")
                    raise ValueError

    def command_in_response(self, command: str, message_json: json):
        control = message_json['LL']['control']
        if self.strip_by_first_char('/', control) == self.strip_by_first_char('/', command) or \
                urllib.parse.quote(self.strip_by_first_char('/', control)) == \
                self.strip_by_first_char(urllib.parse.quote('/'), command):
            return True
        else:
            return False

    @staticmethod
    def find_code_in_response(message_json: json):
        if 'code' in message_json['LL']:
            return int(message_json['LL']['code'])
        elif 'Code' in message_json['LL']:
            return int(message_json['LL']['Code'])
        else:
            logging.error(f"Websocket response code not found: {message_json}")
            raise ValueError

    @staticmethod
    def parse_outputs(resp: json):
        outputs = {}
        for field in resp['LL']:
            if field.startswith('output'):
                output_name = resp['LL'][field]['name']
                outputs[output_name] = resp['LL'][field]['value']
        return outputs

    @staticmethod
    def strip_by_first_char(char: str, txt: str):
        first_slash_pos = txt.find(char)
        return txt[first_slash_pos:]

    @staticmethod
    def check_ip_and_port(serial_number: str) -> (str, str):
        response = requests.get(f"https://dns.loxonecloud.com/?getip&snr={serial_number}&json=true")
        json_response = response.json()
        code = json_response["Code"]
        if code == 200:
            ip_port = json_response["IPHTTPS"].split(":")  # split IP from PORT
            logging.info(f"Received current IP from Loxone Cloud for Miniserver with S/N {serial_number}:"
                         f" {ip_port[0]}:{ip_port[1]}")
            return ip_port[0], ip_port[1]
        else:
            logging.error(f"Failed to fetch miniserver's ip. Is it running and connected? response: {json_response}")
            Exception("Response code other than 200")

    @staticmethod
    def create_hostname(ip: str, serial_number: str) -> str:
        """ Creates Miniserver's hostname without leading protocol name or 'www' and following port number """
        if ip.startswith("["):
            ip = ip[1:-1]  # remove [] at beginning & end
            cleaned_ip = ip.replace(":", "-")  # IPv6
        else:
            cleaned_ip = ip.replace(".", "-")  # IPv4

        return f"{cleaned_ip}.{serial_number.lower()}.dyndns.loxonecloud.com"

    @staticmethod
    def encrypt_rsa(plain_text: str, key: bytes):
        key_obj = RSA.importKey(key)
        cipher_rsa = PKCS1_v1_5.new(key_obj)
        encrypted = cipher_rsa.encrypt(plain_text.encode())

        return base64.standard_b64encode(encrypted).decode()

    @staticmethod
    def bytes2hex(txt: bytes) -> str:
        return txt.hex()
