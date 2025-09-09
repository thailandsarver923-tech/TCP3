import threading
import jwt
import random
from threading import Thread
import json
import requests 
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json
import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import*
from byte import*
tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

freefire_version = "OB50"
chat_ip = "98.98.162.76"
chat_port = 39698
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
def generate_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[D3D3D3][b][c]",
    "[F0F0F0][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  # Convert the number to a string

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
    
def check_banned_status(player_id):
   
    url = api_check_ban.format(player_id=player_id)
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
        

def send_vistttt(uid):
    try:
        # التحقق من صحة ID أولًا
        info_response = newinfo(uid)
        
        if info_response.get('status') != "ok":
            return (
                f"[FF0000]________________________\n"
                f"خطأ في المعرف: {fix_num(uid)}\n"
                f"الرجاء التحقق من الرقم\n"
                f"________________________\n"

            )
        
        # إرسال الطلب إلى API الجديد
        url = Api visit hana
        response = requests.get(url)
        
        # التحقق من استجابة API
        if response.status_code == 200:
            return (
                f"{generate_random_color()}________________________\n"
                f"تم إرسال 1000 زيارة بنجاح ✅\n"
                f"إلى: {fix_num(uid)}\n"
                f"________________________\n"   
            )
        else:
            return (
                f"[FF0000]________________________\n"
                f"فشل الإرسال (كود الخطأ: {response.status_code})\n"
                f"________________________\n"
            )
            
    except requests.exceptions.RequestException as e:
        return (
            f"[FF0000]________________________\n"
            f"فشل الاتصال بالخادم:\n"
            f"{str(e)}\n"
            f"________________________\n"
        )
        print(error_message)        

    return message        


def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
def newinfo(uid):
    try:
        url = api m3loumat hna
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print(f"Response Data: {data}")  # طباعة البيانات للتحقق منها

            # التحقق من وجود `basicinfo`
            if "basicinfo" in data and isinstance(data["basicinfo"], list) and len(data["basicinfo"]) > 0:
                data["basic_info"] = data["basicinfo"][0]
            else:
                print("Error: 'basicinfo' key not found or empty")
                return {"status": "wrong_id"}

            # التحقق من وجود `claninfo`
            if "claninfo" in data and isinstance(data["claninfo"], list) and len(data["claninfo"]) > 0:
                data["clan_info"] = data["claninfo"][0]
            else:
                data["clan_info"] = "false"

            # التحقق من وجود `clanadmin`
            if "clanadmin" in data and isinstance(data["clanadmin"], list) and len(data["clanadmin"]) > 0:
                data["clan_admin"] = data["clanadmin"][0]  # استخراج أول عنصر
            else:
                data["clan_admin"] = "false"  # تعيين قيمة افتراضية إذا لم يكن هناك مسؤول عشيرة

            return {"status": "ok", "info": data}

        elif response.status_code == 500:
            print("Server Error: 500 - Internal Server Error")
            return {"status": "error", "message": "Server error, please try again later."}

        print(f"Error: Unexpected status code {response.status_code}")
        return {"status": "wrong_id"}

    except Exception as e:
        print(f"Error in newinfo: {str(e)}")
        return {"status": "error", "message": str(e)}
	
import requests

def send_spam(uid):
    try:
        # أولاً، التحقق من صحة المعرف باستخدام دالة newinfo
        info_response = newinfo(uid)
        
        if info_response.get('status') != "ok":
            return (
                f"[FF0000]-----------------------------------\n"
                f"خطأ في المعرف: {fix_num(uid)}\n"
                f"تأكد أن اللآيدي صحيح\n"
                f"-----------------------------------\n"
            )
        
        # ثانيًا، إرسال الطلب إلى الرابط الصحيح باستخدام المعرف
        api_url = Api spam hna
        response = requests.get(api_url)
        
        # ثالثًا، التحقق من نجاح الطلب
        if response.status_code == 200:
            return (
                f"{generate_random_color()}-----------------------------------\n"
                f"تم فشخ الاعب سبام✅ \n"
                f"إلى: {fix_num(uid)}\n"
                f"-----------------------------------\n"
            )
        else:
            return (
                f"[FF0000]-----------------------------------\n"
                f"فشل الإرسال (كود الخطأ: {response.status_code})\n"
                f"-----------------------------------\n"
            )
            
    except requests.exceptions.RequestException as e:
        # معالجة أخطاء الاتصال بالشبكة
        return (
            f"[FF0000]-----------------------------------\n"
            f"فشل الاتصال بالخادم:\n"
            f"{str(e)}\n"
            f"-----------------------------------\n"
        )
            
    except requests.exceptions.RequestException as e:
        # معالجة أخطاء الاتصال بالشبكة
        return (
            f"[FF0000]-----------------------------------\n"
            f"فشل الاتصال بالخادم:\n"
            f"{str(e)}\n"
            f"-----------------------------------\n"
        )

def attack_profail(player_id):
    url = api zwar hna
    res = requests.get(url)
    if res.status_code() == 200:
        print("Done-Attack")
    else:
        print("Fuck-Attack")

def send_likes(uid):
    try:
        likes_api_response = requests.get api liket hna # ✅ تم تمرير uid بشكل صحيح

        if likes_api_response.status_code == 200:
            api_data = likes_api_response.json()

            if api_data.get("likes_added", 0) == 0:

                # حالة الحد اليومي (لون أحمر)
                return {
                    "status": "failed",
                    "message": (
                        f"[C][B][FF0000]________________________\n"
                        f" ❌ الحد اليومي لإرسال الإعجابات!\n"
                        f" حاول مرة أخرى بعد 24 ساعة\n"
                        f"________________________"
                    )
                }
            else:
                # حالة النجاح مع التفاصيل (لون أخضر)
                return {
                    "status": "ok",
                    "message": (
                        f"[C][B][00FF00]________________________\n"
                        f" ✅ تم إضافة {api_data['likes_added']} إعجاب\n"
                        f" الاسم: {api_data['name']}\n"
                        f" الإعجابات السابقة: {api_data['likes_before']}\n"
                        f" الإعجابات الجديدة: {api_data['likes_after']}\n"
                        f"________________________"
                    )
                }

        else:
            # حالة الفشل العامة (لون أحمر)
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]________________________\n"
                    f" ❌ خطأ في الإرسال!\n"
                    f" تأكد من صحة اليوزر ID\n"
                    f"________________________"
                )
            }

    except Exception as e:
        # في حال حدوث أي استثناء
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ⚠️ حدث خطأ أثناء محاولة الإرسال!\n"
                f" التفاصيل: {str(e)}\n"
                f"________________________"
            )
        }
		
def Encrypt(number):
    number = int(number)  # تحويل الرقم إلى عدد صحيح
    encoded_bytes = []    # إنشاء قائمة لتخزين البايتات المشفرة

    while True:  # حلقة تستمر حتى يتم تشفير الرقم بالكامل
        byte = number & 0x7F  # استخراج أقل 7 بتات من الرقم
        number >>= 7  # تحريك الرقم لليمين بمقدار 7 بتات
        if number:
            byte |= 0x80  # تعيين البت الثامن إلى 1 إذا كان الرقم لا يزال يحتوي على بتات إضافية

        encoded_bytes.append(byte)
        if not number:
            break  # التوقف إذا لم يتبقى بتات إضافية في الرقم

    return bytes(encoded_bytes).hex()
    


def get_random_avatar():
	avatar_list = [
        '902000061',
        '902000060',
        '902000064',
        '902000065',
        '902000066', 
        '902000074',
        '902000075',
        '902000077',
        '902000347'
    ]
	random_avatar = random.choice(avatar_list)
	return  random_avatar

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
    

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = psutil.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass
            
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")

    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "[C][B][FF0000]7ama [FF00FF]yn.ik [00FFFF]lkol",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "ME",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 11371687918
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "ME",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "ME",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11371687918,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1,
            2: {
            1: 3557944186,
            2: Enc_Id,
            3: 2,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
            
            2: int(get_random_avatar()),
            3: 901041021,
            4: 330,
            
            10: 1,
            11: 155
            },
            10: "en",
            13: {
            1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160",
            2: 1,
            3: 1
            }
            },
            14: ""
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "7ama ",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        online_port = int(online_port)

        socket_client.connect((online_ip,online_port))
        print(f" Con port {online_port} Host {online_ip} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4]:
                accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                kk = get_available_room(accept_packet)
                parsed_data = json.loads(kk)
                fark = parsed_data.get("4", {}).get("data", None)
                if fark is not None:
                    print(f"haaaaaaaaaaaaaaaaaaaaaaho {fark}")
                    if fark == 18:
                        if sent_inv:
                            accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                            print(accept_packet)
                            print(tempid)
                            aa = gethashteam(accept_packet)
                            ownerid = getownteam(accept_packet)
                            print(ownerid)
                            print(aa)
                            ss = self.accept_sq(aa, tempid, int(ownerid))
                            socket_client.send(ss)
                            sleep(1)
                            startauto = self.start_autooo()
                            socket_client.send(startauto)
                            start_par = False
                            sent_inv = False
                    if fark == 6:
                        leaveee = True
                        print("kaynaaaaaaaaaaaaaaaa")
                    if fark == 50:
                        pleaseaccept = True
                print(data2.hex())

            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "OFFLINE":
                        tempdata = f"The id is {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nid room : {idrooom1}"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nleader id : {idleader1}"
                        else:
                            tempdata = f"id : {idplayer1}\nstatus : {tempdata}"
                    statusinfo = True 

                    print(data2.hex())
                    print(tempdata)
                
                    

                else:
                    pass
            if "0e00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idplayer1 = fix_num(idplayer)
                asdj = parsed_data["2"]["data"]
                tempdata1 = get_player_status(packett)
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    maxplayer1 = fix_num(maxplayer)
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    nowplayer1 = fix_num(nowplayer)
                    tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                    print(tempdata1)
                    

                    
                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
    
    
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, whisper_port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            data = clients.recv(9999)

            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")

            if "1200" in data.hex()[0:4] and b"/admin" in data:
                i = re.split("/admin", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(
                    self.GenResponsMsg(
                        f"""

╔════════════════════════╗

[C][B][FF00FF] 7ama yn.ik lkol

[b][i][A5E2CFٍ]telegram:@mythic7AMA

[b][c][1E90FF]instagram : @_imohamed_m

[C][B][FF6347] Developer: ☞mythic7AMA | t.me/botx7ama

╚════════════════════════╝ """
, uid
                    )
                )
            

            if "1200" in data.hex()[0:4] and b"/x" in data:
                try:
                    command_split = re.split("/x ", str(data))
                    if len(command_split) > 1:
                        player_id = command_split[1].split('(')[0].strip()
                        if "***" in player_id:
                            player_id = player_id.replace("***", "106")
                            
                            
                            
                    
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][1E90FF]جـــــاري ارسال طلبات الانضمام...!!!\n"                              , uid
                            )
                        )                            

                        
                        json_result = get_available_room(data.hex()[10:])
                        
                        parsed_data = json.loads(json_result)

                        tempid = player_id
                        
                        def send_invite():
                            invskwad = self.request_skwad(player_id)
                            socket_client.send(invskwad)                         

                       


                        threadss = []
                        for _ in range(30):
                            thread = threading.Thread(target=send_invite)
                            thread.start()
                            threadss.append(thread)                                                        
                        
                        for thread in threadss:
                            thread.join()

                        sent_inv = True

                    
                    
                      
                except Exception as e:
                    print(f"Error in /md command: {e}")

            if "1200" in data.hex()[0:4] and b"/3" in data:
                # يแยก i من الأمر /3
                i = re.split("/3", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                
                # استخراج بيانات اللاعب المرسل
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                # 1. إنشاء فريق جديد
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)
                sleep(0.5)  # انتظر قليلاً لضمان إنشاء الفريق

                # 2. تغيير وضع الفريق إلى 3 لاعبين (2 = 3-1)
                packetfinal = self.changes(2)
                socket_client.send(packetfinal)
                sleep(0.5)

                # 3. التحقق مما إذا كان هناك ID لدعوته
                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/3')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(
                            b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                            # إرسال دعوة للاعب المحدد
                            invitess = self.invite_skwad(iddd)
                            socket_client.send(invitess)
                        else:
                            # إذا لم يتم تحديد ID، يتم دعوة الشخص الذي أرسل الأمر
                            iddd = uid
                            invitess = self.invite_skwad(iddd)
                            socket_client.send(invitess)

                # 4. إرسال رسالة تأكيد للمستخدم
                if uid:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B][1E90FF]-----------------------------\n\n\n\nجاري  تحويل الفريق الي  ثلاثي\n\n\n\n-----------------------------",
                            uid
                        )
                    )

                # 5. مغادرة الفريق وتغيير الوضع إلى فردي (Solo) بعد فترة
                sleep(5)  # انتظر 5 ثوانٍ
                leavee = self.leave_s()
                socket_client.send(leavee)
                sleep(1)
                change_to_solo = self.changes(1)
                socket_client.send(change_to_solo)
                    
            if "1200" in data.hex()[0:4] and b"/5" in data:
                i = re.split("/5", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)

                # إنشاء الفريق
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)

                sleep(1)

                # تعيين نوع الفريق
                packetfinal = self.changes(4)
                socket_client.send(packetfinal)

                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/5')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(
                            b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                        else:
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            iddd = parsed_data["5"]["data"]["1"]["data"]

                # إرسال الدعوة
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)

                if uid:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B][1E90FF]-----------------------------\n\n\n\nجاري  تحويل الفريق الي  خماسي\n\n\n\n-----------------------------",
                            uid))

                # التأكد من المغادرة بعد 5 ثوانٍ إذا لم تتم المغادرة تلقائيًا
                sleep(5)
                print("Checking if still in squad...")

                leavee = self.leave_s()
                socket_client.send(leavee)

                # تأخير أطول للتأكد من تنفيذ المغادرة قبل تغيير الوضع
                sleep(2)

                # إرسال أمر تغيير وضع اللعبة إلى Solo
                change_to_solo = self.changes(1)  # تأكد أن `1` هو القيمة الصحيحة لـ Solo
                socket_client.send(change_to_solo)

                # تأخير بسيط قبل إرسال التأكيد للمستخدم

                 

                
                    
            if "1200" in data.hex()[0:4] and b"/6" in data:
                i = re.split("/6", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)
                sleep(0.5)
                packetfinal = self.changes(5)
                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/6')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(
                            b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                        else:
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            iddd = parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if uid:
                    clients.send(
                        self.GenResponsMsg(
                  f"[C][B][1E90FF]-----------------------------\n\n\n\nجاري  تحويل الفريق الي  سداسي\n\n\n\n-----------------------------",
                            uid))

                sleep(4)  # انتظار 2 ثواني
                leavee = self.leave_s()
                socket_client.send(leavee)
                sleep(0.5)
                change_to_solo = self.changes(1)  # تغيير إلى Solo
                socket_client.send(change_to_solo)


            if "1200" in data.hex()[0:4] and b"/status" in data:
                try:
                    print("Received /st command")
                    i = re.split("/status", str(data))[1]
                    if "***" in i:
                        i = i.replace("***", "106")
                    sid = str(i).split("(\\x")[0]
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    split_data = re.split(rb'/status', data)
                    room_data = split_data[1].split(b'(')[0].decode().strip().split()
                    if room_data:
                        player_id = room_data[0]
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        packetmaker = self.createpacketinfo(player_id)
                        socket_client.send(packetmaker)
                        statusinfo1 = True
                        while statusinfo1:
                            if statusinfo == True:
                                if "IN ROOM" in tempdata:
                                    inforoooom = self.info_room(data22)
                                    socket_client.send(inforoooom)
                                    sleep(0.5)
                                    clients.send(self.GenResponsMsg(f"{tempdata1}", uid))  
                                    tempdata = None
                                    tempdata1 = None
                                    statusinfo = False
                                    statusinfo1 = False
                                else:
                                    clients.send(self.GenResponsMsg(f"{tempdata}", uid))  
                                    tempdata = None
                                    tempdata1 = None
                                    statusinfo = False
                                    statusinfo1 = False
                    else:
                        clients.send(self.GenResponsMsg("[C][B][FF0000] الرجاء إدخال معرف اللاعب!", uid))  
                except Exception as e:
                    print(f"Error in /rs command: {e}")
                    clients.send(self.GenResponsMsg("[C][B][FF0000]ERROR!", uid))
                
             
            if "1200" in data.hex()[0:4] and b"/inv" in data:
                i = re.split("/inv", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/inv', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    print(room_data)
                    iddd = room_data[0]
                    numsc1 = "5"

                    if numsc1 is None:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/ inv 123[c]456[c]78 4\n/ inv 123[c]456[c]78 5", uid
                            )
                        )
                    else:
                        numsc = int(numsc1) - 1
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        if int(numsc1) < 3 or int(numsc1) > 6:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000] Usage : /inv <uid> <Squad Type>\n[ffffff]Example : \n/ inv 12345678 4\n/ inv 12345678 5", uid
                                )
                            )
                        else:
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(1)
                            packetfinal = self.changes(int(numsc))
                            socket_client.send(packetfinal)
                            
                            invitess = self.invite_skwad(iddd)
                            socket_client.send(invitess)
                            iddd1 = parsed_data["5"]["data"]["1"]["data"]
                            invitessa = self.invite_skwad(iddd1)
                            socket_client.send(invitessa)
                            clients.send(
                        self.GenResponsMsg(
                            f"[C][B][00ff00]جاري[0000FFَ] عمل[0000FFَ] فريق[00FF00َ]وارسل لك[FF8000َ]! ", uid
                        )
                    )

                # التأكد من المغادرة بعد 5 ثوانٍ إذا لم تتم المغادرة تلقائيًا
                sleep(5)
                print("[FF8000َ]Checking [6E00FFَ]if [00FF00َ]still in [FFFF00ِ]squad...")

                leavee = self.leave_s()
                socket_client.send(leavee)

                 # تأخير أطول للتأكد من تنفيذ المغادرة قبل تغيير الوضع
                sleep(5)

                 # إرسال أمر تغيير وضع اللعبة إلى Solo
                change_to_solo = self.changes(1)  # تأكد أن `1` هو القيمة الصحيحة لـ Solo
                socket_client.send(change_to_solo)

                 # تأخير بسيط قبل إرسال التأكيد للمستخدم
                sleep(0.1)

                clients.send(
                     self.GenResponsMsg(
                         f" البوت  اصبح سلو  الان.", uid
                     )
                 )
                    
            if "1200" in data.hex()[0:4] and b"/room" in data:
                i = re.split("/room", str(data))[1] 
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                split_data = re.split(rb'/room', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    
                    player_id = room_data[0]
                    if player_id.isdigit():
                        if "***" in player_id:
                            player_id = rrrrrrrrrrrrrr(player_id)
                        packetmaker = self.createpacketinfo(player_id)
                        socket_client.send(packetmaker)
                        sleep(0.5)
                        if "IN ROOM" in tempdata:
                            room_id = get_idroom_by_idplayer(data22)
                            packetspam = self.spam_room(room_id, player_id)
                            print(packetspam.hex())
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00ff00]جاري العمل علي طلب {fix_num(player_id)} ! ", uid
                                )
                            )
                            
                            
                            for _ in range(99):

                                print(" sending spam to "+player_id)
                                threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                            #socket_client.send(packetspam)
                            
                            
                            
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B] [00FF00]نجح الطلب", uid
                                )
                            )
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B] [FF00FF]The player is not in room", uid
                                )
                            )      
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]Please write the id of player not!", uid
                            )
                        )   

                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B] [FF00FF]Please write the id of player !", uid
                        )
                    )   
            

            
            

            if "1200" in data.hex()[0:4] and b"by 7ama" in data:
            	pass
            else:
             
	            if "1200" in data.hex()[0:4] and b"/spam" in data:

	                command_split = re.split("/spam", str(data))
	                if len(command_split) > 1:
	                    player_id = command_split[1].split('(')[0].strip()
	                    print(f"Sending Spam To {player_id}")
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}جاري ارسال طلبات الصداقه..", uid
	                    )
	                )
	                    
	                    message = send_spam(player_id)
	                    print(message)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    
	                    clients.send(self.GenResponsMsg(message, uid))
	            if "1200" in data.hex()[0:4] and b"/visit" in data:

	                command_split = re.split("/visit", str(data))
	                if len(command_split) > 1:
	                    player_id = command_split[1].split('(')[0].strip()

	                    print(f"[C][B]Sending vist To {player_id}")
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
            self.GenResponsMsg(
                f"{generate_random_color()}جارِ إرسال 1000 زيارة إلى {fix_num(player_id)}...", uid
	                    )
	                )
	                    
	                    message = send_vistttt(player_id)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    
	                    clients.send(self.GenResponsMsg(message, uid))	                           
	                    
	            if "1200" in data.hex()[0:4] and b"/info" in data:
	                try:
	                    print("✅ /info command detected.")  
	                    command_split = re.split("/info", str(data))

	                    if len(command_split) <= 1 or not command_split[1].strip():  # ✅ إذا لم يتم إدخال ID
	                        print("❌ No ID provided, sending error message.")
	                        json_result = get_available_room(data.hex()[10:])
	                        parsed_data = json.loads(json_result)
	                        sender_id = parsed_data["5"]["data"]["1"]["data"]
	                        clients.send(self.GenResponsMsg("[C][B][FF0000] Please enter [00FF00َ]a valid[6E00FFَ] player [FFFF00ِ]ID!", sender_id))
	                        
	                    else:
	                        print("✅ Command has parameters.")  
	                        json_result = get_available_room(data.hex()[10:])
	                        parsed_data = json.loads(json_result)

	                        sender_id = parsed_data["5"]["data"]["1"]["data"]
	                        sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                        print(f"✅ Sender ID: {sender_id}, Sender Name: {sender_name}")  

	                        # ✅ استخراج UID الصحيح فقط
	                        uids = re.findall(r"\b\d{5,15}\b", command_split[1])  # استخراج أول رقم بين 5 و 15 رقمًا
	                        uid = uids[0] if uids else ""  # ✅ أخذ أول UID فقط

	                        if not uid:
	                            print("❌ No valid UID found, sending error message.")
	                            clients.send(self.GenResponsMsg("[C][B][FF0000] Invalid Player ID!", sender_id))
	                            
	                        else:
	                            print(f"✅ Extracted UID: {uid}")  

	                            try:
	                                info_response = newinfo(uid)
	                                print(f"✅ API Response Received: {info_response}")  
	                            except Exception as e:
	                                print(f"❌ API Error: {e}")
	                                clients.send(self.GenResponsMsg("[C][B] [FF0000] Server Error, Try Again!", sender_id))
	                                
	                            if 'info' not in info_response or info_response['status'] != "ok":
	                                print("❌ Invalid ID or API Error, sending wrong ID message.")
	                                clients.send(self.GenResponsMsg("[C][B] [FF0000] Wrong ID .. Please Check Again", sender_id))
	                                
	                            else:
	                                print("✅ Valid API Response, Extracting Player Info.")  
	                                infoo = info_response['info']
	                                basic_info = infoo['basic_info']
	                                clan_info = infoo.get('clan_info', "false")
	                                clan_admin = infoo.get('clan_admin', {})

	                                if clan_info == "false":
	                                    clan_info_text = "\nPlayer Not In Clan\n"
	                                else:
	                                    clan_info_text = (
	                                        f" Clan Info :\n"
	                                        f"Clan ID : {fix_num(clan_info['clanid'])}\n"
	                                        f"[B][FFA500]• Name: [FFFFFF]{clan_info.get('clanname', 'N/A')}\n"
	                                        f"[B][FFA500]• Members: [FFFFFF]{clan_info.get('livemember', 0)}\n"
	                                        f"[B][FFA500]• Level: [FFFFFF]{clan_info.get('guildlevel', 0)}\n"
	                                       f"[C][B][00FF00]«—————— END Info ——————»\n"
	                                         
	                                        
	                                    )

	                                level = basic_info['level']
	                                likes = basic_info['likes']
	                                name = basic_info['username']
	                                region = basic_info['region']
	                                bio = basic_info.get('bio', "No bio available").replace("|", " ")
	                                br_rank = fix_num(basic_info['brrankscore'])
	                                exp = fix_num(basic_info['Exp'])

	                                print(f"✅ Player Info Extracted: {name}, Level: {level}, Region: {region}")

	                                message_info = (
	                                    f"[C][B][00FF00]«—————— Player Info ——————»\n"
    f"[B][FFA500]• Name: [FFFFFF]{name}\n"
    f"[B][FFA500]• Level: [FFFFFF]{level}\n"
    f"[B][FFA500]• Server: [FFFFFF]{region}\n"
    f"[B][FFA500]• Likes: [FFFFFF]{fix_num(likes)}\n"
    f"[B][FFA500]• Bio: [FFFFFF]{bio}\n"
	                          
	                                 f"{clan_info_text}\n"
	                                    
	                                )

	                                print(f"📤 Sending message to game: {message_info}")  

	                                try:
	                                    clients.send(self.GenResponsMsg(message_info, sender_id))
	                                    print("✅ Message Sent Successfully!")  
	                                except Exception as e:
	                                    print(f"❌ Error sending message: {e}")
	                                    clients.send(self.GenResponsMsg("[C][B] [FF0000] Failed to send message!", sender_id))

	                except Exception as e:
	                    print(f"❌ Unexpected Error: {e}")
	                    clients.send(self.GenResponsMsg("[C][B][FF0000] An unexpected error occurred!", sender_id))
	                    
	                    
	            if "1200" in data.hex()[0:4] and b"/biccco" in data:
	                try:
	                    print("✅ /info command detected.")  
	                    command_split = re.split("/biccco", str(data))

	                    if len(command_split) <= 1 or not command_split[1].strip():  # ✅ إذا لم يتم إدخال ID
	                        print("❌ No ID provided, sending error message.")
	                        json_result = get_available_room(data.hex()[10:])
	                        parsed_data = json.loads(json_result)
	                        sender_id = parsed_data["5"]["data"]["1"]["data"]
	                        clients.send(self.GenResponsMsg("[C][B][FF0000] Please enter a valid player ID!", sender_id))
	                        
	                    else:
	                        print("✅ Command has parameters.")  
	                        json_result = get_available_room(data.hex()[10:])
	                        parsed_data = json.loads(json_result)

	                        sender_id = parsed_data["5"]["data"]["1"]["data"]
	                        sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                        print(f"✅ Sender ID: {sender_id}, Sender Name: {sender_name}")  

	                        # ✅ استخراج UID الصحيح فقط
	                        uids = re.findall(r"\b\d{5,15}\b", command_split[1])  # استخراج أول رقم بين 5 و 15 رقمًا
	                        uid = uids[0] if uids else ""  # ✅ أخذ أول UID فقط

	                        if not uid:
	                            print("❌ No valid UID found, sending error message.")
	                            clients.send(self.GenResponsMsg("[C][B][FF0000] معرف اللاعب غير صالح!", sender_id))
	                            
	                        else:
	                            print(f"✅ Extracted UID: {uid}")  

	                            try:
	                                info_response = newinfo(uid)
	                                print(f"✅ API Response Received: {info_response}")  
	                            except Exception as e:
	                                print(f"❌ API Error: {e}")
	                                clients.send(self.GenResponsMsg("[C][B] [FF0000] Server Error, Try Again!", sender_id))
	                                
	                            if 'info' not in info_response or info_response['status'] != "ok":
	                                print("❌ Invalid ID or API Error, sending wrong ID message.")
	                                clients.send(self.GenResponsMsg("[C][B] [FF0000] Wrong ID .. Please Check Again", sender_id))
	                                
	                            else:
	                                print("✅ Valid API Response, Extracting Player Info.")  
	                                infoo = info_response['info']
	                                basic_info = infoo['basic_info']
	                                clan_info = infoo.get('clan_info', "false")
	                                clan_admin = infoo.get('clan_admin', {})

	                                if clan_info == "false":
	                                    clan_info_text = "\nPlayer Not In Clan\n"
	                                else:
	                                    clan_info_text = (
	                                        f" Clan Info :\n"
	                                        f"Clan ID : {fix_num(clan_info['clanid'])}\n"
	                                        f"Clan Name : {clan_info['clanname']}\n"
	                                        f"Clan Level: {clan_info['guildlevel']}\n\n"
	                                        "Clan Admin Info : \n"
	                                        f"ID : {fix_num(clan_admin.get('idadmin', 'N/A'))}\n"
	                                        f"Name : {clan_admin.get('adminname', 'N/A')}\n"
	                                        f"Exp : {clan_admin.get('exp', 'N/A')}\n"
	                                        f"Level : {clan_admin.get('level', 'N/A')}\n"
	                                        f"Ranked (Br) Score : {fix_num(clan_admin.get('brpoint', 0))}\n"
	                                    )

	                                level = basic_info['level']
	                                likes = basic_info['likes']
	                                name = basic_info['username']
	                                region = basic_info['region']
	                                bio = basic_info.get('bio', "No bio available").replace("|", " ")
	                                br_rank = fix_num(basic_info['brrankscore'])
	                                exp = fix_num(basic_info['Exp'])

	                                print(f"✅ Player Info Extracted: {name}, Level: {level}, Region: {region}")

	                                message_info = (
	                                    f"{bio}"
	                                )

	                                print(f"📤 Sending message to game: {message_info}")  

	                                try:
	                                    clients.send(self.GenResponsMsg(message_info, sender_id))
	                                    print("✅ Message Sent Successfully!")  
	                                except Exception as e:
	                                    print(f"❌ Error sending message: {e}")
	                                    clients.send(self.GenResponsMsg("[C][B] [FF0000] Failed to send message!", sender_id))

	                except Exception as e:
	                    print(f"❌ Unexpected Error: {e}")
	                    clients.send(self.GenResponsMsg("[C][B][FF0000] An unexpected error occurred!", sender_id))	                    
	                    
	                    
	                    
	            if "1200" in data.hex()[0:4] and b"/likes" in data:
	                   
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}جاري العمل علي الطلب", uid
	                    )
	                )
	                    command_split = re.split("/likes", str(data))
	                    player_id = command_split[1].split('(')[0].strip()
	                    print(player_id)
	                    likes_response = send_likes(player_id)
	                    status = likes_response['status']
	                    message = likes_response['message']
	                    print(message)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(self.GenResponsMsg(message, uid))
	            	
	            if "1200" in data.hex()[0:4] and b"/check" in data:
	                   try:
	                   	print("Received /check command")
	                   	command_split = re.split("/check", str(data))
	                   	json_result = get_available_room(data.hex()[10:])
	                   	parsed_data = json.loads(json_result)
	                   	uid = parsed_data["5"]["data"]["1"]["data"]
	                   	clients.send(
	                   	self.GenResponsMsg(
                            f"{generate_random_color()}جاري فحص الباند...", uid
                        )
                    )
	                   	if len(command_split) > 1:
	                   	   player_id = command_split[1].split("\\x")[0].strip()
	                   	   player_id = command_split[1].split('(')[0].strip()
	                   	   print(player_id)

	                   	   banned_status = check_banned_status(player_id)
	                   	   print(banned_status)
	                   	   player_id = fix_num(player_id)
	                   	   status = banned_status.get('status', 'Unknown')
	                   	   player_name = banned_status.get('player_name', 'Unknown')

	                   	   response_message = (
                            f"{generate_random_color()}Player Name: {player_name}\n"
                            f"Player ID : {player_id}\n"
                            f"Status: {status}"
                        )
	                   	   print(response_message)
	                   	   clients.send(self.GenResponsMsg(response_message, uid))
	                   except Exception as e:
	                   	print(f"Error in /check command: {e}")
	                   	clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred, but the bot is still running!", uid))

	            if "1200" in data.hex()[0:4] and b"/help" in data:
	                
	                lines = "_"*20
	                
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                user_name = parsed_data['5']['data']['9']['data']['1']['data']
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                if "***" in str(uid):
	                	uid = rrrrrrrrrrrrrr(uid)
	                
	                print(f"\nUser With ID : {uid}\nName : {user_name}\nStarted Help\n")
 

	                
	                time.sleep
	                clients.send(
		                    self.GenResponsMsg(
		                        f"""

[FFFFFF][B]لفتح السكواد لصديقك:
[32CD32]/ 5 [ id ]

[FFFFFF][B]تحويل الفريق إلى:
[00FF00]/ 3    
[00FF00]/ 5  
[00FF00]/ 6  

[FFFFFF][B]جلب لاعب إلى الفريق:
[1E90FF]/ inv [ id ]

[FFFFFF][B]سبام طلبات انضمام:
[FFA500]/ x [ id ]

[FFFFFF][B]سبام رومات:
[FF4500] / room [ id ]

[FFFFFF][B]جلب معلومات اللاعب:
[00CED1]/ info [ id ]

[FFFFFF][B]معرفة حالة اللاعب:
[DC143C]/ status [ id ]

[FFFFFF][B]معرفة إذا كان اللاعب تنا.ك او لا:
[32CD32]/ check [ id ]

[FFFFFF][B]سبام طلبات صداقة:
[1E90FF]/ spam [ id ]

""", uid
	                    )
	                )
	                time.sleep(0.5)
	                clients.send(
		                    self.GenResponsMsg(
		                        f"""

[FFFFFF][B]زيادة عدد زوار الحساب:
[FFA500]/ visit  [ id ]

[FFFFFF][B]تزويد 100 لايك للحساب 
[FF69B4]/ like  [ id ]

[FFFFFF][B]لتحدث مع الذكاء الاصطناعي 
[9370DB]/🗿ai [نصك هنا]

[FFFFFF][B]جعل البوت سولو  :
[1E90FF] /solo 

""", uid
	                    )
	                )
		                

	            if "1200" in data.hex()[0:4] and b"/ai" in data:
	                i = re.split("/ai", str(data))[1]
	                if "***" in i:
	                    i = i.replace("***", "106")
	                sid = str(i).split("(\\x")[0].strip()
	                headers = {"Content-Type": "application/json"}
	                payload = {
	                    "contents": [
	                        {
	                            "parts": [
	                                {"text": sid}
	                            ]
	                        }
	                    ]
	                }
	                response = requests.post(
	                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDZvi8G_tnMUx7loUu51XYBt3t9eAQQLYo",
	                    headers=headers,
	                    json=payload,
	                )
	                if response.status_code == 200:
	                    ai_data = response.json()
	                    ai_response = ai_data['candidates'][0]['content']['parts'][0]['text']
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                        self.GenResponsMsg(
	                            ai_response, uid
	                        )
	                    )
	                else:
	                    print("Error with AI API:", response.status_code, response.text)



                    pass
            if "1200" in data.hex()[0:4] and b"/solo" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                # إرسال أمر مغادرة الفريق
                leavee = self.leave_s()
                socket_client.send(leavee)

                sleep(1)  # انتظار للتأكد من تنفيذ الخروج

                # تغيير الوضع إلى Solo
                change_to_solo = self.changes(1)
                socket_client.send(change_to_solo)

                

                clients.send(
                    self.GenResponsMsg(
                        f"[C][B][00FF00] تم الخروج من المجموعة.", uid
                    )
                )


            if "1200" in data.hex()[0:4] and b"/addVOPN" in data:
                i = re.split("/addVOPN", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/add', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    print(room_data)
                    iddd = room_data[0]
                    numsc1 = room_data[1] if len(room_data) > 1 else None

                    if numsc1 is None:
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/ add 123[c]456[c]78 4\n/ add 123[c]456[c]78 5", uid
                            )
                        )
                    else:
                        numsc = int(numsc1) - 1
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        if int(numsc1) < 3 or int(numsc1) > 6:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000] Usage : /add <uid> <Squad Type>\n[ffffff]Example : \n/ add 12345678 4\n/ add 12345678 5", uid
                                )
                            )
                        else:
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(1)
                            packetfinal = self.changes(int(numsc))
                            socket_client.send(packetfinal)
                            
                            invitess = self.invite_skwad(iddd)
                            socket_client.send(invitess)
                            iddd1 = parsed_data["5"]["data"]["1"]["data"]
                            invitessa = self.invite_skwad(iddd1)
                            socket_client.send(invitessa)
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00ff00]- AcCept The Invite QuickLy ! ", uid
                                )
                            )
                            leaveee1 = True
                            while leaveee1:
                                if leaveee == True:
                                    print("Leave")
                                    leavee = self.leave_s()
                                    sleep(5)
                                    socket_client.send(leavee)   
                                    leaveee = False
                                    leaveee1 = False
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]succes !", uid
                                        )
                                    )    
                                if pleaseaccept == True:
                                    print("Leave")
                                    leavee = self.leave_s()
                                    socket_client.send(leavee)   
                                    leaveee1 = False
                                    pleaseaccept = False
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]Please accept the invite", uid
                                        )
                                    )   
                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/ inv 123[c]456[c]78 4\n/ inv 123[c]456[c]78 5", uid
                        )
                    ) 

	                    
                    
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            whisper_ip, whisper_port, online_ip, online_port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = self.guest_token(self.id, self.password)
        g_token = token
        print(whisper_ip, whisper_port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            print("Final token constructed successfully.")
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        
      
        return token, key, iv
        
with open('7ama.json', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(3)
    thread.start()

for thread in threads:
    thread.join()
    
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="", password="")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()
