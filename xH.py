import requests, json, binascii, random, warnings
import urllib3
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers import Cipher as Cp, algorithms as Al, modes as Md
from cryptography.hazmat.backends import default_backend as Bk
from google.protobuf.internal.decoder import _DecodeVarint32





warnings.filterwarnings("ignore")
urllib3.disable_warnings()

K  = b"Yg&tc%DEuh6%Zc^8"
IV = b"6oyZDr22E3ychjM%"

dT = bytes.fromhex(
    "1a13323032352d30372d33302031343a31313a3230220966726565206669726528013a07"
    "322e3131342e324234416e64726f6964204f53203133202f204150492d33332028545031"
    "412e3232303632342e3031342f3235303531355631393737294a0848616e6468656c6452"
    "094f72616e676520544e5a0457494649609c1368b80872033438307a1d41524d3634204650"
    "204153494d4420414553207c2032303030207c20388001973c8a010c4d616c692d473532"
    "204d433292013e4f70656e474c20455320332e322076312e72333270312d3031656163302e"
    "32613839336330346361303032366332653638303264626537643761663563359a012b476f"
    "6f676c657c61326365613833342d353732362d346235622d383666322d373130356364386666"
    "353530a2010e3139362e3138372e3132382e3334aa0102656eb201203965373166616266343364"
    "383863303662373966353438313034633766636237ba010134c2010848616e6468656c64ca0115"
    "494e46494e495820496e66696e6978205836383336ea014063363231663264363231343330646163"
    "316137383261306461623634653663383061393734613662633732386366326536623132323464313836"
    "633962376166f00101ca02094f72616e676520544ed2020457494649ca03203161633462383065636630"
    "343738613434323033626638666163363132306635e003dc810ee803daa106f003ef068004e7a506"
    "8804dc810e9004e7a5069804dc810ec80403d2045b2f646174612f6170702f7e7e73444e524632"
    "526357313830465a4d66624d5a636b773d3d2f636f6d2e6474732e66726565666972656d61782d"
    "4a534d4f476d33464e59454271535376587767495a413d3d2f6c69622f61726d3634e00402ea047b"
    "61393862306265333734326162303061313966393737633637633031633266617c2f646174612f6170"
    "702f7e7e73444e524632526357313830465a4d66624d5a636b773d3d2f636f6d2e6474732e66726565"
    "666972656d61782d4a534d4f476d33464e59454271535376587767495a413d3d2f626173652e61706b"
    "f00402f804028a050236349a050a32303139313135363537a80503b205094f70656e474c455333b805"
    "ff7fc00504d20506526164c3a873da05023133e005b9f601ea050b616e64726f69645f6d6178f2055c"
    "4b71734854346230414a3777466c617231594d4b693653517a6732726b3665764f38334f306f59306763"
    "635a626457467a785633483564454f586a47704e3967476956774b7533547a312b716a36326546673074"
    "627537664350553d8206147b226375725f72617465223a5b36302c39305d7d880601900601"
    "9a060134a2060134b20600"
)

def padB(d): n=16-(len(d)%16); return d+bytes([n]*n)
def upd(d): p=d[-1]; return d[:-p] if 1<=p<=16 else d

def enc(b):
    c=Cp(Al.AES(K),Md.CBC(IV),backend=Bk()); e=c.encryptor()
    return e.update(padB(b))+e.finalize()

def dec(b):
    c=Cp(Al.AES(K),Md.CBC(IV),backend=Bk()); d=c.decryptor()
    return upd(d.update(b)+d.finalize())

def pbD(data):
    i,out=0,{}
    while i<len(data):
        try: key,i=_DecodeVarint32(data,i)
        except: break
        fn,wt=key>>3,key&0x7
        if wt==0:
            v,i=_DecodeVarint32(data,i); out[str(fn)]={"t":"int","v":v}
        elif wt==2:
            ln,i=_DecodeVarint32(data,i); v=data[i:i+ln]; i+=ln
            try: out[str(fn)]={"t":"str","v":v.decode()}
            except: out[str(fn)]={"t":"hex","v":v.hex()}
        elif wt==1: out[str(fn)]={"t":"64b","v":data[i:i+8].hex()}; i+=8
        elif wt==5: out[str(fn)]={"t":"32b","v":data[i:i+4].hex()}; i+=4
        else: break
    return out

def eID(x):
    x=int(x); e=[]
    while x:
        e.append((x&0x7F)|(0x80 if x>0x7F else 0)); x>>=7
    return bytes(e).hex()

def ua():
    return random.choice([
        "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "GarenaMSDK/4.0.18P6(SM-A125F ;Android 11;en;IN;)",
        "GarenaMSDK/4.1.0P3(Redmi 9A ;Android 10;en;ID;)"
    ])

def gTok(u,p):
    r=requests.post(
        "https://100067.connect.garena.com/oauth/guest/token/grant",
        headers={"Host":"100067.connect.garena.com","User-Agent":ua(),"Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"gzip, deflate, br","Connection":"close"},
        data={"uid":u,"password":p,"response_type":"token","client_type":"2","client_secret":"2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id":"100067"},
        verify=False,timeout=15
    )
    if r.status_code!=200: raise Exception(f"garena {r.status_code}")
    d=r.json(); return d["access_token"],d["open_id"]

def bLd(at,oid):
    x=dT[:]
    x=x.replace(b"2025-07-30 14:11:20",str(datetime.now())[:-7].encode())
    x=x.replace(b"c621f2d621430dac1a782a0dab64e6c80a974a6bc728cf2e6b1224d186c9b7af",at.encode())
    x=x.replace(b"9e71fabf43d88c06b79f548104c7fcb7",oid.encode())
    return enc(x)

def gJwt(u,p):
    at,oid=gTok(u,p)
    pay=bLd(at,oid)
    r=requests.post(
        "https://loginbp.common.ggbluefox.com/MajorLogin",
        headers={"Expect":"100-continue","X-Unity-Version":"2018.4.11f1","X-GA":"v1 1","ReleaseVersion":"OB53","Authorization":"Bearer ","Host":"loginbp.common.ggbluefox.com","User-Agent":"Dalvik/2.1.0 (Linux; U; Android 13; A063)","Content-Type":"application/x-www-form-urlencoded","Accept-Encoding":"gzip"},
        data=pay,verify=False,timeout=20
    )
    if r.status_code!=200: raise Exception(f"MajorLogin {r.status_code}")
    d=pbD(r.content); tok=d.get("8",{}).get("v","")
    if not tok: raise Exception("no jwt")
    return tok.strip()

def hdr(tok):
    return {"Content-Type":"application/x-www-form-urlencoded","X-GA":"v1 1","ReleaseVersion":"OB53","Host":"clientbp.ggpolarbear.com","Accept-Encoding":"gzip, deflate, br","Accept-Language":"en-GB,en-US;q=0.9,en;q=0.8","User-Agent":"Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0","Connection":"keep-alive","Authorization":f"Bearer {tok}","X-Unity-Version":"2018.4.11f1","Accept":"*/*"}
