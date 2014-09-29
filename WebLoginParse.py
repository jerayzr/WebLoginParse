#!/usr/bin/python
# -*- coding: utf-8 -*-

#=============================================================================
#  Author:          Jeray
#  Email:           Jerayzr@gmail.com
#  FileName:        WebLoginParse.py
#  Description:     1.程序测试时在django下调用，这里做了对用户登录后所返回的ticket和sign
#                     进行验签和解码的工作，第一步的重定向工作和获得用户登录成功信息之后的工
#                     作请根据所使用不同web框架自行定制
#                   2.运行该程序需要安装Crypto库，下载地址：https://pypi.python.org/
#                     pypi/pycrypto,本程序运行时所安装为pycrypto 2.6.1
#                   3.建议使用时将CERT,PUB_KEY放入settings.py文件当中                   
#  Version:         0.0.1
#  LastChange:      2014-06-21 17:24:23
#  History:         
#=============================================================================

from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import  PKCS1_v1_5
from pprint import pprint
import base64

CERT = '''-----BEGIN CERT-----
MIIDhzCCAm+gAwIBAgIBAzANBgkqhkiG9w0BAQUFADBXMQswCQYDVQQGEwJDTjEL
MAkGA1UECAwCQkoxCzAJBgNVBAcMAkJKMQwwCgYDVQQKDANDQVMxDzANBgNVBAsM
BkNBUyBDCDEPMA0GA1UEAwwGQ0FTIENBMB4XDTEyMTIxNTIxMDM0MVoXDTEzMTIx
NTIxMDM0MVowOjELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkJKMQwwCgYDVQQKDAND
QVMxEDAOBgNVBAMMB0NBUyBJRFAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDB9esx7utpbwp2A0c4Ys+4AQytuQsHkn2yzQLlL3AonNIW3kFmfk/3at7V
ISWblnREJ7dK89XR9DPa8v4KtO501cSf7A/deNZD9FxhZKICUU9iiW1It/kqnz8M
OVvmW+2IOPTEgrhv8LtXWXcxmjAAxuRCMUGxfwlV52U2r5Sa8VNpmRwpLlaTyBFG
03xNQlOLk2YlSyoN1VYkh2aWg1oeG+caVeUnpLkLYJDNqvJwfyXCOflAxst4cv8a
R1ytcp7fnAEVcBbUn+UX6NxDxD+lwRIqD68Z9YpSbSzd+aXmrp2KaXQO36tYwyj1
nD/br/12mkLiX/HkjfyVNexcuaGxAgMBAAGjezB5MAkGA1UdEwQCMAAwLAYJYIZI
AYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQW
BBSLjmN91cRV4pU7Z2z3Q8wGtWXH7zAfBgNVHSMEGDAWgBQa9Aq/c1vtkD41rqxu
2aFR3vvqRTANBgkqhkiG9w0BAQUFAAOCAQEAXiTtViESPbuU7J3IpIAi7UN/ToxZ
8OWonVqrtfIXrTG34YAvPb3+SsVs8mdq5dYL+FwJbXRb90uUbz8cN0r76KHvGHVc
c7/WGOgiihc9coEL2RM7dOWxnTxKkecHh1v+t+j/gqrYAtvNftZmfFYkIGKLTM5r
IDYotFvs6KMjc6znIjRNVPLBicsq5z3ND+WaC7MdvqdA12Ux5f5L5hseleRSURqy
9llSdvKeb+sQ8pNxn9D4t9e8fYvvutMF9vNO0dhsfr4sWNvtco81mfnPbTpcGDvK
CF6QTnUG5f+vJpSax9JWlS+BVg3DBnthHfFb/hFNZ6i2GO2w6PZglVHqjg==
-----END CERT-----'''
PUB_KEY = 'lz6yYQkBokSkbFmwHSTYGQ7Y5vCGFQkH/BMOKhyB4DQ='

def sxor(s1,s2):    
    '''对两个字符串进行异或操作，并且返回字符串格式'''
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

class WebLoginParse:
    '''单点登录集成模块'''
    def __init__(self, ticket, sign):
        '''初始化，输入为ticket和sign两个参数'''
        self.ticket = ticket
        self.sign = sign
    
    def base64decode(self):
        '''将ticket和sign做base64解码'''
        ticket = base64.decodestring(self.ticket)
        sign = base64.decodestring(self.sign)
        return ticket,sign
    
    def sign_verify(self, t, s):
        '''使用sha1withrsa算法验证签名'''
        pem = CERT                                 #获得证书
        #把从证书获取publickey
        lines = pem.replace(" ",'').split()
        der = base64.decodestring(''.join(lines[1:-1]))
        cert = DerSequence()
        cert.decode(der)
        tbsCertificate = DerSequence()
        tbsCertificate.decode(cert[0])
        subjectPublicKeyInfo = tbsCertificate[6]
        #导入publickey进行验证
        rsa_key = RSA.importKey(subjectPublicKeyInfo)
        h = SHA.new()
        h.update(t)
        verifier = PKCS1_v1_5.new(rsa_key)
        if not verifier.verify(h,s):                        #开始验签
            return False                                    #验签未通过
        return True                                         #验签通过
    
    def decode_info(self, t):
        '''对ticket进行解码操作'''
        from Crypto.Cipher import AES
        pub_key = base64.decodestring(PUB_KEY)     
        pub_key_1 = pub_key[:16]
        pub_key_2 = pub_key[16:]
        aes_key = sxor(pub_key_1, pub_key_2)                #将前16字节和后16字节进行异或
        aes_tool = AES.new(aes_key, AES.MODE_ECB)           #使用AES算法的ECB模式进行解码
        aes_result = aes_tool.decrypt(t)
        split_aes = aes_result.rstrip('\0').split('&')      #去掉字符串最后的空格，并且以"&"进行分割
        dict = {}                                           #定义一个空的字典
        for i in split_aes:
            split_i = i.split('=')                          #对每一项以"="进行分割
            dict[split_i[0]] = split_i[1]                   #"="左侧的作为字典的key，"="右侧的作为字典的value
        return dict                                         #返回字典
    
    def login_info(self):
        '''获得用户登录信息'''
        ticket,sign = self.base64decode()
        if not self.sign_verify(ticket, sign):              #验签未通过，返回-1
            print u'验签未通过'
            return -1
        print u'验签通过'
        parse_info_dict = self.decode_info(ticket)
        return parse_info_dict
    
def test_func():
    '''测试程序'''
    ticket = 'c2EOHp/5RRvFpIV6X6tH8lHiY4iptzmimZnDkvwqjS8j9ksBOtVErM4vxreCjUZTYaf4tCHhZtGj25zTl/tscNYVi5psDZfO8XpNE84F2nGTNNHyEN8SD16QlQc6MXQlmfIcVl/g4+3QXUXxHorkFq1r6yXleVQ+oYcTMlbyR2R0dHnfZjs7HWP84MnSbyVZl/n+1W+ZPuLqQRGL+q3aas4md0/A62H5Hk5M7R9vxvJdcry5SLCdaKCN1qFjBm9OWdu6AqTQS76Wy0BlRPnFaEkNHOMEz3/T3j1+imr+zWH9lPDSgl9MR5KWPXVu2E2rGj3Krbb7iBCy0fvc+aeG6imZ1I61a0pH5NTpCObzxB5YKsDphTUAdqiZq9hClup3kEFckaobvGk7y4nB62rkM3OdHcWcTEJ3H+9dfFqnNgjo15ByJScDKHhlcVtxRAUf10IU9+vwpga7OwkIlAdfZ/3yM64xkL+E1arhnyHQjEtKMgFJ4IdQ2AbPpzevUMGlXwa1BgFGxt3luwfCRESH3w=='
    sign = 'FC9K7jhi83VPwgKY3cIY3qaHfdK7GV9/io40DmKbTuJPAIq+c7owzGemq2T+QNokXIXoAUpYSD+FhVeFwk7eTT6qTM2NuSPVsrpPb3kdMfTRc/w+96J3d6by7mpZd9tVfdahRgp/6JmLHwWBvPdy8/y9UzrcZhXZUdtcMn39fSCOLVZ1gNgog6a73Izm9Vfd+BAQ4kRQz+kjTuHDtfWSjp/w6+VFQRs+b6C5jq2TI9fEVyomLZHDYi2erMs2tH5ZFwWBXjpI4lEM72l2M6yJd9fBly3psbMzXttwlGGCphwh61JbuyrKlDFVODVK4yeoFo6G6u21uyjgVvaSUOn7fA=='
    login_parse = WebLoginParse(ticket, sign)   #初始化WebLoginParse类
    login_info = login_parse.login_info()       #调用WebLoginParse类中的login_info方法，得到返回结果
    pprint(login_info)

if __name__ == '__main__':
    test_func()






