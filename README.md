WebLoginParse
=============
#  Description:     1.程序测试时在django下调用，这里做了对用户登录后所返回的ticket和sign
#                     进行验签和解码的工作，第一步的重定向工作和获得用户登录成功信息之后的工
#                     作请根据所使用不同web框架自行定制
#                   2.运行该程序需要安装Crypto库，下载地址：https://pypi.python.org/
#                     pypi/pycrypto,本程序运行时所安装为pycrypto 2.6.1
#                   3.建议使用时将CERT,PUB_KEY放入settings.py文件当中 
