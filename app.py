from flask import Flask
from flask import request
from crypto import sign, crypto
import time
import requests
import json

app = Flask(__name__)

# ISV 套件的 suite_key
suite_key = '<your suite key>'

# ISV 套件的 suite_secret
suite_secret = '<your suite secret>'

# ISV 套件的 encoding aes key，经过 base64 后的 43 位 aes key
encoding_aes_key = '<your encoding aes key>'

# 开放平台推送的 suite ticket, 每 20 分钟推送一次, 接收到新的 ticket 后旧 ticket 即过期
suite_ticket = ''

suite_sign = sign.Sign(suite_key, suite_secret)
suite_crypto = crypto.Crypto(suite_key, suite_secret, encoding_aes_key)


@app.route('/')
def hello_world():
    return 'Hello World! </br> suite_key: %s, suite_secret: %s, encoding_aes_key: %s' % (
        suite_key, suite_secret, encoding_aes_key)


@app.route('/suitePush', methods=['POST'])
def push_suite_event():
    """
    接收开放平台推送的套件相关事件（推送 ticket、推送授权信息等），开放平台会直接调用该接口，复杂耗时业务推荐异步处理
    :return: 处理成功返回 'success'，否则开放平台判定处理失败，会重试推送，直到 24 小时
    """
    global suite_ticket

    request_json = request.get_json()

    # 解密验签
    decoded = suite_crypto.decode_dict_with_validate(request_json)
    print(decoded)
    event = json.loads(decoded)
    event_type = event['type']

    # 根据事件类型进行业务处理，开放平台投递超时时间 5s，复杂业务推荐异步处理，超时视为投递失败，ticket 事件不会重试，授权事件会重试
    if 'SUITE_TICKET' == event_type:
        print('新的 ticket 推送事件，ticket: %s' % event['suiteTicket'])
        suite_ticket = event['suiteTicket']
    elif 'SUITE_AUTH' == event_type:
        print('新的授权事件, authTenantId: %s' % event['authTenantId'])
        # 处理授权相关逻辑

    # 处理成功返回 'success'，否则开放平台认为投递失败
    return 'success'


@app.route('/getAccessToken')
def get_access_token():
    """
    获取 access_token
    :return: 开放平台返回的包含 access_token 的原始消息体
    """
    tenant_id = request.args.get('tenantId')

    timestamp = int(time.time() * 1000)
    param_dict = {'suiteKey': suite_key, 'tenantId': tenant_id, 'suiteTicket': suite_ticket, 'timestamp': timestamp}
    signature = suite_sign.sign(param_dict)
    param_dict['signature'] = signature
    res = requests.get('https://open.yonyoucloud.com/open-auth/suiteApp/getAccessToken', param_dict)
    return res.content


@app.route('/login')
def login_free():
    """
    免登
    :return: 登陆用户的 id、租户 id 等信息
    """
    code = request.args.get('code')

    timestamp = int(time.time() * 1000)
    param_dict = {'suiteKey': suite_key, 'code': code, 'suiteTicket': suite_ticket, 'timestamp': timestamp}
    signature = suite_sign.sign(param_dict)
    param_dict['signature'] = signature
    res = requests.get('https://open.yonyoucloud.com/open-auth/suiteApp/getBaseInfoByCode', param_dict)
    return res.content


@app.route('/dataPush', methods=['POST'])
def push_data_change_event():
    """
    接收开放平台推送的数据变动事件，开放平台会直接调用该接口，推送数据变动的 id，超时时间 5s，复杂耗时业务推荐异步处理
    :return: 处理成功返回 'success'，否则开放平台判定处理失败，会重试推送，直到 24 小时
    """

    request_json = request.get_json()

    # 解密验签
    decoded = suite_crypto.decode_dict_with_validate(request_json)
    print(decoded)
    event = json.loads(decoded)
    event_type = event['type']

    # 根据事件类型进行业务处理，开放平台投递超时时间 5s，复杂业务推荐异步处理，超时视为投递失败，会进行重试
    if 'CHECK_URL' == event_type:
        print('事件类型: %s, 说明: 检查事件推送回调地址' % event_type)
    elif 'STAFF_ADD' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下员工增加, 员工变更 id: %s' % (event_type, event['tenantId'], event['staffId']))
    elif 'STAFF_UPDATE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下员工更改, 员工变更 id: %s' % (event_type, event['tenantId'], event['staffId']))
    elif 'STAFF_ENABLE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下员工启用, 员工变更 id: %s' % (event_type, event['tenantId'], event['staffId']))
    elif 'STAFF_DISABLE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下员工停用, 员工变更 id: %s' % (event_type, event['tenantId'], event['staffId']))
    elif 'STAFF_DELETE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下员工删除, 员工变更 id: %s' % (event_type, event['tenantId'], event['staffId']))
    elif 'DEPT_ADD' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下部门创建, 部门变更 id: %s' % (event_type, event['tenantId'], event['deptId']))
    elif 'DEPT_UPDATE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下部门修改, 部门变更 id: %s' % (event_type, event['tenantId'], event['deptId']))
    elif 'DEPT_ENABLE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下部门启用, 部门变更 id: %s' % (event_type, event['tenantId'], event['deptId']))
    elif 'DEPT_DISABLE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下部门停用, 部门变更 id: %s' % (event_type, event['tenantId'], event['deptId']))
    elif 'DEPT_DELETE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下部门删除, 部门变更 id: %s' % (event_type, event['tenantId'], event['deptId']))
    elif 'USER_ADD' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下用户增加, 用户 id: %s' % (event_type, event['tenantId'], event['userId']))
    elif 'USER_DELETE' == event_type:
        print('事件类型: %s, 说明: 租户 %s 下用户移除, 用户 id: %s' % (event_type, event['tenantId'], event['userId']))

    # 处理成功返回 'success'，否则开放平台认为投递失败，会重试投递直到 24 小时
    return 'success'


if __name__ == '__main__':
    app.run()
