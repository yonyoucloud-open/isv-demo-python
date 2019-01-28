from urllib import parse
import base64
import hmac
from hashlib import sha256


class Sign:
    """
    用于加签，向开放平台发送的部分请求需要使用该类加签
    """
    def __init__(self, suite_key, suite_secret):
        """
        构建用于加签的 Sign 对象实例
        :param suite_key:     ISV 套件的 app key
        :param suite_secret:  ISV 套件的 app secret
        """
        self.suite_key = suite_key
        self.suite_secret = bytes(suite_secret, encoding='utf8')

    def sign(self, param_dict):
        """
        加签，签名未进行 urlEncode，使用 request 框架会自动进行 urlEncode
        :param param_dict: 待签名的参数 dict
        :return: 签名，未进行 urlEncode
        """
        keys = list(param_dict.keys())
        keys.sort()
        param_str = ""
        for key in keys:
            param_str = param_str + str(key) + str(param_dict[key])
        param_bytes = bytes(param_str, encoding='utf8')
        sha_data = hmac.new(self.suite_secret, param_bytes, digestmod=sha256).digest()
        signature = base64.b64encode(sha_data)
        return signature

    def sign_with_url_encoding(self, param_dict):
        """
        加签，签名已进行 urlEncode，拼接 url 请求时可直接使用该签名
        :param param_dict: 待签名的参数 dict
        :return: 签名，已 urlEncode
        """
        signature = self.sign(param_dict)
        return parse.quote(signature)
