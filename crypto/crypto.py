from Crypto.Cipher import AES
from hashlib import sha1
import base64


class Crypto:
    """
    用于验签解密，处理开放平台推送的消息
    """
    def __init__(self, suite_key: 'str', suite_secret: 'str', encoding_aes_key: 'str'):
        """
        构造用于验签解密的 Crypto 对象实例
        :param suite_key:           ISV 套件的 suite secret
        :param suite_secret:        ISV 套件的 suite secret
        :param encoding_aes_key:    ISV 套件的 base64 后的 aes key
        """
        self.suite_key = suite_key
        self.suite_secret = suite_secret
        self.aes_key = _aes_key_from(encoding_aes_key)

    def decode_dict_with_validate(self, param_dict: 'dict'):
        """
        验签解密
        :param param_dict: 包含请求参数的 dict, 必须包含 encrypt, timestamp, nonce, msgSignature 字段
        :return: 验签解密后的消息体
        """
        return self.decode_with_validate(param_dict['encrypt'], param_dict['timestamp'], param_dict['nonce'], param_dict['msgSignature'])

    def decode_with_validate(self, encrypted: 'str', timestamp: 'int', nonce: 'str', signature: 'str'):
        """
        验签解密
        :param encrypted: 被加密的消息体
        :param timestamp: 时间戳
        :param nonce:     随机值
        :param signature: 签名
        :return: 验签解密后的消息体
        """
        my_sign = self.sign(encrypted, timestamp, nonce)
        if my_sign != signature:
            raise RuntimeError('签名校验失败！需要：' + my_sign + '，实际: ' + signature)
        return self.decode(encrypted)

    def decode(self, encrypted: 'str'):
        """
        仅解密，不验签
        :param encrypted: 被加密的消息体
        :return: 解密后的消息体
        """
        missing_padding_count = 4 - len(encrypted) % 4
        if missing_padding_count != 4:
            missing_padding = b'=' * missing_padding_count
            missing_padding_str = missing_padding.decode('utf-8')
        else:
            missing_padding_str = ''
        return self._decode_aes(base64.b64decode(encrypted + missing_padding_str)).decode()

    def sign(self, encrypted: 'str', timestamp: 'int', nonce: 'str'):
        """
        计算签名
        :param encrypted: 被加密的消息体
        :param timestamp: 时间戳
        :param nonce:     随机值，盐
        :return:
        """
        array = [self.suite_secret, str(timestamp), nonce, encrypted]
        array.sort()
        sort_str = ''
        for s in array:
            sort_str += s
        sha = sha1()
        sha.update(sort_str.encode())
        return sha.hexdigest()

    def _decode_aes(self, aes_data: 'bytes'):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_key[:16])
        origin = cipher.decrypt(aes_data)
        unpad_bytes = _byte_unpad(origin)
        content_len = _recover_bytes_order(origin[16: 20])
        message = origin[20: 20 + content_len]
        from_key = origin[20 + content_len: len(unpad_bytes)]
        if from_key.decode() != self.suite_key:
            raise RuntimeError('suite key 不匹配, 需要：' + self.suite_key + '，实际：' + from_key.decode())
        return message


def _aes_key_from(encoding_aes_key: 'str'):
    encoding_aes_key += '='
    return base64.b64decode(encoding_aes_key)


def _recover_bytes_order(source_bytes: 'bytes'):
    source_number = 0
    for i in range(4):
        source_number <<= 8
        source_number |= source_bytes[i] & 0xff
    return source_number


def _byte_unpad(origin_bytes: 'bytes'):
    pad = int(origin_bytes[len(origin_bytes) - 1])
    if pad < 1 or pad > 32:
        return origin_bytes[0:]
    return origin_bytes[0: - pad]
