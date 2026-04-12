'use strict';

const { toUTF8String } = require('./iso/isoBase64URL.js'),
    /**
     * 内部 API,允许在测试期间替换返回值
     * @ignore 不包含在文档输出中
     */
    internalAPI = { stubThis: value => value };

/**
 * 将认证器返回的 base64url 编码的 clientDataJSON 解码为 JSON 对象
 */
function decodeClientDataJSON(data) {
    const toString = toUTF8String(data), clientData = JSON.parse(toString);
    // 这里引用的是即将导出的对象中的 stubThis 方法
    // 由于 module.exports 是在下方统一定义的,直接引用局部变量或通过函数名均可
    return internalAPI.stubThis(clientData);
}

// 导出
module.exports = { decodeClientDataJSON, _decodeClientDataJSONInternals: internalAPI };