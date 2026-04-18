import { b64urlToUtf8 } from './iso/index.js';

/**
 * 使测试期间能够模拟（stub）返回值
 * - 查看定义:@see {@link _decodeClientDataJSONInternals}
 * @ignore 不要将此内容包含在文档输出中
 */
const _decodeClientDataJSONInternals = { stubThis: value => value },

    /**
     * 将身份验证器的 base64url 编码的 clientDataJSON 解码为 JSON 对象
     * - 查看定义:@see {@link decodeClientDataJSON}
     */
    decodeClientDataJSON = data => {
        const toString = b64urlToUtf8(data), clientData = JSON.parse(toString);
        return _decodeClientDataJSONInternals.stubThis(clientData);
    };

export { _decodeClientDataJSONInternals, decodeClientDataJSON };