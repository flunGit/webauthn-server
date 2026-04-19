import { b64urlToUtf8 } from '../helpers/iso/index.js';

/**
 * 将 JWT 解析为 JavaScript 友好的数据结构
 * - 查看定义: @see {@link verifyJWT}
 * @param {string} jwt - 原始的 JWT 字符串（三段式 base64url 编码）
 * @returns {[Record<string, unknown>, Record<string, unknown>, string]}
 *   返回一个元组：
 *   - 索引 0: 解码后的 JWT 头部（标准 JSON 对象）
 *   - 索引 1: 解码后的 JWT 载荷（标准 JSON 对象）
 *   - 索引 2: 原始签名部分（base64url 字符串）
 */
const parseJWT = jwt => {
    const parts = jwt.split('.');
    return [
        JSON.parse(b64urlToUtf8(parts[0])),
        JSON.parse(b64urlToUtf8(parts[1])),
        parts[2]
    ];
};

export { parseJWT };