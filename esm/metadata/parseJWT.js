import { toUTF8String } from '../helpers/iso/isoBase64URL.js';
/**
 * 将 JWT 处理为 JavaScript 友好的数据结构
 */
function parseJWT(jwt) {
    const parts = jwt.split('.');
    return [
        JSON.parse(toUTF8String(parts[0])),
        JSON.parse(toUTF8String(parts[1])), parts[2]
    ];
}

export { parseJWT };