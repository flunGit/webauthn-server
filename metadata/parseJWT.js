import { b64urlToUtf8 } from '../helpers/iso/index.js';
/**
 * 将 JWT 处理为 JavaScript 友好的数据结构
 */
const parseJWT = jwt => {
    const parts = jwt.split('.');
    return [
        JSON.parse(b64urlToUtf8(parts[0])),
        JSON.parse(b64urlToUtf8(parts[1])), parts[2]
    ];
};

export { parseJWT };