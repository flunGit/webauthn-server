'use strict';

const { toUTF8String } = require('../helpers/iso/isoBase64URL.js');

/**
 * 将 JWT 解析为 JavaScript 友好的数据结构
 *
 * @param {string} jwt 待解析的 JWT 字符串
 * @returns {[object, object, string]} 返回数组,依次为头部（header）、载荷（payload）和签名（signature）
 */
function parseJWT(jwt) {
    const parts = jwt.split('.');
    return [JSON.parse(toUTF8String(parts[0])), JSON.parse(toUTF8String(parts[1])), parts[2]];
}

module.exports = { parseJWT };