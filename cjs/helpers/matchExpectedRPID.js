'use strict';

const { toHash } = require('./toHash.js'), { fromASCIIString, areEqual } = require('./iso/isoUint8Array.js');
/**
 * 遍历所有预期的 RP ID，尝试找到匹配项。返回与响应中哈希值相匹配的未哈希 RP ID。
 *
 * 如果未找到任何匹配，将抛出 `UnexpectedRPIDHash` 错误。
 *
 * @param {Uint8Array} rpIDHash 响应中返回的 RP ID 哈希值
 * @param {string[]} expectedRPIDs 预期的 RP ID 列表
 * @returns {Promise<string>} 匹配到的原始 RP ID 字符串
 */
async function matchExpectedRPID(rpIDHash, expectedRPIDs) {
    try {
        const matchedRPID = await Promise.any(
            expectedRPIDs.map(expected => {
                return new Promise((resolve, reject) => {
                    toHash(fromASCIIString(expected)).then(expectedRPIDHash => {
                        if (areEqual(rpIDHash, expectedRPIDHash)) resolve(expected);
                        else reject();
                    });
                });
            })
        );
        return matchedRPID;
    } catch (err) {
        // 表示未找到任何匹配项
        if (err.name === 'AggregateError') throw new UnexpectedRPIDHash();
        throw err; // 其他意外错误直接抛出
    }
}

/**
 * 当 RP ID 哈希值与任何预期值都不匹配时抛出的错误
 */
class UnexpectedRPIDHash extends Error {
    constructor() {
        const message = 'Unexpected RP ID hash';
        super(message), this.name = 'UnexpectedRPIDHash';
    }
}

// 导出公共 API
module.exports = { matchExpectedRPID, UnexpectedRPIDHash };