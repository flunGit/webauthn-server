import { toHash } from './toHash.js';
import { fromASCIIString, areEqual } from './iso/isoUint8Array.js';

class UnexpectedRPIDHash extends Error {
    constructor() {
        const message = '意外的 RP ID 哈希值';
        super(message), this.name = 'UnexpectedRPIDHash';
    }
}

/**
 * 遍历每个预期的 RP ID,尝试找到匹配项,返回与响应中的哈希值匹配的未哈希 RP ID;
 *
 * 如果未找到匹配项,则抛出 `UnexpectedRPIDHash` 错误;
 */
const matchExpectedRPID = async (rpIDHash, expectedRPIDs) => {
    try {
        const matchedRPID = await Promise.any(expectedRPIDs.map(expected => {
            return new Promise((resolve, reject) => {
                toHash(fromASCIIString(expected)).then(expectedRPIDHash => {
                    if (areEqual(rpIDHash, expectedRPIDHash)) resolve(expected);
                    else reject();
                });
            });
        }));
        return matchedRPID;
    }
    catch (err) {
        const _err = err;
        // 表示没有找到任何匹配项
        if (_err.name === 'AggregateError') throw new UnexpectedRPIDHash();
        throw err; // 发生了意外错误,重新抛出
    }
}

export { matchExpectedRPID, UnexpectedRPIDHash };