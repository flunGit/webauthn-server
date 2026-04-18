import { toHash } from './toHash.js';
import { asciiToBytes, areEqual } from './iso/isoUint8Array.js';

/**
 * 当响应中的 RP ID 哈希值与所有预期的 RP ID 均不匹配时抛出的错误;
* - 查看定义:@see {@link UnexpectedRPIDHash}
 */
class UnexpectedRPIDHash extends Error {
    constructor() {
        const message = '意外的 RP ID 哈希值';
        super(message), this.name = 'UnexpectedRPIDHash';
    }
}

/**
 * 遍历所有预期的 RP ID,找出与响应中哈希值匹配的项,并返回对应的原始 RP ID
 * 如果未找到匹配项,则抛出 `UnexpectedRPIDHash` 错误;
 * - 查看定义:@see {@link matchExpectedRPID}
 */
const matchExpectedRPID = async (rpIDHash, expectedRPIDs) => {
    try {
        const matchedRPID = await Promise.any(expectedRPIDs.map(expected => {
            return new Promise((resolve, reject) => {
                toHash(asciiToBytes(expected)).then(expectedRPIDHash => {
                    if (areEqual(rpIDHash, expectedRPIDHash)) resolve(expected);
                    else reject();
                });
            });
        }));
        return matchedRPID;
    }
    catch (err) {
        // 表示没有找到任何匹配项
        if (err.name === 'AggregateError') throw new UnexpectedRPIDHash();
        throw err; // 发生了意外错误,重新抛出
    }
}

export { matchExpectedRPID, UnexpectedRPIDHash };