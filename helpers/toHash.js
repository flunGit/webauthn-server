import { isoUint8Array, isoCrypto } from './iso/index.js';
/**
 * 返回给定数据的哈希摘要,如果提供了算法参数,则使用指定的算法:默认使用 SHA-256;
 * - 查看定义:@see {@link toHash}
 */
const toHash = (data, algorithm = -7) => {
    if (typeof data === 'string') data = isoUint8Array.fromUTF8String(data);
    const digest = isoCrypto.digest(data, algorithm);
    return digest;
};

export { toHash };