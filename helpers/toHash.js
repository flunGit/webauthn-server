import { utf8Tobytes, digest } from './iso/index.js';
/**
 * 返回给定数据的哈希摘要,如果提供了算法参数,则使用指定的算法:默认使用 SHA-256;
 * - 查看定义:@see {@link toHash}
 */
const toHash = (data, algorithm = -7) => {
    if (typeof data === 'string') data = utf8Tobytes(data);
    const digestV = digest(data, algorithm);
    return digestV;
};

export { toHash };