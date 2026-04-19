import { getWebCrypto } from './getWebCrypto.js';

/**
 * 使用与数组长度相等的随机字节填充传入的字节数组
 * - 查看定义:@see {@link getRandomValues}
 *
 * @template T
 * @param {T} array - 要填充随机值的类型化数组（如 Uint8Array）
 * @returns {Promise<T>} 返回传入的同一个字节数组（已填充随机值）
 */
const getRandomValues = async array => {
    const WebCrypto = await getWebCrypto();
    WebCrypto.getRandomValues(array);
    return array;
}

export { getRandomValues };