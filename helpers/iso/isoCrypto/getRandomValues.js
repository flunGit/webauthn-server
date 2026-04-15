import { getWebCrypto } from './getWebCrypto.js';

/**
 * 使用与数组长度相等的随机字节填充传入的字节数组;
 *
 * @returns 返回传入的同一个字节数组
 */
async function getRandomValues(array) {
    const WebCrypto = await getWebCrypto();
    WebCrypto.getRandomValues(array);
    return array;
}

export { getRandomValues };