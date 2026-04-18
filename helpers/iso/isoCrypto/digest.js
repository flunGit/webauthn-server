import { mapCoseAlgToWebCryptoAlg } from './mapCoseAlgToWebCryptoAlg.js';
import { getWebCrypto } from './getWebCrypto.js';

/**
 * 生成所提供数据的摘要（哈希值）;
 * - 查看定义:@see {@link digest}
 * @param data 要生成摘要的数据
 * @param algorithm COSE 算法 ID，该 ID 映射到所需的 SHA 算法
 */
const digest = async (data, algorithm) => {
    const WebCrypto = await getWebCrypto(), subtleAlgorithm = mapCoseAlgToWebCryptoAlg(algorithm),
        hashed = await WebCrypto.subtle.digest(subtleAlgorithm, data);
    return new Uint8Array(hashed);
};

export { digest };