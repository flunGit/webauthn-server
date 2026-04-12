"use strict";

let webCrypto = undefined;

// 允许在测试期间替换返回值(允许重置文件顶部的 `webCrypto` 缓存)
const _getWebCryptoInternals = {
    stubThisGlobalThisCrypto: () => globalThis.crypto, setCachedCrypto: newCrypto => webCrypto = newCrypto
};

/**
 * 尝试从当前运行时获取 Crypto API 的实例,应该支持 Node 以及实现了 Web API 的其他环境（如 Deno）;
 * @returns {Promise<Crypto>} 解析为 Crypto 对象（可通过 .subtle 访问 SubtleCrypto）
 */
function getWebCrypto() {
    /**
     * 你好！如果你想知道为什么这个方法使用异步方式而直接访问 `globalThis.crypto` 却是同步的,
     * 这是为了尽量减少因为将其改为同步而导致的大量重构工作,例如,如果我们把这里改为同步,
     * 那么 `generateRegistrationOptions()` 和 `generateAuthenticationOptions()` 也会变成同步
     * （因为该方法中没有其他异步操作）,这会导致本库核心 API 发生破坏性变更;
     *
     * TODO: 如果你读到这段注释时已经是 2025 年 2 月之后，请考虑是否仍有必要保留此方法的异步特性;
     */
    const toResolve = new Promise((resolve, reject) => {
        if (webCrypto) return resolve(webCrypto);

        /**
         * 尝试通过全局对象直接访问 Crypto,流行的 ESM 运行时（以及 Node v20+）都支持这种方式;
         */
        const _globalThisCrypto = _getWebCryptoInternals.stubThisGlobalThisCrypto();

        if (_globalThisCrypto) return resolve(webCrypto = _globalThisCrypto);
        return reject(new MissingWebCrypto()); // 在 Node 和全局环境下都尝试过了,最终失败
    });

    return toResolve;
}

class MissingWebCrypto extends Error {
    constructor() {
        const message = '未能找到 Crypto API 的实例';
        super(message), this.name = 'MissingWebCrypto';
    }
}

module.exports = { getWebCrypto, MissingWebCrypto, _getWebCryptoInternals };