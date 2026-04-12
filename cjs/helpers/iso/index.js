'use strict';

/**
 * 用于以同构方式处理较棘手的数据类型的方法集合
 *
 * 目标是为了更容易替换那些可能无法与暴露了全局 Web API 的特定服务端运行时（CloudFlare Workers、Deno、Bun 等）良好兼容的依赖,
 * 同时支持在 Node 环境中执行;
 */

const isoBase64URL = require('./isoBase64URL.js'), isoCBOR = require('./isoCBOR.js'),
    isoCrypto = require('./isoCrypto/index.js'), isoUint8Array = require('./isoUint8Array.js');

module.exports = { isoBase64URL, isoCBOR, isoCrypto, isoUint8Array };