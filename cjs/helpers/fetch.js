'use strict';

/**
 * 允许在测试期间对返回值进行桩替换 (Stub)
 * @ignore 不包含在文档输出中
 */
const _fetchInternals = { stubThis: url => globalThis.fetch(url) };

/**
 * 一个简单的基于标准 `fetch` 的数据请求方法;
 * 旨在跨多种运行时环境工作;
 *
 * @param {string | URL | Request} url 请求地址
 * @returns {Promise<Response>} fetch 响应 Promise
 */
function fetch(url) {
    return _fetchInternals.stubThis(url);
}

// 导出公共 API
module.exports = { fetch, _fetchInternals };