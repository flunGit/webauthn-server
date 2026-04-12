/**
 * 用于在测试期间模拟返回值的内部实现
 * @ignore 不要将此内容包含在文档输出中
 */
const _fetchInternals = { stubThis: url => globalThis.fetch(url) };

/**
 * 一个用于通过标准 `fetch` 请求数据的简单方法,可在多种运行时环境中工作;
 */
function fetch(url) {
    return _fetchInternals.stubThis(url);
}

export { _fetchInternals, fetch };