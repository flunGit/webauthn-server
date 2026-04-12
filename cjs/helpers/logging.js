'use strict';

/**
 * 生成一个 "flun-webauthn-server" 的 `debug` 日志记录器实例,以确保命名风格一致;
 *
 * 有关在 flun-webauthn-server 中如何控制日志输出的更多信息,请参阅 https://www.npmjs.com/package/debug
 *
 * 示例：
 *
 * ```
 * const log = getLogger('mds');
 * log('hello');
 * ```
 *
 * @param {string} _name 日志命名空间后缀
 * @returns {Function} 日志记录函数（当前为空实现）
 */
function getLogger(_name) {
    return (_message, ..._rest) => { }; // 当前为空操作,暂用于寻找更合适的调试日志方案
}

module.exports = { getLogger };