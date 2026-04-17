
/**
 * 生成一个 `debug` 日志记录器实例,该实例基于 "flunWebauthn" 扩展,以保证命名的一致性;
 *
 * 有关如何在使用 flun-webauthn-server 时控制日志输出的信息,请参阅 https://www.npmjs.com/package/debug
 * - 查看定义:@see {@link getLogger}
 * - 示例：
 *
 * ```
 * const log = getLogger('mds');
 * log('hello'); // flunWebauthn:mds hello +0ms
 * ```
 */
const getLogger = _name => {
    // 目前这是一个空操作,我正在寻找更好的 debug 日志记录技术
    return (_message, ..._rest) => { };
};

export { getLogger };