import {
    supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions, verifyRegistrationResponse
} from './registration.js';
/**
 *
 * 验证器注册处理模块函数：
 * ```js
 * generateRegistrationOptions();              // 生成用于身份验证器注册的参数
 * verifyRegistrationResponse();               // 验证用户是否合法地完成了注册流程
 * const supportedCOSEAlgorithmIdentifiers=[]; // 支持的加密算法标识符
 * ```
 * - 查看定义:@see {@link supportedCOSEAlgorithmIdentifiers}、{@link generateRegistrationOptions}、{@link verifyRegistrationResponse}
 */
declare module './index.js' {
    export * from './registration.js';
}