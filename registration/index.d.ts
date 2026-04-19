import { supportedCOSEAlgorithmIdentifiers, generateRegistrationOptions } from './generateRegistrationOptions.js';
import { verifyRegistrationResponse } from './verifyRegistrationResponse.js';

// ================================= generateRegistrationOptions.js =================================
/**
 * ```js
 * // 文件导出内容
 * const supportedCOSEAlgorithmIdentifiers=[]; // 支持的加密算法标识符
 * generateRegistrationOptions(); // 生成用于身份验证器注册的参数,该参数可直接传递给 `navigator.credentials.create(...)`
 * ```
 * - 查看定义:@see {@link supportedCOSEAlgorithmIdentifiers}、{@link generateRegistrationOptions}
 */
module './generateRegistrationOptions.js' {
    export * from './generateRegistrationOptions.js';
}

// ================================= verifyRegistrationResponse.js =================================
/**
 * ```js
  * // 文件导出内容
 * verifyRegistrationResponse(); // 验证用户是否合法地完成了注册流程
 * ```
 * - 查看定义:@see {@link verifyRegistrationResponse}
 */
module './verifyRegistrationResponse.js' {
    export * from './verifyRegistrationResponse.js';
}

// ================================= 模块整体导出 =================================
/**
 *
 * 验证器注册处理模块函数：
 * ```js
 * generateRegistrationOptions(); // 生成用于身份验证器注册的参数
 * verifyRegistrationResponse();  // 验证用户是否合法地完成了注册流程
 * ```
 * - 查看定义:@see {@link generateRegistrationOptions}、{@link verifyRegistrationResponse}
 */
module './index.js' { }
export * from './generateRegistrationOptions.js';
export * from './verifyRegistrationResponse.js';