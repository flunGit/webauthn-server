import { generateAuthenticationOptions } from './generateAuthenticationOptions.js';
import { verifyAuthenticationResponse } from './verifyAuthenticationResponse.js';

// ================================= generateAuthenticationOptions.js =================================
/**
 * ```js
 * // 文件导出内容
 * generateAuthenticationOptions(); // 生成用于身份验证器认证的参数
 * ```
 * - 查看定义:@see {@link generateAuthenticationOptions}
 */
module './generateAuthenticationOptions.js' {
    export * from './generateAuthenticationOptions.js';
}

// ================================= verifyAuthenticationResponse.js =================================
/**
 * ```js
 * // 文件导出内容
 * verifyAuthenticationResponse(); // 验证用户是否合法完成了认证流程
 * ```
 * - 查看定义:@see {@link verifyAuthenticationResponse}
 *
 */
module './verifyAuthenticationResponse.js' {
    export * from './verifyAuthenticationResponse.js';
}

// ================================= 模块整体导出 =================================
/**
 *
 * 本模块导出的主要函数包括：
 * ```js
 * generateAuthenticationOptions(); // 生成用于身份验证器认证的参数
 * verifyAuthenticationResponse();  // 验证用户是否合法完成了认证流程
 * ```
 * - 查看定义:@see {@link generateAuthenticationOptions}、{@link verifyAuthenticationResponse}
 */
module './index.js' { }
export * from './generateAuthenticationOptions.js';
export * from './verifyAuthenticationResponse.js';
