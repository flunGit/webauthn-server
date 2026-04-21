import { BaseMetadataService, MetadataService } from './metadata.js';
import { BaseSettingsService, SettingsService } from './settings.js';

// ================================= metadataService.js =================================
/**
 * ```js
 * // 文件导出内容
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * ```
 * - 查看定义:@see {@link BaseMetadataService}、{@link MetadataService}
 */
declare module './metadata.js' {
    export * from './metadata.js';
}

// ================================= settings.js =================================
/**
 * ```js
 * // 文件导出内容
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * ```
 * - 查看定义:@see {@link BaseSettingsService}、{@link SettingsService}
 */
declare module './settings.js' {
    export * from './settings.js';
}

// ================================= 模块整体导出 =================================
/**
 *
 * 服务处理模块导出：
 * ```js
 * class BaseMetadataService{};                    // 下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * const MetadataService= new BaseMetadataService; // 用于协调与 FIDO 元数据交互的基础服务;
 * class BaseSettingsService{};                    // 用于管理各类 attestation 语句格式的根证书;
 * const SettingsService= new BaseSettingsService; // 用于为所有支持的证明声明格式指定可接受的根证书;
 * ```
 * - 查看定义:@see {@link BaseMetadataService}、{@link MetadataService}、{@link BaseSettingsService}、{@link SettingsService}
 */
declare module './index.js' { }
export * from './metadata.js';
export * from './settings.js';