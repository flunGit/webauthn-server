import type { MetadataStatement } from '../metadata/index.js';
import type { Uint8Array_ } from '../types/index.js';
import type { AttestationFormat } from '../helpers/index.js';

// ================================= metadataService.js =================================
/**
 * 允许 MetadataService 处理未注册的 AAGUID（`"permissive"` 宽松模式）,或仅允许已注册的 AAGUID（`"strict"` 严格模式）;
 * 当前主要影响 `getStatement()` 的行为
 */
export type VerificationMode = 'permissive' | 'strict';

interface MetadataService {
    /**
     * 准备服务以处理远程 MDS 服务器和/或缓存本地元数据语句;
     *
     * **选项说明：**
     *
     * @param opts.mdsServers - FIDO 联盟元数据服务（Metadata Service，版本 3.0）兼容服务器的 URL 数组,默认为官方 FIDO MDS 服务器
     * @param opts.statements - 本地元数据语句数组。语句将被加载但不会刷新
     * @param opts.verificationMode - MetadataService 如何处理未注册的 AAGUID。默认为 `"strict"`（严格模式）,在注册响应验证过程
     * 中遇到未注册的 AAGUID 时会抛出错误。设置为 `"permissive"`（宽松模式）可允许使用未注册 AAGUID 的身份验证器进行注册;
     */
    initialize(opts?: {
        mdsServers?: string[];
        statements?: MetadataStatement[], verificationMode?: VerificationMode;
    }): Promise<void>;

    /**
     * 获取给定 AAGUID 的元数据语句。
     *
     * 该方法将根据初始 BLOB 下载中的 `nextUpdate` 属性协调更新缓存。
     */
    getStatement(aaguid: string | Uint8Array): Promise<MetadataStatement | undefined>;
}

/**
 * `MetadataService` 的一个实现，能够下载并解析 BLOB，并支持按需请求和缓存单个元数据语句。
 *
 * https://fidoalliance.org/metadata/
 */
export declare class BaseMetadataService implements MetadataService {
    private mdsCache;
    private statementCache;
    private state;
    private verificationMode;

    initialize(opts?: {
        mdsServers?: string[];
        statements?: MetadataStatement[], verificationMode?: VerificationMode;
    }): Promise<void>;

    getStatement(aaguid: string | Uint8Array_): Promise<MetadataStatement | undefined>;

    /**
     * 从 MDS 下载并处理最新的 BLOB
     */
    private downloadBlob;

    /**
     * 验证并处理 MDS 元数据 BLOB
     */
    private verifyBlob;

    /**
     * 辅助方法,暂停执行直到服务准备就绪
     */
    private pauseUntilReady;

    /**
     * 状态变更时报告服务状态
     */
    private setState;
}

/**
 * 用于协调与 FIDO 元数据服务交互的基础服务,包括 BLOB 下载和解析,以及按需请求和缓存单个元数据语句;
 *
 * https://fidoalliance.org/metadata/
 */
export declare const MetadataService: MetadataService;
export { };

// ================================= settingsService.js =================================
export type RootCertIdentifier = AttestationFormat | 'mds';

interface SettingsService {
    /**
     * 为使用根证书的证明格式设置潜在的根证书,在验证证书链时会逐一尝试这些根证书;
     *
     * 证书可以指定为原始的 `Buffer`,或者 PEM 格式的字符串,如果传入 `Buffer`,会将其转换为 PEM 格式;
     */
    setRootCertificates(opts: {
        identifier: RootCertIdentifier;
        certificates: (Uint8Array_ | string)[];
    }): void;

    /**
     * 获取指定证明格式下已注册的所有根证书
     */
    getRootCertificates(opts: { identifier: RootCertIdentifier }): string[];
}

/**
 * 一个基础服务，用于为所有支持的证明声明格式指定可接受的根证书;
 *
 * 此外,以下声明格式已内置了默认根证书：
 *
 * - `'android-key'`
 * - `'android-safetynet'`
 * - `'apple'`
 * - `'android-mds'`
 *
 * 如果需要,可以通过调用 `setRootCertificates()` 为这些格式标识符设置替代根证书来覆盖默认值;
 */
export declare const SettingsService: SettingsService;
export { };