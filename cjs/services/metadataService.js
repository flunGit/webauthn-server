'use strict';

const { convertAAGUIDToString, getLogger, fetch, verifyMDSBlob } = require('../helpers/index.js'),

    /**
     * 一个不会触发对应条目 BLOB 刷新操作的 `CachedMDS` 实例
     */
    NonRefreshingMDS = { url: '', no: 0, nextUpdate: new Date(0) }, defaultURLMDS = 'https://mds.fidoalliance.org/',
    // 服务状态常量
    SERVICE_STATE = { DISABLED: 0, REFRESHING: 1, READY: 2 }, log = getLogger('MetadataService');

/**
 * `MetadataService` 的实现，可下载并解析 BLOB，并支持按需请求和缓存单个元数据声明。
 *
 * https://fidoalliance.org/metadata/
 */
class BaseMetadataService {
    mdsCache = {};                  // 缓存 MDS 服务器信息
    statementCache = {};            // 缓存元数据声明条目
    state = SERVICE_STATE.DISABLED; // 当前服务状态
    verificationMode = 'strict';    // 验证模式：strict 或宽松

    /**
     * 初始化元数据服务
     * @param {Object} opts 配置选项
     * @param {string[]} [opts.mdsServers] MDS 服务器 URL 列表
     * @param {Array} [opts.statements] 本地提供的元数据声明数组
     * @param {string} [opts.verificationMode] 验证模式
     */
    async initialize(opts = {}) {
        // 重置声明缓存
        this.statementCache = {};
        const { mdsServers = [defaultURLMDS], statements, verificationMode } = opts;
        this.setState(SERVICE_STATE.REFRESHING);

        // 如果提供了本地元数据声明，优先载入缓存（这些声明不会因过期而自动刷新）
        if (statements?.length) {
            let statementsAdded = 0;
            statements.forEach((statement) => {
                // 仅缓存支持 FIDO2 的认证器声明
                if (statement.aaguid) {
                    this.statementCache[statement.aaguid] = {
                        entry: { metadataStatement: statement, statusReports: [], timeOfLastStatusChange: '1970-01-01' },
                        url: NonRefreshingMDS.url,
                    };
                    statementsAdded += 1;
                }
            });
            log(`已缓存 ${statementsAdded} 条本地元数据声明`);
        }

        // 如果提供了 MDS 服务器,则下载、验证 BLOB 并将其条目加入缓存;
        // 通过这种方式加载的 BLOB 会在检测到过期条目时被刷新;
        if (mdsServers?.length) {
            const currentCacheCount = Object.keys(this.statementCache).length;
            let numServers = mdsServers.length;
            for (const url of mdsServers) {
                try {
                    const cachedMDS = { url, no: 0, nextUpdate: new Date(0), }, blob = await this.downloadBlob(cachedMDS);
                    await this.verifyBlob(blob, cachedMDS);
                } catch (err) {
                    log(`无法从 ${url} 下载 BLOB：`, err), numServers -= 1;
                }
            }
            const newCacheCount = Object.keys(this.statementCache).length, cacheDiff = newCacheCount - currentCacheCount;
            log(`从 ${numServers} 个元数据服务器缓存了 ${cacheDiff} 条声明`);
        }

        if (verificationMode) this.verificationMode = verificationMode;
        this.setState(SERVICE_STATE.READY);
    }

    /**
     * 获取指定 AAGUID 的元数据声明
     * @param {string|Uint8Array} aaguid 认证器 AAGUID
     * @returns {Promise<Object|undefined>} 元数据声明对象
     */
    async getStatement(aaguid) {
        if (this.state === SERVICE_STATE.DISABLED) return;
        if (!aaguid) return;
        if (aaguid instanceof Uint8Array) aaguid = convertAAGUIDToString(aaguid);

        // 如果缓存正在刷新,等待服务就绪
        await this.pauseUntilReady();
        const cachedStatement = this.statementCache[aaguid];
        if (!cachedStatement) {
            // FIDO 规范要求依赖方仅支持已注册的 AAGUID
            if (this.verificationMode === 'strict') throw new Error(`未找到 AAGUID "${aaguid}" 对应的元数据声明`);
            return; // 允许在不使用元数据的情况下继续进行注册验证
        }

        // 如果声明来自某个 MDS API，检查对应 MDS 的 nextUpdate 以决定是否需要刷新
        if (cachedStatement.url) {
            const mds = this.mdsCache[cachedStatement.url], now = new Date();
            if (now > mds.nextUpdate) {
                try {
                    this.setState(SERVICE_STATE.REFRESHING);
                    const blob = await this.downloadBlob(mds);
                    await this.verifyBlob(blob, mds);
                }
                finally { this.setState(SERVICE_STATE.READY); }
            }
        }

        const { entry } = cachedStatement;
        // 检查是否存在“已失陷”状态的状态报告
        for (const report of entry.statusReports) {
            const { status } = report;
            if (
                status === 'USER_VERIFICATION_BYPASS' || status === 'ATTESTATION_KEY_COMPROMISE' ||
                status === 'USER_KEY_REMOTE_COMPROMISE' || status === 'USER_KEY_PHYSICAL_COMPROMISE'
            ) throw new Error(`检测到 AAGUID "${aaguid}" 对应的认证器已失陷`);
        }

        return entry.metadataStatement;
    }

    /**
     * 从 MDS 下载最新的 BLOB
     * @param {Object} cachedMDS 缓存的 MDS 信息
     * @returns {Promise<string>} BLOB 文本内容
     */
    async downloadBlob(cachedMDS) {
        const { url } = cachedMDS, resp = await fetch(url), data = await resp.text();
        return data;
    }

    /**
     * 验证并处理 MDS 元数据 BLOB
     * @param {string} blob BLOB 文本
     * @param {Object} cachedMDS 缓存的 MDS 信息
     */
    async verifyBlob(blob, cachedMDS) {
        const { url, no } = cachedMDS, { payload, parsedNextUpdate } = await verifyMDSBlob(blob);

        // 根据 FIDO MDS 文档：“如果文件编号（no）小于或等于本地缓存的最新 BLOB 编号，则忽略该文件”
        if (payload.no <= no) throw new Error(`最新 BLOB 编号 ${payload.no} 不大于之前的编号 ${no}`);

        // 缓存 FIDO2 设备条目
        for (const entry of payload.entries) {
            if (entry.aaguid) this.statementCache[entry.aaguid] = { entry, url };
        }

        // 记录服务器信息以便后续刷新
        if (url) this.mdsCache[url] = { ...cachedMDS, no: payload.no, nextUpdate: parsedNextUpdate };
        else {
            // 此 BLOB 不会自动刷新，但如果其 nextUpdate 已过期则发出警告
            if (parsedNextUpdate < new Date())
                log(
                    `⚠️ 此 MDS BLOB（序列号：${payload.no}）中的数据已于 ${parsedNextUpdate.toISOString()} 过期;
                    请考虑使用更新的 MDS BLOB 重新初始化 MetadataService;`
                );
        }
    }

    /**
     * 挂起当前操作，直到服务状态变为 READY
     * @returns {Promise<void>}
     */
    pauseUntilReady() {
        if (this.state === SERVICE_STATE.READY) return Promise.resolve();

        return new Promise((resolve, reject) => {
            const totalTimeoutMS = 70000, intervalMS = 100;
            let iterations = totalTimeoutMS / intervalMS;

            const intervalID = globalThis.setInterval(() => {
                if (iterations < 1)
                    clearInterval(intervalID), reject(new Error(`服务状态在 ${totalTimeoutMS / 1000} 秒内未变为就绪`));
                else if (this.state === SERVICE_STATE.READY) clearInterval(intervalID), resolve();
                iterations -= 1;
            }, intervalMS);
        });
    }

    /**
     * 更新服务状态并记录日志
     * @param {number} newState 新状态值
     */
    setState(newState) {
        this.state = newState;
        if (newState === SERVICE_STATE.DISABLED) log('MetadataService 状态：已禁用');
        else if (newState === SERVICE_STATE.REFRESHING) log('MetadataService 状态：刷新中');
        else if (newState === SERVICE_STATE.READY) log('MetadataService 状态：就绪');
    }
}

/**
 * 用于协调与 FIDO 元数据服务交互的基础服务实例。包括 BLOB 下载与解析，以及按需请求和缓存单个元数据声明。
 *
 * https://fidoalliance.org/metadata/
 */
const MetadataService = new BaseMetadataService();

module.exports = { BaseMetadataService, MetadataService };