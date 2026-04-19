import { convertAAGUIDToString, getLogger, fetch, verifyMDSBlob } from '../helpers/index.js';

/**
 * 一个 `CachedMDS` 实例,不会触发刷新关联条目 BLOB 的尝试
 * @type {{ url: string, no: number, nextUpdate: Date }}
 */
const NonRefreshingMDS = { url: '', no: 0, nextUpdate: new Date(0) },
    defaultURLMDS = 'https://mds.fidoalliance.org/',// v3
    /** @type {{ DISABLED: 0, REFRESHING: 1, READY: 2 }} */
    SERVICE_STATE = { DISABLED: 0, REFRESHING: 1, READY: 2 },
    log = getLogger('MetadataService');

/**
 * `MetadataService` 的一个实现,能够下载和解析 BLOB,并支持按需请求和缓存各个元数据声明;
 * - 查看定义:@see {@link BaseMetadataService}、
 * https://fidoalliance.org/metadata/
 */
class BaseMetadataService {
    /**
     * 初始化 BaseMetadataService 实例
     */
    constructor() {
        /**
         * MDS 服务器缓存映射，键为 URL，值为 CachedMDS 信息
         * @type {Record<string, { url: string, no: number, nextUpdate: Date }>}
         */
        Object.defineProperty(this, "mdsCache", {
            enumerable: true, configurable: true, writable: true, value: {}
        });
        /**
         * 元数据声明缓存映射，键为 AAGUID 字符串，值为包含条目和 URL 的对象
         * @type {Record<string, { entry: Object, url: string }>}
         */
        Object.defineProperty(this, "statementCache", {
            enumerable: true, configurable: true, writable: true, value: {}
        });
        /**
         * 服务当前状态
         * @type {0 | 1 | 2}
         */
        Object.defineProperty(this, "state", {
            enumerable: true, configurable: true, writable: true, value: SERVICE_STATE.DISABLED
        });
        /**
         * 验证模式：'strict' 或宽松模式（允许跳过未注册的 AAGUID）
         * @type {'strict' | 'permissive'}
         */
        Object.defineProperty(this, "verificationMode", {
            enumerable: true, configurable: true, writable: true, value: 'strict'
        });
    }

    /**
     * 初始化元数据服务
     * @param {Object} [opts] - 初始化选项
     * @param {string[]} [opts.mdsServers] - MDS 服务器 URL 列表，默认使用 FIDO 官方服务器
     * @param {Object[]} [opts.statements] - 预先提供的元数据声明列表
     * @param {'strict' | 'permissive'} [opts.verificationMode] - 验证模式
     * @returns {Promise<void>}
     */
    async initialize(opts = {}) {
        // 重置声明缓存
        this.statementCache = {};

        const { mdsServers = [defaultURLMDS], statements, verificationMode } = opts;
        this.setState(SERVICE_STATE.REFRESHING);

        /**
         * 如果提供了元数据声明,则首先将它们加载到缓存中;
         * 这些声明在检测到过期时不会被刷新;
         */
        if (statements?.length) {
            let statementsAdded = 0;
            statements.forEach((statement) => {
                // 仅缓存兼容 FIDO2 认证器的声明
                if (statement.aaguid) {
                    this.statementCache[statement.aaguid] = {
                        entry: { metadataStatement: statement, statusReports: [], timeOfLastStatusChange: '1970-01-01' },
                        url: NonRefreshingMDS.url,
                    };
                    statementsAdded += 1;
                }
            });
            log(`已缓存 ${statementsAdded} 条本地声明`);
        }

        /**
         * 如果提供了 MDS 服务器，则从中下载 BLOB、验证它们,并将其条目添加到缓存中;
         * 通过这种方式加载的 BLOB 在检测到其中的条目过期时会被刷新;
         */
        if (mdsServers?.length) {
            // 获取当前缓存数量,以便知道从 MDS 服务器新增了多少声明
            const currentCacheCount = Object.keys(this.statementCache).length;
            let numServers = mdsServers.length;

            for (const url of mdsServers) {
                try {
                    const cachedMDS = { url, no: 0, nextUpdate: new Date(0) }, blob = await this.downloadBlob(cachedMDS);
                    await this.verifyBlob(blob, cachedMDS);
                } catch (err) {
                    log(`无法从 ${url} 下载 BLOB：`, err), numServers -= 1; // 通知错误并继续
                }
            }

            // 计算差值，得到成功新增的声明总数
            const newCacheCount = Object.keys(this.statementCache).length, cacheDiff = newCacheCount - currentCacheCount;
            log(`已从 ${numServers} 个元数据服务器缓存 ${cacheDiff} 条声明`);
        }

        if (verificationMode) this.verificationMode = verificationMode;
        this.setState(SERVICE_STATE.READY);
    }

    /**
     * 获取指定 AAGUID 的元数据声明
     * @param {string | Uint8Array} aaguid - 认证器 GUID（字符串或二进制形式）
     * @returns {Promise<Object | undefined>} 元数据声明对象，若未找到且模式非 strict 则返回 undefined
     * @throws {Error} 当 strict 模式下未找到声明或检测到认证器泄露时抛出错误
     */
    async getStatement(aaguid) {
        if (this.state === SERVICE_STATE.DISABLED || !aaguid) return;
        if (aaguid instanceof Uint8Array) aaguid = convertAAGUIDToString(aaguid);

        await this.pauseUntilReady(); // 如果缓存刷新正在进行,则等待服务就绪
        // 尝试获取缓存的声明
        const cachedStatement = this.statementCache[aaguid];
        if (!cachedStatement) {
            // FIDO 一致性要求 RP 仅支持已注册的 AAGUID
            if (this.verificationMode === 'strict') throw new Error(`未找到 aaguid“${aaguid}”的元数据声明`);
            return; // 允许在不使用元数据的情况下继续注册验证
        }

        // 如果声明指向 MDS API，则检查 MDS 的 nextUpdate 是否需要刷新
        if (cachedStatement.url) {
            const mds = this.mdsCache[cachedStatement.url], now = new Date();
            if (now > mds.nextUpdate) {
                try {
                    this.setState(SERVICE_STATE.REFRESHING);
                    const blob = await this.downloadBlob(mds);
                    await this.verifyBlob(blob, mds);
                }
                finally { this.setState(SERVICE_STATE.READY) }
            }
        }

        const { entry } = cachedStatement;
        // 检查该 aaguid 的状态报告中是否存在“已泄露”状态
        for (const report of entry.statusReports) {
            const { status } = report;
            if (
                status === 'USER_VERIFICATION_BYPASS' || status === 'ATTESTATION_KEY_COMPROMISE' ||
                status === 'USER_KEY_REMOTE_COMPROMISE' || status === 'USER_KEY_PHYSICAL_COMPROMISE'
            ) throw new Error(`检测到 aaguid“${aaguid}”已泄露`);
        }

        return entry.metadataStatement;
    }

    /**
     * 从 MDS 下载并处理最新的 BLOB
     * @param {{ url: string, no: number, nextUpdate: Date }} cachedMDS - 缓存的 MDS 信息
     * @returns {Promise<string>} BLOB 原始文本内容
     */
    async downloadBlob(cachedMDS) {
        // 获取最新的“BLOB”（FIDO 的术语）
        const { url } = cachedMDS, resp = await fetch(url), data = await resp.text();
        return data;
    }

    /**
     * 验证并处理 MDS 元数据 BLOB
     * @param {string} blob - BLOB 原始文本内容
     * @param {{ url: string, no: number, nextUpdate: Date }} cachedMDS - 缓存的 MDS 信息
     * @returns {Promise<void>}
     */
    async verifyBlob(blob, cachedMDS) {
        const { url, no } = cachedMDS, { payload, parsedNextUpdate } = await verifyMDSBlob(blob);

        // 来自 FIDO MDS 文档：“如果文件的编号（no）小于或等于本地缓存的最后一个 BLOB 的编号,则忽略该文件;”
        if (payload.no <= no) throw new Error(`最新 BLOB 编号 ${payload.no} 不大于先前编号 ${no}`);

        // 缓存 FIDO2 设备的声明
        for (const entry of payload.entries) {
            // 仅缓存包含 `aaguid` 的条目
            if (entry.aaguid) this.statementCache[entry.aaguid] = { entry, url };
        }

        if (url) {
            // 记录服务器信息以便后续刷新
            this.mdsCache[url] = {
                ...cachedMDS,
                // 存储 payload 中的 `no`,确保获取序列中的下一个 BLOB
                no: payload.no, nextUpdate: parsedNextUpdate // 记录需要刷新此 BLOB 的时间
            };
        } else {
            /**
             * 该 BLOB 不会被刷新,但如果其 `nextUpdate` 早于当前时间,仍应发出警告
             */
            if (parsedNextUpdate < new Date())
                // TODO（2026年2月）：此处抛出一个具体的错误会更便于开发者处理,
                // 然后在更上层记录该消息,同时包含过期 BLOB 在数组中的索引;
                log(`⚠️ 此 MDS BLOB（序列号：${payload.no}）的数据自 ${parsedNextUpdate.toISOString()} 起已过期;
                请考虑使用更新的 MDS BLOB 重新初始化 MetadataService;`);
        }
    }

    /**
     * 辅助方法：暂停执行直到服务就绪
     * @returns {Promise<void>}
     */
    pauseUntilReady() {
        if (this.state === SERVICE_STATE.READY) return new Promise((resolve) => resolve());

        // 状态未就绪,设置轮询
        const readyPromise = new Promise((resolve, reject) => {
            const totalTimeoutMS = 70000, intervalMS = 100;
            let iterations = totalTimeoutMS / intervalMS;

            // 每隔 `intervalMS` 毫秒检查一次服务状态
            const intervalID = globalThis.setInterval(() => {
                if (iterations < 1) clearInterval(intervalID), reject(`状态在 ${totalTimeoutMS / 1000} 秒内未能变为 READY`);
                else if (this.state === SERVICE_STATE.READY) clearInterval(intervalID), resolve();
                iterations -= 1;
            }, intervalMS);
        });

        return readyPromise;
    }

    /**
     * 报告服务状态变更
     * @param {0 | 1 | 2} newState - 新状态值
     * @returns {void}
     */
    setState(newState) {
        this.state = newState;
        if (newState === SERVICE_STATE.DISABLED) log('MetadataService 已禁用');
        else if (newState === SERVICE_STATE.REFRESHING) log('MetadataService 正在刷新');
        else if (newState === SERVICE_STATE.READY) log('MetadataService 已就绪');
    }
}

/**
 * 用于协调与 FIDO 元数据交互的基础服务;
 * 包括 BLOB 下载与解析,以及按需请求和缓存各个元数据声明;
 * - 查看定义:@see {@link MetadataService}、
 * https://fidoalliance.org/metadata/
 * @type {BaseMetadataService}
 */
const MetadataService = new BaseMetadataService();

export { BaseMetadataService, MetadataService };