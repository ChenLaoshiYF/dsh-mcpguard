/**
 * 明棱 mcpguard - 运行时观察模式（v0.2 experimental）
 *
 * 设计原则（安全第一）：
 * 1. 只观察、只记录 —— 本模块永不拦截任何工具调用，永远 next() 放行
 * 2. 全部 try-catch —— 任何异常都放行 + 记录，绝不因插件 bug 卡死 agent
 * 3. 不缓存敏感内容 —— 检测后立即释放，不保存工具参数
 * 4. 参数截断 —— 超长参数只检测前 8KB，避免性能问题
 *
 * 挂接点：tools/pre-execute（官方预留的水瀑布接缝）
 * 与 dsh-tool-policy 的关系：它是策略层（谁能调），我们是检测层（内容干不干净）。
 */
export interface ObserverConfig {
    enabled: boolean;
    /** 跳过检测的工具名（内置工具白名单） */
    trustedTools: string[];
    /** 参数检测截断长度（字节） */
    maxArgBytes: number;
    /** 只记录 critical/high 及以上 */
    minSeverity: 'critical' | 'high' | 'medium';
}
export declare const DEFAULT_OBSERVER_CONFIG: ObserverConfig;
interface ToolCallInfo {
    name: string;
    description?: string;
    args?: unknown;
}
/** 观察记录（只保留摘要，不保留完整参数） */
export interface Observation {
    ts: string;
    tool: string;
    ruleIds: string[];
    severity: string;
    snippet: string;
}
export declare class ToolObserver {
    private engine;
    private observations;
    private maxObservations;
    private log;
    constructor(config?: Partial<ObserverConfig>, log?: (msg: string) => void);
    private cfg;
    /** 检测一次工具调用。永远返回 undefined（放行），只记录观察结果。 */
    inspect(call: ToolCallInfo): void;
    /** 取观察摘要（不含完整参数，安全） */
    summary(): {
        total: number;
        bySeverity: Record<string, number>;
        recent: Observation[];
    };
    reset(): void;
}
/** 生成 Cordis pre-execute 钩子函数（永远 next() 放行）。 */
export declare function makePreExecuteHook(observer: ToolObserver): (call: ToolCallInfo, next: () => unknown) => unknown;
export {};
