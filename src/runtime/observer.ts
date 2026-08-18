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

import { buildDefaultEngine, scanText } from '../rules.js';

export interface ObserverConfig {
  enabled: boolean;
  /** 跳过检测的工具名（内置工具白名单） */
  trustedTools: string[];
  /** 参数检测截断长度（字节） */
  maxArgBytes: number;
  /** 只记录 critical/high 及以上 */
  minSeverity: 'critical' | 'high' | 'medium';
}

export const DEFAULT_OBSERVER_CONFIG: ObserverConfig = {
  enabled: true,
  trustedTools: ['read', 'write', 'edit', 'bash', 'list', 'stat', 'grep'],
  maxArgBytes: 8192,
  minSeverity: 'high',
};

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
  snippet: string; // 截断的命中片段（≤120 字符）
}

export class ToolObserver {
  private engine = buildDefaultEngine();
  private observations: Observation[] = [];
  private maxObservations = 100;
  private log: (msg: string) => void;

  constructor(config: Partial<ObserverConfig> = {}, log: (msg: string) => void = () => {}) {
    this.cfg = { ...DEFAULT_OBSERVER_CONFIG, ...config };
    this.log = log;
  }

  private cfg: ObserverConfig;

  /** 检测一次工具调用。永远返回 undefined（放行），只记录观察结果。 */
  inspect(call: ToolCallInfo): void {
    // 防御：任何异常都不影响工具调用本身
    try {
      if (!this.cfg.enabled) return;
      if (this.cfg.trustedTools.includes(call.name)) return;

      // 只检测 name + description + args 的 JSON 序列化（截断）
      let payload = call.name || '';
      if (call.description) payload += ' ' + call.description;
      if (call.args !== undefined) {
        try {
          const argStr = JSON.stringify(call.args);
          if (argStr.length > this.cfg.maxArgBytes) {
            payload += ' ' + argStr.slice(0, this.cfg.maxArgBytes);
          } else {
            payload += ' ' + argStr;
          }
        } catch {
          // JSON 序列化失败（循环引用等），跳过参数检测
        }
      }

      const findings = scanText(payload, `runtime:${call.name}`, this.engine);
      if (findings.length === 0) return;

      // 按最低严重度过滤
      const severityOrder = { critical: 0, high: 1, medium: 2 };
      const min = severityOrder[this.cfg.minSeverity] ?? 1;
      const relevant = findings.filter((f) => (severityOrder[f.severity as keyof typeof severityOrder] ?? 9) <= min);
      if (relevant.length === 0) return;

      const top = relevant[0];
      const obs: Observation = {
        ts: new Date().toISOString(),
        tool: call.name,
        ruleIds: [...new Set(relevant.map((f) => f.ruleId))],
        severity: top.severity,
        snippet: top.excerpt.slice(0, 120),
      };
      this.observations.push(obs);
      if (this.observations.length > this.maxObservations) {
        this.observations.shift();
      }
      this.log(`[明棱·观察] ${call.name} 命中 ${obs.ruleIds.join(',')} (${obs.severity})`);
    } catch (e) {
      // 绝对不因观察器问题影响工具调用
      this.log(`[明棱·观察] 检测异常已忽略: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** 取观察摘要（不含完整参数，安全） */
  summary(): { total: number; bySeverity: Record<string, number>; recent: Observation[] } {
    const bySeverity: Record<string, number> = {};
    for (const o of this.observations) {
      bySeverity[o.severity] = (bySeverity[o.severity] || 0) + 1;
    }
    return {
      total: this.observations.length,
      bySeverity,
      recent: this.observations.slice(-10),
    };
  }

  reset(): void {
    this.observations = [];
  }
}

/** 生成 Cordis pre-execute 钩子函数（永远 next() 放行）。 */
export function makePreExecuteHook(observer: ToolObserver) {
  return (call: ToolCallInfo, next: () => unknown) => {
    observer.inspect(call);
    // 观察模式：永不拦截
    return next();
  };
}
