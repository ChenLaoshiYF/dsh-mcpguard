/**
 * dsh-mcpguard - DeepSeek Harness 安全扫描插件
 *
 * 提供工具：
 * - mcpguard_scan: 扫描本机默认位置（MCP 配置 + skill 目录）
 * - mcpguard_scan_path: 扫描指定路径
 * - mcpguard_observe: 运行时观察摘要（v0.2 experimental，只记录不拦截）
 *
 * 基于 Cordis 插件系统（host 面），零运行时依赖。
 * 兼容 DeepSeek Harness 0.1.0-rc.5：tools.register + execute + output。
 */
import { ToolObserver } from './runtime/observer.js';
export declare const name = "mcpguard";
export declare const inject: string[];
/** 运行时观察器（v0.2，只记录不拦截） */
export declare const observer: ToolObserver;
export declare function apply(ctx: unknown): void;
declare const _default: {
    name: string;
    inject: string[];
    apply: typeof apply;
};
export default _default;
