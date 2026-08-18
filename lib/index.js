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
import { buildDefaultEngine, scanText, severityScore, redact } from './rules.js';
import { scanAll } from './scanner.js';
import { ToolObserver, makePreExecuteHook } from './runtime/observer.js';
export const name = 'mcpguard';
export const inject = ['tools'];
/** 运行时观察器（v0.2，只记录不拦截） */
export const observer = new ToolObserver();
function runScan(paths) {
    const rules = buildDefaultEngine();
    const targets = scanAll(paths);
    let total = 0;
    let critical = 0;
    const report = [];
    for (const t of targets) {
        const findings = scanText(t.content, `${t.name} (${t.filePath})`, rules);
        const visible = findings.map((f) => ({
            ruleId: f.ruleId,
            severity: f.severity,
            title: f.title,
            excerpt: redact(f.excerpt),
        }));
        total += findings.length;
        critical += findings.filter((f) => f.severity === 'critical').length;
        report.push({
            name: t.name,
            path: redact(t.filePath),
            score: severityScore(findings),
            findings: visible,
        });
    }
    return { targets: targets.length, findings: total, critical, score: 100 - critical * 40, report };
}
export function apply(ctx) {
    const tools = ctx.tools;
    // rc.5 要求的 output 定义（含 render 渲染）
    const output = {
        schema: { type: 'object' },
        render: (_args, value) => [
            { type: 'text', text: JSON.stringify(value, null, 2) },
        ],
    };
    tools.register({
        name: 'mcpguard_scan',
        description: '明棱 mcpguard：扫描本机 MCP 配置与 skill 目录，检测提示注入、同形字、Unicode 隐形字符、危险 shell、凭据泄露。返回安全报告 JSON。',
        parameters: {
            type: 'object',
            properties: {},
        },
        output,
        async execute() {
            return runScan([]);
        },
    });
    tools.register({
        name: 'mcpguard_scan_path',
        description: '明棱 mcpguard：扫描指定目录或文件，检测提示注入、同形字、Unicode 隐形字符、危险 shell、凭据泄露。返回安全报告 JSON。',
        parameters: {
            type: 'object',
            properties: {
                path: { type: 'string', description: '要扫描的目录或文件路径' },
            },
            required: ['path'],
        },
        output,
        async execute(args) {
            return runScan([args.path]);
        },
    });
    // ---- v0.2 运行时观察模式（experimental，只记录不拦截） ----
    tools.register({
        name: 'mcpguard_observe',
        description: '明棱 mcpguard：运行时观察摘要（v0.2 experimental）。查看工具调用投毒检测记录，只观察不拦截。返回统计 + 最近 10 条记录。',
        parameters: {
            type: 'object',
            properties: {},
        },
        output,
        async execute() {
            return observer.summary();
        },
    });
    // 挂接 tools/pre-execute（观察模式：永远 next() 放行，只记录）
    // 防御：挂接失败不影响插件其他功能
    try {
        const toolsCtx = ctx;
        if (typeof toolsCtx?.tools?.preExecute === 'function') {
            toolsCtx.tools.preExecute(makePreExecuteHook(observer));
        }
        else if (typeof toolsCtx.on === 'function') {
            // 备用：Cordis 事件方式挂接
            toolsCtx.on('tools/pre-execute', makePreExecuteHook(observer));
        }
        else {
            console.warn('[明棱] tools/pre-execute 接缝不可用，观察模式未挂接（不影响扫描功能）');
        }
    }
    catch (e) {
        console.warn('[明棱] 观察模式挂接失败（不影响扫描功能）:', e instanceof Error ? e.message : String(e));
    }
}
export default { name, inject, apply };
