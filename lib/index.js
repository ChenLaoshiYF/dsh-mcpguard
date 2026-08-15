/**
 * dsh-mcpguard - DeepSeek Harness 安全扫描插件
 *
 * 提供两个工具：
 * - mcpguard_scan: 扫描本机默认位置（MCP 配置 + skill 目录）
 * - mcpguard_scan_path: 扫描指定路径
 *
 * 基于 Cordis 插件系统（host 面），零运行时依赖。
 * 兼容 DeepSeek Harness 0.1.0-rc.5：tools.register + execute + output。
 */
import { buildDefaultEngine, scanText, severityScore, redact } from './rules.js';
import { scanAll } from './scanner.js';
export const name = 'mcpguard';
export const inject = ['tools'];
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
}
export default { name, inject, apply };
