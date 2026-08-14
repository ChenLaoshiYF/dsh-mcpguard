/**
 * dsh-mcpguard - DeepSeek Harness 安全扫描插件
 *
 * 提供两个工具：
 * - mcpguard_scan: 扫描本机默认位置（MCP 配置 + skill 目录）
 * - mcpguard_scan_path: 扫描指定路径
 *
 * 基于 Cordis 插件系统（host 面），零运行时依赖。
 */

import { buildDefaultEngine, scanText, severityScore, redact } from './rules.js';
import { scanAll } from './scanner.js';

export const name = 'mcpguard';
export const inject = ['tools', 'logger'];
export const Config = {
  sensitivity: { type: 'string', default: 'medium', description: '灵敏度：low/medium/high' },
  scanOnStartup: { type: 'boolean', default: false, description: '启动时自动扫描一次' },
};

interface ScanResult {
  targets: number;
  findings: number;
  critical: number;
  score: number;
  report: Array<{
    name: string;
    path: string;
    score: number;
    findings: Array<{ ruleId: string; severity: string; title: string; excerpt: string }>;
  }>;
}

function runScan(paths: string[]): ScanResult {
  const rules = buildDefaultEngine();
  const targets = scanAll(paths);
  let total = 0;
  let critical = 0;
  const report: ScanResult['report'] = [];

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

export function apply(ctx: unknown, config: { sensitivity?: string; scanOnStartup?: boolean }): void {
  const tools = (ctx as { tools: { add: (t: Record<string, unknown>) => void } }).tools;
  const logger = (ctx as { logger?: { info?: (msg: string) => void } }).logger;

  tools.add({
    name: 'mcpguard_scan',
    description:
      '明棱 mcpguard：扫描本机 MCP 配置与 skill 目录，检测提示注入、同形字、Unicode 隐形字符、危险 shell、凭据泄露。返回安全报告 JSON。',
    parameters: {
      type: 'object',
      properties: {
        sensitivity: { type: 'string', enum: ['low', 'medium', 'high'], description: '灵敏度（可选，默认取插件配置）' },
      },
    },
    call: async () => JSON.stringify(runScan([]), null, 2),
  });

  tools.add({
    name: 'mcpguard_scan_path',
    description:
      '明棱 mcpguard：扫描指定目录或文件，检测提示注入、同形字、Unicode 隐形字符、危险 shell、凭据泄露。返回安全报告 JSON。',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: '要扫描的目录或文件路径' },
      },
      required: ['path'],
    },
    call: async (args: { path: string }) => JSON.stringify(runScan([args.path]), null, 2),
  });

  if (config.scanOnStartup) {
    const r = runScan([]);
    logger?.info?.(`[mcpguard] 启动扫描完成: ${r.targets} 目标, ${r.findings} 发现, ${r.critical} critical`);
  }
}

export default { name, inject, Config, apply };
