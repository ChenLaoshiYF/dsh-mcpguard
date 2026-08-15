/**
 * dsh-mcpguard 扫描器：扫描文件/目录中的 skill 与 MCP 配置
 */
export interface ScanTarget {
    kind: 'dir' | 'file';
    name: string;
    filePath: string;
    content: string;
}
/** 默认扫描位置（常见 MCP 配置 + skill 目录） */
export declare function defaultPaths(): string[];
/** 扫描全部目标 */
export declare function scanAll(extraPaths?: string[]): ScanTarget[];
