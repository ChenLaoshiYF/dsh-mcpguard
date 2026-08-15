/**
 * dsh-mcpguard 扫描器：扫描文件/目录中的 skill 与 MCP 配置
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
const SKILL_EXTS = new Set([
    '.md', '.txt', '.json', '.jsonl', '.yaml', '.yml',
    '.py', '.js', '.ts', '.toml', '.xml', '.html',
]);
const SKIP_DIRS = new Set([
    '.git', '.venv', 'venv', 'node_modules', '__pycache__',
    'dist', 'build', 'models', '.idea', '.vscode',
    '.ssh', '.aws', '.gnupg', // 敏感凭据目录（v0.1.3 补充）
]);
function walk(dir, targets, depth) {
    if (depth > 8)
        return;
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return;
    }
    for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
            if (!SKIP_DIRS.has(e.name))
                walk(full, targets, depth + 1);
        }
        else if (e.isFile()) {
            const ext = path.extname(e.name).toLowerCase();
            if (!SKILL_EXTS.has(ext))
                continue;
            try {
                const st = fs.statSync(full);
                if (st.size > 256 * 1024)
                    continue; // 256KB 上限
                const content = fs.readFileSync(full, 'utf-8');
                targets.push({ kind: 'file', name: e.name, filePath: full, content });
            }
            catch {
                // 竞态/权限错误跳过
            }
        }
    }
}
function scanFile(p, targets) {
    const ext = path.extname(p).toLowerCase();
    if (!SKILL_EXTS.has(ext))
        return;
    // 敏感目录检查：显式路径落在 .ssh/.aws/.git 等目录内则拒绝（防止凭据泄露）
    const normalized = p.replace(/\\/g, '/');
    if (/(^|\/)\.(ssh|aws|gnupg)(\/|$)/i.test(normalized))
        return;
    if (/(^|\/)\.git\/(config|credentials)(\/|$)/i.test(normalized))
        return;
    try {
        const st = fs.statSync(p);
        if (st.size > 256 * 1024)
            return;
        const content = fs.readFileSync(p, 'utf-8');
        targets.push({ kind: 'file', name: path.basename(p), filePath: p, content });
    }
    catch {
        // 跳过
    }
}
/** 默认扫描位置（常见 MCP 配置 + skill 目录） */
export function defaultPaths() {
    const home = process.env.USERPROFILE ?? process.env.HOME ?? '';
    if (!home)
        return [];
    const isWin = process.platform === 'win32';
    const paths = [];
    if (isWin) {
        paths.push(path.join(home, '.claude', 'claude_desktop_config.json'), path.join(home, '.cursor', 'mcp.json'), path.join(home, '.mcp.json'), path.join(home, '.claude', 'skills'), path.join(home, '.config', 'claude', 'skills'));
    }
    else {
        paths.push(path.join(home, '.claude', 'claude_desktop_config.json'), path.join(home, '.config', 'claude', 'claude_desktop_config.json'), path.join(home, '.mcp.json'), path.join(home, '.claude', 'skills'), path.join(home, '.config', 'claude', 'skills'));
    }
    return paths;
}
/** 扫描全部目标 */
export function scanAll(extraPaths = []) {
    const targets = [];
    const paths = extraPaths.length > 0 ? extraPaths : defaultPaths();
    for (const p of paths) {
        let st;
        try {
            st = fs.statSync(p);
        }
        catch {
            continue;
        }
        if (st.isDirectory())
            walk(p, targets, 0);
        else
            scanFile(p, targets);
    }
    return targets;
}
