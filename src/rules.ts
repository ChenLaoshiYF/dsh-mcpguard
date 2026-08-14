/**
 * dsh-mcpguard 检测规则引擎（TypeScript）
 * 与 mcpguard Python/Go 版同一套 8 类规则：UNI/B64/INJ/PTH/SHL/PWD/BH/HMG
 */

export interface Finding {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  source: string;
  excerpt: string;
}

type Check = (text: string) => string[];

export interface Rule {
  id: string;
  name: string;
  severity: Finding['severity'];
  description: string;
  check: Check;
}

// ---------------------------------------------------------------------------
// 规则数据
// ---------------------------------------------------------------------------

// Unicode 隐形字符的字符类见 checkHiddenUnicode（需要 u 标志处理 astral 范围）

// 同形字映射
const HOMOGLYPH_MAP: Record<string, string> = {
  // 西里尔
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j',
  '\u0432': 'b', '\u043D': 'h', '\u043A': 'k', '\u043C': 'm',
  '\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
  '\u0421': 'C', '\u0425': 'X', '\u0433': 'r', '\u0455': 's',
  // 拉丁扩展
  '\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E4': 'a',
  '\u00E9': 'e', '\u00E8': 'e', '\u00EA': 'e', '\u00EB': 'e',
  '\u00ED': 'i', '\u00EC': 'i', '\u00EE': 'i', '\u00EF': 'i',
  '\u00F3': 'o', '\u00F2': 'o', '\u00F4': 'o', '\u00F6': 'o',
  '\u00FC': 'u', '\u00F9': 'u', '\u00FB': 'u', '\u00E7': 'c',
};
// 数学字母数字符号（U+1D400–U+1D7FF）：粗体/斜体/等宽体字母，肉眼与 ASCII 完全一致
function addMathBlock(start: number, asciiStart: number): void {
  for (let i = 0; i < 26; i++) {
    HOMOGLYPH_MAP[String.fromCodePoint(start + i)] = String.fromCharCode(asciiStart + i);
  }
}
addMathBlock(0x1d400, 0x41); // 数学粗体大写 A-Z
addMathBlock(0x1d41a, 0x61); // 数学粗体小写 a-z
addMathBlock(0x1d4d0, 0x61); // 数学粗斜体小写 a-z
addMathBlock(0x1d608, 0x61); // 数学无衬线粗体小写 a-z
addMathBlock(0x1d622, 0x61); // 数学无衬线斜体小写 a-z

const HOMOGLYPH_TRIGGERS = [
  'ignore', 'previous', 'instructions', 'system prompt', 'override',
  '忽略', '指令', '规则', '忘记', '现在开始', '你扮演', '你是',
  'exfiltrat', 'send to', 'cc ', 'bcc ', 'new prime directive',
];

// 指令覆盖
const IGNORE_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)/i,
  /ignore\s+everything\s+(you|i|we)\s+/i,
  /忽略(之前|以上|先前|前面).{0,6}(指令|指示|规则|要求)/,
  /disregard\s+(all\s+)?((previous|prior|above)\s+)?(instruction|rule|prompt)s?/i,
  /忘记|忘掉.{0,6}(之前|以上|所有|一切).{0,6}(指令|提示|规则|要求|内容)/,
  /override\s+(the\s+)?system\s+prompt/i,
  /you\s+are\s+now\s+/i,
  /new\s+prime\s+directive/i,
  /从现在起.{0,12}(你是|扮演|忘记|不再)/,
  /你不再是.{0,12}(AI|助手|机器人|模型)/,
  /输出你(收到|的).{0,6}(系统|所有|全部).{0,4}(指令|提示|prompt)/,
  /(复述|泄露|透露|展示).{0,8}(系统提示|system prompt|系统指令)/,
];

// 危险路径
const DANGEROUS_PATHS = [
  /[/\\]\.ssh[/\\]/, /[/\\]\.aws[/\\]/, /[/\\]\.git[/\\]config/,
  /\.env\b/, /\bid_rsa\b/, /\bid_ed25519\b/, /credentials\b/, /\.pem\b/,
  /access[_-]?token/, /api[_-]?token/, /bearer[_-]?token/, /api[_-]?key\b/,
  /secret[_-]?key\b/, /client[_-]?secret\b/, /AWS[_A-Z]*SECRET/, /\/etc\/passwd\b/,
].map((r) => new RegExp(r.source, 'i'));

// 危险 shell
const DANGEROUS_SHELL = [
  /curl[^\n]{0,60}\|\s*(ba)?sh/i,
  /wget[^\n]{0,60}\|\s*(ba)?sh/i,
  /rm\s+-rf\s+[/~]?\.?(\/|\*|home|root)/i,
  /rm\s+-rf\s+~\/\\?/i,
  /nc\s+-[^\n]*\s+(-e|-c)\s+/i,
  /base64\s+[^\n]{0,40}-d/i,
  /\beval\s*\(\s*["'$]|\beval\s+\$\s*\(|\beval\s+`/i,
  /\$\s*\(\s*(curl|wget|iwr|irm)\s/i,
  /(?:^|[^`])`(curl|wget|bash|sh|python)\s[^`]*`/i,
  /iex\s*\(\s*(iwr|irm|invoke-webrequest|invoke-restmethod)/i,
  /invoke-expression\s*[\(\s]/i,
  /os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(/i,
  /\bexec\s*\(\s*["']/i,
  /(curl|wget|iwr|irm)[^\n]{0,80}(-o|out-file)[^\n]{0,60}(&&|;|and).{0,20}(bash|sh|\.\/|start)/i,
];

// base64 长串
const B64_RE = /[A-Za-z0-9+/]{40,}={0,2}/;

// 可疑行为
const SUSPICIOUS_BEHAVIOR = [
  /always\s+(bcc|cc|copy|send|forward)[^\n]{0,40}(to|@)/i,
  /without\s+(asking|telling|informing|notifying)[^\n]{0,40}(user|human)/i,
  /静默[^\n]{0,10}(发送|抄送|上传|转发|删除)/,
  /(静默|暗中|偷偷|背着你|不通知|无需确认)[^\n]{0,12}(发送|上传|执行|提交|转发|删除)/,
  /do\s+not\s+(tell|inform|mention)\b[^\n]{0,60}(user|human|author|client)/i,
  /(exfiltrat\w*\s+(data|content|files?|logs|info))|((data|content|files?|logs|info)\s+to\s+.{0,40}(exfiltrat))/i,
  /steal|phish/i,
];

// 密码赋值
const PASSWORD_ASSIGN_RE = /(password|passwd|pwd)\s*[=:]\s*[^\s,;"'\n]{1,60}/i;

// ---------------------------------------------------------------------------
// 规则实现
// ---------------------------------------------------------------------------

function checkHiddenUnicode(text: string): string[] {
  const hits: string[] = [];
  // 注意：\u{E0000} 需要 u 标志（astral 范围，6 位 hex）；其余用 4 位 \uXXXX
  const re = new RegExp(
    '[\u{E0000}-\u{E007F}\u200B\u200C\u200D\u2060\uFEFF\u00AD' +
      '\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069' +
      '\u061C\u034F]',
    'gu',
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && hits.length < 20) {
    const start = Math.max(0, m.index - 30);
    const end = Math.min(text.length, m.index + 1 + 30);
    hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
  }
  return hits;
}

function normalizeHomoglyphs(text: string): string {
  let out = '';
  for (const ch of text) {
    out += HOMOGLYPH_MAP[ch] ?? ch;
  }
  return out;
}

function checkHomoglyph(text: string): string[] {
  const hits: string[] = [];
  let hasSuspicious = false;
  for (const ch of text) {
    if (HOMOGLYPH_MAP[ch]) {
      hasSuspicious = true;
      break;
    }
  }
  if (!hasSuspicious) return hits;
  const lowered = normalizeHomoglyphs(text).toLowerCase();
  for (const trigger of HOMOGLYPH_TRIGGERS) {
    let idx = lowered.indexOf(trigger);
    while (idx !== -1 && hits.length < 20) {
      const start = Math.max(0, idx - 25);
      const end = Math.min(text.length, idx + trigger.length + 25);
      hits.push(`位置 ${idx}: …${text.slice(start, end)}…`);
      idx = lowered.indexOf(trigger, idx + 1);
    }
  }
  return hits;
}

function checkBase64(text: string): string[] {
  const hits: string[] = [];
  const re = new RegExp(B64_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && hits.length < 20) {
    const cand = m[0];
    if (/[a-z]{6,}/.test(cand)) continue;
    const before = text.slice(Math.max(0, m.index - 60), m.index);
    if (/data:\s*image\/|data:\s*[a-z]+\/[a-z+.-]+;base64,/i.test(before)) continue;
    hits.push(`位置 ${m.index}: ${cand.slice(0, 60)}…`);
  }
  return hits;
}

function checkInstructionOverride(text: string): string[] {
  const hits: string[] = [];
  for (const pat of IGNORE_PATTERNS) {
    const re = new RegExp(pat.source, pat.flags.includes('g') ? pat.flags : pat.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkDangerousPaths(text: string): string[] {
  const hits: string[] = [];
  for (const pat of DANGEROUS_PATHS) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 20);
      const end = Math.min(text.length, m.index + m[0].length + 20);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkPasswordAssignment(text: string): string[] {
  const hits: string[] = [];
  const re = new RegExp(PASSWORD_ASSIGN_RE.source, 'ig');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null && hits.length < 10) {
    const start = Math.max(0, m.index - 20);
    const end = Math.min(text.length, m.index + m[0].length + 20);
    hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
  }
  return hits;
}

function checkDangerousShell(text: string): string[] {
  const hits: string[] = [];
  for (const pat of DANGEROUS_SHELL) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

function checkSuspiciousBehavior(text: string): string[] {
  const hits: string[] = [];
  for (const pat of SUSPICIOUS_BEHAVIOR) {
    const re = new RegExp(pat.source, 'ig');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null && hits.length < 20) {
      const start = Math.max(0, m.index - 25);
      const end = Math.min(text.length, m.index + m[0].length + 25);
      hits.push(`位置 ${m.index}: …${text.slice(start, end)}…`);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// 引擎
// ---------------------------------------------------------------------------

export function buildDefaultEngine(): Rule[] {
  return [
    { id: 'UNI-001', name: 'Unicode 隐形字符', severity: 'high',
      description: '检测到不可见 Unicode 字符（私有区/零宽字符/双向文本控制符），可能用于隐藏恶意指令以规避人工审查。',
      check: checkHiddenUnicode },
    { id: 'B64-001', name: '可疑 base64 长串', severity: 'medium',
      description: '检测到疑似 base64 编码的长字符串，可能用于混淆指令内容，建议解码后人工确认。',
      check: checkBase64 },
    { id: 'INJ-001', name: '指令覆盖模式', severity: 'critical',
      description: '检测到试图覆盖/忽略原有指令的表述（如 ignore previous instructions），这是提示注入与工具投毒的核心特征。',
      check: checkInstructionOverride },
    { id: 'PTH-001', name: '敏感路径引用', severity: 'high',
      description: '检测到对敏感文件路径的引用（SSH 密钥、AWS 凭据、token 等），存在被利用进行凭据窃取的风险。',
      check: checkDangerousPaths },
    { id: 'SHL-001', name: '危险 shell 模式', severity: 'critical',
      description: '检测到管道执行远程脚本、危险删除、反向 shell 等模式。',
      check: checkDangerousShell },
    { id: 'PWD-001', name: '密码赋值形态', severity: 'info',
      description: '检测到 password= / password: 形式的赋值（可能是配置中的明文密码），仅提示注意，不作高危判定。',
      check: checkPasswordAssignment },
    { id: 'BH-001', name: '可疑工具行为描述', severity: 'high',
      description: '检测到静默操作、自动外发数据、绕过用户知情等异常行为描述，符合已知工具投毒攻击特征。',
      check: checkSuspiciousBehavior },
    { id: 'HMG-001', name: '同形字混淆 (homoglyph)', severity: 'high',
      description: '检测到使用视觉相近的 Unicode 字符冒充 ASCII 字母（如西里尔 а 冒充 a），用于绕过关键词过滤隐藏恶意指令。',
      check: checkHomoglyph },
  ];
}

/** 对一段文本跑全部规则，返回命中列表 */
export function scanText(text: string, source: string, rules: Rule[] = buildDefaultEngine()): Finding[] {
  if (!text) return [];
  const findings: Finding[] = [];
  for (const rule of rules) {
    try {
      const hits = rule.check(text);
      for (const hit of hits) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.name,
          detail: rule.description,
          source,
          excerpt: hit.slice(0, 200),
        });
      }
    } catch {
      // 单条规则异常不影响整体
    }
  }
  return findings;
}

/** 评分：100 - 扣分 */
export function severityScore(findings: Finding[]): number {
  if (!findings.length) return 100;
  const weights: Record<string, number> = { critical: 40, high: 20, medium: 8, low: 3, info: 1 };
  let score = 100;
  for (const f of findings) score -= weights[f.severity] ?? 1;
  return Math.max(0, score);
}

/** 脱敏：密钥模式替换为 *** */
export function redact(s: string): string {
  const patterns = [
    /sk-[A-Za-z0-9_-]{20,}/gi,
    /ghp_[A-Za-z0-9]{30,}/gi,
    /github_pat_[A-Za-z0-9_]{20,}/gi,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi,
    /AIza[A-Za-z0-9_-]{20,}/gi,
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/gi,
    /password\s*[=:]\s*["'][^"']{6,}["']|password\s*[=:]\s*[^\s,;"']{6,}/gi,
  ];
  let out = s;
  for (const p of patterns) out = out.replace(p, '***');
  return out;
}
