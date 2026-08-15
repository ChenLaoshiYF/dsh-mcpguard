# dsh-mcpguard 明棱

DeepSeek Harness (dsh) 安全扫描插件：扫描 skill 文件、MCP 配置与工具描述，检测**提示注入、同形字混淆、Unicode 隐形字符、危险 shell、凭据泄露**。

**DSH 生态首个安全类插件**（截至 2026-08 调研，163 个社区插件中安全方向空白）。

## 安装

```bash
dsh plugin --profile web add "github:ChenLaoshiYF/dsh-mcpguard"
```

或在管理面板 Settings → Plugins 中安装。重启 `dsh --profile web` 生效。

## 工具

| 工具 | 说明 |
|------|------|
| `mcpguard_scan` | 扫描本机默认位置（MCP 配置 + skill 目录） |
| `mcpguard_scan_path` | 扫描指定目录或文件 |

## 检测规则

与 mcpguard 主项目同一套引擎（Python / Go / TS 三实现规则一致）：

| ID | 规则 | 严重度 |
|----|------|--------|
| UNI-001 | Unicode 隐形字符（零宽/Bidi/私有区） | high |
| B64-001 | 可疑 base64 长串 | medium |
| INJ-001 | 指令覆盖（ignore previous instructions） | **critical** |
| INJ-002 | 角色扮演注入（"从现在开始你是…"） | **critical** |
| INJ-003 | 多语言指令覆盖（日語/韓語指令忽略） | high |
| PTH-001 | 敏感路径（~/.ssh、token、.env） | high |
| SHL-001 | 危险 shell（curl\|sh、eval、IEX） | **critical** |
| PWD-001 | 密码赋值形态 | info |
| BH-001 | 静默外发/工具行为异常 | high |
| HMG-001 | 同形字混淆（西里尔/数学体） | high |

报告自动脱敏：API key、GitHub token、SSH 私钥块、JWT → `***`。

## 兼容性

兼容 DeepSeek Harness `0.1.0-rc.5` 及后续版本（tools.register + execute + output API）。

兼容性问题请在 [GitHub Issues](https://github.com/ChenLaoshiYF/dsh-mcpguard/issues) 反馈，我们会快速修复（v0.1.2 已根据社区反馈修复 4 处 rc.5 不兼容）。

## 开发

```bash
npm install
npm run build     # 编译到 lib/（已随仓库分发，GitHub 直装可用）
node test/smoke.mjs   # 规则自测（19 项）
node test/robust.mjs  # 扫描器健壮性（超大文件/敏感目录/异常路径）
```

## 安装配置

插件通过 `cordis.patch.yml` 注册，无需额外配置：

```yaml
- insert:
    - id: mcpguard
      name: dsh-mcpguard
```

## 隐私

完全本地运行，零网络请求，零遥测。

## License

MIT
