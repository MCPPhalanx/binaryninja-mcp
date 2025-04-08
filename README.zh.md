# Another™ MCP Server for Binary Ninja

<div align="center">

<strong>Binary Ninja 的 MCP（模型上下文协议）服务器</strong>

[![PyPI][pypi-badge]][pypi-url] [![Apache licensed][license-badge]][license-url]
[![Python Version][python-badge]][python-url]
[![GitHub Discussions][discussions-badge]][discussions-url]

</div>

[English](README.md) | 中文

[pypi-badge]: https://img.shields.io/pypi/v/binaryninja-mcp.svg
[pypi-url]: https://pypi.org/project/binaryninja-mcp/
[license-badge]: https://img.shields.io/pypi/l/binaryninja-mcp.svg
[license-url]: https://github.com/MCPPhalanx/binaryninja-mcp/blob/main/LICENSE
[python-badge]: https://img.shields.io/pypi/pyversions/binaryninja-mcp.svg
[python-url]: https://www.python.org/downloads/
[discussions-badge]:
  https://img.shields.io/github/discussions/MCPPhalanx/binaryninja-mcp
[discussions-url]: https://github.com/MCPPhalanx/binaryninja-mcp/discussions

# 演示

[tests/binary/beleaf.elf](tests/binary/beleaf.elf) 文件取自
[CSAW'19: Beleaf - Nightmare](https://guyinatuxedo.github.io/03-beginner_re/csaw19_beleaf/index.html)。
您也可以从上述链接找到完整的解题过程！

![demo](docs/demo-1.jpg)

## ... 为什么是“又一款”？

参见：
[与现有插件的关键区别（英文）](https://github.com/Vector35/community-plugins/issues/305)

# 安装

## 服务器设置

有两种方式运行 MCP 服务器：

1. **通过 Binary Ninja UI 插件**：

   - 通过 Binary Ninja 的插件管理器安装本插件
   - 首次加载二进制文件时， MCP 服务器将自动启动
     - 自动启动功能可通过 `Settings - MCP Server - Auto Start` 配置
     - 监听端口可通过 `Settings - MCP Server - Server port number` 配置
   - 所有打开的文件都将作为独立资源暴露，详见下
     方[可用资源](#提供给-mcp-客户端的可用资源)章节

2. **通过 Binary Ninja Headless （无界面）模式**：
   ```bash
   uvx binaryninja-mcp install-api  # 只需运行一次
   uvx binaryninja-mcp server <文件名> [文件名]...
   ```
   - `文件名` 可以是任意二进制文件或 BNDB 文件，与 UI 模式类似，所有打开的文件都
     将对 MCP 客户端可用
   - 服务器默认运行在 7000 端口
   - 使用 `--port` 参数指定其他端口

## MCP 客户端设置

1. **Claude Desktop（stdio 中继客户端）**：配置客户端通过 stdio 传输使用内置中继
   连接

   ```json
   {
     "mcpServers": {
       "binaryninja": {
         "command": "uvx",
         "args": ["binaryninja-mcp", "client"]
       }
     }
   }
   ```

2. **Cherry Studio**：
   - **SSE 模式（推荐）**：URL: `http://localhost:7000/sse`
   - **stdio 模式**：
     - 命令：`uvx`
     - 参数：
       ```
       binaryninja-mcp
       client
       ```

若需使用非默认端口，请在服务器和客户端命令中添加 `--port 12345` 参数。

# 提供给 MCP 客户端的可用工具

MCP 服务器提供以下工具：

- `rename_symbol`：重命名函数或数据变量
- `pseudo_c`：获取指定函数的伪 C 代码
- `pseudo_rust`：获取指定函数的伪 Rust 代码
- `high_level_il`：获取指定函数的高级中间语言（HLIL）
- `medium_level_il`：获取指定函数的中级中间语言（MLIL）
- `disassembly`：获取函数或指定范围的汇编代码
- `update_analysis_and_wait`：更新二进制分析并等待完成
- `get_triage_summary`：获取 Binary Ninja 概要视图的基本信息
- `get_imports`：获取导入符号字典
- `get_exports`：获取导出符号字典
- `get_segments`：获取内存段列表
- `get_sections`：获取二进制区段列表
- `get_strings`：获取二进制文件中发现的字符串列表
- `get_functions`：获取函数列表
- `get_data_variables`：获取数据变量列表

# 提供给 MCP 客户端的可用资源

MCP 资源可通过以下格式的 URI 访问：`binaryninja://{文件名}/{资源类型}`

服务器为每个二进制文件提供以下资源类型：

- `triage_summary`：来自 Binary Ninja 概要视图的基本信息
- `imports`：导入符号/函数字典
- `exports`：导出符号/函数字典
- `segments`：内存段列表
- `sections`：二进制区段列表
- `strings`：二进制文件中发现的字符串列表
- `functions`：函数列表
- `data_variables`：数据变量列表

# 开发

推荐使用 [uv](https://github.com/astral-sh/uv) 作为本项目的包管理工具。

## 克隆仓库到 Binary Ninja 插件目录

```powershell
git clone https://github.com/MCPPhalanx/binaryninja-mcp.git "${env:APPDATA}\Binary Ninja\plugins\MCPPhalanx_binaryninja_mcp"
```

## 配置 Python 环境

需要手动将 Binary Ninja API 安装到虚拟环境中。

```bash
uv venv
uv sync --dev
# 安装 binaryninja API
binaryninja-mcp install-api
# 检查 API 是否正确安装
uv run python -c 'import binaryninja as bn; print(f"ui_enabled={bn.core_ui_enabled()}")'
```

## 为开发配置 MCP 客户端

对于使用 stdio 传输的 MCP 客户端（如 Claude Desktop），将工作目录更改为开发文件
夹。

```json
{
  "mcpServers": {
    "binaryninja": {
      "command": "uv",
      "args": [
        "--directory",
        "C:/path/to/binaryninja-mcp",
        "run",
        "binaryninja-mcp",
        "client"
      ]
    }
  }
}
```

支持 SSE 的 MCP 客户端可使用：`http://localhost:7000/sse` 进行连接。

## 构建

```bash
uv build
```

## 测试

```bash
pytest
# 更新测试快照
pytest --snapshot-update
```

## 版本推进

PyPI 包版本自动从 Binary Ninja 的 `plugin.json`（使用 package.json 格式）生成，
保持 BN 插件与 PyPI 包版本一致。

```bash
# 升级 alpha 版本
uvx hatch version a

# 升级正式版本
uvx hatch version minor,rc
uvx hatch version release
```

参考：[Versioning - Hatch](https://hatch.pypa.io/1.12/version/)

## 发布

```bash
uv publish
```

# 许可协议

[Apache 2.0](LICENSE)
