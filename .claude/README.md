# 本仓库的 Claude Code 配置（猎面用）

Skill 和本项目绑定，**不是**本机 `~/.claude` 全局环境。

| 路径 | 用途 |
|------|------|
| `.claude/skills/` | 本仓库 skills（源文件，进 git） |
| `backend/data/workspaces/<pid>/.claude/skills/` | 每个猎面会话的 cwd 副本（运行时拷贝） |

从者会话：`cwd` 是猎工作区，`setting_sources=["project"]`，`skills=` 白名单只放这里的名字，`plugins=[]`。子智能体仍由 SDK `agents=` 注入，不写用户全局 agents。
