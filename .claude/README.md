# 本仓库猎面 skills

Skill 源文件和本项目绑定，**不是**本机 `~/.pi` 全局环境。

| 路径 | 用途 |
|------|------|
| `.claude/skills/` | 本仓库 skills（源文件，进 git） |
| `backend/data/workspaces/<pid>/.agents/skills/` | 每个猎面会话的 cwd 副本（运行时拷贝，Pi 从 cwd 发现） |

从者与角色工人的 `cwd` 是猎工作区。调度按御主方案并发拉起 Pi 进程，工人禁止再开子进程。
