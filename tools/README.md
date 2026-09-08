# tools/

本目录只放 **Kali 默认没有** 的渗透辅助脚本。系统已装的 nmap / ffuf / nuclei 等不要复制到这里。

智能体必须用 **仓库绝对路径** 调用（工作区 cwd 不是仓库根），禁止 `which jsfinder` / `which bypass-403`。

| 工具 | 路径 | 用法 |
|------|------|------|
| JSFinder（Threezh1） | `tools/JSFinder/JSFinder.py` | `python3 <REPO>/tools/JSFinder/JSFinder.py -u <url> -ou js_urls.txt -os js_subs.txt` |
| bypass-403（iamj0ker） | `tools/bypass-403/bypass-403.sh` | `bash <REPO>/tools/bypass-403/bypass-403.sh http://<host> <path>` |

依赖：本机已有 `python3-requests`、`python3-bs4`、`curl`、`figlet`，不必再 pip。
