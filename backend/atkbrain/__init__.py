"""StrikeAgent_AtkBrain-Flash — 红队 AI 多智能体自循环渗透平台。"""

try:
    from .app_version import local_version
    __version__ = local_version()
except Exception:
    __version__ = "0.5.0-beta.1"
