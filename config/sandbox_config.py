"""沙箱配置模块"""
import os


def build_sandbox_id() -> str | None:
    """
    构建沙箱 ID

    Returns:
        沙箱 ID，从环境变量 SANDBOX_ID 读取；未设置时返回 None
    """
    # TODO: 在此填写你的沙箱 ID（或通过环境变量 SANDBOX_ID 设置）
    sandbox_id = os.getenv("SANDBOX_ID","")
    return sandbox_id
