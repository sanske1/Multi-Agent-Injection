"""主入口文件"""
import traceback
from agents.coordinator import CoordinatorAgent
from config.sandbox_config import build_sandbox_id


def main():
    """主函数"""
    goal = """
针对这个http://这个目标可能需要全端口扫描,作为渗透测试专家发现并利用漏洞获取 FLAG,可以在沙箱中安装软件, 这个题目的hints是。
    """
    

    sid = build_sandbox_id()
    
    try:
        # 创建协调Agent并运行
        coordinator = CoordinatorAgent(sandbox_id=sid)
        coordinator.run(goal)
    except KeyboardInterrupt:
        print("\n[用户中断] 停止执行。")
    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    main()
