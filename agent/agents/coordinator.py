"""
协调Agent模块 - 主协调者 CoordinatorAgent
职责：全局流程总调度，串联规划Agent、执行Agent，统一管理会话状态、漏洞线索、任务队列，
控制循环、会话过期检测、动态重规划、Flag终止判断、执行记录归档。
不直接调用curl/沙箱工具，仅做流程调度与数据流转。
"""
from typing import List, Tuple, Dict, Any
from langchain_openai import ChatOpenAI
# 导入另外两个子智能体：规划、执行
from agents.planner import PlannerAgent
from agents.executor import ExecutorAgent
# 通用工具函数：状态更新、Cookie过期校验、文本格式化、长文本截断
from utils.state_manager import update_state, check_cookie_expired, format_state_summary, truncate
# 线索提取工具：解析漏洞/发现/Flag、判断是否拿到Flag
from utils.finding_extractor import extract_findings, has_flag
# LLM统一构造函数，生成大模型实例
from config.llm_config import build_llm


class CoordinatorAgent:
    """
    主协调Agent，整个系统的调度中枢
    1. 初始化LLM、规划器、执行器
    2. 维护全局运行状态(cookie/user_id等会话信息)
    3. 维护任务队列、已完成任务、漏洞线索、执行历史
    4. 开启主循环，循环取出任务交给Executor执行
    5. 执行完毕自动更新会话、提取新漏洞线索
    6. 满足条件自动重新生成任务清单（动态规划）
    7. 命中Flag/登录失败超限/达到最大循环次数自动终止流程
    """

    def __init__(self, sandbox_id: str | None = None):
        """
        协调器初始化方法
        :param sandbox_id: 可选，Docker沙箱唯一标识，透传给执行Agent用于隔离命令执行环境
        """
        # 1. 构建全局共用LLM大模型实例
        self.llm = build_llm()
        # 2. 实例化规划Agent，用于生成/更新待办任务清单
        self.planner = PlannerAgent(self.llm)
        # 3. 实例化执行Agent，传入LLM与沙箱ID，负责调用curl/沙箱工具执行真实操作
        self.executor = ExecutorAgent(self.llm, sandbox_id)

        # ---------------------- 全局会话状态存储 ----------------------
        # 存储登录凭证、目标基础地址，贯穿全流程
        self.state = {
            "cookie": None,       # 网站登录Cookie，HTTP请求鉴权核心
            "user_id": None,       # 当前登录用户ID
            "base_url": None,      # 目标站点根地址
        }

        # ---------------------- 流程记录容器 ----------------------
        self.findings: List[str] = []          # 所有探测到的漏洞、新路径、敏感信息、Flag集合
        self.step_history: List[Dict[str, Any]] = []  # 每一步完整执行日志，用于复盘重规划
        self.completed_todos: List[str] = []   # 已经执行完成的任务列表（用于去重）
        self.todos: List[str] = []             # 待执行任务队列（FIFO先进先出）

        # ---------------------- 循环控制、熔断标记变量 ----------------------
        self.session_established = False       # 是否曾经成功登录获取过Cookie（区分首次未登录和中途掉线）
        self.consecutive_login_attempts = 0     # 连续登录失败计数器，超过3次强制终止
        self.max_iter = 100                    # 全局最大循环次数，兜底防止死循环
        self.has_new_findings = False          # 本轮执行是否产生新线索，作为重规划触发条件

    def run(self, goal: str) -> Tuple[List[str], str]:
        """
        程序主入口，启动完整渗透测试循环
        :param goal: 用户传入的总体渗透目标（如获取网站Flag、挖掘漏洞）
        :return: 元组 (已完成任务列表, 最终汇总报告字符串)
        """
        # 第一步：调用规划Agent，根据总目标生成初始待办任务
        self.todos = self.planner.generate_todos(goal)
        print(f"[PLAN] 初始待办清单 ({len(self.todos)}项):")
        for idx, t in enumerate(self.todos, 1):
            print(f"  {idx}. {t}")

        # 开启主循环，最多执行max_iter轮
        for i in range(1, self.max_iter + 1):
            # 待办队列为空，无任务可执行，退出循环
            if not self.todos:
                print("\n[完成] 所有待办已执行完毕。")
                break

            # 取出队列头部第一个任务，移入已完成列表
            todo = self.todos.pop(0)
            self.completed_todos.append(todo)

            # 打印分割线，输出当前执行步骤与会话简略信息
            print(f"\n{'='*60}")
            print(f"[步骤 {i}] 执行: {todo}")
            print(
                f"[当前状态] Cookie: {truncate(str(self.state.get('cookie', 'None')), 30)}, "
                f"UserID: {self.state.get('user_id', 'None')}"
            )
            print('='*60)

            # 1. 将当前会话、历史线索压缩为文本摘要，传给执行Agent
            state_summary = format_state_summary(self.state, self.findings)
            # 2. 调用执行Agent执行当前单条任务，拿到工具执行完整输出文本
            result = self.executor.execute(goal, todo, state_summary)
            output = result["output"]

            # 记录本轮执行前线索总量，用于判断本次是否挖掘出新内容
            findings_before = len(self.findings)

            # 从工具输出里更新全局cookie/user_id等会话状态
            self._update_state_from_output(output, todo)
            # 从输出文本提取漏洞、新路径等发现，存入findings
            self._extract_and_update_findings(output)
            # 对比前后线索数量，标记本轮是否存在新发现
            self.has_new_findings = len(self.findings) > findings_before

            # 归档当前步骤完整日志，存入历史记录（供后续重规划读取上下文）
            self.step_history.append({
                "step": i,
                "todo": todo,
                "output": truncate(output),
                "state_before": self.state.copy(),
                "findings_before": findings_before
            })

            # 校验是否成功获取Flag，命中直接终止全部流程
            if has_flag(self.findings):
                print("\n" + "="*60)
                print("[SUCCESS] 🎉 恭喜！已获取 Flag，任务完成！")
                print("="*60)
                break

            # 满足条件则重新调用规划器，生成新的待办队列
            self._replan_if_needed(goal)

            # 连续登录失败超过3次，判定账号/路径异常，熔断终止
            if self.consecutive_login_attempts > 3:
                print("[ERROR] 连续3次登录失败，可能凭据错误，终止执行。")
                break

        # 循环结束，生成最终执行报告并返回
        return self._generate_final_report()

    def _update_state_from_output(self, output: str, todo: str):
        """
        私有方法：从执行器输出更新全局会话状态，同时检测Cookie会话失效
        :param output: Executor工具执行返回的完整文本
        :param todo: 当前正在执行的任务文本，用于判断是否是登录类任务
        """
        # 保存更新前的Cookie，用于对比变化
        old_cookie = self.state.get("cookie")
        # 调用工具函数，正则提取[STATE_UPDATE]标记或Set-Cookie，覆盖state字典
        self.state = update_state(output, self.state)
        new_cookie = self.state.get("cookie")

        # 判断当前任务是否属于登录任务（中英文关键词匹配）
        is_login_task = "登录" in todo.lower() or "login" in todo.lower()

        # 检测会话失效：跳转首页且Cookie无更新，清除凭证并累加失败次数
        if check_cookie_expired(output, old_cookie, new_cookie, is_login_task):
            print("[STATE] ⚠️ 检测到会话失效（认证失败重定向），清除 Cookie。")
            self.state["cookie"] = None
            self.consecutive_login_attempts += 1
        # 拿到全新有效Cookie，重置登录失败计数器，标记会话建立成功
        elif new_cookie and new_cookie != old_cookie:
            self.consecutive_login_attempts = 0
            self.session_established = True
            print(f"[STATE] ✓ 新会话已建立")

    def _extract_and_update_findings(self, output: str):
        """
        私有方法：从执行输出提取新漏洞/线索，去重后存入全局findings列表
        :param output: Executor返回的工具执行文本
        """
        # 调用提取工具，过滤重复内容，只返回本次新增发现
        new_finds = extract_findings(output, self.findings)
        if new_finds:
            print(f"\n[FINDING] 新发现 ({len(new_finds)}条):")
            for nf in new_finds:
                print(f"  - {nf}")
            # 将新线索追加到全局存储
            self.findings.extend(new_finds)

    def _replan_if_needed(self, goal: str):
        """
        私有方法：判断是否需要动态重规划任务，满足任一条件则重新生成todo队列
        触发重规划3种场景：会话丢失需要登录 / 本轮产生新漏洞线索 / 待办任务全部跑完
        :param goal: 原始总渗透目标
        """
        need_replan = False
        replan_reason = []

        # 场景1：曾经登录过，现在Cookie为空，且队列无登录任务，需要重新登录
        cookie_missing = self.state.get("cookie") is None or self.state.get("cookie") == "None"
        if cookie_missing and self.session_established:
            if not any("登录" in t.lower() or "login" in t.lower() for t in self.todos):
                replan_reason.append("会话丢失，需要登录")
                need_replan = True

        # 场景2：本轮探测出新线索，需要基于新情报拓展测试步骤
        if self.has_new_findings:
            replan_reason.append("发现新线索")
            need_replan = True
            self.has_new_findings = False  # 重置新线索标记，避免重复重规划

        # 场景3：原有待办全部执行完毕，无后续任务，需要LLM生成下一步动作
        if not self.todos:
            replan_reason.append("待办队列为空")
            need_replan = True

        # 满足任意重规划条件，执行重新生成任务
        if need_replan:
            print(f"\n[PLAN] 触发重新规划: {', '.join(replan_reason)}")
            # 整合当前状态、历史线索、最近执行步骤作为规划上下文
            planner_context = self.planner.format_planning_context(
                self.state,
                self.findings,
                self.step_history
            )
            # 传入上下文，让LLM生成适配当前进度的新任务清单
            new_todos = self.planner.generate_todos(goal, context=planner_context)

            # 简单去重：过滤最近5步已完成的相似任务，避免重复执行
            unique_todos = []
            for nt in new_todos:
                if not any(nt.lower() in ct.lower() for ct in self.completed_todos[-5:]):
                    unique_todos.append(nt)

            # 覆盖原有待办队列，更新为新生成任务
            self.todos = unique_todos
            print(f"[PLAN] 更新后的待办 ({len(self.todos)}项):")
            for idx, t in enumerate(self.todos, 1):
                print(f"  {idx}. {t}")

    def _generate_final_report(self) -> Tuple[List[str], str]:
        """
        私有方法：循环结束后，统计并打印完整执行总结，封装返回结果
        :return: (已完成任务列表, 汇总文本)
        """
        print("\n" + "="*60)
        print("执行总结")
        print("="*60)
        print(f"完成步骤数: {len(self.completed_todos)}")
        print(f"最终状态: {self.state}")
        print(f"发现总数: {len(self.findings)}")

        # 打印全部收集到的漏洞、线索、Flag
        if self.findings:
            print("\n所有发现:")
            for idx, f in enumerate(self.findings, 1):
                print(f"  {idx}. {f}")

        # 拼接精简汇总字符串，作为函数返回第二参数
        summary = f"Final State: {self.state}\nFindings: {self.findings}"
        return self.completed_todos, summary