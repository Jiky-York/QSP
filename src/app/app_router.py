"""
src/app/app_router.py
[Phase 15] QSP 应用层安全路由器 (C10 路由隔离重构版)
负责解析解密后的业务明文，并将其分发给对应的业务模块。
核心特性：强制身份覆写机制，彻底杜绝身份伪造攻击。
"""

import logging
import traceback
from typing import Callable, Dict, Optional, Tuple
from .app_protocol import AppMessage, AppCmd, AppMessageV2, AppCmdV2


class AppRouter:
    """
    QSP 应用层安全路由器 (C10 路由隔离重构版)
    负责解析解密后的业务明文，并将其分发给对应的业务模块。
    """
    def __init__(self, ui_invoker: Optional[Callable] = None):
        # 路由表映射：支持新旧两种协议
        self.handlers: Dict = {}  # 兼容 AppCmd 和 AppCmdV2
        self.ui_invoker = ui_invoker

    def register_handler(self, cmd: AppCmd, handler: Callable):
        """注册特定指令的应用层回调函数"""
        self.handlers[cmd] = handler

    def route_message(self, verified_source_id: str, payload: bytes):
        """
        【第三阶段核心：身份锚定分发】
        接收来自底层 SecureLink 隔离墙放行的明文数据，并根据强绑定的身份进行路由。
        支持新版协议 AppMessageV2。
        
        :param verified_source_id: 底层抗量子双向认证提取的真实公钥指纹 (不可伪造)
        :param payload: AES-GCM 解密后的应用层业务流
        """
        try:
            # 1. 使用新版协议反序列化 JSON 报文
            msg = AppMessageV2.decode(payload)

            # 2. 【强制身份覆写机制】：绝不信任报文自称的身份
            if msg.sender_id != verified_source_id:
                logging.warning(
                    f"[Security] 拦截到身份伪造尝试！"
                    f"报文自称发送者为 {msg.sender_id}，但底层密码学验证其真实身份为 {verified_source_id}。"
                    f"已强制修正为真实身份！"
                )
                # 强行覆盖，使得后续业务逻辑 (如份额校验、请求响应) 绝对使用真实的节点 ID
                msg.sender_id = verified_source_id

            # 3. 安全分发给对应的业务处理器
            if msg.cmd in self.handlers:
                # 注意：我们显式地把 verified_source_id 作为第一参数传给处理器
                if self.ui_invoker:
                    self.ui_invoker(self.handlers[msg.cmd], verified_source_id, msg)
                else:
                    self.handlers[msg.cmd](verified_source_id, msg)
            else:
                logging.warning(f"[AppRouter] 收到未知或未注册的业务指令: {msg.cmd}")

        except ValueError as e:
            logging.error(f"[AppRouter] 丢弃非法格式的报文: {e}")
        except Exception as e:
            logging.error(f"[AppRouter] 路由分发时发生系统异常: {e}")
            traceback.print_exc()

    # ==========================================
    # 旧版API兼容层
    # ==========================================
    def dispatch_network_data(self, peer_addr: Tuple[str, int], raw_data: bytes):
        """
        旧版API：向后兼容的网络数据分发方法
        注意：此方法没有底层认证的身份信息，安全性较低
        """
        try:
            msg = AppMessage.unpack(raw_data)
            
            handler = self.handlers.get(msg.cmd)
            if not handler:
                print(f"[AppRouter] 未知或未注册的业务指令丢弃: {msg.cmd}")
                return

            if self.ui_invoker:
                self.ui_invoker(handler, peer_addr, msg)
            else:
                handler(peer_addr, msg)

        except ValueError as e:
            print(f"[AppRouter] 安全拦截：接收到格式非法的应用层报文自 {peer_addr}: {e}")
        except Exception as e:
            print(f"[AppRouter] 严重错误：分发业务数据时发生异常: {e}")
            traceback.print_exc()
