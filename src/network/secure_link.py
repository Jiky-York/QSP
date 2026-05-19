"""
src/network/secure_link.py
[Phase 14] QSP 安全链路管理器 (C10 双向认证隔离墙重构版)

作为底层物理网络 (UDP/RUDP) 和加密信道 (SecureChannel) 之间的桥梁。
核心功能：
1. 状态机流转控制：监控 3-Way Handshake 的状态切换。
2. 终极数据隔离墙：在双向认证完成前，阻断一切应用层数据的上传与下发。
"""

import logging
import time
import threading
from typing import Callable, Optional

from src.network.secure_channel import SecureChannel, ChannelState


class SecureLink:
    """
    QSP 安全链路管理器 (C10 双向认证隔离墙重构版)
    
    作为底层物理网络 (UDP/RUDP) 和加密信道 (SecureChannel) 之间的桥梁。
    核心功能：
    1. 状态机流转控制：监控 3-Way Handshake 的状态切换。
    2. 终极数据隔离墙：在双向认证完成前，阻断一切应用层数据的上传与下发。
    
    支持两种 API：
    - 新版 API: SecureLink(is_server, peer_addr, my_keypair, expected_fp)
    - 旧版 API: SecureLink(send_raw_fn, peer_addr, session_id, role, peer_fp, local_pk, local_sk)
    """
    def __init__(self, *args, **kwargs):
        # 检测是新版API还是旧版API
        # 新版API: is_server (bool), peer_addr (tuple), my_keypair (dict), expected_fp (str)
        # 旧版API: send_raw_fn (callable), peer_addr (tuple), session_id (int), role (str), peer_fp (str), local_pk (bytes), local_sk (bytes)
        
        if len(args) >= 1 and isinstance(args[0], bool):
            # 新版API
            self._init_new_api(*args, **kwargs)
        else:
            # 旧版API
            self._init_old_api(*args, **kwargs)
    
    def _init_new_api(self, is_server: bool, peer_addr: tuple, my_keypair: dict, expected_fp: str = None):
        """新版API初始化"""
        self.peer_addr = peer_addr
        
        # 挂载第一阶段重构的 1.5-RTT 双向认证信道
        self.channel = SecureChannel(is_server=is_server, my_identity_keypair=my_keypair, expected_peer_fp=expected_fp)
        
        # 状态流转标记
        self._was_established = False
        
        # ==========================================
        # 【第四阶段核心】：防爆破超时看门狗
        # ==========================================
        self._handshake_timer = None
        self.handshake_timeout_sec = 5.0  # 严格限制：必须在 5 秒内提供抗量子签名证明
        
        # 上下层通信回调钩子
        self.send_raw_network_func = None  
        self.on_link_established = None    # 当信道进入 ESTABLISHED 时触发
        self.on_app_data_received = None   # 当收到解密后的合法业务数据时触发
        self.on_link_closed = None         # 当信道熔断或关闭时触发
        
        # 将底层发送动作注入给 SecureChannel
        self.channel.set_send_callback(self._raw_send)
    
    def _init_old_api(self, send_raw_fn, peer_addr, session_id, role='client', peer_fp="", local_pk=b"", local_sk=b""):
        """旧版API初始化 (保持向后兼容)"""
        self._send_raw_external = send_raw_fn
        self.peer_addr = peer_addr
        self.session_id = session_id
        self.role = role
        
        # 兼容旧版属性名
        self.sec_channel = SecureChannel(role=role, my_pk=local_pk, my_sk=local_sk, peer_fp=peer_fp)
        self.channel = self.sec_channel  # 也设置新版属性名
        
        # 状态流转标记
        self._was_established = False
        
        # 旧版回调
        self.on_handshake_done = None
        self.on_data_received = None
        
        # 新版回调 (添加支持)
        self.on_link_established = None
        self.on_app_data_received = None
        self.on_link_closed = None
        
        # 心跳机制
        import time
        import threading
        self.last_send_time = time.time()
        self.last_recv_time = time.time()
        self.is_running = True
        self.heartbeat_interval = 15.0
        
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
    
    def stop(self):
        """安全释放后台心跳线程 (旧版API兼容)"""
        if hasattr(self, 'is_running'):
            self.is_running = False
    
    def _heartbeat_loop(self):
        """心跳守护线程 (旧版API兼容)"""
        import time
        while self.is_running:
            time.sleep(1.0)
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                continue
                
            now = time.time()
            if now - self.last_send_time >= self.heartbeat_interval:
                from src.network.protocol import QSPProtocol, PacketType
                pkt = QSPProtocol.pack(
                    PacketType.KEEPALIVE, 
                    seq=0, 
                    payload=b"PING", 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)
    
    def _send_wrapped(self, data: bytes):
        """旧版API的发送包装 (保持向后兼容)"""
        import time
        self.last_send_time = time.time()
        self._send_raw_external(data, self.peer_addr)
    
    def initiate_security_handshake(self):
        """旧版API的握手方法 (保持向后兼容)"""
        if self.sec_channel.role != 'client':
            return
        
        init_payload = self.sec_channel.initiate_handshake()
        from src.network.protocol import QSPProtocol, PacketType
        pkt = QSPProtocol.pack(
            PacketType.HANDSHAKE_INIT, 
            seq=0, 
            payload=init_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)
    
    def handle_network_packet(self, parsed_pkt: dict):
        """旧版API的数据包处理方法 (保持向后兼容)"""
        import time
        self.last_recv_time = time.time()
        
        from src.network.protocol import PacketType
        
        msg_type = parsed_pkt['type']
        
        if msg_type == PacketType.KEEPALIVE:
            return

        payload = parsed_pkt['payload']
        seq = parsed_pkt['seq']
        ack = parsed_pkt['ack']

        if msg_type == PacketType.HANDSHAKE_INIT:
            resp_payload = self.sec_channel.handle_handshake_request(payload)
            from src.network.protocol import QSPProtocol
            pkt = QSPProtocol.pack(
                PacketType.HANDSHAKE_RESP, 
                seq=0, 
                payload=resp_payload, 
                session_id=self.session_id
            )
            self._send_wrapped(pkt)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.HANDSHAKE_RESP:
            self.sec_channel.handle_handshake_response(payload)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.DATA:
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                return

            from src.network.rudp import RUDPConnection
            from src.network.protocol import QSPProtocol
            
            cleartext = self.sec_channel.decrypt_payload(payload)
            self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
            deliverable, current_ack, sack_blocks = self.rudp.receive_data(seq, cleartext)
            sack_payload = QSPProtocol.build_sack_payload(sack_blocks)
            
            ack_pkt = QSPProtocol.pack(
                PacketType.SACK, 
                seq=0, 
                payload=sack_payload, 
                ack=current_ack, 
                session_id=self.session_id
            )
            self._send_wrapped(ack_pkt)

            # 优先调用新版回调
            if self.on_app_data_received:
                for data in deliverable:
                    # 新版回调需要节点ID，这里使用peer_addr作为标识
                    self.on_app_data_received(str(self.peer_addr), data)
            elif self.on_data_received:
                for data in deliverable:
                    self.on_data_received(data)

        elif msg_type == PacketType.SACK:
            from src.network.protocol import QSPProtocol
            from src.network.congestion import HybridCongestionControl
            
            sack_blocks = QSPProtocol.parse_sack_blocks(payload)
            retransmits, rtt_sample = self.rudp.handle_sack(ack, sack_blocks)
            
            self.cc = HybridCongestionControl() if not hasattr(self, 'cc') else self.cc

            if len(retransmits) > 0:
                self.cc.on_loss()
            elif rtt_sample > 0:
                self.cc.on_ack(rtt=rtt_sample)

            for r_seq, encrypted_payload in retransmits:
                pkt = QSPProtocol.pack(
                    PacketType.DATA, 
                    seq=r_seq, 
                    payload=encrypted_payload, 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)
    
    def send_reliable(self, cleartext: bytes):
        """旧版API的可靠发送方法 (保持向后兼容)"""
        if self.sec_channel.state != ChannelState.ESTABLISHED:
            raise PermissionError("安全信道尚未建立，拒绝传输资产数据。")

        encrypted_payload = self.sec_channel.encrypt_payload(cleartext)
        
        from src.network.rudp import RUDPConnection
        from src.network.protocol import QSPProtocol, PacketType
        
        self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
        seq = self.rudp.next_seq_num
        self.rudp.track_sent_packet(seq, encrypted_payload)
        
        pkt = QSPProtocol.pack(
            PacketType.DATA, 
            seq=seq, 
            payload=encrypted_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)

# ==========================================
    # 新版API - 网络数据入口与状态机隔离墙
    # ==========================================
    def receive_network_data(self, data: bytes):
        """
        【隔离墙外层】：接收来自真实网卡的物理二进制数据流。
        这里接收到的是包含了握手信令、公钥、或密文的原始数据。
        """
        try:
            # 记录处理前的状态，用于捕捉状态跃迁
            prev_state = self.channel.state
            
            # 喂给底层加密信道处理
            self.channel.feed_data(data)
            
            # 检查状态机并执行熔断/放行逻辑
            self._check_state_transition(prev_state)
            
        except Exception as e:
            logging.error(f"[SecureLink] 处理物理层数据时发生严重异常: {e}")
            self.close()

    def _check_state_transition(self, prev_state: ChannelState):
        """
        【核心状态墙】：监控双向认证的状态流转，控制定时器与隔离墙。
        """
        if self.channel.state == ChannelState.CLOSED:
            self.close()
            return

        current_state = self.channel.state

        # 【触发熔断倒计时】：当服务端响应完毕，进入等待客户端证明的阶段
        if prev_state != ChannelState.WAIT_CLIENT_FINISHED and current_state == ChannelState.WAIT_CLIENT_FINISHED:
            self._start_handshake_timer()

        # 【解除隔离与警报】：双向认证成功，信道建立
        if not self._was_established and current_state == ChannelState.ESTABLISHED:
            # 1. 客户端合法，取消爆炸倒计时
            self._cancel_handshake_timer()
            self._was_established = True
            
            # 2. 提取真实身份并放行数据
            real_remote_id = self.channel.remote_node_id
            logging.info(f"[SecureLink] 隔离墙解除！与物理坐标 {self.peer_addr} 的双向认证成功。真实身份: {real_remote_id}")
            
            # 【核心安全放行】：挂载业务数据回调
            self.channel.app_data_callback = self._handle_decrypted_app_data
            
            # 向上层 P2P Router 触发连通事件
            if self.on_link_established:
                self.on_link_established(self.peer_addr, real_remote_id)

    # ==========================================
    # 【新增】：看门狗生命周期管理
    # ==========================================
    def _start_handshake_timer(self):
        """启动防 DoS 超时计时器"""
        self._cancel_handshake_timer()  # 确保不会产生悬空线程
        self._handshake_timer = threading.Timer(self.handshake_timeout_sec, self._on_handshake_timeout)
        self._handshake_timer.start()
        logging.debug(f"[Security] 启动半连接监控 ({self.peer_addr})，限时 {self.handshake_timeout_sec}s。")

    def _on_handshake_timeout(self):
        """倒计时结束触发此方法"""
        # 如果 5 秒后，信道依然没有达到 ESTABLISHED 状态
        if self.channel.state != ChannelState.ESTABLISHED:
            logging.warning(
                f"[Security-Firewall] 握手超时！节点 {self.peer_addr} "
                f"未能在限时内提交合法的 ClientFinished 身份证明，疑似 DoS 攻击。强制熔断！"
            )
            self.close()

    def _cancel_handshake_timer(self):
        """安全销毁计时器"""
        if self._handshake_timer:
            self._handshake_timer.cancel()
            self._handshake_timer = None

    # ==========================================
    # 业务数据流转控制
    # ==========================================
    def _handle_decrypted_app_data(self, remote_node_id: str, plaintext: bytes):
        """
        【隔离墙内层-收】：处理已经过 AES-GCM 解密且认证合法的纯明文业务数据。
        将其安全地提交给 AppRouter 处理。
        """
        if self.on_app_data_received:
            # 注意：这里强行传递了底层握手得出的 remote_node_id，
            # 绝不相信明文 payload 里可能伪造的身份字段 (为第三阶段铺垫)
            self.on_app_data_received(remote_node_id, plaintext)

    def send_app_data(self, plaintext: bytes):
        """
        【隔离墙内层-发】：上层请求发送业务数据。
        强制校验状态，防止在握手完成前泄露业务明文。
        """
        if self.channel.state != ChannelState.ESTABLISHED:
            logging.warning(f"[SecureLink] 拦截！信道 {self.peer_addr} 尚未完成双向认证，拒绝发送应用层数据。")
            return
            
        self.channel.encrypt_and_send(plaintext)

    # ==========================================
    # 底层网络交互
    # ==========================================
    def _raw_send(self, data: bytes):
        """将 SecureChannel 打包好的握手信令或密文推入物理网卡"""
        if self.send_raw_network_func:
            self.send_raw_network_func(self.peer_addr, data)

    def close(self):
        """熔断并深度清理资源"""
        # 1. 立即停止任何正在进行的倒计时
        self._cancel_handshake_timer()
        
        # 2. 清理底层加密信道的会话密钥 (K_session)
        if self.channel.state != ChannelState.CLOSED:
            self.channel.close()
            
        # 3. 撤销建立状态并通知上层物理路由表
        if self._was_established:
            logging.info(f"[SecureLink] 与 {self.peer_addr} 的安全链路已断开。")
            self._was_established = False
            
        # 【第四阶段核心清理】：无论是否 ESTABLISHED，都要触发 on_link_closed。
        # 这样 P2PNode 的字典 (self.links) 就会将这个物理地址 (peer_addr) 彻底剔除，释放内存。
        if self.on_link_closed:
            self.on_link_closed(self.peer_addr, self.channel.remote_node_id)


# ==========================================
# 旧版API兼容层 (保持向后兼容)
# ==========================================
class LegacySecureLink:
    """
    旧版 SecureLink 的兼容包装器
    保持与现有代码的兼容性，同时内部使用新的隔离墙机制
    """
    def __init__(self, 
                 send_raw_fn: Callable[[bytes, tuple], None], 
                 peer_addr: tuple, 
                 session_id: int, 
                 role: str = 'client', 
                 peer_fp: str = "",          
                 local_pk: bytes = b"",      
                 local_sk: bytes = b""):
        
        self._send_raw_external = send_raw_fn
        self.peer_addr = peer_addr
        self.session_id = session_id

        my_keypair = {"pk": local_pk, "sk": local_sk}
        self.sec_channel = SecureChannel(role=role, my_pk=local_pk, my_sk=local_sk, peer_fp=peer_fp)
        
        self.on_handshake_done: Optional[Callable] = None
        self.on_data_received: Optional[Callable[[bytes], None]] = None

        self.last_send_time = time.time()
        self.last_recv_time = time.time()
        self.is_running = True
        self.heartbeat_interval = 15.0
        
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def stop(self):
        self.is_running = False

    def _send_wrapped(self, data: bytes):
        self.last_send_time = time.time()
        self._send_raw_external(data, self.peer_addr)

    def _heartbeat_loop(self):
        while self.is_running:
            time.sleep(1.0)
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                continue
                
            now = time.time()
            if now - self.last_send_time >= self.heartbeat_interval:
                from src.network.protocol import QSPProtocol, PacketType
                pkt = QSPProtocol.pack(
                    PacketType.KEEPALIVE, 
                    seq=0, 
                    payload=b"PING", 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)

    def initiate_security_handshake(self):
        if self.sec_channel.role != 'client':
            return
        
        init_payload = self.sec_channel.initiate_handshake()
        from src.network.protocol import QSPProtocol, PacketType
        pkt = QSPProtocol.pack(
            PacketType.HANDSHAKE_INIT, 
            seq=0, 
            payload=init_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)

    def handle_network_packet(self, parsed_pkt: dict):
        self.last_recv_time = time.time()
        
        from src.network.protocol import PacketType
        
        msg_type = parsed_pkt['type']
        
        if msg_type == PacketType.KEEPALIVE:
            return

        payload = parsed_pkt['payload']
        seq = parsed_pkt['seq']
        ack = parsed_pkt['ack']

        if msg_type == PacketType.HANDSHAKE_INIT:
            resp_payload = self.sec_channel.handle_handshake_request(payload)
            from src.network.protocol import QSPProtocol
            pkt = QSPProtocol.pack(
                PacketType.HANDSHAKE_RESP, 
                seq=0, 
                payload=resp_payload, 
                session_id=self.session_id
            )
            self._send_wrapped(pkt)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.HANDSHAKE_RESP:
            self.sec_channel.handle_handshake_response(payload)
            if self.sec_channel.state == ChannelState.ESTABLISHED:
                if self.on_handshake_done:
                    self.on_handshake_done()

        elif msg_type == PacketType.DATA:
            if self.sec_channel.state != ChannelState.ESTABLISHED:
                return

            from src.network.rudp import RUDPConnection
            from src.network.protocol import QSPProtocol
            
            cleartext = self.sec_channel.decrypt_payload(payload)
            self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
            deliverable, current_ack, sack_blocks = self.rudp.receive_data(seq, cleartext)
            sack_payload = QSPProtocol.build_sack_payload(sack_blocks)
            
            ack_pkt = QSPProtocol.pack(
                PacketType.SACK, 
                seq=0, 
                payload=sack_payload, 
                ack=current_ack, 
                session_id=self.session_id
            )
            self._send_wrapped(ack_pkt)

            if self.on_data_received:
                for data in deliverable:
                    self.on_data_received(data)

        elif msg_type == PacketType.SACK:
            from src.network.protocol import QSPProtocol
            from src.network.congestion import HybridCongestionControl
            
            sack_blocks = QSPProtocol.parse_sack_blocks(payload)
            retransmits, rtt_sample = self.rudp.handle_sack(ack, sack_blocks)
            
            self.cc = HybridCongestionControl() if not hasattr(self, 'cc') else self.cc

            if len(retransmits) > 0:
                self.cc.on_loss()
            elif rtt_sample > 0:
                self.cc.on_ack(rtt=rtt_sample)

            for r_seq, encrypted_payload in retransmits:
                pkt = QSPProtocol.pack(
                    PacketType.DATA, 
                    seq=r_seq, 
                    payload=encrypted_payload, 
                    session_id=self.session_id
                )
                self._send_wrapped(pkt)

    def send_reliable(self, cleartext: bytes):
        if self.sec_channel.state != ChannelState.ESTABLISHED:
            raise PermissionError("安全信道尚未建立，拒绝传输资产数据。")

        encrypted_payload = self.sec_channel.encrypt_payload(cleartext)
        
        from src.network.rudp import RUDPConnection
        from src.network.protocol import QSPProtocol
        
        self.rudp = RUDPConnection(self.session_id) if not hasattr(self, 'rudp') else self.rudp
        seq = self.rudp.next_seq_num
        self.rudp.track_sent_packet(seq, encrypted_payload)
        
        pkt = QSPProtocol.pack(
            PacketType.DATA, 
            seq=seq, 
            payload=encrypted_payload, 
            session_id=self.session_id
        )
        self._send_wrapped(pkt)
