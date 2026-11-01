# -*- coding: utf-8 -*-
"""
repository.py —— 仓库（DAO）层：所有数据库读写收口于此

约定：
  - 业务层 / GUI 层禁止直接写 SQL，一律通过本模块的仓库类；
  - EvidenceRepository 不提供 update / delete —— 存证记录不可篡改。

提供仓库类：
  UserRepository     用户账号：创建 / 查询 / 校验登录 / 改状态 / 删除（引用置空）
  SessionRepository  登录态：签发 / 校验 token / 吊销（登出 / 按用户批量吊销）
  EvidenceRepository 存证记录：写入 / 按指纹查 / 语义检索 / 按归属查 / 计数
  SignerRepository   签名人登记：登记（幂等）/ 按公钥或归属查
"""

import secrets
from datetime import datetime, timedelta

from sqlalchemy import or_

from app.dao.security import hash_password, verify_password
from app.models import Evidence, LoginSession, Signer, User


def _now() -> datetime:
    return datetime.now()


class _BaseRepository:
    """仓库基类：持有会话工厂，每个方法开一个短会话。"""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def _session(self):
        return self._session_factory()


class UserRepository(_BaseRepository):
    """用户 / 账号仓库。"""

    def create_user(self, username, password, role="user",
                    display_name=None, status="enabled") -> User:
        """创建用户：口令经 PBKDF2 加盐哈希后入库，绝不存明文。"""
        if not username:
            raise ValueError("用户名不能为空")
        password_hash, salt = hash_password(password)
        with self._session() as s:
            if s.query(User).filter(User.username == username).first():
                raise ValueError(f"用户名已存在：{username}")
            user = User(
                username=username, password_hash=password_hash, salt=salt,
                role=role, status=status, display_name=display_name or username,
            )
            s.add(user)
            s.commit()
            return user

    def find_by_username(self, username) -> User:
        with self._session() as s:
            return s.query(User).filter(User.username == username).first()

    def find_by_id(self, user_id) -> User:
        with self._session() as s:
            return s.get(User, user_id)

    def verify_login(self, username, password) -> User:
        """校验登录：比对加盐哈希；账号不存在 / 被禁用 / 口令错误均返回 None。"""
        user = self.find_by_username(username)
        if not user or user.status != "enabled":
            return None
        if verify_password(password, user.password_hash, user.salt):
            return user
        return None

    def set_status(self, username_or_id, status) -> bool:
        with self._session() as s:
            if isinstance(username_or_id, str):
                q = s.query(User).filter(User.username == username_or_id)
            else:
                q = s.query(User).filter(User.id == username_or_id)
            user = q.first()
            if not user:
                return False
            user.status = status
            user.updated_at = _now()
            s.commit()
            return True

    def set_role(self, username_or_id, role) -> bool:
        """修改账号角色（普通用户 / 管理员）。权限校验由业务层负责。"""
        with self._session() as s:
            if isinstance(username_or_id, str):
                q = s.query(User).filter(User.username == username_or_id)
            else:
                q = s.query(User).filter(User.id == username_or_id)
            user = q.first()
            if not user:
                return False
            user.role = role
            user.updated_at = _now()
            s.commit()
            return True

    def update_password(self, username_or_id, password_hash, salt) -> bool:
        """更新口令的加盐哈希（业务层校验原密码后调用）。"""
        with self._session() as s:
            if isinstance(username_or_id, str):
                q = s.query(User).filter(User.username == username_or_id)
            else:
                q = s.query(User).filter(User.id == username_or_id)
            user = q.first()
            if not user:
                return False
            user.password_hash = password_hash
            user.salt = salt
            user.updated_at = _now()
            s.commit()
            return True

    def list_all(self):
        with self._session() as s:
            return s.query(User).order_by(User.id).all()

    def delete_user(self, user_id) -> bool:
        """物理删除用户，并处理引用（存证本体保留，不做物理删除）：

          - sessions：删除该用户全部登录态（迫使其重新登录）
          - evidence.uploader_id → NULL（存证记录本体保留，不可篡改）
          - signer.user_id      → NULL（签名人登记仍保留公钥）
        """
        with self._session() as s:
            user = s.get(User, user_id)
            if user is None:
                return False
            (s.query(LoginSession)
             .filter(LoginSession.user_id == user_id)
             .delete(synchronize_session=False))
            (s.query(Evidence)
             .filter(Evidence.uploader_id == user_id)
             .update({Evidence.uploader_id: None}, synchronize_session=False))
            (s.query(Signer)
             .filter(Signer.user_id == user_id)
             .update({Signer.user_id: None}, synchronize_session=False))
            s.delete(user)
            s.commit()
            return True


class SessionRepository(_BaseRepository):
    """登录态仓库。"""

    def create_session(self, user_id, ttl_seconds=8 * 3600, token=None) -> LoginSession:
        token = token or secrets.token_hex(32)
        now = _now()
        with self._session() as s:
            sess = LoginSession(
                user_id=user_id, token=token,
                created_at=now, expires_at=now + timedelta(seconds=ttl_seconds),
            )
            s.add(sess)
            s.commit()
            return sess

    def validate_token(self, token) -> User:
        """令牌有效则返回对应用户，否则 None（不存在 / 已过期 / 已吊销）。"""
        if not token:
            return None
        with self._session() as s:
            sess = s.query(LoginSession).filter(LoginSession.token == token).first()
            if sess is None or sess.expires_at < _now():
                return None
            return s.get(User, sess.user_id)

    def revoke_session(self, token) -> bool:
        """登出：删除该令牌对应的登录态。"""
        with self._session() as s:
            sess = s.query(LoginSession).filter(LoginSession.token == token).first()
            if sess is None:
                return False
            s.delete(sess)
            s.commit()
            return True

    def revoke_user_sessions(self, user_id) -> int:
        """吊销某用户的全部登录态（管理员重置密码后迫使其重新登录）。"""
        with self._session() as s:
            count = (s.query(LoginSession)
                     .filter(LoginSession.user_id == user_id)
                     .delete(synchronize_session=False))
            s.commit()
            return count


class EvidenceRepository(_BaseRepository):
    """存证记录仓库 —— 只增不改不删（不可篡改）。

    注意：本仓库【不提供】任何 update / delete 方法。
    """

    def save_evidence(self, file_sha256, file_name, signer_pubkey, signature,
                      chain_hash, semantic_index=None, uploader_id=None,
                      cipher_path=None, file_id=None) -> Evidence:
        """写入一条存证记录（只存指纹 / 公钥 / 签名 / 链哈希 / 语义索引 / 密文路径，绝不含原文与私钥）。"""
        with self._session() as s:
            record = Evidence(
                file_id=file_id, file_sha256=file_sha256, file_name=file_name,
                signer_pubkey=signer_pubkey, signature=signature,
                chain_hash=chain_hash, semantic_index=semantic_index,
                uploader_id=uploader_id, cipher_path=cipher_path,
            )
            s.add(record)
            s.commit()
            return record

    def find_by_fingerprint(self, file_sha256):
        """验真：按指纹查询全部匹配的存证记录。"""
        with self._session() as s:
            return (s.query(Evidence)
                    .filter(Evidence.file_sha256 == file_sha256)
                    .order_by(Evidence.created_at.desc()).all())

    def semantic_search(self, query, limit=20):
        """语义检索：当前按关键词索引匹配（semantic_index / 文件名 / file_id），预留 AI 向量检索接口。"""
        if not query:
            return []
        pattern = f"%{query}%"
        with self._session() as s:
            return (s.query(Evidence)
                    .filter(or_(Evidence.semantic_index.like(pattern),
                                Evidence.file_name.like(pattern),
                                Evidence.file_id.like(pattern)))
                    .order_by(Evidence.created_at.desc()).limit(limit).all())

    def find_by_user(self, user_id):
        """按 uploader 查询归属人的存证；user_id 为 None 时查「无归属（匿名）」记录。"""
        with self._session() as s:
            q = s.query(Evidence)
            q = (q.filter(Evidence.uploader_id == user_id) if user_id is not None
                 else q.filter(Evidence.uploader_id.is_(None)))
            return q.order_by(Evidence.created_at.desc()).all()

    def find_all(self, limit=None):
        """全部存证（管理员视角）。"""
        with self._session() as s:
            q = s.query(Evidence).order_by(Evidence.created_at.desc())
            if limit:
                q = q.limit(limit)
            return q.all()

    def count(self, user_id=None) -> int:
        """计数：user_id 为空时返回全部存证总数。"""
        with self._session() as s:
            q = s.query(Evidence)
            if user_id is not None:
                q = q.filter(Evidence.uploader_id == user_id)
            return q.count()


class SignerRepository(_BaseRepository):
    """签名人登记仓库。"""

    def register(self, name, pubkey, user_id=None) -> Signer:
        """按公钥登记签名人（幂等：已存在则复用，并补全归属人）。"""
        with self._session() as s:
            existing = s.query(Signer).filter(Signer.pubkey == pubkey).first()
            if existing is not None:
                if user_id is not None and existing.user_id is None:
                    existing.user_id = user_id
                    s.commit()
                return existing
            signer = Signer(name=name or "anonymous", pubkey=pubkey, user_id=user_id)
            s.add(signer)
            s.commit()
            return signer

    def find_by_pubkey(self, pubkey) -> Signer:
        with self._session() as s:
            return s.query(Signer).filter(Signer.pubkey == pubkey).first()

    def find_by_user(self, user_id):
        with self._session() as s:
            return (s.query(Signer)
                    .filter(Signer.user_id == user_id)
                    .order_by(Signer.id).all())
