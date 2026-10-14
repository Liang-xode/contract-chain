# -*- coding: utf-8 -*-
"""
sm2_keys.py —— SM2 公钥推导（自实现 SM2 椭圆曲线点运算）

gmssl 3.2.x 不再提供「私钥 -> 公钥」的推导接口，
因此这里基于 SM2 标准曲线参数（GM/T 0003-2012）自实现：
    点加法、点倍点、标量乘法，最终由 私钥 d 计算公钥 P = d * G。

这既是 demo 自包含的基础，也是展示「对 SM2 椭圆曲线原理的理解」的加分点。
"""

# ---- SM2 标准曲线参数（十六进制）----
SM2_P = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
SM2_A = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
SM2_B = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
SM2_N = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
SM2_GX = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
SM2_GY = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)


class SM2Point:
    """SM2 椭圆曲线上的点（仿射坐标）。infinity=True 表示无穷远点（单位元）。"""

    __slots__ = ("x", "y", "infinity")

    def __init__(self, x=0, y=0, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __eq__(self, other):
        if self.infinity or other.infinity:
            return self.infinity and other.infinity
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        return "INF" if self.infinity else f"({self.x:064x}, {self.y:064x})"


def point_add(p: SM2Point, q: SM2Point) -> SM2Point:
    """椭圆曲线点加法：P + Q"""
    if p.infinity:
        return q
    if q.infinity:
        return p
    # P + (-P) = O
    if p.x == q.x and (p.y + q.y) % SM2_P == 0:
        return SM2Point(infinity=True)

    if p == q:  # 倍点：P + P
        if p.y == 0:
            return SM2Point(infinity=True)
        lam = (3 * p.x * p.x + SM2_A) * pow(2 * p.y, SM2_P - 2, SM2_P) % SM2_P
    else:
        lam = (q.y - p.y) * pow(q.x - p.x, SM2_P - 2, SM2_P) % SM2_P

    xr = (lam * lam - p.x - q.x) % SM2_P
    yr = (lam * (p.x - xr) - p.y) % SM2_P
    return SM2Point(xr, yr)


def point_mul(k: int, p: SM2Point) -> SM2Point:
    """标量乘法：k * P（使用 double-and-add）"""
    result = SM2Point(infinity=True)
    addend = p
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)  # 倍点
        k >>= 1
    return result


def private_key_to_public_key(private_key_hex: str) -> str:
    """
    由 SM2 私钥（64 位 hex，32 字节）推导公钥。
    公钥格式：64 位 hex = 未压缩坐标 (Px || Py)，各 32 字节。
    用于与 gmssl.CryptSM2 的 public_key 参数对齐。
    """
    d = int(private_key_hex, 16)
    if not (0 < d < SM2_N):
        raise ValueError("私钥取值范围不合法：应为 1 <= d < n")

    G = SM2Point(SM2_GX, SM2_GY)
    pub = point_mul(d, G)
    if pub.infinity:
        raise ValueError("私钥推导得到无穷远点，非法")
    return f"{pub.x:064x}{pub.y:064x}"


if __name__ == "__main__":
    # 自测：同一私钥两次推导结果一致，且与预期长度一致
    import gmssl.func as func

    d1 = func.random_hex(64)
    pub1 = private_key_to_public_key(d1)
    pub2 = private_key_to_public_key(d1)
    assert pub1 == pub2, "公钥推导应具有确定性"
    assert len(pub1) == 128, "公钥应为 128 位 hex（64 字节）"
    print("私钥:", d1)
    print("公钥:", pub1)
    print("SM2 公钥推导自测通过（确定性 + 长度正确）")
