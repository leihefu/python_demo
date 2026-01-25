import os
from cryptography.hazmat.primitives.asymmetric import ec

# ========== 修复关键：定义 P-256 曲线的阶 n ==========
# P-256 (secp256r1) 曲线的阶，这是一个标准值
# n = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def split_private_key_randomized(private_key_hex):
    """
    使用密码学安全随机数将私钥A拆分为 A1 和 A2。
    A1 随机生成，A2 = (A - A1) mod n。
    返回: (A1_hex, A2_hex, A1_int, A2_int)
    """
    A_int = int(private_key_hex, 16)

    # 1. 随机生成 A1 (在 [1, n-1] 范围内)
    # 生成32字节随机数，并确保它在有效范围内
    while True:
        A1_int = int.from_bytes(os.urandom(32), 'big')
        # 确保 A1_int 在 [1, n-1] 范围内
        if 1 <= A1_int < P256_ORDER:
            break

    # 2. 计算 A2 = (A - A1) mod n
    A2_int = (A_int - A1_int) % P256_ORDER

    # 转换为十六进制字符串（固定32字节，64字符）
    A1_hex = A1_int.to_bytes(32, 'big').hex()
    A2_hex = A2_int.to_bytes(32, 'big').hex()

    return A1_hex, A2_hex, A1_int, A2_int


def restore_and_verify(original_private_key_hex, A1_hex, A2_hex):
    """从拆分部分恢复私钥并验证"""
    original_int = int(original_private_key_hex, 16)
    A1_int = int(A1_hex, 16)
    A2_int = int(A2_hex, 16)

    # 计算恢复的私钥 (模n加法)
    restored_int = (A1_int + A2_int) % P256_ORDER

    print("\n" + "=" * 60)
    print("【恢复验证】")
    print(f"原始私钥 (模n后): {hex(original_int % P256_ORDER)[:30]}...")
    print(f"恢复私钥 (模n后): {hex(restored_int)[:30]}...")
    print(f"是否匹配: {restored_int == (original_int % P256_ORDER)}")

    # 重建私钥对象并验证公钥
    if restored_int == (original_int % P256_ORDER):
        restored_key = ec.derive_private_key(restored_int, ec.SECP256R1())
        original_key = ec.derive_private_key(original_int, ec.SECP256R1())

        # 验证公钥是否匹配
        from cryptography.hazmat.primitives import serialization

        original_pub = original_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        ).hex()

        restored_pub = restored_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        ).hex()

        print(f"\n【公钥验证】")
        print(f"原始公钥 (压缩): {original_pub[:20]}...")
        print(f"恢复公钥 (压缩): {restored_pub[:20]}...")
        print(f"公钥是否相同: {original_pub == restored_pub}")

        return restored_key
    else:
        raise ValueError("❌ 私钥恢复失败！拆分或恢复过程有误。")


def main():
    """主函数：完整的密钥拆分与验证流程"""
    print("P-256 私钥拆分与验证")
    print("=" * 60)

    # ========== 1. 输入你的32字节私钥 ==========
    # 注意：请替换为你自己的32字节私钥（64位十六进制字符串）
    private_key_hex = "2f4b6e8c5d9a3f7b1e0d8c9a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c"  # 示例

    # 验证输入格式
    if len(private_key_hex) != 64:
        print(f"警告：私钥长度应为64个十六进制字符（32字节），当前为{len(private_key_hex)}字符")
        # 如果长度不够，可以填充零（根据你的实际需求调整）
        if len(private_key_hex) < 64:
            private_key_hex = private_key_hex.zfill(64)
        # 如果长度超出，可以截断（根据你的实际需求调整）
        else:
            private_key_hex = private_key_hex[:64]

    print(f"原始私钥A: {private_key_hex}")
    print(f"长度: {len(private_key_hex)} 字符 ({len(private_key_hex) // 2} 字节)")

    # ========== 2. 随机化拆分私钥 ==========
    print("\n" + "-" * 60)
    print("步骤1: 随机化拆分私钥")
    A1_hex, A2_hex, A1_int, A2_int = split_private_key_randomized(private_key_hex)

    print(f"拆分后的A1: {A1_hex}")
    print(f"拆分后的A2: {A2_hex}")

    # 显示数值信息
    print(f"\n数值验证:")
    print(f"A1_int = {hex(A1_int)[:30]}...")
    print(f"A2_int = {hex(A2_int)[:30]}...")
    print(f"(A1_int + A2_int) % n = {hex((A1_int + A2_int) % P256_ORDER)[:30]}...")

    # ========== 3. 验证拆分结果 ==========
    print("\n" + "-" * 60)
    print("步骤2: 验证拆分结果")

    # 直接验证模运算
    original_int = int(private_key_hex, 16)
    verification = (A1_int + A2_int) % P256_ORDER == original_int % P256_ORDER
    print(f"验证 (A1 + A2) % n == A % n: {verification}")

    if verification:
        print("✅ 拆分算法正确：在模n运算下 A1 + A2 ≡ A")
    else:
        print("❌ 拆分验证失败！")
        return

    # ========== 4. 恢复并完整验证 ==========
    restored_key = restore_and_verify(private_key_hex, A1_hex, A2_hex)

    print("\n" + "=" * 60)
    print("✅ 流程完成！私钥已成功拆分为两个部分：")
    print(f"   A1 (随机部分): 保管位置1")
    print(f"   A2 (计算部分): 保管位置2")
    print("\n⚠️  安全提示：")
    print("   1. A1 和 A2 必须分开存储（如不同设备/地理位置）")
    print("   2. 单独持有 A1 或 A2 无法恢复原始私钥")
    print("   3. 只有同时获得 A1 和 A2 才能重构原始私钥")
    print("   4. 确保 A1 和 A2 的存储安全级别与原始私钥相同")


# 运行主程序
if __name__ == "__main__":
    main()