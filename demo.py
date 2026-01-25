from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64


def generate_public_key_from_private(private_key_hex, curve=ec.SECP256K1()):
    """
    从十六进制私钥生成公钥
    """
    # 将十六进制私钥转换为整数
    private_value = int(private_key_hex, 16)

    # 创建私钥对象
    private_key = ec.derive_private_key(
        private_value,
        curve,
        default_backend()
    )

    # 获取公钥
    public_key = private_key.public_key()

    return private_key, public_key


# 示例：使用现有的私钥
existing_private_key_hex = "296cb9ac68da3c32cb31d96dc273ba9708d81ace40689e3e02aadfacd269a565"  # 示例私钥

private_key, public_key = generate_public_key_from_private(existing_private_key_hex)

# 输出公钥信息
numbers = public_key.public_numbers()
print(f"私钥 (16进制): {existing_private_key_hex}")
print(f"公钥坐标:")
print(f"X: {hex(numbers.x)}")
print(f"Y: {hex(numbers.y)}")
print(f"\n公钥 (非压缩格式):")
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
print(f"04{public_bytes.hex()[2:]}")  # 添加04前缀表示非压缩格式