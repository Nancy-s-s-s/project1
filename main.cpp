#include "sm4_simd.h"
#include <stdio.h>
#include <string.h>

int main() {
    // 密钥 (16字节)
    const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // 8个128位测试数据 (128字节)
    uint8_t plaintext[128] = {
        // 块1: ASCII "SM4 Block 1: ABC"
        0x53, 0x4D, 0x34, 0x20, 0x42, 0x6C, 0x6F, 0x63,
        0x6B, 0x20, 0x31, 0x3A, 0x20, 0x41, 0x42, 0x43,

        // 块2: ASCII "SM4 Block 2: DEF"
        0x53, 0x4D, 0x34, 0x20, 0x42, 0x6C, 0x6F, 0x63,
        0x6B, 0x20, 0x32, 0x3A, 0x20, 0x44, 0x45, 0x46,

        // 块3: 0x00-0x0F
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

        // 块4: 0x10-0x1F
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

        // 块5: 全零
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // 块6: 全FF
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

        // 块7: 递增序列
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

        // 块8: 递减序列
        0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28,
        0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20
    };

    uint8_t ciphertext[128];  // 加密结果
    uint8_t decrypted[128];   // 解密结果

    // 初始化密钥
    SM4_Key sm4_key;
    SM4_KeyInit(key, &sm4_key);

    // 基本功能测试
    printf("=== SM4功能测试 ===\n");

    // 使用8路并行加密8个数据块
    SM4_Encrypt_x8(plaintext, ciphertext, &sm4_key);
    printf("加密完成。处理了 %ld 字节。\n", sizeof(plaintext));

    // 使用8路并行解密8个数据块
    SM4_Decrypt_x8(ciphertext, decrypted, &sm4_key);
    printf("解密完成。处理了 %ld 字节。\n", sizeof(ciphertext));

    // 验证解密结果
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("成功: 解密文本与原始明文匹配!\n");

        // 打印第一块数据验证
        printf("\n块1原始值: ");
        for (int i = 0; i < 16; i++) printf("%02X ", plaintext[i]);

        printf("\n块1解密值: ");
        for (int i = 0; i < 16; i++) printf("%02X ", decrypted[i]);
        printf("\n");
    }
    else {
        printf("错误: 解密失败! 检测到不匹配。\n");
    }

    // 性能测试 
    printf("\n=== SM4性能测试 ===\n");

    // 准备更大的测试数据 (64MB)
    const size_t test_data_size = 64 * 1024 * 1024; // 64MB
    uint8_t* large_data = new uint8_t[test_data_size];
    memset(large_data, 0xAA, test_data_size); // 填充测试数据

    // 测试基本实现的性能 (每次处理1块)
    auto basic_encrypt = [](const uint8_t* in, uint8_t* out, const SM4_Key* key) {
        SM4_Encrypt_Block(in, out, key);
        };

    // 测试SIMD优化实现的性能 (每次处理8块)
    auto simd_encrypt = [](const uint8_t* in, uint8_t* out, const SM4_Key* key) {
        SM4_Encrypt_x8(in, out, key);
        };

    // 运行基准测试
    double basic_speed = benchmark_sm4(basic_encrypt, "基本实现 (单块)",
        large_data, test_data_size,
        &sm4_key, 1);

    double simd_speed = benchmark_sm4(simd_encrypt, "SIMD优化 (8块并行)",
        large_data, test_data_size,
        &sm4_key, 8);

    // 计算加速比
    double speedup = simd_speed / basic_speed;
    printf("\n加速比: %.2fx\n", speedup);

    // 清理大测试数据
    delete[] large_data;

    // 删除密钥
    SM4_KeyDelete(&sm4_key);
    return 0;
}
