#pragma once

#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include <bit> 


namespace {

    // SM4 S盒定义 (GB/T 32907-2016)
    alignas(64) constexpr uint8_t SM4_SBOX[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
    };

    // 轮常数 (FK & CK)
    alignas(16) constexpr uint32_t FK[4] = {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };

    alignas(64) constexpr uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    // 合并 S 盒与线性变换 L 的查找表
    alignas(64) uint32_t T_table[4][256] = { {0} };
    alignas(64) uint32_t Tp_table[4][256] = { {0} }; // 用于密钥扩展的T'表

    // 循环左移函数 (兼容 C++17)
    template <typename T>
    constexpr T rotl(T x, int s) {
        return (x << s) | (x >> (sizeof(T) * 8 - s));
    }

    // 初始化合并查找表 (线程安全的延迟初始化)
    struct SM4_TableInitializer {
        SM4_TableInitializer() {
            // 线性变换 L: L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
            auto L_transform = [](uint32_t b) {
                return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
                };

            // 密钥扩展线性变换 L': L'(B) = B ^ (B <<< 13) ^ (B <<< 23)
            auto Lp_transform = [](uint32_t b) {
                return b ^ rotl(b, 13) ^ rotl(b, 23);
                };

            // 初始化 T_table 和 Tp_table
            for (int i = 0; i < 256; i++) {
                uint32_t s = SM4_SBOX[i];

                // 加密表
                T_table[0][i] = L_transform(s << 24);
                T_table[1][i] = L_transform(s << 16);
                T_table[2][i] = L_transform(s << 8);
                T_table[3][i] = L_transform(s);

                // 密钥扩展表
                Tp_table[0][i] = Lp_transform(s << 24);
                Tp_table[1][i] = Lp_transform(s << 16);
                Tp_table[2][i] = Lp_transform(s << 8);
                Tp_table[3][i] = Lp_transform(s);
            }
        }
    };

    
    inline void EnsureTablesInitialized() {
        static SM4_TableInitializer initializer;
    }

} 

// SM4 密钥结构体
struct SM4_Key {
    uint32_t rk[32]; // 32轮密钥

    // 设置轮密钥为常量值（用于清零）
    void clear() noexcept {
        for (auto& v : rk) v = 0;
    }
};

// 密钥初始化函数
inline int SM4_KeyInit(const uint8_t* key, SM4_Key* sm4_key) noexcept {
    if (!key || !sm4_key) return -1;

    
    EnsureTablesInitialized();

    // 加载主密钥
    uint32_t MK[4];
    memcpy(MK, key, 16);

    // 初始变换: K = MK ^ FK
    uint32_t K[4];
    for (int i = 0; i < 4; i++) {
        K[i] = MK[i] ^ FK[i];
    }

    // 轮密钥生成
    for (int i = 0; i < 32; i++) {
        // 中间值: tmp = K1 ^ K2 ^ K3 ^ CK[i]
        uint32_t tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];

        // T' 变换: 应用S盒和L'变换
        tmp = Tp_table[0][(tmp >> 24) & 0xFF] ^
            Tp_table[1][(tmp >> 16) & 0xFF] ^
            Tp_table[2][(tmp >> 8) & 0xFF] ^
            Tp_table[3][tmp & 0xFF];

        // 轮密钥: rk[i] = tmp ^ K0
        sm4_key->rk[i] = tmp ^ K[0];

        // 更新密钥状态: [K0, K1, K2, K3] = [K1, K2, K3, rk[i]]
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = sm4_key->rk[i];
    }

    return 0;
}

// SIMD T_transform 函数 (AVX2 实现)
inline __m256i T_transform(__m256i input) noexcept {
    const __m256i mask = _mm256_set1_epi32(0xFF);

    // 提取4个字节位置
    __m256i in0 = _mm256_srli_epi32(input, 24);        // 字节0 (MSB)
    __m256i in1 = _mm256_srli_epi32(input, 16);
    in1 = _mm256_and_si256(in1, mask);
    __m256i in2 = _mm256_srli_epi32(input, 8);
    in2 = _mm256_and_si256(in2, mask);
    __m256i in3 = _mm256_and_si256(input, mask);        // 字节3 (LSB)

    // AVX2 gather 指令并行查表
    __m256i t0 = _mm256_i32gather_epi32(
        reinterpret_cast<const int*>(T_table[0]), in0, 4);
    __m256i t1 = _mm256_i32gather_epi32(
        reinterpret_cast<const int*>(T_table[1]), in1, 4);
    __m256i t2 = _mm256_i32gather_epi32(
        reinterpret_cast<const int*>(T_table[2]), in2, 4);
    __m256i t3 = _mm256_i32gather_epi32(
        reinterpret_cast<const int*>(T_table[3]), in3, 4);

    // 合并结果: t0 ⊕ t1 ⊕ t2 ⊕ t3
    __m256i res = _mm256_xor_si256(t0, t1);
    res = _mm256_xor_si256(res, t2);
    return _mm256_xor_si256(res, t3);
}

// SM4 8路并行加密
inline void SM4_Encrypt_x8(const uint8_t* plaintext,
    uint8_t* ciphertext,
    const SM4_Key* sm4_key) noexcept {
    // 确保查找表已初始化
    EnsureTablesInitialized();

    // 加载8组128位消息 (共128字节)
    __m256i X0 = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(plaintext + 0));
    __m256i X1 = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(plaintext + 32));
    __m256i X2 = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(plaintext + 64));
    __m256i X3 = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(plaintext + 96));

    // 32轮Feistel迭代
    for (int r = 0; r < 32; r++) {
        // 加载轮密钥 (复制8份)
        __m256i rk = _mm256_set1_epi32(sm4_key->rk[r]);

        // Temp = X1 ⊕ X2 ⊕ X3 ⊕ rk
        __m256i Temp = _mm256_xor_si256(X1, X2);
        Temp = _mm256_xor_si256(Temp, X3);
        Temp = _mm256_xor_si256(Temp, rk);

        // T变换
        Temp = T_transform(Temp);

        // Temp = Temp ⊕ X0
        Temp = _mm256_xor_si256(Temp, X0);

        // 更新寄存器: (X0, X1, X2, X3) ← (X1, X2, X3, Temp)
        X0 = X1;
        X1 = X2;
        X2 = X3;
        X3 = Temp;
    }

    // 最终反序变换: [X0, X1, X2, X3] -> [X3, X2, X1, X0]
    __m256i tmp = X0;
    X0 = X3;
    X3 = tmp;
    tmp = X1;
    X1 = X2;
    X2 = tmp;

    // 写回密文
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(ciphertext + 0), X0);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(ciphertext + 32), X1);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(ciphertext + 64), X2);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(ciphertext + 96), X3);
}

// SM4 8路并行解密
inline void SM4_Decrypt_x8(const uint8_t* ciphertext,
    uint8_t* plaintext,
    const SM4_Key* sm4_key) noexcept {
    
    EnsureTablesInitialized();

    // 创建逆序轮密钥
    SM4_Key reversed_key;
    for (int i = 0; i < 32; i++) {
        reversed_key.rk[i] = sm4_key->rk[31 - i];
    }

    // 使用相同的加密流程
    SM4_Encrypt_x8(ciphertext, plaintext, &reversed_key);
}

// 密钥删除 (安全清零)
inline void SM4_KeyDelete(SM4_Key* sm4_key) noexcept {
    if (sm4_key) {
        sm4_key->clear();
    }
}
