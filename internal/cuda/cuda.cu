/*
 * cuda.cu — GYhost 公共 NVIDIA CUDA 库实现。
 *
 * 结构（自上而下）：
 *   1. 编译期工具：__host__ __device__ 函数宏、常量表宏、长度上限
 *   2. 摘要原语：MD5 / SHA-256 / SHA-512 的增量式上下文（init/update/final）
 *   3. crypt 编码：crypt base64 + 置换表
 *   4. 算法核心：md5crypt($1$)、sha256crypt($5$)、sha512crypt($6$)
 *      —— 全部写成 __host__ __device__，主机参考实现与 GPU 内核共用一份代码
 *   5. GPU 内核：一个线程校验一个候选密码
 *   6. extern "C" 主机接口（见 cuda.h）
 *
 * 算法口径与 internal/pwdhash 使用的 go-crypt/x 保持逐字节一致，
 * 任何一边跑出来的密文都必须完全相同。
 *
 * 设计参考了项目内 cuda_kernel/cuda_kernel.cu 的哈希原语写法。
 */

#include "cuda.h"

#include <cuda_runtime.h>

#include <cstdio>
#include <cstring>

/* ------------------------------------------------------------------ *
 * 1. 编译期工具                                                       *
 * ------------------------------------------------------------------ */

/*
 * GY_HOSTDEV：算法核心同时供主机与设备调用。
 *   - 设备编译（__CUDA_ARCH__ 已定义）时是 __host__ __device__
 *   - 主机编译时是普通函数
 * GY_TABLE：常量表在设备端放进 constant memory（免去每线程重复初始化），
 *           在主机端就是普通静态常量。
 */
#if defined(__CUDA_ARCH__)
#define GY_HOSTDEV __host__ __device__
#define GY_TABLE(T, name, ...) __device__ __constant__ T name[] = {__VA_ARGS__}
#else
#define GY_HOSTDEV
#define GY_TABLE(T, name, ...) static const T name[] = {__VA_ARGS__}
#endif

/* 单个候选密码 / 盐的长度上限（与 cuda.go 中的 MaxPasswordLen/MaxSaltLen 一致） */
#define GY_MAX_PW 255
#define GY_MAX_SALT 64
/* 每次内核发射处理的候选数：限制每线程的局部内存占用 */
#define GY_CHUNK 8192
#define GY_BLOCK 256

/* memcpy / strcmp 的设备安全替代实现 */
GY_HOSTDEV inline void gy_copy(void *dst, const void *src, int n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (int i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

/* 两个 NUL 结尾字符串是否相等（用于密文比对） */
GY_HOSTDEV inline int gy_streq(const char *a, const char *b) {
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

/* ------------------------------------------------------------------ *
 * 2. 摘要原语                                                         *
 * ------------------------------------------------------------------ */

/* ============================ MD5 ============================ */

struct GyMD5Ctx {
    uint32_t state[4];
    uint64_t nbytes;
    uint8_t buf[64];
    int buflen;
};

GY_TABLE(unsigned int, gy_md5_s,
         7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21);

GY_TABLE(uint32_t, gy_md5_k,
         0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
         0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
         0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
         0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
         0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
         0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
         0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
         0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
         0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
         0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
         0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
         0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
         0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
         0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
         0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
         0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391);

GY_HOSTDEV void gy_md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }

    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (b & d) | (c & (~d));
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        uint32_t sum = a + f + gy_md5_k[i] + x[g];
        uint32_t rot = (sum << gy_md5_s[i]) | (sum >> (32 - gy_md5_s[i]));
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rot;
        a = tmp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

GY_HOSTDEV void gy_md5_init(GyMD5Ctx *c) {
    c->state[0] = 0x67452301u;
    c->state[1] = 0xefcdab89u;
    c->state[2] = 0x98badcfeu;
    c->state[3] = 0x10325476u;
    c->nbytes = 0;
    c->buflen = 0;
}

GY_HOSTDEV void gy_md5_update(GyMD5Ctx *c, const void *data, int n) {
    const uint8_t *p = (const uint8_t *)data;
    c->nbytes += (uint64_t)n;
    while (n > 0) {
        int take = 64 - c->buflen;
        if (take > n) {
            take = n;
        }
        gy_copy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            gy_md5_transform(c->state, c->buf);
            c->buflen = 0;
        }
    }
}

GY_HOSTDEV void gy_md5_final(GyMD5Ctx *c, uint8_t out[16]) {
    const uint64_t bits = c->nbytes << 3;
    const uint8_t pad = 0x80;
    const uint8_t zero = 0;
    uint8_t lenb[8];
    int i;

    gy_md5_update(c, &pad, 1);
    while (c->buflen != 56) {
        gy_md5_update(c, &zero, 1);
    }
    for (i = 0; i < 8; i++) {
        lenb[i] = (uint8_t)(bits >> (8 * i));
    }
    gy_md5_update(c, lenb, 8);

    for (i = 0; i < 4; i++) {
        out[i * 4 + 0] = (uint8_t)(c->state[i]);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(c->state[i] >> 24);
    }
}

/* ============================ SHA-256 ============================ */

struct GySHA256Ctx {
    uint32_t state[8];
    uint64_t nbytes;
    uint8_t buf[64];
    int buflen;
};

GY_TABLE(uint32_t, gy_sha256_k,
         0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2);

GY_HOSTDEV inline uint32_t gy_rotr32(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

GY_HOSTDEV void gy_sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = gy_rotr32(w[i - 15], 7) ^ gy_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = gy_rotr32(w[i - 2], 17) ^ gy_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int t = 0; t < 64; t++) {
        uint32_t bsig1 = gy_rotr32(e, 6) ^ gy_rotr32(e, 11) ^ gy_rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + bsig1 + ch + gy_sha256_k[t] + w[t];
        uint32_t bsig0 = gy_rotr32(a, 2) ^ gy_rotr32(a, 13) ^ gy_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = bsig0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

GY_HOSTDEV void gy_sha256_init(GySHA256Ctx *c) {
    c->state[0] = 0x6a09e667u;
    c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u;
    c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu;
    c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu;
    c->state[7] = 0x5be0cd19u;
    c->nbytes = 0;
    c->buflen = 0;
}

GY_HOSTDEV void gy_sha256_update(GySHA256Ctx *c, const void *data, int n) {
    const uint8_t *p = (const uint8_t *)data;
    c->nbytes += (uint64_t)n;
    while (n > 0) {
        int take = 64 - c->buflen;
        if (take > n) {
            take = n;
        }
        gy_copy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            gy_sha256_transform(c->state, c->buf);
            c->buflen = 0;
        }
    }
}

GY_HOSTDEV void gy_sha256_final(GySHA256Ctx *c, uint8_t out[32]) {
    const uint64_t bits = c->nbytes << 3;
    const uint8_t pad = 0x80;
    const uint8_t zero = 0;
    int i;

    gy_sha256_update(c, &pad, 1);
    while (c->buflen != 56) {
        gy_sha256_update(c, &zero, 1);
    }
    for (i = 0; i < 8; i++) {
        c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    gy_sha256_transform(c->state, c->buf);

    for (i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

/* ============================ SHA-512 ============================ */

struct GySHA512Ctx {
    uint64_t state[8];
    uint64_t nbytes;
    uint8_t buf[128];
    int buflen;
};

GY_TABLE(uint64_t, gy_sha512_k,
         0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
         0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
         0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
         0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
         0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
         0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
         0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
         0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
         0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
         0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
         0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
         0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
         0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
         0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
         0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
         0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
         0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
         0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
         0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
         0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL);

GY_HOSTDEV inline uint64_t gy_rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

GY_HOSTDEV void gy_sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i * 8] << 56) | ((uint64_t)block[i * 8 + 1] << 48) |
               ((uint64_t)block[i * 8 + 2] << 40) | ((uint64_t)block[i * 8 + 3] << 32) |
               ((uint64_t)block[i * 8 + 4] << 24) | ((uint64_t)block[i * 8 + 5] << 16) |
               ((uint64_t)block[i * 8 + 6] << 8) | (uint64_t)block[i * 8 + 7];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = gy_rotr64(w[i - 15], 1) ^ gy_rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = gy_rotr64(w[i - 2], 19) ^ gy_rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int t = 0; t < 80; t++) {
        uint64_t bsig1 = gy_rotr64(e, 14) ^ gy_rotr64(e, 18) ^ gy_rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = h + bsig1 + ch + gy_sha512_k[t] + w[t];
        uint64_t bsig0 = gy_rotr64(a, 28) ^ gy_rotr64(a, 34) ^ gy_rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = bsig0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

GY_HOSTDEV void gy_sha512_init(GySHA512Ctx *c) {
    c->state[0] = 0x6a09e667f3bcc908ULL;
    c->state[1] = 0xbb67ae8584caa73bULL;
    c->state[2] = 0x3c6ef372fe94f82bULL;
    c->state[3] = 0xa54ff53a5f1d36f1ULL;
    c->state[4] = 0x510e527fade682d1ULL;
    c->state[5] = 0x9b05688c2b3e6c1fULL;
    c->state[6] = 0x1f83d9abfb41bd6bULL;
    c->state[7] = 0x5be0cd19137e2179ULL;
    c->nbytes = 0;
    c->buflen = 0;
}

GY_HOSTDEV void gy_sha512_update(GySHA512Ctx *c, const void *data, int n) {
    const uint8_t *p = (const uint8_t *)data;
    c->nbytes += (uint64_t)n;
    while (n > 0) {
        int take = 128 - c->buflen;
        if (take > n) {
            take = n;
        }
        gy_copy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 128) {
            gy_sha512_transform(c->state, c->buf);
            c->buflen = 0;
        }
    }
}

/* SHA-384 与 SHA-512 的区别只有初始向量与输出长度，共用同一套压缩函数 */
GY_HOSTDEV void gy_sha384_init(GySHA512Ctx *c) {
    c->nbytes = 0;
    c->buflen = 0;
    c->state[0] = 0xcbbb9d5dc1059ed8ULL;
    c->state[1] = 0x629a292a367cd507ULL;
    c->state[2] = 0x9159015a3070dd17ULL;
    c->state[3] = 0x152fecd8f70e5939ULL;
    c->state[4] = 0x67332667ffc00b31ULL;
    c->state[5] = 0x8eb44a8768581511ULL;
    c->state[6] = 0xdb0c2e0d64f98fa7ULL;
    c->state[7] = 0x47b5481dbefa4fa4ULL;
}

GY_HOSTDEV void gy_sha512_final_n(GySHA512Ctx *c, uint8_t *out, int outlen) {
    const uint64_t hi = c->nbytes >> 61;
    const uint64_t lo = c->nbytes << 3;
    const uint8_t pad = 0x80;
    const uint8_t zero = 0;
    int i;

    gy_sha512_update(c, &pad, 1);
    while (c->buflen != 112) {
        gy_sha512_update(c, &zero, 1);
    }
    for (i = 0; i < 8; i++) {
        c->buf[112 + i] = (uint8_t)(hi >> (56 - 8 * i));
    }
    for (i = 0; i < 8; i++) {
        c->buf[120 + i] = (uint8_t)(lo >> (56 - 8 * i));
    }
    gy_sha512_transform(c->state, c->buf);

    /* SHA-384 取状态前 48 字节，SHA-512 取 64 字节 */
    for (i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(c->state[i >> 3] >> (56 - 8 * (i & 7)));
    }
}

GY_HOSTDEV void gy_sha512_final(GySHA512Ctx *c, uint8_t out[64]) {
    gy_sha512_final_n(c, out, 64);
}

GY_HOSTDEV void gy_sha384_final(GySHA512Ctx *c, uint8_t out[48]) {
    gy_sha512_final_n(c, out, 48);
}

/* ------------------------------------------------------------------ *
 * 3. crypt 编码                                                       *
 * ------------------------------------------------------------------ */

/* 6 位值 -> crypt base64 字符（算术映射，免去设备端常量表寻址） */
GY_HOSTDEV inline char gy_b64ch(unsigned int v) {
    v &= 0x3f;
    if (v < 12) {
        return (char)('.' + v); /* . / 0-9 */
    }
    if (v < 38) {
        return (char)('A' + v - 12); /* A-Z */
    }
    return (char)('a' + v - 38); /* a-z */
}

/*
 * crypt base64：字母表 "./0123456789A-Za-z"，
 * 每 3 字节按低位优先切 4 个 6 位值（与 glibc crypt 一致）。
 * 输出 NUL 结尾，返回字符数。
 */
GY_HOSTDEV int gy_crypt_b64(const uint8_t *src, int len, char *out) {
    int idst = 0;
    int isrc = 0;

    for (; isrc < len / 3 * 3; isrc += 3) {
        unsigned int v = ((unsigned int)src[isrc + 2] << 16) |
                         ((unsigned int)src[isrc + 1] << 8) |
                         (unsigned int)src[isrc];
        out[idst++] = gy_b64ch(v & 0x3f);
        out[idst++] = gy_b64ch((v >> 6) & 0x3f);
        out[idst++] = gy_b64ch((v >> 12) & 0x3f);
        out[idst++] = gy_b64ch((v >> 18) & 0x3f);
    }

    int rem = len - isrc;
    if (rem == 1) {
        unsigned int v = (unsigned int)src[isrc];
        out[idst++] = gy_b64ch(v & 0x3f);
        out[idst++] = gy_b64ch((v >> 6) & 0x3f);
    } else if (rem == 2) {
        unsigned int v = (unsigned int)src[isrc] | ((unsigned int)src[isrc + 1] << 8);
        out[idst++] = gy_b64ch(v & 0x3f);
        out[idst++] = gy_b64ch((v >> 6) & 0x3f);
        out[idst++] = gy_b64ch((v >> 12) & 0x3f);
    }

    out[idst] = '\0';
    return idst;
}

/* 各算法的最终置换表（顺序与 go-crypt/x 的 permuteTable* 一致） */
GY_TABLE(int, gy_perm_md5, 12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11);

GY_TABLE(int, gy_perm_sha256,
         20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5,
         25, 15, 26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31);

GY_TABLE(int, gy_perm_sha512,
         42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26,
         5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52,
         31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
         16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63);

/* 置换 + crypt base64 编码，输出 NUL 结尾的密文 */
GY_HOSTDEV int gy_encode_key(int hlen, const uint8_t *sum, char *out) {
    uint8_t perm[64];
    const int *tbl = NULL;

    if (hlen == 16) {
        tbl = gy_perm_md5;
    } else if (hlen == 32) {
        tbl = gy_perm_sha256;
    } else if (hlen == 64) {
        tbl = gy_perm_sha512;
    } else {
        out[0] = '\0';
        return 0;
    }

    for (int i = 0; i < hlen; i++) {
        perm[i] = sum[tbl[i]];
    }
    return gy_crypt_b64(perm, hlen, out);
}

/* ------------------------------------------------------------------ *
 * 4. 算法核心                                                         *
 * ------------------------------------------------------------------ */

/*
 * md5crypt（$1$）：与 go-crypt/x 的 crypt.KeyMD5Crypt 逐字节一致。
 * 返回 1 命中 / 0 未命中 / -1 参数非法。
 */
GY_HOSTDEV int gy_md5crypt_check(const char *pw, int pwlen, const char *salt, int saltlen,
                                 const char *key) {
    if (pwlen < 0 || pwlen > GY_MAX_PW || saltlen < 0 || saltlen > GY_MAX_SALT) {
        return -1;
    }

    GyMD5Ctx ctx;
    uint8_t sumB[16], sumA[16], tmp[16], rep[GY_MAX_PW];
    char out[24];

    /* sumB = MD5(P || S || P) */
    gy_md5_init(&ctx);
    gy_md5_update(&ctx, pw, pwlen);
    gy_md5_update(&ctx, salt, saltlen);
    gy_md5_update(&ctx, pw, pwlen);
    gy_md5_final(&ctx, sumB);

    /* sumA = MD5(P || "$1$" || S || repeat(sumB, len(P)) || 位循环) */
    gy_md5_init(&ctx);
    gy_md5_update(&ctx, pw, pwlen);
    gy_md5_update(&ctx, "$1$", 3);
    gy_md5_update(&ctx, salt, saltlen);
    for (int i = 0; i < pwlen; i++) {
        rep[i] = sumB[i % 16];
    }
    gy_md5_update(&ctx, rep, pwlen);
    for (int i = pwlen; i > 0; i >>= 1) {
        const uint8_t b = ((i & 1) == 0) ? (uint8_t)pw[0] : (uint8_t)0;
        gy_md5_update(&ctx, &b, 1);
    }
    gy_md5_final(&ctx, sumA);

    /* 1000 轮迭代 */
    for (int i = 0; i < 1000; i++) {
        gy_md5_init(&ctx);
        if ((i & 1) == 0) {
            gy_md5_update(&ctx, sumA, 16);
        } else {
            gy_md5_update(&ctx, pw, pwlen);
        }
        if (i % 3 != 0) {
            gy_md5_update(&ctx, salt, saltlen);
        }
        if (i % 7 != 0) {
            gy_md5_update(&ctx, pw, pwlen);
        }
        if ((i & 1) == 0) {
            gy_md5_update(&ctx, pw, pwlen);
        } else {
            gy_md5_update(&ctx, sumA, 16);
        }
        gy_md5_final(&ctx, tmp);
        gy_copy(sumA, tmp, 16);
    }

    gy_encode_key(16, sumA, out);
    return gy_streq(out, key) ? 1 : 0;
}

/* SHA-crypt 策略：把 256/512 两套差异（上下文类型、摘要长度、置换表）收敛到一个模板 */
struct GySHA256Policy {
    typedef GySHA256Ctx Ctx;
    enum { HLEN = 32 };
    static GY_HOSTDEV void init(Ctx &c) { gy_sha256_init(&c); }
    static GY_HOSTDEV void update(Ctx &c, const void *p, int n) { gy_sha256_update(&c, p, n); }
    static GY_HOSTDEV void final(Ctx &c, uint8_t *out) { gy_sha256_final(&c, out); }
};

struct GySHA512Policy {
    typedef GySHA512Ctx Ctx;
    enum { HLEN = 64 };
    static GY_HOSTDEV void init(Ctx &c) { gy_sha512_init(&c); }
    static GY_HOSTDEV void update(Ctx &c, const void *p, int n) { gy_sha512_update(&c, p, n); }
    static GY_HOSTDEV void final(Ctx &c, uint8_t *out) { gy_sha512_final(&c, out); }
};

/*
 * sha256crypt($5$) / sha512crypt($6$)：与 go-crypt/x 的 crypt.KeySHACrypt 一致。
 * 返回 1 命中 / 0 未命中 / -1 参数非法。
 */
template <class P>
GY_HOSTDEV int gy_shacrypt_check(const char *pw, int pwlen, const char *salt, int saltlen,
                                 int rounds, const char *key) {
    if (pwlen < 0 || pwlen > GY_MAX_PW || saltlen < 0 || saltlen > GY_MAX_SALT) {
        return -1;
    }
    if (rounds < 0) {
        return -1;
    }

    const int H = P::HLEN;
    typename P::Ctx ctx;
    uint8_t sumA[64], sumB[64], sumDP[64], sumDS[64], tmp[64];
    uint8_t rep[GY_MAX_PW], seqP[GY_MAX_PW], seqS[GY_MAX_SALT];
    char out[96];

    /* sumB = H(P || S || P) */
    P::init(ctx);
    P::update(ctx, pw, pwlen);
    P::update(ctx, salt, saltlen);
    P::update(ctx, pw, pwlen);
    P::final(ctx, sumB);

    /* sumA = H(P || S || repeat(sumB, len(P)) || 位循环) */
    P::init(ctx);
    P::update(ctx, pw, pwlen);
    P::update(ctx, salt, saltlen);
    for (int i = 0; i < pwlen; i++) {
        rep[i] = sumB[i % H];
    }
    P::update(ctx, rep, pwlen);
    for (int i = pwlen; i > 0; i >>= 1) {
        if ((i & 1) == 0) {
            P::update(ctx, pw, pwlen);
        } else {
            P::update(ctx, sumB, H);
        }
    }
    P::final(ctx, sumA);

    /* sumDP = H(P 重复 len(P) 次)，seqP = repeat(sumDP, len(P)) */
    P::init(ctx);
    for (int i = 0; i < pwlen; i++) {
        P::update(ctx, pw, pwlen);
    }
    P::final(ctx, sumDP);
    for (int i = 0; i < pwlen; i++) {
        seqP[i] = sumDP[i % H];
    }

    /* sumDS = H(S 重复 16+sumA[0] 次)，seqS = repeat(sumDS, len(S)) */
    P::init(ctx);
    for (int i = 0; i < 16 + (int)sumA[0]; i++) {
        P::update(ctx, salt, saltlen);
    }
    P::final(ctx, sumDS);
    for (int i = 0; i < saltlen; i++) {
        seqS[i] = sumDS[i % H];
    }

    /* 主循环：rounds 轮 */
    for (int i = 0; i < rounds; i++) {
        P::init(ctx);
        if ((i & 1) != 0) {
            P::update(ctx, seqP, pwlen);
        } else {
            P::update(ctx, sumA, H);
        }
        if (i % 3 != 0) {
            P::update(ctx, seqS, saltlen);
        }
        if (i % 7 != 0) {
            P::update(ctx, seqP, pwlen);
        }
        if ((i & 1) != 0) {
            P::update(ctx, sumA, H);
        } else {
            P::update(ctx, seqP, pwlen);
        }
        P::final(ctx, tmp);
        gy_copy(sumA, tmp, H);
    }

    gy_encode_key(H, sumA, out);
    return gy_streq(out, key) ? 1 : 0;
}

/* ------------------------------------------------------------------ *
 * 4b. 通用哈希校验（hashac 模块）：SHA-1 / HMAC / PBKDF2 / 算法分派   *
 * ------------------------------------------------------------------ */

/* ============================ SHA-1 ============================ */

struct GySHA1Ctx {
    uint32_t state[5];
    uint64_t nbytes;
    uint8_t buf[64];
    int buflen;
};

/*
 * gy_sha1_transform_x — 标准 SHA-1 块变换，可选导出消息扩展字 W[64..80]。
 * RAR3 的交织哈希（sha1_process_rar29）需要把扩展字写回输入缓冲区。
 */
GY_HOSTDEV void gy_sha1_transform_x(uint32_t state[5], const uint8_t block[64],
                                    uint32_t w64[16]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++) {
        uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (v << 1) | (v >> 31);
    }
    if (w64 != NULL) {
        for (int i = 0; i < 16; i++) {
            w64[i] = w[64 + i];
        }
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        uint32_t tmp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = tmp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

GY_HOSTDEV void gy_sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    gy_sha1_transform_x(state, block, NULL);
}

GY_HOSTDEV void gy_sha1_init(GySHA1Ctx *c) {
    c->state[0] = 0x67452301u;
    c->state[1] = 0xefcdab89u;
    c->state[2] = 0x98badcfeu;
    c->state[3] = 0x10325476u;
    c->state[4] = 0xc3d2e1f0u;
    c->nbytes = 0;
    c->buflen = 0;
}

GY_HOSTDEV void gy_sha1_update(GySHA1Ctx *c, const void *data, int n) {
    const uint8_t *p = (const uint8_t *)data;
    c->nbytes += (uint64_t)n;
    while (n > 0) {
        int take = 64 - c->buflen;
        if (take > n) {
            take = n;
        }
        gy_copy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            gy_sha1_transform(c->state, c->buf);
            c->buflen = 0;
        }
    }
}

GY_HOSTDEV void gy_sha1_final(GySHA1Ctx *c, uint8_t out[20]) {
    const uint64_t bits = c->nbytes << 3;
    const uint8_t pad = 0x80;
    const uint8_t zero = 0;
    int i;

    gy_sha1_update(c, &pad, 1);
    while (c->buflen != 56) {
        gy_sha1_update(c, &zero, 1);
    }
    for (i = 0; i < 8; i++) {
        c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    gy_sha1_transform(c->state, c->buf);

    for (i = 0; i < 5; i++) {
        out[i * 4 + 0] = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

/* 定长比较：返回 1 表示完全相同。 */
GY_HOSTDEV int gy_memeq(const uint8_t *a, const uint8_t *b, int n) {
    uint8_t diff = 0;
    for (int i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 1 : 0;
}

/* ============================ HMAC ============================ */

GY_HOSTDEV void gy_hmac_sha1(const uint8_t *key, int keylen,
                              const uint8_t *data, int datalen, uint8_t out[20]) {
    uint8_t k[64], ipad[64], opad[64], inner[20];
    GySHA1Ctx c;

    for (int i = 0; i < 64; i++) {
        k[i] = 0;
    }
    if (keylen > 64) {
        GySHA1Ctx kc;
        gy_sha1_init(&kc);
        gy_sha1_update(&kc, key, keylen);
        gy_sha1_final(&kc, k);
    } else {
        for (int i = 0; i < keylen; i++) {
            k[i] = key[i];
        }
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    gy_sha1_init(&c);
    gy_sha1_update(&c, ipad, 64);
    gy_sha1_update(&c, data, datalen);
    gy_sha1_final(&c, inner);

    gy_sha1_init(&c);
    gy_sha1_update(&c, opad, 64);
    gy_sha1_update(&c, inner, 20);
    gy_sha1_final(&c, out);
}

GY_HOSTDEV void gy_hmac_sha256(const uint8_t *key, int keylen,
                                const uint8_t *data, int datalen, uint8_t out[32]) {
    uint8_t k[64], ipad[64], opad[64], inner[32];
    GySHA256Ctx c;

    for (int i = 0; i < 64; i++) {
        k[i] = 0;
    }
    if (keylen > 64) {
        GySHA256Ctx kc;
        gy_sha256_init(&kc);
        gy_sha256_update(&kc, key, keylen);
        gy_sha256_final(&kc, k);
    } else {
        for (int i = 0; i < keylen; i++) {
            k[i] = key[i];
        }
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    gy_sha256_init(&c);
    gy_sha256_update(&c, ipad, 64);
    gy_sha256_update(&c, data, datalen);
    gy_sha256_final(&c, inner);

    gy_sha256_init(&c);
    gy_sha256_update(&c, opad, 64);
    gy_sha256_update(&c, inner, 32);
    gy_sha256_final(&c, out);
}

/* HMAC-MD5（WPA keyver 1 的 EAPOL MIC） */
GY_HOSTDEV void gy_hmac_md5(const uint8_t *key, int keylen,
                            const uint8_t *data, int datalen, uint8_t out[16]) {
    uint8_t k[64], ipad[64], opad[64], inner[16];
    GyMD5Ctx c;

    for (int i = 0; i < 64; i++) {
        k[i] = 0;
    }
    if (keylen > 64) {
        GyMD5Ctx kc;
        gy_md5_init(&kc);
        gy_md5_update(&kc, key, keylen);
        gy_md5_final(&kc, k);
    } else {
        for (int i = 0; i < keylen; i++) {
            k[i] = key[i];
        }
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }

    gy_md5_init(&c);
    gy_md5_update(&c, ipad, 64);
    gy_md5_update(&c, data, datalen);
    gy_md5_final(&c, inner);

    gy_md5_init(&c);
    gy_md5_update(&c, opad, 64);
    gy_md5_update(&c, inner, 16);
    gy_md5_final(&c, out);
}

/* 预计算 HMAC 的 ipad/opad 起始状态，供 PBKDF2 复用。 */
GY_HOSTDEV void gy_hmac_sha1_pads(const uint8_t *key, int keylen,
                                  GySHA1Ctx *innerBase, GySHA1Ctx *outerBase) {
    uint8_t k[64], ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        k[i] = 0;
    }
    if (keylen > 64) {
        GySHA1Ctx kc;
        gy_sha1_init(&kc);
        gy_sha1_update(&kc, key, keylen);
        gy_sha1_final(&kc, k);
    } else {
        for (int i = 0; i < keylen; i++) {
            k[i] = key[i];
        }
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    gy_sha1_init(innerBase);
    gy_sha1_update(innerBase, ipad, 64);
    gy_sha1_init(outerBase);
    gy_sha1_update(outerBase, opad, 64);
}

GY_HOSTDEV void gy_hmac_sha256_pads(const uint8_t *key, int keylen,
                                    GySHA256Ctx *innerBase, GySHA256Ctx *outerBase) {
    uint8_t k[64], ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        k[i] = 0;
    }
    if (keylen > 64) {
        GySHA256Ctx kc;
        gy_sha256_init(&kc);
        gy_sha256_update(&kc, key, keylen);
        gy_sha256_final(&kc, k);
    } else {
        for (int i = 0; i < keylen; i++) {
            k[i] = key[i];
        }
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    gy_sha256_init(innerBase);
    gy_sha256_update(innerBase, ipad, 64);
    gy_sha256_init(outerBase);
    gy_sha256_update(outerBase, opad, 64);
}

/* ============================ PBKDF2 ============================ */

/* PBKDF2-HMAC-SHA1（RFC 2898）。 */
GY_HOSTDEV void gy_pbkdf2_sha1(const uint8_t *pw, int pwlen,
                               const uint8_t *salt, int saltlen,
                               int iter, uint8_t *out, int outlen) {
    GySHA1Ctx innerBase, outerBase;
    gy_hmac_sha1_pads(pw, pwlen, &innerBase, &outerBase);

    int pos = 0;
    uint32_t idx = 1;
    while (pos < outlen) {
        uint8_t u[20], t[20], inner[20], ib[4];
        GySHA1Ctx c;

        ib[0] = (uint8_t)(idx >> 24);
        ib[1] = (uint8_t)(idx >> 16);
        ib[2] = (uint8_t)(idx >> 8);
        ib[3] = (uint8_t)(idx);

        /* U_1 = HMAC(pw, salt || idx) */
        c = innerBase;
        gy_sha1_update(&c, salt, saltlen);
        gy_sha1_update(&c, ib, 4);
        gy_sha1_final(&c, inner);
        c = outerBase;
        gy_sha1_update(&c, inner, 20);
        gy_sha1_final(&c, u);
        gy_copy(t, u, 20);

        /* U_2 .. U_c */
        for (int i = 1; i < iter; i++) {
            c = innerBase;
            gy_sha1_update(&c, u, 20);
            gy_sha1_final(&c, inner);
            c = outerBase;
            gy_sha1_update(&c, inner, 20);
            gy_sha1_final(&c, u);
            for (int j = 0; j < 20; j++) {
                t[j] ^= u[j];
            }
        }

        int take = outlen - pos;
        if (take > 20) {
            take = 20;
        }
        for (int j = 0; j < take; j++) {
            out[pos + j] = t[j];
        }
        pos += take;
        idx++;
    }
}

/* PBKDF2-HMAC-SHA256（块长 32 字节）。 */
GY_HOSTDEV void gy_pbkdf2_sha256(const uint8_t *pw, int pwlen,
                                 const uint8_t *salt, int saltlen,
                                 int iter, uint8_t *out, int outlen) {
    GySHA256Ctx innerBase, outerBase;
    gy_hmac_sha256_pads(pw, pwlen, &innerBase, &outerBase);

    int pos = 0;
    uint32_t idx = 1;
    while (pos < outlen) {
        uint8_t u[32], t[32], inner[32], ib[4];
        GySHA256Ctx c;

        ib[0] = (uint8_t)(idx >> 24);
        ib[1] = (uint8_t)(idx >> 16);
        ib[2] = (uint8_t)(idx >> 8);
        ib[3] = (uint8_t)(idx);

        /* U_1 = HMAC(pw, salt || idx) */
        c = innerBase;
        gy_sha256_update(&c, salt, saltlen);
        gy_sha256_update(&c, ib, 4);
        gy_sha256_final(&c, inner);
        c = outerBase;
        gy_sha256_update(&c, inner, 32);
        gy_sha256_final(&c, u);
        gy_copy(t, u, 32);

        /* U_2 .. U_c */
        for (int i = 1; i < iter; i++) {
            c = innerBase;
            gy_sha256_update(&c, u, 32);
            gy_sha256_final(&c, inner);
            c = outerBase;
            gy_sha256_update(&c, inner, 32);
            gy_sha256_final(&c, u);
            for (int j = 0; j < 32; j++) {
                t[j] ^= u[j];
            }
        }

        int take = outlen - pos;
        if (take > 32) {
            take = 32;
        }
        for (int j = 0; j < take; j++) {
            out[pos + j] = t[j];
        }
        pos += take;
        idx++;
    }
}

/* WPA2 PMK / WinZip AES 的固定迭代次数。 */
#define GY_WPA2_ITER 4096
#define GY_ZIP_AES_ITER 1000

/* ============================ RAR3 交织 SHA-1 ============================ */

/*
 * gy_sha1_update_rar29 — RAR3 的 "intertwined" SHA-1 更新（unrar sha1.cpp 逐行等价）。
 *
 * 与普通 update 的差别：完全落在输入内的 64 字节块被变换后，
 * 用该块自身的消息扩展字 W[64..80]（每个按小端 4 字节，对应 unrar 的 RawPut4）
 * 原地覆写。密码不超过 28 字符（RawPsw <= 64 字节）时永远不会触发写回。
 */
GY_HOSTDEV void gy_sha1_update_rar29(GySHA1Ctx *c, uint8_t *data, int len) {
    const int j = c->buflen;
    c->nbytes += (uint64_t)len;

    if (j + len > 63) {
        const int take = 64 - j;
        gy_copy(c->buf + j, data, take);
        gy_sha1_transform(c->state, c->buf); /* 补齐半块，不写回 */

        int i = take;
        for (; i + 63 < len; i += 64) {
            uint32_t t[16];
            gy_sha1_transform_x(c->state, data + i, t);
            for (int k = 0; k < 16; k++) {
                data[i + 4 * k + 0] = (uint8_t)(t[k]);
                data[i + 4 * k + 1] = (uint8_t)(t[k] >> 8);
                data[i + 4 * k + 2] = (uint8_t)(t[k] >> 16);
                data[i + 4 * k + 3] = (uint8_t)(t[k] >> 24);
            }
        }
        c->buflen = 0;
        if (len > i) {
            gy_copy(c->buf, data + i, len - i);
            c->buflen = len - i;
        }
        return;
    }
    if (len > 0) {
        gy_copy(c->buf + j, data, len);
        c->buflen = j + len;
    }
}

/* ============================ AES 解密 ============================ */

/* AES S 盒与逆 S 盒（FIPS-197） */
GY_TABLE(uint8_t, gy_aes_sbox,
         0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16);

GY_TABLE(uint8_t, gy_aes_inv_sbox,
         0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
         0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
         0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
         0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
         0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
         0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
         0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
         0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
         0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
         0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
         0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
         0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
         0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
         0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
         0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d);

/* GF(2^8) 乘法（用于逆列混淆） */
GY_HOSTDEV inline uint8_t gy_aes_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b != 0) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t hi = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (hi != 0) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

/* xtime / ×3：正向 MixColumns 只需要这两个常量乘法，展开成单步运算，
 * 比走 gy_aes_mul 的 8 轮逐位循环快得多（R=6 的 PDF 强化是本文件最热的路径）。 */
GY_HOSTDEV inline uint8_t gy_aes_xtime(uint8_t a) {
    return (uint8_t)((uint8_t)(a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}

GY_HOSTDEV inline uint8_t gy_aes_mul3(uint8_t a) {
    return (uint8_t)(gy_aes_xtime(a) ^ a);
}

GY_HOSTDEV inline void gy_aes_inv_mixcol(uint8_t *p) {
    const uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    p[0] = (uint8_t)(gy_aes_mul(a0, 14) ^ gy_aes_mul(a1, 11) ^ gy_aes_mul(a2, 13) ^ gy_aes_mul(a3, 9));
    p[1] = (uint8_t)(gy_aes_mul(a0, 9) ^ gy_aes_mul(a1, 14) ^ gy_aes_mul(a2, 11) ^ gy_aes_mul(a3, 13));
    p[2] = (uint8_t)(gy_aes_mul(a0, 13) ^ gy_aes_mul(a1, 9) ^ gy_aes_mul(a2, 14) ^ gy_aes_mul(a3, 11));
    p[3] = (uint8_t)(gy_aes_mul(a0, 11) ^ gy_aes_mul(a1, 13) ^ gy_aes_mul(a2, 9) ^ gy_aes_mul(a3, 14));
}

/* 解密轮密钥（等价逆密码：中间轮已预乘 InvMixColumns） */
struct GyAESKey {
    uint8_t rk[15][16];
    int nr; /* AES-128 = 10, AES-256 = 14 */
};

/* 轮密钥展开（FIPS-197 KeyExpansion），输出正向形式的轮密钥 */
GY_HOSTDEV void gy_aes_expand(GyAESKey *k, const uint8_t *key, int keybits) {
    const int nk = keybits / 32;
    if (nk != 4 && nk != 8) {
        k->nr = 0;
        return;
    }
    k->nr = nk + 6;
    const int nw = 4 * (k->nr + 1);

    uint32_t w[60];
    for (int i = 0; i < nk; i++) {
        w[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
    }
    uint8_t rcon = 1;
    for (int i = nk; i < nw; i++) {
        uint32_t t = w[i - 1];
        if (i % nk == 0) {
            t = (t << 8) | (t >> 24); /* RotWord */
            t = ((uint32_t)gy_aes_sbox[(t >> 24) & 0xff] << 24) |
                ((uint32_t)gy_aes_sbox[(t >> 16) & 0xff] << 16) |
                ((uint32_t)gy_aes_sbox[(t >> 8) & 0xff] << 8) |
                (uint32_t)gy_aes_sbox[t & 0xff];
            t ^= (uint32_t)rcon << 24;
            rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0));
        } else if (nk > 6 && i % nk == 4) {
            t = ((uint32_t)gy_aes_sbox[(t >> 24) & 0xff] << 24) |
                ((uint32_t)gy_aes_sbox[(t >> 16) & 0xff] << 16) |
                ((uint32_t)gy_aes_sbox[(t >> 8) & 0xff] << 8) |
                (uint32_t)gy_aes_sbox[t & 0xff];
        }
        w[i] = w[i - nk] ^ t;
    }

    for (int r = 0; r <= k->nr; r++) {
        for (int c = 0; c < 4; c++) {
            const uint32_t x = w[4 * r + c];
            k->rk[r][4 * c + 0] = (uint8_t)(x >> 24);
            k->rk[r][4 * c + 1] = (uint8_t)(x >> 16);
            k->rk[r][4 * c + 2] = (uint8_t)(x >> 8);
            k->rk[r][4 * c + 3] = (uint8_t)(x);
        }
    }
}

/* 解密轮密钥：把正向轮密钥的中间轮预乘 InvMixColumns（等价逆密码） */
GY_HOSTDEV void gy_aes_decrypt_key(GyAESKey *k, const uint8_t *key, int keybits) {
    gy_aes_expand(k, key, keybits);
    for (int r = 1; r < k->nr; r++) {
        for (int c = 0; c < 4; c++) {
            gy_aes_inv_mixcol(k->rk[r] + 4 * c);
        }
    }
}

/* 加密轮密钥：直接使用正向轮密钥 */
GY_HOSTDEV void gy_aes_encrypt_key(GyAESKey *k, const uint8_t *key, int keybits) {
    gy_aes_expand(k, key, keybits);
}

/* 正向 MixColumns（与 gy_aes_inv_mixcol 对应） */
GY_HOSTDEV inline void gy_aes_mixcol(uint8_t *p) {
    const uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    p[0] = (uint8_t)(gy_aes_xtime(a0) ^ gy_aes_mul3(a1) ^ a2 ^ a3);
    p[1] = (uint8_t)(a0 ^ gy_aes_xtime(a1) ^ gy_aes_mul3(a2) ^ a3);
    p[2] = (uint8_t)(a0 ^ a1 ^ gy_aes_xtime(a2) ^ gy_aes_mul3(a3));
    p[3] = (uint8_t)(gy_aes_mul3(a0) ^ a1 ^ a2 ^ gy_aes_xtime(a3));
}

/* AES 正向加密一块（FIPS-197；列主序 s[4c+j] = 第 c 列第 j 行） */
GY_HOSTDEV void gy_aes_encrypt_block(const GyAESKey *k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    uint8_t t;

    for (int i = 0; i < 16; i++) {
        s[i] = in[i] ^ k->rk[0][i];
    }
    for (int r = 1; r <= k->nr; r++) {
        for (int i = 0; i < 16; i++) {
            s[i] = gy_aes_sbox[s[i]];
        }
        /* ShiftRows：行 1/2/3 分别左移 1/2/3 */
        t = s[1];  s[1] = s[5];   s[5] = s[9];   s[9] = s[13];  s[13] = t;
        t = s[2];  s[2] = s[10];  s[10] = t;     t = s[6];      s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7] = s[3];   s[3] = t;
        if (r != k->nr) {
            for (int c = 0; c < 4; c++) {
                gy_aes_mixcol(s + 4 * c);
            }
        }
        for (int i = 0; i < 16; i++) {
            s[i] ^= k->rk[r][i];
        }
    }
    gy_copy(out, s, 16);
}

/*
 * AES-128-CMAC（RFC 4493），key 取前 16 字节。
 *
 * 用于 WPA2-SHA256（keyver 3）的 EAPOL MIC 计算；与 hashac 的 CPU 实现
 * aesCMAC 逐步对应（子密钥 K1/K2、末块补齐、CBC-MAC 链）。
 */
GY_HOSTDEV void gy_aes_cmac(const uint8_t *key, const uint8_t *msg, int msglen,
                            uint8_t out[16]) {
    GyAESKey k;
    uint8_t zero[16], l[16], k1[16], k2[16], last[16], x[16], tmp[16];

    gy_aes_encrypt_key(&k, key, 128);
    for (int i = 0; i < 16; i++) {
        zero[i] = 0;
    }
    gy_aes_encrypt_block(&k, zero, l);

    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        k1[i] = (uint8_t)((l[i] << 1) | carry);
        carry = (uint8_t)(l[i] >> 7);
    }
    if (carry) {
        k1[15] ^= 0x87;
    }
    carry = 0;
    for (int i = 15; i >= 0; i--) {
        k2[i] = (uint8_t)((k1[i] << 1) | carry);
        carry = (uint8_t)(k1[i] >> 7);
    }
    if (carry) {
        k2[15] ^= 0x87;
    }

    int n = (msglen + 15) / 16;
    if (n == 0) {
        n = 1;
    }
    const int complete = (msglen > 0 && (msglen % 16) == 0);
    if (complete) {
        for (int i = 0; i < 16; i++) {
            last[i] = (uint8_t)(msg[(n - 1) * 16 + i] ^ k1[i]);
        }
    } else {
        const int rem = msglen - (n - 1) * 16;
        for (int i = 0; i < 16; i++) {
            last[i] = 0;
        }
        for (int i = 0; i < rem; i++) {
            last[i] = msg[(n - 1) * 16 + i];
        }
        last[rem] = 0x80;
        for (int i = 0; i < 16; i++) {
            last[i] ^= k2[i];
        }
    }

    for (int i = 0; i < 16; i++) {
        x[i] = 0;
    }
    for (int b = 0; b < n - 1; b++) {
        for (int i = 0; i < 16; i++) {
            x[i] ^= msg[b * 16 + i];
        }
        gy_aes_encrypt_block(&k, x, tmp);
        gy_copy(x, tmp, 16);
    }
    for (int i = 0; i < 16; i++) {
        x[i] ^= last[i];
    }
    gy_aes_encrypt_block(&k, x, out);
}

GY_HOSTDEV void gy_aes_decrypt_block(const GyAESKey *k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    uint8_t t;

    for (int i = 0; i < 16; i++) {
        s[i] = in[i] ^ k->rk[k->nr][i];
    }
    for (int r = k->nr - 1; r >= 1; r--) {
        /* InvShiftRows（行 1/2/3 分别右移 1/2/3） */
        t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2];  s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3];  s[3] = s[7];  s[7] = s[11]; s[11] = s[15]; s[15] = t;
        for (int i = 0; i < 16; i++) {
            s[i] = gy_aes_inv_sbox[s[i]];
        }
        for (int i = 0; i < 16; i++) {
            s[i] ^= k->rk[r][i];
        }
        for (int c = 0; c < 4; c++) {
            gy_aes_inv_mixcol(s + 4 * c);
        }
    }
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2];  s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3];  s[3] = s[7];  s[7] = s[11]; s[11] = s[15]; s[15] = t;
    for (int i = 0; i < 16; i++) {
        out[i] = gy_aes_inv_sbox[s[i]] ^ k->rk[0][i];
    }
}

/* ============================ CRC-32 ============================ */

/* 标准 CRC-32（IEEE 802.3，逐位计算，无需常量表） */
GY_HOSTDEV uint32_t gy_crc32(const uint8_t *p, int n) {
    uint32_t c = 0xffffffffu;
    for (int i = 0; i < n; i++) {
        c ^= p[i];
        for (int b = 0; b < 8; b++) {
            const uint32_t mask = (c & 1) ? 0xedb88320u : 0;
            c = (c >> 1) ^ mask;
        }
    }
    return ~c;
}

/* ============================ RAR3 -hp ============================ */

/* RAR3 KDF 固定 2^18 轮；UTF-16LE 密码最多 64 个码元（与 hashcat 一致） */
#define GY_RAR3_ROUNDS 262144
#define GY_RAR3_MAX_PW16 128

/*
 * gy_rar3hp_check — RAR3 头加密（-hp，hashcat -m 12500）。
 *
 * 与 unrar crypt3.cpp SetKey30 / JtR rar_fmt.c 逐字节一致：
 *   1. RawPsw = pw_utf16le || salt(8)，连续 262144 轮
 *      "交织 SHA-1 更新(RawPsw) + 更新(LE24(i))"；
 *   2. 每 16384 轮对上下文副本做 SHA-1 final，取摘要最后一字节为 IV；
 *   3. 全部轮次结束后 final，AES 密钥 = 摘要前 16 字节按 4 字节逆序
 *      （unrar: AESKey[I*4+J] = digest[I] >> (8*J)）；
 *   4. AES-128-CBC 解密 16 字节密文头，前 7 字节应等于 -hp 归档主头明文
 *      常量 c4 3d 7b 00 40 07 00（由调用方经 check 传入）。
 */
GY_HOSTDEV int gy_rar3hp_check(const uint8_t *pw16, int pw16len,
                               const uint8_t *salt, int saltlen,
                               const uint8_t *crypted, int cryptedlen,
                               const uint8_t *check, int checklen) {
    if (saltlen != 8 || cryptedlen != 16 || checklen != 7) {
        return 0;
    }
    if (pw16len < 0 || pw16len > GY_RAR3_MAX_PW16) {
        return 0;
    }

    uint8_t raw[GY_RAR3_MAX_PW16 + 8]; /* RawPsw（写回不会越界） */
    gy_copy(raw, pw16, pw16len);
    gy_copy(raw + pw16len, salt, 8);
    const int rawlen = pw16len + 8;

    GySHA1Ctx c;
    gy_sha1_init(&c);
    uint8_t iv[16];
    for (uint32_t i = 0; i < GY_RAR3_ROUNDS; i++) {
        gy_sha1_update_rar29(&c, raw, rawlen);
        const uint8_t ctr[3] = {(uint8_t)i, (uint8_t)(i >> 8), (uint8_t)(i >> 16)};
        gy_sha1_update(&c, ctr, 3);
        if ((i & 0x3fffu) == 0) {
            GySHA1Ctx tmp = c;
            uint8_t dg[20];
            gy_sha1_final(&tmp, dg);
            iv[i >> 14] = dg[19];
        }
    }
    uint8_t dg[20];
    gy_sha1_final(&c, dg);

    uint8_t key[16];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            key[i * 4 + j] = dg[i * 4 + (3 - j)];
        }
    }

    GyAESKey ak;
    gy_aes_decrypt_key(&ak, key, 128);
    uint8_t plain[16];
    gy_aes_decrypt_block(&ak, crypted, plain);
    for (int i = 0; i < 16; i++) {
        plain[i] ^= iv[i];
    }
    return gy_memeq(plain, check, 7);
}

/* ============================ 7z AES-256 ============================ */

/* 7z 仅支持 Copy 编码器（未压缩）交给 GPU；UTF-16LE 密码最多 127 个码元 */
#define GY_7Z_MAX_PW16 254

/*
 * gy_7z_check — 7z AES-256 的 GPU 可校验子集（hashcat -m 11600，datatype 0）。
 *
 *   1. KDF: key = SHA256( concat_{i=0}^{2^power-1} ( salt || pw16 || LE32(i) || 00000000 ) )；
 *   2. AES-256-CBC 解密 Data，对前 unpack 字节计算 CRC32；
 *   3. Check 为 4 字节小端 CRC 值。
 * LZMA/Deflate 等需要解压校验的类型由调用方回退 CPU。
 */
GY_HOSTDEV int gy_7z_check(const uint8_t *pw16, int pw16len,
                           const uint8_t *salt, int saltlen,
                           const uint8_t *iv, int ivlen,
                           const uint8_t *data, int datalen,
                           const uint8_t *check, int checklen,
                           int power, int unpack) {
    if (ivlen != 16 || checklen != 4) {
        return 0;
    }
    if (datalen <= 0 || datalen > GYHOST_HASH_MAX_DATA || (datalen & 15) != 0) {
        return 0;
    }
    if (unpack <= 0 || unpack > datalen) {
        return 0;
    }
    if (power < 0 || power > 24) {
        return 0;
    }
    if (pw16len < 0 || pw16len > GY_7Z_MAX_PW16) {
        return 0;
    }

    uint8_t blk[GYHOST_HASH_MAX_SALT + GY_7Z_MAX_PW16 + 8];
    gy_copy(blk, salt, saltlen);
    gy_copy(blk + saltlen, pw16, pw16len);
    const int blen = saltlen + pw16len;
    blk[blen + 4] = 0;
    blk[blen + 5] = 0;
    blk[blen + 6] = 0;
    blk[blen + 7] = 0;

    GySHA256Ctx c;
    gy_sha256_init(&c);
    for (uint32_t i = 0; i < (1u << power); i++) {
        blk[blen + 0] = (uint8_t)i;
        blk[blen + 1] = (uint8_t)(i >> 8);
        blk[blen + 2] = (uint8_t)(i >> 16);
        blk[blen + 3] = (uint8_t)(i >> 24);
        gy_sha256_update(&c, blk, blen + 8);
    }
    uint8_t key[32];
    gy_sha256_final(&c, key);

    GyAESKey ak;
    gy_aes_decrypt_key(&ak, key, 256);

    uint8_t prev[16], dec[16];
    gy_copy(prev, iv, 16);
    uint32_t crc = 0xffffffffu;
    for (int off = 0; off < datalen; off += 16) {
        gy_aes_decrypt_block(&ak, data + off, dec);
        for (int j = 0; j < 16; j++) {
            const uint8_t p = (uint8_t)(dec[j] ^ prev[j]);
            if (off + j < unpack) {
                crc ^= p;
                for (int b = 0; b < 8; b++) {
                    const uint32_t mask = (crc & 1) ? 0xedb88320u : 0;
                    crc = (crc >> 1) ^ mask;
                }
            }
            prev[j] = data[off + j];
        }
    }
    crc = ~crc;

    const uint32_t want = (uint32_t)check[0] | ((uint32_t)check[1] << 8) |
                          ((uint32_t)check[2] << 16) | ((uint32_t)check[3] << 24);
    return crc == want ? 1 : 0;
}

/* ============================ ZipCrypto ============================ */

/* PKZIP 流密码的密钥更新；等价于查 CRC-32 表，此处逐位算出该表项。 */
GY_HOSTDEV uint32_t gy_zip_key_update(uint32_t key, uint8_t c) {
    uint32_t t = (key ^ c) & 0xffu;
    for (int b = 0; b < 8; b++) {
        t = (t & 1u) ? ((t >> 1) ^ 0xedb88320u) : (t >> 1);
    }
    return (key >> 8) ^ t;
}

/*
 * ZipCrypto 传统加密的 GPU 校验（hashcat -m 17200/17210）。
 *
 * Extra = 12 字节加密头 + 密文；Check 前 2 字节为 CS（小端）、后 2 字节为
 * TC（小端）；Iter = B，即头部已知明文的字节数（1 或 2）。
 *
 * 注意：这是弱校验（只比对头部 1~2 字节），命中后必须由 CPU 做完整的
 * CRC32 / 解压复核，否则会有误报。
 */
GY_HOSTDEV int gy_zipcrypto_check(const uint8_t *pw, int pwlen,
                                  const uint8_t *data, int datalen,
                                  const uint8_t *check, int checklen,
                                  int b) {
    if (checklen != 4 || datalen <= 12) {
        return 0;
    }
    if (b != 1 && b != 2) {
        return 0;
    }

    uint32_t k0 = 0x12345678u, k1 = 0x23456789u, k2 = 0x34567890u;
    for (int i = 0; i < pwlen; i++) {
        k0 = gy_zip_key_update(k0, (uint8_t)pw[i]);
        k1 = (k1 + (k0 & 0xffu)) * 134775813u + 1u;
        k2 = gy_zip_key_update(k2, (uint8_t)(k1 >> 24));
    }

    uint8_t plain[12];
    for (int i = 0; i < 12; i++) {
        const uint32_t temp = (k2 | 2u) & 0xffffu;
        const uint8_t ks = (uint8_t)(((temp * (temp ^ 1u)) >> 8) & 0xffu);
        const uint8_t p = (uint8_t)(data[i] ^ ks);
        k0 = gy_zip_key_update(k0, p);
        k1 = (k1 + (k0 & 0xffu)) * 134775813u + 1u;
        k2 = gy_zip_key_update(k2, (uint8_t)(k1 >> 24));
        plain[i] = p;
    }

    const uint16_t cs = (uint16_t)(check[0] | (check[1] << 8));
    const uint16_t tc = (uint16_t)(check[2] | (check[3] << 8));
    if (b == 1) {
        return (plain[11] == (uint8_t)(cs >> 8) || plain[11] == (uint8_t)(tc >> 8)) ? 1 : 0;
    }
    const uint16_t v = (uint16_t)(plain[10] | (plain[11] << 8));
    return (v == cs || v == tc) ? 1 : 0;
}

/* ============================ WPA/WPA2 四次握手 ============================ */

/*
 * WPA/WPA2 四次握手的 GPU 可校验子集（hashcat -m 22000 的 WPA*02*）。
 *
 * Extra 布局: MAC块(12) || ANonce(32) || EAPOL 帧(n)
 *   MAC块 = Min(AP,STA) || Max(AP,STA)，由调用方预先排好序；
 *   EAPOL 帧内的 SNonce 位于偏移 17..49，MIC 字段必须已置零。
 * Salt = ESSID，Check = MIC(16 字节)，Iter = keyver。
 *
 * keyver 1(WPA) 用 HMAC-MD5、2(WPA2) 用 HMAC-SHA1、3(WPA2-SHA256) 用
 * AES-CMAC 计算 MIC；PRF 输出的前 16 字节即 KCK。
 */
GY_HOSTDEV int gy_wpa2_eapol_check(const uint8_t *pw, int pwlen,
                                   const uint8_t *ssid, int ssidlen,
                                   const uint8_t *extra, int extralen,
                                   const uint8_t *check, int checklen,
                                   int keyver) {
    if (checklen != 16 || extralen < 44 + 97) {
        return 0;
    }
    if (keyver < 1 || keyver > 3) {
        return 0;
    }

    const uint8_t *macblk = extra;      /* 12 字节: Min(AP,STA)||Max(AP,STA) */
    const uint8_t *anonce = extra + 12; /* 32 字节 */
    const uint8_t *eapol = extra + 44;
    const int eapollen = extralen - 44;
    const uint8_t *snonce = eapol + 17;

    uint8_t pmk[32];
    gy_pbkdf2_sha1(pw, pwlen, ssid, ssidlen, GY_WPA2_ITER, pmk, 32);

    /* PRF 输入：legacy(keyver 1/2) 用 0x00 分隔并以 HMAC-SHA1 收尾；
       keyver 3 用 0x01 0x00 前缀与 0x80 0x01 后缀、HMAC-SHA256。 */
    uint8_t buf[112];
    int blen = 0;
    if (keyver == 3) {
        buf[blen++] = 0x01;
        buf[blen++] = 0x00;
    }
    const char *label = "Pairwise key expansion";
    for (int i = 0; i < 22; i++) {
        buf[blen++] = (uint8_t)label[i];
    }
    if (keyver != 3) {
        buf[blen++] = 0x00;
    }
    for (int i = 0; i < 12; i++) {
        buf[blen++] = macblk[i];
    }
    int cmp = 0;
    for (int i = 0; i < 32; i++) {
        if (anonce[i] != snonce[i]) {
            cmp = (anonce[i] < snonce[i]) ? -1 : 1;
            break;
        }
    }
    for (int i = 0; i < 32; i++) {
        buf[blen++] = (cmp <= 0) ? anonce[i] : snonce[i];
    }
    for (int i = 0; i < 32; i++) {
        buf[blen++] = (cmp <= 0) ? snonce[i] : anonce[i];
    }
    if (keyver != 3) {
        buf[blen++] = 0x00;
    } else {
        buf[blen++] = 0x80;
        buf[blen++] = 0x01;
    }

    uint8_t kck[16];
    if (keyver == 3) {
        uint8_t prf[32];
        gy_hmac_sha256(pmk, 32, buf, blen, prf);
        gy_copy(kck, prf, 16);
    } else {
        uint8_t prf[20];
        gy_hmac_sha1(pmk, 32, buf, blen, prf);
        gy_copy(kck, prf, 16);
    }

    uint8_t mic[16];
    if (keyver == 1) {
        gy_hmac_md5(kck, 16, eapol, eapollen, mic);
    } else if (keyver == 2) {
        uint8_t m[20];
        gy_hmac_sha1(kck, 16, eapol, eapollen, m);
        gy_copy(mic, m, 16);
    } else {
        gy_aes_cmac(kck, eapol, eapollen, mic);
    }
    return gy_memeq(mic, check, 16);
}

/* ============================ PDF 口令校验 ============================ */

/* 标准安全处理器的 32 字节口令填充串（PDF 32000-1 §7.6.3.3） */
GY_TABLE(uint8_t, gy_pdf_pad,
         0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
         0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
         0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
         0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a);

/* R=6 强化：至少 64 轮，64 轮后由密文末字节是否大于「轮次-32」决定是否继续 */
#define GY_PDF_MIN_ROUNDS 64
#define GY_PDF_MAX_ROUNDS 288

/* RC4：KSA + 就地异或（PDF 的 R=2..4 全靠它，与 ZipCrypto 的流密码无关） */
GY_HOSTDEV void gy_rc4_init(uint8_t s[256], const uint8_t *key, int keylen) {
    int i, j = 0;
    uint8_t t;
    for (i = 0; i < 256; i++) {
        s[i] = (uint8_t)i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) & 0xff;
        t = s[i]; s[i] = s[j]; s[j] = t;
    }
}

GY_HOSTDEV void gy_rc4_xor(uint8_t s[256], uint8_t *data, int len) {
    int i = 0, j = 0;
    uint8_t t;
    for (int n = 0; n < len; n++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        t = s[i]; s[i] = s[j]; s[j] = t;
        data[n] ^= s[(s[i] + s[j]) & 0xff];
    }
}

/* 口令填充/截断到 32 字节：超长只取前 32 字节，不足则在后面追加固定填充串 */
GY_HOSTDEV void gy_pdf_pad_pw(const uint8_t *pw, int pwlen, uint8_t out[32]) {
    int n = pwlen;
    if (n < 0) {
        n = 0;
    }
    if (n > 32) {
        n = 32;
    }
    gy_copy(out, pw, n);
    gy_copy(out + n, gy_pdf_pad, 32 - n);
}

/* Algorithm 2/3 的 50 轮 MD5 强化：反复取前 keylen 字节做 MD5 */
GY_HOSTDEV void gy_pdf_key_rounds(uint8_t d[16], int keylen, int r) {
    uint8_t tmp[16];
    GyMD5Ctx c;
    if (keylen > 16) {
        keylen = 16;
    }
    if (r >= 3) {
        for (int i = 0; i < 50; i++) {
            gy_md5_init(&c);
            gy_md5_update(&c, d, keylen);
            gy_md5_final(&c, tmp);
            gy_copy(d, tmp, 16);
        }
    }
}

/* Algorithm 2：MD5(填充口令 ‖ O ‖ P 小端 ‖ ID[0] ‖ FFFFFFFF?)，R>=3 再强化 50 轮 */
GY_HOSTDEV void gy_pdf_derive_key(const uint8_t padded[32], const uint8_t *o,
                                  uint32_t p, const uint8_t *id0, int encmeta,
                                  int r, int keylen, uint8_t key[16]) {
    uint8_t d[16];
    GyMD5Ctx c;
    gy_md5_init(&c);
    gy_md5_update(&c, padded, 32);
    gy_md5_update(&c, o, 32);
    gy_md5_update(&c, (const uint8_t *)&p, 4); /* P 按 32 位小端 */
    gy_md5_update(&c, id0, 16);
    if (r >= 4 && !encmeta) {
        const uint8_t ff[4] = {0xff, 0xff, 0xff, 0xff};
        gy_md5_update(&c, ff, 4);
    }
    gy_md5_final(&c, d);
    gy_pdf_key_rounds(d, keylen, r);
    gy_copy(key, d, keylen);
}

/* Algorithm 4(R=2)/5(R>=3)：重建 /U 与 Check 比对 */
GY_HOSTDEV int gy_pdf_check_user(const uint8_t padded[32], const uint8_t *o,
                                 uint32_t p, const uint8_t *id0, int encmeta,
                                 int r, int keylen, const uint8_t *u) {
    uint8_t key[16], s[256], buf[16], full[32];
    GyMD5Ctx c;

    gy_pdf_derive_key(padded, o, p, id0, encmeta, r, keylen, key);

    if (r < 3) {
        /* U = RC4(key, 32 字节填充串)，全部 32 字节参与比对 */
        gy_rc4_init(s, key, keylen);
        gy_copy(full, gy_pdf_pad, 32);
        gy_rc4_xor(s, full, 32);
        return gy_memeq(full, u, 32);
    }

    /* R>=3：U[0:16] = RC4^i(MD5(填充串 ‖ ID[0]))，i=0..19，第 i 轮用 key^i */
    gy_md5_init(&c);
    gy_md5_update(&c, gy_pdf_pad, 32);
    gy_md5_update(&c, id0, 16);
    gy_md5_final(&c, buf);
    for (int i = 0; i < 20; i++) {
        uint8_t kx[16];
        for (int j = 0; j < keylen; j++) {
            kx[j] = (uint8_t)(key[j] ^ i);
        }
        gy_rc4_init(s, kx, keylen);
        gy_rc4_xor(s, buf, 16);
    }
    return gy_memeq(buf, u, 16);
}

/*
 * Algorithm 3 的逆运算：/O 是把"填充后的用户口令"用所有者口令派生的密钥
 * RC4 迭代加密得到的（R>=3 共 20 轮，按 key^19..key^0 逆序解），还原后走用户校验。
 */
GY_HOSTDEV int gy_pdf_check_owner(const uint8_t *pw, int pwlen, const uint8_t *o,
                                  uint32_t p, const uint8_t *id0, int encmeta,
                                  int r, int keylen, const uint8_t *u) {
    uint8_t padded[32], d[16], key[16], s[256], user[32];
    const int iters = (r >= 3) ? 20 : 1;
    GyMD5Ctx c;

    gy_pdf_pad_pw(pw, pwlen, padded);
    gy_md5_init(&c);
    gy_md5_update(&c, padded, 32);
    gy_md5_final(&c, d);
    gy_pdf_key_rounds(d, keylen, r);
    gy_copy(key, d, keylen);

    gy_copy(user, o, 32);
    for (int x = iters - 1; x >= 0; x--) {
        uint8_t kx[16];
        for (int j = 0; j < keylen; j++) {
            kx[j] = (uint8_t)(key[j] ^ x);
        }
        gy_rc4_init(s, kx, keylen);
        gy_rc4_xor(s, user, 32);
    }
    /* 还原出的已是 32 字节填充口令，直接按用户口令校验 */
    return gy_pdf_check_user(user, o, p, id0, encmeta, r, keylen, u);
}

/* R=2..4（-m 10400/10500）：先试用户口令，再用所有者口令反解 /O */
GY_HOSTDEV int gy_pdf_legacy_check(const uint8_t *pw, int pwlen, const uint8_t *id0,
                                   const uint8_t *o, const uint8_t *u, uint32_t p,
                                   int encmeta, int r, int keylen) {
    uint8_t padded[32];
    if (keylen < 5 || keylen > 16 || r < 2 || r > 4) {
        return 0;
    }
    if (pwlen < 0) {
        return 0;
    }
    if (pwlen > 32) {
        pwlen = 32; /* 规范规定口令只用前 32 字节，与 CPU 侧 pdfPad 的截断一致 */
    }
    gy_pdf_pad_pw(pw, pwlen, padded);
    if (gy_pdf_check_user(padded, o, p, id0, encmeta, r, keylen, u)) {
        return 1;
    }
    return gy_pdf_check_owner(pw, pwlen, o, p, id0, encmeta, r, keylen, u);
}

/*
 * Algorithm 2.B 的一轮（R=6）：把 (pw ‖ K ‖ udata) 重复 64 次做 AES-128-CBC
 * （key=K[0:16]，IV=K[16:32]），密文按首块 mod 3 选 SHA-256/384/512 摘出新的 K。
 *
 * 明文以 16 字节为界流式喂入，跨段（pw/K/udata、跨重复）的半块留在 carry 里；
 * 64 份的总长恒为 16 的倍数，因此轮末 carry 必为空。密文先攒满 128 字节
 * （SHA 的最大分组）再喂给摘要，减少 update 调用次数。
 *
 * 成功后把新的 K 写回 k 并更新 *klen，同时返回本轮密文 E 的最后一个字节
 * （R=6 的续做条件要用它），失败返回 -1。
 */
GY_HOSTDEV int gy_pdf_v5_round(const uint8_t *pw, int pwlen, const uint8_t *salt, int saltlen,
                               const uint8_t *udata, int udatalen,
                               uint8_t k[64], int *klen) {
    GyAESKey ak;
    uint8_t prev[16], carry[16], pt[16], ct[16], stage[128];
    uint8_t d256[32], d384[48], d512[64];
    GySHA256Ctx c256;
    GySHA512Ctx c512;
    int n = 0, stagen = 0, sum = 0, last = 0, sel = -1;

    gy_aes_encrypt_key(&ak, k, 128);
    gy_copy(prev, k + 16, 16);

    for (int rep = 0; rep < 64; rep++) {
        for (int part = 0; part < 3; part++) {
            const uint8_t *seg;
            int seglen, off = 0;
            if (part == 0) {
                seg = pw; seglen = pwlen;
            } else if (part == 1) {
                seg = k; seglen = *klen;
            } else {
                seg = udata; seglen = udatalen;
            }
            while (off < seglen) {
                int take = 16 - n;
                if (take > seglen - off) {
                    take = seglen - off;
                }
                for (int i = 0; i < take; i++) {
                    carry[n + i] = seg[off + i];
                }
                n += take;
                off += take;
                if (n < 16) {
                    continue;
                }
                for (int i = 0; i < 16; i++) {
                    pt[i] = carry[i] ^ prev[i];
                }
                gy_aes_encrypt_block(&ak, pt, ct);
                gy_copy(prev, ct, 16);
                if (sel < 0) {
                    /* 首块密文的前 16 字节之和 mod 3 决定本轮用哪种摘要 */
                    for (int i = 0; i < 16; i++) {
                        sum += ct[i];
                    }
                    sel = sum % 3;
                    if (sel == 0) {
                        gy_sha256_init(&c256);
                    } else {
                        if (sel == 1) {
                            gy_sha384_init(&c512);
                        } else {
                            gy_sha512_init(&c512);
                        }
                    }
                }
                gy_copy(stage + stagen, ct, 16);
                stagen += 16;
                if (stagen == 128) {
                    if (sel == 0) {
                        gy_sha256_update(&c256, stage, 128);
                    } else {
                        gy_sha512_update(&c512, stage, 128);
                    }
                    stagen = 0;
                }
                last = ct[15];
                n = 0;
            }
        }
    }

    if (sel < 0 || n != 0) {
        return -1; /* 没凑出整块：参数非法 */
    }
    if (stagen > 0) {
        if (sel == 0) {
            gy_sha256_update(&c256, stage, stagen);
        } else {
            gy_sha512_update(&c512, stage, stagen);
        }
    }
    if (sel == 0) {
        gy_sha256_final(&c256, d256);
        gy_copy(k, d256, 32);
        *klen = 32;
    } else if (sel == 1) {
        gy_sha384_final(&c512, d384);
        gy_copy(k, d384, 48);
        *klen = 48;
    } else {
        gy_sha512_final(&c512, d512);
        gy_copy(k, d512, 64);
        *klen = 64;
    }
    return last;
}

/*
 * Algorithm 2.A / 2.B：V=5 的口令哈希。
 *
 *   R=5（2.A）= SHA-256(pw ‖ 校验盐 ‖ udata)，一次即完成；
 *   R=6（2.B）= 先按 2.A 求出 K，然后循环「AES 轮 → 摘要」至少 64 轮；
 *              第 65 轮起，若本轮密文 E 的末字节大于「轮次 - 32」就继续，
 *              上限 288 轮（规范给的安全上限）。
 *
 * out 固定 32 字节（ISO 32000-2 的校验值长度），成功返回 1。
 */
GY_HOSTDEV int gy_pdf_v5_hash(const uint8_t *pw, int pwlen, const uint8_t *salt, int saltlen,
                              const uint8_t *udata, int udatalen, int r, uint8_t out[32]) {
    uint8_t k[64];
    int klen = 32;
    GySHA256Ctx c;

    gy_sha256_init(&c);
    gy_sha256_update(&c, pw, pwlen);
    gy_sha256_update(&c, salt, saltlen);
    gy_sha256_update(&c, udata, udatalen);
    gy_sha256_final(&c, k);

    if (r < 6) {
        gy_copy(out, k, 32);
        return 1;
    }
    for (int round = 1; round <= GY_PDF_MAX_ROUNDS; round++) {
        const int last = gy_pdf_v5_round(pw, pwlen, salt, saltlen, udata, udatalen, k, &klen);
        if (last < 0) {
            return 0;
        }
        if (round >= GY_PDF_MIN_ROUNDS && last <= round - 32) {
            break;
        }
    }
    gy_copy(out, k, 32);
    return 1;
}

/* R=5/6（-m 10600/10700）：先校验用户口令，再用 /U 前 48 字节校验所有者口令 */
GY_HOSTDEV int gy_pdf_v5_check(const uint8_t *pw, int pwlen, const uint8_t *u, const uint8_t *o,
                               int r) {
    uint8_t d[32];
    static const uint8_t none[1] = {0};

    if (r != 5 && r != 6) {
        return 0;
    }
    if (pwlen < 0) {
        return 0;
    }
    if (pwlen > 127) {
        pwlen = 127; /* ISO 32000-2 规定口令只用前 127 字节，与 CPU 侧一致 */
    }
    /* 用户口令：盐取 /U 的校验盐(32..40)，udata 为空 */
    if (!gy_pdf_v5_hash(pw, pwlen, u + 32, 8, none, 0, r, d)) {
        return 0;
    }
    if (gy_memeq(d, u, 32)) {
        return 1;
    }
    /* 所有者口令：盐取 /O 的校验盐(32..40)，udata 为 /U 前 48 字节 */
    if (!gy_pdf_v5_hash(pw, pwlen, o + 32, 8, u, 48, r, d)) {
        return 0;
    }
    return gy_memeq(d, o, 32);
}


/*
 * gy_generic_hash_check — 主机与 GPU 共用的通用哈希校验。
 *
 * 各算法字段含义与 internal/cuda 的 HashXxx 注释一致，命中返回 1：
 *   裸摘要     直接比较摘要与 Check；
 *   ZIP AES    PBKDF2-SHA1(1000) 派生 2*KeyLen+2 字节，先比末尾 2 字节密码
 *              校验值，再用 auth key 做 HMAC-SHA1(密文) 比对 10 字节认证码；
 *   WPA2 PMKID PBKDF2-SHA1(4096) 得 PMK，再 HMAC-SHA1(PMK, Data) 前 16 字节；
 *   RAR5       PBKDF2-SHA256(1<<Iter) 得 32 字节密钥，按 8 字节分组异或折叠比对；
 *   RAR3 -hp   交织 SHA-1 KDF + AES-128-CBC（pw 为 UTF-16LE，Data=16 字节密文头）；
 *   7z         SHA-256 KDF(2^Iter) + AES-256-CBC + CRC32（pw 为 UTF-16LE，
 *              仅 Copy 编码器，KeyLen = 解压后字节数，IV = 16 字节初始向量）；
 *   ZipCrypto  PKZIP 流密码，解密 12 字节头后按 Iter=B(1/2) 比对 CS/TC（弱校验）；
 *   WPA2-EAPOL PBKDF2-SHA1(4096) 得 PMK，PRF 前 16 字节为 KCK，再按
 *              Iter=keyver(1/2/3) 用 HMAC-MD5/HMAC-SHA1/AES-CMAC 比对 MIC。
 */
GY_HOSTDEV int gy_generic_hash_check(int algo,
                                     const char *pw, int pwlen,
                                     const char *salt, int saltlen,
                                     const char *extra, int extralen,
                                     const char *check, int checklen,
                                     const char *iv, int ivlen,
                                     int iter, int keylen) {
    const uint8_t *sp = (const uint8_t *)salt;
    const uint8_t *xp = (const uint8_t *)extra;
    const uint8_t *cp = (const uint8_t *)check;
    uint8_t d[64];

    if (algo == GYHOST_HASH_RAW_MD5) {
        GyMD5Ctx c;
        gy_md5_init(&c);
        gy_md5_update(&c, pw, pwlen);
        gy_md5_final(&c, d);
        return (checklen == 16) ? gy_memeq(d, cp, 16) : 0;
    }
    if (algo == GYHOST_HASH_RAW_SHA1) {
        GySHA1Ctx c;
        gy_sha1_init(&c);
        gy_sha1_update(&c, pw, pwlen);
        gy_sha1_final(&c, d);
        return (checklen == 20) ? gy_memeq(d, cp, 20) : 0;
    }
    if (algo == GYHOST_HASH_RAW_SHA256) {
        GySHA256Ctx c;
        gy_sha256_init(&c);
        gy_sha256_update(&c, pw, pwlen);
        gy_sha256_final(&c, d);
        return (checklen == 32) ? gy_memeq(d, cp, 32) : 0;
    }
    if (algo == GYHOST_HASH_RAW_SHA512) {
        GySHA512Ctx c;
        gy_sha512_init(&c);
        gy_sha512_update(&c, pw, pwlen);
        gy_sha512_final(&c, d);
        return (checklen == 64) ? gy_memeq(d, cp, 64) : 0;
    }
    if (algo == GYHOST_HASH_ZIP_AES) {
        uint8_t derived[2 * 32 + 2];
        uint8_t auth[20];
        if (keylen != 16 && keylen != 24 && keylen != 32) {
            return 0;
        }
        if (checklen != 12 || extralen <= 0) {
            return 0;
        }
        gy_pbkdf2_sha1((const uint8_t *)pw, pwlen, sp, saltlen,
                       GY_ZIP_AES_ITER, derived, 2 * keylen + 2);
        if (gy_memeq(derived + 2 * keylen, cp, 2) == 0) {
            return 0;
        }
        gy_hmac_sha1(derived + keylen, keylen, xp, extralen, auth);
        return gy_memeq(auth, cp + 2, 10);
    }
    if (algo == GYHOST_HASH_WPA2_PMKID) {
        uint8_t pmk[32], mac[20];
        if (checklen != 16 || extralen != 20) {
            return 0;
        }
        gy_pbkdf2_sha1((const uint8_t *)pw, pwlen, sp, saltlen,
                       GY_WPA2_ITER, pmk, 32);
        gy_hmac_sha1(pmk, 32, xp, 20, mac);
        return gy_memeq(mac, cp, 16);
    }
    if (algo == GYHOST_HASH_RAR5) {
        uint8_t key[32], fold[8];
        if (checklen != 8 || iter < 0 || iter > 24) {
            return 0;
        }
        /* RAR5 的 KDF 迭代次数是 (1<<power)+32，不是单纯的 2^power */
        gy_pbkdf2_sha256((const uint8_t *)pw, pwlen, sp, saltlen,
                         (1 << iter) + 32, key, 32);
        for (int i = 0; i < 8; i++) {
            fold[i] = (uint8_t)(key[i] ^ key[i + 8] ^ key[i + 16] ^ key[i + 24]);
        }
        return gy_memeq(fold, cp, 8);
    }
    if (algo == GYHOST_HASH_RAR3HP) {
        return gy_rar3hp_check((const uint8_t *)pw, pwlen, sp, saltlen,
                               xp, extralen, cp, checklen);
    }
    if (algo == GYHOST_HASH_7Z) {
        return gy_7z_check((const uint8_t *)pw, pwlen, sp, saltlen,
                           (const uint8_t *)iv, ivlen, xp, extralen,
                           cp, checklen, iter, keylen);
    }
    if (algo == GYHOST_HASH_ZIPCRYPTO) {
        return gy_zipcrypto_check((const uint8_t *)pw, pwlen, xp, extralen,
                                  cp, checklen, iter);
    }
    if (algo == GYHOST_HASH_WPA2_EAPOL) {
        return gy_wpa2_eapol_check((const uint8_t *)pw, pwlen, sp, saltlen,
                                   xp, extralen, cp, checklen, iter);
    }
    if (algo == GYHOST_HASH_PDF) {
        /*
         * PDF 口令校验（hashcat -m 10400/10500/10600/10700）。
         *
         * V<=4（MD5 + RC4 标准安全处理器）：
         *   Salt = ID[0](16 字节)、Data = /O(32)、Check = /U(32)、Iter = R、
         *   KeyLen = 加密密钥字节数(5 或 16)、
         *   IV = P(4 字节小端) || flags(1，bit0 = EncryptMetadata) || 保留(3)
         * V=5（AES-256，Algorithm 2.A/2.B）：
         *   Salt = 用户校验盐(8) || 所有者校验盐(8)、Data = /U(48)、Check = /O(48)、
         *   Iter = R(5 或 6)
         */
        if (iter >= 5) {
            if (saltlen != 16 || extralen != 48 || checklen != 48) {
                return 0;
            }
            return gy_pdf_v5_check((const uint8_t *)pw, pwlen, xp, cp, iter);
        }
        if (saltlen != 16 || extralen != 32 || checklen != 32 || ivlen < 8) {
            return 0;
        }
        const uint32_t p = (uint32_t)((const uint8_t *)iv)[0] |
                           ((uint32_t)((const uint8_t *)iv)[1] << 8) |
                           ((uint32_t)((const uint8_t *)iv)[2] << 16) |
                           ((uint32_t)((const uint8_t *)iv)[3] << 24);
        const int encmeta = (((const uint8_t *)iv)[4] & 1) ? 1 : 0;
        return gy_pdf_legacy_check((const uint8_t *)pw, pwlen, sp, xp, cp,
                                   p, encmeta, iter, keylen);
    }
    return 0;
}

/* 通用哈希算法编号是否受支持（与 internal/cuda.SupportedHash 一致）。 */
int gyhost_hash_supported(int algo) {
    switch (algo) {
        case GYHOST_HASH_RAW_MD5:
        case GYHOST_HASH_RAW_SHA1:
        case GYHOST_HASH_RAW_SHA256:
        case GYHOST_HASH_RAW_SHA512:
        case GYHOST_HASH_ZIP_AES:
        case GYHOST_HASH_WPA2_PMKID:
        case GYHOST_HASH_RAR5:
        case GYHOST_HASH_RAR3HP:
        case GYHOST_HASH_7Z:
        case GYHOST_HASH_ZIPCRYPTO:
        case GYHOST_HASH_WPA2_EAPOL:
        case GYHOST_HASH_PDF:
            return 1;
        default:
            return 0;
    }
}

/* ------------------------------------------------------------------ *
 * 5. GPU 内核                                                         *
 * ------------------------------------------------------------------ */

/* 一个线程 = 一个候选密码；命中则用 atomicMin 记录最小下标 */
__global__ void gy_verify_kernel(int algo, const char *pw_data, const int *pw_off,
                                 const int *pw_len, int count,
                                 const char *salt, int salt_len, int rounds,
                                 const char *key, int *match) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) {
        return;
    }

    const char *pw = pw_data + pw_off[i];
    int n = pw_len[i];
    int hit = 0;

    if (algo == GYHOST_ALGO_MD5CRYPT) {
        hit = gy_md5crypt_check(pw, n, salt, salt_len, key);
    } else if (algo == GYHOST_ALGO_SHA256CRYPT) {
        hit = gy_shacrypt_check<GySHA256Policy>(pw, n, salt, salt_len, rounds, key);
    } else if (algo == GYHOST_ALGO_SHA512CRYPT) {
        hit = gy_shacrypt_check<GySHA512Policy>(pw, n, salt, salt_len, rounds, key);
    }

    if (hit == 1) {
        atomicMin(match, i);
    }
}

/* 通用哈希（hashac）：一个线程 = 一个候选密码，命中用 atomicMin 记录最小下标 */
__global__ void gy_verify_hash_kernel(int algo, const char *pw_data, const int *pw_off,
                                      const int *pw_len, int count,
                                      const char *salt, int salt_len,
                                      const char *extra, int extra_len,
                                      const char *check, int check_len,
                                      const char *iv, int iv_len,
                                      int iter, int key_len, int *match) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) {
        return;
    }

    const char *pw = pw_data + pw_off[i];
    int n = pw_len[i];

    if (gy_generic_hash_check(algo, pw, n, salt, salt_len, extra, extra_len,
                              check, check_len, iv, iv_len, iter, key_len) == 1) {
        atomicMin(match, i);
    }
}

/* ------------------------------------------------------------------ *
 * 6. extern "C" 主机接口                                              *
 * ------------------------------------------------------------------ */

int gyhost_cuda_supported(int algo) {
    return (algo == GYHOST_ALGO_MD5CRYPT || algo == GYHOST_ALGO_SHA256CRYPT ||
            algo == GYHOST_ALGO_SHA512CRYPT)
               ? 1
               : 0;
}

const char *gyhost_cuda_strerror(int code) {
    switch (code) {
        case GYHOST_CUDA_OK:
            return "ok";
        case GYHOST_CUDA_ERR_PARAM:
            return "invalid parameter";
        case GYHOST_CUDA_ERR_NO_DEV:
            return "no CUDA device available";
        case GYHOST_CUDA_ERR_ALLOC:
            return "device memory allocation failed";
        case GYHOST_CUDA_ERR_KERNEL:
            return "kernel launch failed";
        case GYHOST_CUDA_ERR_ALGO:
            return "hash algorithm not supported on GPU";
        default:
            return "unknown CUDA error";
    }
}

int gyhost_cuda_device_count(void) {
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess) {
        cudaGetLastError(); /* 清除错误状态，避免污染后续调用 */
        return 0;
    }
    return count < 0 ? 0 : count;
}

int gyhost_cuda_available(void) { return gyhost_cuda_device_count() > 0 ? 1 : 0; }

int gyhost_cuda_device_name(int device, char *buf, int buf_len) {
    if (buf == NULL || buf_len <= 0) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device) != cudaSuccess) {
        cudaGetLastError();
        return GYHOST_CUDA_ERR_NO_DEV;
    }
    snprintf(buf, (size_t)buf_len, "%s", prop.name);
    return GYHOST_CUDA_OK;
}

long long gyhost_cuda_device_memory(int device) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device) != cudaSuccess) {
        cudaGetLastError();
        return 0;
    }
    return (long long)(prop.totalGlobalMem / (1024 * 1024));
}

int gyhost_cuda_set_device(int device) {
    int count = gyhost_cuda_device_count();
    if (count <= 0) {
        return GYHOST_CUDA_ERR_NO_DEV;
    }
    if (device < 0 || device >= count) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (cudaSetDevice(device) != cudaSuccess) {
        cudaGetLastError();
        return GYHOST_CUDA_ERR_NO_DEV;
    }
    return GYHOST_CUDA_OK;
}

int gyhost_cuda_check_host(int algo, const char *pw, int pw_len,
                           const char *salt, int salt_len, int rounds,
                           const char *key) {
    if (pw == NULL || salt == NULL || key == NULL) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (pw_len < 0 || pw_len > GY_MAX_PW || salt_len < 0 || salt_len > GY_MAX_SALT) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (rounds < 0) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (!gyhost_cuda_supported(algo)) {
        return GYHOST_CUDA_ERR_ALGO;
    }
    if (key[0] == '\0') {
        return GYHOST_CUDA_ERR_PARAM;
    }

    if (algo == GYHOST_ALGO_MD5CRYPT) {
        return gy_md5crypt_check(pw, pw_len, salt, salt_len, key);
    }
    if (algo == GYHOST_ALGO_SHA256CRYPT) {
        return gy_shacrypt_check<GySHA256Policy>(pw, pw_len, salt, salt_len, rounds, key);
    }
    return gy_shacrypt_check<GySHA512Policy>(pw, pw_len, salt, salt_len, rounds, key);
}

int gyhost_cuda_verify(int algo, const char *pw_data, int pw_total,
                       const int *pw_off, const int *pw_len, int count,
                       const char *salt, int salt_len, int rounds,
                       const char *key, int device, int *match) {
    if (pw_data == NULL || pw_off == NULL || pw_len == NULL || salt == NULL ||
        key == NULL || match == NULL) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (count <= 0 || count > (1 << 20)) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (pw_total < 0 || salt_len < 0 || salt_len > GY_MAX_SALT || rounds < 0) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (!gyhost_cuda_supported(algo)) {
        return GYHOST_CUDA_ERR_ALGO;
    }

    const int key_len = (int)strlen(key);
    if (key_len <= 0) {
        return GYHOST_CUDA_ERR_PARAM;
    }

    for (int i = 0; i < count; i++) {
        if (pw_len[i] < 0 || pw_len[i] > GY_MAX_PW) {
            return GYHOST_CUDA_ERR_PARAM;
        }
        if (pw_off[i] < 0 || pw_off[i] > pw_total - pw_len[i]) {
            return GYHOST_CUDA_ERR_PARAM;
        }
    }

    int rc = gyhost_cuda_set_device(device);
    if (rc != GYHOST_CUDA_OK) {
        return rc;
    }

    cudaGetLastError(); /* 清除历史错误，避免误判本次内核 */

    const size_t pw_bytes = (size_t)(pw_total > 0 ? pw_total : 1);
    const size_t salt_bytes = (size_t)(salt_len > 0 ? salt_len : 1);
    const size_t key_bytes = (size_t)key_len + 1;
    const size_t off_bytes = (size_t)count * sizeof(int);

    char *d_pw = NULL;
    int *d_off = NULL;
    int *d_len = NULL;
    char *d_salt = NULL;
    char *d_key = NULL;
    int *d_match = NULL;
    int best = count;
    int rc_err = GYHOST_CUDA_OK;

    if (cudaMalloc(&d_pw, pw_bytes) != cudaSuccess ||
        cudaMalloc(&d_off, off_bytes) != cudaSuccess ||
        cudaMalloc(&d_len, off_bytes) != cudaSuccess ||
        cudaMalloc(&d_salt, salt_bytes) != cudaSuccess ||
        cudaMalloc(&d_key, key_bytes) != cudaSuccess ||
        cudaMalloc(&d_match, sizeof(int)) != cudaSuccess) {
        rc_err = GYHOST_CUDA_ERR_ALLOC;
    } else if (cudaMemcpy(d_pw, pw_data, pw_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_off, pw_off, off_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_len, pw_len, off_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_salt, salt, salt_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_key, key, key_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        rc_err = GYHOST_CUDA_ERR_ALLOC;
    } else {
        /* 分块发射：控制每线程局部内存占用，命中最小子标提前结束 */
        for (int base = 0; base < count && rc_err == GYHOST_CUDA_OK; base += GY_CHUNK) {
            int n = count - base;
            if (n > GY_CHUNK) {
                n = GY_CHUNK;
            }
            int sentinel = n; /* 无命中时保持为 n */

            if (cudaMemcpy(d_match, &sentinel, sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess) {
                rc_err = GYHOST_CUDA_ERR_ALLOC;
                break;
            }

            dim3 block(GY_BLOCK);
            dim3 grid((n + GY_BLOCK - 1) / GY_BLOCK);
            gy_verify_kernel<<<grid, block>>>(algo, d_pw, d_off + base, d_len + base, n,
                                              d_salt, salt_len, rounds, d_key, d_match);

            cudaError_t err = cudaGetLastError();
            if (err != cudaSuccess) {
                rc_err = GYHOST_CUDA_ERR_KERNEL;
                break;
            }
            /* DeviceToHost 拷贝会同步设备并带回内核的异步错误 */
            if (cudaMemcpy(&sentinel, d_match, sizeof(int), cudaMemcpyDeviceToHost) != cudaSuccess) {
                rc_err = GYHOST_CUDA_ERR_KERNEL;
                break;
            }
            if (sentinel < n) {
                best = base + sentinel;
                break; /* 分块按顺序处理，首个命中的分块即含最小子标 */
            }
        }
    }

    if (d_pw != NULL) cudaFree(d_pw);
    if (d_off != NULL) cudaFree(d_off);
    if (d_len != NULL) cudaFree(d_len);
    if (d_salt != NULL) cudaFree(d_salt);
    if (d_key != NULL) cudaFree(d_key);
    if (d_match != NULL) cudaFree(d_match);

    if (rc_err != GYHOST_CUDA_OK) {
        cudaGetLastError();
        return rc_err;
    }

    *match = (best < count) ? best : -1;
    return GYHOST_CUDA_OK;
}

int gyhost_cuda_check_hash(int algo, const char *pw, int pw_len,
                           const char *salt, int salt_len,
                           const char *extra, int extra_len,
                           const char *check, int check_len,
                           const char *iv, int iv_len,
                           int iter, int key_len) {
    if (pw == NULL || salt == NULL || extra == NULL || check == NULL) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (pw_len < 0 || pw_len > GY_MAX_PW) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (salt_len < 0 || salt_len > GYHOST_HASH_MAX_SALT ||
        extra_len < 0 || extra_len > GYHOST_HASH_MAX_DATA ||
        check_len < 0 || check_len > GYHOST_HASH_MAX_CHECK) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (iv_len < 0 || iv_len > 16 || (iv_len > 0 && iv == NULL)) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (iter < 0 || key_len < 0) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (!gyhost_hash_supported(algo)) {
        return GYHOST_CUDA_ERR_ALGO;
    }
    if (algo == GYHOST_HASH_RAR3HP && pw_len > GY_RAR3_MAX_PW16) {
        return GYHOST_CUDA_ERR_PARAM;
    }

    return gy_generic_hash_check(algo, pw, pw_len, salt, salt_len, extra, extra_len,
                                 check, check_len, iv, iv_len, iter, key_len);
}

int gyhost_cuda_verify_hash(int algo, const char *pw_data, int pw_total,
                            const int *pw_off, const int *pw_len, int count,
                            const char *salt, int salt_len,
                            const char *extra, int extra_len,
                            const char *check, int check_len,
                            const char *iv, int iv_len,
                            int iter, int key_len,
                            int device, int *match) {
    if (pw_data == NULL || pw_off == NULL || pw_len == NULL || salt == NULL ||
        extra == NULL || check == NULL || match == NULL) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (count <= 0 || count > (1 << 20)) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (pw_total < 0 ||
        salt_len < 0 || salt_len > GYHOST_HASH_MAX_SALT ||
        extra_len < 0 || extra_len > GYHOST_HASH_MAX_DATA ||
        check_len <= 0 || check_len > GYHOST_HASH_MAX_CHECK ||
        iter < 0 || key_len < 0) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (iv_len < 0 || iv_len > 16 || (iv_len > 0 && iv == NULL)) {
        return GYHOST_CUDA_ERR_PARAM;
    }
    if (!gyhost_hash_supported(algo)) {
        return GYHOST_CUDA_ERR_ALGO;
    }

    for (int i = 0; i < count; i++) {
        if (pw_len[i] < 0 || pw_len[i] > GY_MAX_PW) {
            return GYHOST_CUDA_ERR_PARAM;
        }
        if (algo == GYHOST_HASH_RAR3HP && pw_len[i] > GY_RAR3_MAX_PW16) {
            return GYHOST_CUDA_ERR_PARAM;
        }
        if (pw_off[i] < 0 || pw_off[i] > pw_total - pw_len[i]) {
            return GYHOST_CUDA_ERR_PARAM;
        }
    }

    int rc = gyhost_cuda_set_device(device);
    if (rc != GYHOST_CUDA_OK) {
        return rc;
    }

    cudaGetLastError(); /* 清除历史错误，避免误判本次内核 */

    const size_t pw_bytes = (size_t)(pw_total > 0 ? pw_total : 1);
    const size_t salt_bytes = (size_t)(salt_len > 0 ? salt_len : 1);
    const size_t extra_bytes = (size_t)(extra_len > 0 ? extra_len : 1);
    const size_t check_bytes = (size_t)check_len;
    const size_t iv_bytes = (size_t)(iv_len > 0 ? iv_len : 1);
    const size_t off_bytes = (size_t)count * sizeof(int);

    char *d_pw = NULL;
    int *d_off = NULL;
    int *d_len = NULL;
    char *d_salt = NULL;
    char *d_extra = NULL;
    char *d_check = NULL;
    char *d_iv = NULL;
    int *d_match = NULL;
    int best = count;
    int rc_err = GYHOST_CUDA_OK;

    if (cudaMalloc(&d_pw, pw_bytes) != cudaSuccess ||
        cudaMalloc(&d_off, off_bytes) != cudaSuccess ||
        cudaMalloc(&d_len, off_bytes) != cudaSuccess ||
        cudaMalloc(&d_salt, salt_bytes) != cudaSuccess ||
        cudaMalloc(&d_extra, extra_bytes) != cudaSuccess ||
        cudaMalloc(&d_check, check_bytes) != cudaSuccess ||
        cudaMalloc(&d_iv, iv_bytes) != cudaSuccess ||
        cudaMalloc(&d_match, sizeof(int)) != cudaSuccess) {
        rc_err = GYHOST_CUDA_ERR_ALLOC;
    } else if (cudaMemcpy(d_pw, pw_data, pw_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_off, pw_off, off_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_len, pw_len, off_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_salt, salt, salt_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_extra, extra, extra_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               cudaMemcpy(d_check, check, check_bytes, cudaMemcpyHostToDevice) != cudaSuccess ||
               (iv_len > 0 && cudaMemcpy(d_iv, iv, iv_bytes, cudaMemcpyHostToDevice) != cudaSuccess)) {
        rc_err = GYHOST_CUDA_ERR_ALLOC;
    } else {
        /* 分块发射：命中最小子标提前结束 */
        for (int base = 0; base < count && rc_err == GYHOST_CUDA_OK; base += GY_CHUNK) {
            int n = count - base;
            if (n > GY_CHUNK) {
                n = GY_CHUNK;
            }
            int sentinel = n;

            if (cudaMemcpy(d_match, &sentinel, sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess) {
                rc_err = GYHOST_CUDA_ERR_ALLOC;
                break;
            }

            dim3 block(GY_BLOCK);
            dim3 grid((n + GY_BLOCK - 1) / GY_BLOCK);
            gy_verify_hash_kernel<<<grid, block>>>(algo, d_pw, d_off + base, d_len + base, n,
                                                   d_salt, salt_len, d_extra, extra_len,
                                                   d_check, check_len, d_iv, iv_len,
                                                   iter, key_len, d_match);

            cudaError_t err = cudaGetLastError();
            if (err != cudaSuccess) {
                rc_err = GYHOST_CUDA_ERR_KERNEL;
                break;
            }
            /* DeviceToHost 拷贝会同步设备并带回内核的异步错误 */
            if (cudaMemcpy(&sentinel, d_match, sizeof(int), cudaMemcpyDeviceToHost) != cudaSuccess) {
                rc_err = GYHOST_CUDA_ERR_KERNEL;
                break;
            }
            if (sentinel < n) {
                best = base + sentinel;
                break;
            }
        }
    }

    if (d_pw != NULL) cudaFree(d_pw);
    if (d_off != NULL) cudaFree(d_off);
    if (d_len != NULL) cudaFree(d_len);
    if (d_salt != NULL) cudaFree(d_salt);
    if (d_extra != NULL) cudaFree(d_extra);
    if (d_check != NULL) cudaFree(d_check);
    if (d_iv != NULL) cudaFree(d_iv);
    if (d_match != NULL) cudaFree(d_match);

    if (rc_err != GYHOST_CUDA_OK) {
        cudaGetLastError();
        return rc_err;
    }

    *match = (best < count) ? best : -1;
    return GYHOST_CUDA_OK;
}
