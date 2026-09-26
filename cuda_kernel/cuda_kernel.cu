
#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PBKDF2_ITERATIONS 4096
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20
#define SHA1_WORKING_SIZE 80
#define MAX_PASSWORD_LEN 64
#define MAX_SSID_LEN 32
#define MAX_MSG_LEN 128
#define PMK_SIZE 32
#define MD5_SIZE 16
#define SHA256_SIZE 32
#define SHA512_SIZE 64
#define MD4_SIZE 16
#define IPAD 0x36
#define OPAD 0x5c
#define MAX_INPUT_LEN 256

__device__ inline uint32_t sha1_rotl(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32 - n));
}

__device__ inline uint32_t sha1_ch(uint32_t x, uint32_t y, uint32_t z, int t) {
    if (t < 20) return (x & y) | ((~x) & z);
    if (t < 40) return x ^ y ^ z;
    if (t < 60) return (x & y) | (x & z) | (y & z);
    return x ^ y ^ z;
}

__device__ void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int t = 0; t < 80; t++) {
        uint32_t k;
        if (t < 20) k = 0x5A827999;
        else if (t < 40) k = 0x6ED9EBA1;
        else if (t < 60) k = 0x8F1BBCDC;
        else k = 0xCA62C1D6;

        uint32_t tmp = sha1_rotl(a, 5) + sha1_ch(b, c, d, t) + e + k + w[t];
        e = d; d = c; c = sha1_rotl(b, 30); b = a; a = tmp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

__device__ void sha1_hash(const uint8_t *data, int data_len, uint8_t digest[20]) {
    uint32_t state[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };

    uint64_t bit_len = (uint64_t)data_len * 8;
    uint8_t block[64];
    int pos = 0;

    for (int i = 0; i < data_len; i++) {
        block[pos++] = data[i];
        if (pos == 64) {
            sha1_transform(state, block);
            pos = 0;
        }
    }

    block[pos++] = 0x80;
    if (pos > 56) {
        while (pos < 64) block[pos++] = 0;
        sha1_transform(state, block);
        pos = 0;
    }
    while (pos < 56) block[pos++] = 0;

    for (int i = 7; i >= 0; i--) {
        block[56 + i] = (uint8_t)(bit_len >> ((7 - i) * 8));
    }
    sha1_transform(state, block);

    for (int i = 0; i < 5; i++) {
        digest[i*4]     = (uint8_t)(state[i] >> 24);
        digest[i*4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i*4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i*4 + 3] = (uint8_t)(state[i]);
    }
}

__device__ void hmac_sha1(const uint8_t *key, int key_len,
                          const uint8_t *msg, int msg_len,
                          uint8_t result[20]) {
    uint8_t key_pad[64];
    if (key_len > 64) {
        sha1_hash(key, key_len, key_pad);
        for (int i = 20; i < 64; i++) key_pad[i] = 0;
    } else {
        for (int i = 0; i < key_len; i++) key_pad[i] = key[i];
        for (int i = key_len; i < 64; i++) key_pad[i] = 0;
    }

    uint8_t inner_key[64], outer_key[64];
    for (int i = 0; i < 64; i++) {
        inner_key[i] = key_pad[i] ^ IPAD;
        outer_key[i] = key_pad[i] ^ OPAD;
    }

    uint8_t inner_msg[64 + MAX_MSG_LEN];
    for (int i = 0; i < 64; i++) inner_msg[i] = inner_key[i];
    for (int i = 0; i < msg_len; i++) inner_msg[64 + i] = msg[i];

    uint8_t inner_hash[20];
    sha1_hash(inner_msg, 64 + msg_len, inner_hash);

    uint8_t outer_msg[64 + 20];
    for (int i = 0; i < 64; i++) outer_msg[i] = outer_key[i];
    for (int i = 0; i < 20; i++) outer_msg[64 + i] = inner_hash[i];

    sha1_hash(outer_msg, 64 + 20, result);
}

__device__ void pbkdf2_sha1(const uint8_t *password, int pass_len,
                            const uint8_t *salt, int salt_len,
                            uint8_t dk[32]) {
    uint8_t u[SHA1_DIGEST_SIZE];
    uint8_t t[PMK_SIZE];
    for (int i = 0; i < PMK_SIZE; i++) t[i] = 0;

    int block_num = 2;
    for (int blk = 1; blk <= block_num; blk++) {
        uint8_t salt_block[128];
        int sbl = 0;
        for (int i = 0; i < salt_len; i++) salt_block[sbl++] = salt[i];
        salt_block[sbl++] = (uint8_t)(blk >> 24);
        salt_block[sbl++] = (uint8_t)(blk >> 16);
        salt_block[sbl++] = (uint8_t)(blk >> 8);
        salt_block[sbl++] = (uint8_t)(blk);

        hmac_sha1(password, pass_len, salt_block, salt_len + 4, u);
        for (int j = 0; j < SHA1_DIGEST_SIZE; j++)
            t[(blk-1)*SHA1_DIGEST_SIZE + j] = u[j];

        for (int iter = 1; iter < PBKDF2_ITERATIONS; iter++) {
            hmac_sha1(password, pass_len, u, SHA1_DIGEST_SIZE, u);
            for (int j = 0; j < SHA1_DIGEST_SIZE; j++)
                t[(blk-1)*SHA1_DIGEST_SIZE + j] ^= u[j];
        }
    }

    for (int i = 0; i < PMK_SIZE; i++) dk[i] = t[i];
}

__global__ void pbkdf2_sha1_kernel(
    const uint8_t *passwords, const int *pass_lens, int pass_stride,
    const uint8_t *ssid, int ssid_len,
    uint8_t *pmks, int num_passwords) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_passwords) return;

    const uint8_t *pass = passwords + (size_t)idx * pass_stride;
    int pass_len = pass_lens[idx];

    uint8_t pmk[PMK_SIZE];
    pbkdf2_sha1(pass, pass_len, ssid, ssid_len, pmk);

    uint8_t *out = pmks + (size_t)idx * PMK_SIZE;
    for (int i = 0; i < PMK_SIZE; i++) out[i] = pmk[i];
}

int cuda_get_device_count() {
    int count;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess) return 0;
    return count;
}

int cuda_get_device_name(int device, char *name, int max_len) {
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, device);
    if (err != cudaSuccess) {
        snprintf(name, max_len, "Unknown");
        return -1;
    }
    snprintf(name, max_len, "%s", prop.name);
    return 0;
}

long long cuda_get_device_memory(int device) {
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, device);
    if (err != cudaSuccess) return 0;
    return (long long)(prop.totalGlobalMem / (1024 * 1024));
}

int cuda_wpa2_pmk_batch(
    const char **passwords, const int *pass_lens, int num_passwords,
    const char *ssid, int ssid_len,
    uint8_t *pmks_out) {

    if (num_passwords <= 0) return 0;

    int max_pass_len = 0;
    for (int i = 0; i < num_passwords; i++) {
        if (pass_lens[i] > max_pass_len) max_pass_len = pass_lens[i];
    }

    uint8_t *d_passwords = NULL, *d_ssid = NULL, *d_pmks = NULL;
    int *d_pass_lens = NULL;

    size_t pass_buf_size = (size_t)num_passwords * max_pass_len;
    cudaMalloc(&d_passwords, pass_buf_size);
    cudaMalloc(&d_pass_lens, num_passwords * sizeof(int));
    cudaMalloc(&d_ssid, ssid_len);
    cudaMalloc(&d_pmks, (size_t)num_passwords * PMK_SIZE);

    uint8_t *h_pass_buf = (uint8_t *)malloc(pass_buf_size);
    memset(h_pass_buf, 0, pass_buf_size);
    for (int i = 0; i < num_passwords; i++) {
        memcpy(h_pass_buf + (size_t)i * max_pass_len, passwords[i], pass_lens[i]);
    }

    cudaMemcpy(d_passwords, h_pass_buf, pass_buf_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_pass_lens, pass_lens, num_passwords * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_ssid, ssid, ssid_len, cudaMemcpyHostToDevice);

    int block_size = 256;
    int grid_size = (num_passwords + block_size - 1) / block_size;

    pbkdf2_sha1_kernel<<<grid_size, block_size>>>(
        d_passwords, d_pass_lens, max_pass_len,
        d_ssid, ssid_len,
        d_pmks, num_passwords);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("CUDA kernel error: %s\n", cudaGetErrorString(err));
        free(h_pass_buf);
        cudaFree(d_passwords); cudaFree(d_pass_lens);
        cudaFree(d_ssid); cudaFree(d_pmks);
        return -1;
    }

    cudaDeviceSynchronize();

    cudaMemcpy(pmks_out, d_pmks, (size_t)num_passwords * PMK_SIZE, cudaMemcpyDeviceToHost);

    free(h_pass_buf);
    cudaFree(d_passwords); cudaFree(d_pass_lens);
    cudaFree(d_ssid); cudaFree(d_pmks);

    return 0;
}

// === MD5 批量哈希 ===

__device__ inline uint32_t md5_F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((~x) & z); }
__device__ inline uint32_t md5_G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & (~z)); }
__device__ inline uint32_t md5_H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
__device__ inline uint32_t md5_I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | (~z)); }
__device__ inline uint32_t md5_rotl(uint32_t x, unsigned int n) { return (x << n) | (x >> (32 - n)); }

__device__ void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    const unsigned int s[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };

    const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
        0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
        0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
        0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
        0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
        0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
        0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
        0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
        0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };

    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16)      { f = md5_F(b, c, d); g = i; }
        else if (i < 32) { f = md5_G(b, c, d); g = (5*i + 1) % 16; }
        else if (i < 48) { f = md5_H(b, c, d); g = (3*i + 5) % 16; }
        else             { f = md5_I(b, c, d); g = (7*i) % 16; }

        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + md5_rotl(a + f + K[i] + x[g], s[i]);
        a = tmp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

__device__ void md5_hash(const uint8_t *data, int data_len, uint8_t digest[16]) {
    uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

    uint64_t bit_len = (uint64_t)data_len * 8;
    uint8_t block[64];
    int pos = 0;

    for (int i = 0; i < data_len; i++) {
        block[pos++] = data[i];
        if (pos == 64) { md5_transform(state, block); pos = 0; }
    }

    block[pos++] = 0x80;
    if (pos > 56) {
        while (pos < 64) block[pos++] = 0;
        md5_transform(state, block);
        pos = 0;
    }
    while (pos < 56) block[pos++] = 0;

    for (int i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(bit_len >> (i * 8));
    }
    md5_transform(state, block);

    for (int i = 0; i < 4; i++) {
        digest[i*4]     = (uint8_t)(state[i]);
        digest[i*4 + 1] = (uint8_t)(state[i] >> 8);
        digest[i*4 + 2] = (uint8_t)(state[i] >> 16);
        digest[i*4 + 3] = (uint8_t)(state[i] >> 24);
    }
}

__global__ void md5_batch_kernel(
    const uint8_t *inputs, const int *lens, int stride,
    uint8_t *hashes, int count) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    md5_hash(inputs + (size_t)idx * stride, lens[idx], hashes + (size_t)idx * MD5_SIZE);
}

int cuda_md5_batch(const char **inputs, const int *lens, int count, uint8_t *hashes_out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;

    uint8_t *d_inputs = NULL, *d_hashes = NULL;
    int *d_lens = NULL;
    size_t buf_size = (size_t)count * max_len;
    cudaMalloc(&d_inputs, buf_size);
    cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_hashes, (size_t)count * MD5_SIZE);

    uint8_t *h_buf = (uint8_t *)malloc(buf_size);
    memset(h_buf, 0, buf_size);
    for (int i = 0; i < count; i++) {
        memcpy(h_buf + (size_t)i * max_len, inputs[i], lens[i]);
    }
    cudaMemcpy(d_inputs, h_buf, buf_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);

    int block = 256;
    int grid = (count + block - 1) / block;
    md5_batch_kernel<<<grid, block>>>(d_inputs, d_lens, max_len, d_hashes, count);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("MD5 kernel error: %s\n", cudaGetErrorString(err));
        free(h_buf); cudaFree(d_inputs); cudaFree(d_lens); cudaFree(d_hashes);
        return -1;
    }
    cudaDeviceSynchronize();
    cudaMemcpy(hashes_out, d_hashes, (size_t)count * MD5_SIZE, cudaMemcpyDeviceToHost);

    free(h_buf); cudaFree(d_inputs); cudaFree(d_lens); cudaFree(d_hashes);
    return 0;
}

// === SHA256 批量哈希 ===

__device__ inline uint32_t sha256_rotr(uint32_t x, unsigned int n) { return (x >> n) | (x << (32 - n)); }
__device__ inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ ((~x) & z); }
__device__ inline uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
__device__ inline uint32_t sha256_bsig0(uint32_t x) { return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22); }
__device__ inline uint32_t sha256_bsig1(uint32_t x) { return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25); }
__device__ inline uint32_t sha256_ssig0(uint32_t x) { return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3); }
__device__ inline uint32_t sha256_ssig1(uint32_t x) { return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10); }

__device__ void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sha256_ssig1(w[i-2]) + w[i-7] + sha256_ssig0(w[i-15]) + w[i-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    for (int t = 0; t < 64; t++) {
        uint32_t T1 = h + sha256_bsig1(e) + sha256_ch(e, f, g) + K[t] + w[t];
        uint32_t T2 = sha256_bsig0(a) + sha256_maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha256_hash(const uint8_t *data, int data_len, uint8_t digest[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint64_t bit_len = (uint64_t)data_len * 8;
    uint8_t block[64];
    int pos = 0;

    for (int i = 0; i < data_len; i++) {
        block[pos++] = data[i];
        if (pos == 64) { sha256_transform(state, block); pos = 0; }
    }

    block[pos++] = 0x80;
    if (pos > 56) {
        while (pos < 64) block[pos++] = 0;
        sha256_transform(state, block);
        pos = 0;
    }
    while (pos < 56) block[pos++] = 0;

    for (int i = 7; i >= 0; i--) {
        block[56 + i] = (uint8_t)(bit_len >> ((7 - i) * 8));
    }
    sha256_transform(state, block);

    for (int i = 0; i < 8; i++) {
        digest[i*4]     = (uint8_t)(state[i] >> 24);
        digest[i*4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i*4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i*4 + 3] = (uint8_t)(state[i]);
    }
}

__global__ void sha256_batch_kernel(
    const uint8_t *inputs, const int *lens, int stride,
    uint8_t *hashes, int count) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    sha256_hash(inputs + (size_t)idx * stride, lens[idx], hashes + (size_t)idx * SHA256_SIZE);
}

int cuda_sha256_batch(const char **inputs, const int *lens, int count, uint8_t *hashes_out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;

    uint8_t *d_inputs = NULL, *d_hashes = NULL;
    int *d_lens = NULL;
    size_t buf_size = (size_t)count * max_len;
    cudaMalloc(&d_inputs, buf_size);
    cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_hashes, (size_t)count * SHA256_SIZE);

    uint8_t *h_buf = (uint8_t *)malloc(buf_size);
    memset(h_buf, 0, buf_size);
    for (int i = 0; i < count; i++) {
        memcpy(h_buf + (size_t)i * max_len, inputs[i], lens[i]);
    }
    cudaMemcpy(d_inputs, h_buf, buf_size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);

    int block = 256;
    int grid = (count + block - 1) / block;
    sha256_batch_kernel<<<grid, block>>>(d_inputs, d_lens, max_len, d_hashes, count);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("SHA256 kernel error: %s\n", cudaGetErrorString(err));
        free(h_buf); cudaFree(d_inputs); cudaFree(d_lens); cudaFree(d_hashes);
        return -1;
    }
    cudaDeviceSynchronize();
    cudaMemcpy(hashes_out, d_hashes, (size_t)count * SHA256_SIZE, cudaMemcpyDeviceToHost);

    free(h_buf); cudaFree(d_inputs); cudaFree(d_lens); cudaFree(d_hashes);
    return 0;
}

// === 通用 PBKDF2 批量计算 ===

__device__ void hmac_sha256(const uint8_t *key, int key_len,
                            const uint8_t *msg, int msg_len,
                            uint8_t result[32]) {
    uint8_t key_pad[64];
    if (key_len > 64) {
        sha256_hash(key, key_len, key_pad);
        for (int i = 32; i < 64; i++) key_pad[i] = 0;
    } else {
        for (int i = 0; i < key_len; i++) key_pad[i] = key[i];
        for (int i = key_len; i < 64; i++) key_pad[i] = 0;
    }

    uint8_t inner_key[64], outer_key[64];
    for (int i = 0; i < 64; i++) {
        inner_key[i] = key_pad[i] ^ IPAD;
        outer_key[i] = key_pad[i] ^ OPAD;
    }

    uint8_t inner_msg[64 + MAX_MSG_LEN];
    for (int i = 0; i < 64; i++) inner_msg[i] = inner_key[i];
    for (int i = 0; i < msg_len; i++) inner_msg[64 + i] = msg[i];

    uint8_t inner_hash[32];
    sha256_hash(inner_msg, 64 + msg_len, inner_hash);

    uint8_t outer_msg[64 + 32];
    for (int i = 0; i < 64; i++) outer_msg[i] = outer_key[i];
    for (int i = 0; i < 32; i++) outer_msg[64 + i] = inner_hash[i];

    sha256_hash(outer_msg, 64 + 32, result);
}

__device__ void pbkdf2_generic_sha1(const uint8_t *pass, int pass_len,
                                     const uint8_t *salt, int salt_len,
                                     int iterations, int key_len,
                                     uint8_t *dk) {
    int blocks = (key_len + SHA1_DIGEST_SIZE - 1) / SHA1_DIGEST_SIZE;
    uint8_t u[SHA1_DIGEST_SIZE];
    for (int blk = 1; blk <= blocks; blk++) {
        uint8_t salt_block[128];
        int sbl = 0;
        for (int i = 0; i < salt_len; i++) salt_block[sbl++] = salt[i];
        salt_block[sbl++] = (uint8_t)(blk >> 24);
        salt_block[sbl++] = (uint8_t)(blk >> 16);
        salt_block[sbl++] = (uint8_t)(blk >> 8);
        salt_block[sbl++] = (uint8_t)(blk);

        hmac_sha1(pass, pass_len, salt_block, salt_len + 4, u);
        for (int j = 0; j < SHA1_DIGEST_SIZE; j++)
            dk[(blk-1)*SHA1_DIGEST_SIZE + j] = u[j];

        for (int iter = 1; iter < iterations; iter++) {
            hmac_sha1(pass, pass_len, u, SHA1_DIGEST_SIZE, u);
            for (int j = 0; j < SHA1_DIGEST_SIZE; j++)
                dk[(blk-1)*SHA1_DIGEST_SIZE + j] ^= u[j];
        }
    }
}

__device__ void pbkdf2_generic_sha256(const uint8_t *pass, int pass_len,
                                       const uint8_t *salt, int salt_len,
                                       int iterations, int key_len,
                                       uint8_t *dk) {
    int blocks = (key_len + SHA256_SIZE - 1) / SHA256_SIZE;
    uint8_t u[SHA256_SIZE];
    for (int blk = 1; blk <= blocks; blk++) {
        uint8_t salt_block[128];
        int sbl = 0;
        for (int i = 0; i < salt_len; i++) salt_block[sbl++] = salt[i];
        salt_block[sbl++] = (uint8_t)(blk >> 24);
        salt_block[sbl++] = (uint8_t)(blk >> 16);
        salt_block[sbl++] = (uint8_t)(blk >> 8);
        salt_block[sbl++] = (uint8_t)(blk);

        hmac_sha256(pass, pass_len, salt_block, salt_len + 4, u);
        for (int j = 0; j < SHA256_SIZE; j++)
            dk[(blk-1)*SHA256_SIZE + j] = u[j];

        for (int iter = 1; iter < iterations; iter++) {
            hmac_sha256(pass, pass_len, u, SHA256_SIZE, u);
            for (int j = 0; j < SHA256_SIZE; j++)
                dk[(blk-1)*SHA256_SIZE + j] ^= u[j];
        }
    }
}

__global__ void pbkdf2_sha1_generic_kernel(
    const uint8_t *passwords, const int *pass_lens, int pass_stride,
    const uint8_t *salt, int salt_len,
    int iterations, int key_len,
    uint8_t *output, int count) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    pbkdf2_generic_sha1(
        passwords + (size_t)idx * pass_stride, pass_lens[idx],
        salt, salt_len, iterations, key_len,
        output + (size_t)idx * key_len);
}

__global__ void pbkdf2_sha256_generic_kernel(
    const uint8_t *passwords, const int *pass_lens, int pass_stride,
    const uint8_t *salt, int salt_len,
    int iterations, int key_len,
    uint8_t *output, int count) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    pbkdf2_generic_sha256(
        passwords + (size_t)idx * pass_stride, pass_lens[idx],
        salt, salt_len, iterations, key_len,
        output + (size_t)idx * key_len);
}

__global__ void pbkdf2_sha512_generic_kernel(
    const uint8_t *passwords, const int *pass_lens, int pass_stride,
    const uint8_t *salt, int salt_len,
    int iterations, int key_len,
    uint8_t *output, int count);

int cuda_pbkdf2_batch(
    const char **passwords, const int *pass_lens, int count,
    const char *salt, int salt_len,
    int iterations, int hash_alg, int key_len,
    uint8_t *output) {

    if (count <= 0 || key_len <= 0 || iterations <= 0) return -1;

    int max_pass_len = 0;
    for (int i = 0; i < count; i++) { if (pass_lens[i] > max_pass_len) max_pass_len = pass_lens[i]; }

    uint8_t *d_pw = NULL, *d_salt = NULL, *d_out = NULL;
    int *d_lens = NULL;
    size_t pw_buf = (size_t)count * max_pass_len;
    cudaMalloc(&d_pw, pw_buf);
    cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_salt, salt_len);
    cudaMalloc(&d_out, (size_t)count * key_len);

    uint8_t *h_buf = (uint8_t *)malloc(pw_buf);
    memset(h_buf, 0, pw_buf);
    for (int i = 0; i < count; i++)
        memcpy(h_buf + (size_t)i * max_pass_len, passwords[i], pass_lens[i]);

    cudaMemcpy(d_pw, h_buf, pw_buf, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, pass_lens, count * sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_salt, salt, salt_len, cudaMemcpyHostToDevice);

    int block = 256;
    int grid = (count + block - 1) / block;

    cudaError_t err;
    if (hash_alg == 0) {
        pbkdf2_sha1_generic_kernel<<<grid, block>>>(d_pw, d_lens, max_pass_len, d_salt, salt_len, iterations, key_len, d_out, count);
    } else if (hash_alg == 1) {
        pbkdf2_sha256_generic_kernel<<<grid, block>>>(d_pw, d_lens, max_pass_len, d_salt, salt_len, iterations, key_len, d_out, count);
    } else {
        pbkdf2_sha512_generic_kernel<<<grid, block>>>(d_pw, d_lens, max_pass_len, d_salt, salt_len, iterations, key_len, d_out, count);
    }

    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("PBKDF2 kernel error: %s\n", cudaGetErrorString(err));
        free(h_buf); cudaFree(d_pw); cudaFree(d_lens); cudaFree(d_salt); cudaFree(d_out);
        return -1;
    }
    cudaDeviceSynchronize();
    cudaMemcpy(output, d_out, (size_t)count * key_len, cudaMemcpyDeviceToHost);

    free(h_buf); cudaFree(d_pw); cudaFree(d_lens); cudaFree(d_salt); cudaFree(d_out);
    return 0;
}

// === 设备管理 ===

int cuda_set_device(int device_id) {
    cudaError_t err = cudaSetDevice(device_id);
    return (err == cudaSuccess) ? 0 : -1;
}

int cuda_sync_device(void) {
    cudaError_t err = cudaDeviceSynchronize();
    return (err == cudaSuccess) ? 0 : -1;
}

int cuda_get_device_info(int device, int *cc_major, int *cc_minor,
                         int *mp_count, int *max_threads, int *clock_khz) {
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, device);
    if (err != cudaSuccess) return -1;
    *cc_major = prop.major;
    *cc_minor = prop.minor;
    *mp_count = prop.multiProcessorCount;
    *max_threads = prop.maxThreadsPerBlock;
    *clock_khz = 0;
    return 0;
}

// === SHA512 批量哈希 ===

__device__ inline uint64_t sha512_rotr(uint64_t x, unsigned int n) { return (x >> n) | (x << (64 - n)); }
__device__ inline uint64_t sha512_ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ ((~x) & z); }
__device__ inline uint64_t sha512_maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
__device__ inline uint64_t sha512_bsig0(uint64_t x) { return sha512_rotr(x, 28) ^ sha512_rotr(x, 34) ^ sha512_rotr(x, 39); }
__device__ inline uint64_t sha512_bsig1(uint64_t x) { return sha512_rotr(x, 14) ^ sha512_rotr(x, 18) ^ sha512_rotr(x, 41); }
__device__ inline uint64_t sha512_ssig0(uint64_t x) { return sha512_rotr(x, 1) ^ sha512_rotr(x, 8) ^ (x >> 7); }
__device__ inline uint64_t sha512_ssig1(uint64_t x) { return sha512_rotr(x, 19) ^ sha512_rotr(x, 61) ^ (x >> 6); }

__device__ void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) | (uint64_t)block[i*8+7];
    }
    for (int i = 16; i < 80; i++)
        w[i] = sha512_ssig1(w[i-2]) + w[i-7] + sha512_ssig0(w[i-15]) + w[i-16];

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    const uint64_t K[80] = {
        0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
        0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
        0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
        0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
    };

    for (int t = 0; t < 80; t++) {
        uint64_t T1 = h + sha512_bsig1(e) + sha512_ch(e, f, g) + K[t] + w[t];
        uint64_t T2 = sha512_bsig0(a) + sha512_maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha512_hash(const uint8_t *data, int data_len, uint8_t digest[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    uint64_t bit_len = (uint64_t)data_len * 8;
    uint8_t block[128];
    int pos = 0;

    for (int i = 0; i < data_len; i++) {
        block[pos++] = data[i];
        if (pos == 128) { sha512_transform(state, block); pos = 0; }
    }

    block[pos++] = 0x80;
    if (pos > 112) {
        while (pos < 128) block[pos++] = 0;
        sha512_transform(state, block);
        pos = 0;
    }
    while (pos < 112) block[pos++] = 0;

    for (int i = 7; i >= 0; i--) {
        block[120 + i] = (uint8_t)(bit_len >> ((7 - i) * 8));
    }
    sha512_transform(state, block);

    for (int i = 0; i < 8; i++) {
        digest[i*8]     = (uint8_t)(state[i] >> 56);
        digest[i*8 + 1] = (uint8_t)(state[i] >> 48);
        digest[i*8 + 2] = (uint8_t)(state[i] >> 40);
        digest[i*8 + 3] = (uint8_t)(state[i] >> 32);
        digest[i*8 + 4] = (uint8_t)(state[i] >> 24);
        digest[i*8 + 5] = (uint8_t)(state[i] >> 16);
        digest[i*8 + 6] = (uint8_t)(state[i] >> 8);
        digest[i*8 + 7] = (uint8_t)(state[i]);
    }
}

__global__ void sha512_batch_kernel(const uint8_t *inputs, const int *lens, int stride, uint8_t *hashes, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    sha512_hash(inputs + (size_t)idx * stride, lens[idx], hashes + (size_t)idx * SHA512_SIZE);
}

int cuda_sha512_batch(const char **inputs, const int *lens, int count, uint8_t *hashes_out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_in = NULL, *d_out = NULL; int *d_lens = NULL;
    size_t buf = (size_t)count * max_len;
    cudaMalloc(&d_in, buf); cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_out, (size_t)count * SHA512_SIZE);
    uint8_t *h = (uint8_t *)malloc(buf); memset(h, 0, buf);
    for (int i = 0; i < count; i++) memcpy(h + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_in, h, buf, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    sha512_batch_kernel<<<grid, block>>>(d_in, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(hashes_out, d_out, (size_t)count * SHA512_SIZE, cudaMemcpyDeviceToHost);
    free(h); cudaFree(d_in); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

// === MD4 批量哈希 (用于 NTLM) ===

__device__ inline uint32_t md4_F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((~x) & z); }
__device__ inline uint32_t md4_G(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); }
__device__ inline uint32_t md4_H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
__device__ inline uint32_t md4_rotl(uint32_t x, unsigned int n) { return (x << n) | (x >> (32 - n)); }

__device__ void md4_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);

    // Round 1
    for (int i = 0; i < 16; i++) {
        uint32_t k = i; int s = (i & 3) == 0 ? 3 : ((i & 3) == 1 ? 7 : ((i & 3) == 2 ? 11 : 19));
        uint32_t tmp = a + md4_F(b, c, d) + x[k];
        a = d; d = c; c = b; b = md4_rotl(tmp, s);
    }
    // Round 2
    for (int i = 0; i < 16; i++) {
        uint32_t k = (i & 3) * 4 + (i >> 2); int s = (i & 3) == 0 ? 3 : ((i & 3) == 1 ? 5 : ((i & 3) == 2 ? 9 : 13));
        uint32_t tmp = a + md4_G(b, c, d) + x[k] + 0x5A827999;
        a = d; d = c; c = b; b = md4_rotl(tmp, s);
    }
    // Round 3
    int order[16] = {0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};
    for (int i = 0; i < 16; i++) {
        int s = (i & 3) == 0 ? 3 : ((i & 3) == 1 ? 9 : ((i & 3) == 2 ? 11 : 15));
        uint32_t tmp = a + md4_H(b, c, d) + x[order[i]] + 0x6ED9EBA1;
        a = d; d = c; c = b; b = md4_rotl(tmp, s);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

__device__ void md4_hash(const uint8_t *data, int data_len, uint8_t digest[16]) {
    uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    uint64_t bit_len = (uint64_t)data_len * 8;
    uint8_t block[64];
    int pos = 0;
    for (int i = 0; i < data_len; i++) {
        block[pos++] = data[i];
        if (pos == 64) { md4_transform(state, block); pos = 0; }
    }
    block[pos++] = 0x80;
    if (pos > 56) { while (pos < 64) block[pos++] = 0; md4_transform(state, block); pos = 0; }
    while (pos < 56) block[pos++] = 0;
    for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bit_len >> (i * 8));
    md4_transform(state, block);
    for (int i = 0; i < 4; i++) {
        digest[i*4] = (uint8_t)(state[i]);
        digest[i*4+1] = (uint8_t)(state[i] >> 8);
        digest[i*4+2] = (uint8_t)(state[i] >> 16);
        digest[i*4+3] = (uint8_t)(state[i] >> 24);
    }
}

__global__ void md4_batch_kernel(const uint8_t *inputs, const int *lens, int stride, uint8_t *hashes, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    md4_hash(inputs + (size_t)idx * stride, lens[idx], hashes + (size_t)idx * MD4_SIZE);
}

int cuda_md4_batch(const char **inputs, const int *lens, int count, uint8_t *hashes_out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_in = NULL, *d_out = NULL; int *d_lens = NULL;
    size_t buf = (size_t)count * max_len;
    cudaMalloc(&d_in, buf); cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_out, (size_t)count * MD4_SIZE);
    uint8_t *h = (uint8_t *)malloc(buf); memset(h, 0, buf);
    for (int i = 0; i < count; i++) memcpy(h + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_in, h, buf, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    md4_batch_kernel<<<grid, block>>>(d_in, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(hashes_out, d_out, (size_t)count * MD4_SIZE, cudaMemcpyDeviceToHost);
    free(h); cudaFree(d_in); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

// === NTLM 哈希批量 ===

__device__ void ntlm_hash_device(const uint8_t *pass, int pass_len, uint8_t digest[16]) {
    uint8_t utf16[256];
    int ul = 0;
    for (int i = 0; i < pass_len && ul < 254; i++) {
        utf16[ul++] = pass[i];
        utf16[ul++] = 0;
    }
    md4_hash(utf16, ul, digest);
}

__global__ void ntlm_batch_kernel(const uint8_t *inputs, const int *lens, int stride, uint8_t *hashes, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    ntlm_hash_device(inputs + (size_t)idx * stride, lens[idx], hashes + (size_t)idx * MD4_SIZE);
}

int cuda_ntlm_batch(const char **inputs, const int *lens, int count, uint8_t *hashes_out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_in = NULL, *d_out = NULL; int *d_lens = NULL;
    size_t buf = (size_t)count * max_len;
    cudaMalloc(&d_in, buf); cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_out, (size_t)count * MD4_SIZE);
    uint8_t *h = (uint8_t *)malloc(buf); memset(h, 0, buf);
    for (int i = 0; i < count; i++) memcpy(h + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_in, h, buf, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    ntlm_batch_kernel<<<grid, block>>>(d_in, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(hashes_out, d_out, (size_t)count * MD4_SIZE, cudaMemcpyDeviceToHost);
    free(h); cudaFree(d_in); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

// === HMAC 批量 ===

__global__ void hmac_sha1_batch_kernel(const uint8_t *key, int key_len,
    const uint8_t *msgs, const int *msg_lens, int msg_stride,
    uint8_t *outs, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    hmac_sha1(key, key_len,
        msgs + (size_t)idx * msg_stride, msg_lens[idx],
        outs + (size_t)idx * SHA1_DIGEST_SIZE);
}

__global__ void hmac_sha256_batch_kernel(const uint8_t *key, int key_len,
    const uint8_t *msgs, const int *msg_lens, int msg_stride,
    uint8_t *outs, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    hmac_sha256(key, key_len,
        msgs + (size_t)idx * msg_stride, msg_lens[idx],
        outs + (size_t)idx * SHA256_SIZE);
}

__device__ void hmac_sha512_device(const uint8_t *key, int key_len,
    const uint8_t *msg, int msg_len, uint8_t result[64]) {
    uint8_t key_pad[128];
    if (key_len > 128) {
        sha512_hash(key, key_len, key_pad);
        for (int i = 64; i < 128; i++) key_pad[i] = 0;
    } else {
        for (int i = 0; i < key_len; i++) key_pad[i] = key[i];
        for (int i = key_len; i < 128; i++) key_pad[i] = 0;
    }
    uint8_t ik[128], ok[128];
    for (int i = 0; i < 128; i++) { ik[i] = key_pad[i] ^ 0x36; ok[i] = key_pad[i] ^ 0x5c; }
    uint8_t im[128 + MAX_MSG_LEN];
    for (int i = 0; i < 128; i++) im[i] = ik[i];
    for (int i = 0; i < msg_len; i++) im[128 + i] = msg[i];
    uint8_t ih[64];
    sha512_hash(im, 128 + msg_len, ih);
    uint8_t om[128 + 64];
    for (int i = 0; i < 128; i++) om[i] = ok[i];
    for (int i = 0; i < 64; i++) om[128 + i] = ih[i];
    sha512_hash(om, 128 + 64, result);
}

__global__ void hmac_sha512_batch_kernel(const uint8_t *key, int key_len,
    const uint8_t *msgs, const int *msg_lens, int msg_stride,
    uint8_t *outs, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    hmac_sha512_device(key, key_len,
        msgs + (size_t)idx * msg_stride, msg_lens[idx],
        outs + (size_t)idx * SHA512_SIZE);
}

int cuda_hmac_sha1_batch(const char **inputs, const int *lens, int count,
    const char *key_str, int key_len, uint8_t *out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_key = NULL, *d_msgs = NULL, *d_out = NULL; int *d_lens = NULL;
    cudaMalloc(&d_key, key_len); cudaMalloc(&d_msgs, (size_t)count * max_len);
    cudaMalloc(&d_lens, count * sizeof(int)); cudaMalloc(&d_out, (size_t)count * 20);
    cudaMemcpy(d_key, key_str, key_len, cudaMemcpyHostToDevice);
    uint8_t *h_buf = (uint8_t *)malloc((size_t)count * max_len);
    memset(h_buf, 0, (size_t)count * max_len);
    for (int i = 0; i < count; i++) memcpy(h_buf + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_msgs, h_buf, (size_t)count * max_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    hmac_sha1_batch_kernel<<<grid, block>>>(d_key, key_len, d_msgs, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(out, d_out, (size_t)count * 20, cudaMemcpyDeviceToHost);
    free(h_buf); cudaFree(d_key); cudaFree(d_msgs); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

int cuda_hmac_sha256_batch(const char **inputs, const int *lens, int count,
    const char *key_str, int key_len, uint8_t *out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_key = NULL, *d_msgs = NULL, *d_out = NULL; int *d_lens = NULL;
    cudaMalloc(&d_key, key_len); cudaMalloc(&d_msgs, (size_t)count * max_len);
    cudaMalloc(&d_lens, count * sizeof(int)); cudaMalloc(&d_out, (size_t)count * 32);
    cudaMemcpy(d_key, key_str, key_len, cudaMemcpyHostToDevice);
    uint8_t *h_buf = (uint8_t *)malloc((size_t)count * max_len);
    memset(h_buf, 0, (size_t)count * max_len);
    for (int i = 0; i < count; i++) memcpy(h_buf + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_msgs, h_buf, (size_t)count * max_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    hmac_sha256_batch_kernel<<<grid, block>>>(d_key, key_len, d_msgs, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(out, d_out, (size_t)count * 32, cudaMemcpyDeviceToHost);
    free(h_buf); cudaFree(d_key); cudaFree(d_msgs); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

int cuda_hmac_sha512_batch(const char **inputs, const int *lens, int count,
    const char *key_str, int key_len, uint8_t *out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_key = NULL, *d_msgs = NULL, *d_out = NULL; int *d_lens = NULL;
    cudaMalloc(&d_key, key_len); cudaMalloc(&d_msgs, (size_t)count * max_len);
    cudaMalloc(&d_lens, count * sizeof(int)); cudaMalloc(&d_out, (size_t)count * 64);
    cudaMemcpy(d_key, key_str, key_len, cudaMemcpyHostToDevice);
    uint8_t *h_buf = (uint8_t *)malloc((size_t)count * max_len);
    memset(h_buf, 0, (size_t)count * max_len);
    for (int i = 0; i < count; i++) memcpy(h_buf + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_msgs, h_buf, (size_t)count * max_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    hmac_sha512_batch_kernel<<<grid, block>>>(d_key, key_len, d_msgs, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(out, d_out, (size_t)count * 64, cudaMemcpyDeviceToHost);
    free(h_buf); cudaFree(d_key); cudaFree(d_msgs); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

// === SHA256d (双 SHA256, Bitcoin 用) ===

__device__ void sha256d_hash(const uint8_t *data, int data_len, uint8_t digest[32]) {
    uint8_t tmp[32];
    sha256_hash(data, data_len, tmp);
    sha256_hash(tmp, 32, digest);
}

__global__ void sha256d_batch_kernel(const uint8_t *inputs, const int *lens, int stride, uint8_t *hashes, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    sha256d_hash(inputs + (size_t)idx * stride, lens[idx], hashes + (size_t)idx * SHA256_SIZE);
}

int cuda_sha256d_batch(const char **inputs, const int *lens, int count, uint8_t *hashes_out) {
    if (count <= 0) return 0;
    int max_len = 0;
    for (int i = 0; i < count; i++) { if (lens[i] > max_len) max_len = lens[i]; }
    if (max_len <= 0) return 0;
    uint8_t *d_in = NULL, *d_out = NULL; int *d_lens = NULL;
    size_t buf = (size_t)count * max_len;
    cudaMalloc(&d_in, buf); cudaMalloc(&d_lens, count * sizeof(int));
    cudaMalloc(&d_out, (size_t)count * SHA256_SIZE);
    uint8_t *h = (uint8_t *)malloc(buf); memset(h, 0, buf);
    for (int i = 0; i < count; i++) memcpy(h + (size_t)i * max_len, inputs[i], lens[i]);
    cudaMemcpy(d_in, h, buf, cudaMemcpyHostToDevice);
    cudaMemcpy(d_lens, lens, count * sizeof(int), cudaMemcpyHostToDevice);
    int block = 256, grid = (count + 255) / 256;
    sha256d_batch_kernel<<<grid, block>>>(d_in, d_lens, max_len, d_out, count);
    cudaDeviceSynchronize();
    cudaMemcpy(hashes_out, d_out, (size_t)count * SHA256_SIZE, cudaMemcpyDeviceToHost);
    free(h); cudaFree(d_in); cudaFree(d_lens); cudaFree(d_out);
    return 0;
}

// === 扩展 PBKDF2 支持 SHA512 ===

__device__ void pbkdf2_generic_sha512(const uint8_t *pass, int pass_len,
                                       const uint8_t *salt, int salt_len,
                                       int iterations, int key_len,
                                       uint8_t *dk) {
    int blocks = (key_len + SHA512_SIZE - 1) / SHA512_SIZE;
    uint8_t u[SHA512_SIZE];
    for (int blk = 1; blk <= blocks; blk++) {
        uint8_t salt_block[128];
        int sbl = 0;
        for (int i = 0; i < salt_len; i++) salt_block[sbl++] = salt[i];
        salt_block[sbl++] = (uint8_t)(blk >> 24);
        salt_block[sbl++] = (uint8_t)(blk >> 16);
        salt_block[sbl++] = (uint8_t)(blk >> 8);
        salt_block[sbl++] = (uint8_t)(blk);

        hmac_sha512_device(pass, pass_len, salt_block, salt_len + 4, u);
        for (int j = 0; j < SHA512_SIZE; j++)
            dk[(blk-1)*SHA512_SIZE + j] = u[j];

        for (int iter = 1; iter < iterations; iter++) {
            hmac_sha512_device(pass, pass_len, u, SHA512_SIZE, u);
            for (int j = 0; j < SHA512_SIZE; j++)
                dk[(blk-1)*SHA512_SIZE + j] ^= u[j];
        }
    }
}

__global__ void pbkdf2_sha512_generic_kernel(
    const uint8_t *passwords, const int *pass_lens, int pass_stride,
    const uint8_t *salt, int salt_len,
    int iterations, int key_len,
    uint8_t *output, int count) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    pbkdf2_generic_sha512(
        passwords + (size_t)idx * pass_stride, pass_lens[idx],
        salt, salt_len, iterations, key_len,
        output + (size_t)idx * key_len);
}

#ifdef __cplusplus
}
#endif
