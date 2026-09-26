/*
 * cuda.h — GYhost 公共 NVIDIA CUDA 加速接口。
 *
 * 本文件与同目录下的 cuda.cu 构成 GYhost 的公共 CUDA 库：
 * shadow 模块以及后续任何需要 GPU 加速的模块，统一通过
 * internal/cuda/cuda.go（cgo）调用这里声明的 extern "C" 函数，
 * 业务代码不直接触碰 CUDA 运行时。
 *
 * 接口风格参考项目内 cuda_kernel/cuda_kernel.h：
 *   - 设备查询（数量/名称/显存/选卡）
 *   - 批量校验（一个目标哈希 × 一批候选密码）
 *
 * 编译: nvcc -O2 -Xcompiler -fPIC -c cuda.cu && ar rcs libgyhost_cuda.a cuda.o
 * 链接: go build -tags cuda
 */
#ifndef GYHOST_CUDA_H
#define GYHOST_CUDA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 返回码（负数为错误） ---- */
#define GYHOST_CUDA_OK 0
#define GYHOST_CUDA_ERR_PARAM (-1)  /* 参数非法（长度/空指针/设备号） */
#define GYHOST_CUDA_ERR_NO_DEV (-2) /* 没有可用的 CUDA 设备 */
#define GYHOST_CUDA_ERR_ALLOC (-3)  /* 显存分配失败 */
#define GYHOST_CUDA_ERR_KERNEL (-4) /* 内核启动或同步失败 */
#define GYHOST_CUDA_ERR_ALGO (-5)   /* 不支持的哈希算法 */

/* ---- 算法编号：与 internal/pwdhash 的 AlgoOf 保持一致 ---- */
#define GYHOST_ALGO_MD5CRYPT 1    /* $1$   */
#define GYHOST_ALGO_SHA256CRYPT 5  /* $5$   */
#define GYHOST_ALGO_SHA512CRYPT 6  /* $6$   */

/* ---- 通用哈希算法编号：与 internal/cuda 的 HashXxx 常量保持一致 ---- */
#define GYHOST_HASH_RAW_MD5 100
#define GYHOST_HASH_RAW_SHA1 101
#define GYHOST_HASH_RAW_SHA256 102
#define GYHOST_HASH_RAW_SHA512 103
#define GYHOST_HASH_ZIP_AES 110
#define GYHOST_HASH_ZIPCRYPTO 111 /* ZipCrypto 传统加密（-m 17200/17210），弱校验 */
#define GYHOST_HASH_WPA2_PMKID 120
#define GYHOST_HASH_WPA2_EAPOL 121 /* WPA/WPA2 四次握手（-m 22000 的 WPA*02*） */
#define GYHOST_HASH_RAR5 130
#define GYHOST_HASH_RAR3HP 131 /* RAR3 -hp 头加密（-m 12500） */
#define GYHOST_HASH_7Z 140     /* 7z AES-256，仅 Copy 编码器（-m 11600 的子集） */

/*
 * 通用哈希各字段的长度上限（与 internal/cuda 的 MaxHash* 一致）。
 *
 * MAX_DATA 取 384：WPA2-EAPOL 的 extra 为「MAC块(12) + ANonce(32) + EAPOL 帧」，
 * 需要容纳接近 255 字节的 802.1X 帧。
 */
#define GYHOST_HASH_MAX_SALT 64
#define GYHOST_HASH_MAX_DATA 384
#define GYHOST_HASH_MAX_CHECK 64


/* ============================ 设备查询 ============================ */

/* 是否存在可用设备：1 可用 / 0 不可用（含驱动缺失、初始化失败）。 */
int gyhost_cuda_available(void);

/* 设备数量；CUDA 不可用时返回 0。 */
int gyhost_cuda_device_count(void);

/* 读取设备名称，成功返回 GYHOST_CUDA_OK，失败返回负数错误码。 */
int gyhost_cuda_device_name(int device, char *buf, int buf_len);

/* 设备显存总量（MB）；失败返回 0。 */
long long gyhost_cuda_device_memory(int device);

/* 选中设备，供后续校验调用使用。 */
int gyhost_cuda_set_device(int device);

/* 该算法编号是否支持 GPU 校验（1/5/6）。 */
int gyhost_cuda_supported(int algo);

/* 错误码转可读描述（英文，供日志/调试使用）。 */
const char *gyhost_cuda_strerror(int code);

/* ============================ 校验接口 ============================ */

/*
 * gyhost_cuda_check_host — 主机端（CPU）参考实现。
 *
 * 与 GPU 内核共用同一套 __host__ __device__ 算法代码，用于一致性自检与调试。
 * 返回 1 命中 / 0 未命中 / 负数错误码。
 *
 * pw      候选密码（按 pw_len 截取，可含 NUL）
 * salt    盐（按 salt_len 截取）
 * rounds  仅 sha-crypt 有意义；md5crypt 固定 1000 轮，此参数被忽略
 * key     目标密文（crypt base64，NUL 结尾）
 */
int gyhost_cuda_check_host(int algo, const char *pw, int pw_len,
                           const char *salt, int salt_len, int rounds,
                           const char *key);

/*
 * gyhost_cuda_verify — 批量校验候选密码（GPU）。
 *
 * 一批候选密码共享同一个目标哈希（salt/rounds/key 固定），
 * 内部按块分批发射内核，首个命中的候选下标写入 *match（无命中为 -1）。
 * 成功返回 GYHOST_CUDA_OK，失败返回负数错误码。
 *
 * pw_data  所有候选密码拼接后的连续缓冲
 * pw_total pw_data 的字节数（用于越界校验）
 * pw_off   第 i 个候选在 pw_data 中的偏移
 * pw_len   第 i 个候选的长度（<= 255）
 * count    候选数量（> 0）
 * device   设备编号
 */
int gyhost_cuda_verify(int algo,
                       const char *pw_data, int pw_total,
                       const int *pw_off, const int *pw_len, int count,
                       const char *salt, int salt_len, int rounds,
                       const char *key, int device, int *match);

/*
 * gyhost_cuda_check_hash — 通用哈希的主机端（CPU）参考实现。
 *
 * 与 GPU 内核共用同一套算法代码，返回 1 命中 / 0 未命中 / 负数错误码。
 * 各算法字段含义见 GYHOST_HASH_* 与 internal/cuda 的 HashXxx 注释。
 */
int gyhost_cuda_check_hash(int algo, const char *pw, int pw_len,
                           const char *salt, int salt_len,
                           const char *extra, int extra_len,
                           const char *check, int check_len,
                           const char *iv, int iv_len,
                           int iter, int key_len);

/*
 * gyhost_cuda_verify_hash — 通用哈希的批量校验（GPU）。
 *
 * 参数含义与 gyhost_cuda_verify 相同，另加：
 *   extra/extra_len  额外数据（ZIP AES 的密文、RAR3 的 16 字节密文头）
 *   check/check_len  目标校验值
 *   iv/iv_len        初始向量（仅 7z 使用，16 字节；其余算法传 NULL/0）
 *   iter             RAR5/7z 的 KDF power（RAR3 固定 2^18 轮，忽略）
 *   key_len          ZIP AES 的密钥长度 / 7z 的解压后字节数
 *
 * 注意：RAR3 与 7z 的候选密码按 UTF-16LE 编码传入（pw_len 为编码后的字节数），
 * 由 internal/cuda 在 Go 侧完成转换。
 */
int gyhost_cuda_verify_hash(int algo,
                            const char *pw_data, int pw_total,
                            const int *pw_off, const int *pw_len, int count,
                            const char *salt, int salt_len,
                            const char *extra, int extra_len,
                            const char *check, int check_len,
                            const char *iv, int iv_len,
                            int iter, int key_len,
                            int device, int *match);

/* 通用哈希算法编号是否受支持。 */
int gyhost_hash_supported(int algo);

#ifdef __cplusplus
}
#endif
#endif /* GYHOST_CUDA_H */
