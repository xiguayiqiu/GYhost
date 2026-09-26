
#ifndef CUDA_KERNEL_H
#define CUDA_KERNEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int cuda_get_device_count(void);
int cuda_get_device_name(int device, char *name, int max_len);
long long cuda_get_device_memory(int device);

int cuda_wpa2_pmk_batch(
    const char **passwords, const int *pass_lens, int num_passwords,
    const char *ssid, int ssid_len, uint8_t *pmks_out);

int cuda_md5_batch(const char **inputs, const int *lens, int count, uint8_t *out);
int cuda_sha256_batch(const char **inputs, const int *lens, int count, uint8_t *out);
int cuda_sha512_batch(const char **inputs, const int *lens, int count, uint8_t *out);
int cuda_md4_batch(const char **inputs, const int *lens, int count, uint8_t *out);
int cuda_ntlm_batch(const char **inputs, const int *lens, int count, uint8_t *out);
int cuda_sha256d_batch(const char **inputs, const int *lens, int count, uint8_t *out);

int cuda_hmac_sha1_batch(const char **inputs, const int *lens, int count,
    const char *key, int key_len, uint8_t *out);
int cuda_hmac_sha256_batch(const char **inputs, const int *lens, int count,
    const char *key, int key_len, uint8_t *out);
int cuda_hmac_sha512_batch(const char **inputs, const int *lens, int count,
    const char *key, int key_len, uint8_t *out);

int cuda_pbkdf2_batch(
    const char **passwords, const int *pass_lens, int count,
    const char *salt, int salt_len,
    int iterations, int hash_alg, int key_len, uint8_t *output);

int cuda_set_device(int device_id);
int cuda_sync_device(void);

int cuda_get_device_info(int device, int *cc_major, int *cc_minor,
                         int *mp_count, int *max_threads, int *clock_khz);

#ifdef __cplusplus
}
#endif
#endif
