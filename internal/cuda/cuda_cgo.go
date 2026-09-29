//go:build cuda

package cuda

/*
#cgo LDFLAGS: -L${SRCDIR} -lgyhost_cuda -L/opt/cuda/lib64 -L/usr/local/cuda/lib64 -lcudart -lstdc++
#include <stdlib.h>
#include "cuda.h"
*/
import "C"

import (
	"bytes"
	"unsafe"
)

// 本文件是 internal/cuda 的 cgo 绑定，仅在 -tags cuda 时参与编译；
// 未启用 CUDA 的构建见 cuda_stub.go。
//
// 依赖同目录下由 `cmake --build <dir> --target cuda-lib`（或直接构建 gyhost 目标）
// 生成的 libgyhost_cuda.a。

func compiled() bool { return true }

func deviceCount() int { return int(C.gyhost_cuda_device_count()) }

func deviceAt(index int) (name string, memoryMB int64, err error) {
	buf := make([]byte, 256)
	rc := int(C.gyhost_cuda_device_name(C.int(index), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))))
	if rc != codeOK {
		return "", 0, errFromCode(rc)
	}
	n := bytes.IndexByte(buf, 0)
	if n < 0 {
		n = len(buf)
	}
	memoryMB = int64(C.gyhost_cuda_device_memory(C.int(index)))
	return string(buf[:n]), memoryMB, nil
}

// verifyNative 调用 gyhost_cuda_verify，返回 (命中下标, 错误)。
func verifyNative(algo int, data []byte, offs, lens []int32, salt string, rounds int, key string, device int) (int, error) {
	if len(data) == 0 || len(offs) == 0 || len(offs) != len(lens) {
		return -1, ErrParam
	}

	cOffs := make([]C.int, len(offs))
	for i, v := range offs {
		cOffs[i] = C.int(v)
	}
	cLens := make([]C.int, len(lens))
	for i, v := range lens {
		cLens[i] = C.int(v)
	}

	cSalt, freeSalt := cBytes([]byte(salt))
	defer freeSalt()
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	var match C.int
	rc := int(C.gyhost_cuda_verify(
		C.int(algo),
		(*C.char)(unsafe.Pointer(&data[0])), C.int(len(data)),
		(*C.int)(unsafe.Pointer(&cOffs[0])),
		(*C.int)(unsafe.Pointer(&cLens[0])),
		C.int(len(cOffs)),
		(*C.char)(cSalt), C.int(len(salt)),
		C.int(rounds),
		(*C.char)(cKey),
		C.int(device),
		&match,
	))
	if rc != codeOK {
		return -1, errFromCode(rc)
	}
	return int(match), nil
}

// checkNative 调用 gyhost_cuda_check_host，返回 (1 命中 / 0 未命中, 错误)。
func checkNative(algo int, password, salt string, rounds int, key string) (int, error) {
	cPw, freePw := cBytes([]byte(password))
	defer freePw()
	cSalt, freeSalt := cBytes([]byte(salt))
	defer freeSalt()
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	rc := int(C.gyhost_cuda_check_host(
		C.int(algo),
		(*C.char)(cPw), C.int(len(password)),
		(*C.char)(cSalt), C.int(len(salt)),
		C.int(rounds),
		(*C.char)(cKey),
	))
	if rc < 0 {
		return 0, errFromCode(rc)
	}
	return rc, nil
}

// verifyBeginNative 调用 gyhost_cuda_verify_begin（crypt 目标的异步版），返回槽位句柄。
func verifyBeginNative(algo int, data []byte, offs, lens []int32, salt string, rounds int, key string, device int) (int, error) {
	if len(data) == 0 || len(offs) == 0 || len(offs) != len(lens) {
		return -1, ErrParam
	}

	cOffs := make([]C.int, len(offs))
	for i, v := range offs {
		cOffs[i] = C.int(v)
	}
	cLens := make([]C.int, len(lens))
	for i, v := range lens {
		cLens[i] = C.int(v)
	}

	cSalt, freeSalt := cBytes([]byte(salt))
	defer freeSalt()
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	var handle C.int
	rc := int(C.gyhost_cuda_verify_begin(
		C.int(algo),
		(*C.char)(unsafe.Pointer(&data[0])), C.int(len(data)),
		(*C.int)(unsafe.Pointer(&cOffs[0])),
		(*C.int)(unsafe.Pointer(&cLens[0])),
		C.int(len(cOffs)),
		(*C.char)(cSalt), C.int(len(salt)),
		C.int(rounds),
		(*C.char)(cKey),
		C.int(device),
		&handle,
	))
	if rc != codeOK {
		return -1, errFromCode(rc)
	}
	return int(handle), nil
}

// verifyEndNative 调用 gyhost_cuda_verify_end，返回 (命中下标, 错误)。
func verifyEndNative(handle, device int) (int, error) {
	var match C.int
	rc := int(C.gyhost_cuda_verify_end(
		C.int(handle),
		C.int(device),
		&match,
	))
	if rc != codeOK {
		return -1, errFromCode(rc)
	}
	return int(match), nil
}

// pipelineSlotsNative 返回 native 侧异步流水线可同时在飞的批次数。
func pipelineSlotsNative() int { return int(C.gyhost_cuda_pipeline_slots()) }

// verifyHashNative 调用 gyhost_cuda_verify_hash，返回 (命中下标, 错误)。
func verifyHashNative(algo int, data []byte, offs, lens []int32, salt, extra, check, iv []byte, iter, keyLen, device int) (int, error) {
	if len(data) == 0 || len(offs) == 0 || len(offs) != len(lens) {
		return -1, ErrParam
	}

	cOffs := make([]C.int, len(offs))
	for i, v := range offs {
		cOffs[i] = C.int(v)
	}
	cLens := make([]C.int, len(lens))
	for i, v := range lens {
		cLens[i] = C.int(v)
	}

	cSalt, freeSalt := cBytes(salt)
	defer freeSalt()
	cExtra, freeExtra := cBytes(extra)
	defer freeExtra()
	cCheck, freeCheck := cBytes(check)
	defer freeCheck()
	cIV, freeIV := cBytes(iv)
	defer freeIV()

	var match C.int
	rc := int(C.gyhost_cuda_verify_hash(
		C.int(algo),
		(*C.char)(unsafe.Pointer(&data[0])), C.int(len(data)),
		(*C.int)(unsafe.Pointer(&cOffs[0])),
		(*C.int)(unsafe.Pointer(&cLens[0])),
		C.int(len(cOffs)),
		(*C.char)(cSalt), C.int(len(salt)),
		(*C.char)(cExtra), C.int(len(extra)),
		(*C.char)(cCheck), C.int(len(check)),
		(*C.char)(cIV), C.int(len(iv)),
		C.int(iter), C.int(keyLen),
		C.int(device),
		&match,
	))
	if rc != codeOK {
		return -1, errFromCode(rc)
	}
	return int(match), nil
}

// verifyHashBeginNative 调用 gyhost_cuda_verify_hash_begin，返回 (槽位句柄, 错误)。
// 只上传候选并发射内核，不等待完成；用 verifyHashEndNative 取结果。
func verifyHashBeginNative(algo int, data []byte, offs, lens []int32, salt, extra, check, iv []byte, iter, keyLen, device int) (int, error) {
	if len(data) == 0 || len(offs) == 0 || len(offs) != len(lens) {
		return -1, ErrParam
	}

	cOffs := make([]C.int, len(offs))
	for i, v := range offs {
		cOffs[i] = C.int(v)
	}
	cLens := make([]C.int, len(lens))
	for i, v := range lens {
		cLens[i] = C.int(v)
	}

	cSalt, freeSalt := cBytes(salt)
	defer freeSalt()
	cExtra, freeExtra := cBytes(extra)
	defer freeExtra()
	cCheck, freeCheck := cBytes(check)
	defer freeCheck()
	cIV, freeIV := cBytes(iv)
	defer freeIV()

	var handle C.int
	rc := int(C.gyhost_cuda_verify_hash_begin(
		C.int(algo),
		(*C.char)(unsafe.Pointer(&data[0])), C.int(len(data)),
		(*C.int)(unsafe.Pointer(&cOffs[0])),
		(*C.int)(unsafe.Pointer(&cLens[0])),
		C.int(len(cOffs)),
		(*C.char)(cSalt), C.int(len(salt)),
		(*C.char)(cExtra), C.int(len(extra)),
		(*C.char)(cCheck), C.int(len(check)),
		(*C.char)(cIV), C.int(len(iv)),
		C.int(iter), C.int(keyLen),
		C.int(device),
		&handle,
	))
	if rc != codeOK {
		return -1, errFromCode(rc)
	}
	return int(handle), nil
}

// verifyHashEndNative 调用 gyhost_cuda_verify_hash_end，返回 (命中下标, 错误)。
func verifyHashEndNative(handle, device int) (int, error) {
	var match C.int
	rc := int(C.gyhost_cuda_verify_hash_end(
		C.int(handle),
		C.int(device),
		&match,
	))
	if rc != codeOK {
		return -1, errFromCode(rc)
	}
	return int(match), nil
}
func checkHashNative(algo int, password string, salt, extra, check, iv []byte, iter, keyLen int) (int, error) {
	cPw, freePw := cBytes([]byte(password))
	defer freePw()
	cSalt, freeSalt := cBytes(salt)
	defer freeSalt()
	cExtra, freeExtra := cBytes(extra)
	defer freeExtra()
	cCheck, freeCheck := cBytes(check)
	defer freeCheck()
	cIV, freeIV := cBytes(iv)
	defer freeIV()

	rc := int(C.gyhost_cuda_check_hash(
		C.int(algo),
		(*C.char)(cPw), C.int(len(password)),
		(*C.char)(cSalt), C.int(len(salt)),
		(*C.char)(cExtra), C.int(len(extra)),
		(*C.char)(cCheck), C.int(len(check)),
		(*C.char)(cIV), C.int(len(iv)),
		C.int(iter), C.int(keyLen),
	))
	if rc < 0 {
		return 0, errFromCode(rc)
	}
	return rc, nil
}

// cBytes 把字节切片复制到 C 内存（空切片也保证返回合法指针）。
func cBytes(b []byte) (unsafe.Pointer, func()) {
	if len(b) == 0 {
		b = []byte{0}
	}
	p := C.CBytes(b)
	return p, func() { C.free(p) }
}
