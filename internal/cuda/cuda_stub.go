//go:build !cuda

package cuda

// 本文件是未启用 CUDA 构建（默认 go build）时的桩实现：
// 所有底层能力都不可用，公共 API 据此返回 ErrNotCompiled，
// 调用方（shadow --gpu）捕获后打印提示并回退 CPU。

func compiled() bool { return false }

func deviceCount() int { return 0 }

func deviceAt(index int) (string, int64, error) { return "", 0, ErrNotCompiled }

func verifyNative(algo int, data []byte, offs, lens []int32, salt string, rounds int, key string, device int) (int, error) {
	return -1, ErrNotCompiled
}

func checkNative(algo int, password, salt string, rounds int, key string) (int, error) {
	return 0, ErrNotCompiled
}

func verifyHashNative(algo int, data []byte, offs, lens []int32, salt, extra, check, iv []byte, iter, keyLen, device int) (int, error) {
	return -1, ErrNotCompiled
}

func verifyHashBeginNative(algo int, data []byte, offs, lens []int32, salt, extra, check, iv []byte, iter, keyLen, device int) (int, error) {
	return -1, ErrNotCompiled
}

func verifyHashEndNative(handle, device int) (int, error) {
	return -1, ErrNotCompiled
}

func verifyBeginNative(algo int, data []byte, offs, lens []int32, salt string, rounds int, key string, device int) (int, error) {
	return -1, ErrNotCompiled
}

func verifyEndNative(handle, device int) (int, error) {
	return -1, ErrNotCompiled
}

func pipelineSlotsNative() int { return 0 }

func checkHashNative(algo int, password string, salt, extra, check, iv []byte, iter, keyLen int) (int, error) {
	return 0, ErrNotCompiled
}
