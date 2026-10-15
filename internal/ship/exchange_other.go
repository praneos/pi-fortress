//go:build !(linux && (arm64 || amd64))

package ship

const sysRenameat2 = 0
