// +build android
package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
import "C"

import (
	"bufio"
	"log"
	"math"
	"net"
	"strings"

	"golang.org/x/sys/unix"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type AndroidLogger struct {
	level C.int
}

func (logger AndroidLogger) Write(buffer []byte) (int, error) {
	C.__android_log_write(logger.level, C.CString("wireguard"), C.CString(string(buffer)))
	return len(buffer), nil
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	fd, err := handle.device.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return -1
	}
	fd, err := handle.device.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return int32(fd)
}

//export wgTurnOnWithFdAndroid
func wgTurnOnWithFdAndroid(cIfaceName *C.char, mtu int, cSettings *C.char, fd int, loggingFd int, level int) int32 {

	logger := &device.Logger {
		Debug: log.New(&AndroidLogger { level: C.ANDROID_LOG_DEBUG }, "", 0),
		Info: log.New(&AndroidLogger { level: C.ANDROID_LOG_INFO }, "", 0),
		Error: log.New(&AndroidLogger { level: C.ANDROID_LOG_ERROR }, "", 0),
	}

	if cIfaceName == nil {
		logger.Error.Println("cIfaceName is null")
		return -1
	}

	if cSettings == nil {
		logger.Error.Println("cSettings is null")
		return -1
	}
	settings := C.GoString(cSettings)
	ifaceName := C.GoString(cIfaceName)

	tunDevice, ifaceName, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		logger.Error.Println(err)
		unix.Close(fd)
		if (err.Error() == "bad file descriptor") {
			return -2
		}
		return -1
	}
	device := device.NewDevice(tunDevice, logger)

	var uapi net.Listener

	uapiFile, err := ipc.UAPIOpen(ifaceName)
	if err != nil {
		logger.Error.Println(err)
	} else {
		uapi, err = ipc.UAPIListen(ifaceName, uapiFile)
		if err != nil {
			logger.Error.Println("Failed to start the UAPI")
			logger.Error.Println(err)
			uapiFile.Close()
		} else {
			go func() {
				for {
					conn, err := uapi.Accept()
					if err != nil {
						return
					}
					go device.IpcHandle(conn)
				}
			}()
		}
	}

	setError := device.IpcSetOperation(bufio.NewReader(strings.NewReader(settings)))
	if setError != nil {
		logger.Error.Println(setError)
		device.Close()
		return -2
	}
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		device.Close()
		return -1
	}
	tunnelHandles[i] = TunnelHandle{device: device, uapi: uapi}
	device.Up()

	return i
}
