package main

import (
	"fmt"
)

// #cgo LDFLAGS: -L/home/djwar/repos/Qasa/src/crypto/target/release -lqasa_crypto
// #include <stdlib.h>
// #include <stdint.h>
//
// typedef char* error_msg_t;
//
// int qasa_crypto_init(error_msg_t* error);
// void qasa_free_string(error_msg_t error);
import "C"

func main() {
	var errorPtr *C.error_msg_t
	result := C.qasa_crypto_init(&errorPtr)
	
	if result != 0 {
		fmt.Println("Error initializing crypto library")
		if errorPtr != nil {
			fmt.Printf("Error: %s\n", C.GoString(errorPtr))
			C.qasa_free_string(errorPtr)
		}
		return
	}
	
	fmt.Println("Successfully initialized the crypto library!")
}
