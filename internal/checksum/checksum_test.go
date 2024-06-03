package checksum

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
)

func Example_md5() {
	dataOriginal := "check the validity of the string."
	md5Original := md5.Sum([]byte(dataOriginal))
	fmt.Printf("%x\n", md5Original)

	dataTampered := "check the validity of the string" // missing full-stop at the end
	md5Tampered := md5.Sum([]byte(dataTampered))
	fmt.Printf("%x\n", md5Tampered)

	if md5Original != md5Tampered {
		fmt.Println("data has been tampered")
	} else {
		fmt.Println("data has not been tampered")
	}

	// Output:
	// b0e2955f34bd91daea2ac671cf9c0cac
	// 0d5f102617870d313affe12144c7f005
	// data has been tampered
}

func Example_sha256() {
	dataOriginal := "check the validity of the string."
	sha256Original := sha256.Sum256([]byte(dataOriginal))
	fmt.Printf("%x\n", sha256Original)

	dataTampered := "check the validity of the string" // missing full-stop at the end
	sha256Tampered := sha256.Sum256([]byte(dataTampered))
	fmt.Printf("%x\n", sha256Tampered)

	if sha256Original != sha256Tampered {
		fmt.Println("data has been tampered")
	} else {
		fmt.Println("data has not been tampered")
	}

	// Output:
	// 9ce938d94b960c922152bd11b7229fbae1593a62fd71dd1635800b7317aeb675
	// e854ac17edc88cbc0554a3d8318d11a39ac355ce776bc5c5845b952911fa893f
	// data has been tampered
}
