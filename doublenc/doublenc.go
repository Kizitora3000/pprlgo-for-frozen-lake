package doublenc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

/*
	Why is MAX_RSA_CIPHERTEXT_SIZE 190?

When use OAEP, max size is ...

max_size = k - 2h - 2

k: RSA's bytes (2048 bit -> 256 byte)
h: hask output bytes (256 bit -> 32 byte)

therefore

max_size = 256 - 2 * 32 - 2 = 190 byte
*/
const MAX_RSA_CIPHERTEXT_SIZE = 190

func DEenc(params ckks.Parameters, encoder ckks.Encoder, encryptor rlwe.Encryptor, publicKey *rsa.PublicKey, vector []float64, filename string) [][]uint8 {
	fhe_ciphetext := FHEenc(params, encoder, encryptor, vector)
	rsa_ciphertext := RSAenc(publicKey, fhe_ciphetext, filename)

	return rsa_ciphertext
}

func DEdec(params ckks.Parameters, encoder ckks.Encoder, decryptor rlwe.Decryptor, privateKey *rsa.PrivateKey, filename string) []complex128 {
	fhe_ciphetext := RSAdec(privateKey, filename)
	plaintext := FHEdec(params, encoder, decryptor, fhe_ciphetext)

	return plaintext
}

func FHEenc(params ckks.Parameters, encoder ckks.Encoder, encryptor rlwe.Encryptor, vector []float64) *rlwe.Ciphertext {
	r := float64(16)

	values := make([]complex128, len(vector))
	for i := range values {
		values[i] = complex(vector[i], 0)
	}

	plaintext := ckks.NewPlaintext(params, params.MaxLevel())
	plaintext.Scale = plaintext.Scale.Div(rlwe.NewScale(r))
	encoder.Encode(values, plaintext, params.LogSlots())
	ciphertext := encryptor.EncryptNew(plaintext)

	return ciphertext
}

func FHEdec(params ckks.Parameters, encoder ckks.Encoder, decryptor rlwe.Decryptor, ciphertext *rlwe.Ciphertext) []complex128 {
	plaintext := encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())
	return plaintext
}

func RSAenc(publicKey *rsa.PublicKey, fhe_ciphetext *rlwe.Ciphertext, filename string) [][]uint8 {
	// convert ciphtext into bytes
	fhe_ciphetext_bytes, err := fhe_ciphetext.MarshalBinary()
	if err != nil {
		panic(err)
	}

	total_chunks := len(fhe_ciphetext_bytes) / MAX_RSA_CIPHERTEXT_SIZE

	// add total_chunks for a remain chunk.
	if len(fhe_ciphetext_bytes)%MAX_RSA_CIPHERTEXT_SIZE != 0 {
		total_chunks++
	}

	rsa_ciphertexts := make([][]byte, total_chunks)

	// split fhe_ciphetext_bytes and encrypt it by RSA
	for i := 0; i < total_chunks; i++ {
		start := i * MAX_RSA_CIPHERTEXT_SIZE
		end := start + MAX_RSA_CIPHERTEXT_SIZE
		if end > len(fhe_ciphetext_bytes) {
			end = len(fhe_ciphetext_bytes)
		}

		fhe_chunk := fhe_ciphetext_bytes[start:end]

		rsa_ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, fhe_chunk, nil)
		if err != nil {
			panic(err)
		}

		rsa_ciphertexts[i] = rsa_ciphertext
	}

	return rsa_ciphertexts
}

func RSAdec2(privateKey *rsa.PrivateKey, rsa_ciphertexts [][]uint8) *rlwe.Ciphertext {
	results := make([][]byte, len(rsa_ciphertexts))
	var wg sync.WaitGroup

	for i := 0; i < len(rsa_ciphertexts); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			rsa_ciphertext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, rsa_ciphertexts[i], nil)
			if err != nil {
				panic(err)
			}

			results[i] = rsa_ciphertext
		}(i)
	}
	wg.Wait()

	// Combine results in order
	fhe_ciphertext_bytes := []byte{}
	for _, bytes := range results {
		fhe_ciphertext_bytes = append(fhe_ciphertext_bytes, bytes...)
	}

	fhe_ciphertext := new(rlwe.Ciphertext)
	_ = fhe_ciphertext.UnmarshalBinary(fhe_ciphertext_bytes)

	return fhe_ciphertext
}

func RSAdec(privateKey *rsa.PrivateKey, filename string) *rlwe.Ciphertext {
	dir_path := "doublenc/output/rsa_" + filename

	dir_content, err := os.ReadDir(dir_path)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		os.Exit(1)
	}

	results := make([][]byte, len(dir_content))
	var wg sync.WaitGroup

	for i := 0; i < len(dir_content); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			rsa_filename := fmt.Sprintf(dir_path+"/rsa_%s_%d.txt", filename, i+1)
			splited_rsa_ciphertext, err := os.ReadFile(rsa_filename)
			if err != nil {
				panic(err)
			}

			splited_fhe_ciphertext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, splited_rsa_ciphertext, nil)
			if err != nil {
				panic(err)
			}

			results[i] = splited_fhe_ciphertext
		}(i)
	}

	wg.Wait()

	// Combine results in order
	fhe_ciphertext_bytes := []byte{}
	for _, bytes := range results {
		fhe_ciphertext_bytes = append(fhe_ciphertext_bytes, bytes...)
	}

	fhe_ciphertext := new(rlwe.Ciphertext)
	err = fhe_ciphertext.UnmarshalBinary(fhe_ciphertext_bytes)

	return fhe_ciphertext
}

func BFVenc(params bfv.Parameters, encoder bfv.Encoder, encryptor rlwe.Encryptor, vector []uint64) *rlwe.Ciphertext {
	plaintext := bfv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(vector, plaintext)
	ciphertext := encryptor.EncryptNew(plaintext)

	return ciphertext
}

func BFVdec(params bfv.Parameters, encoder bfv.Encoder, decryptor rlwe.Decryptor, ciphertext *rlwe.Ciphertext) []uint64 {
	plaintext := encoder.DecodeUintNew(decryptor.DecryptNew(ciphertext))
	return plaintext
}

func DEencBFV(params bfv.Parameters, encoder bfv.Encoder, encryptor rlwe.Encryptor, publicKey *rsa.PublicKey, vector []uint64, filename string) [][]uint8 {
	bfv_ciphetext := BFVenc(params, encoder, encryptor, vector)
	rsa_ciphertext := RSAenc(publicKey, bfv_ciphetext, filename)

	return rsa_ciphertext
}
