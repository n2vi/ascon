# test vectors from ASCON developers' submission to NIST LightWeightCrypto.
test:
	go test

# for inspecting generated code, especially of round()
asm: Makefile sam ascon80pq.go
	go build -gcflags=-S 2>asm && sam -d asm < sam
