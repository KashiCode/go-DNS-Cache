package main

import "encoding/binary"

// ---- DNS flag bit-positions (RFC 1035) ----
const (
	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7
)


func patchHeader(resp, clientReq []byte) []byte {
	if len(resp) < 12 || len(clientReq) < 12 {
		return resp // safety guard
	}

	out := append([]byte(nil), resp...) 
	
	copy(out[0:2], clientReq[0:2])

	
	cFlags := binary.BigEndian.Uint16(clientReq[2:4])
	rFlags := binary.BigEndian.Uint16(out[2:4])

	rFlags &^= flagAA               
	rFlags |= flagRA                
	rFlags &^= flagRD               
	if cFlags&flagRD != 0 {
		rFlags |= flagRD
	}
	binary.BigEndian.PutUint16(out[2:4], rFlags)

	return out
}
