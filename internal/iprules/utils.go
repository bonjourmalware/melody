package iprules

// From https://github.com/apparentlymart/go-cidr/blob/master/cidr/cidr.go
import (
	"fmt"
	"math/big"
	"net"
)

func AddressRange(network *net.IPNet) (net.IP, net.IP, error) {
	// the first IP is easy
	firstIP := network.IP

	// the last IP is the network address OR NOT the mask address
	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		// Easy!
		// But make sure that our two slices are distinct, since they
		// would be in all other cases.
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP, nil
	}

	firstIPInt, bits, err := ipToInt(firstIP)
	if err != nil {
		return net.IP{}, net.IP{}, err
	}

	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)

	return firstIP, intToIP(lastIPInt, bits), nil
}

func ipToInt(ip net.IP) (*big.Int, int, error) {
	val := &big.Int{}
	val.SetBytes(ip)
	if len(ip) == net.IPv4len {
		return val, 32, nil
	} else if len(ip) == net.IPv6len {
		return val, 128, nil
	}

	return nil, 0, fmt.Errorf("unsupported address length %d", len(ip))
}

func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8)
	// Pack our IP bytes into the end of the return array,
	// since big.Int.Bytes() removes front zero padding.
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}
	return ret
}
