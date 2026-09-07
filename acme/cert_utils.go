package acme

import (
	"crypto/x509"
	"encoding/pem"
	"time"
)

// parseCertDates 解析 PEM 证书中的生效时间和失效时间 (RFC3339 格式)
func parseCertDates(certPEM string) (string, string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ""
	}
	return cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339)
}

// certValidity 解析 PEM 证书并返回 time.Time 类型的 NotBefore 和 NotAfter
func certValidity(certPEM string) (time.Time, time.Time) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	return cert.NotBefore.UTC(), cert.NotAfter.UTC()
}
