package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func printIssueSuccessSummary(out io.Writer, cn string, domains []string, role, certPEM string) {
	fmt.Fprintln(out, "\n✓ 证书签发成功！")
	tw := newTabWriter(out)
	fmt.Fprintf(tw, "Common Name:\t%s\n", cn)
	if len(domains) > 0 {
		fmt.Fprintf(tw, "Domains:\t%s\n", strings.Join(domains, ", "))
	}
	fmt.Fprintf(tw, "Role:\t%s\n", role)
	if nb, na := parseCertDates(certPEM); na != "" {
		fmt.Fprintf(tw, "Not Before:\t%s\n", nb)
		fmt.Fprintf(tw, "Not After:\t%s\n", na)
		rem := formatRemaining(na)
		fmt.Fprintf(tw, "Expires In:\t%s\n", rem)
	}
	_ = tw.Flush()
	fmt.Fprintln(out, "\n提示: 可使用 `bao-acme cert list` 查看全部证书，或 `bao-acme cert get <cert_id>` 随时查看与导出证书 PEM。")
}

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

func saveOrPrintCert(certPEM, keyPEM, outCert, outKey string, fullObj any) error {
	if outCert != "" && certPEM != "" {
		if err := os.WriteFile(outCert, []byte(certPEM), 0o644); err != nil {
			return fmt.Errorf("写入证书文件失败: %w", err)
		}
		fmt.Fprintf(os.Stderr, "证书已保存到: %s\n", outCert)
	}
	if outKey != "" && keyPEM != "" {
		if err := os.WriteFile(outKey, []byte(keyPEM), 0o600); err != nil {
			return fmt.Errorf("写入私钥文件失败: %w", err)
		}
		fmt.Fprintf(os.Stderr, "私钥已保存到: %s\n", outKey)
	}

	if outCert == "" && outKey == "" {
		if FlagFormat == "json" {
			PrintOutput(fullObj)
		} else {
			fmt.Println(certPEM)
			if keyPEM != "" {
				fmt.Println(keyPEM)
			}
		}
	}
	return nil
}
