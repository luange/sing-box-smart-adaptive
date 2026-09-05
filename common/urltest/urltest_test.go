package urltest

import "testing"

func TestProbeTLSServerName(t *testing.T) {
	for _, test := range []struct {
		host string
		want string
	}{
		{host: "1.1.1.1", want: "cloudflare-dns.com"},
		{host: "1.0.0.1", want: "cloudflare-dns.com"},
		{host: "www.gstatic.com", want: "www.gstatic.com"},
	} {
		t.Run(test.host, func(t *testing.T) {
			if got := probeTLSServerName(test.host); got != test.want {
				t.Fatalf("probeTLSServerName(%q) = %q, want %q", test.host, got, test.want)
			}
		})
	}
}
