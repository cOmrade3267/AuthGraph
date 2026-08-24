package testdata

import "net/http"

func fetchPeerInfo(peerURL string) {
	resp, err := http.Get(peerURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
