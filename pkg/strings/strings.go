package strings

import (
	"net/url"
)

func Contains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func ContainDomain(list []string, needle string) bool {
	needleUrl, _ := url.Parse(needle)
	for _, item := range list {
		itemUrl, _ := url.Parse(item)
		if itemUrl.Hostname() == needleUrl.Hostname() {
			return true
		}
	}
	return false
}
