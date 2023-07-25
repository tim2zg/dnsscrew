package main

import (
	"strings"
)

func fixHostname(hostname string) string {
	if hostname == "" {
		return ""
	}

	sdomains := strings.Split(hostname, ".")
	reverseSlice(sdomains)

	dp1 := indexOf(sdomains, "cn")

	if dp1 == 0 {
		sdomains = removeElement(sdomains, 0)
	}

	dp2 := indexOf(sdomains, "amazonaws")
	dp3 := indexOf(sdomains, "s3")
	dp4 := indexOf(sdomains, "s3-control")
	dp5 := indexOf(sdomains, "s3-w")
	dp6 := indexOf(sdomains, "s3-accelerate")
	dp7 := indexOf(sdomains, "s3-accesspoint")
	dp8 := indexOf(sdomains, "s3-website")

	if dp2 == 1 {
		if len(sdomains) >= 3 {
			ssdomains := strings.Split(sdomains[2], "-")
			if len(sdomains) == 5 {
				sdomains[4] = sdomains[3]
			}

			if dp6 == 2 {
				sdomains = insertElement(sdomains, 2, "dualstack")
				dp1 = -1
			} else if dp7 == 3 {
				if len(sdomains) > 4 {
					sdomains = removeElement(sdomains, 4)
				}
			} else if dp8 == 3 {
				if len(sdomains) > 4 {
					sdomains = removeElement(sdomains, 4)
				}
				dp1 = -1
			} else if len(ssdomains) >= 2 && ssdomains[0] == "s3" && ssdomains[1] == "1" && dp1 != 0 {
				sdomains = insertElement(sdomains, 2, "us-east-1")
				sdomains = insertElement(sdomains, 4, "s3")
			} else if dp3 == 3 && dp1 != 0 {
				if len(sdomains) > 4 {
					sdomains = removeElement(sdomains, 4)
				}
			} else if dp4 == 3 && dp1 != 0 {
				if len(sdomains) > 4 {
					sdomains = removeElement(sdomains, 4)
				}
			} else if dp5 == 3 {
				sdomains = insertElement(sdomains, 4, "s3-w")
			} else if len(ssdomains) >= 2 && ssdomains[0] == "s3" && ssdomains[1] == "website" {
				sdomains = replaceElement(sdomains, 2, "us-east-1")
				if len(sdomains) > 3 {
					sdomains = replaceElement(sdomains, 3, "s3-website")
				}
			} else if len(ssdomains) > 1 {
				if ssdomains[0] != "s3" {
					return ""
				}

				sdomains = removeElement(sdomains, 2)

				if len(ssdomains) == 4 && dp1 != 0 {
					ssdomains = removeElement(ssdomains, 0)
				}

				sdomains = insertElement(sdomains, 2, strings.Join(ssdomains, "-"))

				if dp3 == -1 && len(sdomains) > 3 {
					sdomains = insertElement(sdomains, 3, "s3")
				}
			} else if dp2 == 1 && dp3 == 2 && dp1 != 0 {
				sdomains = insertElement(sdomains, 2, "us-east-1")
			} else {
				return ""
			}

			if len(sdomains) > 2 && sdomains[2] != "dualstack" {
				sdomains = insertElement(sdomains, 3, "dualstack")
			}

			if dp1 == 0 {
				sdomains = insertElement(sdomains, 0, "cn")
			}

			return strings.Join(reverseSlice(sdomains), ".")
		}
	}

	return ""
}

func indexOf(arr []string, val string) int {
	for i, v := range arr {
		if v == val {
			return i
		}
	}
	return -1
}

func removeElement(arr []string, index int) []string {
	if index >= 0 && index < len(arr) {
		return append(arr[:index], arr[index+1:]...)
	}
	return arr
}

func insertElement(arr []string, index int, element string) []string {
	if index >= 0 && index <= len(arr) {
		return append(arr[:index], append([]string{element}, arr[index:]...)...)
	}
	return arr
}

func replaceElement(arr []string, index int, element string) []string {
	if index >= 0 && index < len(arr) {
		arr[index] = element
	}
	return arr
}

func reverseSlice(arr []string) []string {
	for i := 0; i < len(arr)/2; i++ {
		j := len(arr) - i - 1
		arr[i], arr[j] = arr[j], arr[i]
	}
	return arr
}
