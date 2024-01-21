package parser

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sub2clash/model"
)

func ParseHysteria2(proxy string) (model.Proxy, error) {
	// check if proxy starts with hysteria2://
	if !strings.HasPrefix(proxy, "hysteria2://") {
		return model.Proxy{}, fmt.Errorf("invalid hysteria2 Url")
	}

	// split the proxy string
	parts := strings.SplitN(strings.TrimPrefix(proxy, "hysteria2://"), "@", 2)
	if len(parts) != 2 {
		return model.Proxy{}, fmt.Errorf("invalid hysteria2 Url")
	}

	// retrieve the server basic information
	serverInfo := strings.SplitN(parts[1], "#", 2)
	serverAndPortAndParams := strings.SplitN(serverInfo[0], "?", 2)
	serverAndPort := serverAndPortAndParams[0]

	// retrieve the server name and port
	serverNameRe := regexp.MustCompile(`(.*):`)
	serverNameMatch := serverNameRe.FindStringSubmatch(serverAndPort)
	serverName := ""
	if len(serverNameMatch) == 2 {
		serverName = serverNameMatch[1]
	} else {
		return model.Proxy{}, fmt.Errorf("invalid hysteria2 Url")
	}
	portRe := regexp.MustCompile(`:(\d+)`)
	portMatch := portRe.FindStringSubmatch(serverAndPort)
	port := 0
	if len(portMatch) == 2 {
		port, _ = strconv.Atoi(portMatch[1])
	} else {
		return model.Proxy{}, fmt.Errorf("invalid hysteria2 Url")
	}

	params, err := url.ParseQuery(serverAndPortAndParams[1])
	if err != nil {
		return model.Proxy{}, err
	}

	// result struct
	result := model.Proxy{
		Type:           "hysteria2",
		Server:         strings.TrimSpace(serverName),
		Port:           port,
		UDP:            true,
		Password:       strings.TrimSpace(parts[0]),
		Sni:            params.Get("sni"),
		SkipCertVerify: params.Get("insecure") == "1",
	}

	// add proxy name if exists
	if len(serverInfo) == 2 {
		result.Name, _ = url.QueryUnescape(strings.TrimSpace(serverInfo[1]))
	} else {
		result.Name = serverName
	}
	return result, nil
}
