package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

type Checklist struct {
	Asset Asset   `xml:"ASSET"`
	Stigs []Istig `xml:"STIGS>iSTIG"`
}

type Asset struct {
	Role          string `xml:"ROLE"`
	AssetType     string `xml:"ASSET_TYPE"`
	Marking       string `xml:"MARKING"`
	HostName      string `xml:"HOST_NAME"`
	HostIP        string `xml:"HOST_IP"`
	HostMAC       string `xml:"HOST_MAC"`
	HostFQDN      string `xml:"HOST_FQDN"`
	TargetComment string `xml:"TARGET_COMMENT"`
	TechArea      string `xml:"TECH_AREA"`
	TargetKey     string `xml:"TARGET_KEY"`
	WebOrDatabase string `xml:"WEB_OR_DATABASE"`
	WebDBSite     string `xml:"WEB_DB_SITE"`
	WebDBInstance string `xml:"WEB_DB_INSTANCE"`
}

type Istig struct {
	StigInfo StigInfo `xml:"STIG_INFO"`
	Vuln     []Vuln   `xml:"VULN"`
}

type StigInfo struct {
	SiData []SiData `xml:"SI_DATA"`
}

type Vuln struct {
	StigData              []StigData `xml:"STIG_DATA"`
	Status                string     `xml:"STATUS"`
	FindingDetails        string     `xml:"FINDING_DETAILS"`
	Comments              string     `xml:"COMMENTS"`
	SeverityOverride      string     `xml:"SEVERITY_OVERRIDE"`
	SeverityJustification string     `xml:"SEVERITY_JUSTIFICATION"`
}

type SiData struct {
	SidName string `xml:"SID_NAME"`
	SidData string `xml:"SID_DATA"`
}

type StigData struct {
	VulnAttribute string `xml:"VULN_ATTRIBUTE"`
	AttributeData string `xml:"ATTRIBUTE_DATA"`
}

func (checklist *Checklist) countByStatus() map[string]int {
	statusCounts := make(map[string]int)
	for _, vuln := range checklist.Stigs[0].Vuln {
		if statusCounts[vuln.Status] == 0 {
			statusCounts[vuln.Status] = 1
		} else {
			statusCounts[vuln.Status]++
		}
	}
	return statusCounts
}

func main() {
	args := os.Args

	if len(args) < 2 {
		_ = fmt.Errorf("usage: %s <ckl_file>", args[0])
		return
	}

	var checklist Checklist

	data, err := os.ReadFile(args[1])
	if err != nil {
		_ = fmt.Errorf("something went wrong with file read: %v", err)
	}

	if err := xml.Unmarshal([]byte(data), &checklist); err != nil {
		_ = fmt.Errorf("something went wrong with xml unmarshal: %v", err)
	}

	statusCounts := checklist.countByStatus()

	fmt.Printf("Open: %d Not Reviewed: %d Not Applicable: %d Not a Finding: %d\n", statusCounts["Open"], statusCounts["Not_Reviewed"], statusCounts["Not_Applicable"], statusCounts["NotAFinding"])
}
