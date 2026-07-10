package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

type XmlChecklist struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Asset   Asset    `xml:"ASSET"`
	Stigs   []Istig  `xml:"STIGS>iSTIG"`
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

func (checklist *XmlChecklist) countByStatus() map[string]int {
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

func (checklist *XmlChecklist) ExportToXML() error {
	xmlData, err := xml.MarshalIndent(checklist, "", "\t")
	if err != nil {
		return fmt.Errorf("something went wrong with xml marshal: %v", err)
	}

	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!--DISA STIG Viewer :: 2.18-->
`)

	data = append(data, xmlData...)

	err = os.WriteFile("output.ckl", data, 0o644)
	if err != nil {
		return fmt.Errorf("something went wrong with file write: %v", err)
	}
	return nil
}

func (checklist *XmlChecklist) ExportToJson() error {
	xmlData, err := xml.MarshalIndent(checklist, "", "\t")
	if err != nil {
		return fmt.Errorf("something went wrong with xml marshal: %v", err)
	}

	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!--DISA STIG Viewer :: 2.18-->
`)

	data = append(data, xmlData...)

	err = os.WriteFile("output.ckl", data, 0o644)
	if err != nil {
		return fmt.Errorf("something went wrong with file write: %v", err)
	}
	return nil
}

func main() {
	args := os.Args

	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <ckl_file>\n", args[0])
		return
	}

	var checklist XmlChecklist

	data, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "something went wrong with file read: %v\n", err)
		os.Exit(1)
	}

	if err := xml.Unmarshal([]byte(data), &checklist); err != nil {
		fmt.Fprintf(os.Stderr, "something went wrong with xml unmarshal: %v\n", err)
		os.Exit(1)
	}

	statusCounts := checklist.countByStatus()

	fmt.Printf("Open: %d Not Reviewed: %d Not Applicable: %d Not a Finding: %d\n", statusCounts["Open"], statusCounts["Not_Reviewed"], statusCounts["Not_Applicable"], statusCounts["NotAFinding"])

	if err := checklist.ExportToXML(); err != nil {
		fmt.Fprintf(os.Stderr, "something went wrong with xml export: %v\n", err)
		os.Exit(1)
	}
}
