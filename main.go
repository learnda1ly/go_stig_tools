package main

import (
	"encoding/xml"
	"fmt"
)

type Checklist struct {
	Asset
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

var blob = `
	<ASSET>
		<ROLE>None</ROLE>
		<ASSET_TYPE>Computing</ASSET_TYPE>
		<MARKING>CUI</MARKING>
		<HOST_NAME></HOST_NAME>
		<HOST_IP></HOST_IP>
		<HOST_MAC></HOST_MAC>
		<HOST_FQDN></HOST_FQDN>
		<TARGET_COMMENT></TARGET_COMMENT>
		<TECH_AREA></TECH_AREA>
		<TARGET_KEY>2921</TARGET_KEY>
		<WEB_OR_DATABASE>false</WEB_OR_DATABASE>
		<WEB_DB_SITE></WEB_DB_SITE>
		<WEB_DB_INSTANCE></WEB_DB_INSTANCE>
	</ASSET>`

type StigInfo struct {
	SiData []SiData `xml:"SI_DATA"`
}

type SiData struct {
	SidName string `xml:"SID_NAME"`
	SidData string `xml:"SID_DATA"`
}

var anotherBlob = `
			<STIG_INFO>
				<SI_DATA>
					<SID_NAME>version</SID_NAME>
					<SID_DATA>2</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>classification</SID_NAME>
					<SID_DATA>UNCLASSIFIED</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>customname</SID_NAME>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>stigid</SID_NAME>
					<SID_DATA>RHEL_8_STIG</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>description</SID_NAME>
					<SID_DATA>This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>filename</SID_NAME>
					<SID_DATA>U_RHEL_8_STIG_V2R1_Manual-xccdf.xml</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>releaseinfo</SID_NAME>
					<SID_DATA>Release: 1 Benchmark Date: 24 Oct 2024</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>title</SID_NAME>
					<SID_DATA>Red Hat Enterprise Linux 8 Security Technical Implementation Guide</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>uuid</SID_NAME>
					<SID_DATA>5ac8fc68-2b0e-4907-9f2e-caf02973464b</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>notice</SID_NAME>
					<SID_DATA>terms-of-use</SID_DATA>
				</SI_DATA>
				<SI_DATA>
					<SID_NAME>source</SID_NAME>
					<SID_DATA>STIG.DOD.MIL</SID_DATA>
				</SI_DATA>
			</STIG_INFO>`

func main() {
	var checklist Checklist

	if err := xml.Unmarshal([]byte(blob), &checklist); err != nil {
		fmt.Errorf("Something went wrong with xml unmarshal: %v", err)
	}
	fmt.Printf("%v\n", checklist.Asset)

	var stigInfo StigInfo
	if err := xml.Unmarshal([]byte(anotherBlob), &stigInfo); err != nil {
		fmt.Errorf("Something went wrong with xml unmarshal: %v", err)
	}

	for _, siDatum := range stigInfo.SiData {
		fmt.Printf("%s: %s\n", siDatum.SidName, siDatum.SidData)
	}
}
