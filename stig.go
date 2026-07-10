package main

type Stig struct {
	StigName    string     `json:"stig_name"`
	DisplayName string     `json:"display_name"`
	Version     string     `json:"version"`
	StigID      string     `json:"stig_id"`
	ReleaseInfo string     `json:"release_info"`
	Uuid        string     `json:"uuid"`
	Size        int        `json:"size"`
	Rules       []StigRule `json:"rules"`
	Title       string     `json:"title"`
	Id          string     `json:"id"`
	Active      bool       `json:"active"`
	Mode        int        `json:"mode"`
	HasPath     bool       `json:"has_path"`
	CklbVersion string     `json:"cklb_version"`
	TargetData  struct {
		TargetType     string `json:"target_type"`
		HostName       string `json:"host_name"`
		IpAddress      string `json:"ip_address"`
		MacAddress     string `json:"mac_address"`
		Fqdn           string `json:"fqdn"`
		Comments       string `json:"comments"`
		Role           string `json:"role"`
		IsWebDatabase  bool   `json:"is_web_database"`
		TechnologyArea string `json:"technology_area"`
		WebDbSite      string `json:"web_db_site"`
		WebDbInstance  string `json:"web_db_instance"`
	}
}

type StigRule struct {
	GroupId                  string   `json:"group_id"`
	GroupIdSrc               string   `json:"group_id_src"`
	Severity                 string   `json:"severity"`
	GroupTitle               string   `json:"group_title"`
	RuleIdSrc                string   `json:"rule_id_src"`
	RuleId                   string   `json:"rule_id"`
	RuleVersion              string   `json:"rule_version"`
	RuleTitle                string   `json:"rule_title"`
	Discussion               string   `json:"discussion"`
	IaControls               string   `json:"ia_controls"`
	CheckContent             string   `json:"check_content"`
	FixText                  string   `json:"fix_text"`
	FalsePositives           string   `json:"false_positives"`
	FalseNegatives           string   `json:"false_negatives"`
	Documentable             string   `json:"documentable"`
	Mitigations              string   `json:"mitigations"`
	PotentialImpacts         string   `json:"potential_impacts"`
	ThirdPartyTools          string   `json:"third_party_tools"`
	MitigationControl        string   `json:"mitigation_control"`
	Responsibility           string   `json:"responsibility"`
	SecurityOverrideGuidance string   `json:"security_override_guidance"`
	Weight                   string   `json:"weight"`
	Classification           string   `json:"classification"`
	LegacyIds                []string `json:"legacy_ids"`
	Ccis                     []string `json:"ccis"`
	StigRef                  string   `json:"stig_ref"`
	TargetKey                string   `json:"target_key"`
	StigUuid                 string   `json:"stig_uuid"`
	Uuid                     string   `json:"uuid"`
	Comments                 string   `json:"comments"`
	FindingDetails           string   `json:"finding_details"`
	GroupTree                []string `json:"group_tree"`
	Status                   string   `json:"status"`
	Overrides                struct {
		Severity struct {
			Severity string `json:"severity"`
			Reason   string `json:"reason"`
		}
	}
	CheckContentRef struct {
		Name string `json:"name"`
		Href string `json:"href"`
	}
}
