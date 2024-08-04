package catogo

import (
	"encoding/json"
	"fmt"
)

type EnumPolicyActiveOnEnum string

const EnumPolicyActiveOnEnumALWAYS EnumPolicyActiveOnEnum = "ALWAYS"
const EnumPolicyActiveOnEnumWORKING_HOURS EnumPolicyActiveOnEnum = "WORKING_HOURS"
const EnumPolicyActiveOnEnumCUSTOM_TIMEFRAME EnumPolicyActiveOnEnum = "CUSTOM_TIMEFRAME"
const EnumPolicyActiveOnEnumCUSTOM_RECURRING EnumPolicyActiveOnEnum = "CUSTOM_RECURRING"

type EnumConnectionOriginEnum string

const EnumConnectionOriginEnumANY EnumConnectionOriginEnum = "ANY"
const EnumConnectionOriginEnumREMOTE EnumConnectionOriginEnum = "REMOTE"
const EnumConnectionOriginEnumSITE EnumConnectionOriginEnum = "SITE"

type EnumInternetFirewallActionEnum string

const EnumInternetFirewallActionEnumBLOCK EnumInternetFirewallActionEnum = "BLOCK"
const EnumInternetFirewallActionEnumALLOW EnumInternetFirewallActionEnum = "ALLOW"
const EnumInternetFirewallActionEnumPROMPT EnumInternetFirewallActionEnum = "PROMPT"
const EnumInternetFirewallActionEnumRBI EnumInternetFirewallActionEnum = "RBI"

type EnumOperatingSystem string

const EnumOperatingSystemWINDOWS EnumOperatingSystem = "WINDOWS"
const EnumOperatingSystemMACOS EnumOperatingSystem = "MACOS"
const EnumOperatingSystemIOS EnumOperatingSystem = "IOS"
const EnumOperatingSystemANDROID EnumOperatingSystem = "ANDROID"
const EnumOperatingSystemLINUX EnumOperatingSystem = "LINUX"
const EnumOperatingSystemEMBEDDED EnumOperatingSystem = "EMBEDDED"

type EnumDayOfWeek string

const EnumDayOfWeekSUNDAY EnumDayOfWeek = "SUNDAY"
const EnumDayOfWeekMONDAY EnumDayOfWeek = "MONDAY"
const EnumDayOfWeekTUESDAY EnumDayOfWeek = "TUESDAY"
const EnumDayOfWeekWEDNESDAY EnumDayOfWeek = "WEDNESDAY"
const EnumDayOfWeekTHURSDAY EnumDayOfWeek = "THURSDAY"
const EnumDayOfWeekFRIDAY EnumDayOfWeek = "FRIDAY"
const EnumDayOfWeekSATURDAY EnumDayOfWeek = "SATURDAY"

type EnumPolicyElementPropertiesEnum string

const EnumPolicyElementPropertiesEnumADDED EnumPolicyElementPropertiesEnum = "ADDED"
const EnumPolicyElementPropertiesEnumUPDATED EnumPolicyElementPropertiesEnum = "UPDATED"
const EnumPolicyElementPropertiesEnumREMOVED EnumPolicyElementPropertiesEnum = "REMOVED"
const EnumPolicyElementPropertiesEnumMOVED EnumPolicyElementPropertiesEnum = "MOVED"
const EnumPolicyElementPropertiesEnumLOCKED EnumPolicyElementPropertiesEnum = "LOCKED"
const EnumPolicyElementPropertiesEnumANCHORED EnumPolicyElementPropertiesEnum = "ANCHORED"
const EnumPolicyElementPropertiesEnumSYSTEM EnumPolicyElementPropertiesEnum = "SYSTEM"

type EnumIpProtocol string

const EnumIpProtocolANY EnumIpProtocol = "ANY"
const EnumIpProtocolTCP EnumIpProtocol = "TCP"
const EnumIpProtocolTCP_UDP EnumIpProtocol = "TCP_UDP"
const EnumIpProtocolUDP EnumIpProtocol = "UDP"
const EnumIpProtocolICMP EnumIpProtocol = "ICMP"

type EnumPolicyRuleTrackingFrequencyEnum string

const EnumPolicyRuleTrackingFrequencyEnumHOURLY EnumPolicyRuleTrackingFrequencyEnum = "HOURLY"
const EnumPolicyRuleTrackingFrequencyEnumDAILY EnumPolicyRuleTrackingFrequencyEnum = "DAILY"
const EnumPolicyRuleTrackingFrequencyEnumWEEKLY EnumPolicyRuleTrackingFrequencyEnum = "WEEKLY"
const EnumPolicyRuleTrackingFrequencyEnumIMMEDIATE EnumPolicyRuleTrackingFrequencyEnum = "IMMEDIATE"

type IpAddressRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type PortRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type CustomService struct {
	Port      []string       `json:"port,omitempty"`
	PortRange *PortRange     `json:"portRange,omitempty"`
	Protocol  EnumIpProtocol `json:"protocol,omitempty"`
}

type UserRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type UsersGroupRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type DeviceProfileRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CustomCategoryRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type GroupRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type FloatingSubnetRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type HostRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type NetworkInterfaceRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SiteRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SiteNetworkSubnetRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ApplicationRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ApplicationCategoryRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SanctionedAppsCategoryRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CustomApplicationRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ServiceRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type CountryRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SubscriptionGroupRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SubscriptionWebhookRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SubscriptionMailingListRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type SystemGroupRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type GlobalIpRangeRef struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type InternetFirewallDestination struct {
	Application            []ApplicationRef            `json:"application,omitempty"`
	CustomApp              []CustomApplicationRef      `json:"customApp,omitempty"`
	AppCategory            []ApplicationCategoryRef    `json:"appCategory,omitempty"`
	CustomCategory         []CustomCategoryRef         `json:"customCategory,omitempty"`
	SanctionedAppsCategory []SanctionedAppsCategoryRef `json:"sanctionedAppsCategory,omitempty"`
	Country                []CountryRef                `json:"country,omitempty"`
	Domain                 []string                    `json:"domain,omitempty"`
	Fqdn                   []string                    `json:"fqdn,omitempty"`
	Ip                     []string                    `json:"ip,omitempty"`
	Subnet                 []string                    `json:"subnet,omitempty"`
	IpRange                []IpAddressRange            `json:"ipRange,omitempty"`
	GlobalIpRange          []GlobalIpRangeRef          `json:"globalIpRange,omitempty"`
	RemoteAsn              []string                    `json:"remoteAsn,omitempty"`
}

type InternetFirewallPolicy struct {
	Enabled  bool                          `json:"enabled,omitempty"`
	Rules    []InternetFirewallRulePayload `json:"rules,omitempty"`
	Sections []PolicySectionPayload        `json:"sections,omitempty"`
	Audit    *PolicyAudit                  `json:"audit,omitempty"`
	Revision *PolicyRevision               `json:"revision,omitempty"`
}

type InternetFirewallRule struct {
	Id               string                          `json:"id,omitempty"`
	Name             string                          `json:"name,omitempty"`
	Description      string                          `json:"description,omitempty"`
	Index            int64                           `json:"index,omitempty"`
	Section          PolicySectionInfo               `json:"section,omitempty"`
	Enabled          bool                            `json:"enabled,omitempty"`
	Source           InternetFirewallSource          `json:"source,omitempty"`
	ConnectionOrigin EnumConnectionOriginEnum        `json:"connectionOrigin,omitempty"`
	Country          []CountryRef                    `json:"country,omitempty"`
	Device           []DeviceProfileRef              `json:"device,omitempty"`
	DeviceOS         []EnumOperatingSystem           `json:"deviceOS,omitempty"`
	Destination      InternetFirewallDestination     `json:"destination,omitempty"`
	Service          InternetFirewallServiceType     `json:"service,omitempty"`
	Action           EnumInternetFirewallActionEnum  `json:"action,omitempty"`
	Tracking         PolicyTracking                  `json:"tracking,omitempty"`
	Schedule         PolicySchedule                  `json:"schedule,omitempty"`
	Exceptions       []InternetFirewallRuleException `json:"exceptions,omitempty"`
}

type InternetFirewallRuleException struct {
	Name             string                      `json:"name,omitempty"`
	Source           InternetFirewallSource      `json:"source,omitempty"`
	DeviceOS         []EnumOperatingSystem       `json:"deviceOS,omitempty"`
	Country          []CountryRef                `json:"country,omitempty"`
	Device           []DeviceProfileRef          `json:"device,omitempty"`
	Destination      InternetFirewallDestination `json:"destination,omitempty"`
	Service          InternetFirewallServiceType `json:"service,omitempty"`
	ConnectionOrigin EnumConnectionOriginEnum    `json:"connectionOrigin,omitempty"`
}

type InternetFirewallRulePayload struct {
	Audit      PolicyElementAudit                `json:"audit,omitempty"`
	Rule       InternetFirewallRule              `json:"rule,omitempty"`
	Properties []EnumPolicyElementPropertiesEnum `json:"properties,omitempty"`
}

type InternetFirewallServiceType struct {
	Standard []ServiceRef    `json:"standard,omitempty"`
	Custom   []CustomService `json:"custom,omitempty"`
}

type InternetFirewallSource struct {
	Ip                []string               `json:"ip,omitempty"`
	Host              []HostRef              `json:"host,omitempty"`
	Site              []SiteRef              `json:"site,omitempty"`
	Subnet            []string               `json:"subnet,omitempty"`
	IpRange           []IpAddressRange       `json:"ipRange,omitempty"`
	GlobalIpRange     []GlobalIpRangeRef     `json:"globalIpRange,omitempty"`
	NetworkInterface  []NetworkInterfaceRef  `json:"networkInterface,omitempty"`
	SiteNetworkSubnet []SiteNetworkSubnetRef `json:"siteNetworkSubnet,omitempty"`
	FloatingSubnet    []FloatingSubnetRef    `json:"floatingSubnet,omitempty"`
	User              []UserRef              `json:"user,omitempty"`
	UsersGroup        []UsersGroupRef        `json:"usersGroup,omitempty"`
	Group             []GroupRef             `json:"group,omitempty"`
	SystemGroup       []SystemGroupRef       `json:"systemGroup,omitempty"`
}

type PolicyAudit struct {
	PublishedTime string `json:"publishedTime,omitempty"`
	PublishedBy   string `json:"publishedBy,omitempty"`
}

type PolicyCustomRecurring struct {
	From string          `json:"from,omitempty"`
	To   string          `json:"to,omitempty"`
	Days []EnumDayOfWeek `json:"days,omitempty"`
}

type PolicyCustomTimeframe struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type PolicyElementAudit struct {
	UpdatedTime string `json:"updatedTime,omitempty"`
	UpdatedBy   string `json:"updatedBy,omitempty"`
}

type PolicyRevision struct {
	Id          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Changes     int64  `json:"changes,omitempty"`
	CreatedTime string `json:"createdTime,omitempty"`
	UpdatedTime string `json:"updatedTime,omitempty"`
}

type PolicyRuleTrackingAlert struct {
	Enabled           bool                                `json:"enabled,omitempty"`
	Frequency         EnumPolicyRuleTrackingFrequencyEnum `json:"frequency,omitempty"`
	SubscriptionGroup []SubscriptionGroupRef              `json:"subscriptionGroup,omitempty"`
	Webhook           []SubscriptionWebhookRef            `json:"webhook,omitempty"`
	MailingList       []SubscriptionMailingListRef        `json:"mailingList,omitempty"`
}

type PolicyRuleTrackingEvent struct {
	Enabled bool `json:"enabled,omitempty"`
}

type PolicySchedule struct {
	ActiveOn        EnumPolicyActiveOnEnum `json:"activeOn,omitempty"`
	CustomTimeframe *PolicyCustomTimeframe `json:"customTimeframe,omitempty"`
	CustomRecurring *PolicyCustomRecurring `json:"customRecurring,omitempty"`
}

type PolicySectionInfo struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type PolicySectionPayload struct {
	Audit      PolicyElementAudit                `json:"audit,omitempty"`
	Section    PolicySectionInfo                 `json:"section,omitempty"`
	Properties []EnumPolicyElementPropertiesEnum `json:"properties,omitempty"`
}

type PolicyTracking struct {
	Event PolicyRuleTrackingEvent `json:"event,omitempty"`
	Alert PolicyRuleTrackingAlert `json:"alert,omitempty"`
}

type InternetFirewall struct {
	Data struct {
		Policy struct {
			InternetFirewall struct {
				Policy InternetFirewallPolicy `json:"policy,omitempty"`
			} `json:"internetFirewall,omitempty"`
		} `json:"policy,omitempty"`
	} `json:"data,omitempty"`
}

type EnumPolicyRulePositionEnum string

const EnumPolicyRulePositionEnumAFTER_RULE EnumPolicyRulePositionEnum = "AFTER_RULE"
const EnumPolicyRulePositionEnumBEFORE_RULE EnumPolicyRulePositionEnum = "BEFORE_RULE"
const EnumPolicyRulePositionEnumFIRST_IN_SECTION EnumPolicyRulePositionEnum = "FIRST_IN_SECTION"
const EnumPolicyRulePositionEnumLAST_IN_SECTION EnumPolicyRulePositionEnum = "LAST_IN_SECTION"
const EnumPolicyRulePositionEnumFIRST_IN_POLICY EnumPolicyRulePositionEnum = "FIRST_IN_POLICY"
const EnumPolicyRulePositionEnumLAST_IN_POLICY EnumPolicyRulePositionEnum = "LAST_IN_POLICY"

type EnumObjectRefBy string

const EnumObjectRefByID EnumObjectRefBy = "ID"
const EnumObjectRefByNAME EnumObjectRefBy = "NAME"

type IpAddressRangeInput struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type PortRangeInput struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type CustomServiceInput struct {
	Port      []string        `json:"port,omitempty"`
	PortRange *PortRangeInput `json:"portRange,omitempty"`
	Protocol  EnumIpProtocol  `json:"protocol,omitempty"`
}

type UserRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type UsersGroupRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type DeviceProfileRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type CustomCategoryRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type GroupRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type FloatingSubnetRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type HostRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type NetworkInterfaceRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type SiteRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type SiteNetworkSubnetRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type ApplicationRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type ApplicationCategoryRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type SanctionedAppsCategoryRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type CustomApplicationRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type ServiceRefInput struct {
	By    EnumObjectRefBy `json:"by,omitempty"`
	Input string          `json:"input,omitempty"`
}

type CountryRefInput struct {
	Input string          `json:"input,omitempty"`
	By    EnumObjectRefBy `json:"by,omitempty"`
}

type SubscriptionGroupRefInput struct {
	Input string          `json:"input,omitempty"`
	By    EnumObjectRefBy `json:"by,omitempty"`
}

type SubscriptionWebhookRefInput struct {
	Input string          `json:"input,omitempty"`
	By    EnumObjectRefBy `json:"by,omitempty"`
}

type SubscriptionMailingListRefInput struct {
	Input string          `json:"input,omitempty"`
	By    EnumObjectRefBy `json:"by,omitempty"`
}

type SystemGroupRefInput struct {
	Input string          `json:"input,omitempty"`
	By    EnumObjectRefBy `json:"by,omitempty"`
}

type GlobalIpRangeRefInput struct {
	Input string          `json:"input,omitempty"`
	By    EnumObjectRefBy `json:"by,omitempty"`
}

type InternetFirewallAddRuleDataInput struct {
	Enabled          bool                                 `json:"enabled,omitempty"`
	Name             string                               `json:"name,omitempty"`
	Description      string                               `json:"description,omitempty"`
	Source           *InternetFirewallSourceInput         `json:"source,omitempty"`
	ConnectionOrigin EnumConnectionOriginEnum             `json:"connectionOrigin,omitempty"`
	Country          []CountryRefInput                    `json:"country,omitempty"`
	Device           []DeviceProfileRefInput              `json:"device,omitempty"`
	DeviceOS         []EnumOperatingSystem                `json:"deviceOS,omitempty"`
	Destination      *InternetFirewallDestinationInput    `json:"destination,omitempty"`
	Service          *InternetFirewallServiceTypeInput    `json:"service,omitempty"`
	Action           EnumInternetFirewallActionEnum       `json:"action,omitempty"`
	Tracking         *PolicyTrackingInput                 `json:"tracking,omitempty"`
	Schedule         *PolicyScheduleInput                 `json:"schedule,omitempty"`
	Exceptions       []InternetFirewallRuleExceptionInput `json:"exceptions,omitempty"`
}

type InternetFirewallAddRuleInput struct {
	Rule InternetFirewallAddRuleDataInput `json:"rule,omitempty"`
	At   *PolicyRulePositionInput         `json:"at"`
}

type InternetFirewallDestinationInput struct {
	Application            []ApplicationRefInput            `json:"application,omitempty"`
	CustomApp              []CustomApplicationRefInput      `json:"customApp,omitempty"`
	AppCategory            []ApplicationCategoryRefInput    `json:"appCategory,omitempty"`
	CustomCategory         []CustomCategoryRefInput         `json:"customCategory,omitempty"`
	SanctionedAppsCategory []SanctionedAppsCategoryRefInput `json:"sanctionedAppsCategory,omitempty"`
	Country                []CountryRefInput                `json:"country,omitempty"`
	Domain                 []string                         `json:"domain,omitempty"`
	Fqdn                   []string                         `json:"fqdn,omitempty"`
	Ip                     []string                         `json:"ip,omitempty"`
	Subnet                 []string                         `json:"subnet,omitempty"`
	IpRange                []IpAddressRangeInput            `json:"ipRange,omitempty"`
	GlobalIpRange          []GlobalIpRangeRefInput          `json:"globalIpRange,omitempty"`
	RemoteAsn              []string                         `json:"remoteAsn,omitempty"`
}

type InternetFirewallRuleExceptionInput struct {
	Name             string                           `json:"name,omitempty"`
	Source           InternetFirewallSourceInput      `json:"source,omitempty"`
	DeviceOS         []EnumOperatingSystem            `json:"deviceOS,omitempty"`
	Country          []CountryRefInput                `json:"country,omitempty"`
	Device           []DeviceProfileRefInput          `json:"device,omitempty"`
	Destination      InternetFirewallDestinationInput `json:"destination,omitempty"`
	Service          InternetFirewallServiceTypeInput `json:"service,omitempty"`
	ConnectionOrigin EnumConnectionOriginEnum         `json:"connectionOrigin,omitempty"`
}

type InternetFirewallServiceTypeInput struct {
	Standard []ServiceRefInput    `json:"standard,omitempty"`
	Custom   []CustomServiceInput `json:"custom,omitempty"`
}

type PolicyCustomRecurringInput struct {
	From string          `json:"from,omitempty"`
	To   string          `json:"to,omitempty"`
	Days []EnumDayOfWeek `json:"days,omitempty"`
}

type PolicyCustomTimeframeInput struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type PolicyRulePositionInput struct {
	Position *EnumPolicyRulePositionEnum `json:"position,omitempty"`
	Ref      *string                     `json:"ref,omitempty"`
}

type PolicyRuleTrackingAlertInput struct {
	Enabled           bool                                `json:"enabled,omitempty"`
	Frequency         EnumPolicyRuleTrackingFrequencyEnum `json:"frequency,omitempty"`
	SubscriptionGroup []SubscriptionGroupRefInput         `json:"subscriptionGroup,omitempty"`
	Webhook           []SubscriptionWebhookRefInput       `json:"webhook,omitempty"`
	MailingList       []SubscriptionMailingListRefInput   `json:"mailingList,omitempty"`
}

type PolicyRuleTrackingEventInput struct {
	Enabled bool `json:"enabled,omitempty"`
}

type PolicyScheduleInput struct {
	ActiveOn        EnumPolicyActiveOnEnum      `json:"activeOn,omitempty"`
	CustomTimeframe *PolicyCustomTimeframeInput `json:"customTimeframe,omitempty"`
	CustomRecurring *PolicyCustomRecurringInput `json:"customRecurring,omitempty"`
}

type PolicyTrackingInput struct {
	Event PolicyRuleTrackingEventInput `json:"event,omitempty"`
	Alert PolicyRuleTrackingAlertInput `json:"alert,omitempty"`
}

type InternetFirewallSourceInput struct {
	Ip                []string                    `json:"ip,omitempty"`
	Host              []HostRefInput              `json:"host,omitempty"`
	Site              []SiteRefInput              `json:"site,omitempty"`
	Subnet            []string                    `json:"subnet,omitempty"`
	IpRange           []IpAddressRangeInput       `json:"ipRange,omitempty"`
	GlobalIpRange     []GlobalIpRangeRefInput     `json:"globalIpRange,omitempty"`
	NetworkInterface  []NetworkInterfaceRefInput  `json:"networkInterface,omitempty"`
	SiteNetworkSubnet []SiteNetworkSubnetRefInput `json:"siteNetworkSubnet,omitempty"`
	FloatingSubnet    []FloatingSubnetRefInput    `json:"floatingSubnet,omitempty"`
	User              []UserRefInput              `json:"user,omitempty"`
	UsersGroup        []UsersGroupRefInput        `json:"usersGroup,omitempty"`
	Group             []GroupRefInput             `json:"group,omitempty"`
	SystemGroup       []SystemGroupRefInput       `json:"systemGroup,omitempty"`
}

type InternetFirewallRuleMutationPayload struct {
	Data struct {
		Policy struct {
			InternetFirewall struct {
				AddRule struct {
					Status string `json:"status,omitempty"`
					Rule   struct {
						Rule struct {
							Name string `json:"name,omitempty"`
							ID   string `json:"id,omitempty"`
						} `json:"rule,omitempty"`
					} `json:"rule,omitempty"`
				} `json:"addRule,omitempty"`
			} `json:"internetFirewall,omitempty"`
		} `json:"policy,omitempty"`
	} `json:"data,omitempty"`
}

type InternetFirewallPolicyMutationPayload struct {
	Data struct {
		Policy struct {
			InternetFirewall struct {
				PublishPolicyRevision struct {
					Status string `json:"status,omitempty"`
				} `json:"publishPolicyRevision,omitempty"`
			} `json:"internetFirewall,omitempty"`
		} `json:"policy,omitempty"`
	} `json:"data,omitempty"`
}

func (c *Client) GetInternetFirewallPolicy(accountId string) (*InternetFirewall, error) {

	query := graphQLRequest{
		Query: `query InternetFirewall($accountId: ID!) {
					policy(accountId: $accountId) {
						internetFirewall {
						policy {
							audit {
							publishedBy
							publishedTime
							}
							enabled
							revision {
							changes
							createdTime
							description
							id
							name
							updatedTime
							}
							rules {
							properties
							audit {
								updatedBy
								updatedTime
							}
							rule {
								action
								connectionOrigin
								country {
								id
								name
								}
								source {
								ip
								subnet
								ipRange {
									from
									to
								}
								floatingSubnet {
									id
									name
								}
								group {
									id
									name
								}
								site {
									id
									name
								}
								host {
									id
									name
								}
								usersGroup {
									id
									name
								}
								user {
									id
									name
								}
								systemGroup {
									id
									name
								}
								}
								section {
								id
								name
								}
								schedule {
								activeOn
								}
								name
								index
								id
								description
								destination {
								appCategory {
									id
									name
								}
								application {
									id
									name
								}
								domain
								fqdn
								ip
								subnet
								remoteAsn
								}
								enabled
								deviceOS
								device {
								id
								name
								}
								tracking {
								alert {
									enabled
								}
								event {
									enabled
								}
								}
							}
							}
							sections {
							properties
							audit {
								updatedBy
								updatedTime
							}
							section {
								id
								name
							}
							}
						}
						}
					}
        }`,
		Variables: map[string]interface{}{
			"accountId": accountId,
		},
	}

	body, err := c.do(query)
	if err != nil {
		return nil, err
	}

	response := InternetFirewall{}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) GetInternetFirewallRuleByName(accountId string, name string) (*InternetFirewallRule, error) {

	policy, _ := c.GetInternetFirewallPolicy(accountId)

	rule := InternetFirewallRule{}

	for _, item := range policy.Data.Policy.InternetFirewall.Policy.Rules {

		if item.Rule.Name == name {
			rule = item.Rule
		}

	}

	return &rule, nil
}

func (c *Client) CreateInternetFirewallRule(accountId string, rule InternetFirewallAddRuleInput) (*InternetFirewallRuleMutationPayload, error) {

	query := graphQLRequest{
		Query: `mutation AddInternetFirewallRule($accountId: ID!, $input: InternetFirewallAddRuleInput!) {
					policy(accountId: $accountId) {
					internetFirewall {
						addRule( input: $input ) {
							status
							rule {
								rule {
									name
									id
								}
							}
						}
					}
					}
				}`,
		Variables: map[string]interface{}{
			"accountId": accountId,
			"input":     rule,
			// "input": InternetFirewallAddRuleInput{
			// 	Rule: InternetFirewallAddRuleDataInput{
			// 		Name:        string(rule.Rule.Name),
			// 		Source:      rule.Rule.Source,
			// 		Destination: rule.Rule.Destination,
			// 		// Destination: rule.Rule.Destination,
			// 	},
			// },
		},
	}
	// DEBUG
	query_json, _ := json.Marshal(query)
	fmt.Println(string(query_json))

	body, err := c.do(query)
	if err != nil {
		return nil, err
	}

	response := InternetFirewallRuleMutationPayload{}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) PublishInternetFirewallDefaultPolicyRevision(accountId string) (*InternetFirewallPolicyMutationPayload, error) {

	query := graphQLRequest{
		Query: `mutation PublishFirewalRevision($accountId: ID!) {
			policy(accountId: $accountId) {
				internetFirewall {
				publishPolicyRevision {
					status
				}
				}
			}
		}`,
		Variables: map[string]interface{}{
			"accountId": accountId,
		},
	}

	body, err := c.do(query)
	if err != nil {
		return nil, err
	}

	response := InternetFirewallPolicyMutationPayload{}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}
