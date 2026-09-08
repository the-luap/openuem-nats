package nats

import "time"

type Computer struct {
	Manufacturer   string `json:"manufacturer,omitempty"`
	Model          string `json:"model,omitempty"`
	Serial         string `json:"serial,omitempty"`
	Processor      string `json:"processor,omitempty"`
	ProcessorArch  string `json:"processor_arch,omitempty"`
	ProcessorCores int64  `json:"processor_cores,omitempty"`
	Memory         uint64 `json:"memory,omitempty"`
}

type Antivirus struct {
	Name      string `json:"name,omitempty"`
	IsActive  bool   `json:"is_active,omitempty"`
	IsUpdated bool   `json:"is_updated,omitempty"`
}

type OperatingSystem struct {
	Version        string    `json:"version,omitempty"`
	Description    string    `json:"description,omitempty"`
	InstallDate    time.Time `json:"install_date"`
	Edition        string    `json:"edition,omitempty"`
	Arch           string    `json:"arch,omitempty"`
	Username       string    `json:"username,omitempty"`
	LastBootUpTime time.Time `json:"last_bootup_time"`
	Domain         string    `json:"domain,omitempty"`
}

type LogicalDisk struct {
	Label                 string `json:"label,omitempty"`
	Usage                 int8   `json:"usage,omitempty"`
	Filesystem            string `json:"filesystem,omitempty"`
	SizeInUnits           string `json:"size_in_units,omitempty"`
	RemainingSpaceInUnits string `json:"remaining_space_in_units,omitempty"`
	VolumeName            string `json:"volume_name,omitempty"`
	BitLockerStatus       string `json:"bitlocker_status,omitempty"`
}

type PhysicalDisk struct {
	DeviceID     string `json:"device_id,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	SizeInUnits  string `json:"size_in_units,omitempty"`
}

type Monitor struct {
	Manufacturer      string `json:"manufacturer,omitempty"`
	Model             string `json:"model,omitempty"`
	Serial            string `json:"serial,omitempty"`
	WeekOfManufacture string `json:"week_of_manufacture,omitempty"`
	YearOfManufacture string `json:"year_of_manufacture,omitempty"`
}

type MemorySlot struct {
	Slot         string `json:"slot,omitempty"`
	Size         string `json:"size,omitempty"`
	MemoryType   string `json:"type,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	PartNumber   string `json:"part_number,omitempty"`
	Speed        string `json:"speed,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
}

type Printer struct {
	Name      string `json:"name,omitempty"`
	Port      string `json:"port,omitempty"`
	IsDefault bool   `json:"is_default,omitempty"`
	IsNetwork bool   `json:"is_network,omitempty"`
	IsShared  bool   `json:"is_shared,omitempty"`
}

type Share struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Path        string `json:"path,omitempty"`
}

type SystemUpdate struct {
	Status         string    `json:"status,omitempty"`
	LastInstall    time.Time `json:"last_install"`
	LastSearch     time.Time `json:"last_search"`
	PendingUpdates bool      `json:"pending_updates,omitempty"`
}

type NetworkAdapter struct {
	Name              string    `json:"name,omitempty"`
	MACAddress        string    `json:"mac_address,omitempty"`
	Addresses         string    `json:"addresses,omitempty"`
	Subnet            string    `json:"subnet,omitempty"`
	DefaultGateway    string    `json:"default_gateway,omitempty"`
	DNSServers        string    `json:"dns_servers,omitempty"`
	DNSDomain         string    `json:"dns_domain,omitempty"`
	DHCPEnabled       bool      `json:"dhcp_enabled,omitempty"`
	DHCPLeaseObtained time.Time `json:"dhcp_lease_obtained"`
	DHCPLeaseExpired  time.Time `json:"dhcp_lease_expired"`
	Speed             string    `json:"speed,omitempty"`
	Virtual           bool      `json:"virtual,omitempty"`
}

type Application struct {
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
}

type Update struct {
	Title      string    `json:"title,omitempty"`
	Date       time.Time `json:"date"`
	SupportURL string    `json:"support_url,omitempty"`
}

type LoggedOnUser struct {
	Name      string    `json:"name,omitempty"`
	LastLogon time.Time `json:"last_logon"`
}

type Netbird struct {
	Version             string   `json:"version,omitempty"`
	Installed           bool     `json:"installed,omitempty"`
	IP                  string   `json:"ip,omitempty"`
	Profile             string   `json:"profile,omitempty"`
	ManagementURL       string   `json:"management_url,omitempty"`
	ManagementConnected bool     `json:"management_connected,omitempty"`
	SignalURL           string   `json:"signal_url,omitempty"`
	SignalConnected     bool     `json:"signal_connected,omitempty"`
	PeersTotal          int      `json:"peers_total,omitempty"`
	PeersConnected      int      `json:"peers_connected,omitempty"`
	SSHEnabled          bool     `json:"ssh_enabled,omitempty"`
	ServiceStatus       string   `json:"service_status,omitempty"`
	Profiles            []string `json:"profiles,omitempty"`
	DNSServers          []string `json:"dns_servers,omitempty"`
	Error               string   `json:"error,omitempty"`
}

type NetBirdGroups struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PeersCount int    `json:"peers_count"`
}

type NetbirdSettings struct {
	OneOffKey     string `json:"key,omitempty"`
	ManagementURL string `json:"management_url,omitempty"`
	Profile       string `json:"profile,omitempty"`
}

type NetbirdTask struct {
	ID           string          `json:"id"`
	Install      bool            `json:"install,omitempty"`
	Uninstall    bool            `json:"uinstall,omitempty"`
	Register     bool            `json:"register,omitempty"`
	RegisterInfo NetbirdSettings `json:"register_info,omitempty"`
}

type AgentReport struct {
	AgentID                     string           `json:"id,omitempty"`
	OS                          string           `json:"os,omitempty"`
	Hostname                    string           `json:"hostname,omitempty"`
	Release                     Release          `json:"release,omitempty"`
	ExecutionTime               time.Time        `json:"execution_time,omitempty"`
	IP                          string           `json:"ip,omitempty"`
	WAN                         string           `json:"wan_ip,omitempty"`
	MACAddress                  string           `json:"mac,omitempty"`
	SFTPPort                    string           `json:"sftp_port,omitempty"`
	VNCProxyPort                string           `json:"vnc_proxy_port,omitempty"`
	Enabled                     bool             `json:"enabled,omitempty"`
	DebugMode                   bool             `json:"debug,omitempty"`
	Computer                    Computer         `json:"computer"`
	Antivirus                   Antivirus        `json:"antivirus"`
	OperatingSystem             OperatingSystem  `json:"operatingsystem"`
	LogicalDisks                []LogicalDisk    `json:"logicaldisks,omitempty"`
	PhysicalDisks               []PhysicalDisk   `json:"physicaldisks,omitempty"`
	Monitors                    []Monitor        `json:"monitors,omitempty"`
	MemorySlots                 []MemorySlot     `json:"memoryslots,omitempty"`
	Printers                    []Printer        `json:"printers,omitempty"`
	Shares                      []Share          `json:"shares,omitempty"`
	SystemUpdate                SystemUpdate     `json:"systemupdate"`
	NetworkAdapters             []NetworkAdapter `json:"networkadapters,omitempty"`
	Applications                []Application    `json:"apps,omitempty"`
	LoggedOnUsers               []LoggedOnUser   `json:"loggedonusers,omitempty"`
	SupportedVNCServer          string           `json:"vnc,omitempty"`
	Updates                     []Update         `json:"updates,omitempty"`
	LastUpdateTaskExecutionTime time.Time        `json:"last_update_task_execution_time"`
	LastUpdateTaskStatus        string           `json:"last_update_task_status,omitempty"`
	LastUpdateTaskResult        string           `json:"last_update_task_result,omitempty"`
	CertificateReady            bool             `json:"certificate_ready,omitempty"`
	RestartRequired             bool             `json:"restart_required,omitempty"`
	SftpServiceDisabled         bool             `json:"sftp_service_disabled,omitempty"`
	RemoteAssistanceDisabled    bool             `json:"remote_assistance_disabled,omitempty"`
	Tenant                      string           `json:"tenant,omitempty"`
	Site                        string           `json:"site,omitempty"`
	IsWayland                   bool             `json:"is_wayland,omitempty"`
	HasRustDesk                 bool             `json:"has_rust_desk,omitempty"`
	HasRustDeskService          bool             `json:"has_rust_desk_service,omitempty"`
	IsFlatpakRustDesk           bool             `json:"is_flatpak_rust_desk,omitempty"`
	Netbird                     Netbird          `json:"netbird"`
}

type Config struct {
	RecoveryTaskVersion      int  `json:"recovery_task_version,omitempty"`
	HardwareInventoryVersion int  `json:"hardware_inventory_version,omitempty"`
	Ok                       bool `json:"ok,omitempty"`
	AgentFrequency           int  `json:"agent_frequency,omitempty"`
	WinGetFrequency          int  `json:"winget_frequency,omitempty"`
	SFTPDisabled             bool `json:"sftp_disabled,omitempty"`
	RemoteAssistanceDisabled bool `json:"remote_assistance_disabled,omitempty"`
}

type Release struct {
	Version      string    `json:"version,omitempty"`
	Channel      string    `json:"channel,omitempty"`
	Summary      string    `json:"summary,omitempty"`
	ReleaseNotes string    `json:"release_notes,omitempty"`
	FileURL      string    `json:"file_url,omitempty"`
	Checksum     string    `json:"checksum,omitempty"`
	IsCritical   bool      `json:"is_critical,omitempty"`
	ReleaseDate  time.Time `json:"release_date,omitempty"`
	Arch         string    `json:"arch,omitempty"`
	Os           string    `json:"os,omitempty"`
}

type VNCConnection struct {
	PIN        string `json:"pin,omitempty"`
	NotifyUser bool   `json:"notify_user,omitempty"`
}

type RebootOrRestart struct {
	Date time.Time `json:"date,omitempty"`
}

type AgentSetting struct {
	DebugMode        bool
	SFTPService      bool
	RemoteAssistance bool
	SFTPPort         string
	VNCProxyPort     string
	WebSocketPort    string
}

type RemoteConfigRequest struct {
	AgentID  string `json:"agentID,omitempty"`
	TenantID string `json:"tenantID,omitempty"`
	SiteID   string `json:"siteID,omitempty"`
}

type RustDesk struct {
	CustomRendezVousServer  string `json:"customRendezVousServer,omitempty"`
	RelayServer             string `json:"relayServer,omitempty"`
	APIServer               string `json:"apiServer,omitempty"`
	Key                     string `json:"key,omitempty"`
	PermanentPassword       string `json:"permanentPassword,omitempty"`
	Whitelist               string `json:"whitelist,omitempty"`
	DirectIPAccess          bool   `json:"directIPAccess,omitempty"`
	VerificationMethod      string `json:"verificationMethod,omitempty"`
	TemporaryPasswordLength int    `json:"temporaryPasswordLength,omitempty"`
}

type RustDeskResult struct {
	Error      string `json:"error"`
	RustDeskID string `json:"id"`
}
