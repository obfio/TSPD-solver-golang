package TSPD

type Payload struct {
	Language                string `json:"10"` // en-US
	UserAgent               string `json:"11"` // Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
	WeirdStr                string `json:"12"`
	State                   int    `json:"13"` // 0 -> 0 |= x
	HTTPInterceptorsRunning string `json:"14"` // ""
	NavigatorCheck          int    `json:"00"` // 0
	PhantomCheck            int    `json:"01"` // 0
	HistoryCheck            int    `json:"02"` // 1
	ReferrerCheck           int    `json:"03"` // 1
	ShockwaveFlashCheck     int    `json:"04"` // 0
	WGLCheck                int    `json:"05"` // 1
	SpoofedUACheck          int    `json:"06"` // 0
	SeleniumCheck           int    `json:"07"` // 0
	Idk                     int    `json:"08"` // 0
	SafariAutomationCheck   int    `json:"09"` // 0
}
