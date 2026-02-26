package models

type ZAPSummary struct {
	ProgramName string `json:"@programName"`
	Version     string `json:"@version"`
	Generated   string `json:"@generated"`
	Site        []Site `json:"site"`
}

type Instances struct {
	URI            string `json:"uri"`
	Method         string `json:"method"`
	Param          string `json:"param"`
	Attack         string `json:"attack"`
	Evidence       string `json:"evidence"`
	Otherinfo      string `json:"otherinfo"`
	RequestHeader  string `json:"request-header"`
	RequestBody    string `json:"request-body"`
	ResponseHeader string `json:"response-header"`
	ResponseBody   string `json:"response-body"`
}

type Alerts struct {
	PluginID   string      `json:"pluginid"`
	AlertRef   string      `json:"alertRef"`
	Alert      string      `json:"alert"`
	Name       string      `json:"name"`
	Riskcode   string      `json:"riskcode"`
	Confidence string      `json:"confidence"`
	Riskdesc   string      `json:"riskdesc"`
	Desc       string      `json:"desc"`
	Instances  []Instances `json:"instances"`
	Count      string      `json:"count"`
	Solution   string      `json:"solution"`
	Otherinfo  string      `json:"otherinfo"`
	Reference  string      `json:"reference"`
	CWE        string      `json:"cweid"`
	Wascid     string      `json:"wascid"`
	Sourceid   string      `json:"sourceid"`
	Tags       []Tags      `json:"tags"`
}

type Site struct {
	Name   string   `json:"@name"`
	Host   string   `json:"@host"`
	Port   string   `json:"@port"`
	Ssl    string   `json:"@ssl"`
	Alerts []Alerts `json:"alerts"`
}

type Tags struct {
	Tag  string `json:"tag"`
	Link string `json:"link"`
}

type DASTFinding struct {
	ID       string `json:"id"`
	Scanner  string `json:"scanner"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	AppType  string `json:"appType"`
	CWE      string `json:"cwe"`
	Solution string `json:"solution"`
	Tags     []Tags
	REST     RESTFinding `json:"rest"`
}

type RESTFinding struct {
	AppName                  string            `json:"appName"`
	Host                     string            `json:"host"`
	HTTPVersion              string            `json:"httpVersion"`
	Method                   string            `json:"method"`
	Path                     string            `json:"path"`
	QueryParameters          map[string]string `json:"queryParameters"`
	VulnerableParameterName  string            `json:"vulnerableParameterName"`
	VulnerableParameterValue string            `json:"vulnerableParameterValue"`
	ErrorType                string            `json:"errorType"`
	ErrorDescription         string            `json:"errorDescription"`
	PreviousResponse         string            `json:"previousResponse"`
	URI                      string            `json:"uri"`
	RequestHeader            map[string]string `json:"requestHeader"`
	RequestBody              string            `json:"requestBody"`
	ResponseHeader           map[string]string `json:"responseHeader"`
	ResponseBody             string            `json:"responseBody"`
}
