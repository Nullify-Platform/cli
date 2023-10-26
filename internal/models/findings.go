package models

type DASTFinding struct {
	ID       string      `json:"id"`
	Scanner  string      `json:"scanner"`
	Title    string      `json:"title"`
	Severity string      `json:"severity"`
	AppType  string      `json:"appType"`
	CWE      string      `json:"cwe"`
	REST     RESTFinding `json:"rest"`
}

type RESTFinding struct {
	AppName          string            `json:"appName"`
	Host             string            `json:"host"`
	HTTPVersion      string            `json:"httpVersion"`
	Method           string            `json:"httpMethod"`
	Endpoint         string            `json:"httpEndpoint"`
	RequestBody      string            `json:"requestBody"`
	PreviousResponse string            `json:"previousResponse"`
	ErrorType        string            `json:"errorType"`
	QueryParameters  map[string]string `json:"queryParameters"`
}
