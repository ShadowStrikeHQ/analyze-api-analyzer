# analyze-api-analyzer
Examines API endpoints (e.g., Swagger/OpenAPI definitions or live endpoints) for common vulnerabilities like missing authentication, rate limiting issues, or insecure data handling. Uses `requests` and `json` for API interaction and definition parsing. - Focused on Data analysis and reporting

## Install
`git clone https://github.com/ShadowStrikeHQ/analyze-api-analyzer`

## Usage
`./analyze-api-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--output`: No description provided
- `--auth_header`: Authorization header to use (e.g., 
- `--rate_limit_threshold`: Threshold for rate limiting analysis.  Defaults to 100 requests/minute.
- `--verbose`: No description provided

## License
Copyright (c) ShadowStrikeHQ
