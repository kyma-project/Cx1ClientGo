module github.com/cxpsemea/Cx1ClientGo/examples/AccessManagement

go 1.22.0

require (
	github.com/cxpsemea/Cx1ClientGo v0.0.92
	github.com/sirupsen/logrus v1.9.3
	github.com/t-tomalak/logrus-easy-formatter v0.0.0-20190827215021-c074f06c5816
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	golang.org/x/exp v0.0.0-20241108190413-2d47ceb2692f // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
)

replace github.com/cxpsemea/Cx1ClientGo => ../../
