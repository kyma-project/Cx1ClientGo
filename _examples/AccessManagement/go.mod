module github.com/cxpsemea/Cx1ClientGo/examples/AccessManagement

go 1.19

require (
	github.com/cxpsemea/Cx1ClientGo v0.0.10
	github.com/sirupsen/logrus v1.9.0
	github.com/t-tomalak/logrus-easy-formatter v0.0.0-20190827215021-c074f06c5816
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/oauth2 v0.4.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace (
    github.com/cxpsemea/Cx1ClientGo => ../../
)