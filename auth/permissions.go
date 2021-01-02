package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// UserPermission is the data used in HasPermission.
type UserPermission struct {
	Request    *http.Request
	Permission string
}

// UserValidation is the data used in ValidUser.
type UserValidation struct {
	Request    *http.Request
	UserID     int
	Permission string
	Identifier string
	Key        string
}

// HasPermission confirms the user making a request has the correct permissions to complete the action.
var HasPermission = func(up UserPermission) (bool, error) {
	permissions, err := getPermissions(up.Request)
	if err != nil {
		return false, err
	}
	return permissionPresent(permissions, up.Permission), nil
}

// ValidUser confirms the user making a request is either making changes to their own data or has the correct
// permissions to complete the action.
var ValidUser = func(uv UserValidation) (int, error) {
	if matchingUser, err := matchingUser(uv.Request, uv.Identifier, uv.Key); err != nil {
		return http.StatusInternalServerError, err
	} else if !matchingUser {
		up := UserPermission{
			Request:    uv.Request,
			Permission: uv.Permission,
		}

		if hasPermission, err := HasPermission(up); err != nil {
			return http.StatusInternalServerError, err
		} else if !hasPermission {
			return http.StatusUnauthorized, errors.New("missing or invalid permissions")
		}
	}

	return 200, nil
}

func getPermissions(request *http.Request) ([]interface{}, error) {
	token, _, err := parseToken(request)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims["permissions"].([]interface{}), nil
	}
	return nil, errors.New("failed to parse claims from token")
}

func parseToken(request *http.Request) (*jwt.Token, []string, error) {
	header := request.Header.Get("Authorization")
	if len(header) < 8 {
		return nil, nil, errors.New("token missing or invalid length")
	}

	tokenString := header[7:]
	parser := new(jwt.Parser)
	return parser.ParseUnverified(tokenString, jwt.MapClaims{})
}

func permissionPresent(permissions []interface{}, target string) bool {
	for _, permission := range permissions {
		if permission == target {
			return true
		}
	}
	return false
}

var matchingUser = func(request *http.Request, identifier string, target string) (bool, error) {
	identifier, err := getIdentifier(request, identifier)
	if err != nil {
		return false, err
	}
	return identifier == target, nil
}

func getIdentifier(request *http.Request, identifier string) (string, error) {
	token, _, err := parseToken(request)
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return fmt.Sprintf("%s", claims[identifier]), nil
	}
	return "", errors.New("failed to parse claims from token")
}
