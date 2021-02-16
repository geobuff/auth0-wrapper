# geobuff/auth
A package to make it easier to handle Auth0 authorization and check whether a user is valid or has permissions based on API scopes.

## Setup
 - Create [scopes](https://auth0.com/docs/scopes/api-scopes) for your API in Auth0.
 - If using ValidUser, add a [custom claims rule](https://auth0.com/docs/scopes/sample-use-cases-scopes-and-claims#add-custom-claims-to-a-token) in Auth0 to include your key in the access token returned to the user:
 ```
 function (user, context, callback) {
  context.accessToken['http://example.com/username'] = user.username;
  return callback(null, user, context);
}
 ```
 
## Install
```
go get github.com/geobuff/auth
```

## Usage

### GetJwtMiddleware(audience, issuer string) *jwtmiddleware.JWTMiddleware
Returns the Auth0 middleware used to handle authorized endpoints.

```
package main

include (
  "net/http"
  
  "github.com/geobuff/api/users"
  "github.com/geobuff/api/scores"
  "github.com/geobuff/auth"
  "github.com/gorilla/mux"
)

func main() {
  router := mux.NewRouter()
  jwtMiddleware := auth.GetJwtMiddleware("example_audience", "example_issuer")
  
  router.Handle("/api/users", jwtMiddleware.Handler(users.GetUsers)).Methods("GET")
  router.Handle("/api/scores", jwtMiddleware.Handler(scores.CreateScore)).Methods("POST")
  
  http.ListenAndServe(":8080", router)
}
```

### HasPermission(up UserPermission) (bool, error)
Confirms the user making a request has the correct permissions to complete the action.

```
package users

include (
  "fmt"
  "net/http"
  
  "github.com/geobuff/auth"
)

var GetUsers = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
  up := auth.UserPermission{
    Request:    request,
    Permission: "read_users",
  }

  if hasPermission, err := auth.HasPermission(up); err != nil {
    http.Error(writer, fmt.Sprintf("%v\n", err), http.StatusInternalServerError)
    return
  } else if !hasPermission {
    http.Error(writer, "invalid permissions to make request", http.StatusUnauthorized)
    return
  }
  
  // User has permission...
})
```

### ValidUser(uv UserValidation) (int, error)
Confirms the user making a request is either making changes to their own data or has the correct permissions to complete the action.

```
package scores

include (
  "fmt"
  "net/http"
  
  "github.com/geobuff/auth"
)

var CreateScore = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
  uv := auth.UserValidation{
    Request:    request,
    Permission: "write_scores",
    Identifier: "http://example.com/username",
    Key:        "example_username",
  }

  if code, err := auth.ValidUser(uv); err != nil {
    http.Error(writer, fmt.Sprintf("%v\n", err), code)
    return
  }

  // User is valid...
})

```
