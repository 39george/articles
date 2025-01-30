# User authentication in go

User authentication and authorization are fundamental concepts in building secure applications. They ensure that only authorized users can access specific resources or functionalities within your application.

This article dives into these concepts and explores how Golang packages like Authpher can simplify their implementation.

## Let's start!

To effectively manage user authentication and authorization, we need to consider how to store user data and handle user sessions.

- User Data Storage: In this example, we'll utilize a PostgreSQL database to securely store user information, such as usernames, passwords, and associated permissions.
- Session Management: To enhance user experience, we'll implement session caching using Redis. This allows users to authenticate once and have their session information stored in Redis for subsequent requests. A unique session token will be securely stored in the user's browser cookie, enabling seamless identification and access to their session data.

To simplify things, we will use [gin](https://github.com/gin-gonic/gin) framework and several additional packages:
- [pgx](https://github.com/jackc/pgx) - postgreSQL driver and toolkit for Go.
- [sqlc](https://github.com/sqlc-dev/sqlc) -  type-safe code from SQL generator.
- [go-redis](https://github.com/redis/go-redis) - redis Go client.
- [scs](https://github.com/alexedwards/scs) - HTTP Session Management for Go.
- [scs_gin_adapter](https://github.com/39george/scs_gin_adapter) - a tiny adapter for using scs with gin.
- [scs_redisstore](https://github.com/39george/scs_redisstore) - go-redis store for scs.
- [authpher](https://github.com/39george/authpher) - user identification, authentication, and authorization for Go.

## Prepare storage

Create `any-name` project directory, in my example, it will be `auth_example`.
Run `go mod init auth_example` to create go module for our project.

We will use awesome [dbmate](https://github.com/amacneil/dbmate) migration tool for our migrations.

Run in the terminal in our project root:
```bash
dbmate new init_migration
```
Output:
```bash
Creating migration: db/migrations/20250129053023_init_migration.sql
```

Lets write our first database migration:
```sql
-- migrate:up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(500) NOT NULL,
    -- Ensure case insensitive uniqueness with CITEXT type
    email CITEXT UNIQUE NOT NULL
);

CREATE TABLE groups (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

-- Create `users_groups` table for many-to-many
-- relationships between users and groups.
CREATE TABLE user_groups (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,    
    group_id INTEGER REFERENCES groups(id) ON DELETE RESTRICT,
    PRIMARY KEY (user_id, group_id)
);

-- Create `groups_permissions` table for many-to-many relationships
-- between groups and permissions.
CREATE TABLE group_permissions (
    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, permission_id)
);

-- Insert "users" and "administrators" groups.
INSERT INTO groups (name) VALUES ('group.administrators');
INSERT INTO groups (name) VALUES ('group.users-starter');
INSERT INTO groups (name) VALUES ('group.users-medium');
INSERT INTO groups (name) VALUES ('group.users-pro');

-- Insert individual permissions.
INSERT INTO permissions (name) VALUES ('administrator');
INSERT INTO permissions (name) VALUES ('starter');
INSERT INTO permissions (name) VALUES ('medium');
INSERT INTO permissions (name) VALUES ('pro');

-- Insert group permissions.
INSERT INTO group_permissions (group_id, permission_id)
VALUES (
    (SELECT id FROM groups WHERE name = 'group.users-starter'),
    (SELECT id FROM permissions WHERE name = 'starter')
), (
    (SELECT id FROM groups WHERE name = 'group.users-medium'),
    (SELECT id FROM permissions WHERE name = 'starter')
), (
    (SELECT id FROM groups WHERE name = 'group.users-medium'),
    (SELECT id FROM permissions WHERE name = 'medium')
), (
    (SELECT id FROM groups WHERE name = 'group.users-pro'),
    (SELECT id FROM permissions WHERE name = 'starter')
), (
    (SELECT id FROM groups WHERE name = 'group.users-pro'),
    (SELECT id FROM permissions WHERE name = 'medium')
), (
    (SELECT id FROM groups WHERE name = 'group.users-pro'),
    (SELECT id FROM permissions WHERE name = 'pro')
), (
    (SELECT id FROM groups WHERE name = 'group.administrators'),
    (SELECT id FROM permissions WHERE name = 'starter')
), (
    (SELECT id FROM groups WHERE name = 'group.administrators'),
    (SELECT id FROM permissions WHERE name = 'medium')
), (
    (SELECT id FROM groups WHERE name = 'group.administrators'),
    (SELECT id FROM permissions WHERE name = 'pro')
), (
    (SELECT id FROM groups WHERE name = 'group.administrators'),
    (SELECT id FROM permissions WHERE name = 'administrator')
);

-- migrate:down
DROP FUNCTION IF EXISTS insert_request;

DROP TABLE IF EXISTS group_permissions;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS citext;
```

In this example, we have four groups of users with varying access levels:

- `Administrators`: Have access to all endpoints within the application.
- `Pro` Users: Have access to all endpoints intended for users.
- `Medium` Users: Have access to "starter" and "medium" level endpoints.
- `Starter` Users: Have access to only "starter" level endpoints.

Implying that you already have postgres available (for example, in docker container), run our first migration with (use our own credentials):
```bash
dbmate --url postgres://postgres:admin@pg.docker.loc/auth_example?sslmode=disable --no-dump-schema up
```

Next, let's write sql queries for retrieving our users & their permissions. Here we will use [sqlc](https://github.com/sqlc-dev/sqlc) for type-safe code generation from our sql queries, and [pgx](https://github.com/jackc/pgx/v5) as its backend
```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
go get github.com/jackc/pgx/v5
go get github.com/jackc/pgx/v5/pgxpool
```

Create sqlc.yaml at the root of our project:
```yaml
version: "2"
sql:
  - engine: "postgresql"
    queries: "db/queries"
    schema: "db/migrations/"
    gen:
      go:
        package: "sqlc" # Package name
        out: "db/sqlc" # Output folder
        sql_package: "pgx/v5" # Use sql types provided by pgx
        emit_json_tags: true
        emit_db_tags: true
        emit_pointers_for_null_types: true
        emit_empty_slices: true
```

Then create `db/queries/user_auth_queries.sql`:
```sql
-- name: GetAuthUserData :one
SELECT id, username, password_hash
FROM users
WHERE username = sqlc.narg(username) OR id = sqlc.narg(id);

-- name: GetUserPermissions :many
SELECT DISTINCT permissions.name
FROM users
JOIN user_groups
ON users.id = user_groups.user_id
JOIN group_permissions
ON user_groups.group_id = group_permissions.group_id
JOIN permissions
ON group_permissions.permission_id = permissions.id
WHERE users.id = $1;

-- name: InsertUserToDb :one
INSERT INTO users (username, password_hash, email) 
VALUES ($1, $2, $3) RETURNING id;

-- name: AddUserToGroup :exec
INSERT INTO user_groups(user_id, group_id)
VALUES ($1, (
    SELECT id FROM groups WHERE name = $2
));
```

Then run `sqlc generate` to generate go code from our queries.
Go code should appear in the db/sqlc folder.

## Go logic implementation

Let's write some go code! Add our dependencies:
```bash
go get github.com/gin-gonic/gin
go get github.com/alexedwards/scs/v2
go get github.com/39george/scs_gin_adapter
go get github.com/39george/scs_redisstore go get github.com/39george/authpher
go get github.com/redis/go-redis/v9
```

Create `auth_example/internal/appstate.go`, it will hold our app's state:
```go
package internal

import (
	ginAdapter "github.com/39george/scs_gin_adapter"
	"github.com/redis/go-redis/v9"

	"auth_example/db/sqlc"
)

const AppStateLabel = "auth_example.appstate"

// Should be cheap-to-copy and thread-safe for using from many requests concurrently
type AppState struct {
	Sqlc            *sqlc.Queries
	RedisClient     *redis.Client
	Session         *ginAdapter.GinAdapter
}
```

Also we will use [argon2](https://en.wikipedia.org/wiki/Argon2), modern password-hashing function for securing our password, create `auth_example/internal/argon2/argon2.go`:
```go
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash = errors.New(
		"the encoded hash is not in the correct format",
	)
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var StdParams = params{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}
var LightParams = params{
	memory:      15000,
	iterations:  2,
	parallelism: 1,
	saltLength:  16,
	keyLength:   32,
}

func GenWithParams(p params, pass string) (string, error) {
	// Generate a cryptographically secure random salt.
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash, err := generateFromPassword(salt, pass, &p)
	if err != nil {
		return "", err
	}

	// Encode salt and hash using Base64
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	// Construct the Argon2 hash format
	hashString := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.memory, p.iterations, p.parallelism, encodedSalt, encodedHash)

	return hashString, nil
}

func ComparePasswordAndHash(
	password, encodedHash string,
) (match bool, err error) {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keyLength,
	)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func generateFromPassword(
	salt []byte,
	password string,
	p *params,
) (hash []byte, err error) {
	// Pass the plaintext password, salt and parameters to the argon2.IDKey
	// function. This will generate a hash of the password using the Argon2id
	// variant.
	hash = argon2.IDKey(
		[]byte(password),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keyLength,
	)
	return hash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(
		vals[3],
		"m=%d,t=%d,p=%d",
		&p.memory,
		&p.iterations,
		&p.parallelism,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}
```

Next step, we will implement our actual authentication backend, create `auth_example/internal/auth/backend.go`, we could just fetch user data from postgres, but for reducing database read rate we will cache that data for limited time in redis:
```go
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
	"log/slog"
	"strconv"

	"github.com/39george/authpher"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"auth_example/db/sqlc"
	"auth_example/internal/argon2"
)

type User struct {
	ID           int32  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

func UserFromMap(m map[string]string) (User, error) {
	var user User
	if len(m) == 0 {
		return user, errors.New("map len is 0")
	}
	idS, ok := m["id"]
	if !ok {
		return user, errors.New("id field not found")
	}
	id, err := strconv.Atoi(idS)
	if err != nil {

	}
	username, ok := m["username"]
	if !ok {
		return user, errors.New("username field not found")
	}
	passwordHash, ok := m["password_hash"]
	if !ok {
		return user, errors.New("password_hash field not found")
	}
	return User{int32(id), username, passwordHash}, nil
}

func (u *User) IntoMap() map[string]string {
	return map[string]string{
		"id":            strconv.Itoa(int(u.ID)),
		"username":      u.Username,
		"password_hash": u.PasswordHash,
	}
}

func (u *User) UserId() any {
	return u.ID
}

func (u *User) SessionAuthHash() []byte {
	return []byte(u.PasswordHash)
}

type Credentials struct {
  Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
	Email    string `form:"email"    json:"email"`
	Group    string `form:"group"    json:"group"`
}

type MyBackend struct {
	PgPool    *sqlc.Queries
	RedisPool *redis.Client
}

func (mb MyBackend) Authenticate(
	ctx context.Context,
	creds Credentials,
) (authpher.AuthUser, error) {
	// Get user data by username
	data, err := mb.PgPool.GetAuthUserData(
		ctx,
		sqlc.GetAuthUserDataParams{Username: &creds.Username},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to get auth user data for %v, %w",
			creds,
			err,
		)
	}
	// Run argon2 verification
	user := User(data)
	match, err := argon2.ComparePasswordAndHash(
		creds.Password,
		user.PasswordHash,
	)
	if err != nil {
		return nil, err
	}
	if match {
		return &user, nil
	} else {
		return nil, nil
	}
}

func (mb MyBackend) GetUser(
	ctx context.Context,
	userId any,
) (authpher.AuthUser, error) {
	usrId := userId.(int32)

	// Try to get user usrData by username from cache
	rKey := fmt.Sprintf("user_data_cache:%d", usrId)
	m, err := mb.RedisPool.HGetAll(ctx, rKey).Result()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to fetch user_data_cache from redis: %w",
			err,
		)
	} else if len(m) != 0 {
		user, err := UserFromMap(m)
		if err != nil {
			slog.Warn(fmt.Errorf("failed to get user from map: %w", err).Error())
		} else {
			// Return pointer!
			return &user, nil
		}
	}

	// Get user usrData by username from db
	usrData, err := mb.PgPool.GetAuthUserData(
		ctx,
		sqlc.GetAuthUserDataParams{ID: &usrId},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user := User(usrData)

	// Cache user
	_, err = mb.RedisPool.HSet(ctx, rKey, user.IntoMap()).Result()
	if err != nil {
		slog.Error(fmt.Errorf("failed to cache user: %w", err).Error())
	}
	_, err = mb.RedisPool.Expire(ctx, rKey, time.Minute).Result()
	if err != nil {
		slog.Error(fmt.Errorf("failed to set expiration: %w", err).Error())
	}

	// Return pointer!
	return &user, nil
}

func (mb MyBackend) GetUserPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	perms := mapset.NewSetWithSize[string](0)
	return perms, nil
}

func (mb MyBackend) GetGroupPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	// user is pointer!
	u := user.(*User)

	// Try to get user permissions from cache
	rKey := fmt.Sprintf("user_permissions_cache:%d", u.ID)
	slice, err := mb.RedisPool.SMembers(ctx, rKey).Result()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to fetch user_permissions_cache from redis: %w",
			err,
		)
	} else if len(slice) != 0 {
		perms := mapset.NewSetWithSize[string](len(slice))
		for _, perm := range slice {
			perms.Add(perm)
		}
		return perms, nil
	}

	// Get user permissions from db
	data, err := mb.PgPool.GetUserPermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	perms := mapset.NewSetWithSize[string](len(data))
	for _, perm := range data {
		perms.Add(perm)
	}

	// Cache permissions
	_, err = mb.RedisPool.SAdd(ctx, rKey, data).Result()
	if err != nil {
		slog.Error(
			fmt.Errorf("failed to cache user permissions: %w", err).Error(),
		)
	}
	_, err = mb.RedisPool.Expire(ctx, rKey, time.Minute).Result()
	if err != nil {
		slog.Error(fmt.Errorf("failed to set expiration: %w", err).Error())
	}

	return perms, nil
}
```

We will not create separate `config` package, instead, for simplicity, just pass all configs directly in code. Create `auth_example/app.go` file:
```go
package auth_example

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
 	"http"

	"github.com/39george/authpher"
	"github.com/39george/authpher/adapters/authgin"
	"github.com/39george/authpher/sessions/ginsessions"
	ginAdapter "github.com/39george/scs_gin_adapter"
	scsRedisStore "github.com/39george/scs_redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"auth_example/db/sqlc"
	"auth_example/internal"
	"auth_example/internal/argon2"
	"auth_example/internal/auth"
)

type Application struct {
	server   *gin.Engine
	listener *net.Listener
}

func BuildApplication(router *gin.Engine) Application {
	ctx := context.Background()

	// NOTE: Adjust options yourself
    pgConnStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=allow",
		"localhost",
		5432,
		"postgres",
		"admin",
		"auth_example",
	)
	pool := getPgPool(ctx, pgConnStr)
	sqlcObj := sqlc.New(pool)

	// NOTE: Adjust options yourself
	redisClient := getRedisConnectionPool("localhost:6379", "admin", 0)

	// Initialize a new session manager and configure the session lifetime.
	sessionManager := scs.New()
	sessionManager.Store = scsRedisStore.New(redisClient)
	sessionManager.Lifetime = 24 * time.Hour
	sessionAdapter := ginAdapter.New(sessionManager)

	appState := &internal.AppState{
		Sqlc:            sqlcObj,
		RedisClient:     redisClient,
		Session:         sessionAdapter,
	}

    // Use our app state for every request
	router.Use(func(c *gin.Context) {
		c.Set(internal.AppStateLabel, appState)
	})

	// Logging errors
	router.Use(func(c *gin.Context) {
		c.Next()
		errors := c.Errors.Errors()
		for i, error := range errors {
			err := fmt.Errorf("#%02d: %s", i+1, error)
            slog.Error(err.Error())
		}
		c.Errors = nil
	})

	// Session middleware
	router.Use(sessionAdapter.LoadAndSave)

	router.Use(authgin.Auth[string, auth.Credentials](
		auth.MyBackend{
			PgPool:    appState.Sqlc,
			RedisPool: appState.RedisClient,
		},
		&ginsessions.GinSessions{Store: sessionAdapter}),
	)

    openRoutes := router.Group("/open")
    userRoutes := router.Group("/user")
    userRoutes.Use(authgin.PermissionRequired[string, auth.Credentials]("starter"))
    adminRoutes := router.Group("/admin")
    adminRoutes.Use(authgin.PermissionRequired[string, auth.Credentials]("admin"))

    // Define handlers
    userRoutes.GET("/test", func(c *gin.Context) {})
    adminRoutes.GET("/test", func(c *gin.Context) {})
    openRoutes.GET("/test", func(c *gin.Context) {})
    openRoutes.POST("/login", func(c *gin.Context) {
        credentials := new(auth.Credentials)
        err := c.ShouldBindWith(credentials, binding.JSON)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        authSession, _ := c.Get(authpher.AuthContextString)
        aS := authSession.(*authpher.AuthSession[string, auth.Credentials])
        user, err := aS.Authenticate(c, *credentials)
        if err != nil {
            c.AbortWithError(http.StatusUnauthorized, err)
            return
        }
        if user != nil {
            u := user.(*auth.User)
            err = aS.Login(c, u)
            if err != nil {
                slog.Warn("Failed to login user", "error", err.Error())
            }
        } else {
            c.AbortWithStatus(http.StatusUnauthorized)
        }
    })
    openRoutes.POST("/signup", func(c *gin.Context) {
        s, _ := c.Get(internal.AppStateLabel)
        state := s.(*internal.AppState)

        creds := new(auth.Credentials)
        err := c.ShouldBindWith(creds, binding.FormPost)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        passwordHash, err := argon2.GenWithParams(argon2.LightParams, creds.Password)
        if err != nil {
            c.AbortWithStatus(http.StatusInternalServerError)
            return
        }
        userId, err := state.Sqlc.InsertUserToDb(c, sqlc.InsertUserToDbParams{
            Username:     creds.Username,
            PasswordHash: passwordHash,
            Email:        creds.Email,
        })
        if err != nil {
            c.AbortWithError(http.StatusInternalServerError, err)
        }
        err = state.Sqlc.AddUserToGroup(c, sqlc.AddUserToGroupParams{
            UserID: userId,
            Name:   creds.Group,
        })
        if err != nil {
            c.AbortWithError(http.StatusInternalServerError, err)
        }
        c.Status(http.StatusOK)
    })

	listener, err := net.Listen(
		"tcp",
		fmt.Sprintf("%s:%d", "localhost", 8080),
	)
	panicOnError(err, "Error binding to port")
	return Application{server: router, listener: &listener}
}

func (a *Application) RunUntilStopped() {
	a.server.RunListener(*a.listener)
}

func getRedisConnectionPool(addr string, password string, dbNumber int) *redis.Client {
	opts := &redis.Options{
		Addr:     addr,
		Password: password,
		DB:       dbNumber,
	}

	return redis.NewClient(opts)
}

func getPgPool(
	ctx context.Context,
    connStr string,
) *pgxpool.Pool {
	pool, err := pgxpool.New(ctx, connStr)
	panicOnError(err, "Failed to connect to postgres")
	return pool
}

func panicOnError(err error, message string) {
	if err != nil {
		panic(message + ": " + err.Error())
	}
}
```

And, finally, lets implement our `auth_example/main.go` program:
```go
package main

import (
	"github.com/gin-gonic/gin"

	"auth_example"
)

func main() {
    r := gin.New()
    r.Use(gin.Recovery())
    app := auth_example.BuildApplication(r)
    app.RunUntilStopped()
}
```
Now we should can run our application with:
```bash
go run main.go
```

## Testing

Now lets test our open handler with curl:
```bash
curl -i localhost:8080/open/test
```
You should get:
```http
HTTP/1.1 200 OK
Vary: Cookie
Date: Thu, 30 Jan 2025 12:45:47 GMT
Content-Length: 0
```

Try to get access to protected route:
```bash
curl -i -X GET localhost:8080/user/test
```
You will get:
```http
HTTP/1.1 401 Unauthorized
Vary: Cookie
Date: Thu, 30 Jan 2025 13:07:35 GMT
Content-Length: 0
```

Then we will create new account with command:
```bash
 curl -i -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=user1&password=pass&email=email1@mail.com&group=group.users-starter' localhost:8080/open/signup
```
Output should be:
```http
HTTP/1.1 200 OK
Vary: Cookie
Date: Thu, 30 Jan 2025 13:00:03 GMT
Content-Length: 0
```

And now login to our account (we use `-c` curl flag to store response cookies into a file, simulating web browser session):
```bash
curl -i -X POST -c cookie.txt -H 'Content-Type: application/json' -d '{"username":"user1","password":"pass"}' localhost:8080/open/login
```
Response:
```http
HTTP/1.1 200 OK
Cache-Control: no-cache="Set-Cookie"
Set-Cookie: session=yoP9sQprjrBeTbbEdxO_pa_eGCenKnvmUFqjNfY4kqA; Path=/; Expires=Fri, 31 Jan 2025 13:09:02 GMT; Max-Age=86400; HttpOnly; SameSite=Lax
Vary: Cookie
Date: Thu, 30 Jan 2025 13:09:02 GMT
Content-Length: 0
```

After that you should have access to protected endpoint:
```bash
curl -i -X GET -b cookie.txt localhost:8080/user/test
```
Response:
```http
HTTP/1.1 200 OK
Vary: Cookie
Date: Thu, 30 Jan 2025 13:10:59 GMT
Content-Length: 0
```

If you want, you can go further and create more accounts for testing various permissions for our groups!
That's all.
