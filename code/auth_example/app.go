package auth_example

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

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
		"docker.loc",
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
		Sqlc:        sqlcObj,
		RedisClient: redisClient,
		Session:     sessionAdapter,
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
				slog.Warn("Failed to login user:", "error", err.Error())
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
