package internal

import (
	ginAdapter "github.com/39george/scs_gin_adapter"
	"github.com/redis/go-redis/v9"

	"auth_example/db/sqlc"
)

const AppStateLabel = "auth_example.appstate"

// Should be cheap-to-copy and thread-safe for using from many requests concurrently
type AppState struct {
	Sqlc        *sqlc.Queries
	RedisClient *redis.Client
	Session     *ginAdapter.GinAdapter
}
