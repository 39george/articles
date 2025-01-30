package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

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
