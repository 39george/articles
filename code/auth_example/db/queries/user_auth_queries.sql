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
