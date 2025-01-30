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
