CREATE TABLE users(
    id TEXT PRIMARY KEY UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT DEFAULT (DATETIME()) NOT NULL
);

SELECT * FROM users;

DROP TABLE users;

INSERT INTO users (id, name, email, password, role)
VALUES
    ("u001", "Eugenia", "eugenia@email.com", "Eu@genia489", "ADMIN"),
    ("u002", "Alex", "alex@email.com", "#ALex8520", "NORMAL");

CREATE TABLE posts(
    id TEXT PRIMARY KEY UNIQUE NOT NULL,
    creator_id TEXT NOT NULL,
    content TEXT NOT NULL,
    likes INTEGER DEFAULT(0) NOT NULL,
    dislikes INTEGER DEFAULT(0) NOT NULL,
    created_at TEXT DEFAULT(DATETIME()) NOT NULL,
    updated_at TEXT DEFAULT(DATETIME()) NOT NULL,
    FOREIGN KEY (creator_id) REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

SELECT * FROM posts;

DROP TABLE posts;

INSERT INTO posts (id, creator_id, content)
VALUES
    ("p001", "u001", "Muito projeto legal!"),
    ("p002", "u001", "quero logo trabalhar"),
    ("p003", "u002", "cansado porém não humilhado");

CREATE TABLE likes_dislikes(
    user_id TEXT NOT NULL,
    post_id TEXT NOT NULL,
    like INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

SELECT * FROM likes_dislikes;

DROP TABLE likes_dislikes;

INSERT INTO likes_dislikes (user_id, post_id, like)
VALUES
    ("u001", "p001", 400),
    ("u001", "p002", 200),
    ("u002", "p003", 20);

SELECT 
    posts.id,
    posts.creator_id,
    posts.content,
    posts.likes,
    posts.dislikes,
    posts.created_at,
    posts.updated_at,
    users.name AS creator_name
FROM posts
JOIN users
ON posts.creator_id = users.id;

UPDATE users
SET password = "$2a$12$iSd0f004.jVFVrAjslARD.myipBt.4b0Sbf/8VTvZAqIYiq6GbDju"
WHERE id = "u001";

UPDATE users
SET password = "$2a$12$ZLXrqt.6dqrzRnpba.u8zu.S97F0V8TLVLYeU1jaBIRFNr2jCdVLu"
WHERE id = "u002";

