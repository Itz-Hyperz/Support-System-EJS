CREATE DATABASE supportsystem CHARACTER SET utf8;
use supportsystem;

CREATE TABLE sitesettings (
    sitename TEXT,
    sitedesc TEXT,
    sitecolor TEXT
);

CREATE TABLE users (
    id TEXT,
    username TEXT,
    email TEXT,
    password TEXT
);

CREATE TABLE categories (
    id TEXT,
    name TEXT
);

CREATE TABLE tickets (
    id TEXT,
    userid TEXT,
    username TEXT,
    category TEXT,
    title TEXT,
    content TEXT,
    datecreated TEXT,
    answerid TEXT
);

CREATE TABLE comments (
    id TEXT,
    ticketid TEXT,
    userid TEXT,
    username TEXT,
    content TEXT,
    datecreated TEXT
);

CREATE TABLE staff (
    userid TEXT
);

ALTER DATABASE supportsystem CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
ALTER TABLE sitesettings CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
ALTER TABLE users CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
ALTER TABLE categories CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
ALTER TABLE tickets CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
ALTER TABLE comments CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
ALTER TABLE staff CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;

INSERT INTO sitesettings (sitename, sitedesc, sitecolor) VALUES ('Change Me', 'A description placeholder...', '#15161c');