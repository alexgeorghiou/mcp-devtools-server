-- Sample schema for trying the Postgres tools: a small lending library.

CREATE TABLE authors (
    author_id   serial PRIMARY KEY,
    name        text NOT NULL,
    born        int
);

CREATE TABLE books (
    book_id     serial PRIMARY KEY,
    author_id   int NOT NULL REFERENCES authors(author_id),
    title       text NOT NULL,
    published   int,
    genre       text NOT NULL
);

CREATE TABLE members (
    member_id   serial PRIMARY KEY,
    display_name text NOT NULL,
    joined_on   date NOT NULL DEFAULT current_date
);

CREATE TABLE checkouts (
    checkout_id bigserial PRIMARY KEY,
    book_id     int NOT NULL REFERENCES books(book_id),
    member_id   int NOT NULL REFERENCES members(member_id),
    checked_out timestamptz NOT NULL,
    returned    timestamptz
);
-- Deliberately no index on checkouts(member_id) so explain_slow_query has something to find.

INSERT INTO authors (name, born) VALUES
    ('Ursula K. Le Guin', 1929), ('Terry Pratchett', 1948), ('Octavia E. Butler', 1947),
    ('Italo Calvino', 1923), ('N. K. Jemisin', 1972);

INSERT INTO books (author_id, title, published, genre) VALUES
    (1, 'A Wizard of Earthsea', 1968, 'fantasy'),
    (1, 'The Dispossessed', 1974, 'science fiction'),
    (2, 'Guards! Guards!', 1989, 'fantasy'),
    (2, 'Small Gods', 1992, 'fantasy'),
    (3, 'Kindred', 1979, 'science fiction'),
    (3, 'Parable of the Sower', 1993, 'science fiction'),
    (4, 'Invisible Cities', 1972, 'literary'),
    (5, 'The Fifth Season', 2015, 'fantasy');

INSERT INTO members (display_name, joined_on)
SELECT 'member-' || g, date '2024-01-01' + (g % 700)
FROM generate_series(1, 2000) AS g;

INSERT INTO checkouts (book_id, member_id, checked_out, returned)
SELECT 1 + (g % 8),
       1 + (g * 7 % 2000),
       timestamptz '2025-01-01' + make_interval(hours => g),
       CASE WHEN g % 5 = 0 THEN NULL
            ELSE timestamptz '2025-01-01' + make_interval(hours => g + 72) END
FROM generate_series(1, 50000) AS g;

ANALYZE;

-- Least-privilege role for the MCP server: SELECT only, read-only by default.
CREATE ROLE devtools_reader LOGIN PASSWORD 'reader';
ALTER ROLE devtools_reader SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE library TO devtools_reader;
GRANT USAGE ON SCHEMA public TO devtools_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO devtools_reader;
