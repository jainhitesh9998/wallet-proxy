CREATE TABLE IF NOT EXISTS managed_document (
    kind       VARCHAR(16)  NOT NULL,
    id         VARCHAR(255) NOT NULL,
    document   CLOB         NOT NULL,
    updated_at TIMESTAMP    NOT NULL,
    PRIMARY KEY (kind, id)
);
