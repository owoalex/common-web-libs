DROP FUNCTION IF EXISTS UuidToBin;
DROP FUNCTION IF EXISTS BinToUuid;

DELIMITER //

CREATE FUNCTION UuidToBin(_uuid BINARY(36))
    RETURNS BINARY(16)
    LANGUAGE SQL  DETERMINISTIC  CONTAINS SQL  SQL SECURITY INVOKER
RETURN
    UNHEX(CONCAT(
        SUBSTR(_uuid, 15, 4),
        SUBSTR(_uuid, 10, 4),
        SUBSTR(_uuid,  1, 8),
        SUBSTR(_uuid, 20, 4),
        SUBSTR(_uuid, 25) ));
//
CREATE FUNCTION BinToUuid(_bin BINARY(16))
    RETURNS BINARY(36)
    LANGUAGE SQL  DETERMINISTIC  CONTAINS SQL  SQL SECURITY INVOKER
RETURN
    LCASE(CONCAT_WS('-',
        HEX(SUBSTR(_bin,  5, 4)),
        HEX(SUBSTR(_bin,  3, 2)),
        HEX(SUBSTR(_bin,  1, 2)),
        HEX(SUBSTR(_bin,  9, 2)),
        HEX(SUBSTR(_bin, 11))
                ));

//
DELIMITER ;

GRANT EXECUTE ON FUNCTION UuidToBin TO "indent_one"@"localhost";
GRANT EXECUTE ON FUNCTION BinToUuid TO "indent_one"@"localhost";

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS flow_data;
DROP TABLE IF EXISTS access_log;

CREATE TABLE users (
    user_uuid BINARY(16) NOT NULL UNIQUE,
    display_name VARCHAR(1024),
    username VARCHAR(1024) NOT NULL UNIQUE,
    password_hash VARCHAR(1024) NOT NULL,
    account_scopes VARCHAR(2048) DEFAULT "SELF_READ,SELF_WRITE,SELF_MANAGE" NOT NULL,
    totp_secret VARCHAR(128),
    creation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (user_uuid),
    INDEX (username)
) DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;

CREATE TABLE sessions (
    session_uuid BINARY(16) NOT NULL UNIQUE,
    user_uuid BINARY(16),
    active BOOLEAN DEFAULT false NOT NULL,
    creation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (session_uuid),
    INDEX (user_uuid)
) DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;

CREATE TABLE flow_sessions (
    flow_uuid BINARY(16) NOT NULL UNIQUE,
    flow_data TEXT,
    creation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (flow_uuid)
) DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;

CREATE TABLE access_log (
    ip_address VARCHAR(64),
    uri VARCHAR(4096),
    result VARCHAR(4096),
    user_agent VARCHAR(4096),
    session_uuid BINARY(16),
    access_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
) DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;
