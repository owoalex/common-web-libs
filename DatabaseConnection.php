<?php
namespace indent_one;

class DatabaseConnection {
    private static $pdo = null;
    
    public static function getPDO() {
        if (self::$pdo == null) {
            self::$pdo = new \PDO("mysql:host=".CREDENTIAL_SQL_HOST.";dbname=".CREDENTIAL_SQL_DATABASE, CREDENTIAL_SQL_USERNAME, CREDENTIAL_SQL_PASSWORD);
            self::$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        }
        
        return self::$pdo;
    }
}
