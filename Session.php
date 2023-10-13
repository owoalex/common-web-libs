<?php
namespace indent_one;

class Session implements PersistentObject {
    private static $current = null;
    private static $cookieConsent = false;
    private $sessionUuid = null;
    private $currentUser = null;
    private $active = false;
    
    public function __construct($sessionUuid = null) {
        if ($sessionUuid == null) {
            $sessionUuid = new_random_uuid();
            $bindVariables = [
                "session_uuid" => $sessionUuid,
            ];
            $sql = "INSERT INTO sessions (session_uuid) VALUES (UuidToBin(:session_uuid))";
            $statement = DatabaseConnection::getPdo()->prepare($sql);
            $statement->execute($bindVariables);
            $this->sessionUuid = $sessionUuid;
        } else {
            $bindVariables = [
                "session_uuid" => $sessionUuid,
            ];
            $sql = "SELECT BinToUuid(user_uuid) AS user_uuid, active FROM sessions WHERE session_uuid=UuidToBin(:session_uuid)";
            $statement = DatabaseConnection::getPdo()->prepare($sql);
            $statement->execute($bindVariables);
            $sessionInfo = $statement->fetch();
            if ($sessionInfo != null) { // This is a valid session, this part DOES NOT CHECK for validity to allow fringe use cases for viewing expired session info
                $this->sessionUuid = $sessionUuid;
                if ($sessionInfo["user_uuid"] != null) {
                    $this->currentUser = new User($sessionInfo["user_uuid"]);
                }
                $this->active = $sessionInfo["active"];
            }
        }
    }
    
    private function saveData() {
        $bindVariables = [
            "session_uuid" => $this->sessionUuid,
            "user_uuid" => null,
            "active" => $this->active ? 1:0,
        ];
        if ($this->currentUser != null) {
            $bindVariables["user_uuid"] = $this->currentUser->getUUID();
        }
        $sql = "UPDATE sessions SET user_uuid = UuidToBin(:user_uuid), active = :active WHERE session_uuid = UuidToBin(:session_uuid)";
        $statement = DatabaseConnection::getPdo()->prepare($sql);
        $statement->execute($bindVariables);
    }
    
    public function invalidate() {
        $this->active = false;
        $this->saveData();
    }
    
    public function getUUID() {
        return $this->sessionUuid;
    }
    
    public static function getCurrent() {
        if (self::$current == null) {
            $jwtToUse = null;
            if (isset($_COOKIE["root_jwt"])) {
                $rootJwt = new \indent_one\JWT($_COOKIE["root_jwt"]);
                if ($rootJwt->isValidForRecipient(SERVER_FQDN) && $rootJwt->isValidForPurpose("ROOT_TRUST")) {
                    $jwtToUse = $rootJwt;
                }
            } elseif (get_bearer_token() != null) {
                $authJwt = new \indent_one\JWT(get_bearer_token());
                if ($authJwt->isValidForRecipient(SERVER_FQDN) || $authJwt->isValidForRecipient($_SERVER["SERVER_NAME"])) {
                    if ($authJwt->isValidForPurpose("SERVICE_AUTH") || $authJwt->isValidForPurpose("ROOT_TRUST")) {
                        $jwtToUse = $authJwt;
                    }
                }
            } elseif (isset($_COOKIE["indent_one_jwt"])) {
                $authJwt = new \indent_one\JWT($_COOKIE["indent_one_jwt"]);
                if (($authJwt->isValidForRecipient(SERVER_FQDN) || $authJwt->isValidForRecipient($_SERVER["SERVER_NAME"])) && $authJwt->isValidForPurpose("SERVICE_AUTH")) {
                    $jwtToUse = $authJwt;
                }
            }
            if ($jwtToUse != null) {
                $bindVariables = [
                    "session_uuid" => $jwtToUse->getClaim("sid"),
                ];
                $sql = "SELECT 1 FROM sessions WHERE session_uuid=UuidToBin(:session_uuid) AND active=1";
                $statement = DatabaseConnection::getPdo()->prepare($sql);
                $statement->execute($bindVariables);
                $sessionInfo = $statement->fetch();
                if ($sessionInfo != null) { // This is a valid and active session
                    self::$current = new Session($jwtToUse->getClaim("sid"));
                }
            }
        }
        
        return self::$current;
    }
    
    public function getUser() {
        return $this->currentUser;
    }
    
    public function setUser($user = null) {
        $this->currentUser = $user;
        if ($user != null) {
            $this->active = true;
        }
        $this->saveData();
    }
}
