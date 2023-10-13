<?php
namespace indent_one;

class FlowSession implements PersistentObject {
    private static $current = null;
    private $sessionUuid = null;
    private $sessionData = null;
    
    public function __construct($sessionUuid = null) {
        if ($sessionUuid == null) {
            $sessionUuid = new_random_uuid();
            $bindVariables = [
                "flow_uuid" => $sessionUuid,
            ];
            $sql = "INSERT INTO flow_sessions (flow_uuid) VALUES (UuidToBin(:flow_uuid))";
            $statement = DatabaseConnection::getPdo()->prepare($sql);
            $statement->execute($bindVariables);
            $this->sessionUuid = $sessionUuid;
            $this->sessionData = [
                "chain" => []
            ];
        } else {
            $bindVariables = [
                "flow_uuid" => $sessionUuid,
            ];
            $sql = "SELECT flow_data FROM flow_sessions WHERE flow_uuid=UuidToBin(:flow_uuid)";
            $statement = DatabaseConnection::getPdo()->prepare($sql);
            $statement->execute($bindVariables);
            $sessionInfo = $statement->fetch();
            if ($sessionInfo != null) {
                $this->sessionUuid = $sessionUuid;
                $this->sessionData = json_decode($sessionInfo["flow_data"], true);
            }
        }
    }
    
    public function getUUID() {
        return $this->sessionUuid;
    }
    
    public static function getCurrent() {
        if (self::$current == null) {
            $jwtToUse = null;
            if (isset($_COOKIE["flow_jwt"])) {
                $rootJwt = new \indent_one\JWT($_COOKIE["flow_jwt"]);
                if ($rootJwt->isValidForRecipient(SERVER_FQDN) && $rootJwt->isValidForPurpose("FLOW")) {
                    $jwtToUse = $rootJwt;
                }
            } elseif (isset($_GET["flow_jwt"])) {
                $authJwt = new \indent_one\JWT($_GET["flow_jwt"]);
                if ($authJwt->isValidForRecipient(SERVER_FQDN) && $authJwt->isValidForPurpose("FLOW")) {
                    $jwtToUse = $authJwt;
                }
            }
            if ($jwtToUse != null) {
                $bindVariables = [
                    "flow_uuid" => $jwtToUse->getClaim("sid"),
                ];
                $sql = "SELECT 1 FROM flow_sessions WHERE flow_uuid=UuidToBin(:flow_uuid)";
                $statement = DatabaseConnection::getPdo()->prepare($sql);
                $statement->execute($bindVariables);
                $sessionInfo = $statement->fetch();
                if ($sessionInfo != null) { // This is a valid session
                    self::$current = new FlowSession($jwtToUse->getClaim("sid"));
                }
            }
        }
        
        return self::$current;
    }
    
    private function saveData() {
        $bindVariables = [
            "flow_uuid" => $this->sessionUuid,
            "flow_data" => json_encode($this->sessionData)
        ];
        $sql = "UPDATE flow_sessions SET flow_data = :flow_data WHERE flow_uuid = UuidToBin(:flow_uuid)";
        $statement = DatabaseConnection::getPdo()->prepare($sql);
        $statement->execute($bindVariables);
    }
    
    public function authReturnJWTAsGetParameter() {
        $this->sessionData["auth_return"] = "JWT_GET_PARAMETER";
        $this->saveData();
    }
    
    public function getAuthReturnType() {
        return $this->sessionData["auth_return"];
    }
    
    public function prependToChain($url) {
        array_unshift($this->sessionData["chain"], $url);
        $this->saveData();
    }
    
    public function appendToChain($url) {
        array_push($this->sessionData["chain"], $url);
        $this->saveData();
    }
    
    public function popFromChain() {
        return array_shift($this->sessionData["chain"]);
        $this->saveData();
    }
}
