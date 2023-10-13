<?php
namespace indent_one;

class APIFactory {
    private static $currentUser = null;
    private $apiVariables;
    private $returnData;

    public function __construct() {
        $returnData = [
            "response_code" => http_response_code()
        ];
    }
    
    public function isInIpRange($range, $ip) {
        list($range, $netmask) = explode('/', $range, 2);
        $rangeDecimal = ip2long($range);
        $ipDecimal = ip2long($ip);
        $wildcardDecimal = pow(2, (32 - $netmask)) - 1;
        $netmaskDecimal = ~$wildcardDecimal;
        if (($ipDecimal & $netmaskDecimal) == ($rangeDecimal & $netmaskDecimal)) {
            return true;
        } else {
            return false;
        }
    }
    
    public function requireIpRange(array $ipRanges) {
        $internalAPIConnection = false;
        foreach ($ipRanges as &$range) {
            if ($this->isInIpRange($range, $_SERVER["REMOTE_ADDR"])) {
                $internalAPIConnection = true;
            }
        }
        
        if (!$internalAPIConnection) {
            header("Content-Type: application/json; charset=utf-8");
            http_response_code(401);
            $returnData = [
                "status" => "UNAUTHORIZED",
                "error_message" => "This API is for internal use only. Check client ip range.",
                "response_code" => 401
            ];
            echo json_encode($returnData, JSON_PRETTY_PRINT);
            echo "\n";
            exit();
        }
        
        return $this;
    }
    
    public function isInInternalIpRange($ip) {
        if ($this->isInIpRange("10.8.0.0/16", $ip) || $this->isInIpRange("127.0.0.0/8", $ip)) {
            return true;
        } else {
            return false;
        }
    }
    
    public function requireInternalIpRange() {
        $this->requireIpRange(["10.8.0.0/16", "127.0.0.0/8"]);
        return $this;
    }

    public function requireInternalApiKey() {
        $internalAPIConnection = false;
        
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            if (str_starts_with($_SERVER['HTTP_AUTHORIZATION'], "Digest ")) {
                $authDigest = substr($_SERVER['HTTP_AUTHORIZATION'], strlen("Digest "));
                if ($authDigest == hash("sha256", INSTANCE_CREDENTIAL_LOCAL_ONLY_API_KEY)) {
                    $internalAPIConnection = true;
                }
            }
        }

        if (!$internalAPIConnection) {
            header("Content-Type: application/json; charset=utf-8");
            http_response_code(401);
            $returnData = [
                "status" => "UNAUTHORIZED",
                "error_message" => "This API is for internal use only. Check bearer token.",
                "response_code" => 401
            ];
            echo json_encode($returnData, JSON_PRETTY_PRINT);
            echo "\n";
            exit();
        }
        
        return $this;
    }
    
    public function setVariable($key, $value = null) {
        $this->returnData[$key] = $value;
        return $this;
    }
    
    public function getVariable($key) {
        return $this->returnData[$key];
    }
    
    public function setStatus($value) {
        $this->setVariable("status", $value);
        return $this;
    }
    
    public function setErrorText($value) {
        $this->setVariable("error_message", $value);
        if (http_response_code() == 200) {
            http_response_code(400);
        }
        return $this;
    }
    
    public function setResponseCode($responseCode = 200) {
        http_response_code($responseCode);
        return $this;
    }
    
    public static function getUser() {
        if (self::$currentUser == null) {
            $jwtToUse = null;
            $bearerToken = false;
            if (isset($_COOKIE["root_jwt"])) {
                $rootJwt = new \indent_one\JWT($_COOKIE["root_jwt"]);
                if ($rootJwt->isValidForRecipient(SERVER_FQDN) && $rootJwt->isValidForPurpose("ROOT_TRUST")) {
                    $jwtToUse = $rootJwt;
                }
            } elseif (get_bearer_token() != null) {
                $authJwt = new \indent_one\JWT(get_bearer_token());
                $bearerToken = true;
                if ($authJwt->isValidForRecipient(SERVER_FQDN) || $authJwt->isValidForRecipient($_SERVER["SERVER_NAME"])) {
                    if ($authJwt->isValidForPurpose("SERVICE_AUTH") || $authJwt->isValidForPurpose("ROOT_TRUST")) {
                        $jwtToUse = $authJwt;
                    } elseif ($authJwt->isValidForPurpose("API_AUTH")) {
                        $jwtToUse = $authJwt;
                        self::$currentUser = new User($jwtToUse->getClaim("sub"));
                        return self::$currentUser;
                    }
                }
            } elseif (isset($_COOKIE["indent_one_jwt"])) {
                $authJwt = new \indent_one\JWT($_COOKIE["indent_one_jwt"]);
                if (($authJwt->isValidForRecipient(SERVER_FQDN) || $authJwt->isValidForRecipient($_SERVER["SERVER_NAME"])) && $authJwt->isValidForPurpose("SERVICE_AUTH")) {
                    $jwtToUse = $authJwt;
                }
            }
            if ($jwtToUse == null) {
                if ($bearerToken) {
                    header("Content-Type: application/json; charset=utf-8");
                    http_response_code(400);
                    $returnData = [
                        "status" => "INVALID_BEARER_TOKEN",
                        "error_message" => "The token supplied is not valid for this endpoint or purpose.",
                        "response_code" => 400
                    ];
                    echo json_encode($returnData, JSON_PRETTY_PRINT);
                    echo "\n";
                    exit();
                }
            } else {
                $bindVariables = [
                    "session_uuid" => $jwtToUse->getClaim("sid"),
                ];
                $sql = "SELECT 1 FROM sessions WHERE session_uuid=UuidToBin(:session_uuid) AND active=1";
                $statement = DatabaseConnection::getPdo()->prepare($sql);
                $statement->execute($bindVariables);
                $sessionInfo = $statement->fetch();
                if ($sessionInfo != null) { // This is a valid and active session
                    $session = new Session($jwtToUse->getClaim("sid"));
                    self::$currentUser = $session->getUser();
                } else {
                    header("Content-Type: application/json; charset=utf-8");
                    http_response_code(400);
                    $returnData = [
                        "status" => "EXPIRED_SESSION",
                        "error_message" => "You provided a valid JWT, but it relates to an expired session. Please try again after obtaining a fresh token.",
                        "response_code" => 400
                    ];
                    echo json_encode($returnData, JSON_PRETTY_PRINT);
                    echo "\n";
                    exit();
                }
            }
        }
        
        return self::$currentUser;
    }
    
    public function requireMembershipOfAnyGroup(array $groups) {
        $isGroupMember = false;
        
        $user = $this->getUser();
        
        if ($user != null) {
            foreach ($groups as &$group) {
                switch ($group) {
                    case "POWER_SENSOR_VIEWERS":
                        switch ($user->getUUID()) {
                            case "872be8f8-77c1-49d2-8e27-f0d533d7c74e":
                            case "868ad59c-df46-445c-b4da-0bbcfeb105e3":
                            case "d1fe741b-0741-4614-9983-2ef35518527b":
                                $isGroupMember = true;
                                break;
                        }
                        break;
                }
            }
        } else {
            header("Content-Type: application/json; charset=utf-8");
            http_response_code(401);
            $returnData = [
                "status" => "UNAUTHORIZED",
                "error_message" => "You need to be logged in to access this resource.",
                "response_code" => 401
            ];
            echo json_encode($returnData, JSON_PRETTY_PRINT);
            echo "\n";
            exit();
        }

        if (!$isGroupMember) {
            header("Content-Type: application/json; charset=utf-8");
            http_response_code(403);
            $returnData = [
                "status" => "FORBIDDEN",
                "error_message" => "This API is for members of the following groups only: ".implode(", ", $groups).".",
                "response_code" => 403
            ];
            echo json_encode($returnData, JSON_PRETTY_PRINT);
            echo "\n";
            exit();
        }
        
        return $this;
    }
    
    public function requireGroupMembership($groupName) {
        $this->requireMembershipOfAnyGroup([$groupName]);
        return $this;
    }
    
    public function output() {
        header("Content-Type: application/json; charset=utf-8");
        $this->returnData["response_code"] = http_response_code();
        if (!isset($this->returnData["status"])) {
            if (http_response_code() == 200) {
                $this->returnData["status"] = "OK";
            } else {
                $this->returnData["status"] = "ERROR";
            }
        }
        echo json_encode($this->returnData, JSON_PRETTY_PRINT);
        echo "\n";
        exit();
    }
}
?>
