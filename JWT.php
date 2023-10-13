<?php
namespace indent_one;

class JWT {
    private $stringRepresentation = null;
    private $jwk;
    private $jwtHeader;
    private $jwtPayload;
    private $jwtSignature;
    private $jwtSignatureVerified = false;
    private $jwtDecoded = false;
    
    public function __construct($stringRepresentation) {
        $this->stringRepresentation = $stringRepresentation;
    }
    
    public function isValid() {
        if ($this->jwtDecoded) {
            return $this->jwtSignatureVerified;
        } else {
            $jwtComponents = explode(".", $this->stringRepresentation);
            if (count($jwtComponents) != 3) { return false; } // If the JWT is properly malformed just exit now
            $this->jwtHeader = json_decode(base64_decode_url_safe($jwtComponents[0]), true);
            $this->jwtPayload = json_decode(base64_decode_url_safe($jwtComponents[1]), true);
            if ($this->jwtHeader["alg"] != "EdDSA") { return false; } // We only bother to verify keys using modern crypto
            if (isset($this->jwtPayload["exp"])) {
                if ($this->jwtPayload["exp"] < time()) { return false; } // This JWT has expired already
            }
            if (isset($this->jwtPayload["nbf"])) {
                if ($this->jwtPayload["nbf"] > time()) { return false; } // This JWT is from the future???
            }
            $this->jwtSignature = base64_decode_url_safe($jwtComponents[2]);
            if (strlen($this->jwtSignature) != SODIUM_CRYPTO_SIGN_BYTES) { return false; } // Signature size is wrong!
            $jwkUUID = $this->jwtHeader["kid"];
            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $jwkUUID)) { return false; } // This key id contains special chars!
            $this->jwk = json_decode(file_get_contents(CREDENTIAL_JWK_PUBLIC_KEY_STORE.$jwkUUID.".json"), true);
            
            $this->jwtSignatureVerified = sodium_crypto_sign_verify_detached($this->jwtSignature, $jwtComponents[0].".".$jwtComponents[1], base64_decode_url_safe($this->jwk["x"]));
            $this->jwtDecoded = true;
            return $this->jwtSignatureVerified;
        }
    }
    
    public function isValidForPurpose($purpose) {
        if (!$this->isValid()) {
            return false;
        }
        if (!isset($this->jwtPayload["prp"])) {
            return false;
        }
        return ($purpose == $this->jwtPayload["prp"]);
    }
    
    public function isValidForRecipient($fqdn) {
        if (!$this->isValid()) {
            return false;
        }
        if (!isset($this->jwtPayload["aud"])) {
            return false;
        }
        foreach ($this->jwtPayload["aud"] as &$recipient) {
            if ($recipient == $fqdn) {
                return true;
            }
        }
        return false;
    }
    
    public function getClaim($claim) {
        if (!$this->isValid()) {
            return null;
        }
        if (isset($this->jwtPayload[$claim])) {
            return $this->jwtPayload[$claim];
        } else {
            return null;
        }
    }
    
    public function getCredentialHolder() {
        if (!$this->isValid()) {
            return null;
        }
        if (isset($this->jwtPayload["sub"])) {
            return new User($this->jwtPayload["sub"]);
        } else {
            return null;
        }
    }
    
    public function getPurpose() {
        return $this->getClaim("prp");
    }
    
    public function getIssuer() {
        return $this->getClaim("iss");
    }
    
    public function getExpiryTime() {
        return $this->getClaim("exp");
    }
    
    public function getUUID() {
        return $this->getClaim("jti");
    }
    
    public function getRecipients() {
        return $this->getClaim("aud");
    }
    
    public function getSessionUUID() {
        return $this->getClaim("sid");
    }
    
    public function __toString() {
        return $this->stringRepresentation;
    }
}
?>
