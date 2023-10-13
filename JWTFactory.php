<?php
namespace indent_one;

class JWTFactory {
    private $jwk;
    private $jwtHeader;
    private $jwtPayload;
    private $jwtSignature;
    private $tokenLifetime = 3600 * 24 * 7; // one week lifetime is standard

    public function __construct() {
        $this->jwk = json_decode(file_get_contents(CREDENTIAL_JWK_PRIVATE_KEY_STORE.CREDENTIAL_PRIMARY_JWT_SIGNING_JWK_ID.".json"), true);
        $this->jwtHeader = [
            "typ"   => "JWT",
            "kid"   => CREDENTIAL_PRIMARY_JWT_SIGNING_JWK_ID,
            "alg"   => "EdDSA"
        ];
        $this->jwtPayload = [
            "iss"   => CREDENTIAL_JWK_ISSUER,
            "aud"   => []
        ];
    }
    
    public function addRecipient($recipient) {
        array_push($this->jwtPayload["aud"], $recipient);
        return $this;
    }
    
    public function setClaim($claim, $value) {
        $this->jwtPayload[$claim] = $value;
        return $this;
    }
    
    public function setSession(PersistentObject $session) {
        $this->jwtPayload["sid"] = $session->getUUID();
        return $this;
    }
    
    public function setSessionUUID(string $sessionUUID) {
        $this->jwtPayload["sid"] = $sessionUUID;
        return $this;
    }
    
    public function setCredentialHolder(User $holder) {
        $this->jwtPayload["sub"] = $holder->getUUID();
        return $this;
    }
    
    // Must be FLOW|ROOT_AUTH|SERVICE_AUTH
    // FLOW = Temporary jwt for redirecting user along the correct chain of pages
    // ONE_TIME_ACCESS = One off jwt allowing a 3rd party to obtain a SERVICE_AUTH JWT
    // ROOT_TRUST = Used for auth on indent-one and generating SERVICE_AUTH JWTs
    // SERVICE_AUTH = Used for auth on third party services, without the ability to be used on other services
    public function setPurpose($purpose) {
        $this->jwtPayload["prp"] = $purpose;
        return $this;
    }
    
    // Set to -1 to make it everlasting
    public function setLifetime($seconds) {
        $this->tokenLifetime = $seconds;
        return $this;
    }
    
    public function build() {
        if ($this->tokenLifetime >= 0) {
            $this->jwtPayload["exp"] = time() + $this->tokenLifetime;
        }
        $this->jwtPayload["iat"] = time();
        $this->jwtPayload["jti"] = new_random_uuid();
        $this->jwtPayload["nbf"] = time() - 120; // Allow for about two minutes of clock drift
        $this->jwtHeader = json_encode($this->jwtHeader);
        $this->jwtPayload = json_encode($this->jwtPayload);
        $headerPayloadCombination = base64_encode_url_safe($this->jwtHeader).".".base64_encode_url_safe($this->jwtPayload);
        $this->jwtSignature = sodium_crypto_sign_detached($headerPayloadCombination, base64_decode_url_safe($this->jwk["d"]));
        return new JWT($headerPayloadCombination.".".base64_encode_url_safe($this->jwtSignature));
    }
}
?>
