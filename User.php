<?php
namespace indent_one;

class User implements PersistentObject {
    private $userUuid = null;
    private $displayName = null;
    private $username = null;
    
    public function __construct($userUuid) {
        if ($userUuid != null) {
            $bindVariables = [
                "user_uuid" => $userUuid,
            ];
            $sql = "SELECT display_name, username FROM users WHERE user_uuid=UuidToBin(:user_uuid)";
            $statement = DatabaseConnection::getPdo()->prepare($sql);
            $statement->execute($bindVariables);
            $userInfo = $statement->fetch();
            if ($userInfo != null) { // This is a valid user, this part DOES NOT CHECK for validity to allow fringe use cases for viewing expired user info
                $this->userUuid = $userUuid;
                $this->username = $userInfo["username"];
                if ($userInfo["display_name"] != null) {
                    $this->displayName = $userInfo["display_name"];
                } else {
                    $this->displayName = $this->username;
                }
            }
        }
    }
    
    public function getUUID() {
        return $this->userUuid;
    }
    
    public function getDisplayName() {
        if ($this->displayName == null) {
            return $this->username;
        } else {
            return $this->displayName;
        }
    }
    
    public function getUsername() {
        return $this->username;
    }
    
    public function __toString() {
        return $this->getDisplayName();
    }
}
