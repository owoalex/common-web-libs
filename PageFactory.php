<?php
namespace indent_one;

class PageFactory {
    private $twigVariables;
    private $template = "base.twig.html";
    private $domain = "www.indent.one";
    private $cookiesRequired = false;
    private $loginRequired = false;
    private $cookieConsent = false;

    public function __construct() {
        $this->twigVariables = [];
        
        if (isset($_COOKIE["cookieConsent"])) {
            if ($_COOKIE["cookieConsent"] == "true") {
                $this->twigVariables["cookieConsent"] = true;
                $this->cookieConsent = true;
            }
        }

        // Grab style options if present
        $this->twigVariables["headAssetOptions"] = [];
        if(isset($_COOKIE["style"])) {
            if(isset($_COOKIE["style"])) {
                $this->twigVariables["headAssetOptions"] = explode(" ", $_COOKIE["style"]);
            }
        }
        
        $this->twigVariables["currentSession"] = Session::getCurrent();
        
        return $this;
    }
    
    public function requireCookieConsent() {
        $cookiesRequired = true;
        return $this;
    }
    
    public function requireLogin() {
        if (DataManager::getInstance()->sessionAuthenticated()) {
            header("Location: /login");
            exit();
        }
        
        return $this;
    }
    
    public function addResourceFlag($resource) {
        array_push($this->twigVariables["headAssetOptions"], $resource);
        
        return $this;
    }
    
    public function setDomain($domain) {
        $this->domain = $domain;
        return $this;
    }
    
    public function setTemplate($template) {
        $this->template = $template.".twig.html";
        return $this;
    }
    
    public function setVariable($key, $value = null) {
        $this->twigVariables[$key] = $value;
        return $this;
    }
    
    public function getVariable($key) {
        return $this->twigVariables[$key];
    }
    
    public function render() {
        $domainPieces = explode(".", $this->domain);
        $reversedDomain = array_reverse($domainPieces);
        
        $twigLoader = new \Twig\Loader\FilesystemLoader(WEB_ROOT_DIRECTORY."templates");
        $twig = new \Twig\Environment($twigLoader, [
            "cache" => false,
        ]);
        $this->twigVariables["currentUri"] = $_SERVER["REQUEST_URI"];
        $session = Session::getCurrent();
        if ($session != null) {
            $this->twigVariables["session"] = $session;
            $this->twigVariables["user"] = $session->getUser();
        }
        
        if ($this->cookiesRequired && (!$this->cookieConsent)) {
            $this->setTemplate("cookie-consent-required");
            echo $twig->render($this->template, $this->twigVariables);
            exit();
        }
        
        echo $twig->render(implode("/", $reversedDomain)."/".$this->template, $this->twigVariables);
        exit();
    }
}
?>
