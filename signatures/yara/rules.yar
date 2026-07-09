rule php_webshell { strings: $a = "eval(" $b = "system(" condition: any of them }
