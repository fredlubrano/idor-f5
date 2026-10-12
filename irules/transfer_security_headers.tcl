when HTTP_REQUEST {
    # Réponses non compressées → scrub body fiable (DutchCoders / Modernizr / style)
    HTTP::header remove "Accept-Encoding"
}

when HTTP_RESPONSE {
    # -----------------------------------------------------------
    # 1. En-têtes applicatifs à masquer (DutchCoders / transfer.sh)
    # -----------------------------------------------------------
    HTTP::header remove "x-made-with"
    HTTP::header remove "x-served-by"
    HTTP::header remove "Date"
    HTTP::header remove "Vary"

    # -----------------------------------------------------------
    # 2. Durcissement de sécurité
    # -----------------------------------------------------------
    HTTP::header replace "X-Content-Type-Options" "nosniff"
    HTTP::header replace "X-Frame-Options" "DENY"
    HTTP::header replace "Referrer-Policy" "strict-origin-when-cross-origin"
    HTTP::header replace "Permissions-Policy" "geolocation=(), microphone=(), camera=(), payment=(), usb=()"

    # CSP stricte : pas de 'unsafe-inline' / 'unsafe-hashes'
    HTTP::header replace "Content-Security-Policy" "default-src 'self'; script-src 'self' 'sha256-3qH+JY15Ew+W7CqUisNrjpZWEDGiTQPeG/iXpkWSWVI='; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

    # -----------------------------------------------------------
    # 3. Collecte body texte — forcer Content-Length (évite fuite chunk TE)
    # -----------------------------------------------------------
    set ctype [string tolower [HTTP::header value "Content-Type"]]
    if { ($ctype starts_with "text/plain") || ($ctype starts_with "text/html") } {
        # Réponses chunked : retirer TE avant collect, sinon marqueurs hex dans le HTML
        if { [HTTP::header exists "Transfer-Encoding"] } {
            HTTP::header remove "Transfer-Encoding"
        }
        if { [HTTP::header exists "Content-Length"] } {
            set cl [HTTP::header value "Content-Length"]
            if { [string is integer -strict $cl] && $cl > 0 && $cl <= 512000 } {
                HTTP::collect $cl
            }
        } else {
            HTTP::collect 512000
        }
    }
}

when HTTP_RESPONSE_DATA {
    set payload [HTTP::payload]
    set new $payload

    # Fingerprint / Modernizr / attribut style (peut être sur une autre ligne)
    set new [string map {
        "made with <3 by DutchCoders\r\n" ""
        "made with <3 by DutchCoders\n" ""
        "made with <3 by DutchCoders" ""
        "DutchCoders" ""
        "dutchcoders" ""
        "<script src=\"scripts/vendor/modernizr.js\"></script>\r\n" ""
        "<script src=\"scripts/vendor/modernizr.js\"></script>\n" ""
        "<script src=\"scripts/vendor/modernizr.js\"></script>" ""
        "class=\"no-js\"" "class=\"js\""
    } $new]

    # File input : style= → hidden (tolère \n / \r\n / espace)
    regsub -all {<input type="file" multiple="multiple"[^>]*>} $new \
        {<input type="file" multiple="multiple" hidden />} new

    # Filet de sécurité : marqueurs chunk TE accidentels (ex. \r\n800\r\n)
    regsub -all {\r\n[0-9a-fA-F]+\r\n} $new {} new

    if { $new ne $payload } {
        HTTP::payload replace 0 [HTTP::payload length] $new
        HTTP::header remove "Transfer-Encoding"
        HTTP::header replace "Content-Length" [string length $new]
    }
}
