"""Generate manual Google search queries without automating Google requests."""

from urllib.parse import quote_plus


class GoogleDorker:
    TEMPLATES = {
        "Sensitive files": [
            "site:{domain} ext:env", "site:{domain} ext:log",
            "site:{domain} ext:sql", "site:{domain} ext:bak",
            "site:{domain} ext:config", "site:{domain} filetype:xml inurl:config",
            "site:{domain} filetype:json inurl:config",
        ],
        "Login and admin panels": [
            "site:{domain} inurl:admin", "site:{domain} inurl:login",
            "site:{domain} inurl:dashboard", "site:{domain} inurl:portal",
            'site:{domain} intitle:"admin panel"',
        ],
        "API and endpoints": [
            "site:{domain} inurl:api", "site:{domain} inurl:swagger",
            "site:{domain} inurl:graphql", "site:{domain} inurl:v1 OR inurl:v2",
        ],
        "Exposed credentials": [
            'site:{domain} intext:"password" filetype:log',
            'site:{domain} intext:"api_key" filetype:json',
            'site:{domain} "Index of" inurl:backup',
        ],
        "Error pages": [
            'site:{domain} intext:"SQL syntax"',
            'site:{domain} intext:"Warning: mysql"',
            'site:{domain} intext:"Fatal error"',
            'site:{domain} intext:"stack trace"',
        ],
        "GitHub exposure": [
            "site:github.com {domain}", 'site:github.com "{domain}" password',
            'site:github.com "{domain}" api_key',
            'site:github.com "{domain}" secret',
        ],
        "Code sharing": [
            'site:pastebin.com "{domain}"', 'site:trello.com "{domain}"',
        ],
    }

    def generate_dorks(self, domain):
        domain = str(domain).split("://")[-1].split("/")[0].split(":")[0]
        return {
            category: [
                {
                    "query": template.format(domain=domain),
                    "url": (
                        "https://www.google.com/search?q="
                        + quote_plus(template.format(domain=domain))
                    ),
                }
                for template in templates
            ]
            for category, templates in self.TEMPLATES.items()
        }
