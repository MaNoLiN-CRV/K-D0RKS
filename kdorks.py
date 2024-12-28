import requests
from urllib.parse import quote_plus
import time
from typing import List, Dict

class GoogleDorksAnalyzer:
    def __init__(self):
        
        self.vulnerability_dorks = [
            # SQL Injection
            'site:{domain} inurl:".php?id=" intext:"Warning: mysql_fetch_array()"',
            'site:{domain} inurl:".php?pid=" intext:"Warning: mysql_fetch_assoc()"',
            'site:{domain} inurl:".php?id=" intext:"You have an error in your SQL syntax"',
            'site:{domain} inurl:".asp?id=" intext:"Server Error in Application"',
            'site:{domain} inurl:proc/self/environ intext:"Fatal error"',
            'site:{domain} inurl:".php?suffix=" intext:"mysql_fetch_"',
            
            # XSS
            'site:{domain} inurl:search.php intext:"<script>"',
            'site:{domain} inurl:results.php intext:"<script>"',
            'site:{domain} inurl:display.php intext:"<script>"',
            'site:{domain} inurl:message.php intext:"<script>"',
            
            # Local File Inclusion
            'site:{domain} inurl:include_path intext:"Warning: include()"',
            'site:{domain} inurl:load_file intext:"Failed opening"',
            'site:{domain} inurl:directory intext:"Index of /" "Parent Directory"',
            'site:{domain} ext:php inurl:"../" intext:"Index of /" "parent directory"',
            
            # Remote File Inclusion
            'site:{domain} inurl:include.php?path=http',
            'site:{domain} inurl:load.php?file=http',
            'site:{domain} inurl:download.php?file=http',
            
            # Command Injection
            'site:{domain} inurl:cmd.php intext:"Command execution"',
            'site:{domain} inurl:exec.php intext:"shell_exec"',
            'site:{domain} inurl:shell.php intext:"system()"'
        ]

        self.sensitive_files_dorks = [
            # Contraseñas y credenciales
            'site:{domain} filetype:env "DB_PASSWORD"',
            'site:{domain} filetype:ini "mysql_password"',
            'site:{domain} filetype:properties "passwd"',
            'site:{domain} filetype:xml "password" "username"',
            'site:{domain} filetype:json "apiKey"',
            'site:{domain} filetype:yaml "secret_key"',
            
            # Archivos de configuración
            'site:{domain} filename:configuration.php',
            'site:{domain} filename:config.json',
            'site:{domain} filename:settings.py',
            'site:{domain} filename:database.yml',
            'site:{domain} ext:conf "password" "username" "database"',
            
            # Backups y logs
            'site:{domain} filetype:bak intext:password',
            'site:{domain} filetype:old intext:password',
            'site:{domain} filetype:backup intext:password',
            'site:{domain} filetype:log "authentication failed"',
            'site:{domain} ext:log "password incorrect"'
        ]

        self.api_endpoint_dorks = [
            # Swagger/OpenAPI
            'site:{domain} inurl:swagger-ui.html',
            'site:{domain} inurl:swagger/index.html',
            'site:{domain} filename:swagger.json',
            'site:{domain} filename:openapi.yaml',
            
            # GraphQL
            'site:{domain} inurl:graphql intext:"query"',
            'site:{domain} inurl:graphiql',
            'site:{domain} inurl:graphql/console',
            
            # API Keys y Tokens
            'site:{domain} inurl:api intext:"api_key"',
            'site:{domain} inurl:api intext:"bearer_token"',
            'site:{domain} inurl:api intext:"access_token"',
            
            # API Versioning
            'site:{domain} inurl:api/v1',
            'site:{domain} inurl:api/v2',
            'site:{domain} inurl:api/v3',
            'site:{domain} inurl:rest/api/',
            'site:{domain} inurl:api/swagger',
            
            # API Documentation
            'site:{domain} inurl:api-docs',
            'site:{domain} inurl:apidocs',
            'site:{domain} inurl:swagger-resources',
            'site:{domain} inurl:api/documentation'
        ]

  
        self.infrastructure_dorks = [

            'site:{domain} inurl:s3.amazonaws.com',
            'site:{domain} inurl:storage.googleapis.com',
            'site:{domain} inurl:azurewebsites.net',
            'site:{domain} inurl:blob.core.windows.net',
    
            'site:{domain} filename:dockerfile',
            'site:{domain} filename:docker-compose.yml',
            'site:{domain} intext:"docker run"',
            
            'site:{domain} filename:.gitlab-ci.yml',
            'site:{domain} filename:.travis.yml',
            'site:{domain} filename:jenkins',
            'site:{domain} filename:.github/workflows',
     
            'site:{domain} inurl:grafana',
            'site:{domain} inurl:kibana',
            'site:{domain} inurl:prometheus',
            'site:{domain} inurl:status intext:"server status"'
        ]

    
        self.code_leak_dorks = [
            # Git
            'site:{domain} inurl:.git',
            'site:{domain} inurl:.gitignore',
            'site:{domain} intext:"Index of /.git"',
            'site:{domain} filename:id_rsa',
            'site:{domain} filename:id_dsa',
            
            # Source Code
            'site:{domain} ext:java intext:"private class"',
            'site:{domain} ext:php intext:"define(\'DB_PASSWORD\'")',
            'site:{domain} ext:py intext:"def password"',
            'site:{domain} ext:rb intext:"def initialize"',
            
            # Development Files
            'site:{domain} ext:sql intext:"INSERT INTO users"',
            'site:{domain} filetype:config intext:"development"',
            'site:{domain} filetype:properties intext:"development"'
        ]

        self.admin_panel_dorks = [
            # Panels
            'site:{domain} inurl:admin intitle:"login"',
            'site:{domain} inurl:administrator intitle:"login"',
            'site:{domain} inurl:admin.php intitle:"admin login"',
            'site:{domain} inurl:wp-admin',
            'site:{domain} inurl:cpanel',
            'site:{domain} inurl:webmin',
            
            # Dashboards
            'site:{domain} inurl:dashboard intitle:"admin"',
            'site:{domain} inurl:control intitle:"control panel"',
            'site:{domain} inurl:manage intitle:"management"',
            
            # Portales específicos
            'site:{domain} inurl:phpmyadmin',
            'site:{domain} inurl:plesk',
            'site:{domain} inurl:virtualmin',
            'site:{domain} inurl:whm'
        ]

 
        self.exposed_services_dorks = [
    
            'site:{domain} intitle:"Apache2 Ubuntu Default Page"',
            'site:{domain} intitle:"IIS Windows Server"',
            'site:{domain} intitle:"nginx test page"',
  
            'site:{domain} intitle:"phpMyAdmin"',
            'site:{domain} intitle:"MongoDB Status"',
            'site:{domain} intitle:"Redis Status"',
 
            'site:{domain} intitle:"Roundcube Webmail"',
            'site:{domain} intitle:"WebMail"',
            'site:{domain} intitle:"Zimbra Web Client"'
        ]

        # Dorks para errores y debug
        self.error_debug_dorks = [
            # PHP Errors
            'site:{domain} "PHP Parse error"',
            'site:{domain} "PHP Warning"',
            'site:{domain} "PHP Notice"',
            'site:{domain} "Fatal error:"',
            
            # Database Errors
            'site:{domain} "MySQL Error"',
            'site:{domain} "PostgreSQL Error"',
            'site:{domain} "ORA-00001"',
            'site:{domain} "SQLSTATE["',
            
            # Framework Errors
            'site:{domain} "Laravel Error"',
            'site:{domain} "Django Error"',
            'site:{domain} "Rails Error"',
            'site:{domain} "ASP.NET Error"',
            
            # Debug Information
            'site:{domain} "Debug Information"',
            'site:{domain} "Development Mode"',
            'site:{domain} "Trace Information"',
            'site:{domain} "Stack Trace:"'
        ]
        self.vulnerability_dorks.extend([
            # XXE (XML External Entity)
            'site:{domain} filetype:xml intext:"<!ENTITY"',
            'site:{domain} filetype:xml intext:"<!DOCTYPE"',
            'site:{domain} ext:xml intext:"SYSTEM"',
            
            # SSRF (Server-Side Request Forgery)
            'site:{domain} inurl:url= intext:"http"',
            'site:{domain} inurl:proxy= intext:"http"',
            'site:{domain} inurl:redirect= intext:"http"',
            'site:{domain} inurl:return= intext:"http"',
            
            # Open Redirect
            'site:{domain} inurl:return_url=http',
            'site:{domain} inurl:redirect_uri=http',
            'site:{domain} inurl:redirect_url=http',
            'site:{domain} inurl:returnUrl=http',
            
            # IDOR (Insecure Direct Object References)
            'site:{domain} inurl:user_id=',
            'site:{domain} inurl:account_id=',
            'site:{domain} inurl:order_id=',
            'site:{domain} inurl:id= intext:"profile"',
            
            # RCE (Remote Code Execution)
            'site:{domain} ext:php inurl:eval',
            'site:{domain} ext:jsp intext:"Runtime.getRuntime().exec"',
            'site:{domain} ext:asp intext:"Response.Write(Request"',
            
            # Path Traversal
            'site:{domain} inurl:file= intext:"../"',
            'site:{domain} inurl:path= intext:"../"',
            'site:{domain} inurl:folder= intext:"../"'
        ])


        self.devops_dorks = [
            # Jenkins
            'site:{domain} intext:"Jenkins" intitle:"Dashboard"',
            'site:{domain} inurl:jenkins/job/',
            'site:{domain} intext:"Jenkins ver." intitle:"Log In"',
            
            # GitLab
            'site:{domain} inurl:gitlab intext:"Sign in"',
            'site:{domain} intext:"GitLab" "Projects" "Groups"',
            'site:{domain} filename:.gitlab-ci.yml',
            
            # GitHub Actions
            'site:{domain} filename:workflow.yml path:.github/workflows',
            'site:{domain} filename:dependabot.yml',
            'site:{domain} filename:codeql-analysis.yml',
            
            # Kubernetes
            'site:{domain} filename:kubeconfig',
            'site:{domain} ext:yaml intext:"kind: Deployment"',
            'site:{domain} ext:yaml intext:"kind: Service"',
            
            # Docker
            'site:{domain} filename:docker-compose.yml',
            'site:{domain} ext:env intext:"DOCKER_"',
            'site:{domain} intext:"docker run" ext:txt | ext:log',
            
            # Terraform
            'site:{domain} ext:tf filename:main',
            'site:{domain} ext:tfvars',
            'site:{domain} filename:terraform.tfstate'
        ]

        # Nueva categoría: Cloud Services
        self.cloud_services_dorks = [
            # AWS
            'site:{domain} filetype:txt "aws_access_key_id"',
            'site:{domain} filetype:env "AWS_SECRET_ACCESS_KEY"',
            'site:{domain} ext:yml "aws_access_key"',
            'site:{domain} inurl:s3.amazonaws.com',
            'site:{domain} intext:"aws_secret_key"',
            
            # Azure
            'site:{domain} ext:config "ConnectionString" "Azure"',
            'site:{domain} filetype:xml "azure storage account"',
            'site:{domain} intext:"Azure Blob Storage" ext:config',
            'site:{domain} intext:"azure_tenant" ext:env',
            
            # Google Cloud
            'site:{domain} "google_application_credentials" ext:env',
            'site:{domain} "type: service_account" ext:json',
            'site:{domain} intext:"gcloud auth" ext:log',
            'site:{domain} ext:json "project_id" "private_key"'
        ]

        self.microservices_dorks = [
            # Service Discovery
            'site:{domain} intext:"eureka.client" ext:properties',
            'site:{domain} intext:"consul" "service" ext:json',
            'site:{domain} ext:yml "spring.application.name"',
            
            # Configuration
            'site:{domain} ext:properties "spring.config.import"',
            'site:{domain} filename:application.yml',
            'site:{domain} ext:env "SERVICE_"',
            
            # Service Mesh
            'site:{domain} ext:yaml "istio"',
            'site:{domain} ext:yaml "envoy"',
            'site:{domain} filename:linkerd.yml'
        ]

        self.monitoring_dorks = [
            # ELK Stack
            'site:{domain} intext:"elasticsearch" ext:conf',
            'site:{domain} intext:"logstash" ext:conf',
            'site:{domain} intext:"kibana" "server.host"',
            
            # Prometheus
            'site:{domain} filename:prometheus.yml',
            'site:{domain} ext:rules "alert"',
            'site:{domain} intext:"alertmanager" ext:yml',
            
            # Grafana
            'site:{domain} intext:"grafana" "api_key"',
            'site:{domain} filename:grafana.ini',
            'site:{domain} inurl:grafana/dashboard'
        ]

   
        self.auth_dorks = [
            # OAuth y JWT
            'site:{domain} ext:conf "oauth.client.secret"',
            'site:{domain} ext:conf "jwt.secret"',
            'site:{domain} intext:"client_secret" ext:json',
            
            # SAML
            'site:{domain} ext:xml "EntityDescriptor"',
            'site:{domain} filetype:xml "SAMLResponse"',
            'site:{domain} intext:"saml.signing" ext:properties',
            
            # Auth0
            'site:{domain} ext:json "auth0.client"',
            'site:{domain} intext:"AUTH0_CLIENT_SECRET"',
            'site:{domain} ext:env "AUTH0_"'
        ]


        self.web_security_dorks = [
     
            'site:{domain} ext:conf "ModSecurity"',
            'site:{domain} ext:conf "X-Frame-Options"',
            'site:{domain} ext:conf "Content-Security-Policy"',
            
            # SSL/TLS
            'site:{domain} ext:conf "ssl_certificate"',
            'site:{domain} ext:key "PRIVATE KEY"',
            'site:{domain} ext:crt',

            'site:{domain} filetype:conf "security headers"',
            'site:{domain} ext:conf "Strict-Transport-Security"',
            'site:{domain} ext:conf "X-Content-Type-Options"'
        ]

        self.testing_dorks = [
            # Test Environments
            'site:{domain} inurl:test intext:"login"',
            'site:{domain} inurl:staging intext:"admin"',
            'site:{domain} inurl:dev intext:"password"',
            
            # Test Data
            'site:{domain} ext:sql "test_data"',
            'site:{domain} filetype:csv "test"',
            'site:{domain} ext:json "test_credentials"',
            
            # Test Configuration
            'site:{domain} ext:conf "test.host"',
            'site:{domain} ext:properties "test.database"',
            'site:{domain} ext:yml "test:"'
        ]

    def generate_dork_urls(self, domain: str) -> Dict[str, List[str]]:
        base_url = "https://www.google.com/search?q="
        dork_urls = {
            "vulnerability": [],
            "sensitive_files": [],
            "api_endpoint": [],
            "infrastructure": [],
            "code_leak": [],
            "admin_panel": [],
            "exposed_services": [],
            "error_debug": [],
            "devops": [],
            "cloud_services": [],
            "microservices": [],
            "monitoring": [],
            "auth": [],
            "web_security": [],
            "testing": []
        }

        def process_dorks(dork_list: List[str], category: str):
            for dork in dork_list:
                formatted_dork = dork.format(domain=domain)
                search_url = base_url + quote_plus(formatted_dork)
                dork_urls[category].append({
                    "dork": formatted_dork,
                    "url": search_url
                })

    
        for category, dork_list in self.__dict__.items():
            if category.endswith('_dorks'):
                category_name = category.replace('_dorks', '')
                process_dorks(dork_list, category_name)

        return dork_urls

    def analyze_domain(self, domain: str) -> Dict[str, List[Dict]]:
        print(f"\n[+] Starting dorks generator: {domain}")
        print("[+] D0RK1NG.... ")
        results = self.generate_dork_urls(domain)
        return results

def main():
    analyzer = GoogleDorksAnalyzer()
    print("""



██╗  ██╗     ██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗
██║ ██╔╝     ██╔══██╗██╔═████╗██╔══██╗██║ ██╔╝██╔════╝
█████╔╝█████╗██║  ██║██║██╔██║██████╔╝█████╔╝ ███████╗
██╔═██╗╚════╝██║  ██║████╔╝██║██╔══██╗██╔═██╗ ╚════██║
██║  ██╗     ██████╔╝╚██████╔╝██║  ██║██║  ██╗███████║
╚═╝  ╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

v1.0 By Manolin                  Google Dork Generator
    """)
    domain = input("\n Target domain --> ")
    
    results = analyzer.analyze_domain(domain)
    

    for category, dorks in results.items():
        print(f"\n=== {category.upper()} ===")
        print(f"Total dorks found: {len(dorks)}")
        for dork in dorks:
            print(f"\nDork: {dork['dork']}")
            print(f"URL : {dork['url']}")
            time.sleep(0.2)  

if __name__ == "__main__":
    main()