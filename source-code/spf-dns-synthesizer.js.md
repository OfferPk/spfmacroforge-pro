/\*\*  
 \* SPFMacroForge Pro \- Multi-Provider DNS Synthesizer  
 \* Generates production-ready SPF DNS records & dynamic macro responders for:  
 \* 1\. Cloudflare DNS & Cloudflare Worker Dynamic Macro Handler  
 \* 2\. AWS Route 53 ChangeBatch JSON  
 \* 3\. BIND 9 Zonefile  
 \* 4\. Terraform HCL (Cloudflare & AWS Route 53\)  
 \* 5\. CoreDNS / PowerDNS Dynamic Plugin Config  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.SPFDNSSynthesizer \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const SPFDNSSynthesizer \= {  
    /\*\*  
     \* Cloudflare DNS & Cloudflare Worker Dynamic Macro Handler  
     \*/  
    generateCloudflare(config) {  
      const domain \= (config.domain || 'example.com').replace(/^\\\*\\./, '');  
      const spf \= config.spfRecord || \`v=spf1 include:\_spf.google.com exists:%{i}.\_spf.\${domain} \-all\`;

      return \`\# \==========================================  
\# 1\. Cloudflare DNS TXT Record  
\# Domain: \${domain}  
\# \==========================================  
\# Type: TXT  
\# Name: @  
\# Content: "\${spf}"  
\# TTL: Auto (or 3600\)

\# \==========================================  
\# 2\. Cloudflare Worker Dynamic Macro Handler  
\# Route: \*.\_spf.\${domain}/\*  
\# Responds with 127.0.0.2 if connecting IP is authorized  
\# \==========================================  
export default {  
  async fetch(request, env, ctx) {  
    const url \= new URL(request.url);  
    const hostname \= url.hostname; // e.g. 198.51.100.42.\_spf.\${domain}  
    const ipMatch \= hostname.match(/^(\[0-9.\]+)\\\\.\_spf\\\\.\${domain}\$/);

    if (\!ipMatch) {  
      return new Response("NXDOMAIN", { status: 404 });  
    }

    const clientIp \= ipMatch\[1\];  
      
    // Authorized IP CIDR prefixes (Google, Salesforce, Zendesk, In-House MTAs)  
    const AUTHORIZED\_PREFIXES \= \[  
      "198.51.100.", // In-house datacenter  
      "203.0.113.",  // Corporate VPN gateway  
      "192.0.2."     // Transactional SaaS pool  
    \];

    const isAuthorized \= AUTHORIZED\_PREFIXES.some(prefix \=\> clientIp.startsWith(prefix));

    if (isAuthorized) {  
      // Return DNS A response 127.0.0.2 (Match)  
      return new Response(JSON.stringify({  
        Status: 0,  
        Answer: \[{ name: hostname, type: 1, TTL: 60, data: "127.0.0.2" }\]  
      }), {  
        headers: { "Content-Type": "application/dns-json" }  
      });  
    }

    return new Response("NXDOMAIN", { status: 404 });  
  }  
};\`;  
    },

    /\*\*  
     \* AWS Route 53 ChangeBatch JSON  
     \*/  
    generateRoute53(config) {  
      const domain \= (config.domain || 'example.com').replace(/^\\\*\\./, '');  
      const spf \= config.spfRecord || \`v=spf1 include:\_spf.google.com exists:%{i}.\_spf.\${domain} \-all\`;

      const payload \= {  
        Comment: \`SPF record with RFC 7208 macro delegation for \${domain}\`,  
        Changes: \[  
          {  
            Action: 'UPSERT',  
            ResourceRecordSet: {  
              Name: \`\${domain}.\`,  
              Type: 'TXT',  
              TTL: 3600,  
              ResourceRecords: \[  
                {  
                  Value: \`"\${spf}"\`  
                }  
              \]  
            }  
          }  
        \]  
      };

      return JSON.stringify(payload, null, 2);  
    },

    /\*\*  
     \* BIND 9 Zonefile Format  
     \*/  
    generateBIND(config) {  
      const domain \= (config.domain || 'example.com').replace(/^\\\*\\./, '');  
      const spf \= config.spfRecord || \`v=spf1 include:\_spf.google.com exists:%{i}.\_spf.\${domain} \-all\`;

      return \`; \==========================================  
; BIND 9 Zonefile Entry (RFC 7208 Compliant)  
; Domain: \${domain}  
; \==========================================  
\$ORIGIN \${domain}.  
\$TTL 3600

; SPF TXT Record (Strict \-all termination)  
@       IN      TXT     "\${spf}"

; Static fallback delegation host for authorized IP quads  
\_spf    IN      A       127.0.0.2  
\*. \_spf IN      A       127.0.0.2  
\`;  
    },

    /\*\*  
     \* Terraform HCL (Cloudflare & AWS Route 53\)  
     \*/  
    generateTerraform(config) {  
      const domain \= (config.domain || 'example.com').replace(/^\\\*\\./, '');  
      const spf \= config.spfRecord || \`v=spf1 include:\_spf.google.com exists:%{i}.\_spf.\${domain} \-all\`;

      return \`\# \==========================================  
\# Terraform HCL \- Multi-Provider SPF Deployment  
\# \==========================================

\# 1\. Cloudflare Provider  
resource "cloudflare\_record" "spf\_macro" {  
  zone\_id \= var.cloudflare\_zone\_id  
  name    \= "@"  
  type    \= "TXT"  
  content \= "\${spf}"  
  ttl     \= 3600  
}

\# 2\. AWS Route 53 Provider Alternative  
resource "aws\_route53\_record" "spf\_macro" {  
  zone\_id \= var.aws\_hosted\_zone\_id  
  name    \= "\${domain}"  
  type    \= "TXT"  
  ttl     \= "3600"  
  records \= \[  
    "\${spf}"  
  \]  
}\`;  
    },

    /\*\*  
     \* CoreDNS / PowerDNS Dynamic Plugin Configuration  
     \*/  
    generateCoreDNS(config) {  
      const domain \= (config.domain || 'example.com').replace(/^\\\*\\./, '');

      return \`\# \==========================================  
\# CoreDNS Dynamic Macro Zonefile Plugin  
\# Domain: \_spf.\${domain}  
\# \==========================================  
\_spf.\${domain}:53 {  
    \# Dynamically respond to exists:%{i} queries  
    template IN A {  
        match "^(\[0-9.\]+)\\\\.\_spf\\\\.\${domain}\\\\.\$"  
        answer "{{ .Name }} 60 IN A 127.0.0.2"  
        fallthrough  
    }  
    log  
    errors  
}\`;  
    }  
  };

  return SPFDNSSynthesizer;  
});  
