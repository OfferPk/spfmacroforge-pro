\# SPFMacroForge Pro \- User Guide & Integration Manual

\#\# 1\. Quick Start

\#\#\# Web Studio (100% Client-Side)  
1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an infrastructure preset (\*\*Enterprise Multi-Vendor Macro\*\*, \*\*Standard B2B Cloud\*\*, or \*\*Vulnerable 14-Lookup PermError\*\*).  
3\. Review the \*\*Lookup Budget\*\*:  
   \- The studio calculates the exact recursive lookup cost across all included mechanisms (\`include:\`, \`a\`, \`mx\`, \`redirect\`, \`exists\`).  
   \- If lookups exceed 10, the studio flags a \*\*PERMERROR\*\* alert.  
4\. Click \*\*"Collapse Lookups with Macro"\*\* to automatically generate a dynamic macro record (\`exists:%{i}.\_spf.\<domain\>\`) that collapses lookup cost down to 2\!  
5\. Test real-time macro resolutions using the \*\*Dynamic Macro Simulator\*\* by inputting sample sender emails, client IP addresses, and HELO hosts.  
6\. Check the \*\*10-Point Zero-Trust Scorecard\*\* on the right panel to ensure your domain achieves Grade A+ (100/100).  
7\. Copy production DNS and automation snippets for \*\*Cloudflare\*\* (TXT \+ Worker), \*\*AWS Route 53\*\*, \*\*BIND 9\*\*, \*\*Terraform HCL\*\*, or \*\*CoreDNS\*\*.

\---

\#\# 2\. CLI Tool Usage (\`spfmacro-cli.py\`)

The standalone Python CLI requires zero external dependencies and runs on Python 3.8+.

\#\#\# 2.1 Expanding an RFC 7208 Macro  
\`\`\`bash  
python3 build/spfmacro-cli.py expand \\  
  \-m "exists:%{ir}.%{v}.\_spf.%{d2}" \\  
  \-s "billing@eu.example.com" \\  
  \-i "198.51.100.42"  
\`\`\`  
Output:  
\`\`\`json  
{  
  "input\_macro": "exists:%{ir}.%{v}.\_spf.%{d2}",  
  "expanded": "exists:42.100.51.198.in-addr.\_spf.example.com",  
  "context": {  
    "sender": "billing@eu.example.com",  
    "domain": "eu.example.com",  
    "ip": "198.51.100.42",  
    "helo": "mail.outbound.example.com"  
  }  
}  
\`\`\`

\#\#\# 2.2 Counting DNS Lookup Mechanisms  
\`\`\`bash  
python3 build/spfmacro-cli.py count \\  
  \-r "v=spf1 include:\_spf.google.com exists:%{i}.\_spf.globalbank.com \-all"  
\`\`\`  
Output:  
\`\`\`json  
{  
  "total\_lookups": 4,  
  "max\_allowed": 10,  
  "exceeds\_limit": false,  
  "breakdown": \[  
    {  
      "token": "include:\_spf.google.com",  
      "cost": 3,  
      "type": "include"  
    },  
    {  
      "token": "exists:%{i}.\_spf.globalbank.com",  
      "cost": 1,  
      "type": "exists"  
    },  
    {  
      "token": "-all",  
      "cost": 0,  
      "type": "all"  
    }  
  \]  
}  
\`\`\`

\#\#\# 2.3 Optimizing SPF Records with Macros  
\`\`\`bash  
python3 build/spfmacro-cli.py optimize \-d "globalbank.com"  
\`\`\`

\#\#\# 2.4 Running Zero-Trust Security Audit with Strict Gating  
\`\`\`bash  
python3 build/spfmacro-cli.py audit \-p presets/enterprise-multivendor-saas.json \--strict  
\# Exits code 0 on production-ready status, exits code 1 if PermError risk exists  
\`\`\`

\---

\#\# 3\. NetDevOps CI/CD Integration (GitHub Actions)

Add this check to your DNS repository CI/CD pipeline to prevent engineers from committing SPF records that exceed the 10-lookup limit:

\`\`\`yaml  
name: SPF 10-Lookup Ceiling & PermError Gate

on:  
  pull\_request:  
    paths:  
      \- 'dns/\*\*'  
      \- 'terraform/\*\*'

jobs:  
  spf-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run SPFMacroForge Strict Audit  
        run: |  
          python3 build/spfmacro-cli.py audit \-p presets/enterprise-multivendor-saas.json \--strict  
\`\`\`  
