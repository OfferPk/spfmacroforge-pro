/\*\*  
 \* SPFMacroForge Pro \- Deliverability & PermError Outage Simulator  
 \* Simulates Scenario A (10-Lookup PermError & Silent Spam Outage)  
 \* versus Scenario B (Zero-PermError Macro Shield & Dynamic IP Authorization).  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.SPFSimulator \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const SPFSimulator \= {  
    /\*\*  
     \* Simulates Scenario A: 10-Lookup PermError Outage  
     \*/  
    simulateScenarioA(params) {  
      const domain \= params.domain || 'globalbank.com';  
      const lookups \= params.lookups || 13;  
      const sender \= params.sender || \`billing@\${domain}\`;  
      const ip \= params.ip || '198.51.100.42';

      return {  
        scenario: 'SCENARIO\_A\_PERMERROR\_OUTAGE',  
        title: '10-Lookup Limit PermError Outage (Critical Deliverability Failure)',  
        status: 'OUTAGE\_TRIGGERED',  
        severity: 'CRITICAL',  
        steps: \[  
          {  
            stepNumber: 1,  
            phase: 'Multi-SaaS Vendor Sprawl',  
            actor: 'Marketing / Sales Ops',  
            description: \`IT integrates multiple tools (Google, Zendesk, Salesforce, HubSpot, SendGrid). Total lookups reach \${lookups}/10.\`,  
            state: 'LOOKUP\_OVERFLOW',  
            payload: \`DOMAIN: \${domain}\\nLOOKUP\_COUNT: \${lookups} (RFC 7208 Max: 10)\\nSPF: v=spf1 include:\_spf.google.com include:salesforce.com include:mail.zendesk.com ... \~all\`  
          },  
          {  
            stepNumber: 2,  
            phase: 'Outbound Email Dispatch',  
            actor: 'Invoicing SaaS / MTA',  
            description: \`Invoice dispatch from \${sender} connecting via IP \${ip} to destination mail server.\`,  
            state: 'EMAIL\_DISPATCHED',  
            payload: \`CONNECT \[\${ip}\]:25 \-\> mx.google.com\\nMAIL FROM: \<\${sender}\>\\nRCPT TO: \<customer@client.com\>\`  
          },  
          {  
            stepNumber: 3,  
            phase: 'Recursive DNS SPF Evaluation',  
            actor: 'Receiving Mail Server (Google/Yahoo)',  
            description: 'Receiving resolver traverses nested includes. Upon reaching the 11th DNS query, RFC 7208 Section 4.6.4 forces immediate termination.',  
            state: 'LIMIT\_EXCEEDED',  
            payload: \`DNS Query \#10: include:hubspotemail.net \[OK\]\\nDNS Query \#11: include:sendgrid.net \-\> HALT\!\\nERROR: RFC 7208 10-DNS-lookup limit exceeded.\`  
          },  
          {  
            stepNumber: 4,  
            phase: 'PermError Classification & DMARC Failure',  
            actor: 'Spam Filter & DMARC Policy Engine',  
            description: 'SPF evaluation returns "PermError". DMARC cannot align SPF. Destination policy enforces rejection or spam routing.',  
            state: 'EVALUATION\_FAILED',  
            payload: 'Authentication-Results: mx.google.com;\\n  spf=permerror (google.com: permanent error in SPF record) smtp.mailfrom=' \+ sender \+ ';\\n  dmarc=fail (p=reject action=reject)'  
          },  
          {  
            stepNumber: 5,  
            phase: 'Delivery Drop & Business Interruption',  
            actor: 'Receiving Mail Gateway',  
            description: 'Invoice is rejected or silently banished to spam folder. Customer never receives payment request.',  
            state: 'OUTAGE\_CONFIRMED',  
            payload: 'SMTP 550 5.7.26 Message rejected due to SPF PermError and DMARC enforcement failure.\\nTransaction: ABORTED.'  
          }  
        \],  
        impact: 'Complete transactional and marketing email outage. Invoices and notifications fail SPF and DMARC, leading to missed revenue and blacklisted domain reputation.'  
      };  
    },

    /\*\*  
     \* Simulates Scenario B: Zero-PermError Macro Shield  
     \*/  
    simulateScenarioB(params) {  
      const domain \= params.domain || 'globalbank.com';  
      const sender \= params.sender || \`billing@\${domain}\`;  
      const ip \= params.ip || '198.51.100.42';  
      const macroExp \= params.macroExp || \`\${ip}.\_spf.\${domain}\`;

      return {  
        scenario: 'SCENARIO\_B\_MACRO\_SHIELD',  
        title: 'Zero-PermError SPF Macro Shield (Dynamic Zero-Trust Authorization)',  
        status: 'PROTECTED',  
        severity: 'SECURE',  
        steps: \[  
          {  
            stepNumber: 1,  
            phase: 'Macro Delegation Deployment',  
            actor: 'IT / SRE Team',  
            description: \`Vendor sprawl collapsed into dynamic macro: v=spf1 include:\_spf.google.com exists:%{i}.\_spf.\${domain} \-all.\`,  
            state: 'LOOKUP\_COLLAPSED',  
            payload: \`DOMAIN: \${domain}\\nLOOKUP\_COUNT: 2 / 10\\nMACRO: exists:%{i}.\_spf.\${domain}\`  
          },  
          {  
            stepNumber: 2,  
            phase: 'Outbound Email Dispatch',  
            actor: 'Invoicing SaaS / MTA',  
            description: \`Invoice dispatch from \${sender} connecting via IP \${ip} to destination mail server.\`,  
            state: 'EMAIL\_DISPATCHED',  
            payload: \`CONNECT \[\${ip}\]:25 \-\> mx.google.com\\nMAIL FROM: \<\${sender}\>\\nRCPT TO: \<customer@client.com\>\`  
          },  
          {  
            stepNumber: 3,  
            phase: 'Dynamic Macro Query Resolution',  
            actor: 'Receiving Mail Server (Google/Yahoo)',  
            description: \`Receiver expands macro %{i} with client IP \${ip} and performs a single DNS A lookup: \${macroExp}.\`,  
            state: 'MACRO\_EXPANDED',  
            payload: \`MACRO RESOLUTION: %{i} \-\> \${ip}\\nDNS QUERY: \${macroExp} IN A\\nLOOKUPS CONSUMED: 1\`  
          },  
          {  
            stepNumber: 4,  
            phase: 'Authoritative Match Verification',  
            actor: 'Authoritative DNS / Serverless Worker',  
            description: \`Authoritative DNS confirms IP \${ip} belongs to authorized SaaS sending pool and returns 127.0.0.2.\`,  
            state: 'IP\_AUTHORIZED',  
            payload: \`\${macroExp}. 60 IN A 127.0.0.2\\nRESULT: MATCH (Sender IP is authorized)\`  
          },  
          {  
            stepNumber: 5,  
            phase: 'SPF Pass & 100% Inbox Placement',  
            actor: 'Destination Mailbox',  
            description: 'SPF passes cleanly. DMARC aligns perfectly. Invoice lands directly in primary inbox without delay.',  
            state: 'DELIVERED\_SAFELY',  
            payload: 'Authentication-Results: mx.google.com;\\n  spf=pass (google.com: domain of ' \+ domain \+ ' designates ' \+ ip \+ ' as permitted sender);\\n  dmarc=pass (p=reject)\\nInbox: Primary'  
          }  
        \],  
        impact: '100% guaranteed first-pass email deliverability. Resolves infinite SaaS vendor integrations with only 2 DNS lookups, total immunity to IP drift, and strict \-all spoofing protection.'  
      };  
    }  
  };

  return SPFSimulator;  
});  
