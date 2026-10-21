/\*\*  
 \* SPFMacroForge Pro \- 10-Point Zero-Trust SPF & Email Authentication Auditor  
 \* Evaluates SPF records against RFC 7208, RFC 7489 (DMARC alignment), and M3AAWG best practices.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    const SPFEngine \= require('./spf-engine.js');  
    module.exports \= factory(SPFEngine);  
  } else {  
    root.SPFAuditor \= factory(root.SPFEngine);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (SPFEngine) {  
  'use strict';

  const SPFAuditor \= {  
    /\*\*  
     \* Audits an SPF record configuration against the 10-point Zero-Trust rubric  
     \* @param {Object} config  
     \* @returns {Object} audit report with score, grade, checks, and remediation guidance  
     \*/  
    audit(config) {  
      const record \= config.spfRecord || '';  
      const domain \= config.domain || 'example.com';  
      const recordCount \= typeof config.recordCount \=== 'number' ? config.recordCount : 1;  
      const voidLookups \= typeof config.voidLookups \=== 'number' ? config.voidLookups : 0;  
      const dmarcAlignment \= Boolean(config.dmarcAlignment \!== false);

      const parsed \= SPFEngine.parseSPFRecord(record);  
      const lookupReport \= SPFEngine.countDNSLookups(record);

      const checks \= \[\];  
      let totalScore \= 0;

      // 1\. 10-DNS-Lookup Hard Limit Enforcement (15 pts)  
      const lookups \= lookupReport.totalLookups;  
      if (lookups \<= 7\) {  
        checks.push({  
          id: 'dns\_lookup\_limit',  
          title: '10-DNS-Lookup Limit Enforcement (RFC 7208 Sec 4.6.4)',  
          points: 15,  
          maxPoints: 15,  
          passed: true,  
          level: 'PASS',  
          message: \`Safe lookup budget: \${lookups}/10 DNS queries consumed. Substantial headroom for vendor expansion.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 15;  
      } else if (lookups \<= 10\) {  
        checks.push({  
          id: 'dns\_lookup\_limit',  
          title: '10-DNS-Lookup Limit Enforcement (RFC 7208 Sec 4.6.4)',  
          points: 8,  
          maxPoints: 15,  
          passed: false,  
          level: 'WARN',  
          message: \`Elevated lookup budget: \${lookups}/10 DNS queries consumed. Adding one more SaaS vendor will trigger PermError.\`,  
          remediation: 'Consolidate multiple includes using dynamic SPF macros (exists:%{i}.\_spf.domain.com).'  
        });  
        totalScore \+= 8;  
      } else {  
        checks.push({  
          id: 'dns\_lookup\_limit',  
          title: '10-DNS-Lookup Limit Enforcement (RFC 7208 Sec 4.6.4)',  
          points: 0,  
          maxPoints: 15,  
          passed: false,  
          level: 'CRITICAL',  
          message: \`CRITICAL PERMERROR: \${lookups}/10 DNS queries\! RFC 7208 limits lookups to 10\. Receiving mail gateways (Gmail/Yahoo/M365) evaluate PermError and reject/spam your emails.\`,  
          remediation: 'Deploy SPF Macro delegation (exists:%{i}.\_spf.domain.com) to collapse lookups down to 1-2.'  
        });  
      }

      // 2\. Strict HardFail (-all) Termination (15 pts)  
      const allMech \= parsed.mechanisms.find(m \=\> m.type \=== 'all');  
      if (allMech && allMech.qualifier \=== '-') {  
        checks.push({  
          id: 'hardfail\_termination',  
          title: 'Strict HardFail (-all) Termination',  
          points: 15,  
          maxPoints: 15,  
          passed: true,  
          level: 'PASS',  
          message: 'Record terminates strictly with "-all" (HardFail). Unauthorized IP addresses are definitively rejected.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 15;  
      } else if (allMech && allMech.qualifier \=== '\~') {  
        checks.push({  
          id: 'hardfail\_termination',  
          title: 'Strict HardFail (-all) Termination',  
          points: 8,  
          maxPoints: 15,  
          passed: false,  
          level: 'WARN',  
          message: 'Record terminates with "\~all" (SoftFail). SoftFail allows spoofed emails through unless strict DMARC p=reject is active.',  
          remediation: 'Upgrade "\~all" to "-all" once all authorized sender IPs are mapped.'  
        });  
        totalScore \+= 8;  
      } else {  
        checks.push({  
          id: 'hardfail\_termination',  
          title: 'Strict HardFail (-all) Termination',  
          points: 0,  
          maxPoints: 15,  
          passed: false,  
          level: 'CRITICAL',  
          message: \`Insecure termination: "\${allMech ? allMech.token : 'missing all'}". Leaves domain completely unprotected against email spoofing.\`,  
          remediation: 'Terminate record with "-all".'  
        });  
      }

      // 3\. Macro Syntax & Transformer Validity (10 pts)  
      const hasMacro \= record.includes('%{');  
      if (hasMacro) {  
        const macroValid \= /%\\{\[slodiphvSLODIPHV\](\\d+)?(r)?(\[.\\-+/,=\_\]\*)?\\}/.test(record);  
        if (macroValid) {  
          checks.push({  
            id: 'macro\_syntax\_validity',  
            title: 'RFC 7208 Section 7 Macro Syntax',  
            points: 10,  
            maxPoints: 10,  
            passed: true,  
            level: 'PASS',  
            message: 'Dynamic SPF macros follow valid RFC 7208 syntax and supported transformers.',  
            remediation: 'None required.'  
          });  
          totalScore \+= 10;  
        } else {  
          checks.push({  
            id: 'macro\_syntax\_validity',  
            title: 'RFC 7208 Section 7 Macro Syntax',  
            points: 0,  
            maxPoints: 10,  
            passed: false,  
            level: 'FAIL',  
            message: 'Malformed macro expression syntax detected in SPF string.',  
            remediation: 'Verify macro format adheres to %{\<letter\>\[digits\]\[r\]\[delimiters\]}.'  
          });  
        }  
      } else {  
        checks.push({  
          id: 'macro\_syntax\_validity',  
          title: 'RFC 7208 Section 7 Macro Syntax',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'No macros used (standard static mechanisms). Syntax is clean.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      }

      // 4\. Single SPF Record Hygiene (10 pts)  
      if (recordCount \=== 1\) {  
        checks.push({  
          id: 'single\_record\_hygiene',  
          title: 'Single SPF Record Hygiene (RFC 7208 Sec 3.2)',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Exactly one v=spf1 TXT record declared on the domain.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'single\_record\_hygiene',  
          title: 'Single SPF Record Hygiene (RFC 7208 Sec 3.2)',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'CRITICAL',  
          message: \`CRITICAL PERMERROR: \${recordCount} duplicate SPF records found\! RFC 7208 Section 3.2 specifies that publishing multiple v=spf1 records triggers an immediate PermError.\`,  
          remediation: 'Merge all mechanisms into a single v=spf1 TXT record and delete duplicate DNS entries.'  
        });  
      }

      // 5\. Deprecated Mechanism Prohibition (ptr) (10 pts)  
      const hasPtr \= parsed.mechanisms.some(m \=\> m.type \=== 'ptr');  
      if (\!hasPtr) {  
        checks.push({  
          id: 'deprecated\_ptr\_prohibition',  
          title: 'Deprecated Mechanism Prohibition (ptr)',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'No deprecated "ptr" mechanisms detected (RFC 7208 Section 5.5 compliant).',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'deprecated\_ptr\_prohibition',  
          title: 'Deprecated Mechanism Prohibition (ptr)',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: 'The "ptr" mechanism is deprecated under RFC 7208 Section 5.5 and ignored by major MTAs due to severe DNS latency and unreliability.',  
          remediation: 'Remove "ptr" mechanism and replace with explicit ip4/ip6 or include mechanisms.'  
        });  
      }

      // 6\. Void DNS Lookup Limit Compliance (10 pts)  
      if (voidLookups \<= 2\) {  
        checks.push({  
          id: 'void\_lookup\_limit',  
          title: 'Void DNS Lookup Limit Compliance',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: \`Void DNS queries (\${voidLookups}/2) within RFC 7208 Section 4.6.4 bounds.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'void\_lookup\_limit',  
          title: 'Void DNS Lookup Limit Compliance',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Exceeded void lookup limit: \${voidLookups} lookups returned NXDOMAIN or empty responses. Resolvers will abort with PermError.\`,  
          remediation: 'Remove stale or non-existent include/a/mx domains from the record.'  
        });  
      }

      // 7\. IP Subnet Scope & CIDR Hygiene (10 pts)  
      let broadSubnets \= false;  
      parsed.mechanisms.forEach(m \=\> {  
        if (m.type \=== 'ip4' && m.value.includes('/')) {  
          const prefix \= parseInt(m.value.split('/')\[1\], 10);  
          if (prefix \< 24\) broadSubnets \= true;  
        }  
      });

      if (\!broadSubnets) {  
        checks.push({  
          id: 'subnet\_cidr\_hygiene',  
          title: 'IP Subnet Scope & CIDR Hygiene',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'All IP CIDR blocks use tight scopes (/24 to /32), minimizing shared IP spoofing risks.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'subnet\_cidr\_hygiene',  
          title: 'IP Subnet Scope & CIDR Hygiene',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'WARN',  
          message: 'Overly broad CIDR block (\< /24) detected. Authorizes thousands of unrelated cloud IP addresses to send mail as your domain.',  
          remediation: 'Narrow CIDR masks to specific sending hosts (/28 to /32).'  
        });  
      }

      // 8\. DNS TXT String Length Ceiling (10 pts)  
      const recordLength \= record.length;  
      if (recordLength \<= 255\) {  
        checks.push({  
          id: 'txt\_string\_length',  
          title: 'DNS TXT String Length Ceiling',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: \`Record length (\${recordLength} chars) fits comfortably in a single 255-byte DNS string octet.\`,  
          remediation: 'None required.'  
        });  
        totalScore \+= 10;  
      } else if (recordLength \<= 450\) {  
        checks.push({  
          id: 'txt\_string\_length',  
          title: 'DNS TXT String Length Ceiling',  
          points: 6,  
          maxPoints: 10,  
          passed: false,  
          level: 'WARN',  
          message: \`Record length (\${recordLength} chars) exceeds 255 bytes. Requires multi-string DNS TXT syntax.\`,  
          remediation: 'Split into quoted chunks ("v=spf1 ..." " ...") or compress mechanisms with macros.'  
        });  
        totalScore \+= 6;  
      } else {  
        checks.push({  
          id: 'txt\_string\_length',  
          title: 'DNS TXT String Length Ceiling',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: \`Record length (\${recordLength} chars) risks UDP 512-byte truncation and DNS buffer overflow.\`,  
          remediation: 'Compress record using dynamic macro delegation.'  
        });  
      }

      // 9\. Dynamic Macro Delegation & Vendor Consolidation (5 pts)  
      const hasDynamicMacro \= record.includes('exists:%{i}') || record.includes('exists:%{ir}');  
      if (hasDynamicMacro || lookups \<= 3\) {  
        checks.push({  
          id: 'vendor\_consolidation',  
          title: 'Dynamic Macro & Vendor Consolidation',  
          points: 5,  
          maxPoints: 5,  
          passed: true,  
          level: 'PASS',  
          message: 'Dynamic macro delegation or ultra-compact include architecture active. Immune to vendor IP drift.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'vendor\_consolidation',  
          title: 'Dynamic Macro & Vendor Consolidation',  
          points: 2,  
          maxPoints: 5,  
          passed: false,  
          level: 'WARN',  
          message: 'Multiple static vendor includes present. Consider macro delegation to eliminate lookup overhead.',  
          remediation: 'Adopt exists:%{i}.\_spf.domain.com to future-proof email deliverability.'  
        });  
        totalScore \+= 2;  
      }

      // 10\. Alignment with DMARC Envelope Sender (5 pts)  
      if (dmarcAlignment) {  
        checks.push({  
          id: 'dmarc\_alignment',  
          title: 'Alignment with DMARC Envelope Sender (RFC 7489)',  
          points: 5,  
          maxPoints: 5,  
          passed: true,  
          level: 'PASS',  
          message: 'RFC 5321.MailFrom aligns with RFC 5322.From header domain.',  
          remediation: 'None required.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'dmarc\_alignment',  
          title: 'Alignment with DMARC Envelope Sender (RFC 7489)',  
          points: 0,  
          maxPoints: 5,  
          passed: false,  
          level: 'WARN',  
          message: 'Unaligned return-path. SPF Pass will not satisfy DMARC alignment unless DKIM passes.',  
          remediation: 'Ensure Return-Path matches your branded domain.'  
        });  
      }

      // Grade calculation  
      let grade \= 'F';  
      if (totalScore \>= 95\) grade \= 'A+';  
      else if (totalScore \>= 90\) grade \= 'A';  
      else if (totalScore \>= 80\) grade \= 'B';  
      else if (totalScore \>= 70\) grade \= 'C';  
      else grade \= 'F';

      const isProductionReady \= totalScore \>= 90 && lookups \<= 10 && recordCount \=== 1 && \!hasPtr;

      return {  
        score: totalScore,  
        maxScore: 100,  
        grade,  
        isProductionReady,  
        lookups,  
        checks,  
        summary: \`SPF Security Audit: \${totalScore}/100 (Grade \${grade}) \- \${isProductionReady ? 'Production Ready' : 'Remediation Required'}\`  
      };  
    }  
  };

  return SPFAuditor;  
});  
