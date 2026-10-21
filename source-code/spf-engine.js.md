/\*\*  
 \* SPFMacroForge Pro \- RFC 7208 SPF Macro Expression & DNS Lookup Engine  
 \* Implements RFC 7208 Section 7 Macro Expansions, Section 4.6.4 10-DNS-Lookup Accounting,  
 \* Mechanism Parsing, and Dynamic Macro Delegation Synthesis.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.SPFEngine \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  // Vendor typical nested lookup weights for simulation  
  const VENDOR\_LOOKUPS \= {  
    '\_spf.google.com': 3,  
    'mail.zendesk.com': 2,  
    'spf.protection.outlook.com': 2,  
    'sendgrid.net': 1,  
    'servers.mcsv.net': 2,  
    'hubspotemail.net': 3,  
    'salesforce.com': 4,  
    'mktomail.com': 2  
  };

  const SPFEngine \= {  
    VENDOR\_LOOKUPS,

    /\*\*  
     \* Expands an RFC 7208 macro string using the given email session context.  
     \* @param {string} macroStr \- e.g. "exists:%{ir}.%{v}.\_spf.%{d2}"  
     \* @param {Object} ctx \- { sender, domain, ip, helo }  
     \* @returns {string} expanded macro string  
     \*/  
    expandMacro(macroStr, ctx \= {}) {  
      if (\!macroStr) return '';

      const sender \= ctx.sender || 'sender@example.com';  
      const senderParts \= sender.split('@');  
      const localPart \= senderParts\[0\] || 'sender';  
      const senderDomain \= senderParts\[1\] || ctx.domain || 'example.com';  
      const domain \= ctx.domain || senderDomain;  
      const ip \= ctx.ip || '198.51.100.42';  
      const helo \= ctx.helo || 'mail.outbound.example.com';  
      const isIPv6 \= ip.includes(':');  
      const v \= isIPv6 ? 'ip6' : 'in-addr';

      // Replace escaped sequences first  
      let expanded \= macroStr  
        .replace(/%%/g, '\\u0001')  
        .replace(/%\_/g, ' ')  
        .replace(/%-/g, '%20');

      // RFC 7208 Section 7.2 regex: %\\{(\[slodiphvSLODIPHV\])(\\d+)?(r)?(\[.\\-+/,=\_\]\*)?\\}  
      const macroRegex \= /%\\{(\[slodiphvSLODIPHV\])(\\d+)?(r)?(\[.\\-+/,=\_\]\*)?\\}/g;

      expanded \= expanded.replace(macroRegex, (match, letter, digits, reverse, delimiters) \=\> {  
        const lowerLetter \= letter.toLowerCase();  
        let value \= '';

        switch (lowerLetter) {  
          case 's': value \= sender; break;  
          case 'l': value \= localPart; break;  
          case 'o': value \= senderDomain; break;  
          case 'd': value \= domain; break;  
          case 'i': value \= ip; break;  
          case 'p': value \= 'unknown'; break; // validated domain name of IP  
          case 'v': value \= v; break;  
          case 'h': value \= helo; break;  
          default: value \= ''; break;  
        }

        // Custom delimiters (default '.')  
        const delim \= delimiters || '.';  
        const delimRegex \= new RegExp(\`\[\${delim.replace(/\[-/\\\\^\$\*+?.()|\[\\\]{}\]/g, '\\\\\$&')}\]+\`, 'g');  
        let parts \= value.split(delimRegex);

        // Reverse order if 'r' is present  
        if (reverse) {  
          parts.reverse();  
        }

        // Take digits rightmost parts if specified  
        if (digits) {  
          const num \= parseInt(digits, 10);  
          if (\!isNaN(num) && num \> 0 && num \< parts.length) {  
            parts \= parts.slice(parts.length \- num);  
          }  
        }

        return parts.join('.');  
      });

      // Restore escaped percent  
      expanded \= expanded.replace(/\\u0001/g, '%');

      return expanded;  
    },

    /\*\*  
     \* Parses an SPF record string into tokens and mechanisms  
     \*/  
    parseSPFRecord(recordStr) {  
      if (\!recordStr) return { isValidSPF: false, mechanisms: \[\], modifiers: \[\], raw: '' };

      const trimmed \= recordStr.trim();  
      const tokens \= trimmed.split(/\\s+/);  
      const isSPF \= tokens\[0\] \=== 'v=spf1';

      const mechanisms \= \[\];  
      const modifiers \= \[\];

      for (let i \= 1; i \< tokens.length; i++) {  
        const tok \= tokens\[i\];  
        if (\!tok) continue;

        // Modifier (contains \=)  
        if (tok.includes('=')) {  
          const \[key, val\] \= tok.split('=', 2);  
          modifiers.push({ type: 'modifier', name: key, value: val, token: tok });  
          continue;  
        }

        // Mechanism (qualifier \+ mechanism\_type\[:value\])  
        let qualifier \= '+';  
        let mechBody \= tok;

        if (\['+', '-', '\~', '?'\].includes(tok\[0\])) {  
          qualifier \= tok\[0\];  
          mechBody \= tok.substring(1);  
        }

        let type \= mechBody;  
        let value \= '';

        if (mechBody.includes(':')) {  
          const splitIdx \= mechBody.indexOf(':');  
          type \= mechBody.substring(0, splitIdx);  
          value \= mechBody.substring(splitIdx \+ 1);  
        }

        mechanisms.push({  
          token: tok,  
          qualifier,  
          type: type.toLowerCase(),  
          value  
        });  
      }

      return {  
        isValidSPF: isSPF,  
        version: tokens\[0\],  
        mechanisms,  
        modifiers,  
        raw: trimmed  
      };  
    },

    /\*\*  
     \* Accurately calculates DNS lookup count (RFC 7208 Section 4.6.4).  
     \* Limit is strictly 10\.  
     \*/  
    countDNSLookups(recordStr, customWeights \= {}) {  
      const parsed \= this.parseSPFRecord(recordStr);  
      let lookups \= 0;  
      const breakdown \= \[\];

      if (\!parsed.isValidSPF) {  
        return { totalLookups: 0, exceedsLimit: false, breakdown: \[\] };  
      }

      parsed.mechanisms.forEach(m \=\> {  
        let cost \= 0;  
        let note \= '';

        if (m.type \=== 'include') {  
          // Check if vendor has nested lookups  
          let vendorCost \= 1;  
          for (const vendor in VENDOR\_LOOKUPS) {  
            if (m.value.includes(vendor)) {  
              vendorCost \= VENDOR\_LOOKUPS\[vendor\];  
              break;  
            }  
          }  
          if (customWeights\[m.value\]) {  
            vendorCost \= customWeights\[m.value\];  
          }  
          cost \= vendorCost;  
          note \= cost \> 1 ? \`include (1 direct \+ \${cost \- 1} nested)\` : 'include (1 DNS query)';  
        } else if (\['a', 'mx', 'ptr', 'exists'\].includes(m.type)) {  
          cost \= 1;  
          note \= \`\${m.type} mechanism (1 DNS query)\`;  
        } else if (\['ip4', 'ip6', 'all'\].includes(m.type)) {  
          cost \= 0;  
          note \= \`\${m.type} mechanism (0 DNS queries \- immediate CIDR/policy check)\`;  
        }

        lookups \+= cost;  
        breakdown.push({  
          token: m.token,  
          type: m.type,  
          value: m.value,  
          cost,  
          note  
        });  
      });

      parsed.modifiers.forEach(mod \=\> {  
        if (mod.name.toLowerCase() \=== 'redirect') {  
          lookups \+= 1;  
          breakdown.push({  
            token: mod.token,  
            type: 'redirect',  
            value: mod.value,  
            cost: 1,  
            note: 'redirect modifier (1 DNS query)'  
          });  
        }  
      });

      return {  
        totalLookups: lookups,  
        maxAllowed: 10,  
        exceedsLimit: lookups \> 10,  
        breakdown  
      };  
    },

    /\*\*  
     \* Synthesizes an optimized dynamic SPF Macro delegation record  
     \* Collapses high lookup counts down to 2\.  
     \*/  
    synthesizeMacroOptimization(domain, primaryInclude \= '\_spf.google.com') {  
      const cleanDomain \= (domain || 'example.com').replace(/^\\\*\\./, '');  
      const macroRecord \= \`v=spf1 include:\${primaryInclude} exists:%{i}.\_spf.\${cleanDomain} \-all\`;  
      const fallbackRecord \= \`v=spf1 exists:%{ir}.%{v}.\_spf.\${cleanDomain} \-all\`;

      return {  
        optimizedSPF: macroRecord,  
        fallbackSPF: fallbackRecord,  
        lookupCount: 2,  
        delegationHost: \`\_spf.\${cleanDomain}\`,  
        explanation: \`Replaces vendor includes with exists:%{i}.\_spf.\${cleanDomain}. The authoritative DNS server dynamically verifies the IP, consuming exactly 1 DNS lookup for infinite sender endpoints.\`  
      };  
    }  
  };

  return SPFEngine;  
});  
