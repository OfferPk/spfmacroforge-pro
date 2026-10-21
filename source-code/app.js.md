/\*\*  
 \* SPFMacroForge Pro \- Studio Application Orchestrator  
 \*/

// Global State  
let currentConfig \= {  
  domain: 'globalbank.com',  
  spfRecord: 'v=spf1 include:\_spf.google.com exists:%{i}.\_spf.globalbank.com \-all',  
  sender: 'invoicing@globalbank.com',  
  ip: '198.51.100.42',  
  helo: 'smtp.globalbank.com',  
  recordCount: 1,  
  voidLookups: 0,  
  dmarcAlignment: true  
};

let currentSimMode \= 'B'; // 'A' or 'B'  
let currentConfigTab \= 'cloudflare'; // 'cloudflare', 'route53', 'bind', 'terraform', 'coredns'

const PRESETS \= {  
  enterprise: {  
    domain: 'globalbank.com',  
    spfRecord: 'v=spf1 include:\_spf.google.com exists:%{i}.\_spf.globalbank.com \-all',  
    sender: 'invoicing@globalbank.com',  
    ip: '198.51.100.42',  
    helo: 'smtp.globalbank.com',  
    recordCount: 1,  
    voidLookups: 0,  
    dmarcAlignment: true  
  },  
  standard: {  
    domain: 'cloudpulse.io',  
    spfRecord: 'v=spf1 include:\_spf.google.com include:sendgrid.net \-all',  
    sender: 'support@cloudpulse.io',  
    ip: '192.0.2.15',  
    helo: 'mail.cloudpulse.io',  
    recordCount: 1,  
    voidLookups: 0,  
    dmarcAlignment: true  
  },  
  vulnerable: {  
    domain: 'insecure-legacy.corp',  
    spfRecord: 'v=spf1 include:\_spf.google.com include:salesforce.com include:mail.zendesk.com include:servers.mcsv.net include:hubspotemail.net ptr ?all',  
    sender: 'admin@insecure-legacy.corp',  
    ip: '203.0.113.88',  
    helo: 'mta1.insecure-legacy.corp',  
    recordCount: 2,  
    voidLookups: 3,  
    dmarcAlignment: false  
  }  
};

document.addEventListener('DOMContentLoaded', () \=\> {  
  loadPreset('enterprise');  
});

function loadPreset(key) {  
  const p \= PRESETS\[key\];  
  if (\!p) return;

  \['btnPresetEnterprise', 'btnPresetStandard', 'btnPresetVulnerable'\].forEach(id \=\> {  
    document.getElementById(id)?.classList.remove('active');  
  });

  if (key \=== 'enterprise') document.getElementById('btnPresetEnterprise')?.classList.add('active');  
  if (key \=== 'standard') document.getElementById('btnPresetStandard')?.classList.add('active');  
  if (key \=== 'vulnerable') document.getElementById('btnPresetVulnerable')?.classList.add('active');

  currentConfig \= JSON.parse(JSON.stringify(p));

  // Populate UI inputs  
  document.getElementById('txtDomain').value \= currentConfig.domain;  
  document.getElementById('txtSpfRecord').value \= currentConfig.spfRecord;  
  document.getElementById('txtSender').value \= currentConfig.sender;  
  document.getElementById('txtIp').value \= currentConfig.ip;  
  document.getElementById('txtHelo').value \= currentConfig.helo;

  runLiveAudit();  
}

function onDomainChange(val) {  
  currentConfig.domain \= val.trim();  
  runLiveAudit();  
}

function onRecordChange(val) {  
  currentConfig.spfRecord \= val.trim();  
  runLiveAudit();  
}

function optimizeCurrentRecord() {  
  const opt \= SPFEngine.synthesizeMacroOptimization(currentConfig.domain);  
  currentConfig.spfRecord \= opt.optimizedSPF;  
  document.getElementById('txtSpfRecord').value \= opt.optimizedSPF;  
  runLiveAudit();  
}

function runLiveAudit() {  
  currentConfig.sender \= document.getElementById('txtSender').value;  
  currentConfig.ip \= document.getElementById('txtIp').value;  
  currentConfig.helo \= document.getElementById('txtHelo').value;

  const ctx \= {  
    sender: currentConfig.sender,  
    domain: currentConfig.domain,  
    ip: currentConfig.ip,  
    helo: currentConfig.helo  
  };

  // Live Macro Expansion  
  const expandedQuery \= SPFEngine.expandMacro(currentConfig.spfRecord, ctx);  
  document.getElementById('boxExpandedQuery').innerText \= \`Session Resolution:  
Sender: \${ctx.sender}  
Connecting IP: \${ctx.ip}  
HELO: \${ctx.helo}

Expanded Record:  
\${expandedQuery}\`;

  // Count Lookups  
  const lookupData \= SPFEngine.countDNSLookups(currentConfig.spfRecord);  
  const lookups \= lookupData.totalLookups;

  document.getElementById('metricLookups').innerText \= \`\${lookups} / 10\`;  
  document.getElementById('metricLength').innerText \= \`\${currentConfig.spfRecord.length} ch\`;

  const lookupBadge \= document.getElementById('lookupBadge');  
  lookupBadge.innerText \= \`LOOKUPS: \${lookups} / 10\`;

  if (lookups \> 10\) {  
    lookupBadge.className \= 'badge badge-red';  
    document.getElementById('metricLookups').style.color \= 'var(--accent-red)';  
    document.getElementById('metricPermError').innerText \= 'PERMERROR';  
    document.getElementById('metricPermError').style.color \= 'var(--accent-red)';  
  } else if (lookups \>= 8\) {  
    lookupBadge.className \= 'badge badge-amber';  
    document.getElementById('metricLookups').style.color \= 'var(--accent-amber)';  
    document.getElementById('metricPermError').innerText \= 'Warning';  
    document.getElementById('metricPermError').style.color \= 'var(--accent-amber)';  
  } else {  
    lookupBadge.className \= 'badge badge-green';  
    document.getElementById('metricLookups').style.color \= 'var(--accent-green)';  
    document.getElementById('metricPermError').innerText \= 'Safe';  
    document.getElementById('metricPermError').style.color \= 'var(--accent-green)';  
  }

  // Update DNS deployment entry  
  document.getElementById('txtDnsHost').value \= \`\${currentConfig.domain}. IN TXT\`;  
  document.getElementById('txtDnsVal').value \= currentConfig.spfRecord;

  // Run 10-point audit  
  const report \= SPFAuditor.audit(currentConfig);

  const gradeBadge \= document.getElementById('gradeBadge');  
  gradeBadge.innerText \= report.grade;  
  gradeBadge.className \= 'score-badge-huge grade-' \+ report.grade.toLowerCase().replace('+', 'plus');

  document.getElementById('scoreSummary').innerText \= \`Score: \${report.score} / 100\`;  
  document.getElementById('gradeSubtitle').innerText \= report.isProductionReady  
    ? 'RFC 7208 & DMARC Fully Compliant'  
    : 'PermError or Deliverability Risks Detected';

  const prodBadge \= document.getElementById('prodReadyBadge');  
  if (report.isProductionReady) {  
    prodBadge.innerText \= 'PRODUCTION READY';  
    prodBadge.className \= 'badge badge-green';  
  } else {  
    prodBadge.innerText \= 'PERMERROR RISK';  
    prodBadge.className \= 'badge badge-red';  
  }

  // Render Checks  
  const listEl \= document.getElementById('checksList');  
  listEl.innerHTML \= '';  
  report.checks.forEach(chk \=\> {  
    const item \= document.createElement('div');  
    item.className \= 'check-item';

    const header \= document.createElement('div');  
    header.className \= 'check-header';

    const title \= document.createElement('div');  
    title.className \= 'check-title';  
    title.innerHTML \= \`\<span\>\${chk.passed ? '✅' : (chk.level \=== 'CRITICAL' ? '🛑' : '⚠️')}\</span\> \<span\>\${chk.title}\</span\>\`;

    const badge \= document.createElement('span');  
    badge.className \= \`badge \${chk.passed ? 'badge-green' : (chk.level \=== 'CRITICAL' ? 'badge-red' : 'badge-amber')}\`;  
    badge.innerText \= \`\${chk.points}/\${chk.maxPoints} pts\`;

    header.appendChild(title);  
    header.appendChild(badge);

    const msg \= document.createElement('div');  
    msg.className \= 'check-msg';  
    msg.innerText \= chk.message;

    item.appendChild(header);  
    item.appendChild(msg);

    if (\!chk.passed && chk.remediation) {  
      const rem \= document.createElement('div');  
      rem.className \= 'check-remediation';  
      rem.innerText \= '🔧 Remediation: ' \+ chk.remediation;  
      item.appendChild(rem);  
    }

    listEl.appendChild(item);  
  });

  renderSimulator(lookups);  
  renderConfigSynthesizer();  
}

function switchSimulator(mode) {  
  currentSimMode \= mode;  
  document.getElementById('btnSimA').classList.toggle('active', mode \=== 'A');  
  document.getElementById('btnSimB').classList.toggle('active', mode \=== 'B');  
  runLiveAudit();  
}

function renderSimulator(lookups) {  
  const container \= document.getElementById('simContainer');  
  let sim;  
  if (currentSimMode \=== 'A') {  
    sim \= SPFSimulator.simulateScenarioA({  
      domain: currentConfig.domain,  
      lookups: lookups \> 10 ? lookups : 13,  
      sender: currentConfig.sender,  
      ip: currentConfig.ip  
    });  
  } else {  
    sim \= SPFSimulator.simulateScenarioB({  
      domain: currentConfig.domain,  
      sender: currentConfig.sender,  
      ip: currentConfig.ip,  
      macroExp: \`\${currentConfig.ip}.\_spf.\${currentConfig.domain}\`  
    });  
  }

  let html \= \`\<div style="margin-bottom: 12px; font-size: 13px; font-weight: 600; color: \${sim.severity \=== 'SECURE' ? 'var(--accent-green)' : 'var(--accent-red)'};"\>  
    \${sim.title} \- \${sim.impact}  
  \</div\>\<div class="sim-timeline"\>\`;

  sim.steps.forEach(st \=\> {  
    const isFail \= st.state \=== 'LIMIT\_EXCEEDED' || st.state \=== 'EVALUATION\_FAILED' || st.state \=== 'OUTAGE\_CONFIRMED' || st.state \=== 'LOOKUP\_OVERFLOW';  
    const isSafe \= st.state \=== 'IP\_AUTHORIZED' || st.state \=== 'DELIVERED\_SAFELY' || st.state \=== 'LOOKUP\_COLLAPSED';  
    const borderClass \= isFail ? 'fail' : (isSafe ? 'success' : '');

    html \+= \`  
      \<div class="sim-step \${borderClass}"\>  
        \<div class="sim-step-head"\>  
          \<span\>Step \${st.stepNumber}: \${st.phase}\</span\>  
          \<span class="sim-step-actor"\>\[\${st.actor}\]\</span\>  
        \</div\>  
        \<div class="sim-step-desc"\>\${st.description}\</div\>  
        \<div class="sim-payload"\>\${st.payload}\</div\>  
      \</div\>  
    \`;  
  });

  html \+= '\</div\>';  
  container.innerHTML \= html;  
}

function switchConfigTab(tab) {  
  currentConfigTab \= tab;  
  \['tabCloudflare', 'tabRoute53', 'tabBind', 'tabTerraform', 'tabCoreDNS'\].forEach(id \=\> {  
    document.getElementById(id)?.classList.remove('active');  
  });

  if (tab \=== 'cloudflare') document.getElementById('tabCloudflare')?.classList.add('active');  
  if (tab \=== 'route53') document.getElementById('tabRoute53')?.classList.add('active');  
  if (tab \=== 'bind') document.getElementById('tabBind')?.classList.add('active');  
  if (tab \=== 'terraform') document.getElementById('tabTerraform')?.classList.add('active');  
  if (tab \=== 'coredns') document.getElementById('tabCoreDNS')?.classList.add('active');

  renderConfigSynthesizer();  
}

function renderConfigSynthesizer() {  
  const codeEl \= document.getElementById('configOutput');  
  let code \= '';  
  if (currentConfigTab \=== 'cloudflare') {  
    code \= SPFDNSSynthesizer.generateCloudflare(currentConfig);  
  } else if (currentConfigTab \=== 'route53') {  
    code \= SPFDNSSynthesizer.generateRoute53(currentConfig);  
  } else if (currentConfigTab \=== 'bind') {  
    code \= SPFDNSSynthesizer.generateBIND(currentConfig);  
  } else if (currentConfigTab \=== 'terraform') {  
    code \= SPFDNSSynthesizer.generateTerraform(currentConfig);  
  } else if (currentConfigTab \=== 'coredns') {  
    code \= SPFDNSSynthesizer.generateCoreDNS(currentConfig);  
  }  
  codeEl.innerText \= code;  
}

function copyToClipboard(elementId, alertId) {  
  const el \= document.getElementById(elementId);  
  if (\!el) return;  
  navigator.clipboard.writeText(el.value).then(() \=\> {  
    showAlert(alertId);  
  }).catch(() \=\> {  
    el.select();  
    document.execCommand('copy');  
    showAlert(alertId);  
  });  
}

function copyTextFromElement(elementId, alertId) {  
  const el \= document.getElementById(elementId);  
  if (\!el) return;  
  navigator.clipboard.writeText(el.innerText).then(() \=\> {  
    showAlert(alertId);  
  });  
}

function showAlert(alertId) {  
  const alertEl \= document.getElementById(alertId);  
  if (alertEl) {  
    alertEl.style.display \= 'inline';  
    setTimeout(() \=\> {  
      alertEl.style.display \= 'none';  
    }, 2000);  
  }  
}  
