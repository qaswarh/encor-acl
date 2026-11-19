document.addEventListener('DOMContentLoaded', function () {
  // --- 1. Live Glossary Search (Whole-Word Boundary) ---
  var glossarySearch = document.getElementById('glossarySearch');
  var glossaryNoResults = document.getElementById('glossaryNoResults');
  var glossarySec = document.getElementById('glossarySec');

  function filterGlossary() {
    if (!glossarySearch) return;
    var query = glossarySearch.value.trim();
    var cards = glossarySec.querySelectorAll('.term-card');
    var cats = glossarySec.querySelectorAll('.glossary-cat');
    var visibleCount = 0;

    if (!query) {
      cards.forEach(function (c) { c.classList.remove('hidden'); });
      cats.forEach(function (cat) { cat.classList.remove('hidden'); });
      if (glossaryNoResults) glossaryNoResults.classList.add('hidden');
      return;
    }

    var escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    var regex = new RegExp('\\b' + escaped, 'i');

    cards.forEach(function (card) {
      var match = regex.test(card.textContent);
      card.classList.toggle('hidden', !match);
      if (match) visibleCount++;
    });

    cats.forEach(function (cat) {
      var next = cat.nextElementSibling;
      var hasVisible = false;
      while (next && !next.classList.contains('glossary-cat')) {
        if (next.classList.contains('term-card') && !next.classList.contains('hidden')) {
          hasVisible = true;
          break;
        }
        next = next.nextElementSibling;
      }
      cat.classList.toggle('hidden', !hasVisible);
    });

    if (glossaryNoResults) {
      glossaryNoResults.classList.toggle('hidden', visibleCount > 0);
    }
  }

  if (glossarySearch) {
    glossarySearch.addEventListener('input', filterGlossary);
  }

  // --- 2. IPv4 & Wildcard Bitwise Helper Functions ---
  function parseIPv4(str) {
    var parts = str.trim().split('.');
    if (parts.length !== 4) return null;
    var num = 0;
    for (var i = 0; i < 4; i++) {
      if (!/^\d+$/.test(parts[i])) return null;
      var oct = parseInt(parts[i], 10);
      if (oct < 0 || oct > 255) return null;
      num = ((num << 8) | oct) >>> 0;
    }
    return num;
  }

  function toDottedBinary(ipInt) {
    return [24, 16, 8, 0].map(function (shift) {
      return ((ipInt >>> shift) & 255).toString(2).padStart(8, '0');
    }).join('.');
  }

  // Cisco Wildcard Logic: (PacketIP ^ RuleIP) & (~WildcardMask) === 0
  function matchesWildcard(pktIpInt, ruleIpStr, wildcardStr) {
    var ruleInt = parseIPv4(ruleIpStr);
    var wcInt = parseIPv4(wildcardStr);
    var careMask = (~wcInt) >>> 0;
    return (((pktIpInt ^ ruleInt) & careMask) >>> 0) === 0;
  }

  // --- 3. Cisco IOS Extended ACL Definition ---
  var aclEntries = [
    {
      seq: '10',
      action: 'permit',
      proto: 'TCP',
      srcIp: '10.10.1.0',
      srcWc: '0.0.0.255',
      dstIp: '192.168.50.10',
      dstWc: '0.0.0.0',
      dstPort: 22,
      cli: '10 permit tcp 10.10.1.0 0.0.0.255 host 192.168.50.10 eq 22',
      note: 'Allows Admin subnet (10.10.1.0/24) SSH access (TCP 22) to Management Server.'
    },
    {
      seq: '20',
      action: 'deny',
      proto: 'TCP',
      srcIp: '0.0.0.0',
      srcWc: '255.255.255.255',
      dstIp: '192.168.50.0',
      dstWc: '0.0.0.255',
      dstPort: 22,
      cli: '20 deny tcp any 192.168.50.0 0.0.0.255 eq 22',
      note: 'Blocks all other sources from SSHing into the 192.168.50.0/24 server subnet.'
    },
    {
      seq: '30',
      action: 'permit',
      proto: 'TCP',
      srcIp: '172.16.0.0',
      srcWc: '0.15.255.255',
      dstIp: '0.0.0.0',
      dstWc: '255.255.255.255',
      dstPort: 443,
      cli: '30 permit tcp 172.16.0.0 0.15.255.255 any eq 443',
      note: 'Allows RFC 1918 Class B block (172.16.0.0/12) outbound HTTPS (TCP 443).'
    },
    {
      seq: '40',
      action: 'permit',
      proto: 'ICMP',
      srcIp: '10.10.1.0',
      srcWc: '0.0.0.254',
      dstIp: '0.0.0.0',
      dstWc: '255.255.255.255',
      dstPort: null,
      cli: '40 permit icmp 10.10.1.0 0.0.0.254 any',
      note: 'Non-contiguous wildcard (0.0.0.254): permits ICMP only from EVEN hosts in 10.10.1.0/24.'
    }
  ];
  var pktSrc = document.getElementById('pktSrc');
  var pktDst = document.getElementById('pktDst');
  var pktProto = document.getElementById('pktProto');
  var pktPort = document.getElementById('pktPort');
  var pktPreset = document.getElementById('pktPreset');
  var pktError = document.getElementById('pktError');

  function evaluatePacket() {
    var proto = pktProto.value;
    pktPort.disabled = (proto === 'ICMP');

    var srcInt = parseIPv4(pktSrc.value);
    var dstInt = parseIPv4(pktDst.value);
    var portVal = parseInt(pktPort.value, 10) || 0;

    if (srcInt === null || dstInt === null) {
      pktError.classList.remove('hidden');
      return;
    }
    pktError.classList.add('hidden');

    var matchedAce = null;
    var aclHtml = '';

    aclEntries.forEach(function (ace) {
      if (matchedAce !== null) {
        aclHtml +=
          '<div class="ace-row ace-skipped">' +
          '<span>' + ace.cli + '</span>' +
          '<span class="ace-tag tag-skip">NOT EVALUATED</span>' +
          '</div>';
        return;
      }

      var protoOk = (ace.proto === proto);
      var srcOk = matchesWildcard(srcInt, ace.srcIp, ace.srcWc);
      var dstOk = matchesWildcard(dstInt, ace.dstIp, ace.dstWc);
      var portOk = (ace.dstPort === null) || (ace.dstPort === portVal);

      if (protoOk && srcOk && dstOk && portOk) {
        matchedAce = ace;
        var rowCls = ace.action === 'permit' ? 'ace-match-permit' : 'ace-match-deny';
        var tagCls = ace.action === 'permit' ? 'tag-permit' : 'tag-deny';
        aclHtml +=
          '<div class="ace-row ' + rowCls + '">' +
          '<span>' + ace.cli + '</span>' +
          '<span class="ace-tag ' + tagCls + '">MATCHED (' + ace.action.toUpperCase() + ')</span>' +
          '</div>';
      } else {
        aclHtml +=
          '<div class="ace-row">' +
          '<span>' + ace.cli + '</span>' +
          '<span class="ace-tag tag-nomatch">NO MATCH</span>' +
          '</div>';
      }
    });

    // Implicit deny ip any any at the bottom
    if (matchedAce === null) {
      aclHtml +=
        '<div class="ace-row ace-implicit ace-match-deny">' +
        '<span>! Implicit: deny ip any any</span>' +
        '<span class="ace-tag tag-deny">IMPLICIT DENY</span>' +
        '</div>';
    } else {
      aclHtml +=
        '<div class="ace-row ace-implicit ace-skipped">' +
        '<span>! Implicit: deny ip any any</span>' +
        '<span class="ace-tag tag-skip">NOT REACHED</span>' +
        '</div>';
    }

    document.getElementById('aclTable').innerHTML = aclHtml;

    // Verdict Banner & 32-Bit Wildcard Bitwise Breakdown
    var banner = document.getElementById('verdictBanner');
    var inspector = document.getElementById('bitInspector');

    if (matchedAce !== null) {
      var isPermit = matchedAce.action === 'permit';
      banner.className = 'verdict-banner ' + (isPermit ? 'verdict-permit' : 'verdict-deny');
      banner.textContent = (isPermit ? '✅ PERMITTED' : '⛔ DENIED') +
        ' — Matched Sequence ' + matchedAce.seq + ': ' + matchedAce.cli;

      inspector.innerHTML =
        '<strong>Bitwise Wildcard Match Analysis (Sequence ' + matchedAce.seq + ')</strong>' +
        '<div>' + matchedAce.note + '</div>' +
        '<table class="bit-grid-table">' +
        '<tr><th>Field</th><th>Dotted Decimal</th><th>32-Bit Binary (0 = Must Match, 1 = Ignore)</th></tr>' +
        '<tr><td>Packet Source IP</td><td>' + pktSrc.value.trim() + '</td><td>' + toDottedBinary(srcInt) + '</td></tr>' +
        '<tr><td>ACE Source IP</td><td>' + matchedAce.srcIp + '</td><td>' + toDottedBinary(parseIPv4(matchedAce.srcIp)) + '</td></tr>' +
        '<tr><td>ACE Source Wildcard</td><td>' + matchedAce.srcWc + '</td><td>' + toDottedBinary(parseIPv4(matchedAce.srcWc)) + '</td></tr>' +
        '</table>';
    } else {
      banner.className = 'verdict-banner verdict-deny';
      banner.textContent = '⛔ DROPPED — Hit Implicit "deny ip any any" at the end of ACL ENCOR-IN';

      inspector.innerHTML =
        '<strong>Implicit Deny Analysis</strong>' +
        '<div>None of ACEs 10–40 matched your packet (<code>' + pktSrc.value.trim() + ' → ' + pktDst.value.trim() + '</code>, <code>' + proto + (proto !== 'ICMP' ? ' ' + portVal : '') + '</code>). Every Cisco IOS ACL ends with an invisible <code>deny ip any any</code> statement.</div>';
    }
  }

  pktPreset.addEventListener('change', function () {
    if (!pktPreset.value) return;
    var parts = pktPreset.value.split('|');
    pktSrc.value = parts[0];
    pktDst.value = parts[1];
    pktProto.value = parts[2];
    pktPort.value = parts[3];
    evaluatePacket();
  });

  [pktSrc, pktDst, pktProto, pktPort].forEach(function (el) {
    el.addEventListener('input', evaluatePacket);
    el.addEventListener('change', evaluatePacket);
  });

  // Close parent modal on Esc key when embedded in 4any1
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && window.parent !== window) {
      window.parent.postMessage('closeAclModal', '*');
    }
  });

  evaluatePacket();
});
