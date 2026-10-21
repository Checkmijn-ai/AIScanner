// Haalt een versleuteld rapport op en ontsleutelt het in de browser (AES-256-GCM).
// De sleutel staat alleen in de link, na "#k=", en wordt nooit naar een server gestuurd.
(function () {
  "use strict";
  var plek = document.getElementById("rapport");
  if (!plek) return;
  var id = plek.getAttribute("data-id");
  var melding = document.getElementById("melding");
  var lijst = document.getElementById("rapport-info");
  var knop = document.getElementById("download");

  function fout(tekst) {
    melding.innerHTML = "";
    var h = document.createElement("h1"); h.textContent = "Rapport niet te openen";
    var p = document.createElement("p"); p.className = "lead"; p.textContent = tekst;
    melding.appendChild(h); melding.appendChild(p);
  }
  function b64url(s) {
    var b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    var u = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u;
  }

  var k = new URLSearchParams(location.hash.slice(1)).get("k");
  if (!k) { fout("In deze link ontbreekt de sleutel. Gebruik de volledige link uit je rapport, met alles na het #-teken."); return; }
  if (!window.crypto || !crypto.subtle || !window.DecompressionStream) { fout("Je browser is te oud om het rapport te ontsleutelen. Gebruik een recente versie van Chrome, Edge, Firefox of Safari."); return; }

  var gegevens;
  fetch("/api/v1/rapport/" + encodeURIComponent(id), { referrerPolicy: "no-referrer", cache: "no-store" })
    .then(function (r) {
      if (r.status === 404) throw new Error("Dit rapport bestaat niet (meer). Rapporten die niet in een account bewaard zijn, worden na 90 dagen gewist.");
      if (!r.ok) throw new Error("Het rapport kon nu niet opgehaald worden. Probeer het later opnieuw.");
      return r.json();
    })
    .then(function (d) {
      gegevens = d;
      return crypto.subtle.importKey("raw", b64url(k), "AES-GCM", false, ["decrypt"]);
    })
    .then(function (sleutel) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: b64url(gegevens.iv) }, sleutel, b64url(gegevens.data))
        .catch(function () { throw new Error("De sleutel in de link klopt niet. Kopieer de volledige link, met alles na het #-teken."); });
    })
    .then(function (gz) {
      return new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
    })
    .then(function (html) {
      melding.classList.add("verborgen");
      var f = document.createElement("iframe");
      f.className = "rapport";
      f.title = "Scanrapport";
      f.setAttribute("sandbox", "");  // geen scripts, geen toegang tot deze site
      f.srcdoc = html;
      plek.appendChild(f);
      lijst.textContent = "Gemaakt op " + gegevens.aangemaakt + " · bewaard tot " + gegevens.verloopt + ".";
      knop.hidden = false;
      knop.addEventListener("click", function () {
        var a = document.createElement("a");
        a.href = URL.createObjectURL(new Blob([html], { type: "text/html" }));
        a.download = "checkmijn-rapport-" + gegevens.aangemaakt + ".html";
        a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
      });
    })
    .catch(function (e) { fout(e.message || String(e)); });
})();
