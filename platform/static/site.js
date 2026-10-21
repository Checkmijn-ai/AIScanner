// checkmijn.ai — een beetje JavaScript, alleen voor gemak. Alles werkt ook zonder.
(function () {
  "use strict";

  // Kopieerknoppen bij codeblokken
  document.querySelectorAll("[data-kopieer]").forEach(function (knop) {
    knop.hidden = false;
    knop.addEventListener("click", function () {
      var doel = document.getElementById(knop.getAttribute("data-kopieer"));
      if (!doel || !navigator.clipboard) return;
      navigator.clipboard.writeText(doel.textContent).then(function () {
        var oud = knop.textContent;
        knop.textContent = "Gekopieerd";
        setTimeout(function () { knop.textContent = oud; }, 2000);
      });
    });
  });

  // Zoeken en filteren in de lijst van checks
  // Alle checks: filteren op tekst, onderwerp, niveau en manier van controleren
  var zoekAlle = document.getElementById("zoek");
  var niveau = document.getElementById("niveau-filter");
  if (zoekAlle && niveau) {
    var dom2 = document.getElementById("domein");
    var scanner = document.getElementById("scanner-filter");
    var teller2 = document.getElementById("teller");
    var rijen = Array.prototype.slice.call(document.querySelectorAll("tr.check-rij"));
    var blokken = Array.prototype.slice.call(document.querySelectorAll(".domein"));
    var filter2 = function () {
      var q = zoekAlle.value.trim().toLowerCase(), d = dom2.value, nv = niveau.value, sc = scanner.value, n = 0;
      rijen.forEach(function (tr) {
        var ok = (!q || tr.textContent.toLowerCase().indexOf(q) >= 0) && (!d || tr.getAttribute("data-domein") === d) &&
                 (!nv || tr.getAttribute("data-" + nv) === "verplicht") && (!sc || tr.getAttribute("data-scanner") === sc);
        tr.hidden = !ok;
        if (ok) n++;
      });
      blokken.forEach(function (b) { b.hidden = !b.querySelector("tr.check-rij:not([hidden])"); });
      teller2.textContent = n + " van " + rijen.length + " checks";
    };
    [zoekAlle, dom2, niveau, scanner].forEach(function (el) { el.addEventListener("input", filter2); });
    filter2();
    return;
  }

  var zoek = document.getElementById("zoek");
  if (zoek) {
    var dom = document.getElementById("domein");
    var ernst = document.getElementById("ernst-filter");
    var teller = document.getElementById("teller");
    var items = Array.prototype.slice.call(document.querySelectorAll("ul.checks li"));
    var filter = function () {
      var q = zoek.value.trim().toLowerCase(), d = dom.value, e = ernst.value, n = 0;
      items.forEach(function (li) {
        var ok = (!q || li.textContent.toLowerCase().indexOf(q) >= 0) &&
                 (!d || li.getAttribute("data-domein") === d) && (!e || li.getAttribute("data-ernst") === e);
        li.hidden = !ok;
        if (ok) n++;
      });
      teller.textContent = n + " van " + items.length + " checks";
    };
    [zoek, dom, ernst].forEach(function (el) { el.addEventListener("input", filter); });
    filter();
  }
})();
