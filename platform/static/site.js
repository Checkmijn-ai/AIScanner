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

  // Nieuws: drie tabbladen (zonder JavaScript staan ze onder elkaar) en een taalkeuze
  var tablijst = document.querySelector(".tabs[role=tablist]");
  if (tablijst) {
    var tabs = Array.prototype.slice.call(tablijst.querySelectorAll("[role=tab]"));
    var panelen = tabs.map(function (t) { return document.getElementById(t.getAttribute("aria-controls")); });
    var kies = function (i, focus, inUrl) {
      tabs.forEach(function (t, j) {
        var aan = i === j;
        t.setAttribute("aria-selected", aan ? "true" : "false");
        t.tabIndex = aan ? 0 : -1;
        panelen[j].hidden = !aan;
      });
      if (focus) tabs[i].focus();
      if (inUrl && history.replaceState) history.replaceState(null, "", "#" + panelen[i].id);
    };
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () { kies(i, false, true); });
      t.addEventListener("keydown", function (e) {
        var n = null;
        if (e.key === "ArrowRight") n = (i + 1) % tabs.length;
        if (e.key === "ArrowLeft") n = (i - 1 + tabs.length) % tabs.length;
        if (e.key === "Home") n = 0;
        if (e.key === "End") n = tabs.length - 1;
        if (n !== null) { e.preventDefault(); kies(n, true, true); }
      });
    });
    var start = 0;
    panelen.forEach(function (p, i) { if (location.hash === "#" + p.id) start = i; });
    document.body.classList.add("js-tabs");
    tablijst.hidden = false;
    kies(start, false, false);

    var taalgroep = document.querySelector(".taalkeuze");
    var opgeslagen = "";
    try { opgeslagen = localStorage.getItem("nieuws-taal") || ""; } catch (e) { /* geen opslag */ }
    var zetTaal = function (taal) {
      taalgroep.querySelectorAll("button").forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-taal") === taal ? "true" : "false"); });
      panelen.forEach(function (p) {
        var zichtbaar = 0;
        p.querySelectorAll(".bericht").forEach(function (a) {
          var ok = !taal || (taal === "dichtbij" ? a.getAttribute("data-dichtbij") === "1" : a.getAttribute("data-taal") === taal);
          a.hidden = !ok;
          if (ok) zichtbaar++;
        });
        p.querySelectorAll(".berichten").forEach(function (lijst) {
          var kop = lijst.previousElementSibling;
          var leeg = !lijst.querySelector(".bericht:not([hidden])");
          if (kop && kop.classList.contains("dagkop")) kop.hidden = leeg;
        });
        var melding = p.querySelector(".taalleeg");
        if (melding) melding.hidden = zichtbaar > 0 || !p.querySelector(".bericht");
      });
      try { localStorage.setItem("nieuws-taal", taal); } catch (e) { /* geen opslag */ }
    };
    if (taalgroep) {
      taalgroep.hidden = false;
      taalgroep.querySelectorAll("button").forEach(function (b) {
        b.addEventListener("click", function () { zetTaal(b.getAttribute("data-taal")); });
      });
      zetTaal(opgeslagen);
    }
  }

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
