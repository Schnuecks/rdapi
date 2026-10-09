// Kopfzeile auf dem Handy: Menü auf- und zuklappen
document.querySelectorAll("[data-menu-toggle]").forEach((button) => {
  const bar = button.closest(".topbar");
  const set = (open) => {
    bar.classList.toggle("menu-open", open);
    button.setAttribute("aria-expanded", String(open));
  };
  button.addEventListener("click", () => set(!bar.classList.contains("menu-open")));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") set(false); });
});

// Sprachmenü: schließen bei Klick daneben oder mit Esc
document.querySelectorAll("details[data-menu]").forEach((menu) => {
  document.addEventListener("click", (e) => { if (!menu.contains(e.target)) menu.open = false; });
  menu.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && menu.open) {
      e.preventDefault();
      e.stopPropagation();
      menu.open = false;
      menu.querySelector("summary").focus();
    }
  });
});

// Sicherheitsabfrage vor dem Löschen
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (e) => { if (!confirm(form.dataset.confirm)) e.preventDefault(); });
});
