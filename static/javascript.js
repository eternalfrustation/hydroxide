this.addEventListener("load", () => {
  const nav = document.getElementsByTagName("nav")[0];
  fetch("/static/navbar.html").then((navbar) => {
    console.log(navbar);
    nav.innerHTML = navbar.text().then((navbar) => {
      nav.innerHTML = navbar;
    });
  });
});
