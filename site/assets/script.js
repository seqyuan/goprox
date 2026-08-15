// Sticky glass nav: hairline appears only once content scrolls beneath it.
(function () {
  var nav = document.querySelector('.nav');
  if (!nav) return;
  var onScroll = function () {
    nav.classList.toggle('scrolled', window.scrollY > 8);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();
