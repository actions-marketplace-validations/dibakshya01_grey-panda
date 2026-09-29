/* Grey Panda — shared site behavior (motion + nav) */
(function () {
  // Scroll-reveal (Apple-style fade/slide-up), respecting reduced motion.
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var reveals = document.querySelectorAll('.reveal');
  if (reduce || !('IntersectionObserver' in window)) {
    reveals.forEach(function (el) { el.classList.add('in'); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    reveals.forEach(function (el) { io.observe(el); });
  }

  // Nav: shrink on scroll + subtle hero grid parallax.
  var nav = document.querySelector('nav');
  var grid = document.querySelector('.hero .grid');
  function onScroll() {
    var y = window.scrollY || 0;
    if (nav) nav.classList.toggle('shrink', y > 12);
    if (grid && !reduce && y < 900) grid.style.transform = 'translateY(' + (y * 0.18) + 'px)';
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  // Mobile menu toggle.
  var burger = document.querySelector('.burger');
  var tabs = document.querySelector('.tabs');
  if (burger && tabs) {
    burger.addEventListener('click', function () { tabs.classList.toggle('open'); });
    tabs.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', function () { tabs.classList.remove('open'); });
    });
  }

  // Copy buttons: [data-copy="text"]
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var t = btn.getAttribute('data-copy');
      navigator.clipboard && navigator.clipboard.writeText(t);
      var old = btn.textContent; btn.textContent = 'copied ✓';
      setTimeout(function () { btn.textContent = old; }, 1400);
    });
  });

  // Footer year.
  var y = document.querySelector('[data-year]');
  if (y) y.textContent = new Date().getFullYear();
})();
