// reduced motion
var reduce = matchMedia('(prefers-reduced-motion:reduce)').matches;

// count-up stats
function countUp(el){
  var target = +el.dataset.count, dur = 900, t0 = performance.now();
  function step(t){ var p = Math.min((t-t0)/dur,1);
    el.textContent = Math.round(target*(1-Math.pow(1-p,3)));
    if(p<1) requestAnimationFrame(step); }
  requestAnimationFrame(step);
}
function runCounts(){
  document.querySelectorAll('b[data-count]').forEach(function(el){
    if(el.dataset.done) return;
    if(reduce){ el.textContent = el.dataset.count; el.dataset.done='1'; return; }
    el.dataset.done='1'; countUp(el);
  });
}

// reveal on scroll
if(!reduce && 'IntersectionObserver' in window){
  var revObs = new IntersectionObserver(function(es){
    es.forEach(function(en){ if(en.isIntersecting){ en.target.classList.add('in'); revObs.unobserve(en.target);
      en.target.querySelectorAll('b[data-count]').forEach(function(el){ if(!el.dataset.done){ el.dataset.done='1'; countUp(el); } });
    }});
  },{rootMargin:'0px 0px -8% 0px'});
  document.querySelectorAll('.reveal').forEach(function(el){ revObs.observe(el); });
} else {
  document.querySelectorAll('.reveal').forEach(function(el){ el.classList.add('in'); });
}
runCounts();

// severity filters + search
var search = document.getElementById('cve-search');
function activeSev(target){
  var g = document.querySelector('.filters[data-target="'+target+'"] .chip.active');
  return g ? g.dataset.sev : 'all';
}
function applyFilters(target){
  if(target === 'owasp'){
    var sev = activeSev('owasp');
    document.querySelectorAll('#owasp-grid .card').forEach(function(c){
      c.style.display = (sev==='all'||c.dataset.sev===sev) ? '' : 'none';
    });
  } else {
    var sev = activeSev('cve'), q = (search?search.value:'').trim().toLowerCase(), shown = 0;
    document.querySelectorAll('#cve-grid .card').forEach(function(c){
      var ok = (sev==='all'||c.dataset.sev===sev) && (!q || c.dataset.q.indexOf(q)>-1);
      c.style.display = ok ? '' : 'none'; if(ok) shown++;
    });
    var empty = document.getElementById('cve-empty'); if(empty) empty.hidden = shown>0;
  }
}
document.querySelectorAll('.filters').forEach(function(group){
  var target = group.dataset.target;
  group.addEventListener('click', function(e){
    var btn = e.target.closest('.chip'); if(!btn) return;
    group.querySelectorAll('.chip').forEach(function(c){ c.classList.remove('active'); });
    btn.classList.add('active'); applyFilters(target);
  });
});
if(search) search.addEventListener('input', function(){ applyFilters('cve'); });

// mobile menu
var menuBtn = document.querySelector('.menu-btn'), nav = document.querySelector('.nav');
if(menuBtn && nav){
  menuBtn.addEventListener('click', function(){
    var open = nav.classList.toggle('open');
    menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
}
