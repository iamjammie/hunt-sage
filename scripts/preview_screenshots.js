/* Screenshot key pages of a locally served build. Used by .github/workflows/preview-screenshots.yml.
   Usage: node scripts/preview_screenshots.js <output dir>   (site served at http://127.0.0.1:4173/hunt-sage) */
const { chromium } = require('playwright');
const path = require('path');
(async () => {
  const out = process.argv[2];
  const base = 'http://127.0.0.1:4173/hunt-sage';
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const pages = [
    ['home', '/', 1400, 900, false],
    ['home-full', '/', 1400, 900, true],
    ['hunt', '/hunt/', 1400, 900, true],
    ['light-playbook-light', '/hunt/playbooks/kerberoasting/', 1400, 900, false],
    ['playbook', '/hunt/playbooks/adcs-abuse/', 1400, 900, false],
    ['coverage', '/research/mitre-mapping/', 1400, 900, true],
    ['sigma', '/research/sigma/', 1400, 900, false],
    ['hypotheses', '/hunt/hypotheses/', 1400, 900, false],
    ['query-index', '/hunt/query-index/', 1400, 900, false],
    ['mobile-home', '/', 390, 844, false],
    ['mobile-playbook', '/hunt/playbooks/kerberoasting/', 390, 844, false],
  ];
  for (const [name, url, w, h, full] of pages) {
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
    const page = await ctx.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
    await page.goto(base + url, { waitUntil: 'networkidle' }).catch(e => errors.push('nav: ' + e));
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(out, name + '.png'), fullPage: full });
    if (name === 'home' || name === 'light-playbook-light') {
      await page.click('[data-hs-theme-toggle]').catch(e => errors.push('toggle: ' + e));
      await page.waitForTimeout(300);
      await page.screenshot({ path: path.join(out, name + '-light.png') });
    }
    console.log(name, errors.length ? 'ERRORS: ' + errors.join(' | ') : 'ok');
    await ctx.close();
  }
  await browser.close();
})();
