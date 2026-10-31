// Print HTML files to PDF with headless Chromium (used by build_cheatsheets.py).
// usage: node html2pdf.js <footerHtml> <in1.html> <out1.pdf> [<in2.html> <out2.pdf> ...]
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const [footer, ...rest] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  for (let i = 0; i < rest.length; i += 2) {
    await page.goto('file://' + path.resolve(rest[i]));
    await page.emulateMedia({ media: 'print' });
    await page.pdf({
      path: rest[i + 1],
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<span></span>',
      footerTemplate: footer,
      margin: { top: '13mm', bottom: '16mm', left: '12mm', right: '12mm' },
    });
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
