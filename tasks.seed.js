'use strict';

/**
 * Curated pool of realistic client tasks. The server rotates a daily subset
 * per user (seeded by date + user id) so tasks change every day and differ
 * between users.
 *
 * Every task is REAL, complex client work done OFF the platform (on the
 * freelancer's own computer) and delivered as a FILE UPLOAD. Each template
 * declares its required deliverable format:
 *    pdf   → posters, merged letters  (print-ready PDF)
 *    word  → articles, essays, reports, assignments  (.doc / .docx)
 *    excel → data entry, cleanup, analysis  (.xls / .xlsx)
 * The server scans the uploaded file (type + magic-byte signature) before it
 * enters verification, and earnings are released only after admin approval.
 */

const CATEGORIES = [
  'Assignments',
  'Article Writing',
  'Poster Design',
  'Data Entry',
  'Copywriting',
  'Academic Writing',
  'Mail Merging',
  'Excel Cleanup',
  'Data Analysis'
];

const TEMPLATES = [
  /* ------------------------------- Poster Design (PDF) ------------------------------- */
  { cat: 'Poster Design', deliverable: 'pdf', title: 'Design a charity fundraiser poster for "{org}"', desc: 'A4 charity poster for "{org}". Theme: {theme}. Primary colours: {color1} & {color2}. Event date: {date}. Bold headline, venue (Nairobi), donation call-to-action and till placeholder. Export a print-ready PDF.' },
  { cat: 'Poster Design', deliverable: 'pdf', title: 'Grand-opening poster for {company}', desc: 'A4 portrait poster announcing the grand opening of {company} on {date}. Theme: {theme}; brand colours {color1} & {color2}. Headline, date, location strip and CTA. Print-ready PDF.' },
  { cat: 'Poster Design', deliverable: 'pdf', title: 'Product-launch poster for {company}', desc: 'Launch poster (A4) for a new product by {company}. Theme: {theme}. {color1} dominant with {color2} accents. Include launch date {date} and a QR placeholder. Export as PDF.' },
  { cat: 'Poster Design', deliverable: 'pdf', title: 'Community event poster — theme "{theme}"', desc: 'Warm, welcoming A4 community-event poster. Colours {color1} & {color2}, event date {date}. Headline, 4-item programme list and contacts strip. Print-ready PDF.' },
  { cat: 'Poster Design', deliverable: 'pdf', title: 'Sales-promo poster: "{topic}"', desc: 'Promotional A4 poster on {topic} for {company}. Bold price callout, offer ends {date}. Colours {color1} & {color2}. Export as PDF.' },

  /* -------------------------------- Data Entry (Excel) ------------------------------- */
  { cat: 'Data Entry', deliverable: 'excel', title: 'Data entry: 50 customer records for {company}', desc: 'Create an Excel workbook for {company} with 50 realistic customer records — columns: Name, Phone (+254…), Email, Town, Last Purchase (DD/MM/YYYY), Amount (KES). Consistent formatting, no blank cells. Submit the .xlsx file.' },
  { cat: 'Data Entry', deliverable: 'excel', title: 'Data entry: inventory sheet for {company}', desc: 'Build an Excel stock sheet for {company}: 60 products with SKU, Category, Unit Cost, Quantity, Reorder Level and a Total Value column driven by formulas. Submit .xlsx.' },
  { cat: 'Data Entry', deliverable: 'excel', title: 'Transcribe a field survey into Excel — {topic}', desc: 'Enter 40 survey responses about {topic} into a tidy Excel table: Respondent ID, Age, Gender, County, Q1–Q5 answers. One row per respondent, headers bolded. Submit .xlsx.' },

  /* ------------------------------- Excel Cleanup (Excel) ------------------------------ */
  { cat: 'Excel Cleanup', deliverable: 'excel', title: 'Clean the messy sales export of {company}', desc: 'Rebuild a clean sales workbook for {company}: 80 rows, dates standardised to DD/MM/YYYY, phones in +254 format, duplicates removed, totals row with SUM formulas. Submit .xlsx.' },
  { cat: 'Excel Cleanup', deliverable: 'excel', title: 'Payroll-ready spreadsheet for {company}', desc: 'Excel payroll sheet for {company}: 15 employees — Name, Role, Basic Pay, NSSF (6%), PAYE (10%), Net Pay (formula). Currency formatted as KES. Submit .xlsx.' },

  /* ------------------------------- Data Analysis (Excel) ------------------------------ */
  { cat: 'Data Analysis', deliverable: 'excel', title: 'Analyse half-year sales for {company}', desc: 'Excel report for {company}: monthly sales Jan–Jun 2026 across 12 products, monthly totals, top-5 products, and 2 charts (column + line) on a summary sheet. Submit .xlsx.' },
  { cat: 'Data Analysis', deliverable: 'excel', title: 'Survey analysis workbook — {topic}', desc: 'Excel analysis of a 60-response survey on {topic}: frequency table, percentages, cross-tab of two questions, and a findings sheet with 5 key bullets. Submit .xlsx.' },

  /* ------------------------------- Mail Merging (PDF) --------------------------------- */
  { cat: 'Mail Merging', deliverable: 'pdf', title: 'Mail merge: 20 personalised letters for {company}', desc: 'Produce a 20-page PDF of personalised customer letters for {company} — names, towns and balances must differ on every page. Professional letterhead with {color1} accents. Submit one merged PDF.' },
  { cat: 'Mail Merging', deliverable: 'pdf', title: 'Mail merge: 15 event invitations dated {date}', desc: 'Merged PDF of 15 invitations for a {company} event on {date}: each with a different guest name and table number. Elegant {theme} styling. Submit PDF.' },

  /* ------------------------------ Article Writing (Word) ------------------------------ */
  { cat: 'Article Writing', deliverable: 'word', title: 'Write an 800-word article: "{topic}"', desc: 'Original 800-word article on {topic} for the {company} blog: headline, intro, 3 subheadings, conclusion and a meta description. UK English, zero plagiarism. Submit as a Word document.' },
  { cat: 'Article Writing', deliverable: 'word', title: 'Newsletter feature for {company}', desc: '600-word newsletter feature about {company} and {topic}: punchy headline, two pull-quotes, CTA footer dated {date}. Submit as Word (.docx).' },

  /* ----------------------------- Academic Writing (Word) ------------------------------ */
  { cat: 'Academic Writing', deliverable: 'word', title: 'Write a 1,000-word essay: "{topic}"', desc: 'Formal 1,000-word essay on {topic}: introduction with a clear thesis, 3 body paragraphs, conclusion, and 4 APA 7 references. Submit as a Word document.' },
  { cat: 'Academic Writing', deliverable: 'word', title: 'Research report for {company}', desc: 'A 4-page professional report on {company}: executive summary, market overview of {topic}, findings table and recommendations. Formal headings throughout. Submit as Word.' },

  /* -------------------------------- Copywriting (Word) -------------------------------- */
  { cat: 'Copywriting', deliverable: 'word', title: 'Copy pack for {company}', desc: 'Word document containing: 5 headlines, 3 product descriptions (60 words each) and 2 social captions for {company} — campaign theme "{theme}", launch date {date}. Persuasive and benefit-led.' },
  { cat: 'Copywriting', deliverable: 'word', title: 'Landing-page copy: "{topic}"', desc: 'Full landing-page copy (hero headline + subhead, 3 benefit blocks, 4-question FAQ, CTA) for a {company} campaign about {topic}. Submit as Word.' },

  /* -------------------------------- Assignments (Word) -------------------------------- */
  { cat: 'Assignments', deliverable: 'word', title: 'Business proposal for {company}', desc: 'Write a 3-page business proposal for {company} covering {topic}: objectives, budget table (KES) and a timeline running to {date}. Professional tone. Submit as Word.' },
  { cat: 'Assignments', deliverable: 'word', title: 'Staff training brief for {company}', desc: 'A 2-page HR training brief for {company}: session plan, learning outcomes and an evaluation-form section. Dated {date}. Submit as Word.' }
];

const TOPICS = [
  'M-Pesa for small business', 'Nairobi matatu culture', 'Kenyan coffee farming',
  'SME loans in Kenya', 'E-commerce in East Africa', 'Youth employment',
  'Chama savings groups', 'Agribusiness startups', 'Affordable housing',
  'Digital marketing for SMEs', 'County health services', 'Online learning',
  'Renewable energy in Kenya', 'Tourism recovery post-2025'
];

/* Invented client companies — used so every task brief reads like real client work. */
const COMPANIES = [
  'Savannah Foods Ltd', 'Mombasa Marine Supplies', 'Kijani Agro Ventures', 'Nakuru Fresh Dairies',
  'Teknolink Solutions', 'Lake Basin Traders', 'Uhuru Logistics', 'Zawadi Crafts Co.',
  'Rift Valley Tours', 'Pamoja Microfinance', 'Kilele Exports', 'Mawingu Media',
  'Jenga Hardware Stores', 'Amani Health Clinics', 'Sokoni Fresh Markets', 'Bahari Publishing',
  'Fedha Insurance Brokers', 'Greenline Energy', 'Asili Naturals', 'Twende Safaris'
];

const ORGS = [
  'Hope for Children Foundation', 'Maji Safi Initiative', 'Tunza Mazingira Trust',
  'Elimu Bora Charity', 'Fursa Youth Centre', 'Nia Women Collective'
];

const THEMES = [
  'Sunset warmth', 'Ocean breeze', 'Forest canopy', 'Ubuntu earth tones',
  'Modern minimal', 'Bold Maasai-inspired', 'Gold & charcoal', 'Pastel bloom'
];

const COLOR_PAIRS = [
  ['#E63946', '#F1FA8C'], ['#1D3557', '#F4A261'], ['#2A9D8F', '#E9C46A'],
  ['#6A4C93', '#FFD166'], ['#D62828', '#003049'], ['#118AB2', '#EF476F'],
  ['#3A5A40', '#DDA15E'], ['#22223B', '#C9ADA7']
];

function dailyTasksFor(userId, count, payForTier) {
  // Deterministic daily rotation: same user sees the same set all day,
  // a fresh set tomorrow, and different users see different mixes.
  const dayKey = new Date().toISOString().slice(0, 10);
  let seed = 0;
  const s = userId + dayKey;
  for (let i = 0; i < s.length; i++) seed = (seed * 31 + s.charCodeAt(i)) >>> 0;

  const idxs = TEMPLATES.map((_, i) => i);
  for (let i = idxs.length - 1; i > 0; i--) {
    seed = (seed * 1103515245 + 12345) >>> 0;
    const j = seed % (i + 1);
    [idxs[i], idxs[j]] = [idxs[j], idxs[i]];
  }

  return idxs.slice(0, count).map((i, pos) => {
    const t = TEMPLATES[i];
    const topic = TOPICS[(seed + i) % TOPICS.length];
    const company = COMPANIES[(seed + i * 7) % COMPANIES.length];
    const org = ORGS[(seed + i * 3) % ORGS.length];
    const theme = THEMES[(seed + i * 5) % THEMES.length];
    const pair = COLOR_PAIRS[(seed + i * 11) % COLOR_PAIRS.length];
    // A realistic future event/deadline date, deterministic per task.
    const d = new Date();
    d.setDate(d.getDate() + 14 + ((seed >>> (pos % 16)) % 45));
    const date = d.toLocaleDateString('en-KE', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
    const fill = str => str
      .replace(/\{topic\}/g, topic)
      .replace(/\{company\}/g, company)
      .replace(/\{org\}/g, org)
      .replace(/\{theme\}/g, theme)
      .replace(/\{color1\}/g, pair[0])
      .replace(/\{color2\}/g, pair[1])
      .replace(/\{date\}/g, date);
    return {
      key: dayKey + ':' + i,
      category: t.cat,
      title: fill(t.title),
      description: fill(t.desc),
      deliverable: t.deliverable,   // 'pdf' | 'word' | 'excel' — the ONLY upload format accepted
      pay: payForTier()
    };
  });
}

module.exports = { CATEGORIES, TEMPLATES, dailyTasksFor };
