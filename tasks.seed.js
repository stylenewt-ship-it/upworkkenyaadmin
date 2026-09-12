'use strict';

/**
 * Curated pool of realistic client tasks. The server rotates a daily subset
 * per user (seeded by date + user id) so tasks change every day and differ
 * between users.
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
  { cat: 'Assignments', title: 'Complete a short client assignment: "{topic}"', desc: 'Follow the attached brief, produce the requested document/slides and submit before the deadline. Quality is checked on submission.' },
  { cat: 'Assignments', title: 'Handle a same-day micro assignment', desc: 'A quick-turnaround client task (30–60 minutes). Read the brief carefully and submit exactly what is requested.' },
  { cat: 'Article Writing', title: 'Write a 600-word blog post: "{topic}"', desc: 'Original, well-structured blog post with a headline, intro, 3 sub-sections and a conclusion. UK/US English, no plagiarism.' },
  { cat: 'Article Writing', title: 'Summarise a report into a 300-word article', desc: 'Read the attached brief and produce a crisp 300-word summary suitable for a company newsletter.' },
  { cat: 'Poster Design', title: 'Design an A4 promo poster: "{topic}"', desc: 'Clean, modern A4 poster (PNG/PDF). Include headline, date, venue and a call-to-action. Brand colours provided.' },
  { cat: 'Poster Design', title: 'Social media poster set (3 sizes)', desc: 'One design adapted to 1080x1080, 1080x1350 and 1920x1080. Deliver PNG files.' },
  { cat: 'Data Entry', title: 'Enter 40 records from scanned forms', desc: 'Transcribe fields (name, phone, ID, amount) from scanned forms into the provided spreadsheet template. 100% accuracy required.' },
  { cat: 'Data Entry', title: 'Clean and dedupe a 200-row contact list', desc: 'Remove duplicates, normalise phone numbers to +254 format, fix capitalisation.' },
  { cat: 'Copywriting', title: 'Write 5 product descriptions (60 words each)', desc: 'Persuasive, benefit-led descriptions for an e-commerce store. Include one call-to-action per description.' },
  { cat: 'Copywriting', title: 'Landing page headline + subhead variants', desc: 'Provide 5 headline/subheadline pairs for A/B testing. Tone: confident, friendly.' },
  { cat: 'Academic Writing', title: 'Proofread a 2,000-word essay', desc: 'Grammar, flow, referencing (APA 7). Track changes and add margin comments.' },
  { cat: 'Academic Writing', title: 'Format references to APA 7 (25 entries)', desc: 'Convert a mixed-format reference list to correct APA 7 style.' },
  { cat: 'Mail Merging', title: 'Mail merge 150 letters from a data file', desc: 'Use the provided Word template and Excel data file to generate 150 personalised letters (PDF output).' },
  { cat: 'Mail Merging', title: 'Personalised email blast setup (200 contacts)', desc: 'Prepare a merge-ready CSV and email template with merge fields for first name, company and amount.' },
  { cat: 'Excel Cleanup', title: 'Fix a messy sales spreadsheet', desc: 'Split combined columns, standardise dates to DD/MM/YYYY, remove blank rows, add totals row.' },
  { cat: 'Excel Cleanup', title: 'Build a clean pivot-ready dataset', desc: 'Transform the raw export into a tidy table (one row per record) ready for pivot tables.' },
  { cat: 'Data Analysis', title: 'Analyse monthly sales and chart trends', desc: 'From the provided CSV: monthly totals, top 5 products, and a one-page summary with 2 charts.' },
  { cat: 'Data Analysis', title: 'Survey results summary (120 responses)', desc: 'Frequencies, cross-tab of two questions, key findings in 5 bullet points.' }
];

const TOPICS = [
  'M-Pesa for small business', 'Nairobi matatu culture', 'Kenyan coffee farming',
  'SME loans in Kenya', 'E-commerce in East Africa', 'Youth employment',
  'Chama savings groups', 'Agribusiness startups', 'Affordable housing',
  'Digital marketing for SMEs', 'County health services', 'Online learning'
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

  return idxs.slice(0, count).map(i => {
    const t = TEMPLATES[i];
    const topic = TOPICS[(seed + i) % TOPICS.length];
    return {
      key: dayKey + ':' + i,
      category: t.cat,
      title: t.title.replace('{topic}', topic),
      description: t.desc,
      pay: payForTier()
    };
  });
}

module.exports = { CATEGORIES, TEMPLATES, dailyTasksFor };
