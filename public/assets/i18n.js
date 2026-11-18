(function () {
  const STORAGE_KEY = 'rsbd_lang';
  const COMMON = {
    en: {
      'nav.tagline': 'Detailed Marks • Merit Score • QR Verified',
      'nav.home': 'Result Finder',
      'nav.verify': 'Verify Marksheet',
      'nav.about': 'About',
      'nav.terms': 'Terms',
      'nav.privacy': 'Privacy Policy',
      'footer.rights': 'All official board data remains property of Bangladesh Education Boards.',
      'footer.dev': 'Developed by',
    },
    bn: {
      'nav.tagline': 'বিষয়ভিত্তিক নম্বর • মেরিট স্কোর • QR ভেরিফিকেশন',
      'nav.home': 'ফলাফল খুঁজুন',
      'nav.verify': 'মার্কশিট যাচাই',
      'nav.about': 'সম্পর্কে',
      'nav.terms': 'শর্তাবলী',
      'nav.privacy': 'প্রাইভেসি পলিসি',
      'footer.rights': 'সকল ফলাফল সংশ্লিষ্ট বাংলাদেশ শিক্ষা বোর্ডের সংরক্ষিত সম্পত্তি।',
      'footer.dev': 'নির্মাতা:',
    },
  };

  let pageDict = { en: {}, bn: {} };
  let onChangeCbs = [];

  function getLang() {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === 'bn' ? 'bn' : 'en';
  }

  function t(key) {
    const lang = getLang();
    return (pageDict[lang] && pageDict[lang][key] !== undefined)
      ? pageDict[lang][key]
      : (COMMON[lang] && COMMON[lang][key] !== undefined)
        ? COMMON[lang][key]
        : (pageDict.en && pageDict.en[key] !== undefined)
          ? pageDict.en[key]
          : (COMMON.en[key] !== undefined ? COMMON.en[key] : key);
  }

  function apply() {
    const lang = getLang();
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach(el => {
      el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
      el.innerHTML = t(el.dataset.i18nHtml);
    });
    document.querySelectorAll('[data-i18n-ph]').forEach(el => {
      el.placeholder = t(el.dataset.i18nPh);
    });
    document.querySelectorAll('.rs-lang-btn').forEach(btn => {
      const active = btn.dataset.lang === lang;
      btn.className = 'rs-lang-btn px-2.5 py-1 rounded-md text-xs font-bold transition ' +
        (active ? 'bg-emerald-700 text-white shadow-sm' : 'text-slate-600 hover:text-emerald-700');
    });
    onChangeCbs.forEach(cb => { try { cb(lang); } catch (e) {} });
  }

  function setLang(lang) {
    localStorage.setItem(STORAGE_KEY, lang === 'bn' ? 'bn' : 'en');
    apply();
  }

  function wireButtons() {
    document.querySelectorAll('.rs-lang-btn').forEach(btn => {
      btn.addEventListener('click', () => setLang(btn.dataset.lang));
    });
  }

  window.RS_I18N = {
    register(dict, onChange) {
      if (dict && dict.en) Object.assign(pageDict.en, dict.en);
      if (dict && dict.bn) Object.assign(pageDict.bn, dict.bn);
      if (typeof onChange === 'function') onChangeCbs.push(onChange);
    },
    getLang,
    setLang,
    t,
    apply,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { wireButtons(); apply(); });
  } else {
    wireButtons(); apply();
  }
})();
