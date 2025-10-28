// engine/verification.js
const axios = require("axios");

module.exports = {
  async verifyCrossRef(query) {
    try {
      const res = await axios.get(
        `https://api.crossref.org/works?query=${encodeURIComponent(query)}&rows=3`
      );
      const items = res.data.message.items || [];
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        quality: 0.9,
        sources: items.map(i => ({
          title: i.title?.[0],
          doi: i.DOI,
          published: i.created?.["date-time"]
        }))
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  async verifyOpenAlex(query) {
    try {
      const res = await axios.get(
        `https://api.openalex.org/works?filter=title.search:${encodeURIComponent(query)}&per-page=3`
      );
      const results = res.data.results || [];
      return {
        success: true,
        sourceDetected: results.length > 0,
        count: results.length,
        quality: 0.85,
        sources: results.map(i => ({
          title: i.display_name,
          doi: i.doi,
          year: i.publication_year
        }))
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  async verifyGDELT(query) {
    try {
      const res = await axios.get(
        `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(query)}&format=json`
      );
      const items = res.data.articles || [];
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        quality: 0.8,
        sources: items.map(i => ({
          title: i.title,
          url: i.url,
          source: i.sourceCountry
        }))
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  async verifyWikidata(query) {
    try {
      const res = await axios.get(
        `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=en&format=json`
      );
      const items = res.data.search || [];
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        quality: 0.75,
        sources: items.map(i => ({
          label: i.label,
          description: i.description
        }))
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  async verifyKLaw(query, apiKey) {
    if (!apiKey) return { success: false, error: "K-Law API key required" };
    try {
      const res = await axios.get(
        `https://api.k-law.ai/search?query=${encodeURIComponent(query)}&key=${apiKey}`
      );
      const items = res.data.results || [];
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        quality: 0.9,
        sources: items
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  async verifyGitHub(query, token) {
    if (!token) return { success: false, error: "GitHub token required" };
    try {
      const res = await axios.get(
        `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&per_page=3`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const items = res.data.items || [];
      return {
        success: true,
        sourceDetected: items.length > 0,
        count: items.length,
        quality: 0.8,
        sources: items.map(i => ({
          name: i.full_name,
          url: i.html_url,
          stars: i.stargazers_count
        }))
      };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  async verifyAll(query, apiKeys) {
    const results = {};
    results.crossref = await this.verifyCrossRef(query);
    results.openalex = await this.verifyOpenAlex(query);
    results.gdelt = await this.verifyGDELT(query);
    results.wikidata = await this.verifyWikidata(query);
    if (apiKeys?.klaw) results.klaw = await this.verifyKLaw(query, apiKeys.klaw);
    if (apiKeys?.github) results.github = await this.verifyGitHub(query, apiKeys.github);
    return { success: true, results };
  }
};
