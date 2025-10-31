/**
 * Gemini Proxy v10.4.0
 */

import fetch from "node-fetch";

export async function callGemini({ apiKey, model, prompt }) {
  if (!apiKey || !prompt) return { success: false, error: "Missing apiKey or prompt" };

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
    });

    const data = await response.json();

    if (data.error) return { success: false, error: data.error.message };
    return { success: true, model, output: data };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
