document.addEventListener("DOMContentLoaded", () => {
  console.log("✅ Dashboard script loaded");

  const refreshBtn = document.createElement("button");
  refreshBtn.textContent = "🔄 새로고침";
  refreshBtn.className = "refresh-btn";
  document.querySelector("header").appendChild(refreshBtn);

  refreshBtn.addEventListener("click", () => {
    location.reload();
  });
});
