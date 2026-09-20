// Every command reports a rejected request as well as an HTTP error. Keep retries explicit.
function reportFailure(action) {
  return async (...args) => {
    try { await action(...args); }
    catch (error) { alert(error.message); }
  };
}

async function command(url, o = {}) {
  o.headers = Object.assign({}, o.headers, { "X-TeleCrypt-Request-ID": crypto.randomUUID() });
  return fetch(url, o);
}

async function addSeat(e) {
  e.preventDefault();
  const r = await command("/plan/members/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mxid: e.target.mxid.value.trim() }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}

async function removeSeat(mxid) {
  const r = await command("/plan/members/" + encodeURIComponent(mxid) + "/remove", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
}

async function leaveTeam() {
  const r = await command("/plan/members/leave", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
}

document.querySelector("#add-seat")?.addEventListener("submit", reportFailure(addSeat));
document.querySelectorAll("[data-leave-team]").forEach((button) => {
  button.addEventListener("click", reportFailure(leaveTeam));
});
document.querySelectorAll("[data-remove-seat]").forEach((button) => {
  button.addEventListener("click", reportFailure(() => removeSeat(button.dataset.mxid)));
});
