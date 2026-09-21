// Every command reports a rejected request as well as an HTTP error.
function reportFailure(action) {
  return async (...args) => {
    try { await action(...args); }
    catch (error) { alert(error.message); }
  };
}

async function addMember(e) {
  e.preventDefault();
  const r = await fetch("/plan/members/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mxid: e.target.mxid.value.trim() }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}

async function removeMember(mxid) {
  const r = await fetch("/plan/members/" + encodeURIComponent(mxid) + "/remove", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
}

async function leaveTeam() {
  const r = await fetch("/plan/members/leave", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
}

document.querySelector("#add-member")?.addEventListener("submit", reportFailure(addMember));
document.querySelectorAll("[data-leave-team]").forEach((button) => {
  button.addEventListener("click", reportFailure(leaveTeam));
});
document.querySelectorAll("[data-remove-member]").forEach((button) => {
	button.addEventListener("click", reportFailure(() => removeMember(button.dataset.mxid)));
});
