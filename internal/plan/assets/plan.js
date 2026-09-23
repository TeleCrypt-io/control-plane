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
  await reportMemberResponse(r);
  return false;
}

async function removeMember(mxid) {
  const r = await fetch("/plan/members/" + encodeURIComponent(mxid) + "/remove", { method: "POST" });
  await reportMemberResponse(r);
}

async function leaveTeam() {
  const r = await fetch("/plan/members/leave", { method: "POST" });
  await reportMemberResponse(r);
}

async function reportMemberResponse(response) {
  if (response.ok) {
    location.reload();
    return;
  }
  alert(await response.text());
  if (response.headers.get("X-TeleCrypt-Membership-Changed") === "true") location.reload();
}

document.querySelector("#add-member")?.addEventListener("submit", reportFailure(addMember));
document.querySelectorAll("[data-leave-team]").forEach((button) => {
  button.addEventListener("click", reportFailure(leaveTeam));
});
document.querySelectorAll("[data-remove-member]").forEach((button) => {
	button.addEventListener("click", reportFailure(() => removeMember(button.dataset.mxid)));
});
