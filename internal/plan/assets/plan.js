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

function requireHTTPSLink(value) {
  const link = new URL(value);
  if (link.protocol !== "https:" || link.username || link.password) {
    throw new Error("billing provider returned an unsafe link");
  }
  return link.href;
}

async function responseLink(response, field) {
  const body = await response.json();
  if (typeof body[field] !== "string") throw new Error("billing provider returned no link");
  return requireHTTPSLink(body[field]);
}

async function createPlan() {
  const r = await command("/plan/create", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
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

async function checkout(e) {
  e.preventDefault();
  const r = await command("/plan/checkout/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quantity: +e.target.quantity.value }),
  });
  if (!r.ok) { alert(await r.text()); return false; }
  location.assign(await responseLink(r, "payment_link"));
  return false;
}

async function openPortal() {
  // Open while the click still carries browser user activation. Waiting for the portal-session
  // request first lets browsers classify the later window.open as an unsolicited popup.
  const portal = window.open("about:blank", "_blank");
  if (!portal) { alert("The customer portal window was blocked."); return; }
  try {
    portal.opener = null;
    const r = await command("/plan/billing-portal/open", { method: "POST" });
    if (!r.ok) { portal.close(); alert(await r.text()); return; }
    portal.location.replace(await responseLink(r, "link"));
  } catch (error) {
    portal.close();
    alert(error.message);
  }
}

async function changeSeatCount(e) {
  e.preventDefault();
  const r = await command("/plan/seats/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quantity: +e.target.quantity.value }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}

document.querySelector("#create-plan")?.addEventListener("click", reportFailure(createPlan));
document.querySelector("#add-seat")?.addEventListener("submit", reportFailure(addSeat));
document.querySelector("#checkout")?.addEventListener("submit", reportFailure(checkout));
document.querySelector("#seat-count")?.addEventListener("submit", reportFailure(changeSeatCount));
document.querySelector("#open-portal")?.addEventListener("click", openPortal);
document.querySelectorAll("[data-remove-seat]").forEach((button) => {
  button.addEventListener("click", reportFailure(() => removeSeat(button.dataset.mxid)));
});
