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
  const r = await command("/api/plan", { method: "POST" });
  if (r.ok) location.reload(); else alert(await r.text());
}

async function addSeat(e) {
  e.preventDefault();
  const r = await command("/api/plan/seats", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mxid: e.target.mxid.value.trim() }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}

async function removeSeat(mxid) {
  const r = await command("/api/plan/seats/" + encodeURIComponent(mxid), { method: "DELETE" });
  if (r.ok) location.reload(); else alert(await r.text());
}

async function checkout(e) {
  e.preventDefault();
  const r = await command("/api/plan/checkout", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quantity: +e.target.quantity.value }),
  });
  if (!r.ok) { alert(await r.text()); return false; }
  try {
    location.assign(await responseLink(r, "payment_link"));
  } catch (error) {
    alert(error.message);
  }
  return false;
}

async function openPortal() {
  // Open while the click still carries browser user activation. Waiting for the portal-session
  // request first lets browsers classify the later window.open as an unsolicited popup.
  const portal = window.open("about:blank", "_blank");
  if (!portal) { alert("The customer portal window was blocked."); return; }
  try {
    portal.opener = null;
    const r = await command("/api/plan/portal", { method: "POST" });
    if (!r.ok) { portal.close(); alert(await r.text()); return; }
    portal.location.replace(await responseLink(r, "link"));
  } catch (error) {
    portal.close();
    alert(error.message);
  }
}

async function changeSeatCount(e) {
  e.preventDefault();
  const r = await command("/api/plan/seat-count", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ quantity: +e.target.quantity.value }),
  });
  if (r.ok) location.reload(); else alert(await r.text());
  return false;
}

document.querySelector("#create-plan")?.addEventListener("click", createPlan);
document.querySelector("#add-seat")?.addEventListener("submit", addSeat);
document.querySelector("#checkout")?.addEventListener("submit", checkout);
document.querySelector("#seat-count")?.addEventListener("submit", changeSeatCount);
document.querySelector("#open-portal")?.addEventListener("click", openPortal);
document.querySelectorAll("[data-remove-seat]").forEach((button) => {
  button.addEventListener("click", () => removeSeat(button.dataset.mxid));
});

async function changeSeatAccess(button) {
  button.disabled = true;
  try {
    const r = await command("/api/plan/seats/" + encodeURIComponent(button.dataset.mxid) + "/" + button.dataset.seatAccess, { method: "POST" });
    if (r.ok) { alert(button.dataset.seatAccess === "lock" ? "Member locked." : "Member unlocked."); location.reload(); }
    else alert(await r.text());
  } catch (error) {
    alert(error.message);
  } finally {
    button.disabled = false;
  }
}

document.querySelectorAll("[data-seat-access]").forEach((button) => {
  button.addEventListener("click", () => changeSeatAccess(button));
});
