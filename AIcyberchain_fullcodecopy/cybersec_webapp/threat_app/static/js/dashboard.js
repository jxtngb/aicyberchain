function detect() {
  fetch("/detect-ajax/", {
    method: "POST",
    body: JSON.stringify({ log: log.value })
  }).then(r => r.json()).then(d => {
    steps.innerHTML = "";
    d.steps.forEach(s => {
      steps.innerHTML += `<li>${s}</li>`;
    });

    result.innerText = d.detected ?
      "⚠️ THREAT DETECTED: " + d.attack :
      "Normal Traffic";
  });
}

function logout() {
  fetch("/logout/").then(() => location.href = "/");
}
function startMonitor() {
    fetch("/start-monitor/")
        .then(res => res.json())
        .then(data => {
            document.querySelector(".status-dot").classList.add("active");
            document.querySelector(".status-text").innerText = "Running";
        });
}

function stopMonitor() {
    fetch("/stop-monitor/")
        .then(res => res.json())
        .then(data => {
            document.querySelector(".status-dot").classList.remove("active");
            document.querySelector(".status-text").innerText = "Stopped";
        });
}
def dashboard(request):
    if not request.session.get("user"):
        return redirect("login")
    return render(request, "dashboard.html")
