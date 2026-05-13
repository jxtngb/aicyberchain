function login() {
  fetch("/login-ajax/", {
    method: "POST",
    body: JSON.stringify({
      username: username.value,
      password: password.value
    })
  }).then(r => r.json()).then(d => {
    if (d.status === "success") location.href = "/dashboard/";
    else error.innerText = "Invalid credentials";
  });