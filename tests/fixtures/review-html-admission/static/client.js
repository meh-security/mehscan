fetch("/api/logs")
  .then(response => response.json())
  .then(data => {
    document.getElementById("logs").innerHTML = data.logs[0]
  })
