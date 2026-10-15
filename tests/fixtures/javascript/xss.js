// Hand-written vulnerable fixture (DOM XSS). Never executed.
function show(userInput) {
  document.getElementById("out").innerHTML = userInput;
}
