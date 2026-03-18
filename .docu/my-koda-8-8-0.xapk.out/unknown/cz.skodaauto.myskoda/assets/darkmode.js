document.addEventListener('DOMContentLoaded', () => {
    let file = "light";

    let parts = location.search.split('\?')
    let lastIndex = parts.length - 1
    if (parts[lastIndex] === "dark") {
        file = "dark"
    }

    const styleSheet = document.createElement("link");
    styleSheet.setAttribute('rel', 'stylesheet');
    styleSheet.setAttribute('href', `${file}.css`)
    document.head.appendChild(styleSheet)
});
