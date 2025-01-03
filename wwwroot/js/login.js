async function fetchUserIp() {
    console.log("Rozpoczęto pobieranie adresu IP użytkownika z API...");
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        console.log("Pobrany adres IP z API:", data.ip);
        return data.ip;
    } catch (error) {
        console.error("Błąd podczas pobierania adresu IP z API:", error);
        return "Unknown";
    }
}

document.getElementById('loginForm').addEventListener('submit', async function (e) {
    const userIpField = document.getElementById('userIp');
    if (userIpField.value === "Unknown") {
        e.preventDefault(); // Zatrzymanie przesyłania formularza
        const userIp = await fetchUserIp(); // Pobierz adres IP z API
        userIpField.value = userIp; // Wypełnij pole
        console.log("Przypisano adres IP do pola formularza:", userIp);
        this.submit(); // Wyślij formularz po wypełnieniu pola
    } else {
        e.preventDefault(); // Zatrzymanie przesyłania formularza
    }
});
