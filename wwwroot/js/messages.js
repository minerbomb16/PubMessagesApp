let skip = 10;
let loading = false;
let allMessagesLoaded = false;

window.onscroll = async () => {
    if (allMessagesLoaded || loading) return;

    if (window.innerHeight + window.scrollY >= document.body.offsetHeight) {
        loading = true;
        try {
            const response = await fetch(`/Messages?skip=${skip}&take=10`);
            if (response.ok) {
                const newMessages = await response.text();

                if (newMessages.trim() === "") {
                    allMessagesLoaded = true;
                    document.getElementById('no-more-messages').style.display = "block";
                } else {
                    document.querySelector('#message-list').innerHTML += newMessages;
                    skip += 10;
                }
            } else {
                console.error("Błąd podczas pobierania wiadomości.");
            }
        } catch (error) {
            console.error("Wystąpił błąd:", error);
        } finally {
            loading = false;
        }
    }
};
