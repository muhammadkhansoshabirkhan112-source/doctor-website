// ==========================
// Appointment form
// ==========================

document.addEventListener("DOMContentLoaded", () => {
    const appointmentForm = document.getElementById("appointmentForm");
    const appointmentMessage = document.getElementById("appointmentMessage");
    const submitButton = document.getElementById("submitAppointment");

    if (!appointmentForm) return;

    appointmentForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const formData = new FormData(appointmentForm);
        const appointment = {
            name: (formData.get("name") || "").trim(),
            phone: (formData.get("phone") || "").trim(),
            email: (formData.get("email") || "").trim(), // optional
            date: formData.get("date") || "",
            hospital: formData.get("hospital") || ""
        };

        if (submitButton) {
            submitButton.disabled = true;
            const label = submitButton.querySelector("span:first-child");
            if (label) label.innerText = "Submitting...";
        }
        if (appointmentMessage) {
            appointmentMessage.innerText = "";
            appointmentMessage.className = "";
        }

        try {
            const response = await fetch("/api/appointments", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(appointment)
            });

            const result = await response.json();
            if (!response.ok || !result.success) {
                throw new Error(result.message || "Unable to submit appointment.");
            }

            if (appointmentMessage) {
                appointmentMessage.innerText = "✓ Appointment request submitted successfully. We will contact you to confirm your appointment.";
                appointmentMessage.className = "appointment-success";
            } else {
                alert("✅ Appointment request submitted successfully!");
            }
            appointmentForm.reset();
        } catch (error) {
            console.error("Appointment submission error:", error);
            if (appointmentMessage) {
                appointmentMessage.innerText = "Unable to submit your appointment right now. Please try again or call 0319 5049455.";
                appointmentMessage.className = "appointment-error";
            } else {
                alert("❌ Something went wrong. Please try again.");
            }
        } finally {
            if (submitButton) {
                submitButton.disabled = false;
                const label = submitButton.querySelector("span:first-child");
                if (label) label.innerText = "Request Appointment";
            }
        }
    });
});

// ==========================
// Mobile menu
// ==========================
function toggleMenu() {
    const menu = document.getElementById("mobileMenu");
    if (!menu) return;
    menu.classList.toggle("active");
}

// ==========================
// Appointment button
// ==========================
function openAppointment() {
    const appointmentSection = document.getElementById("appointment");
    if (appointmentSection) {
        appointmentSection.scrollIntoView({ behavior: "smooth" });
    }
}

// ==========================
// Chatbot toggle
// ==========================
function toggleChat() {
    const chatbot = document.getElementById("chatbot");
    if (!chatbot) return;
    const isOpen = chatbot.classList.toggle("active");
    chatbot.style.display = isOpen ? "flex" : "none";
}

// Keep the appointment date from allowing dates in the past.
document.addEventListener("DOMContentLoaded", () => {
    const dateInput = document.getElementById("appointmentDate");
    if (dateInput) {
        const today = new Date();
        const yyyy = today.getFullYear();
        const mm = String(today.getMonth() + 1).padStart(2, "0");
        const dd = String(today.getDate()).padStart(2, "0");
        dateInput.min = `${yyyy}-${mm}-${dd}`;
    }
});

// ==========================
// Chatbot quick replies
// ==========================
function chatReply(type) {
    const chatBody = document.getElementById("chatBody");
    if (!chatBody) return;

    let reply = "";
    if (type === "appointment") {
        reply = "You can request an appointment using the appointment form on this page.";
    } else if (type === "services") {
        reply = "Dr. Tanzil provides gastroenterology, internal medicine, digestive health, liver disease and endoscopy services.";
    } else if (type === "hospital") {
        reply = "Dr. Tanzil consults at Fauji Foundation Hospital, Safari OPD Complex, and Attock Oil Refinery Hospital in Rawalpindi. Please check the Hospitals & Locations section.";
    }

    const message = document.createElement("div");
    message.className = "bot-message";
    message.innerText = reply;
    chatBody.appendChild(message);
    chatBody.scrollTop = chatBody.scrollHeight;
}

// ==========================
// Send chat message
// ==========================
function sendMessage() {
    const input = document.getElementById("chatInput");
    const chatBody = document.getElementById("chatBody");
    if (!input || !chatBody) return;

    const text = input.value.trim();
    if (!text) return;

    const userMessage = document.createElement("div");
    userMessage.className = "bot-message";
    userMessage.innerText = "You: " + text;
    chatBody.appendChild(userMessage);
    input.value = "";

    setTimeout(() => {
        const reply = document.createElement("div");
        reply.className = "bot-message";
        reply.innerText = "Thank you for your message. Please contact the clinic at 0319 5049455 for assistance.";
        chatBody.appendChild(reply);
        chatBody.scrollTop = chatBody.scrollHeight;
    }, 500);
}
