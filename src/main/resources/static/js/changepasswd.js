function validateChangePasswordForm() {
    // Get the form field values
    const currentPassword = document.getElementById("currentPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    // Clear any previous error messages
    const errorMessages = document.getElementById("error-messages-client");
    const errorList = document.getElementById("error-list");
    errorList.innerHTML = ""; // Clear the list
    errorMessages.style.display = "none"; // Hide error container initially

    let hasError = false;

    // Check if any field is empty
    if (!currentPassword) {
        const errorItem = document.createElement("li");
        errorItem.textContent = "Current password is required.";
        errorList.appendChild(errorItem);
        hasError = true;
    }
    if (!newPassword) {
        const errorItem = document.createElement("li");
        errorItem.textContent = "New password is required.";
        errorList.appendChild(errorItem);
        hasError = true;
    }
    if (!confirmPassword) {
        const errorItem = document.createElement("li");
        errorItem.textContent = "Confirm password is required.";
        errorList.appendChild(errorItem);
        hasError = true;
    }

    // Check if the new password and confirm password match

    if (newPassword && confirmPassword && newPassword !== confirmPassword ) {
        const errorItem = document.createElement("li");
        errorItem.textContent = "New password and confirm password do not match.";


         errorList.appendChild(errorItem);


          hasError = true;
    }

    // Display errors if any
    if (hasError) {
        errorMessages.style.display = "block";

        return false;
    }


    return true;
}