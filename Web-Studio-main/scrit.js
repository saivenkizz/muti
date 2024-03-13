document.getElementById('logoutButton').addEventListener('click', function() {
    alert('Logging out!');
    // Implement the logout functionality here.
    // For demonstration, it just shows an alert.
});
document.getElementById('sub').addEventListener('click', function() {
    const fileInput = document.getElementById('myfile');
    const file = myfile.files[0]; // Get the file from the input

    if (!file) {
        alert('Please select a file first!');
        return;
    }

    const formData = new FormData();
    formData.append('file', file); // The 'file' here should match the key expected by your server-side script

    fetch('your-server-endpoint/upload', { // Replace 'your-server-endpoint/upload' with your actual upload script URL
        method: 'POST',
        body: formData,
    })
    .then(response => {
        if (response.ok) {
            return response.json(); // Assuming the server responds with JSON
        } else {
            throw new Error('Upload failed');
        }
    })
    .then(data => {
        console.log(data); // Handle success response
        alert('Upload success!');
    })
    .catch(error => {
        console.error(error);
        alert('Upload failed: ' + error.message);
    });
});
