// function displayMessage(message, messageType) {
//   var messageContainer = document.getElementById('message-container');
//   messageContainer.innerHTML = ''; // Clear previous content
//   
//   var messageText = document.createElement('p');
//   messageText.innerText = message;
//   messageContainer.appendChild(messageText);
//   
//   var icon = document.createElement('i');
//   if (messageType === 'success') {
//     icon.className = 'fas fa-check-circle success-icon';
//   } else if (messageType === 'error') {
//     icon.className = 'fas fa-times-circle error-icon';
//   }
//   messageContainer.appendChild(icon);
//   
//   messageContainer.style.display = 'flex';
// }


function performSNMPScan(hostname) {
  var xhr = new XMLHttpRequest();
  var url = '/clientcare/snmp-scan/' + encodeURIComponent(hostname) + '/';
  xhr.open('GET', url, true);
  xhr.setRequestHeader('Content-type', 'application/json');

  displayPleaseWait(); // Show "Please wait" message before sending the request

  xhr.onload = function() {
    if (xhr.status === 200) {
      var response = JSON.parse(xhr.responseText);
      if (response.success) {
        displayMessage(response.message, 'success');
      } else {
        displayMessage(response.message, 'error');
      }
    } else {
      displayMessage('Error occurred during SNMP scan.', 'error');
    }
  };

  xhr.send(JSON.stringify({ hostname: hostname }));
}



function displayPleaseWait() {
  var messageContainer = document.getElementById('messageContainer');
  messageContainer.innerText = 'Please wait...';
  messageContainer.classList.remove('text-success');
  messageContainer.classList.remove('text-danger');
  messageContainer.classList.add('text-info');

  $('#messageModal').modal('show'); // Show the modal popup
}


function displayMessage(message, messageType) {
  var messageContainer = document.getElementById('messageContainer');
  messageContainer.innerText = message;

  if (messageType === 'success') {
    messageContainer.classList.add('text-success');
    messageContainer.classList.remove('text-danger');
  } else {
    messageContainer.classList.add('text-danger');
    messageContainer.classList.remove('text-success');
  }

  $('#messageModal').modal('show'); // Show the modal popup

  // Add a click event listener to the close button
  var closeButton = document.getElementById('closeButton');
  if (closeButton) {
  closeButton.addEventListener('click', function() {
    $('#messageModal').modal('hide'); // Hide the modal
    location.reload(); 
  });
}
}