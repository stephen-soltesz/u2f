  function serverError(data) {
    console.log(data);
    console.log('Server error code ' + data.status + ': ' + data.responseText);
  }

  function checkError(resp) {
    if (!('errorCode' in resp)) {
      return false;
    }
    if (resp.errorCode === u2f.ErrorCodes['OK']) {
      return false;
    }
    var msg = 'U2F error code ' + resp.errorCode;
    for (name in u2f.ErrorCodes) {
      if (u2f.ErrorCodes[name] === resp.errorCode) {
        msg += ' (' + name + ')';
      }
    }
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    console.log(msg);
    return true;
  }

  function u2fRegistered(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/registerResponse', JSON.stringify(resp)).success(function(data) {
      console.log('Success');
			result = JSON.parse(data);
			console.log(result);
    }).fail(serverError);
  }

  function register() {
    $.getJSON('/registerRequest').success(function(req) {
      console.log(req);
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
      console.log('\nTouch key to register!\n');
    }).fail(serverError);
  }

  function u2fSigned(resp) {
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    $.post('/signResponse', JSON.stringify(resp)).success(function(data) {
      console.log('Success');
			result = JSON.parse(data);
			console.log(result);
			$('#result').text(JSON.stringify(result, null, 2));
    }).fail(serverError);
  }

  function sign() {
    // Find the message form in the DOM by id.
    const form = document.getElementById('message');

    // Get the form data and encode it to preserve spaces, new lines, and special characters.
    $.getJSON('/signRequest?message=' + encodeURIComponent(form.value)).success(function(req) {
      console.log(req);
      console.log('\nTouch key to sign!\n');
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    }).fail(serverError);
  }