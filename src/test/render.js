
var page = require('webpage').create();
var system = require('system');
var url = system.args[1];
var requests = [], responses = [];
var resp_code = {};

page.onResourceRequested = function(request) {
  //console.log('Request ' + JSON.stringify(request, undefined, 4));
  //console.log('Request: ' + request.url);
  requests.push(request.url);
};
page.onResourceReceived = function(response) {
  //console.log('Receive ' + JSON.stringify(response, undefined, 4));
  //console.log('Response: ' + response.url + ' Status: ' + response.status);
  if (!(response.status in resp_code)) 
    resp_code[response.status] = 0;
  resp_code[response.status]++;
  if (requests.indexOf(response.url) >= 0 && response.status == 200 && responses.indexOf(response.url) == -1) {
    responses.push(response.url);
  }
};
page.onError = function(msg, trace) {
  var msgStack = ['ERROR: ' + msg];
  if (trace && trace.length) {
    msgStack.push('TRACE:');
    trace.forEach(function(t) {
      msgStack.push(' -> ' + t.file + ': ' + t.line + (t.function ? ' (in function "' + t.function + '")' : ''));
    });
  }
  // uncomment to log into the console 
  //console.error(msgStack.join('\n'));
};

begin = Date.now();
page.open(url, function(status) {
  end = Date.now();
  console.log("Loading " + url);
  console.log("Status: " + status);
  console.log("Time elasped: " + (end - begin) + " msec");
  console.log("Requests sent: " + requests.length);
  console.log("Responses received: " + JSON.stringify(resp_code) + " (" + responses.length + "/" + requests.length + ")");
  //if(status === "success") {
    //var pngfile = url.slice(url.indexOf("://")+3).split("/")[0] + ".png";
    //page.render(pngfile);
  //}
  /*
  for (var u in requests) {
    if (responses.indexOf(requests[u]) == -1) {
        console.log(requests[u]);
    }
  }
  */
  phantom.exit();
});
