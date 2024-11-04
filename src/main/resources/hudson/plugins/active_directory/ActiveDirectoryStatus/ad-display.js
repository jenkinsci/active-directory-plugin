function display(r) {
    r.domainHealth.forEach(function(domainHealth) {
        var tr = document.createElement('tr');
        var td1 = document.createElement('td');
        var td2 = document.createElement('td');
        var td3 = document.createElement('td');
        var td4 = document.createElement('td');
        var text1 = document.createTextNode(domainHealth.host + ' / ' + domainHealth.ipAddress);
        var text2 = document.createTextNode(domainHealth.canLogin);
        var text3 = document.createTextNode(domainHealth.pingExecutionTime + ' ms');
        var text4 = document.createTextNode(domainHealth.loginExecutionTime  + ' ms');
        td1.appendChild(text1);
        td2.appendChild(text2);
        td3.appendChild(text3);
        td4.appendChild(text4);
        tr.appendChild(td1);
        tr.appendChild(td2);
        tr.appendChild(td3);
        tr.appendChild(td4);
        document.getElementById("demo").appendChild(tr);
    });
}
