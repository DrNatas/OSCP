# Web Requests
## HTTP
The *Hyper Text Transport Protocol* is *application* level for accessing web resources.\
The default port is *80*.

*FQDN*: Fully Qualified Domain Name


### URL
The *Uniform Resource Locator* is how resources are accessed by HTTP.\
Example: **http://admin:password@domain.tld:80/dashboard.php?login=treu#status**\
Breakdown:
- http:// is the ***scheme*** used to identify the protocol being accessed by the client
- admin:password is the ***user***, an optional component that contains the credentials (separated by a colon :) used to authenticate to the host
- domain.tld is the ***host*** and can be a hostname or an IP address
- 80 is the ***port*** 
- /dashboard.php is the ***path*** for a file or directory (defaulting to index.html)
- ?login=true is the ***query string*** which consists of a parameter (login) and a value (true) which can have multiple connected by *&*
- #status is a ***fragment*** which are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page)

> Not all components are required to access a resource. The main mandatory fields are the scheme and the host, without which the request would have no resource to request.

---
### HTTP Flow
The user enters the URL into a browser to access it.\
From there, a *Domain Name reSolution* or *DNS* request is sent to the *DNS* server in order to resolve the domain to an IP.\
The DNS server looks up the domain's IP and returns it.

> Note: the */etc/hosts* file is used first, thenthe DNS server and so on


Once the browser gets the IP address linked to the requested domain, it sends a GET request to the default HTTP port (e.g. 80), asking for the root / path.\
Then, the web server receives the request and processes it\
By default, servers are configured to return an index file when a request for / is received.

In this case, the contents of index.html are read and returned by the web server as an HTTP response and is rendered.\
A successful response has the ***status code: 200***

### CURL
*Client URL* allows us to send web request through the command line through various protocols.\
HTTP is one of them.
```Bash
# Download a file and output content
# -S silences status
curl -S -O domain.tld/index.html
```
 cURL does not render the HTML/JavaScript/CSS code, unlike a web browser, but prints it in its raw format.

---
## HTTPS
HTTP *Secure* on port 443.\
It is designed to prevent man-in-the-middle attacks.

Here, HTTPS does a *key exchange* using *SSL Certificates*

### CURL HTTPS
Here, we need to provide or skip certificates when using HTTPS.
```Bash
# -k skips cert check
curl -k https://domain.tld
```

---
## REQUESTS & RESPONSES
Example request:
```Bash
GET /users/login.html HTTP/1.1
```
Breakdown:
- GET is the *method*
- /users/login.html is the *path*
- HTTP/1.1 is the *version*

> Note: HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests.
>> HTTP version 2.X, on the other hand, sends requests as binary data in a dictionary form.

Example response:
```Bash
HTTP/1.1 200 OK
```
Breakdown:
- 200 OK is the *response code*

There are many codes that can be received and they usually tell you with enough verbosity what is happening.\
Check out this cute [site](https://http.cat/) to see examples and what they mean.

When we use curl, we can add *-v* for verbose to see the request and response:
```Bash
curl domain.tld -v
```
```Bash
[us-academy-5][10.10.14.2][htb-ac-642405@htb-2gebgunznv][~]
 []$ curl 83.136.252.206:42782/download.php -v
*   Trying 83.136.252.206:42782...
* Connected to 83.136.252.206 (83.136.252.206) port 42782 (#0)
> GET /download.php HTTP/1.1
> Host: 83.136.252.206:42782
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Fri, 10 Jan 2025 00:37:38 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Description: File Transfer
< Cache-Control: no-cache, must-revalidate
< Expires: 0
< Content-Disposition: attachment; filename="flag.txt"
< Content-Length: 20
< Pragma: public
< Content-Type: text
< 
* Connection #0 to host 83.136.252.206 left intact
```
> We can also see this in the web browser developer tools!\
> Simply go to the *Network* tab and you can filter requests

### Headers
#### General
These can be in both requests and responses and *describe the message* as opposed to the contents.\
This cna be something like the date, connection status (i.e. *keep-alive*), etc.

#### Entity
These are in both requests and responses and *describe the content* of POST/PUT requests (typically).\
Some examples include *content-type*, *content-length*, *content-encoding*, etc.

#### Request
These are of course request specific and can be something like *host*, *user-agent*, *cookie*, etc.

#### Resposne
These are response specific and can be something like *server*, *www-authenticate*, *set-cookie*, etc.

#### Security
These contain speicifc rules and policies for the browser when accessing the web page.\
Some examples are *content-security-policy*, *strict-transport-security*, etc.

#### curl example
Here, we can do a *-A* to add a *User-Agent*:
```Bash
curl https://domain.tld -A 'Mozilla/5.0'
```
---
## Methods and Codes
### Request
The following methods are available:
- GET: Request a specific resource with query strings such as *param=value*
- POST: Send data to a server such as text, files, and other binary data
- HEAD: Requests GET return to check response length
- PUT: Creates a resource on the server
- DELETE: Deletes a resource on the server
- OPTIONS: Returns server information such as methods it accepts
- PATCH: Applies partial modification to resource at specified location

---
### Response
There are various response types that can indicate what happened with a request.
The following is a basic overview:
- 1xx: Informational
- 2xx: Success
- 3xx: Redirects
- 4xx Client Failure
- 5xx: Server Failure

> *200 OK* is a popular one you'll see
>> Just like *404 not found*

---
#### GET
A GET request retrieves remote resource hosted at the target URL.\
A browser is essentially doing a GET anyime it loads a web page, neat!

##### Basic AUTH
HTTP allows for basic authentication that is hadnled directly by the webserver and not necessarily by the application.\
This involves your typical credential pair, ie. *admin:admin*, into a form.

> An auth failure gives us a *401 AUthorization required*

Here is an example of how to pass that information using CURL:
```Bash
curl -v http://admin:admin@<SERVER_IP>:<PORT>/
```
Or rather we do a base64 encoded version:
```Bash
GNTSQID@htb[/htb]$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
```
> This is older. A more modern example might be something like *JWT* or JSON Web TOken.

---
#### POST
Unlike GET where parameters are in the URL, POST has then as part of the HTTP request body.\
This allows for smaller logs, less encoding, and more data by maximizing length.

##### Auth
```Bash
curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```
Remember the *Set-Cookie* header we talked about earlier?\
This is one way that authentication persists in our browsers:
```Bash
GNTSQID@htb[/htb]$ curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/ -i

HTTP/1.1 200 OK
Date: 
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1; path=/

...SNIP...
        <em>Type a city name and hit <strong>Enter</strong></em>
...SNIP...
```

We can use a cookie when we curl quite simply:
```Bash
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/

# Or as a header
curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```

##### JSON Data
Most post request may require extensive headers.\
Here is an example of one:
```Bash
curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php
```
```JSON
{"search": "London"}
```

---
## CRUD API
### API
APIs or *Application Programming Interfaces* are a common way of interacting with applications.\
There are several types that accomplish distinct tasks.

### CRUD
CREATE: POST\
READ: GET\
UPDATE: PUT\
DELETE: DELETE

All of these are part of the CRUD API for *database interaction*.

#### READ
Reading using an API is the first fundamental task.\
We want to test the fetching of information.

#### CREATE
This is us adding a new entry.\
Using JSON, we want to add to a table.\
Don't forget to add the *Content-Type*!

#### UPDATE
This is a new one for us.\
It specifically modifies an entry that already exitst. 

```Bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

#### DELETE
This one is a bit more obvious




