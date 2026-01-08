# evertouch Security Guide  
**How your data stays private, and what you should know**

Evertouch is built so you can confidently store and share your contact details without worrying that someone else can read them.

This guide explains, in plain language, how evertouch protects you.

---

## 1) The main promise

✅ **Your contact data is encrypted before it leaves your device.**  
✅ **Only the people you share with can decrypt it.**  
✅ **The server stores only encrypted data and cannot read it.**

This is called **end-to-end encryption (E2E)**.

---

## 2) What evertouch encrypts

Evertouch encrypts all sensitive information, including:

- phone numbers  
- email addresses  
- home address  
- work address  
- social links  
- notes (if supported)  
- any custom contact fields  

When you update your contact details, evertouch encrypts the new version before uploading it.

---

## 3) What evertouch keeps public (and why)

To make the app usable, some basic information may be public by design:

- your display name  
- your headline (optional)  
- your public key (used for encryption)

This is similar to how messaging apps work:  
people need a way to identify who is sending a request.

You can choose to keep these public details minimal.

---

## 4) What the server can and cannot see

### The server *can* see:
- that a user exists  
- that an encrypted message was uploaded  
- timestamps (for syncing updates)  
- which encrypted card ID was requested (for public live-cards)

### The server *cannot* see:
- your contact fields  
- the content of your profile  
- your phone number or email address  
- your shared “Pools” content  
- the secret used to decrypt live-cards  
- what anyone actually sees after decryption  

In simple terms:  
**we store encrypted blobs, not your contact information.**

---

## 5) How “Pools” protect you

Pools let you decide what you share, with different groups of people:

- **Work** → business card fields only  
- **Friends** → more personal fields  
- **Family** → everything you choose  

Pools are enforced by encryption:

- evertouch encrypts a different version of your profile for each Pool.
- A “Work” contact cannot decrypt your “Family” fields.

This means even if someone receives your work card, they cannot access personal details that were never shared.

---

## 6) Live Cards (how links stay secure)

Evertouch lets you share an always up-to-date contact card as a link.

Example format: https://evertouch.app/card/#s=

Important part:
- the `#secret` section is **never sent to the server**
- it stays only inside the viewer’s browser
- decryption happens locally, on the viewer’s device

This is how live-cards remain end-to-end encrypted.

---

## 7) What happens if someone forwards your link?

A live-card is similar to a physical business card:
- anyone who has it can view it

So if someone forwards your link, the forwarded person can also open it.

That is why evertouch recommends:
- sharing only minimal fields in “Work” cards  
- using revocation and expiry for sensitive links (if enabled)  

You always stay in control.

---

## 8) Revoking access

You can revoke:
- live-cards  
- connections  

When you revoke:
- the server stops delivering encrypted updates
- live-cards stop working
- future access is blocked instantly

Revocation is your emergency brake.

---

## 9) Device security: your phone matters

Evertouch uses strong encryption, but your security still depends on your device.

We recommend:
- Face ID / Touch ID enabled  
- a strong device passcode  
- updated iOS version  
- avoid jailbroken devices  

If someone unlocks your phone, they may access evertouch like any other app.

---

## 10) What happens if you lose your phone?

Your private key is stored securely on-device.

To allow recovery, evertouch can store an encrypted backup of your private key on the server.

This backup:
- is encrypted with a key derived from your password  
- cannot be decrypted without your password  
- is useless to attackers on its own  

When you reinstall evertouch:
- you log in
- the app downloads your encrypted key backup
- your password decrypts it locally
- your identity is restored

**We cannot recover your encryption keys for you if you forget your password.**

---

## 11) What if you forget your password?

Because evertouch uses end-to-end encryption, we cannot reset your encryption identity without losing access to your old data.

If you forget your password:
- you may still be able to reset login
- but your encrypted identity may need to be regenerated
- old encrypted connections may become unreadable  

This is the tradeoff of strong privacy.

We will guide you clearly if this happens.

---

## 12) Open source transparency

We want you to be able to verify our security claims.

That is why the critical security parts of evertouch are published on GitHub.

Security-minded people can:
- review the implementation  
- challenge assumptions  
- report issues  
- debate and improve the design publicly  

This is how trust should be earned:
**not by promises, but by transparency.**

---

## 13) What evertouch does NOT do

Evertouch does not:
- sell your data  
- run ads  
- track you across the web  
- scan your contact content  
- build shadow profiles  
- collect your address book by default  
- store your contact details in plaintext  

---

## 14) Summary

Evertouch is designed so that:

✅ your sensitive contact data stays encrypted  
✅ only people you choose can decrypt it  
✅ the server cannot read your information  
✅ you can revoke access at any time  
✅ security claims can be verified publicly  

Your identity stays yours.

---

## Questions?

If you want a deeper technical explanation, you can open:

**Settings → Security → Technical details**

Or review the open source
