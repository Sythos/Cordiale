# Encrypted queries: user guide

This guide shows how to start and use an encrypted private chat in Cordiale.
It does not explain how the protocol works.
The technical rules are in [e2e-contract.md](e2e-contract.md).

All nicks and codes in this guide are dummy data.

## 1. Start an encrypted query

A normal query is a clear text chat. Cordiale does not encrypt it.

> **Warning:** Opening or selecting a normal query does not start E2E.
> E2E starts only after you select **Start encrypted chat**.

To start an encrypted chat:

1. Open the normal query with the peer, for example `alice_example`.
2. Look at the side pane on the right of the query.
3. Select **Start encrypted chat**.
4. Read the question. It says that the peer needs a compatible client.
5. Select **Ask**. To stop, select **Cancel**.
6. Wait. The banner says that Cordiale waits for the peer to accept.
7. When the peer accepts, select **Open encrypted chat**.

The peer sees a request. The peer selects **Accept** or **Decline**.
If you receive a request, you see the same two buttons in your query.
You can select **Cancel request** while you wait.
A request that nobody answers expires after 24 hours.
After a refusal or an expiry, select **Try again** or **Dismiss**.

### Two separate queries

After the peer accepts, you have two queries for the same person:

- `alice_example` is the normal query. It stays clear text.
- `🔒alice_example` is the locked query. It is the encrypted chat.

The two queries have separate history. Cordiale does not copy messages
from one query to the other.

Each query is a separate entry in the window list. Look for the lock symbol.

| You want to send | Select this query | Cordiale sends it |
| --- | --- | --- |
| A clear text message | `alice_example` | In clear text |
| An encrypted message | `🔒alice_example` | Encrypted |

The locked query never sends clear text.
If Cordiale cannot encrypt a message, it does not send the message.
It shows an error.

If the locked query exists, select **Open encrypted chat** in the normal query.
Cordiale opens the locked query and sends no new request.

## 2. Read the status

A banner at the top of the locked query shows the state of the chat.
The banner text is, for example, "End-to-end encryption is active."

### What the lock means

The lock means that the messages in this query are encrypted between
the devices of the two users. The server and the IRC network carry the
encrypted data. They cannot read the text.

### Encrypted connection and verified identity

These are two different things.

- **Encrypted** means that nobody on the way can read the messages.
- **Verified** means that you checked that the key belongs to the real person.

An encrypted chat with an unverified peer protects against
a reader on the way. It does not protect against a person who
pretends to be your peer. Verify the peer to be sure.

### Check a peer identity

Use the SAS code. SAS means short authentication string.

1. Open the locked query.
2. Select **Show SAS code**.
3. Contact the peer on a different channel. Use a phone call or a meeting.
4. Compare the code. Both of you must see the same code.
5. If the codes are the same, select **They match**.
6. If the codes are different, select **They do not match**.

If the codes match, Cordiale saves the contact as verified.
If the codes do not match, the contact stays unverified.
Do not trust the chat. Do not send private data.
To close the code without a result, select **Cancel**.

### A key changes

If the banner says that the master key of the contact changed, the identity
of the peer is different from the one you knew.

> **Warning:** Do not trust the chat until you check it with the peer.

1. Stop sending private data in the locked query.
2. Contact the peer on a different channel.
3. Ask if the peer reset the identity or changed the device.

The current build cannot show the SAS code while this warning is active.
The current build has no action that accepts a changed key.
This feature is unavailable.
Do not send private data in this locked query.
Use a different channel to talk to the peer.

## 3. Use more than one device

You can use the same E2E identity on more than one device.
Cordiale calls this pairing.
Pairing works with one network at a time.
The server must support pairing. If it does not, Cordiale shows a message.

### Add a device

Use the first device, which holds the identity key, and the new device.

1. On the first device, type `/e2e pair`.
2. Cordiale shows the **Pair a new device** window with a QR code and a pairing code.
3. On the new device, type `/e2e join` and the pairing link or the code.
4. Both devices show a short check code, for example `42`.
5. Compare the check code on both devices.
6. If the codes are the same, type `/e2e code 42` on each device that asks for it.
   Use the real code, not the example.
7. Wait for the message "The new device is paired."

> **Warning:** Do not post the QR code or the pairing link. A person who has
> them can pair a device until they expire.

If the codes are not the same, the pairing stops. Start again.
To stop a pairing, type `/e2e cancel`.
A pairing that takes too long expires. Start again.

> **Note:** The current build has no screen that reads the QR code with
> a camera. Use the link or the code that Cordiale shows.

### When Cordiale sends a copy to your other devices

When you send an encrypted message from one device, Cordiale also
sends a copy to your other trusted devices. Your other devices show it in
the locked query as a sent message. Cordiale sends a copy only to devices
that are in your own device list.

### List and remove devices

- Type `/e2e devices` to see the device ids.
- Type `/e2e revoke <id>` to remove a device. Use the id from the list.

### Lose a device

Only a device that holds the master key can remove another device.
A device that you added with pairing does not hold the master key.

If a device that holds the master key is still with you:

1. Type `/e2e revoke <id>` on that device. Use the id of the lost device.
2. Verify your peers again if they ask.

If you lost the only device that holds the master key, you cannot remove
the lost device. The lost device stays authorized.
Use the identity reset procedure in the next section.

### Lose all devices with the identity key

No device can send for you now. Nobody can restore the key for you.
Do not ask another person for a key or a recovery secret.

1. Type `/e2e reset`. Cordiale asks you to confirm.
2. To confirm, type `/e2e reset yes`.

Cordiale deletes the identity of this device on the server and on the device.
The locked query cannot send now.

3. Close Cordiale and open it again, or sign out and sign in again.
   Cordiale then makes a new identity.
4. Your peers see a key warning. They cannot accept the new key in the current build.
   Tell them on a different channel that you reset the identity.

## 4. Offline delivery

Cordiale does not send encrypted text as clear text, ever.

### The peer is offline

The server can keep an encrypted message for a peer who is offline.
The peer reads it when a compatible client connects again.

### Accepted and received are different

- **Accepted** means that the server took the message.
- **Received** means that a device of the peer got it.

Cordiale can show a message as sent when the server accepted it.
This does not prove that the peer read it. If the server drops
the message later, Cordiale marks the row as failed.

### Waiting for keys

If Cordiale has no keys for the peer yet, it keeps your message for a short time.
In the current build:

- A message waits at most 90 seconds for the keys.
- At most 16 messages wait for one peer.
- If the keys do not come in time, the message is not sent.
  The banner says that the last message expired. Send the message again.

When the banner shows **Ask for keys again**, select it to ask again.
The banner shows this button when the keys are missing, when the key request
failed, when the peer could not read the last message, or when the peer nick
is not online.
Cordiale asks for keys at most once a minute for each peer.

### Expiry of a stored message

A stored message for an offline device can expire on the server.
The server sets the time. Cordiale does not promise a time.
Do not rely on a stored message for a long time.
If the message matters, ask the peer if they got it.

## 5. Limits

- E2E is only for private queries. Channel messages are not E2E.
- The server and the IRC network can still see who talks to whom.
  They can see when you talk and how large the messages are.
- Cordiale sends a long message in parts, with pauses. A long paste takes time.
  Encryption makes a message larger. A very long message can be too large
  to send. Cordiale then sends nothing. Divide a very long text into shorter messages.
- Encrypted queries take plain text only. Files and media are not available
  in an encrypted query. Cordiale shows "An encrypted chat takes plain text
  only" and sends nothing.
- A line that starts with a slash is a command, not a message. Cordiale runs
  it as in a normal query and never sends it to the peer. Commands such as
  `/ns identify` keep their normal visibility: E2E does not protect them from
  the server or the service. `/me` stays inside the encrypted chat and shows
  as an action on the other device. To send a text that starts with a slash,
  type two slashes: `//text`.
- A peer without a compatible client cannot read encrypted messages.
  A plain IRC client can show control text that looks like random characters.
  This text is not a message.
- An unverified peer has encryption but no proof of identity. See section 2.

## 6. Fix common problems

### You cannot start an encrypted query

- Check that you are in a normal private query and not in a channel.
- Check that the server supports encrypted chat requests.
  Cordiale shows a message if it does not.
- Check that this device has an E2E identity for the network.
  The message "This device has no E2E identity for this network" says it has not.
- Check that the peer is online and uses a compatible client.
- If you reset the identity, close Cordiale and open it again. Cordiale makes a new identity.

### The peer does not answer

- Read the banner. It says if Cordiale waits for the keys or for the peer.
- Wait. A request expires after 24 hours.
- If the banner shows **Ask for keys again**, select it. Wait one minute between tries.
- If the banner says that the last message expired, send the message again.
- Check that the peer nick is online. The banner says when it is not.
- Ask the peer on another channel if they use a compatible client.
- Select **Cancel request** or **Try again** if needed.

### A key warning appears

- Do not trust the chat.
- Follow the steps in "A key changes" in section 2.

### Safety rules

> **Warning:** Never send a private key, a password, or a recovery code to
> another person. This includes the QR code and the pairing link.
> Nobody who helps you needs them.
