// src/libCrypto.ts
async function stringToPublicKeyForEncryption(pkeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(pkeyBase64);
    const key = await window.crypto.subtle.importKey(
      "spki",
      keyArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the public key (for encryption) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the public key (for encryption) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPublicKeyForSignature(pkeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(pkeyBase64);
    const key = await window.crypto.subtle.importKey(
      "spki",
      keyArrayBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      true,
      ["verify"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the public key (for signature verification) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the public key (for signature verification) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPrivateKeyForEncryption(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      keyArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the private key (for decryption) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the private key (for decryption) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPrivateKeyForSignature(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      keyArrayBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      true,
      ["sign"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the private key (for signature) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the private key (for signature) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function publicKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64String(exportedKey);
}
async function privateKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64String(exportedKey);
}
async function generateasymmetricKeysForEncryption() {
  const keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  return [keypair.publicKey, keypair.privateKey];
}
async function generateasymmetricKeysForSignature() {
  const keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  return [keypair.publicKey, keypair.privateKey];
}
function generateNonce() {
  const nonceArray = new Uint32Array(1);
  self.crypto.getRandomValues(nonceArray);
  return nonceArray[0].toString();
}
async function encryptWithPublicKey(publicKey, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const cypheredMessageAB = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      messageToArrayBuffer
    );
    return arrayBufferToBase64String(cypheredMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Encryption failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Public key or message to encrypt is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function signWithPrivateKey(privateKey, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const signedMessageAB = await window.crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      messageToArrayBuffer
    );
    return arrayBufferToBase64String(signedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Signature failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Private key or message to sign is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function decryptWithPrivateKey(privateKey, message) {
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64StringToArrayBuffer(message)
    );
    return arrayBufferToText(decrytpedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for decryption");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Private key or message to decrypt is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage) {
  try {
    const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage);
    const messageInClearToArrayBuffer = textToArrayBuffer(messageInClear);
    const verified = await window.crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signedToArrayBuffer,
      messageInClearToArrayBuffer
    );
    return verified;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for signature verification");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Public key or signed message to verify is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function generateSymetricKey() {
  const key = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
  return key;
}
async function symmetricKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64String(exportedKey);
}
async function stringToSymmetricKey(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyArrayBuffer,
      "AES-GCM",
      true,
      ["encrypt", "decrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the symmetric key is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the symmetric key is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function encryptWithSymmetricKey(key, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ivText = arrayBufferToBase64String(iv);
    const cypheredMessageAB = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      messageToArrayBuffer
    );
    return [arrayBufferToBase64String(cypheredMessageAB), ivText];
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Encryption failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Symmetric key or message to encrypt is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function decryptWithSymmetricKey(key, message, initVector) {
  const decodedInitVector = base64StringToArrayBuffer(initVector);
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodedInitVector },
      key,
      base64StringToArrayBuffer(message)
    );
    return arrayBufferToText(decrytpedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for decryption");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Symmetric key or message to decrypt is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function hash(text) {
  const text2arrayBuf = textToArrayBuffer(text);
  const hashedArray = await window.crypto.subtle.digest("SHA-256", text2arrayBuf);
  return arrayBufferToBase64String(hashedArray);
}
var KeyStringCorrupted = class extends Error {
};
function arrayBufferToBase64String(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var byteString = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
}
function base64StringToArrayBuffer(b64str) {
  try {
    var byteStr = atob(b64str);
    var bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.log(`String starting by '${b64str.substring(0, 10)}' cannot be converted to a valid key or message`);
    throw new KeyStringCorrupted();
  }
}
function textToArrayBuffer(str) {
  var buf = encodeURIComponent(str);
  var bufView = new Uint8Array(buf.length);
  for (var i = 0; i < buf.length; i++) {
    bufView[i] = buf.charCodeAt(i);
  }
  return bufView;
}
function arrayBufferToText(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var str = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    str += String.fromCharCode(byteArray[i]);
  }
  return decodeURIComponent(str);
}

// src/messenger.ts
if (!window.isSecureContext) alert("Not secure context!");
var CasUserName = class {
  constructor(username) {
    this.username = username;
  }
};
var KeyRequest = class {
  constructor(ownerOfTheKey, publicKey, encryption) {
    this.ownerOfTheKey = ownerOfTheKey;
    this.publicKey = publicKey;
    this.encryption = encryption;
  }
};
var KeyResult = class {
  constructor(success, key, errorMessage) {
    this.success = success;
    this.key = key;
    this.errorMessage = errorMessage;
  }
};
var ExtMessage = class {
  constructor(sender, receiver2, content) {
    this.sender = sender;
    this.receiver = receiver2;
    this.content = content;
  }
};
var SendResult = class {
  constructor(success, errorMessage) {
    this.success = success;
    this.errorMessage = errorMessage;
  }
};
var HistoryRequest = class {
  constructor(agentName, index) {
    this.agentName = agentName;
    this.index = index;
  }
};
var HistoryAnswer = class {
  constructor(success, failureMessage, index, allMessages) {
    this.success = success;
    this.failureMessage = failureMessage;
    this.index = index;
    this.allMessages = allMessages;
  }
};
var globalUserName = "";
async function fetchCasName() {
  const urlParams = new URLSearchParams(window.location.search);
  const namerequest = await fetch("/getuser?" + urlParams, {
    method: "GET",
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  });
  if (!namerequest.ok) {
    throw new Error(`Error! status: ${namerequest.status}`);
  }
  const nameResult = await namerequest.json();
  console.log("Fetched CAS name= " + nameResult.username);
  return nameResult.username;
}
async function setCasName() {
  globalUserName = await fetchCasName();
  userButtonLabel.textContent = globalUserName;
}
setCasName();
function getOwnerName() {
  const path = window.location.pathname;
  const name = path.split("/", 2)[1];
  return name;
}
var ownerName = getOwnerName();
async function fetchKey(user, publicKey, encryption) {
  const keyRequestMessage = new KeyRequest(user, publicKey, encryption);
  const urlParams = new URLSearchParams(window.location.search);
  const keyrequest = await fetch("/getKey?" + urlParams, {
    method: "POST",
    body: JSON.stringify(keyRequestMessage),
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  });
  if (!keyrequest.ok) {
    throw new Error(`Error! status: ${keyrequest.status}`);
  }
  const keyResult = await keyrequest.json();
  if (!keyResult.success) alert(keyResult.errorMessage);
  else {
    if (publicKey && encryption) return await stringToPublicKeyForEncryption(keyResult.key);
    else if (!publicKey && encryption) return await stringToPrivateKeyForEncryption(keyResult.key);
    else if (publicKey && !encryption) return await stringToPublicKeyForSignature(keyResult.key);
    else if (!publicKey && !encryption) return await stringToPrivateKeyForSignature(keyResult.key);
  }
}
async function sendMessage(agentName, receiverName, messageContent) {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/sendingMessage/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(messageToSend),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    console.log(`Sent message from ${agentName} to ${receiverName}: ${messageContent}`);
    return await request.json();
  } catch (error) {
    if (error instanceof Error) {
      console.log("error message: ", error.message);
      return new SendResult(false, error.message);
    } else {
      console.log("unexpected error: ", error);
      return new SendResult(false, "An unexpected error occurred");
    }
  }
}
var userButtonLabel = document.getElementById("user-name");
var sendButton = document.getElementById("send-button");
var receiver = document.getElementById("receiver");
var messageG = document.getElementById("message");
var received_messages = document.getElementById("exchanged-messages");
var clearHistory = document.getElementById("clear-history");
clearHistory.addEventListener("click", clearingMessages);
function clearingMessages() {
  received_messages.textContent = "";
}
function stringToHTML(str) {
  var div_elt = document.createElement("div");
  div_elt.innerHTML = str;
  return div_elt;
}
function addingReceivedMessage(message) {
  const p = document.createElement("p");
  p.textContent = message;
  received_messages.append(p);
}
var lastIndexInHistory = 0;
async function refresh() {
  try {
    const user = globalUserName;
    const historyRequest = new HistoryRequest(user, lastIndexInHistory);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch(
      "/history/" + ownerName + "?" + urlParams,
      {
        method: "POST",
        body: JSON.stringify(historyRequest),
        headers: {
          "Content-type": "application/json; charset=UTF-8"
        }
      }
    );
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    const result = await request.json();
    if (!result.success) {
      alert(result.failureMessage);
    } else {
      lastIndexInHistory = result.index;
      if (result.allMessages.length != 0) {
        for (var m of result.allMessages) {
          let [b, sender, msgContent] = await analyseMessage(m);
          if (b) actionOnMessageOne(sender, msgContent);
          else console.log("Msg " + m + " cannot be exploited by " + user);
        }
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      console.log("error message: ", error.message);
      return error.message;
    } else {
      console.log("unexpected error: ", error);
      return "An unexpected error occurred";
    }
  }
}
var intervalRefresh = setInterval(refresh, 2e3);
var nonceTable = /* @__PURE__ */ new Map();
function actionOnMessageOne(fromA, messageContent) {
  const user = globalUserName;
  const textToAdd = `${fromA} -> ${user} : ${messageContent} `;
  addingReceivedMessage(textToAdd);
}
sendButton.onclick = async function() {
  const agentName = globalUserName;
  const receiverName = receiver.value;
  if (!receiverName) return;
  try {
    console.log("Etape 1 : " + agentName + " demande une session avec " + receiverName);
    const pkeyB = await fetchKey(receiverName, true, true);
    const contentToEncrypt = JSON.stringify(["1", agentName]);
    const encryptedMessage = await encryptWithPublicKey(pkeyB, contentToEncrypt);
    const sendResult = await sendMessage(agentName, receiverName, encryptedMessage);
    if (!sendResult.success) console.log("Erreur envoi Etape 1");
  } catch (error) {
    console.log("Erreur au d\xE9but du protocole : ", error);
  }
};
async function analyseMessage(message) {
  const agentName = globalUserName;
  try {
    if (message.receiver !== agentName) return [false, "", ""];
    const privKey = await fetchKey(agentName, false, true);
    const messageInClear = await decryptWithPrivateKey(privKey, message.content);
    const dataArray = JSON.parse(messageInClear);
    const index = parseInt(dataArray[0], 10);
    const senderName = message.sender;
    let contentToEncrypt = "";
    let encryptedMessage;
    let pkeyA, pkeyB;
    switch (index) {
      case 1:
        console.log("Etape 2 : " + senderName + " veut executer le protocole avec  " + message.receiver + ". Il g\xE9n\xE8re son nonceB.");
        const nonceB = generateNonce();
        nonceTable.set(nonceB, senderName);
        pkeyA = await fetchKey(senderName, true, true);
        contentToEncrypt = JSON.stringify(["2", agentName, nonceB]);
        encryptedMessage = await encryptWithPublicKey(pkeyA, contentToEncrypt);
        await sendMessage(agentName, senderName, encryptedMessage);
        return [false, "", ""];
      case 2:
        console.log("Etape 3 : Nonce recu de  " + senderName + ". Envoi de nonceA.");
        const receivedNonceB = dataArray[2];
        const nonceA = generateNonce();
        const messageContent = messageG.value;
        nonceTable.set(nonceA, senderName);
        pkeyB = await fetchKey(senderName, true, true);
        contentToEncrypt = JSON.stringify(["3", agentName, receivedNonceB, messageContent, nonceA]);
        encryptedMessage = await encryptWithPublicKey(pkeyB, contentToEncrypt);
        await sendMessage(agentName, senderName, encryptedMessage);
        addingReceivedMessage(agentName + " -> " + senderName + " : " + messageContent);
        return [false, "", ""];
      case 3:
        console.log("Etape 4 : V\xE9rification de nonceB et confirmation.");
        const checkNonceB = dataArray[2];
        const finalSecret = dataArray[3];
        const receivedNonceA = dataArray[4];
        if (nonceTable.get(checkNonceB) === senderName) {
          nonceTable.delete(checkNonceB);
          pkeyA = await fetchKey(senderName, true, true);
          contentToEncrypt = JSON.stringify(["4", agentName, finalSecret, receivedNonceA]);
          encryptedMessage = await encryptWithPublicKey(pkeyA, contentToEncrypt);
          await sendMessage(agentName, senderName, encryptedMessage);
          return [true, senderName, finalSecret];
        }
        console.log("Alerte : Le nonce re\xE7u ne correspond pas \xE0 la session !");
        return [false, "", ""];
      case 4:
        const checkNonceA = dataArray[3];
        if (nonceTable.get(checkNonceA) === senderName) {
          nonceTable.delete(checkNonceA);
          console.log("Succ\xE8s : " + senderName + " confirme la r\xE9ception du secret.");
          console.log("SYSTEM -> Message bien re\xE7u par " + senderName);
        }
        return [false, "", ""];
      default:
        return [false, "", ""];
    }
  } catch (error) {
    console.log("Erreur dans le protocole : ", error);
    return [false, "", ""];
  }
}
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvbWVzc2VuZ2VyLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBTb3VyY2U6IGh0dHBzOi8vZ2lzdC5naXRodWIuY29tL2dyb3VuZHJhY2UvYjUxNDEwNjJiNDdkZDk2YTVjMjFjOTM4MzlkNGI5NTQgKi9cblxuLyogQXZhaWxhYmxlIGZ1bmN0aW9uczpcblxuICAgICMgS2V5L25vbmNlIGdlbmVyYXRpb246XG4gICAgZ2VuZXJhdGVhc3ltbWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT5cbiAgICBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBnZW5lcmF0ZU5vbmNlKCk6IHN0cmluZ1xuXG4gICAgIyBhc3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb24vU2lnbmF0dXJlL1NpZ25hdHVyZSB2ZXJpZmljYXRpb25cbiAgICBlbmNyeXB0V2l0aFB1YmxpY0tleShwa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShza2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj5cblxuICAgICMgU3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb25cbiAgICBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT5cbiAgICBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSW1wb3J0aW5nIGtleXMgZnJvbSBzdHJpbmdcbiAgICBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoc2tleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cblxuICAgICMgRXhwb3J0aW5nIGtleXMgdG8gc3RyaW5nXG4gICAgcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBwcml2YXRlS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPlxuXG4gICAgIyBIYXNoaW5nXG4gICAgaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiovXG5cbi8vIGltcG9ydCB7IHN1YnRsZSB9IGZyb20gJ2NyeXB0bydcbi8vIExpYkNyeXB0by0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIl1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShwa2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIocGtleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInNwa2lcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1widmVyaWZ5XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKVxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJwa2NzOFwiID8/IGZvcm1hdCBmb3IgaW1wb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBLU9BRVBcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHJpdmF0ZSBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSlcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wic2lnblwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwdWJsaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwic3BraVwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEdlbmVyYXRlcyBhIHBhaXIgb2YgcHVibGljIGFuZCBwcml2YXRlIFJTQSBrZXlzIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yRW5jcnlwdGlvbigpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIFtrZXlwYWlyLnB1YmxpY0tleSwga2V5cGFpci5wcml2YXRlS2V5XVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3Igc2lnbmluZy92ZXJpZnlpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+IHtcbiAgICBjb25zdCBrZXlwYWlyOiBDcnlwdG9LZXlQYWlyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IDIwNDgsXG4gICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzEsIDAsIDFdKSxcbiAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJzaWduXCIsIFwidmVyaWZ5XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcmFuZG9tIG5vbmNlICovXG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmcge1xuICAgIGNvbnN0IG5vbmNlQXJyYXkgPSBuZXcgVWludDMyQXJyYXkoMSlcbiAgICBzZWxmLmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobm9uY2VBcnJheSlcbiAgICByZXR1cm4gbm9uY2VBcnJheVswXS50b1N0cmluZygpXG59XG5cbi8qIEVuY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIFNpZ24gYSBtZXNzYWdlIHdpdGggYSBwcml2YXRlIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZVRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICBjb25zdCBzaWduZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuc2lnbihcbiAgICAgICAgICAgIFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIHByaXZhdGVLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKHNpZ25lZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIlNpZ25hdHVyZSBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlByaXZhdGUga2V5IG9yIG1lc3NhZ2UgdG8gc2lnbiBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBEZWNyeXB0cyBhIG1lc3NhZ2Ugd2l0aCBhIHByaXZhdGUga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVjcnlwdFdpdGhQcml2YXRlS2V5KHByaXZhdGVLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBkZWNyeXRwZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLmRlY3J5cHQoXG4gICAgICAgICAgICAgICAgeyBuYW1lOiBcIlJTQS1PQUVQXCIgfSxcbiAgICAgICAgICAgICAgICBwcml2YXRlS2V5LFxuICAgICAgICAgICAgICAgIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9UZXh0KGRlY3J5dHBlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3IgZGVjcnlwdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiUHJpdmF0ZSBrZXkgb3IgbWVzc2FnZSB0byBkZWNyeXB0IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBWZXJpZmljYXRpb24gb2YgYSBzaWduYXR1cmUgb24gYSBtZXNzYWdlIHdpdGggYSBwdWJsaWMga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleShwdWJsaWNLZXk6IENyeXB0b0tleSwgbWVzc2FnZUluQ2xlYXI6IHN0cmluZywgc2lnbmVkTWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qgc2lnbmVkVG9BcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2lnbmVkTWVzc2FnZSlcbiAgICAgICAgY29uc3QgbWVzc2FnZUluQ2xlYXJUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZUluQ2xlYXIpXG4gICAgICAgIGNvbnN0IHZlcmlmaWVkOiBib29sZWFuID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLnZlcmlmeShcbiAgICAgICAgICAgICAgICBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgcHVibGljS2V5LFxuICAgICAgICAgICAgICAgIHNpZ25lZFRvQXJyYXlCdWZmZXIsXG4gICAgICAgICAgICAgICAgbWVzc2FnZUluQ2xlYXJUb0FycmF5QnVmZmVyKVxuICAgICAgICByZXR1cm4gdmVyaWZpZWRcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiUHVibGljIGtleSBvciBzaWduZWQgbWVzc2FnZSB0byB2ZXJpZnkgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIEdlbmVyYXRlcyBhIHN5bW1ldHJpYyBBRVMtR0NNIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU3ltZXRyaWNLZXkoKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIkFFUy1HQ01cIixcbiAgICAgICAgICAgIGxlbmd0aDogMjU2LFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJlbmNyeXB0XCIsIFwiZGVjcnlwdFwiXVxuICAgIClcbiAgICByZXR1cm4ga2V5XG59XG5cbi8qIGEgc3ltbWV0cmljIEFFUyBrZXkgaW50byBhIHN0cmluZyAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN5bW1ldHJpY0tleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJyYXdcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKiBJbXBvcnRzIHRoZSBnaXZlbiBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBBRVMga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9TeW1tZXRyaWNLZXkoc2tleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHNrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJyYXdcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAgXCJBRVMtR0NNXCIsXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgc3ltbWV0cmljIGtleSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBzeW1tZXRyaWMga2V5IGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vLyBXaGVuIGN5cGhlcmluZyBhIG1lc3NhZ2Ugd2l0aCBhIGtleSBpbiBBRVMsIHdlIG9idGFpbiBhIGN5cGhlcmVkIG1lc3NhZ2UgYW5kIGFuIFwiaW5pdGlhbGlzYXRpb24gdmVjdG9yXCIuXG4vLyBJbiB0aGlzIGltcGxlbWVudGF0aW9uLCB0aGUgb3V0cHV0IGlzIGEgdHdvIGVsZW1lbnRzIGFycmF5IHQgc3VjaCB0aGF0IHRbMF0gaXMgdGhlIGN5cGhlcmVkIG1lc3NhZ2Vcbi8vIGFuZCB0WzFdIGlzIHRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3IuIFRvIHNpbXBsaWZ5LCB0aGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yIGlzIHJlcHJlc2VudGVkIGJ5IGEgc3RyaW5nLlxuLy8gVGhlIGluaXRpYWxpc2F0aW9uIHZlY3RvcmUgaXMgdXNlZCBmb3IgcHJvdGVjdGluZyB0aGUgZW5jcnlwdGlvbiwgaS5lLCAyIGVuY3J5cHRpb25zIG9mIHRoZSBzYW1lIG1lc3NhZ2UgXG4vLyB3aXRoIHRoZSBzYW1lIGtleSB3aWxsIG5ldmVyIHJlc3VsdCBpbnRvIHRoZSBzYW1lIGVuY3J5cHRlZCBtZXNzYWdlLlxuLy8gXG4vLyBOb3RlIHRoYXQgZm9yIGRlY3lwaGVyaW5nLCB0aGUgKipzYW1lKiogaW5pdGlhbGlzYXRpb24gdmVjdG9yIHdpbGwgYmUgbmVlZGVkLlxuLy8gVGhpcyB2ZWN0b3IgY2FuIHNhZmVseSBiZSB0cmFuc2ZlcnJlZCBpbiBjbGVhciB3aXRoIHRoZSBlbmNyeXB0ZWQgbWVzc2FnZS5cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5KGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZ1tdPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZVRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICBjb25zdCBpdiA9IHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7XG4gICAgICAgIGNvbnN0IGl2VGV4dCA9IGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoaXYpXG4gICAgICAgIGNvbnN0IGN5cGhlcmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmVuY3J5cHQoXG4gICAgICAgICAgICB7IG5hbWU6IFwiQUVTLUdDTVwiLCBpdiB9LFxuICAgICAgICAgICAga2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gW2FycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoY3lwaGVyZWRNZXNzYWdlQUIpLCBpdlRleHRdXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhlKTsgY29uc29sZS5sb2coXCJFbmNyeXB0aW9uIGZhaWxlZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3ltbWV0cmljIGtleSBvciBtZXNzYWdlIHRvIGVuY3J5cHQgaXMgaWxsLWZvcm1lZFwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8vIEZvciBkZWN5cGhlcmluZywgd2UgbmVlZCB0aGUga2V5LCB0aGUgY3lwaGVyZWQgbWVzc2FnZSBhbmQgdGhlIGluaXRpYWxpemF0aW9uIHZlY3Rvci4gU2VlIGFib3ZlIHRoZSBcbi8vIGNvbW1lbnRzIGZvciB0aGUgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkgZnVuY3Rpb25cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGRlY29kZWRJbml0VmVjdG9yOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoaW5pdFZlY3RvcilcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBkZWNyeXRwZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLmRlY3J5cHQoXG4gICAgICAgICAgICAgICAgeyBuYW1lOiBcIkFFUy1HQ01cIiwgaXY6IGRlY29kZWRJbml0VmVjdG9yIH0sXG4gICAgICAgICAgICAgICAga2V5LFxuICAgICAgICAgICAgICAgIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9UZXh0KGRlY3J5dHBlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3IgZGVjcnlwdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU3ltbWV0cmljIGtleSBvciBtZXNzYWdlIHRvIGRlY3J5cHQgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vLyBTSEEtMjU2IEhhc2ggZnJvbSBhIHRleHRcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBoYXNoKHRleHQ6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgdGV4dDJhcnJheUJ1ZiA9IHRleHRUb0FycmF5QnVmZmVyKHRleHQpXG4gICAgY29uc3QgaGFzaGVkQXJyYXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kaWdlc3QoXCJTSEEtMjU2XCIsIHRleHQyYXJyYXlCdWYpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoaGFzaGVkQXJyYXkpXG59XG5cbmNsYXNzIEtleVN0cmluZ0NvcnJ1cHRlZCBleHRlbmRzIEVycm9yIHsgfVxuXG4vLyBBcnJheUJ1ZmZlciB0byBhIEJhc2U2NCBzdHJpbmdcbmZ1bmN0aW9uIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoYXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgICB2YXIgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpXG4gICAgdmFyIGJ5dGVTdHJpbmcgPSAnJ1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZUFycmF5LmJ5dGVMZW5ndGg7IGkrKykge1xuICAgICAgICBieXRlU3RyaW5nICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZUFycmF5W2ldKVxuICAgIH1cbiAgICByZXR1cm4gYnRvYShieXRlU3RyaW5nKVxufVxuXG4vLyBCYXNlNjQgc3RyaW5nIHRvIGFuIGFycmF5QnVmZmVyXG5mdW5jdGlvbiBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKGI2NHN0cjogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHRyeSB7XG4gICAgICAgIHZhciBieXRlU3RyID0gYXRvYihiNjRzdHIpXG4gICAgICAgIHZhciBieXRlcyA9IG5ldyBVaW50OEFycmF5KGJ5dGVTdHIubGVuZ3RoKVxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVTdHIubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGJ5dGVzW2ldID0gYnl0ZVN0ci5jaGFyQ29kZUF0KGkpXG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGJ5dGVzLmJ1ZmZlclxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFN0cmluZyBzdGFydGluZyBieSAnJHtiNjRzdHIuc3Vic3RyaW5nKDAsIDEwKX0nIGNhbm5vdCBiZSBjb252ZXJ0ZWQgdG8gYSB2YWxpZCBrZXkgb3IgbWVzc2FnZWApXG4gICAgICAgIHRocm93IG5ldyBLZXlTdHJpbmdDb3JydXB0ZWRcbiAgICB9XG59XG5cbi8vIFN0cmluZyB0byBhcnJheSBidWZmZXJcbmZ1bmN0aW9uIHRleHRUb0FycmF5QnVmZmVyKHN0cjogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHZhciBidWYgPSBlbmNvZGVVUklDb21wb25lbnQoc3RyKSAvLyAyIGJ5dGVzIGZvciBlYWNoIGNoYXJcbiAgICB2YXIgYnVmVmlldyA9IG5ldyBVaW50OEFycmF5KGJ1Zi5sZW5ndGgpXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBidWYubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnVmVmlld1tpXSA9IGJ1Zi5jaGFyQ29kZUF0KGkpXG4gICAgfVxuICAgIHJldHVybiBidWZWaWV3XG59XG5cbi8vIEFycmF5IGJ1ZmZlcnMgdG8gc3RyaW5nXG5mdW5jdGlvbiBhcnJheUJ1ZmZlclRvVGV4dChhcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICAgIHZhciBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShhcnJheUJ1ZmZlcilcbiAgICB2YXIgc3RyID0gJydcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVBcnJheS5ieXRlTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZUFycmF5W2ldKVxuICAgIH1cbiAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KHN0cilcbn1cblxuIiwgIi8vIFRvIGRldGVjdCBpZiB3ZSBjYW4gdXNlIHdpbmRvdy5jcnlwdG8uc3VidGxlXG5pZiAoIXdpbmRvdy5pc1NlY3VyZUNvbnRleHQpIGFsZXJ0KFwiTm90IHNlY3VyZSBjb250ZXh0IVwiKVxuXG4vLyAtLSBETyBOT1QgTU9ESUZZIFRISVMgUEFSVCEgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIE1lc3NhZ2UgZm9yIHVzZXIgbmFtZVxuY2xhc3MgQ2FzVXNlck5hbWUge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyB1c2VybmFtZTogc3RyaW5nKSB7IH1cbn1cblxuLy8gUmVxdWVzdGluZyBrZXlzXG5jbGFzcyBLZXlSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgb3duZXJPZlRoZUtleTogc3RyaW5nLCBwdWJsaWMgcHVibGljS2V5OiBib29sZWFuLCBwdWJsaWMgZW5jcnlwdGlvbjogYm9vbGVhbikgeyB9XG59XG5cbmNsYXNzIEtleVJlc3VsdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sIHB1YmxpYyBrZXk6IHN0cmluZywgcHVibGljIGVycm9yTWVzc2FnZTogc3RyaW5nKSB7IH1cbn1cblxuLy8gVGhlIG1lc3NhZ2UgZm9ybWF0XG5jbGFzcyBFeHRNZXNzYWdlIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc2VuZGVyOiBzdHJpbmcsIHB1YmxpYyByZWNlaXZlcjogc3RyaW5nLCBwdWJsaWMgY29udGVudDogc3RyaW5nKSB7IH1cbn1cblxuLy8gU2VuZGluZyBhIG1lc3NhZ2UgUmVzdWx0IGZvcm1hdFxuY2xhc3MgU2VuZFJlc3VsdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sIHB1YmxpYyBlcnJvck1lc3NhZ2U6IHN0cmluZykgeyB9XG59XG5cbi8vIE1lc3NhZ2UgZm9yIHJlcXVpcmluZyBoaXN0b3J5XG5jbGFzcyBIaXN0b3J5UmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIGFnZW50TmFtZTogc3RyaW5nLCBwdWJsaWMgaW5kZXg6IG51bWJlcikgeyB9XG59XG5cbi8vIFJlc3VsdCBvZiBoaXN0b3J5IHJlcXVlc3RcbmNsYXNzIEhpc3RvcnlBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBwdWJsaWMgZmFpbHVyZU1lc3NhZ2U6IHN0cmluZyxcbiAgICAgICAgcHVibGljIGluZGV4OiBudW1iZXIsXG4gICAgICAgIHB1YmxpYyBhbGxNZXNzYWdlczogRXh0TWVzc2FnZVtdKSB7IH1cbn1cblxubGV0IGdsb2JhbFVzZXJOYW1lID0gXCJcIlxuXG4vLyBXQVJOSU5HIVxuLy8gSXQgaXMgbmVjZXNzYXJ5IHRvIHBhc3MgdGhlIFVSTCBwYXJhbWV0ZXJzLCBjYWxsZWQgYHVybFBhcmFtc2AgYmVsb3csIHRvIFxuLy8gZXZlcnkgR0VUL1BPU1QgcXVlcnkgeW91IHNlbmQgdG8gdGhlIHNlcnZlci4gVGhpcyBpcyBtYW5kYXRvcnkgdG8gaGF2ZSB0aGUgcG9zc2liaWxpdHkgXG4vLyB0byB1c2UgYWx0ZXJuYXRpdmUgaWRlbnRpdGllcyBsaWtlIGFsaWNlQHVuaXYtcmVubmVzLmZyLCBib2JAdW5pdi1yZW5uZXMuZnIsIGV0Yy4gXG4vLyBmb3IgZGVidWdnaW5nIHB1cnBvc2VzLlxuXG4vLyBEbyBub3QgbW9kaWZ5IVxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hDYXNOYW1lKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcbiAgICBjb25zdCBuYW1lcmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL2dldHVzZXI/XCIgKyB1cmxQYXJhbXMsIHtcbiAgICAgICAgbWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICB9XG4gICAgfSk7XG4gICAgaWYgKCFuYW1lcmVxdWVzdC5vaykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7bmFtZXJlcXVlc3Quc3RhdHVzfWApXG4gICAgfVxuICAgIGNvbnN0IG5hbWVSZXN1bHQgPSAoYXdhaXQgbmFtZXJlcXVlc3QuanNvbigpKSBhcyBDYXNVc2VyTmFtZVxuICAgIGNvbnNvbGUubG9nKFwiRmV0Y2hlZCBDQVMgbmFtZT0gXCIgKyBuYW1lUmVzdWx0LnVzZXJuYW1lKVxuICAgIHJldHVybiBuYW1lUmVzdWx0LnVzZXJuYW1lXG59XG5cbi8vIERvIG5vdCBtb2RpZnkhXG5hc3luYyBmdW5jdGlvbiBzZXRDYXNOYW1lKCkge1xuICAgIGdsb2JhbFVzZXJOYW1lID0gYXdhaXQgZmV0Y2hDYXNOYW1lKClcbiAgICAvLyBXZSByZXBsYWNlIHRoZSBuYW1lIG9mIHRoZSB1c2VyIG9mIHRoZSBhcHBsaWNhdGlvbiBhcyB0aGUgZGVmYXVsdCBuYW1lXG4gICAgLy8gSW4gdGhlIHdpbmRvd1xuICAgIHVzZXJCdXR0b25MYWJlbC50ZXh0Q29udGVudCA9IGdsb2JhbFVzZXJOYW1lXG59XG5cbi8vIERvIG5vdCBtb2RpZnkhXG5zZXRDYXNOYW1lKClcblxuLy8gV0FSTklORyFcbi8vIEl0IGlzIG5lY2Vzc2FyeSB0byBwcm92aWRlIHRoZSBuYW1lIG9mIHRoZSBvd25lciBvZiB0aGUgYXBwbGljYXRpb24uIEVhY2ggcGFpciBvZiBzdHVkZW50IGFyZVxuLy8gdGhlIG93bmVyIG9mIHRoZWlyIGFwcGxpY2F0aW9uLiBPdGhlciBzdHVkZW50cyBtYXkgdXNlIGl0IGJ1dCB0aGV5IGFyZSBvbmx5IHVzZXJzIGFuZCBub3Qgb3duZXJzLlxuLy8gTWVzc2FnZXMgc2VudCB0byB0aGUgc2VydmVyIGFyZSBzZXBhcmF0ZWQgdy5yLnQuIHRoZSBuYW1lIG9mIHRoZSBhcHBsaWNhdGlvbiAoaS5lLiB0aGUgbmFtZSBvZiB0aGVpciBvd25lcnMpLlxuLy8gVGhlIG5hbWUgb2YgdGhlIG93bmVycyBpcyB0aGUgbmFtZSBvZiB0aGUgZm9sZGVyIG9mIHRoZSBhcHBsaWNhdGlvbiB3aGVyZSB0aGUgd2ViIHBhZ2VzIG9mIHRoZSBhcHBsaWNhdGlvbiBhcmUgc3RvcmVkLiBcbi8vIEUuZywgZm9yIHRlYWNoZXJzJyBhcHBsaWNhdGlvbiB0aGlzIG5hbWUgaXMgXCJlbnNcIlxuXG4vLyBEbyBub3QgbW9kaWZ5IVxuZnVuY3Rpb24gZ2V0T3duZXJOYW1lKCk6IHN0cmluZyB7XG4gICAgY29uc3QgcGF0aCA9IHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZVxuICAgIGNvbnN0IG5hbWUgPSBwYXRoLnNwbGl0KFwiL1wiLCAyKVsxXVxuICAgIHJldHVybiBuYW1lXG59XG5cbi8vIERvIG5vdCBtb2RpZnkhXG5sZXQgb3duZXJOYW1lID0gZ2V0T3duZXJOYW1lKClcblxuLy8gV0FSTklORyFcbi8vIEl0IGlzIG5lY2Vzc2FyeSB0byBwYXNzIHRoZSBVUkwgcGFyYW1ldGVycywgY2FsbGVkIGB1cmxQYXJhbXNgIGJlbG93LCB0byBcbi8vIGV2ZXJ5IEdFVC9QT1NUIHF1ZXJ5IHlvdSBzZW5kIHRvIHRoZSBzZXJ2ZXIuIFRoaXMgaXMgbWFuZGF0b3J5IHRvIGhhdmUgdGhlIHBvc3NpYmlsaXR5IFxuLy8gdG8gdXNlIGFsdGVybmF0aXZlIGlkZW50aXRpZXMgbGlrZSBhbGljZUB1bml2LXJlbm5lcy5mciwgYm9iQHVuaXYtcmVubmVzLmZyLCBldGMuIFxuLy8gZm9yIGRlYnVnZ2luZyBwdXJwb3Nlcy5cblxuLy8gRG8gbm90IG1vZGlmeVxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hLZXkodXNlcjogc3RyaW5nLCBwdWJsaWNLZXk6IGJvb2xlYW4sIGVuY3J5cHRpb246IGJvb2xlYW4pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIC8vIEdldHRpbmcgdGhlIHB1YmxpYy9wcml2YXRlIGtleSBvZiB1c2VyLlxuICAgIC8vIEZvciBwdWJsaWMga2V5IHRoZSBib29sZWFuICdwdWJsaWNLZXknIGlzIHRydWUuXG4gICAgLy8gRm9yIHByaXZhdGUga2V5IHRoZSBib29sZWFuICdwdWJsaWNLZXknIGlzIGZhbHNlLlxuICAgIC8vIElmIHRoZSBrZXkgaXMgdXNlZCBmb3IgZW5jcnlwdGlvbi9kZWNyeXB0aW9uIHRoZW4gdGhlIGJvb2xlYW4gJ2VuY3J5cHRpb24nIGlzIHRydWUuXG4gICAgLy8gSWYgdGhlIGtleSBpcyB1c2VkIGZvciBzaWduYXR1cmUvc2lnbmF0dXJlIHZlcmlmaWNhdGlvbiB0aGVuIHRoZSBib29sZWFuIGlzIGZhbHNlLlxuICAgIGNvbnN0IGtleVJlcXVlc3RNZXNzYWdlID1cbiAgICAgICAgbmV3IEtleVJlcXVlc3QodXNlciwgcHVibGljS2V5LCBlbmNyeXB0aW9uKVxuICAgIC8vIEZvciBDQVMgYXV0aGVudGljYXRpb24gd2UgbmVlZCB0byBhZGQgdGhlIGF1dGhlbnRpY2F0aW9uIHRpY2tldFxuICAgIC8vIEl0IGlzIGNvbnRhaW5lZCBpbiB1cmxQYXJhbXNcbiAgICBjb25zdCB1cmxQYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpO1xuICAgIC8vIEZvciBnZXR0aW5nIGEga2V5IHdlIGRvIG5vdCBuZWVkIHRoZSBvd25lck5hbWUgcGFyYW1cbiAgICAvLyBCZWNhdXNlIGtleXMgYXJlIGluZGVwZW5kYW50IG9mIHRoZSBhcHBsaWNhdGlvbnNcbiAgICBjb25zdCBrZXlyZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvZ2V0S2V5P1wiICsgdXJsUGFyYW1zLCB7XG4gICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KGtleVJlcXVlc3RNZXNzYWdlKSxcbiAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIGlmICgha2V5cmVxdWVzdC5vaykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7a2V5cmVxdWVzdC5zdGF0dXN9YCk7XG4gICAgfVxuICAgIGNvbnN0IGtleVJlc3VsdCA9IChhd2FpdCBrZXlyZXF1ZXN0Lmpzb24oKSkgYXMgS2V5UmVzdWx0O1xuICAgIGlmICgha2V5UmVzdWx0LnN1Y2Nlc3MpIGFsZXJ0KGtleVJlc3VsdC5lcnJvck1lc3NhZ2UpXG4gICAgZWxzZSB7XG4gICAgICAgIGlmIChwdWJsaWNLZXkgJiYgZW5jcnlwdGlvbikgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbihrZXlSZXN1bHQua2V5KVxuICAgICAgICBlbHNlIGlmICghcHVibGljS2V5ICYmIGVuY3J5cHRpb24pIHJldHVybiBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKGtleVJlc3VsdC5rZXkpXG4gICAgICAgIGVsc2UgaWYgKHB1YmxpY0tleSAmJiAhZW5jcnlwdGlvbikgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHVibGljS2V5Rm9yU2lnbmF0dXJlKGtleVJlc3VsdC5rZXkpXG4gICAgICAgIGVsc2UgaWYgKCFwdWJsaWNLZXkgJiYgIWVuY3J5cHRpb24pIHJldHVybiBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoa2V5UmVzdWx0LmtleSlcbiAgICB9XG59XG5cbi8vIFdBUk5JTkchXG4vLyBJdCBpcyBuZWNlc3NhcnkgdG8gcGFzcyB0aGUgVVJMIHBhcmFtZXRlcnMsIGNhbGxlZCBgdXJsUGFyYW1zYCBiZWxvdywgdG8gXG4vLyBldmVyeSBHRVQvUE9TVCBxdWVyeSB5b3Ugc2VuZCB0byB0aGUgc2VydmVyLiBUaGlzIGlzIG1hbmRhdG9yeSB0byBoYXZlIHRoZSBwb3NzaWJpbGl0eSBcbi8vIHRvIHVzZSBhbHRlcm5hdGl2ZSBpZGVudGl0aWVzIGxpa2UgYWxpY2VAdW5pdi1yZW5uZXMuZnIsIGJvYkB1bml2LXJlbm5lcy5mciwgZXRjLiBcbi8vIGZvciBkZWJ1Z2dpbmcgcHVycG9zZXMuXG4vLyBcbi8vIFdlIGFsc28gbmVlZCB0byBwcm92aWRlIHRoZSBvd25lck5hbWVcblxuLy8gRG8gbm90IG1vZGlmeSFcbmFzeW5jIGZ1bmN0aW9uIHNlbmRNZXNzYWdlKGFnZW50TmFtZTogc3RyaW5nLCByZWNlaXZlck5hbWU6IHN0cmluZywgbWVzc2FnZUNvbnRlbnQ6IHN0cmluZyk6IFByb21pc2U8U2VuZFJlc3VsdD4ge1xuICAgIHRyeSB7XG4gICAgICAgIGxldCBtZXNzYWdlVG9TZW5kID1cbiAgICAgICAgICAgIG5ldyBFeHRNZXNzYWdlKGFnZW50TmFtZSwgcmVjZWl2ZXJOYW1lLCBtZXNzYWdlQ29udGVudClcbiAgICAgICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcblxuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvc2VuZGluZ01lc3NhZ2UvXCIgKyBvd25lck5hbWUgKyBcIj9cIiArIHVybFBhcmFtcywge1xuICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KG1lc3NhZ2VUb1NlbmQpLFxuICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBEZWFsaW5nIHdpdGggdGhlIGFuc3dlciBvZiB0aGUgbWVzc2FnZSBzZXJ2ZXJcbiAgICAgICAgY29uc29sZS5sb2coYFNlbnQgbWVzc2FnZSBmcm9tICR7YWdlbnROYW1lfSB0byAke3JlY2VpdmVyTmFtZX06ICR7bWVzc2FnZUNvbnRlbnR9YClcbiAgICAgICAgcmV0dXJuIChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgU2VuZFJlc3VsdFxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCdlcnJvciBtZXNzYWdlOiAnLCBlcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2VuZFJlc3VsdChmYWxzZSwgZXJyb3IubWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlbmRSZXN1bHQoZmFsc2UsICdBbiB1bmV4cGVjdGVkIGVycm9yIG9jY3VycmVkJylcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBZb3UgY2FuIG1vZGlmeSB0aGUgY29kZSBiZWxvd1xuXG5pbXBvcnQge1xuICAgIHN0cmluZ1RvUHJpdmF0ZUtleUZvckVuY3J5cHRpb24sIHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbixcbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUsXG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUsXG4gICAgZW5jcnlwdFdpdGhQdWJsaWNLZXksXG4gICAgZGVjcnlwdFdpdGhQcml2YXRlS2V5LFxuICAgIGdlbmVyYXRlTm9uY2UsXG59IGZyb20gJy4vbGliQ3J5cHRvJ1xuXG5jb25zdCB1c2VyQnV0dG9uTGFiZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInVzZXItbmFtZVwiKSBhcyBIVE1MTGFiZWxFbGVtZW50XG5jb25zdCBzZW5kQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJzZW5kLWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuY29uc3QgcmVjZWl2ZXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInJlY2VpdmVyXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IG1lc3NhZ2VHID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJtZXNzYWdlXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHJlY2VpdmVkX21lc3NhZ2VzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJleGNoYW5nZWQtbWVzc2FnZXNcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuY29uc3QgY2xlYXJIaXN0b3J5ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJjbGVhci1oaXN0b3J5XCIpIGFzIEhUTUxMYWJlbEVsZW1lbnRcbmNsZWFySGlzdG9yeS5hZGRFdmVudExpc3RlbmVyKFwiY2xpY2tcIixjbGVhcmluZ01lc3NhZ2VzKTtcbi8vIEJhc2ljIHV0aWxpdGllcyBmb3IgYWRkaW5nL2NsZWFyaW5nIHJlY2VpdmVkIG1lc3NhZ2VzIGluIHRoZSBwYWdlXG5mdW5jdGlvbiBjbGVhcmluZ01lc3NhZ2VzKCkge1xuICAgIHJlY2VpdmVkX21lc3NhZ2VzLnRleHRDb250ZW50ID0gXCJcIlxufVxuXG4vLyBCZXdhcmUsIHRoaXMgaXMgdnVsbmVyYWJsZSBjb2RlXG5mdW5jdGlvbiBzdHJpbmdUb0hUTUwoc3RyOiBzdHJpbmcpOiBIVE1MRGl2RWxlbWVudCB7XG4gICAgdmFyIGRpdl9lbHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKVxuICAgIGRpdl9lbHQuaW5uZXJIVE1MID0gc3RyXG4gICAgcmV0dXJuIGRpdl9lbHRcbn1cblxuZnVuY3Rpb24gYWRkaW5nUmVjZWl2ZWRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZykge1xuICAgIC8vcmVjZWl2ZWRfbWVzc2FnZXMuYXBwZW5kKHN0cmluZ1RvSFRNTCgnPHA+PC9wPjxwPjwvcD4nICsgbWVzc2FnZSkpXG4gICAgY29uc3QgcCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ3AnKTtcbiAgICBwLnRleHRDb250ZW50ID0gbWVzc2FnZTtcbiAgICByZWNlaXZlZF9tZXNzYWdlcy5hcHBlbmQocCk7XG59XG5cblxuLy9JbmRleCBvZiB0aGUgbGFzdCByZWFkIG1lc3NhZ2VcbmxldCBsYXN0SW5kZXhJbkhpc3RvcnkgPSAwXG5cbi8vIGZ1bmN0aW9uIGZvciByZWZyZXNoaW5nIHRoZSBjb250ZW50IG9mIHRoZSB3aW5kb3cgKGF1dG9tYXRpYyBvciBtYW51YWwgc2VlIGJlbG93KVxuYXN5bmMgZnVuY3Rpb24gcmVmcmVzaCgpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB1c2VyID0gZ2xvYmFsVXNlck5hbWVcbiAgICAgICAgY29uc3QgaGlzdG9yeVJlcXVlc3QgPVxuICAgICAgICAgICAgbmV3IEhpc3RvcnlSZXF1ZXN0KHVzZXIsIGxhc3RJbmRleEluSGlzdG9yeSlcbiAgICAgICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcbiAgICAgICAgY29uc3QgcmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL2hpc3RvcnkvXCIgKyBvd25lck5hbWUgKyBcIj9cIiArIHVybFBhcmFtc1xuICAgICAgICAgICAgLCB7XG4gICAgICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShoaXN0b3J5UmVxdWVzdCksXG4gICAgICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCByZXN1bHQgPSAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIEhpc3RvcnlBbnN3ZXJcbiAgICAgICAgaWYgKCFyZXN1bHQuc3VjY2VzcykgeyBhbGVydChyZXN1bHQuZmFpbHVyZU1lc3NhZ2UpIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAvLyBUaGlzIGlzIHRoZSBwbGFjZSB3aGVyZSB5b3UgY2FuIHBlcmZvcm0gdHJpZ2dlciBhbnkgb3BlcmF0aW9ucyBmb3IgcmVmcmVzaGluZyB0aGUgcGFnZVxuICAgICAgICAgICAvLyBhZGRpbmdSZWNlaXZlZE1lc3NhZ2UoXCJEdW1teSBtZXNzYWdlIVwiKVxuICAgICAgICAgICBsYXN0SW5kZXhJbkhpc3RvcnkgPSByZXN1bHQuaW5kZXhcbiAgICAgICAgICAgIGlmIChyZXN1bHQuYWxsTWVzc2FnZXMubGVuZ3RoICE9IDApIHtcbiAgICAgICAgICAgICAgICBmb3IgKHZhciBtIG9mIHJlc3VsdC5hbGxNZXNzYWdlcykge1xuICAgICAgICAgICAgICAgICAgICBsZXQgW2IsIHNlbmRlciwgbXNnQ29udGVudF0gPSBhd2FpdCBhbmFseXNlTWVzc2FnZShtKVxuICAgICAgICAgICAgICAgICAgICBpZiAoYikgYWN0aW9uT25NZXNzYWdlT25lKHNlbmRlciwgbXNnQ29udGVudClcbiAgICAgICAgICAgICAgICAgICAgZWxzZSBjb25zb2xlLmxvZyhcIk1zZyBcIiArIG0gKyBcIiBjYW5ub3QgYmUgZXhwbG9pdGVkIGJ5IFwiICsgdXNlcilcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZXJyb3IgbWVzc2FnZTogJywgZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm4gZXJyb3IubWVzc2FnZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnO1xuICAgICAgICB9XG4gICAgfVxufVxuXG4vLyBBdXRvbWF0aWMgcmVmcmVzaDogdGhlIHdhaXRpbmcgdGltZSBpcyBnaXZlbiBpbiBtaWxsaXNlY29uZHNcbmNvbnN0IGludGVydmFsUmVmcmVzaCA9IHNldEludGVydmFsKHJlZnJlc2gsIDIwMDApXG5cbi8vIC0tLS0tLVxuXG5cbmNvbnN0IG5vbmNlVGFibGUgPSBuZXcgTWFwPHN0cmluZywgc3RyaW5nPigpO1xuXG5cbmZ1bmN0aW9uIGFjdGlvbk9uTWVzc2FnZU9uZShmcm9tQTogc3RyaW5nLCBtZXNzYWdlQ29udGVudDogc3RyaW5nKSB7XG4gICAgY29uc3QgdXNlciA9IGdsb2JhbFVzZXJOYW1lXG4gICAgY29uc3QgdGV4dFRvQWRkID0gYCR7ZnJvbUF9IC0+ICR7dXNlcn0gOiAke21lc3NhZ2VDb250ZW50fSBgXG4gICAgYWRkaW5nUmVjZWl2ZWRNZXNzYWdlKHRleHRUb0FkZClcbn1cblxuLy8gRXRhcGUgMSA6IEEgLT4gQlxuc2VuZEJ1dHRvbi5vbmNsaWNrID0gYXN5bmMgZnVuY3Rpb24oKSB7XG4gICAgY29uc3QgYWdlbnROYW1lID0gZ2xvYmFsVXNlck5hbWU7XG4gICAgY29uc3QgcmVjZWl2ZXJOYW1lID0gcmVjZWl2ZXIudmFsdWU7XG4gICAgaWYgKCFyZWNlaXZlck5hbWUpIHJldHVybjtcblxuICAgIHRyeSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiRXRhcGUgMSA6IFwiKyBhZ2VudE5hbWUgKyBcIiBkZW1hbmRlIHVuZSBzZXNzaW9uIGF2ZWMgXCIgKyByZWNlaXZlck5hbWUpO1xuICAgICAgICBjb25zdCBwa2V5QiA9IGF3YWl0IGZldGNoS2V5KHJlY2VpdmVyTmFtZSwgdHJ1ZSwgdHJ1ZSk7XG4gICAgICAgIGNvbnN0IGNvbnRlbnRUb0VuY3J5cHQgPSBKU09OLnN0cmluZ2lmeShbXCIxXCIsIGFnZW50TmFtZV0pO1xuICAgICAgICBjb25zdCBlbmNyeXB0ZWRNZXNzYWdlID0gYXdhaXQgZW5jcnlwdFdpdGhQdWJsaWNLZXkocGtleUIsIGNvbnRlbnRUb0VuY3J5cHQpO1xuICAgICAgICBcbiAgICAgICAgY29uc3Qgc2VuZFJlc3VsdCA9IGF3YWl0IHNlbmRNZXNzYWdlKGFnZW50TmFtZSwgcmVjZWl2ZXJOYW1lLCBlbmNyeXB0ZWRNZXNzYWdlKTtcbiAgICAgICAgaWYgKCFzZW5kUmVzdWx0LnN1Y2Nlc3MpIGNvbnNvbGUubG9nKFwiRXJyZXVyIGVudm9pIEV0YXBlIDFcIik7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc29sZS5sb2coXCJFcnJldXIgYXUgZFx1MDBFOWJ1dCBkdSBwcm90b2NvbGUgOiBcIiwgZXJyb3IpO1xuICAgIH1cbn1cblxuLy8gIEFOQUxZU0UgREVTIE1FU1NBR0VTIEV0YXBlcyAyLCAzIGV0IDRcbmFzeW5jIGZ1bmN0aW9uIGFuYWx5c2VNZXNzYWdlKG1lc3NhZ2U6IEV4dE1lc3NhZ2UpOiBQcm9taXNlPFtib29sZWFuLCBzdHJpbmcsIHN0cmluZ10+IHtcbiAgICBjb25zdCBhZ2VudE5hbWUgPSBnbG9iYWxVc2VyTmFtZTsgXG5cbiAgICB0cnkge1xuICAgICAgICBpZiAobWVzc2FnZS5yZWNlaXZlciAhPT0gYWdlbnROYW1lKSByZXR1cm4gW2ZhbHNlLCBcIlwiLCBcIlwiXTtcblxuICAgICAgICBjb25zdCBwcml2S2V5ID0gYXdhaXQgZmV0Y2hLZXkoYWdlbnROYW1lLCBmYWxzZSwgdHJ1ZSk7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VJbkNsZWFyID0gYXdhaXQgZGVjcnlwdFdpdGhQcml2YXRlS2V5KHByaXZLZXksIG1lc3NhZ2UuY29udGVudCk7XG4gICAgICAgIGNvbnN0IGRhdGFBcnJheSA9IEpTT04ucGFyc2UobWVzc2FnZUluQ2xlYXIpIGFzIHN0cmluZ1tdO1xuICAgICAgICBcbiAgICAgICAgY29uc3QgaW5kZXggPSBwYXJzZUludChkYXRhQXJyYXlbMF0sIDEwKTtcbiAgICAgICAgY29uc3Qgc2VuZGVyTmFtZSA9IG1lc3NhZ2Uuc2VuZGVyO1xuXG4gICAgICAgIGxldCBjb250ZW50VG9FbmNyeXB0ID0gXCJcIjtcbiAgICAgICAgbGV0IGVuY3J5cHRlZE1lc3NhZ2U7XG4gICAgICAgIGxldCBwa2V5QSwgcGtleUI7XG5cbiAgICAgICAgc3dpdGNoIChpbmRleCkge1xuICAgICAgICAgICAgY2FzZSAxOlxuICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiRXRhcGUgMiA6IFwiICsgc2VuZGVyTmFtZSArIFwiIHZldXQgZXhlY3V0ZXIgbGUgcHJvdG9jb2xlIGF2ZWMgIFwiKyBtZXNzYWdlLnJlY2VpdmVyICtcIi4gSWwgZ1x1MDBFOW5cdTAwRThyZSBzb24gbm9uY2VCLlwiKTtcbiAgICAgICAgICAgICAgICBjb25zdCBub25jZUIgPSBnZW5lcmF0ZU5vbmNlKCk7XG4gICAgICAgICAgICAgICAgbm9uY2VUYWJsZS5zZXQobm9uY2VCLCBzZW5kZXJOYW1lKTsgXG5cbiAgICAgICAgICAgICAgICBwa2V5QSA9IGF3YWl0IGZldGNoS2V5KHNlbmRlck5hbWUsIHRydWUsIHRydWUpO1xuICAgICAgICAgICAgICAgIGNvbnRlbnRUb0VuY3J5cHQgPSBKU09OLnN0cmluZ2lmeShbXCIyXCIsIGFnZW50TmFtZSwgbm9uY2VCXSk7XG4gICAgICAgICAgICAgICAgZW5jcnlwdGVkTWVzc2FnZSA9IGF3YWl0IGVuY3J5cHRXaXRoUHVibGljS2V5KHBrZXlBLCBjb250ZW50VG9FbmNyeXB0KTtcbiAgICAgICAgICAgICAgICBcbiAgICAgICAgICAgICAgICBhd2FpdCBzZW5kTWVzc2FnZShhZ2VudE5hbWUsIHNlbmRlck5hbWUsIGVuY3J5cHRlZE1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiBbZmFsc2UsIFwiXCIsIFwiXCJdO1xuXG4gICAgICAgICAgICBjYXNlIDI6XG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coXCJFdGFwZSAzIDogTm9uY2UgcmVjdSBkZSAgXCIgKyBzZW5kZXJOYW1lICsgXCIuIEVudm9pIGRlIG5vbmNlQS5cIik7XG4gICAgICAgICAgICAgICAgY29uc3QgcmVjZWl2ZWROb25jZUIgPSBkYXRhQXJyYXlbMl07XG4gICAgICAgICAgICAgICAgY29uc3Qgbm9uY2VBID0gZ2VuZXJhdGVOb25jZSgpO1xuICAgICAgICAgICAgICAgIGNvbnN0IG1lc3NhZ2VDb250ZW50ID0gbWVzc2FnZUcudmFsdWU7IFxuXG4gICAgICAgICAgICAgICAgbm9uY2VUYWJsZS5zZXQobm9uY2VBLCBzZW5kZXJOYW1lKTsgXG5cbiAgICAgICAgICAgICAgICBwa2V5QiA9IGF3YWl0IGZldGNoS2V5KHNlbmRlck5hbWUsIHRydWUsIHRydWUpO1xuICAgICAgICAgICAgICAgIGNvbnRlbnRUb0VuY3J5cHQgPSBKU09OLnN0cmluZ2lmeShbXCIzXCIsIGFnZW50TmFtZSwgcmVjZWl2ZWROb25jZUIsIG1lc3NhZ2VDb250ZW50LCBub25jZUFdKTtcbiAgICAgICAgICAgICAgICBlbmNyeXB0ZWRNZXNzYWdlID0gYXdhaXQgZW5jcnlwdFdpdGhQdWJsaWNLZXkocGtleUIsIGNvbnRlbnRUb0VuY3J5cHQpO1xuICAgICAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgIGF3YWl0IHNlbmRNZXNzYWdlKGFnZW50TmFtZSwgc2VuZGVyTmFtZSwgZW5jcnlwdGVkTWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgXG4gICAgICAgICAgICAgICAgYWRkaW5nUmVjZWl2ZWRNZXNzYWdlKGFnZW50TmFtZSArIFwiIC0+IFwiICsgc2VuZGVyTmFtZSArIFwiIDogXCIgKyBtZXNzYWdlQ29udGVudCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFtmYWxzZSwgXCJcIiwgXCJcIl07XG5cbiAgICAgICAgICAgIGNhc2UgMzpcbiAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcIkV0YXBlIDQgOiBWXHUwMEU5cmlmaWNhdGlvbiBkZSBub25jZUIgZXQgY29uZmlybWF0aW9uLlwiKTtcbiAgICAgICAgICAgICAgICBjb25zdCBjaGVja05vbmNlQiA9IGRhdGFBcnJheVsyXTtcbiAgICAgICAgICAgICAgICBjb25zdCBmaW5hbFNlY3JldCA9IGRhdGFBcnJheVszXTtcbiAgICAgICAgICAgICAgICBjb25zdCByZWNlaXZlZE5vbmNlQSA9IGRhdGFBcnJheVs0XTtcblxuICAgICAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgIGlmIChub25jZVRhYmxlLmdldChjaGVja05vbmNlQikgPT09IHNlbmRlck5hbWUpIHtcbiAgICAgICAgICAgICAgICAgICAgbm9uY2VUYWJsZS5kZWxldGUoY2hlY2tOb25jZUIpOyBcblxuICAgICAgICAgICAgICAgICAgICBwa2V5QSA9IGF3YWl0IGZldGNoS2V5KHNlbmRlck5hbWUsIHRydWUsIHRydWUpO1xuICAgICAgICAgICAgICAgICAgICBjb250ZW50VG9FbmNyeXB0ID0gSlNPTi5zdHJpbmdpZnkoW1wiNFwiLCBhZ2VudE5hbWUsIGZpbmFsU2VjcmV0LCByZWNlaXZlZE5vbmNlQV0pO1xuICAgICAgICAgICAgICAgICAgICBlbmNyeXB0ZWRNZXNzYWdlID0gYXdhaXQgZW5jcnlwdFdpdGhQdWJsaWNLZXkocGtleUEsIGNvbnRlbnRUb0VuY3J5cHQpO1xuICAgICAgICAgICAgICAgICAgICBcbiAgICAgICAgICAgICAgICAgICAgYXdhaXQgc2VuZE1lc3NhZ2UoYWdlbnROYW1lLCBzZW5kZXJOYW1lLCBlbmNyeXB0ZWRNZXNzYWdlKTtcblxuICAgICAgICAgICAgICAgICAgICByZXR1cm4gW3RydWUsIHNlbmRlck5hbWUsIGZpbmFsU2VjcmV0XTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY29uc29sZS5sb2coXCJBbGVydGUgOiBMZSBub25jZSByZVx1MDBFN3UgbmUgY29ycmVzcG9uZCBwYXMgXHUwMEUwIGxhIHNlc3Npb24gIVwiKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gW2ZhbHNlLCBcIlwiLCBcIlwiXTtcblxuICAgICAgICAgICAgY2FzZSA0OlxuICAgICAgICAgICAgICAgIGNvbnN0IGNoZWNrTm9uY2VBID0gZGF0YUFycmF5WzNdO1xuXG4gICAgICAgICAgICAgICAgaWYgKG5vbmNlVGFibGUuZ2V0KGNoZWNrTm9uY2VBKSA9PT0gc2VuZGVyTmFtZSkge1xuICAgICAgICAgICAgICAgICAgICBub25jZVRhYmxlLmRlbGV0ZShjaGVja05vbmNlQSk7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU3VjY1x1MDBFOHMgOiBcIiArIHNlbmRlck5hbWUgKyBcIiBjb25maXJtZSBsYSByXHUwMEU5Y2VwdGlvbiBkdSBzZWNyZXQuXCIpO1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcIlNZU1RFTSAtPiBNZXNzYWdlIGJpZW4gcmVcdTAwRTd1IHBhciBcIiArIHNlbmRlck5hbWUgKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgcmV0dXJuIFtmYWxzZSwgXCJcIiwgXCJcIl07XG5cbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgcmV0dXJuIFtmYWxzZSwgXCJcIiwgXCJcIl07XG4gICAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zb2xlLmxvZyhcIkVycmV1ciBkYW5zIGxlIHByb3RvY29sZSA6IFwiLCBlcnJvcik7XG4gICAgICAgIHJldHVybiBb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Y0FBTSxTQUFTLGNBQWM7QUFDN0IsY0FBTSxpQkFBaUIsU0FBUztBQUVoQyxtQkFBVyxJQUFJLFFBQVEsVUFBVTtBQUVqQyxnQkFBUSxNQUFNLFNBQVMsWUFBWSxNQUFNLElBQUk7QUFDN0MsMkJBQW1CLEtBQUssVUFBVSxDQUFDLEtBQUssV0FBVyxnQkFBZ0IsZ0JBQWdCLE1BQU0sQ0FBQztBQUMxRiwyQkFBbUIsTUFBTSxxQkFBcUIsT0FBTyxnQkFBZ0I7QUFFckUsY0FBTSxZQUFZLFdBQVcsWUFBWSxnQkFBZ0I7QUFFekQsOEJBQXNCLFlBQVksU0FBUyxhQUFhLFFBQVEsY0FBYztBQUM5RSxlQUFPLENBQUMsT0FBTyxJQUFJLEVBQUU7QUFBQSxNQUV6QixLQUFLO0FBQ0QsZ0JBQVEsSUFBSSxzREFBbUQ7QUFDL0QsY0FBTSxjQUFjLFVBQVUsQ0FBQztBQUMvQixjQUFNLGNBQWMsVUFBVSxDQUFDO0FBQy9CLGNBQU0saUJBQWlCLFVBQVUsQ0FBQztBQUdsQyxZQUFJLFdBQVcsSUFBSSxXQUFXLE1BQU0sWUFBWTtBQUM1QyxxQkFBVyxPQUFPLFdBQVc7QUFFN0Isa0JBQVEsTUFBTSxTQUFTLFlBQVksTUFBTSxJQUFJO0FBQzdDLDZCQUFtQixLQUFLLFVBQVUsQ0FBQyxLQUFLLFdBQVcsYUFBYSxjQUFjLENBQUM7QUFDL0UsNkJBQW1CLE1BQU0scUJBQXFCLE9BQU8sZ0JBQWdCO0FBRXJFLGdCQUFNLFlBQVksV0FBVyxZQUFZLGdCQUFnQjtBQUV6RCxpQkFBTyxDQUFDLE1BQU0sWUFBWSxXQUFXO0FBQUEsUUFDekM7QUFDQSxnQkFBUSxJQUFJLCtEQUF5RDtBQUNyRSxlQUFPLENBQUMsT0FBTyxJQUFJLEVBQUU7QUFBQSxNQUV6QixLQUFLO0FBQ0QsY0FBTSxjQUFjLFVBQVUsQ0FBQztBQUUvQixZQUFJLFdBQVcsSUFBSSxXQUFXLE1BQU0sWUFBWTtBQUM1QyxxQkFBVyxPQUFPLFdBQVc7QUFDN0Isa0JBQVEsSUFBSSxpQkFBYyxhQUFhLHNDQUFtQztBQUMxRSxrQkFBUSxJQUFJLHdDQUFxQyxVQUFXO0FBQUEsUUFDaEU7QUFDQSxlQUFPLENBQUMsT0FBTyxJQUFJLEVBQUU7QUFBQSxNQUV6QjtBQUNJLGVBQU8sQ0FBQyxPQUFPLElBQUksRUFBRTtBQUFBLElBQzdCO0FBQUEsRUFDSixTQUFTLE9BQU87QUFDWixZQUFRLElBQUksK0JBQStCLEtBQUs7QUFDaEQsV0FBTyxDQUFDLE9BQU8sSUFBSSxFQUFFO0FBQUEsRUFDekI7QUFDSjsiLAogICJuYW1lcyI6IFsicmVjZWl2ZXIiXQp9Cg==
