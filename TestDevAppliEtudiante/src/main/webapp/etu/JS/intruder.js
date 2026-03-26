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

// src/serverMessages.ts
var CasUserName = class {
  constructor(username) {
    this.username = username;
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
var FilterRequest = class {
  constructor(from2, to2, indexmin) {
    this.from = from2;
    this.to = to2;
    this.indexmin = indexmin;
  }
};
var FilteredMessage = class {
  constructor(message, index, deleted, deleter) {
    this.message = message;
    this.index = index;
    this.deleted = deleted;
    this.deleter = deleter;
  }
};
var FilteringAnswer = class {
  constructor(success, failureMessage, allMessages) {
    this.success = success;
    this.failureMessage = failureMessage;
    this.allMessages = allMessages;
  }
};
var SendResult = class {
  constructor(success, errorMessage) {
    this.success = success;
    this.errorMessage = errorMessage;
  }
};
var ExtMessage = class {
  constructor(sender, receiver, content) {
    this.sender = sender;
    this.receiver = receiver;
    this.content = content;
  }
};
var DeletingRequest = class {
  constructor(indexToDelete) {
    this.indexToDelete = indexToDelete;
  }
};
var DeletingAnswer = class {
  constructor(success, message) {
    this.success = success;
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

// src/intruder.ts
var filterButton = document.getElementById("filter-button");
var sendButton = document.getElementById("send-button");
var deleteButton = document.getElementById("delete-button");
var getPublicKeyButton = document.getElementById("get-public-key-button");
var getPrivateKeyButton = document.getElementById("get-private-key-button");
var generateNonceButton = document.getElementById("generate-nonce-button");
var public_key_owner = document.getElementById("public-key-owner");
var private_key_owner = document.getElementById("private-key-owner");
var publicKeyElementEnc = document.getElementById("public-key-enc");
var privateKeyElementEnc = document.getElementById("private-key-enc");
var publicKeyElementSign = document.getElementById("public-key-sign");
var privateKeyElementSign = document.getElementById("private-key-sign");
var nonceTextElement = document.getElementById("nonce");
var from = document.getElementById("from");
var to = document.getElementById("to");
var indexminElt = document.getElementById("indexmin");
var filtered_messages = document.getElementById("filtered-messages");
var sendfrom = document.getElementById("sendfrom");
var sendto = document.getElementById("sendto");
var sendcontent = document.getElementById("sendcontent");
var deleteIndex = document.getElementById("deleteindex");
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
  return nameResult.username;
}
async function setCasName() {
  public_key_owner.value = await fetchCasName();
  private_key_owner.value = await fetchCasName();
}
setCasName();
function getOwnerName() {
  const path = window.location.pathname;
  const name = path.split("/", 2)[1];
  return name;
}
var ownerName = getOwnerName();
function clearingMessages() {
  filtered_messages.textContent = "";
}
var entityMap = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "/": "&#x2F;",
  "`": "&#x60;",
  "=": "&#x3D;"
};
function escapeHtml(string) {
  return String(string).replace(/[&<>"'`=\/]/g, function(s) {
    return entityMap[s];
  });
}
function stringToHTML(str) {
  var div_elt = document.createElement("div");
  div_elt.innerHTML = str;
  return div_elt;
}
function addingFilteredMessage(message) {
  filtered_messages.append(stringToHTML("<p></p><p></p>" + message));
}
generateNonceButton.onclick = function() {
  const nonce = generateNonce();
  nonceTextElement.textContent = nonce;
};
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
getPublicKeyButton.onclick = async function() {
  const public_key_owner_name = public_key_owner.value;
  const publicKeyEnc = await fetchKey(public_key_owner_name, true, true);
  const publicKeySign = await fetchKey(public_key_owner_name, true, false);
  publicKeyElementEnc.textContent = await publicKeyToString(publicKeyEnc);
  publicKeyElementSign.textContent = await publicKeyToString(publicKeySign);
};
getPrivateKeyButton.onclick = async function() {
  const private_key_owner_name = private_key_owner.value;
  const privateKeyEnc = await fetchKey(private_key_owner_name, false, true);
  const privateKeySign = await fetchKey(private_key_owner_name, false, false);
  privateKeyElementEnc.textContent = await privateKeyToString(privateKeyEnc);
  privateKeyElementSign.textContent = await privateKeyToString(privateKeySign);
};
deleteButton.onclick = async function() {
  let indexToDelete = deleteIndex.value;
  try {
    let deleteRequest = new DeletingRequest(indexToDelete);
    const request = await fetch("/deleting/" + ownerName, {
      method: "POST",
      body: JSON.stringify(deleteRequest),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    return await request.json();
  } catch (error) {
    if (error instanceof Error) {
      alert(error.message);
      return new DeletingAnswer(false, error.message);
    } else {
      console.log("unexpected error: ", error);
      return new DeletingAnswer(false, "An unexpected error occurred");
    }
  }
};
async function sendMessage(agentName, receiverName, messageContent) {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
    const request = await fetch("/intruderSendingMessage/" + ownerName, {
      method: "POST",
      body: JSON.stringify(messageToSend),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    return await request.json();
  } catch (error) {
    if (error instanceof Error) {
      console.log(error.message);
      return new SendResult(false, error.message);
    } else {
      console.log(error);
      return new SendResult(false, "An unexpected error occurred");
    }
  }
}
sendButton.onclick = async function() {
  let agentName = sendfrom.value;
  let receiverName = sendto.value;
  let content = sendcontent.value;
  try {
    const sendResult = await sendMessage(agentName, receiverName, content);
    if (!sendResult.success) alert(sendResult.errorMessage);
    else {
      console.log("Successfully sent the message!");
    }
  } catch (e) {
    if (e instanceof Error) {
      console.log(e.message);
    } else {
      console.log(e);
    }
  }
};
filterButton.onclick = async function() {
  try {
    const fromText = from.value;
    const toText = to.value;
    const indexmin = indexminElt.value;
    const filterRequest = new FilterRequest(fromText, toText, indexmin);
    const request = await fetch("/filtering/" + ownerName, {
      method: "POST",
      body: JSON.stringify(filterRequest),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    const result = await request.json();
    if (!result.success) {
      alert(result.failureMessage);
    } else {
      clearingMessages();
      for (var filt_message of result.allMessages) {
        if (filt_message.deleted) {
          addingFilteredMessage(`Index: ${filt_message.index} Deleted by: ${filt_message.deleter} <strike> From: ${escapeHtml(filt_message.message.sender)} To: ${escapeHtml(filt_message.message.receiver)} Content: ${escapeHtml(filt_message.message.content)} </strike>`);
        } else {
          addingFilteredMessage(`Index: ${filt_message.index} From: ${escapeHtml(filt_message.message.sender)} To: ${escapeHtml(filt_message.message.receiver)} Content: ${escapeHtml(filt_message.message.content)}`);
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
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvc2VydmVyTWVzc2FnZXMudHMiLCAiLi4vc3JjL2ludHJ1ZGVyLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBTb3VyY2U6IGh0dHBzOi8vZ2lzdC5naXRodWIuY29tL2dyb3VuZHJhY2UvYjUxNDEwNjJiNDdkZDk2YTVjMjFjOTM4MzlkNGI5NTQgKi9cblxuLyogQXZhaWxhYmxlIGZ1bmN0aW9uczpcblxuICAgICMgS2V5L25vbmNlIGdlbmVyYXRpb246XG4gICAgZ2VuZXJhdGVhc3ltbWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT5cbiAgICBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBnZW5lcmF0ZU5vbmNlKCk6IHN0cmluZ1xuXG4gICAgIyBhc3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb24vU2lnbmF0dXJlL1NpZ25hdHVyZSB2ZXJpZmljYXRpb25cbiAgICBlbmNyeXB0V2l0aFB1YmxpY0tleShwa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShza2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj5cblxuICAgICMgU3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb25cbiAgICBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT5cbiAgICBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSW1wb3J0aW5nIGtleXMgZnJvbSBzdHJpbmdcbiAgICBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoc2tleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cblxuICAgICMgRXhwb3J0aW5nIGtleXMgdG8gc3RyaW5nXG4gICAgcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBwcml2YXRlS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPlxuXG4gICAgIyBIYXNoaW5nXG4gICAgaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiovXG5cbi8vIGltcG9ydCB7IHN1YnRsZSB9IGZyb20gJ2NyeXB0bydcbi8vIExpYkNyeXB0by0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIl1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShwa2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIocGtleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInNwa2lcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1widmVyaWZ5XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKVxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJwa2NzOFwiID8/IGZvcm1hdCBmb3IgaW1wb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBLU9BRVBcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHJpdmF0ZSBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSlcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wic2lnblwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwdWJsaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwic3BraVwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEdlbmVyYXRlcyBhIHBhaXIgb2YgcHVibGljIGFuZCBwcml2YXRlIFJTQSBrZXlzIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yRW5jcnlwdGlvbigpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIFtrZXlwYWlyLnB1YmxpY0tleSwga2V5cGFpci5wcml2YXRlS2V5XVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3Igc2lnbmluZy92ZXJpZnlpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+IHtcbiAgICBjb25zdCBrZXlwYWlyOiBDcnlwdG9LZXlQYWlyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IDIwNDgsXG4gICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzEsIDAsIDFdKSxcbiAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJzaWduXCIsIFwidmVyaWZ5XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcmFuZG9tIG5vbmNlICovXG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmcge1xuICAgIGNvbnN0IG5vbmNlQXJyYXkgPSBuZXcgVWludDMyQXJyYXkoMSlcbiAgICBzZWxmLmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobm9uY2VBcnJheSlcbiAgICByZXR1cm4gbm9uY2VBcnJheVswXS50b1N0cmluZygpXG59XG5cbi8qIEVuY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIFNpZ24gYSBtZXNzYWdlIHdpdGggYSBwcml2YXRlIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZVRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICBjb25zdCBzaWduZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuc2lnbihcbiAgICAgICAgICAgIFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIHByaXZhdGVLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKHNpZ25lZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIlNpZ25hdHVyZSBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlByaXZhdGUga2V5IG9yIG1lc3NhZ2UgdG8gc2lnbiBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBEZWNyeXB0cyBhIG1lc3NhZ2Ugd2l0aCBhIHByaXZhdGUga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVjcnlwdFdpdGhQcml2YXRlS2V5KHByaXZhdGVLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBkZWNyeXRwZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLmRlY3J5cHQoXG4gICAgICAgICAgICAgICAgeyBuYW1lOiBcIlJTQS1PQUVQXCIgfSxcbiAgICAgICAgICAgICAgICBwcml2YXRlS2V5LFxuICAgICAgICAgICAgICAgIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9UZXh0KGRlY3J5dHBlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3IgZGVjcnlwdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiUHJpdmF0ZSBrZXkgb3IgbWVzc2FnZSB0byBkZWNyeXB0IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBWZXJpZmljYXRpb24gb2YgYSBzaWduYXR1cmUgb24gYSBtZXNzYWdlIHdpdGggYSBwdWJsaWMga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleShwdWJsaWNLZXk6IENyeXB0b0tleSwgbWVzc2FnZUluQ2xlYXI6IHN0cmluZywgc2lnbmVkTWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qgc2lnbmVkVG9BcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2lnbmVkTWVzc2FnZSlcbiAgICAgICAgY29uc3QgbWVzc2FnZUluQ2xlYXJUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZUluQ2xlYXIpXG4gICAgICAgIGNvbnN0IHZlcmlmaWVkOiBib29sZWFuID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLnZlcmlmeShcbiAgICAgICAgICAgICAgICBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgcHVibGljS2V5LFxuICAgICAgICAgICAgICAgIHNpZ25lZFRvQXJyYXlCdWZmZXIsXG4gICAgICAgICAgICAgICAgbWVzc2FnZUluQ2xlYXJUb0FycmF5QnVmZmVyKVxuICAgICAgICByZXR1cm4gdmVyaWZpZWRcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiUHVibGljIGtleSBvciBzaWduZWQgbWVzc2FnZSB0byB2ZXJpZnkgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIEdlbmVyYXRlcyBhIHN5bW1ldHJpYyBBRVMtR0NNIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU3ltZXRyaWNLZXkoKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIkFFUy1HQ01cIixcbiAgICAgICAgICAgIGxlbmd0aDogMjU2LFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJlbmNyeXB0XCIsIFwiZGVjcnlwdFwiXVxuICAgIClcbiAgICByZXR1cm4ga2V5XG59XG5cbi8qIGEgc3ltbWV0cmljIEFFUyBrZXkgaW50byBhIHN0cmluZyAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN5bW1ldHJpY0tleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJyYXdcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKiBJbXBvcnRzIHRoZSBnaXZlbiBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBBRVMga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9TeW1tZXRyaWNLZXkoc2tleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHNrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJyYXdcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAgXCJBRVMtR0NNXCIsXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgc3ltbWV0cmljIGtleSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBzeW1tZXRyaWMga2V5IGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vLyBXaGVuIGN5cGhlcmluZyBhIG1lc3NhZ2Ugd2l0aCBhIGtleSBpbiBBRVMsIHdlIG9idGFpbiBhIGN5cGhlcmVkIG1lc3NhZ2UgYW5kIGFuIFwiaW5pdGlhbGlzYXRpb24gdmVjdG9yXCIuXG4vLyBJbiB0aGlzIGltcGxlbWVudGF0aW9uLCB0aGUgb3V0cHV0IGlzIGEgdHdvIGVsZW1lbnRzIGFycmF5IHQgc3VjaCB0aGF0IHRbMF0gaXMgdGhlIGN5cGhlcmVkIG1lc3NhZ2Vcbi8vIGFuZCB0WzFdIGlzIHRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3IuIFRvIHNpbXBsaWZ5LCB0aGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yIGlzIHJlcHJlc2VudGVkIGJ5IGEgc3RyaW5nLlxuLy8gVGhlIGluaXRpYWxpc2F0aW9uIHZlY3RvcmUgaXMgdXNlZCBmb3IgcHJvdGVjdGluZyB0aGUgZW5jcnlwdGlvbiwgaS5lLCAyIGVuY3J5cHRpb25zIG9mIHRoZSBzYW1lIG1lc3NhZ2UgXG4vLyB3aXRoIHRoZSBzYW1lIGtleSB3aWxsIG5ldmVyIHJlc3VsdCBpbnRvIHRoZSBzYW1lIGVuY3J5cHRlZCBtZXNzYWdlLlxuLy8gXG4vLyBOb3RlIHRoYXQgZm9yIGRlY3lwaGVyaW5nLCB0aGUgKipzYW1lKiogaW5pdGlhbGlzYXRpb24gdmVjdG9yIHdpbGwgYmUgbmVlZGVkLlxuLy8gVGhpcyB2ZWN0b3IgY2FuIHNhZmVseSBiZSB0cmFuc2ZlcnJlZCBpbiBjbGVhciB3aXRoIHRoZSBlbmNyeXB0ZWQgbWVzc2FnZS5cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5KGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZ1tdPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZVRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICBjb25zdCBpdiA9IHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7XG4gICAgICAgIGNvbnN0IGl2VGV4dCA9IGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoaXYpXG4gICAgICAgIGNvbnN0IGN5cGhlcmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmVuY3J5cHQoXG4gICAgICAgICAgICB7IG5hbWU6IFwiQUVTLUdDTVwiLCBpdiB9LFxuICAgICAgICAgICAga2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gW2FycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoY3lwaGVyZWRNZXNzYWdlQUIpLCBpdlRleHRdXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhlKTsgY29uc29sZS5sb2coXCJFbmNyeXB0aW9uIGZhaWxlZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3ltbWV0cmljIGtleSBvciBtZXNzYWdlIHRvIGVuY3J5cHQgaXMgaWxsLWZvcm1lZFwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8vIEZvciBkZWN5cGhlcmluZywgd2UgbmVlZCB0aGUga2V5LCB0aGUgY3lwaGVyZWQgbWVzc2FnZSBhbmQgdGhlIGluaXRpYWxpemF0aW9uIHZlY3Rvci4gU2VlIGFib3ZlIHRoZSBcbi8vIGNvbW1lbnRzIGZvciB0aGUgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkgZnVuY3Rpb25cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGRlY29kZWRJbml0VmVjdG9yOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoaW5pdFZlY3RvcilcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBkZWNyeXRwZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLmRlY3J5cHQoXG4gICAgICAgICAgICAgICAgeyBuYW1lOiBcIkFFUy1HQ01cIiwgaXY6IGRlY29kZWRJbml0VmVjdG9yIH0sXG4gICAgICAgICAgICAgICAga2V5LFxuICAgICAgICAgICAgICAgIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9UZXh0KGRlY3J5dHBlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3IgZGVjcnlwdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU3ltbWV0cmljIGtleSBvciBtZXNzYWdlIHRvIGRlY3J5cHQgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vLyBTSEEtMjU2IEhhc2ggZnJvbSBhIHRleHRcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBoYXNoKHRleHQ6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgdGV4dDJhcnJheUJ1ZiA9IHRleHRUb0FycmF5QnVmZmVyKHRleHQpXG4gICAgY29uc3QgaGFzaGVkQXJyYXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kaWdlc3QoXCJTSEEtMjU2XCIsIHRleHQyYXJyYXlCdWYpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoaGFzaGVkQXJyYXkpXG59XG5cbmNsYXNzIEtleVN0cmluZ0NvcnJ1cHRlZCBleHRlbmRzIEVycm9yIHsgfVxuXG4vLyBBcnJheUJ1ZmZlciB0byBhIEJhc2U2NCBzdHJpbmdcbmZ1bmN0aW9uIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoYXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgICB2YXIgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpXG4gICAgdmFyIGJ5dGVTdHJpbmcgPSAnJ1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZUFycmF5LmJ5dGVMZW5ndGg7IGkrKykge1xuICAgICAgICBieXRlU3RyaW5nICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZUFycmF5W2ldKVxuICAgIH1cbiAgICByZXR1cm4gYnRvYShieXRlU3RyaW5nKVxufVxuXG4vLyBCYXNlNjQgc3RyaW5nIHRvIGFuIGFycmF5QnVmZmVyXG5mdW5jdGlvbiBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKGI2NHN0cjogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHRyeSB7XG4gICAgICAgIHZhciBieXRlU3RyID0gYXRvYihiNjRzdHIpXG4gICAgICAgIHZhciBieXRlcyA9IG5ldyBVaW50OEFycmF5KGJ5dGVTdHIubGVuZ3RoKVxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVTdHIubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGJ5dGVzW2ldID0gYnl0ZVN0ci5jaGFyQ29kZUF0KGkpXG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGJ5dGVzLmJ1ZmZlclxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFN0cmluZyBzdGFydGluZyBieSAnJHtiNjRzdHIuc3Vic3RyaW5nKDAsIDEwKX0nIGNhbm5vdCBiZSBjb252ZXJ0ZWQgdG8gYSB2YWxpZCBrZXkgb3IgbWVzc2FnZWApXG4gICAgICAgIHRocm93IG5ldyBLZXlTdHJpbmdDb3JydXB0ZWRcbiAgICB9XG59XG5cbi8vIFN0cmluZyB0byBhcnJheSBidWZmZXJcbmZ1bmN0aW9uIHRleHRUb0FycmF5QnVmZmVyKHN0cjogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHZhciBidWYgPSBlbmNvZGVVUklDb21wb25lbnQoc3RyKSAvLyAyIGJ5dGVzIGZvciBlYWNoIGNoYXJcbiAgICB2YXIgYnVmVmlldyA9IG5ldyBVaW50OEFycmF5KGJ1Zi5sZW5ndGgpXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBidWYubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnVmVmlld1tpXSA9IGJ1Zi5jaGFyQ29kZUF0KGkpXG4gICAgfVxuICAgIHJldHVybiBidWZWaWV3XG59XG5cbi8vIEFycmF5IGJ1ZmZlcnMgdG8gc3RyaW5nXG5mdW5jdGlvbiBhcnJheUJ1ZmZlclRvVGV4dChhcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICAgIHZhciBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShhcnJheUJ1ZmZlcilcbiAgICB2YXIgc3RyID0gJydcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVBcnJheS5ieXRlTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZUFycmF5W2ldKVxuICAgIH1cbiAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KHN0cilcbn1cblxuIiwgIi8vIEFsbCBtZXNzYWdlIHR5cGVzIGJldHdlZW4gdGhlIGFwcGxpY2F0aW9uIGFuZCB0aGUgc2VydmVyXG4vLyBNZXNzYWdlIGZvciB1c2VyIG5hbWVcbmV4cG9ydCBjbGFzcyBDYXNVc2VyTmFtZSB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHVzZXJuYW1lOiBzdHJpbmcpIHsgfVxufVxuXG5cbi8vIE1lc3NhZ2UgZm9yIHJlcXVpcmluZyBoaXN0b3J5XG5leHBvcnQgY2xhc3MgSGlzdG9yeVJlcXVlc3Qge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBhZ2VudE5hbWU6IHN0cmluZywgcHVibGljIGluZGV4OiBudW1iZXIpIHsgfVxufVxuXG4vLyBSZXN1bHQgb2YgaGlzdG9yeSByZXF1ZXN0XG5leHBvcnQgY2xhc3MgSGlzdG9yeUFuc3dlciB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sXG4gICAgICAgIHB1YmxpYyBmYWlsdXJlTWVzc2FnZTogc3RyaW5nLFxuICAgICAgICBwdWJsaWMgaW5kZXg6IG51bWJlcixcbiAgICAgICAgcHVibGljIGFsbE1lc3NhZ2VzOiBFeHRNZXNzYWdlW10pIHsgfVxufVxuXG4vLyBGaWx0ZXJpbmcgb2YgbWVzc2FnZXNcbmV4cG9ydCBjbGFzcyBGaWx0ZXJSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgZnJvbTogc3RyaW5nLCBwdWJsaWMgdG86IHN0cmluZywgcHVibGljIGluZGV4bWluOiBzdHJpbmcpIHsgfVxufVxuXG5leHBvcnQgY2xhc3MgRmlsdGVyZWRNZXNzYWdlIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgbWVzc2FnZTogRXh0TWVzc2FnZSxcbiAgICAgICAgcHVibGljIGluZGV4OiBudW1iZXIsXG4gICAgICAgIHB1YmxpYyBkZWxldGVkOiBib29sZWFuLFxuICAgICAgICBwdWJsaWMgZGVsZXRlcjogc3RyaW5nKSB7IH1cbn1cblxuLy8gUmVzdWx0IG9mIGZpbHRlcmluZyByZXF1ZXN0XG5leHBvcnQgY2xhc3MgRmlsdGVyaW5nQW5zd2VyIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc3VjY2VzczogYm9vbGVhbixcbiAgICAgICAgcHVibGljIGZhaWx1cmVNZXNzYWdlOiBzdHJpbmcsXG4gICAgICAgIHB1YmxpYyBhbGxNZXNzYWdlczogRmlsdGVyZWRNZXNzYWdlW10pIHsgfVxufVxuXG4vLyBTZW5kaW5nIGEgbWVzc2FnZSBSZXN1bHQgZm9ybWF0XG5leHBvcnQgY2xhc3MgU2VuZFJlc3VsdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sIHB1YmxpYyBlcnJvck1lc3NhZ2U6IHN0cmluZykgeyB9XG59XG5cbi8vIFNlbmRpbmcgbWVzc2FnZXNcbi8vIFRoZSBtZXNzYWdlIGZvcm1hdFxuZXhwb3J0IGNsYXNzIEV4dE1lc3NhZ2Uge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzZW5kZXI6IHN0cmluZywgcHVibGljIHJlY2VpdmVyOiBzdHJpbmcsIHB1YmxpYyBjb250ZW50OiBzdHJpbmcpIHsgfVxufVxuXG5leHBvcnQgY2xhc3MgRGVsZXRpbmdSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihcbiAgICAgICAgcHVibGljIGluZGV4VG9EZWxldGU6IHN0cmluZykgeyB9XG59XG5cbmV4cG9ydCBjbGFzcyBEZWxldGluZ0Fuc3dlciB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sXG4gICAgICAgIG1lc3NhZ2U6IHN0cmluZykgeyB9XG59XG5cbi8vIFJlcXVlc3Rpbmcga2V5c1xuZXhwb3J0IGNsYXNzIEtleVJlcXVlc3Qge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBvd25lck9mVGhlS2V5OiBzdHJpbmcsIHB1YmxpYyBwdWJsaWNLZXk6IGJvb2xlYW4sIHB1YmxpYyBlbmNyeXB0aW9uOiBib29sZWFuKSB7IH1cbn1cblxuZXhwb3J0IGNsYXNzIEtleVJlc3VsdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sIHB1YmxpYyBrZXk6IHN0cmluZywgcHVibGljIGVycm9yTWVzc2FnZTogc3RyaW5nKSB7IH1cbn0iLCAiLyogdHNjIC0taW5saW5lU291cmNlTWFwIHRydWUgLW91dEZpbGUgSlMvaW50cnVkZXIuanMgc3JjL2xpYkNyeXB0by50cyBzcmMvaW50cnVkZXIudHMgLS10YXJnZXQgZXMyMDE1ICovXG5cbmltcG9ydCB7XG4gICAgZ2VuZXJhdGVOb25jZSxcbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uLCBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24sXG4gICAgcHVibGljS2V5VG9TdHJpbmcsIHByaXZhdGVLZXlUb1N0cmluZywgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlLFxuICAgIHN0cmluZ1RvUHVibGljS2V5Rm9yU2lnbmF0dXJlLFxufSBmcm9tICcuL2xpYkNyeXB0bydcblxuaW1wb3J0IHtcbiAgICBEZWxldGluZ1JlcXVlc3QsIERlbGV0aW5nQW5zd2VyLCBGaWx0ZXJSZXF1ZXN0LCBGaWx0ZXJpbmdBbnN3ZXIsIEtleVJlcXVlc3QsXG4gICAgS2V5UmVzdWx0LCBDYXNVc2VyTmFtZSwgRXh0TWVzc2FnZSwgU2VuZFJlc3VsdFxufSBmcm9tICcuL3NlcnZlck1lc3NhZ2VzJ1xuXG5jb25zdCBmaWx0ZXJCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImZpbHRlci1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcbmNvbnN0IHNlbmRCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInNlbmQtYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCBkZWxldGVCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImRlbGV0ZS1idXR0b25cIikgYXMgSFRNTEJ1dHRvbkVsZW1lbnRcbmNvbnN0IGdldFB1YmxpY0tleUJ1dHRvbiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZ2V0LXB1YmxpYy1rZXktYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5jb25zdCBnZXRQcml2YXRlS2V5QnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJnZXQtcHJpdmF0ZS1rZXktYnV0dG9uXCIpIGFzIEhUTUxCdXR0b25FbGVtZW50XG5cbmNvbnN0IGdlbmVyYXRlTm9uY2VCdXR0b24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImdlbmVyYXRlLW5vbmNlLWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuXG5jb25zdCBwdWJsaWNfa2V5X293bmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJwdWJsaWMta2V5LW93bmVyXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHByaXZhdGVfa2V5X293bmVyID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJwcml2YXRlLWtleS1vd25lclwiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5cbmNvbnN0IHB1YmxpY0tleUVsZW1lbnRFbmMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInB1YmxpYy1rZXktZW5jXCIpIGFzIEhUTUxMYWJlbEVsZW1lbnRcbmNvbnN0IHByaXZhdGVLZXlFbGVtZW50RW5jID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJwcml2YXRlLWtleS1lbmNcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuY29uc3QgcHVibGljS2V5RWxlbWVudFNpZ24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInB1YmxpYy1rZXktc2lnblwiKSBhcyBIVE1MTGFiZWxFbGVtZW50XG5jb25zdCBwcml2YXRlS2V5RWxlbWVudFNpZ24gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInByaXZhdGUta2V5LXNpZ25cIikgYXMgSFRNTExhYmVsRWxlbWVudFxuXG5jb25zdCBub25jZVRleHRFbGVtZW50ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJub25jZVwiKSBhcyBIVE1MTGFiZWxFbGVtZW50XG5cbmNvbnN0IGZyb20gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImZyb21cIikgYXMgSFRNTElucHV0RWxlbWVudFxuY29uc3QgdG8gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInRvXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IGluZGV4bWluRWx0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJpbmRleG1pblwiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5jb25zdCBmaWx0ZXJlZF9tZXNzYWdlcyA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiZmlsdGVyZWQtbWVzc2FnZXNcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuXG5jb25zdCBzZW5kZnJvbSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwic2VuZGZyb21cIikgYXMgSFRNTElucHV0RWxlbWVudFxuY29uc3Qgc2VuZHRvID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJzZW5kdG9cIikgYXMgSFRNTElucHV0RWxlbWVudFxuY29uc3Qgc2VuZGNvbnRlbnQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInNlbmRjb250ZW50XCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IGRlbGV0ZUluZGV4ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJkZWxldGVpbmRleFwiKSBhcyBIVE1MSW5wdXRFbGVtZW50XG5cbmFzeW5jIGZ1bmN0aW9uIGZldGNoQ2FzTmFtZSgpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgY29uc3QgbmFtZXJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9nZXR1c2VyP1wiICsgdXJsUGFyYW1zLCB7XG4gICAgICAgIG1ldGhvZDogXCJHRVRcIixcbiAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIGlmICghbmFtZXJlcXVlc3Qub2spIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke25hbWVyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICB9XG4gICAgY29uc3QgbmFtZVJlc3VsdCA9IChhd2FpdCBuYW1lcmVxdWVzdC5qc29uKCkpIGFzIENhc1VzZXJOYW1lO1xuICAgIHJldHVybiBuYW1lUmVzdWx0LnVzZXJuYW1lXG59XG5cbi8vIFdlIHNldCB0aGUgZGVmYXVsdCBDQVMgbmFtZSBmb3IgdGhlIHB1YmxpYyBrZXkgZmllbGRzXG5hc3luYyBmdW5jdGlvbiBzZXRDYXNOYW1lKCkge1xuICAgIHB1YmxpY19rZXlfb3duZXIudmFsdWUgPSBhd2FpdCBmZXRjaENhc05hbWUoKVxuICAgIHByaXZhdGVfa2V5X293bmVyLnZhbHVlID0gYXdhaXQgZmV0Y2hDYXNOYW1lKClcbn1cbnNldENhc05hbWUoKVxuXG4vKiBOYW1lIG9mIHRoZSBvd25lci9kZXZlbG9wcGVyIG9mIHRoZSBhcHBsaWNhdGlvbiwgaS5lLCB0aGUgbmFtZSBvZiB0aGUgZm9sZGVyIFxuICAgd2hlcmUgdGhlIHdlYiBwYWdlIG9mIHRoZSBhcHBsaWNhdGlvbiBpcyBzdG9yZWQuIEUuZywgZm9yIHRlYWNoZXJzJyBhcHBsaWNhdGlvblxuICAgdGhpcyBuYW1lIGlzIFwiZW5zXCIgKi9cblxuZnVuY3Rpb24gZ2V0T3duZXJOYW1lKCk6IHN0cmluZyB7XG4gICAgY29uc3QgcGF0aCA9IHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZVxuICAgIGNvbnN0IG5hbWUgPSBwYXRoLnNwbGl0KFwiL1wiLCAyKVsxXVxuICAgIHJldHVybiBuYW1lXG59XG5cbmxldCBvd25lck5hbWUgPSBnZXRPd25lck5hbWUoKVxuXG5mdW5jdGlvbiBjbGVhcmluZ01lc3NhZ2VzKCkge1xuICAgIGZpbHRlcmVkX21lc3NhZ2VzLnRleHRDb250ZW50ID0gXCJcIlxufVxuXG5cbmNvbnN0IGVudGl0eU1hcCA9IHtcbiAgJyYnOiAnJmFtcDsnLFxuICAnPCc6ICcmbHQ7JyxcbiAgJz4nOiAnJmd0OycsXG4gICdcIic6ICcmcXVvdDsnLFxuICBcIidcIjogJyYjMzk7JyxcbiAgJy8nOiAnJiN4MkY7JyxcbiAgJ2AnOiAnJiN4NjA7JyxcbiAgJz0nOiAnJiN4M0Q7J1xufTtcblxuZnVuY3Rpb24gZXNjYXBlSHRtbCAoc3RyaW5nKSB7XG4gIHJldHVybiBTdHJpbmcoc3RyaW5nKS5yZXBsYWNlKC9bJjw+XCInYD1cXC9dL2csIGZ1bmN0aW9uIChzKSB7XG4gICAgcmV0dXJuIGVudGl0eU1hcFtzXTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIHN0cmluZ1RvSFRNTChzdHI6IHN0cmluZyk6IEhUTUxEaXZFbGVtZW50IHtcbiAgICB2YXIgZGl2X2VsdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpXG4gICAgZGl2X2VsdC5pbm5lckhUTUwgPSBzdHJcbiAgICByZXR1cm4gZGl2X2VsdFxufVxuXG5mdW5jdGlvbiBhZGRpbmdGaWx0ZXJlZE1lc3NhZ2UobWVzc2FnZTogc3RyaW5nKSB7XG4gICAgZmlsdGVyZWRfbWVzc2FnZXMuYXBwZW5kKHN0cmluZ1RvSFRNTCgnPHA+PC9wPjxwPjwvcD4nICsgKG1lc3NhZ2UpKSlcbn1cblxuZ2VuZXJhdGVOb25jZUJ1dHRvbi5vbmNsaWNrID0gZnVuY3Rpb24gKCkge1xuICAgIGNvbnN0IG5vbmNlID0gZ2VuZXJhdGVOb25jZSgpXG4gICAgbm9uY2VUZXh0RWxlbWVudC50ZXh0Q29udGVudCA9IG5vbmNlXG59XG5cbmFzeW5jIGZ1bmN0aW9uIGZldGNoS2V5KHVzZXI6IHN0cmluZywgcHVibGljS2V5OiBib29sZWFuLCBlbmNyeXB0aW9uOiBib29sZWFuKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICAvLyBHZXR0aW5nIHRoZSBwdWJsaWMvcHJpdmF0ZSBrZXkgb2YgdXNlci5cbiAgICAvLyBGb3IgcHVibGljIGtleSB0aGUgYm9vbGVhbiAncHVibGljS2V5JyBpcyB0cnVlLlxuICAgIC8vIEZvciBwcml2YXRlIGtleSB0aGUgYm9vbGVhbiAncHVibGljS2V5JyBpcyBmYWxzZS5cbiAgICAvLyBJZiB0aGUga2V5IGlzIHVzZWQgZm9yIGVuY3J5cHRpb24vZGVjcnlwdGlvbiB0aGVuIHRoZSBib29sZWFuICdlbmNyeXB0aW9uJyBpcyB0cnVlLlxuICAgIC8vIElmIHRoZSBrZXkgaXMgdXNlZCBmb3Igc2lnbmF0dXJlL3NpZ25hdHVyZSB2ZXJpZmljYXRpb24gdGhlbiB0aGUgYm9vbGVhbiBpcyBmYWxzZS5cbiAgICBjb25zdCBrZXlSZXF1ZXN0TWVzc2FnZSA9XG4gICAgICAgIG5ldyBLZXlSZXF1ZXN0KHVzZXIsIHB1YmxpY0tleSwgZW5jcnlwdGlvbilcbiAgICAvLyBGb3IgQ0FTIGF1dGhlbnRpY2F0aW9uIHdlIG5lZWQgdG8gYWRkIHRoZSBhdXRoZW50aWNhdGlvbiB0aWNrZXRcbiAgICAvLyBJdCBpcyBjb250YWluZWQgaW4gdXJsUGFyYW1zXG4gICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcbiAgICAvLyBGb3IgZ2V0dGluZyBhIGtleSB3ZSBkbyBub3QgbmVlZCB0aGUgb3duZXJOYW1lIHBhcmFtXG4gICAgLy8gQmVjYXVzZSBrZXlzIGFyZSBpbmRlcGVuZGFudCBvZiB0aGUgYXBwbGljYXRpb25zXG4gICAgY29uc3Qga2V5cmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL2dldEtleT9cIiArIHVybFBhcmFtcywge1xuICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShrZXlSZXF1ZXN0TWVzc2FnZSksXG4gICAgICAgIGhlYWRlcnM6IHtcbiAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgIH1cbiAgICB9KTtcbiAgICBpZiAoIWtleXJlcXVlc3Qub2spIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke2tleXJlcXVlc3Quc3RhdHVzfWApO1xuICAgIH1cbiAgICBjb25zdCBrZXlSZXN1bHQgPSAoYXdhaXQga2V5cmVxdWVzdC5qc29uKCkpIGFzIEtleVJlc3VsdDtcbiAgICBpZiAoIWtleVJlc3VsdC5zdWNjZXNzKSBhbGVydChrZXlSZXN1bHQuZXJyb3JNZXNzYWdlKVxuICAgIGVsc2Uge1xuICAgICAgICBpZiAocHVibGljS2V5ICYmIGVuY3J5cHRpb24pIHJldHVybiBhd2FpdCBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24oa2V5UmVzdWx0LmtleSlcbiAgICAgICAgZWxzZSBpZiAoIXB1YmxpY0tleSAmJiBlbmNyeXB0aW9uKSByZXR1cm4gYXdhaXQgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yRW5jcnlwdGlvbihrZXlSZXN1bHQua2V5KVxuICAgICAgICBlbHNlIGlmIChwdWJsaWNLZXkgJiYgIWVuY3J5cHRpb24pIHJldHVybiBhd2FpdCBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShrZXlSZXN1bHQua2V5KVxuICAgICAgICBlbHNlIGlmICghcHVibGljS2V5ICYmICFlbmNyeXB0aW9uKSByZXR1cm4gYXdhaXQgc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKGtleVJlc3VsdC5rZXkpXG4gICAgfVxufVxuXG5nZXRQdWJsaWNLZXlCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICBjb25zdCBwdWJsaWNfa2V5X293bmVyX25hbWUgPSBwdWJsaWNfa2V5X293bmVyLnZhbHVlXG4gICAgY29uc3QgcHVibGljS2V5RW5jID0gYXdhaXQgZmV0Y2hLZXkocHVibGljX2tleV9vd25lcl9uYW1lLCB0cnVlLCB0cnVlKVxuICAgIGNvbnN0IHB1YmxpY0tleVNpZ24gPSBhd2FpdCBmZXRjaEtleShwdWJsaWNfa2V5X293bmVyX25hbWUsIHRydWUsIGZhbHNlKVxuICAgIHB1YmxpY0tleUVsZW1lbnRFbmMudGV4dENvbnRlbnQgPSBhd2FpdCBwdWJsaWNLZXlUb1N0cmluZyhwdWJsaWNLZXlFbmMpXG4gICAgcHVibGljS2V5RWxlbWVudFNpZ24udGV4dENvbnRlbnQgPSBhd2FpdCBwdWJsaWNLZXlUb1N0cmluZyhwdWJsaWNLZXlTaWduKVxufVxuXG5nZXRQcml2YXRlS2V5QnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgY29uc3QgcHJpdmF0ZV9rZXlfb3duZXJfbmFtZSA9IHByaXZhdGVfa2V5X293bmVyLnZhbHVlXG4gICAgY29uc3QgcHJpdmF0ZUtleUVuYyA9IGF3YWl0IGZldGNoS2V5KHByaXZhdGVfa2V5X293bmVyX25hbWUsIGZhbHNlLCB0cnVlKVxuICAgIGNvbnN0IHByaXZhdGVLZXlTaWduID0gYXdhaXQgZmV0Y2hLZXkocHJpdmF0ZV9rZXlfb3duZXJfbmFtZSwgZmFsc2UsIGZhbHNlKVxuICAgIHByaXZhdGVLZXlFbGVtZW50RW5jLnRleHRDb250ZW50ID0gYXdhaXQgcHJpdmF0ZUtleVRvU3RyaW5nKHByaXZhdGVLZXlFbmMpXG4gICAgcHJpdmF0ZUtleUVsZW1lbnRTaWduLnRleHRDb250ZW50ID0gYXdhaXQgcHJpdmF0ZUtleVRvU3RyaW5nKHByaXZhdGVLZXlTaWduKVxufVxuXG5kZWxldGVCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICBsZXQgaW5kZXhUb0RlbGV0ZSA9IGRlbGV0ZUluZGV4LnZhbHVlXG4gICAgdHJ5IHtcbiAgICAgICAgbGV0IGRlbGV0ZVJlcXVlc3QgPVxuICAgICAgICAgICAgbmV3IERlbGV0aW5nUmVxdWVzdChpbmRleFRvRGVsZXRlKVxuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvZGVsZXRpbmcvXCIgKyBvd25lck5hbWUgKyBcIlwiLCB7XG4gICAgICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoZGVsZXRlUmVxdWVzdCksXG4gICAgICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIGlmICghcmVxdWVzdC5vaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke3JlcXVlc3Quc3RhdHVzfWApO1xuICAgICAgICB9XG4gICAgICAgIC8vIERlYWxpbmcgd2l0aCB0aGUgYW5zd2VyIG9mIHRoZSBtZXNzYWdlIHNlcnZlclxuICAgICAgICByZXR1cm4gKGF3YWl0IHJlcXVlc3QuanNvbigpKSBhcyBEZWxldGluZ0Fuc3dlclxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGFsZXJ0KGVycm9yLm1lc3NhZ2UpXG4gICAgICAgICAgICAvL2NvbnNvbGUubG9nKCdlcnJvciBtZXNzYWdlOiAnLCBlcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIHJldHVybiBuZXcgRGVsZXRpbmdBbnN3ZXIoZmFsc2UsIGVycm9yLm1lc3NhZ2UpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygndW5leHBlY3RlZCBlcnJvcjogJywgZXJyb3IpO1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBEZWxldGluZ0Fuc3dlcihmYWxzZSwgJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnKVxuICAgICAgICB9XG4gICAgfVxuXG59XG5cbmFzeW5jIGZ1bmN0aW9uIHNlbmRNZXNzYWdlKGFnZW50TmFtZTogc3RyaW5nLCByZWNlaXZlck5hbWU6IHN0cmluZywgbWVzc2FnZUNvbnRlbnQ6IHN0cmluZyk6IFByb21pc2U8U2VuZFJlc3VsdD4ge1xuICAgIHRyeSB7XG4gICAgICAgIGxldCBtZXNzYWdlVG9TZW5kID0gbmV3IEV4dE1lc3NhZ2UoYWdlbnROYW1lLCByZWNlaXZlck5hbWUsIG1lc3NhZ2VDb250ZW50KVxuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvaW50cnVkZXJTZW5kaW5nTWVzc2FnZS9cIiArIG93bmVyTmFtZSwge1xuICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KG1lc3NhZ2VUb1NlbmQpLFxuICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBEZWFsaW5nIHdpdGggdGhlIGFuc3dlciBvZiB0aGUgbWVzc2FnZSBzZXJ2ZXJcbiAgICAgICAgcmV0dXJuIChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgU2VuZFJlc3VsdFxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKGVycm9yLm1lc3NhZ2UpXG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlbmRSZXN1bHQoZmFsc2UsIGVycm9yLm1lc3NhZ2UpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhlcnJvcilcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2VuZFJlc3VsdChmYWxzZSwgJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnKVxuICAgICAgICB9XG4gICAgfVxufVxuXG4vLyB0aGUgaW50cnVkZXIgc2VuZHMgYSBtZXNzYWdlIGluIHBsYWNlIG9mIGFueSB1c2VyXG5zZW5kQnV0dG9uLm9uY2xpY2sgPSBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgbGV0IGFnZW50TmFtZSA9IHNlbmRmcm9tLnZhbHVlXG4gICAgbGV0IHJlY2VpdmVyTmFtZSA9IHNlbmR0by52YWx1ZVxuICAgIGxldCBjb250ZW50ID0gc2VuZGNvbnRlbnQudmFsdWVcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBzZW5kUmVzdWx0ID0gYXdhaXQgc2VuZE1lc3NhZ2UoYWdlbnROYW1lLCByZWNlaXZlck5hbWUsIGNvbnRlbnQpXG4gICAgICAgIGlmICghc2VuZFJlc3VsdC5zdWNjZXNzKSBhbGVydChzZW5kUmVzdWx0LmVycm9yTWVzc2FnZSlcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIlN1Y2Nlc3NmdWxseSBzZW50IHRoZSBtZXNzYWdlIVwiKVxuICAgICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhlLm1lc3NhZ2UpXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhlKVxuICAgICAgICB9XG4gICAgfVxufVxuXG5maWx0ZXJCdXR0b24ub25jbGljayA9IGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBmcm9tVGV4dCA9IGZyb20udmFsdWVcbiAgICAgICAgY29uc3QgdG9UZXh0ID0gdG8udmFsdWVcbiAgICAgICAgY29uc3QgaW5kZXhtaW4gPSBpbmRleG1pbkVsdC52YWx1ZVxuICAgICAgICBjb25zdCBmaWx0ZXJSZXF1ZXN0ID1cbiAgICAgICAgICAgIG5ldyBGaWx0ZXJSZXF1ZXN0KGZyb21UZXh0LCB0b1RleHQsIGluZGV4bWluKVxuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvZmlsdGVyaW5nL1wiICsgb3duZXJOYW1lLCB7XG4gICAgICAgICAgICBtZXRob2Q6IFwiUE9TVFwiLFxuICAgICAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoZmlsdGVyUmVxdWVzdCksXG4gICAgICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIGlmICghcmVxdWVzdC5vaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke3JlcXVlc3Quc3RhdHVzfWApO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgRmlsdGVyaW5nQW5zd2VyXG4gICAgICAgIGlmICghcmVzdWx0LnN1Y2Nlc3MpIHsgYWxlcnQocmVzdWx0LmZhaWx1cmVNZXNzYWdlKSB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgY2xlYXJpbmdNZXNzYWdlcygpXG4gICAgICAgICAgICBmb3IgKHZhciBmaWx0X21lc3NhZ2Ugb2YgcmVzdWx0LmFsbE1lc3NhZ2VzKSB7XG4gICAgICAgICAgICAgICAgaWYgKGZpbHRfbWVzc2FnZS5kZWxldGVkKSB7XG4gICAgICAgICAgICAgICAgICAgIGFkZGluZ0ZpbHRlcmVkTWVzc2FnZShgSW5kZXg6ICR7ZmlsdF9tZXNzYWdlLmluZGV4fSBEZWxldGVkIGJ5OiAke2ZpbHRfbWVzc2FnZS5kZWxldGVyfSA8c3RyaWtlPiBGcm9tOiAke2VzY2FwZUh0bWwoZmlsdF9tZXNzYWdlLm1lc3NhZ2Uuc2VuZGVyKX0gVG86ICR7ZXNjYXBlSHRtbChmaWx0X21lc3NhZ2UubWVzc2FnZS5yZWNlaXZlcil9IENvbnRlbnQ6ICR7ZXNjYXBlSHRtbChmaWx0X21lc3NhZ2UubWVzc2FnZS5jb250ZW50KX0gPC9zdHJpa2U+YClcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBhZGRpbmdGaWx0ZXJlZE1lc3NhZ2UoYEluZGV4OiAke2ZpbHRfbWVzc2FnZS5pbmRleH0gRnJvbTogJHtlc2NhcGVIdG1sKGZpbHRfbWVzc2FnZS5tZXNzYWdlLnNlbmRlcil9IFRvOiAke2VzY2FwZUh0bWwoZmlsdF9tZXNzYWdlLm1lc3NhZ2UucmVjZWl2ZXIpfSBDb250ZW50OiAke2VzY2FwZUh0bWwoZmlsdF9tZXNzYWdlLm1lc3NhZ2UuY29udGVudCl9YClcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZXJyb3IgbWVzc2FnZTogJywgZXJyb3IubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm4gZXJyb3IubWVzc2FnZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gJ0FuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQnO1xuICAgICAgICB9XG4gICAgfVxufVxuXG4iXSwKICAibWFwcGluZ3MiOiAiO0FBMkNBLGVBQXNCLCtCQUErQixZQUF3QztBQUN6RixNQUFJO0FBQ0EsVUFBTSxpQkFBOEIsMEJBQTBCLFVBQVU7QUFDeEUsVUFBTSxNQUFpQixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsTUFDOUM7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLFFBQ0ksTUFBTTtBQUFBLFFBQ04sTUFBTTtBQUFBLE1BQ1Y7QUFBQSxNQUNBO0FBQUEsTUFDQSxDQUFDLFNBQVM7QUFBQSxJQUNkO0FBQ0EsV0FBTztBQUFBLEVBQ1gsU0FBUyxHQUFHO0FBQ1IsUUFBSSxhQUFhLGNBQWM7QUFBRSxjQUFRLElBQUksMkRBQTJEO0FBQUEsSUFBRSxXQUNqRyxhQUFhLG9CQUFvQjtBQUFFLGNBQVEsSUFBSSwyREFBMkQ7QUFBQSxJQUFFLE9BQ2hIO0FBQUUsY0FBUSxJQUFJLENBQUM7QUFBQSxJQUFFO0FBQ3RCLFVBQU07QUFBQSxFQUNWO0FBQ0o7QUFNQSxlQUFzQiw4QkFBOEIsWUFBd0M7QUFDeEYsTUFBSTtBQUNBLFVBQU0saUJBQThCLDBCQUEwQixVQUFVO0FBQ3hFLFVBQU0sTUFBaUIsTUFBTSxPQUFPLE9BQU8sT0FBTztBQUFBLE1BQzlDO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxRQUNJLE1BQU07QUFBQSxRQUNOLE1BQU07QUFBQSxNQUNWO0FBQUEsTUFDQTtBQUFBLE1BQ0EsQ0FBQyxRQUFRO0FBQUEsSUFDYjtBQUNBLFdBQU87QUFBQSxFQUNYLFNBQVMsR0FBRztBQUNSLFFBQUksYUFBYSxjQUFjO0FBQUUsY0FBUSxJQUFJLHVFQUF1RTtBQUFBLElBQUUsV0FDN0csYUFBYSxvQkFBb0I7QUFBRSxjQUFRLElBQUksdUVBQXVFO0FBQUEsSUFBRSxPQUM1SDtBQUFFLGNBQVEsSUFBSSxDQUFDO0FBQUEsSUFBRTtBQUN0QixVQUFNO0FBQUEsRUFDVjtBQUNKO0FBTUEsZUFBc0IsZ0NBQWdDLFlBQXdDO0FBQzFGLE1BQUk7QUFDQSxVQUFNLGlCQUE4QiwwQkFBMEIsVUFBVTtBQUN4RSxVQUFNLE1BQWlCLE1BQU0sT0FBTyxPQUFPLE9BQU87QUFBQSxNQUM5QztBQUFBLE1BQ0E7QUFBQSxNQUNBO0FBQUEsUUFDSSxNQUFNO0FBQUEsUUFDTixNQUFNO0FBQUEsTUFDVjtBQUFBLE1BQ0E7QUFBQSxNQUNBLENBQUMsU0FBUztBQUFBLElBQUM7QUFDZixXQUFPO0FBQUEsRUFDWCxTQUFTLEdBQUc7QUFDUixRQUFJLGFBQWEsY0FBYztBQUFFLGNBQVEsSUFBSSw0REFBNEQ7QUFBQSxJQUFFLFdBQ2xHLGFBQWEsb0JBQW9CO0FBQUUsY0FBUSxJQUFJLDREQUE0RDtBQUFBLElBQUUsT0FDakg7QUFBRSxjQUFRLElBQUksQ0FBQztBQUFBLElBQUU7QUFDdEIsVUFBTTtBQUFBLEVBQ1Y7QUFDSjtBQU1BLGVBQXNCLCtCQUErQixZQUF3QztBQUN6RixNQUFJO0FBQ0EsVUFBTSxpQkFBOEIsMEJBQTBCLFVBQVU7QUFDeEUsVUFBTSxNQUFpQixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsTUFDOUM7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLFFBQ0ksTUFBTTtBQUFBLFFBQ04sTUFBTTtBQUFBLE1BQ1Y7QUFBQSxNQUNBO0FBQUEsTUFDQSxDQUFDLE1BQU07QUFBQSxJQUFDO0FBQ1osV0FBTztBQUFBLEVBQ1gsU0FBUyxHQUFHO0FBQ1IsUUFBSSxhQUFhLGNBQWM7QUFBRSxjQUFRLElBQUksMkRBQTJEO0FBQUEsSUFBRSxXQUNqRyxhQUFhLG9CQUFvQjtBQUFFLGNBQVEsSUFBSSwyREFBMkQ7QUFBQSxJQUFFLE9BQ2hIO0FBQUUsY0FBUSxJQUFJLENBQUM7QUFBQSxJQUFFO0FBQ3RCLFVBQU07QUFBQSxFQUNWO0FBQ0o7QUFNQSxlQUFzQixrQkFBa0IsS0FBaUM7QUFDckUsUUFBTSxjQUEyQixNQUFNLE9BQU8sT0FBTyxPQUFPLFVBQVUsUUFBUSxHQUFHO0FBQ2pGLFNBQU8sMEJBQTBCLFdBQVc7QUFDaEQ7QUFNQSxlQUFzQixtQkFBbUIsS0FBaUM7QUFDdEUsUUFBTSxjQUEyQixNQUFNLE9BQU8sT0FBTyxPQUFPLFVBQVUsU0FBUyxHQUFHO0FBQ2xGLFNBQU8sMEJBQTBCLFdBQVc7QUFDaEQ7QUFHQSxlQUFzQixzQ0FBNEQ7QUFDOUUsUUFBTSxVQUF5QixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsSUFDdEQ7QUFBQSxNQUNJLE1BQU07QUFBQSxNQUNOLGVBQWU7QUFBQSxNQUNmLGdCQUFnQixJQUFJLFdBQVcsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxDQUFDO0FBQUEsTUFDeEMsTUFBTTtBQUFBLElBQ1Y7QUFBQSxJQUNBO0FBQUEsSUFDQSxDQUFDLFdBQVcsU0FBUztBQUFBLEVBQ3pCO0FBQ0EsU0FBTyxDQUFDLFFBQVEsV0FBVyxRQUFRLFVBQVU7QUFDakQ7QUFHQSxlQUFzQixxQ0FBMkQ7QUFDN0UsUUFBTSxVQUF5QixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsSUFDdEQ7QUFBQSxNQUNJLE1BQU07QUFBQSxNQUNOLGVBQWU7QUFBQSxNQUNmLGdCQUFnQixJQUFJLFdBQVcsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxDQUFDO0FBQUEsTUFDeEMsTUFBTTtBQUFBLElBQ1Y7QUFBQSxJQUNBO0FBQUEsSUFDQSxDQUFDLFFBQVEsUUFBUTtBQUFBLEVBQ3JCO0FBQ0EsU0FBTyxDQUFDLFFBQVEsV0FBVyxRQUFRLFVBQVU7QUFDakQ7QUFHTyxTQUFTLGdCQUF3QjtBQUNwQyxRQUFNLGFBQWEsSUFBSSxZQUFZLENBQUM7QUFDcEMsT0FBSyxPQUFPLGdCQUFnQixVQUFVO0FBQ3RDLFNBQU8sV0FBVyxDQUFDLEVBQUUsU0FBUztBQUNsQztBQUdBLGVBQXNCLHFCQUFxQixXQUFzQixTQUFrQztBQUMvRixNQUFJO0FBQ0EsVUFBTSx1QkFBdUIsa0JBQWtCLE9BQU87QUFDdEQsVUFBTSxvQkFBaUMsTUFBTSxPQUFPLE9BQU8sT0FBTztBQUFBLE1BQzlELEVBQUUsTUFBTSxXQUFXO0FBQUEsTUFDbkI7QUFBQSxNQUNBO0FBQUEsSUFDSjtBQUNBLFdBQU8sMEJBQTBCLGlCQUFpQjtBQUFBLEVBQ3RELFNBQVMsR0FBRztBQUNSLFFBQUksYUFBYSxjQUFjO0FBQUUsY0FBUSxJQUFJLENBQUM7QUFBRyxjQUFRLElBQUksb0JBQW9CO0FBQUEsSUFBRSxXQUMxRSxhQUFhLG9CQUFvQjtBQUFFLGNBQVEsSUFBSSxnREFBZ0Q7QUFBQSxJQUFFLE9BQ3JHO0FBQUUsY0FBUSxJQUFJLENBQUM7QUFBQSxJQUFFO0FBQ3RCLFVBQU07QUFBQSxFQUNWO0FBQ0o7QUFJQSxlQUFzQixtQkFBbUIsWUFBdUIsU0FBa0M7QUFDOUYsTUFBSTtBQUNBLFVBQU0sdUJBQXVCLGtCQUFrQixPQUFPO0FBQ3RELFVBQU0sa0JBQStCLE1BQU0sT0FBTyxPQUFPLE9BQU87QUFBQSxNQUM1RDtBQUFBLE1BQ0E7QUFBQSxNQUNBO0FBQUEsSUFDSjtBQUNBLFdBQU8sMEJBQTBCLGVBQWU7QUFBQSxFQUNwRCxTQUFTLEdBQUc7QUFDUixRQUFJLGFBQWEsY0FBYztBQUFFLGNBQVEsSUFBSSxDQUFDO0FBQUcsY0FBUSxJQUFJLG1CQUFtQjtBQUFBLElBQUUsV0FDekUsYUFBYSxvQkFBb0I7QUFBRSxjQUFRLElBQUksOENBQThDO0FBQUEsSUFBRSxPQUNuRztBQUFFLGNBQVEsSUFBSSxDQUFDO0FBQUEsSUFBRTtBQUN0QixVQUFNO0FBQUEsRUFDVjtBQUNKO0FBSUEsZUFBc0Isc0JBQXNCLFlBQXVCLFNBQWtDO0FBQ2pHLE1BQUk7QUFDQSxVQUFNLHFCQUFrQyxNQUNwQyxPQUFPLE9BQU8sT0FBTztBQUFBLE1BQ2pCLEVBQUUsTUFBTSxXQUFXO0FBQUEsTUFDbkI7QUFBQSxNQUNBLDBCQUEwQixPQUFPO0FBQUEsSUFDckM7QUFDSixXQUFPLGtCQUFrQixrQkFBa0I7QUFBQSxFQUMvQyxTQUFTLEdBQUc7QUFDUixRQUFJLGFBQWEsY0FBYztBQUMzQixjQUFRLElBQUksa0RBQWtEO0FBQUEsSUFDbEUsV0FBVyxhQUFhLG9CQUFvQjtBQUN4QyxjQUFRLElBQUksaURBQWlEO0FBQUEsSUFDakUsTUFDSyxTQUFRLElBQUksbUJBQW1CO0FBQ3BDLFVBQU07QUFBQSxFQUNWO0FBQ0o7QUFJQSxlQUFzQiw2QkFBNkIsV0FBc0IsZ0JBQXdCLGVBQXlDO0FBQ3RJLE1BQUk7QUFDQSxVQUFNLHNCQUFzQiwwQkFBMEIsYUFBYTtBQUNuRSxVQUFNLDhCQUE4QixrQkFBa0IsY0FBYztBQUNwRSxVQUFNLFdBQW9CLE1BQ3RCLE9BQU8sT0FBTyxPQUFPO0FBQUEsTUFDakI7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxJQUEyQjtBQUNuQyxXQUFPO0FBQUEsRUFDWCxTQUFTLEdBQUc7QUFDUixRQUFJLGFBQWEsY0FBYztBQUMzQixjQUFRLElBQUksOERBQThEO0FBQUEsSUFDOUUsV0FBVyxhQUFhLG9CQUFvQjtBQUN4QyxjQUFRLElBQUksc0RBQXNEO0FBQUEsSUFDdEUsTUFDSyxTQUFRLElBQUksbUJBQW1CO0FBQ3BDLFVBQU07QUFBQSxFQUNWO0FBQ0o7QUFJQSxlQUFzQixzQkFBMEM7QUFDNUQsUUFBTSxNQUFpQixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsSUFDOUM7QUFBQSxNQUNJLE1BQU07QUFBQSxNQUNOLFFBQVE7QUFBQSxJQUNaO0FBQUEsSUFDQTtBQUFBLElBQ0EsQ0FBQyxXQUFXLFNBQVM7QUFBQSxFQUN6QjtBQUNBLFNBQU87QUFDWDtBQUdBLGVBQXNCLHFCQUFxQixLQUFpQztBQUN4RSxRQUFNLGNBQTJCLE1BQU0sT0FBTyxPQUFPLE9BQU8sVUFBVSxPQUFPLEdBQUc7QUFDaEYsU0FBTywwQkFBMEIsV0FBVztBQUNoRDtBQUdBLGVBQXNCLHFCQUFxQixZQUF3QztBQUMvRSxNQUFJO0FBQ0EsVUFBTSxpQkFBOEIsMEJBQTBCLFVBQVU7QUFDeEUsVUFBTSxNQUFpQixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsTUFDOUM7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLE1BQ0E7QUFBQSxNQUNBLENBQUMsV0FBVyxTQUFTO0FBQUEsSUFBQztBQUMxQixXQUFPO0FBQUEsRUFDWCxTQUFTLEdBQUc7QUFDUixRQUFJLGFBQWEsY0FBYztBQUFFLGNBQVEsSUFBSSw2Q0FBNkM7QUFBQSxJQUFFLFdBQ25GLGFBQWEsb0JBQW9CO0FBQUUsY0FBUSxJQUFJLDZDQUE2QztBQUFBLElBQUUsT0FDbEc7QUFBRSxjQUFRLElBQUksQ0FBQztBQUFBLElBQUU7QUFDdEIsVUFBTTtBQUFBLEVBQ1Y7QUFDSjtBQVlBLGVBQXNCLHdCQUF3QixLQUFnQixTQUFvQztBQUM5RixNQUFJO0FBQ0EsVUFBTSx1QkFBdUIsa0JBQWtCLE9BQU87QUFDdEQsVUFBTSxLQUFLLE9BQU8sT0FBTyxnQkFBZ0IsSUFBSSxXQUFXLEVBQUUsQ0FBQztBQUMzRCxVQUFNLFNBQVMsMEJBQTBCLEVBQUU7QUFDM0MsVUFBTSxvQkFBaUMsTUFBTSxPQUFPLE9BQU8sT0FBTztBQUFBLE1BQzlELEVBQUUsTUFBTSxXQUFXLEdBQUc7QUFBQSxNQUN0QjtBQUFBLE1BQ0E7QUFBQSxJQUNKO0FBQ0EsV0FBTyxDQUFDLDBCQUEwQixpQkFBaUIsR0FBRyxNQUFNO0FBQUEsRUFDaEUsU0FBUyxHQUFHO0FBQ1IsUUFBSSxhQUFhLGNBQWM7QUFBRSxjQUFRLElBQUksQ0FBQztBQUFHLGNBQVEsSUFBSSxvQkFBb0I7QUFBQSxJQUFFLFdBQzFFLGFBQWEsb0JBQW9CO0FBQUUsY0FBUSxJQUFJLG1EQUFtRDtBQUFBLElBQUUsT0FDeEc7QUFBRSxjQUFRLElBQUksQ0FBQztBQUFBLElBQUU7QUFDdEIsVUFBTTtBQUFBLEVBQ1Y7QUFDSjtBQUlBLGVBQXNCLHdCQUF3QixLQUFnQixTQUFpQixZQUFxQztBQUNoSCxRQUFNLG9CQUFpQywwQkFBMEIsVUFBVTtBQUMzRSxNQUFJO0FBQ0EsVUFBTSxxQkFBa0MsTUFDcEMsT0FBTyxPQUFPLE9BQU87QUFBQSxNQUNqQixFQUFFLE1BQU0sV0FBVyxJQUFJLGtCQUFrQjtBQUFBLE1BQ3pDO0FBQUEsTUFDQSwwQkFBMEIsT0FBTztBQUFBLElBQ3JDO0FBQ0osV0FBTyxrQkFBa0Isa0JBQWtCO0FBQUEsRUFDL0MsU0FBUyxHQUFHO0FBQ1IsUUFBSSxhQUFhLGNBQWM7QUFDM0IsY0FBUSxJQUFJLGtEQUFrRDtBQUFBLElBQ2xFLFdBQVcsYUFBYSxvQkFBb0I7QUFDeEMsY0FBUSxJQUFJLG1EQUFtRDtBQUFBLElBQ25FLE1BQ0ssU0FBUSxJQUFJLG1CQUFtQjtBQUNwQyxVQUFNO0FBQUEsRUFDVjtBQUNKO0FBR0EsZUFBc0IsS0FBSyxNQUErQjtBQUN0RCxRQUFNLGdCQUFnQixrQkFBa0IsSUFBSTtBQUM1QyxRQUFNLGNBQWMsTUFBTSxPQUFPLE9BQU8sT0FBTyxPQUFPLFdBQVcsYUFBYTtBQUM5RSxTQUFPLDBCQUEwQixXQUFXO0FBQ2hEO0FBRUEsSUFBTSxxQkFBTixjQUFpQyxNQUFNO0FBQUU7QUFHekMsU0FBUywwQkFBMEIsYUFBa0M7QUFDakUsTUFBSSxZQUFZLElBQUksV0FBVyxXQUFXO0FBQzFDLE1BQUksYUFBYTtBQUNqQixXQUFTLElBQUksR0FBRyxJQUFJLFVBQVUsWUFBWSxLQUFLO0FBQzNDLGtCQUFjLE9BQU8sYUFBYSxVQUFVLENBQUMsQ0FBQztBQUFBLEVBQ2xEO0FBQ0EsU0FBTyxLQUFLLFVBQVU7QUFDMUI7QUFHQSxTQUFTLDBCQUEwQixRQUE2QjtBQUM1RCxNQUFJO0FBQ0EsUUFBSSxVQUFVLEtBQUssTUFBTTtBQUN6QixRQUFJLFFBQVEsSUFBSSxXQUFXLFFBQVEsTUFBTTtBQUN6QyxhQUFTLElBQUksR0FBRyxJQUFJLFFBQVEsUUFBUSxLQUFLO0FBQ3JDLFlBQU0sQ0FBQyxJQUFJLFFBQVEsV0FBVyxDQUFDO0FBQUEsSUFDbkM7QUFDQSxXQUFPLE1BQU07QUFBQSxFQUNqQixTQUFTLEdBQUc7QUFDUixZQUFRLElBQUksdUJBQXVCLE9BQU8sVUFBVSxHQUFHLEVBQUUsQ0FBQyxpREFBaUQ7QUFDM0csVUFBTSxJQUFJO0FBQUEsRUFDZDtBQUNKO0FBR0EsU0FBUyxrQkFBa0IsS0FBMEI7QUFDakQsTUFBSSxNQUFNLG1CQUFtQixHQUFHO0FBQ2hDLE1BQUksVUFBVSxJQUFJLFdBQVcsSUFBSSxNQUFNO0FBQ3ZDLFdBQVMsSUFBSSxHQUFHLElBQUksSUFBSSxRQUFRLEtBQUs7QUFDakMsWUFBUSxDQUFDLElBQUksSUFBSSxXQUFXLENBQUM7QUFBQSxFQUNqQztBQUNBLFNBQU87QUFDWDtBQUdBLFNBQVMsa0JBQWtCLGFBQWtDO0FBQ3pELE1BQUksWUFBWSxJQUFJLFdBQVcsV0FBVztBQUMxQyxNQUFJLE1BQU07QUFDVixXQUFTLElBQUksR0FBRyxJQUFJLFVBQVUsWUFBWSxLQUFLO0FBQzNDLFdBQU8sT0FBTyxhQUFhLFVBQVUsQ0FBQyxDQUFDO0FBQUEsRUFDM0M7QUFDQSxTQUFPLG1CQUFtQixHQUFHO0FBQ2pDOzs7QUNwYU8sSUFBTSxjQUFOLE1BQWtCO0FBQUEsRUFDckIsWUFBbUIsVUFBa0I7QUFBbEI7QUFBQSxFQUFvQjtBQUMzQztBQUlPLElBQU0saUJBQU4sTUFBcUI7QUFBQSxFQUN4QixZQUFtQixXQUEwQixPQUFlO0FBQXpDO0FBQTBCO0FBQUEsRUFBaUI7QUFDbEU7QUFHTyxJQUFNLGdCQUFOLE1BQW9CO0FBQUEsRUFDdkIsWUFBbUIsU0FDUixnQkFDQSxPQUNBLGFBQTJCO0FBSG5CO0FBQ1I7QUFDQTtBQUNBO0FBQUEsRUFBNkI7QUFDNUM7QUFHTyxJQUFNLGdCQUFOLE1BQW9CO0FBQUEsRUFDdkIsWUFBbUJBLE9BQXFCQyxLQUFtQixVQUFrQjtBQUExRCxnQkFBQUQ7QUFBcUIsY0FBQUM7QUFBbUI7QUFBQSxFQUFvQjtBQUNuRjtBQUVPLElBQU0sa0JBQU4sTUFBc0I7QUFBQSxFQUN6QixZQUFtQixTQUNSLE9BQ0EsU0FDQSxTQUFpQjtBQUhUO0FBQ1I7QUFDQTtBQUNBO0FBQUEsRUFBbUI7QUFDbEM7QUFHTyxJQUFNLGtCQUFOLE1BQXNCO0FBQUEsRUFDekIsWUFBbUIsU0FDUixnQkFDQSxhQUFnQztBQUZ4QjtBQUNSO0FBQ0E7QUFBQSxFQUFrQztBQUNqRDtBQUdPLElBQU0sYUFBTixNQUFpQjtBQUFBLEVBQ3BCLFlBQW1CLFNBQXlCLGNBQXNCO0FBQS9DO0FBQXlCO0FBQUEsRUFBd0I7QUFDeEU7QUFJTyxJQUFNLGFBQU4sTUFBaUI7QUFBQSxFQUNwQixZQUFtQixRQUF1QixVQUF5QixTQUFpQjtBQUFqRTtBQUF1QjtBQUF5QjtBQUFBLEVBQW1CO0FBQzFGO0FBRU8sSUFBTSxrQkFBTixNQUFzQjtBQUFBLEVBQ3pCLFlBQ1csZUFBdUI7QUFBdkI7QUFBQSxFQUF5QjtBQUN4QztBQUVPLElBQU0saUJBQU4sTUFBcUI7QUFBQSxFQUN4QixZQUFtQixTQUNmLFNBQWlCO0FBREY7QUFBQSxFQUNJO0FBQzNCO0FBR08sSUFBTSxhQUFOLE1BQWlCO0FBQUEsRUFDcEIsWUFBbUIsZUFBOEIsV0FBMkIsWUFBcUI7QUFBOUU7QUFBOEI7QUFBMkI7QUFBQSxFQUF1QjtBQUN2RztBQUVPLElBQU0sWUFBTixNQUFnQjtBQUFBLEVBQ25CLFlBQW1CLFNBQXlCLEtBQW9CLGNBQXNCO0FBQW5FO0FBQXlCO0FBQW9CO0FBQUEsRUFBd0I7QUFDNUY7OztBQ3JEQSxJQUFNLGVBQWUsU0FBUyxlQUFlLGVBQWU7QUFDNUQsSUFBTSxhQUFhLFNBQVMsZUFBZSxhQUFhO0FBQ3hELElBQU0sZUFBZSxTQUFTLGVBQWUsZUFBZTtBQUM1RCxJQUFNLHFCQUFxQixTQUFTLGVBQWUsdUJBQXVCO0FBQzFFLElBQU0sc0JBQXNCLFNBQVMsZUFBZSx3QkFBd0I7QUFFNUUsSUFBTSxzQkFBc0IsU0FBUyxlQUFlLHVCQUF1QjtBQUUzRSxJQUFNLG1CQUFtQixTQUFTLGVBQWUsa0JBQWtCO0FBQ25FLElBQU0sb0JBQW9CLFNBQVMsZUFBZSxtQkFBbUI7QUFFckUsSUFBTSxzQkFBc0IsU0FBUyxlQUFlLGdCQUFnQjtBQUNwRSxJQUFNLHVCQUF1QixTQUFTLGVBQWUsaUJBQWlCO0FBQ3RFLElBQU0sdUJBQXVCLFNBQVMsZUFBZSxpQkFBaUI7QUFDdEUsSUFBTSx3QkFBd0IsU0FBUyxlQUFlLGtCQUFrQjtBQUV4RSxJQUFNLG1CQUFtQixTQUFTLGVBQWUsT0FBTztBQUV4RCxJQUFNLE9BQU8sU0FBUyxlQUFlLE1BQU07QUFDM0MsSUFBTSxLQUFLLFNBQVMsZUFBZSxJQUFJO0FBQ3ZDLElBQU0sY0FBYyxTQUFTLGVBQWUsVUFBVTtBQUN0RCxJQUFNLG9CQUFvQixTQUFTLGVBQWUsbUJBQW1CO0FBRXJFLElBQU0sV0FBVyxTQUFTLGVBQWUsVUFBVTtBQUNuRCxJQUFNLFNBQVMsU0FBUyxlQUFlLFFBQVE7QUFDL0MsSUFBTSxjQUFjLFNBQVMsZUFBZSxhQUFhO0FBQ3pELElBQU0sY0FBYyxTQUFTLGVBQWUsYUFBYTtBQUV6RCxlQUFlLGVBQWdDO0FBQzNDLFFBQU0sWUFBWSxJQUFJLGdCQUFnQixPQUFPLFNBQVMsTUFBTTtBQUM1RCxRQUFNLGNBQWMsTUFBTSxNQUFNLGNBQWMsV0FBVztBQUFBLElBQ3JELFFBQVE7QUFBQSxJQUNSLFNBQVM7QUFBQSxNQUNMLGdCQUFnQjtBQUFBLElBQ3BCO0FBQUEsRUFDSixDQUFDO0FBQ0QsTUFBSSxDQUFDLFlBQVksSUFBSTtBQUNqQixVQUFNLElBQUksTUFBTSxrQkFBa0IsWUFBWSxNQUFNLEVBQUU7QUFBQSxFQUMxRDtBQUNBLFFBQU0sYUFBYyxNQUFNLFlBQVksS0FBSztBQUMzQyxTQUFPLFdBQVc7QUFDdEI7QUFHQSxlQUFlLGFBQWE7QUFDeEIsbUJBQWlCLFFBQVEsTUFBTSxhQUFhO0FBQzVDLG9CQUFrQixRQUFRLE1BQU0sYUFBYTtBQUNqRDtBQUNBLFdBQVc7QUFNWCxTQUFTLGVBQXVCO0FBQzVCLFFBQU0sT0FBTyxPQUFPLFNBQVM7QUFDN0IsUUFBTSxPQUFPLEtBQUssTUFBTSxLQUFLLENBQUMsRUFBRSxDQUFDO0FBQ2pDLFNBQU87QUFDWDtBQUVBLElBQUksWUFBWSxhQUFhO0FBRTdCLFNBQVMsbUJBQW1CO0FBQ3hCLG9CQUFrQixjQUFjO0FBQ3BDO0FBR0EsSUFBTSxZQUFZO0FBQUEsRUFDaEIsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUFBLEVBQ0wsS0FBSztBQUNQO0FBRUEsU0FBUyxXQUFZLFFBQVE7QUFDM0IsU0FBTyxPQUFPLE1BQU0sRUFBRSxRQUFRLGdCQUFnQixTQUFVLEdBQUc7QUFDekQsV0FBTyxVQUFVLENBQUM7QUFBQSxFQUNwQixDQUFDO0FBQ0g7QUFFQSxTQUFTLGFBQWEsS0FBNkI7QUFDL0MsTUFBSSxVQUFVLFNBQVMsY0FBYyxLQUFLO0FBQzFDLFVBQVEsWUFBWTtBQUNwQixTQUFPO0FBQ1g7QUFFQSxTQUFTLHNCQUFzQixTQUFpQjtBQUM1QyxvQkFBa0IsT0FBTyxhQUFhLG1CQUFvQixPQUFRLENBQUM7QUFDdkU7QUFFQSxvQkFBb0IsVUFBVSxXQUFZO0FBQ3RDLFFBQU0sUUFBUSxjQUFjO0FBQzVCLG1CQUFpQixjQUFjO0FBQ25DO0FBRUEsZUFBZSxTQUFTLE1BQWMsV0FBb0IsWUFBeUM7QUFNL0YsUUFBTSxvQkFDRixJQUFJLFdBQVcsTUFBTSxXQUFXLFVBQVU7QUFHOUMsUUFBTSxZQUFZLElBQUksZ0JBQWdCLE9BQU8sU0FBUyxNQUFNO0FBRzVELFFBQU0sYUFBYSxNQUFNLE1BQU0sYUFBYSxXQUFXO0FBQUEsSUFDbkQsUUFBUTtBQUFBLElBQ1IsTUFBTSxLQUFLLFVBQVUsaUJBQWlCO0FBQUEsSUFDdEMsU0FBUztBQUFBLE1BQ0wsZ0JBQWdCO0FBQUEsSUFDcEI7QUFBQSxFQUNKLENBQUM7QUFDRCxNQUFJLENBQUMsV0FBVyxJQUFJO0FBQ2hCLFVBQU0sSUFBSSxNQUFNLGtCQUFrQixXQUFXLE1BQU0sRUFBRTtBQUFBLEVBQ3pEO0FBQ0EsUUFBTSxZQUFhLE1BQU0sV0FBVyxLQUFLO0FBQ3pDLE1BQUksQ0FBQyxVQUFVLFFBQVMsT0FBTSxVQUFVLFlBQVk7QUFBQSxPQUMvQztBQUNELFFBQUksYUFBYSxXQUFZLFFBQU8sTUFBTSwrQkFBK0IsVUFBVSxHQUFHO0FBQUEsYUFDN0UsQ0FBQyxhQUFhLFdBQVksUUFBTyxNQUFNLGdDQUFnQyxVQUFVLEdBQUc7QUFBQSxhQUNwRixhQUFhLENBQUMsV0FBWSxRQUFPLE1BQU0sOEJBQThCLFVBQVUsR0FBRztBQUFBLGFBQ2xGLENBQUMsYUFBYSxDQUFDLFdBQVksUUFBTyxNQUFNLCtCQUErQixVQUFVLEdBQUc7QUFBQSxFQUNqRztBQUNKO0FBRUEsbUJBQW1CLFVBQVUsaUJBQWtCO0FBQzNDLFFBQU0sd0JBQXdCLGlCQUFpQjtBQUMvQyxRQUFNLGVBQWUsTUFBTSxTQUFTLHVCQUF1QixNQUFNLElBQUk7QUFDckUsUUFBTSxnQkFBZ0IsTUFBTSxTQUFTLHVCQUF1QixNQUFNLEtBQUs7QUFDdkUsc0JBQW9CLGNBQWMsTUFBTSxrQkFBa0IsWUFBWTtBQUN0RSx1QkFBcUIsY0FBYyxNQUFNLGtCQUFrQixhQUFhO0FBQzVFO0FBRUEsb0JBQW9CLFVBQVUsaUJBQWtCO0FBQzVDLFFBQU0seUJBQXlCLGtCQUFrQjtBQUNqRCxRQUFNLGdCQUFnQixNQUFNLFNBQVMsd0JBQXdCLE9BQU8sSUFBSTtBQUN4RSxRQUFNLGlCQUFpQixNQUFNLFNBQVMsd0JBQXdCLE9BQU8sS0FBSztBQUMxRSx1QkFBcUIsY0FBYyxNQUFNLG1CQUFtQixhQUFhO0FBQ3pFLHdCQUFzQixjQUFjLE1BQU0sbUJBQW1CLGNBQWM7QUFDL0U7QUFFQSxhQUFhLFVBQVUsaUJBQWtCO0FBQ3JDLE1BQUksZ0JBQWdCLFlBQVk7QUFDaEMsTUFBSTtBQUNBLFFBQUksZ0JBQ0EsSUFBSSxnQkFBZ0IsYUFBYTtBQUNyQyxVQUFNLFVBQVUsTUFBTSxNQUFNLGVBQWUsV0FBZ0I7QUFBQSxNQUN2RCxRQUFRO0FBQUEsTUFDUixNQUFNLEtBQUssVUFBVSxhQUFhO0FBQUEsTUFDbEMsU0FBUztBQUFBLFFBQ0wsZ0JBQWdCO0FBQUEsTUFDcEI7QUFBQSxJQUNKLENBQUM7QUFDRCxRQUFJLENBQUMsUUFBUSxJQUFJO0FBQ2IsWUFBTSxJQUFJLE1BQU0sa0JBQWtCLFFBQVEsTUFBTSxFQUFFO0FBQUEsSUFDdEQ7QUFFQSxXQUFRLE1BQU0sUUFBUSxLQUFLO0FBQUEsRUFDL0IsU0FDTyxPQUFPO0FBQ1YsUUFBSSxpQkFBaUIsT0FBTztBQUN4QixZQUFNLE1BQU0sT0FBTztBQUVuQixhQUFPLElBQUksZUFBZSxPQUFPLE1BQU0sT0FBTztBQUFBLElBQ2xELE9BQU87QUFDSCxjQUFRLElBQUksc0JBQXNCLEtBQUs7QUFDdkMsYUFBTyxJQUFJLGVBQWUsT0FBTyw4QkFBOEI7QUFBQSxJQUNuRTtBQUFBLEVBQ0o7QUFFSjtBQUVBLGVBQWUsWUFBWSxXQUFtQixjQUFzQixnQkFBNkM7QUFDN0csTUFBSTtBQUNBLFFBQUksZ0JBQWdCLElBQUksV0FBVyxXQUFXLGNBQWMsY0FBYztBQUMxRSxVQUFNLFVBQVUsTUFBTSxNQUFNLDZCQUE2QixXQUFXO0FBQUEsTUFDaEUsUUFBUTtBQUFBLE1BQ1IsTUFBTSxLQUFLLFVBQVUsYUFBYTtBQUFBLE1BQ2xDLFNBQVM7QUFBQSxRQUNMLGdCQUFnQjtBQUFBLE1BQ3BCO0FBQUEsSUFDSixDQUFDO0FBQ0QsUUFBSSxDQUFDLFFBQVEsSUFBSTtBQUNiLFlBQU0sSUFBSSxNQUFNLGtCQUFrQixRQUFRLE1BQU0sRUFBRTtBQUFBLElBQ3REO0FBRUEsV0FBUSxNQUFNLFFBQVEsS0FBSztBQUFBLEVBQy9CLFNBQ08sT0FBTztBQUNWLFFBQUksaUJBQWlCLE9BQU87QUFDeEIsY0FBUSxJQUFJLE1BQU0sT0FBTztBQUN6QixhQUFPLElBQUksV0FBVyxPQUFPLE1BQU0sT0FBTztBQUFBLElBQzlDLE9BQU87QUFDSCxjQUFRLElBQUksS0FBSztBQUNqQixhQUFPLElBQUksV0FBVyxPQUFPLDhCQUE4QjtBQUFBLElBQy9EO0FBQUEsRUFDSjtBQUNKO0FBR0EsV0FBVyxVQUFVLGlCQUFrQjtBQUNuQyxNQUFJLFlBQVksU0FBUztBQUN6QixNQUFJLGVBQWUsT0FBTztBQUMxQixNQUFJLFVBQVUsWUFBWTtBQUMxQixNQUFJO0FBQ0EsVUFBTSxhQUFhLE1BQU0sWUFBWSxXQUFXLGNBQWMsT0FBTztBQUNyRSxRQUFJLENBQUMsV0FBVyxRQUFTLE9BQU0sV0FBVyxZQUFZO0FBQUEsU0FDakQ7QUFDRCxjQUFRLElBQUksZ0NBQWdDO0FBQUEsSUFDaEQ7QUFBQSxFQUNKLFNBQVMsR0FBRztBQUNSLFFBQUksYUFBYSxPQUFPO0FBQ3BCLGNBQVEsSUFBSSxFQUFFLE9BQU87QUFBQSxJQUN6QixPQUFPO0FBQ0gsY0FBUSxJQUFJLENBQUM7QUFBQSxJQUNqQjtBQUFBLEVBQ0o7QUFDSjtBQUVBLGFBQWEsVUFBVSxpQkFBa0I7QUFDckMsTUFBSTtBQUNBLFVBQU0sV0FBVyxLQUFLO0FBQ3RCLFVBQU0sU0FBUyxHQUFHO0FBQ2xCLFVBQU0sV0FBVyxZQUFZO0FBQzdCLFVBQU0sZ0JBQ0YsSUFBSSxjQUFjLFVBQVUsUUFBUSxRQUFRO0FBQ2hELFVBQU0sVUFBVSxNQUFNLE1BQU0sZ0JBQWdCLFdBQVc7QUFBQSxNQUNuRCxRQUFRO0FBQUEsTUFDUixNQUFNLEtBQUssVUFBVSxhQUFhO0FBQUEsTUFDbEMsU0FBUztBQUFBLFFBQ0wsZ0JBQWdCO0FBQUEsTUFDcEI7QUFBQSxJQUNKLENBQUM7QUFDRCxRQUFJLENBQUMsUUFBUSxJQUFJO0FBQ2IsWUFBTSxJQUFJLE1BQU0sa0JBQWtCLFFBQVEsTUFBTSxFQUFFO0FBQUEsSUFDdEQ7QUFDQSxVQUFNLFNBQVUsTUFBTSxRQUFRLEtBQUs7QUFDbkMsUUFBSSxDQUFDLE9BQU8sU0FBUztBQUFFLFlBQU0sT0FBTyxjQUFjO0FBQUEsSUFBRSxPQUMvQztBQUNELHVCQUFpQjtBQUNqQixlQUFTLGdCQUFnQixPQUFPLGFBQWE7QUFDekMsWUFBSSxhQUFhLFNBQVM7QUFDdEIsZ0NBQXNCLFVBQVUsYUFBYSxLQUFLLGdCQUFnQixhQUFhLE9BQU8sbUJBQW1CLFdBQVcsYUFBYSxRQUFRLE1BQU0sQ0FBQyxRQUFRLFdBQVcsYUFBYSxRQUFRLFFBQVEsQ0FBQyxhQUFhLFdBQVcsYUFBYSxRQUFRLE9BQU8sQ0FBQyxZQUFZO0FBQUEsUUFDdFEsT0FBTztBQUNILGdDQUFzQixVQUFVLGFBQWEsS0FBSyxVQUFVLFdBQVcsYUFBYSxRQUFRLE1BQU0sQ0FBQyxRQUFRLFdBQVcsYUFBYSxRQUFRLFFBQVEsQ0FBQyxhQUFhLFdBQVcsYUFBYSxRQUFRLE9BQU8sQ0FBQyxFQUFFO0FBQUEsUUFDL007QUFBQSxNQUNKO0FBQUEsSUFDSjtBQUFBLEVBQ0osU0FDTyxPQUFPO0FBQ1YsUUFBSSxpQkFBaUIsT0FBTztBQUN4QixjQUFRLElBQUksbUJBQW1CLE1BQU0sT0FBTztBQUM1QyxhQUFPLE1BQU07QUFBQSxJQUNqQixPQUFPO0FBQ0gsY0FBUSxJQUFJLHNCQUFzQixLQUFLO0FBQ3ZDLGFBQU87QUFBQSxJQUNYO0FBQUEsRUFDSjtBQUNKOyIsCiAgIm5hbWVzIjogWyJmcm9tIiwgInRvIl0KfQo=
