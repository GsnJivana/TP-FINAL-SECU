// To detect if we can use window.crypto.subtle
if (!window.isSecureContext) alert("Not secure context!")

// -- DO NOT MODIFY THIS PART! --------------------------------------------------------------------
// Message for user name
class CasUserName {
    constructor(public username: string) { }
}

// Requesting keys
class KeyRequest {
    constructor(public ownerOfTheKey: string, public publicKey: boolean, public encryption: boolean) { }
}

class KeyResult {
    constructor(public success: boolean, public key: string, public errorMessage: string) { }
}

// The message format
class ExtMessage {
    constructor(public sender: string, public receiver: string, public content: string) { }
}

// Sending a message Result format
class SendResult {
    constructor(public success: boolean, public errorMessage: string) { }
}

// Message for requiring history
class HistoryRequest {
    constructor(public agentName: string, public index: number) { }
}

// Result of history request
class HistoryAnswer {
    constructor(public success: boolean,
        public failureMessage: string,
        public index: number,
        public allMessages: ExtMessage[]) { }
}

let globalUserName = ""

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.

// Do not modify!
async function fetchCasName(): Promise<string> {
    const urlParams = new URLSearchParams(window.location.search);
    const namerequest = await fetch("/getuser?" + urlParams, {
        method: "GET",
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
    if (!namerequest.ok) {
        throw new Error(`Error! status: ${namerequest.status}`)
    }
    const nameResult = (await namerequest.json()) as CasUserName
    console.log("Fetched CAS name= " + nameResult.username)
    return nameResult.username
}

// Do not modify!
async function setCasName() {
    globalUserName = await fetchCasName()
    // We replace the name of the user of the application as the default name
    // In the window
    userButtonLabel.textContent = globalUserName
}

// Do not modify!
setCasName()

// WARNING!
// It is necessary to provide the name of the owner of the application. Each pair of student are
// the owner of their application. Other students may use it but they are only users and not owners.
// Messages sent to the server are separated w.r.t. the name of the application (i.e. the name of their owners).
// The name of the owners is the name of the folder of the application where the web pages of the application are stored. 
// E.g, for teachers' application this name is "ens"

// Do not modify!
function getOwnerName(): string {
    const path = window.location.pathname
    const name = path.split("/", 2)[1]
    return name
}

// Do not modify!
let ownerName = getOwnerName()

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.

// Do not modify
async function fetchKey(user: string, publicKey: boolean, encryption: boolean): Promise<CryptoKey> {
    // Getting the public/private key of user.
    // For public key the boolean 'publicKey' is true.
    // For private key the boolean 'publicKey' is false.
    // If the key is used for encryption/decryption then the boolean 'encryption' is true.
    // If the key is used for signature/signature verification then the boolean is false.
    const keyRequestMessage =
        new KeyRequest(user, publicKey, encryption)
    // For CAS authentication we need to add the authentication ticket
    // It is contained in urlParams
    const urlParams = new URLSearchParams(window.location.search);
    // For getting a key we do not need the ownerName param
    // Because keys are independant of the applications
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
    const keyResult = (await keyrequest.json()) as KeyResult;
    if (!keyResult.success) alert(keyResult.errorMessage)
    else {
        if (publicKey && encryption) return await stringToPublicKeyForEncryption(keyResult.key)
        else if (!publicKey && encryption) return await stringToPrivateKeyForEncryption(keyResult.key)
        else if (publicKey && !encryption) return await stringToPublicKeyForSignature(keyResult.key)
        else if (!publicKey && !encryption) return await stringToPrivateKeyForSignature(keyResult.key)
    }
}

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
// 
// We also need to provide the ownerName

// Do not modify!
async function sendMessage(agentName: string, receiverName: string, messageContent: string): Promise<SendResult> {
    try {
        let messageToSend =
            new ExtMessage(agentName, receiverName, messageContent)
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
        // Dealing with the answer of the message server
        console.log(`Sent message from ${agentName} to ${receiverName}: ${messageContent}`)
        return (await request.json()) as SendResult
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return new SendResult(false, error.message)
        } else {
            console.log('unexpected error: ', error);
            return new SendResult(false, 'An unexpected error occurred')
        }
    }
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
// You can modify the code below

import {
    stringToPrivateKeyForEncryption, stringToPublicKeyForEncryption,
    stringToPrivateKeyForSignature,
    stringToPublicKeyForSignature
} from './libCrypto'

const userButtonLabel = document.getElementById("user-name") as HTMLLabelElement
const sendButton = document.getElementById("send-button") as HTMLButtonElement
const receiver = document.getElementById("receiver") as HTMLInputElement
const message = document.getElementById("message") as HTMLInputElement
const received_messages = document.getElementById("exchanged-messages") as HTMLLabelElement

// Basic utilities for adding/clearing received messages in the page
function clearingMessages() {
    received_messages.textContent = ""
}

// Beware, this is vulnerable code
function stringToHTML(str: string): HTMLDivElement {
    var div_elt = document.createElement('div')
    div_elt.innerHTML = str
    return div_elt
}

function addingReceivedMessage(message: string) {
    received_messages.append(stringToHTML('<p></p><p></p>' + message))
}

//Index of the last read message
let lastIndexInHistory = 0

// function for refreshing the content of the window (automatic or manual see below)
async function refresh() {
    try {
        const user = globalUserName
        const historyRequest =
            new HistoryRequest(user, lastIndexInHistory)
        const urlParams = new URLSearchParams(window.location.search);
        const request = await fetch("/history/" + ownerName + "?" + urlParams
            , {
                method: "POST",
                body: JSON.stringify(historyRequest),
                headers: {
                    "Content-type": "application/json; charset=UTF-8"
                }
            });
        if (!request.ok) {
            throw new Error(`Error! status: ${request.status}`);
        }
        const result = (await request.json()) as HistoryAnswer
        if (!result.success) { alert(result.failureMessage) }
        else {
            // This is the place where you can perform trigger any operations for refreshing the page
            addingReceivedMessage("Dummy message!")
        }
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return error.message;
        } else {
            console.log('unexpected error: ', error);
            return 'An unexpected error occurred';
        }
    }
}

// Automatic refresh: the waiting time is given in milliseconds
const intervalRefresh = setInterval(refresh, 2000)

// ------

