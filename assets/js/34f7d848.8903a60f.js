(self.webpackChunkdoc_ops=self.webpackChunkdoc_ops||[]).push([[957],{2330:function(e,t,n){"use strict";n.r(t),n.d(t,{frontMatter:function(){return l},contentTitle:function(){return s},metadata:function(){return d},toc:function(){return p},default:function(){return m}});var a=n(2122),i=n(9756),r=(n(7294),n(3905)),o=["components"],l={description:"The official client layer of Stronghold provides an Actix actor model system for easy Interface as well as functional pass-through to Stronghold's internal actor system.",image:"/img/logo/Stronghold_icon.png",keywords:["rust","interface","procedures","requests","responses"]},s="Structure: Client",d={unversionedId:"structure/client",id:"structure/client",isDocsHomePage:!1,title:"Structure: Client",description:"The official client layer of Stronghold provides an Actix actor model system for easy Interface as well as functional pass-through to Stronghold's internal actor system.",source:"@site/docs/structure/client.md",sourceDirName:"structure",slug:"/structure/client",permalink:"/docs/structure/client",editUrl:"https://github.com/iotaledger/stronghold.rs/tree/dev/documentation/docs/structure/client.md",version:"current",frontMatter:{description:"The official client layer of Stronghold provides an Actix actor model system for easy Interface as well as functional pass-through to Stronghold's internal actor system.",image:"/img/logo/Stronghold_icon.png",keywords:["rust","interface","procedures","requests","responses"]},sidebar:"mySidebar",previous:{title:"IOTA Stronghold Structure",permalink:"/docs/structure/overview"},next:{title:"Structure: Engine",permalink:"/docs/structure/engine/overview"}},p=[],c={toc:p};function m(e){var t=e.components,n=(0,i.Z)(e,o);return(0,r.kt)("wrapper",(0,a.Z)({},c,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"structure-client"},"Structure: Client"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null}),(0,r.kt)("th",{parentName:"tr",align:null}),(0,r.kt)("th",{parentName:"tr",align:null}))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("a",{parentName:"td",href:"https://github.com/iotaledger/stronghold.rs/tree/dev/client"},(0,r.kt)("img",{parentName:"a",src:"https://img.shields.io/badge/github-source-blue.svg",alt:"github"}))),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("a",{parentName:"td",href:"https://docs.rs/iota_stronghold"},(0,r.kt)("img",{parentName:"a",src:"https://img.shields.io/badge/rust-docs-green.svg",alt:"github"}))),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("a",{parentName:"td",href:"https://crates.io/crates/iota_stronghold"},(0,r.kt)("img",{parentName:"a",src:"https://img.shields.io/crates/v/iota_stronghold.svg",alt:null})))))),(0,r.kt)("p",null,(0,r.kt)("h2",{parentName:"p"},"Stronghold Client"),(0,r.kt)("p",{parentName:"p"},"This is the official client layer of Stronghold. It provides an ",(0,r.kt)("a",{parentName:"p",href:"https://actix.rs"},"Actix")," actor model system for easy Interface as well as functional passthrough to Stronghold's internal actor system."),(0,r.kt)("p",{parentName:"p"},(0,r.kt)("strong",{parentName:"p"},"Stronghold Interface"),": "),(0,r.kt)("ul",{parentName:"p"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"init_stronghold_system"),": Initializes a new instance of the Stronghold system.  Sets up the first client actor. Accepts a ",(0,r.kt)("inlineCode",{parentName:"li"},"ActorSystem"),", the first ",(0,r.kt)("inlineCode",{parentName:"li"},"client_path"),": ",(0,r.kt)("inlineCode",{parentName:"li"},"Vec<u8>")," and any ",(0,r.kt)("inlineCode",{parentName:"li"},"StrongholdFlags")," which pertain to the first actor."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"spawn_stronghold_actor"),":  Spawns a new set of actors for the Stronghold system. Accepts the ",(0,r.kt)("inlineCode",{parentName:"li"},"client_path"),": ",(0,r.kt)("inlineCode",{parentName:"li"},"Vec<u8>")," and the options: ",(0,r.kt)("inlineCode",{parentName:"li"},"StrongholdFlags")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"switch_actor_target"),": Switches the actor target to another actor in the system specified by the ",(0,r.kt)("inlineCode",{parentName:"li"},"client_path"),": ",(0,r.kt)("inlineCode",{parentName:"li"},"Vec<u8>"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"write_to_vault"),":  Writes data into the Stronghold. Uses the current target actor as the client and writes to the specified location of ",(0,r.kt)("inlineCode",{parentName:"li"},"Location")," type. The payload must be specified as a ",(0,r.kt)("inlineCode",{parentName:"li"},"Vec<u8>")," and a ",(0,r.kt)("inlineCode",{parentName:"li"},"RecordHint")," can be provided. Also accepts ",(0,r.kt)("inlineCode",{parentName:"li"},"VaultFlags")," for when a new Vault is created."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"write_to_store"),": Writes data into an insecure cache. This method, accepts a ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),", a ",(0,r.kt)("inlineCode",{parentName:"li"},"Vec<u8>")," and an optional ",(0,r.kt)("inlineCode",{parentName:"li"},"Duration"),". The lifetime allows the data to be deleted after the specified duration has passed. If not lifetime is specified, the data will persist until it is manually deleted or over-written. Each store is mapped to a client. "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"read_from_store"),": Reads from an insecure cache. This method, accepts a ",(0,r.kt)("inlineCode",{parentName:"li"},"Location")," and returns the payload in the\nform of a ",(0,r.kt)("inlineCode",{parentName:"li"},"Vec<u8>"),".  If the location does not exist, an empty vector will be returned along with an error ",(0,r.kt)("inlineCode",{parentName:"li"},"StatusMessage"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"delete_from_store")," - delete data from an insecure cache. This method, accepts a ",(0,r.kt)("inlineCode",{parentName:"li"},"Location")," and returns a ",(0,r.kt)("inlineCode",{parentName:"li"},"StatusMessage"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"delete_data"),": Revokes the data from the specified location of type ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),". Revoked data is not readable and can be removed from a vault with a call to ",(0,r.kt)("inlineCode",{parentName:"li"},"garbage_collect"),".  if the ",(0,r.kt)("inlineCode",{parentName:"li"},"should_gc")," flag is set to ",(0,r.kt)("inlineCode",{parentName:"li"},"true"),", this call with automatically cleanup the revoke. Otherwise, the data is just marked as revoked. "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"garbage_collect"),": Garbage collects any revokes in a Vault based on the given vault_path and the current target actor."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"list_hints_and_ids"),": Returns a list of the available ",(0,r.kt)("inlineCode",{parentName:"li"},"RecordId")," and ",(0,r.kt)("inlineCode",{parentName:"li"},"RecordHint")," values in a vault by the given ",(0,r.kt)("inlineCode",{parentName:"li"},"vault_path"),". "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"runtime_exec"),": Executes a runtime command given a ",(0,r.kt)("inlineCode",{parentName:"li"},"Procedure"),".  Returns a ",(0,r.kt)("inlineCode",{parentName:"li"},"ProcResult")," based off of the ",(0,r.kt)("inlineCode",{parentName:"li"},"control_request")," specified."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"record_exists"),": Checks whether a record exists in the client based off of the given ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"vault_exists"),": Checks whether a vault exists in the client by ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"read_snapshot"),": Reads data from a given snapshot file. Can only read the data for a single ",(0,r.kt)("inlineCode",{parentName:"li"},"client_path")," at a time. If the actor uses a new ",(0,r.kt)("inlineCode",{parentName:"li"},"client_path")," the former client path may be passed into the function call to read the data into the new actor. A filename and filepath can be specified, if they aren't provided, the path defaults to ",(0,r.kt)("inlineCode",{parentName:"li"},"$HOME/.stronghold/snapshots/")," and the filename defaults to ",(0,r.kt)("inlineCode",{parentName:"li"},"backup.stronghold"),".\nAlso requires keydata to unlock the snapshot and the keydata must implement and use ",(0,r.kt)("inlineCode",{parentName:"li"},"Zeroize"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"write_all_to_snapshot"),":  Writes the entire state of the ",(0,r.kt)("inlineCode",{parentName:"li"},"Stronghold")," into a snapshot. All Actors and their associated data is written into the specified snapshot. Requires keydata to encrypt the snapshot. The Keydata should implement and use Zeroize.  If a path and filename are not provided, uses the default path ",(0,r.kt)("inlineCode",{parentName:"li"},"$HOME/.stronghold/snapshots/")," and the default filename ",(0,r.kt)("inlineCode",{parentName:"li"},"backup.stronghold"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"kill_stronghold"),": Used to kill a stronghold actor or clear the cache of that actor. Accepts the ",(0,r.kt)("inlineCode",{parentName:"li"},"client_path"),", and a boolean for whether or not to kill the actor.  If ",(0,r.kt)("inlineCode",{parentName:"li"},"kill_actor")," is ",(0,r.kt)("inlineCode",{parentName:"li"},"true")," both the internal actor and the client actor are killed. Otherwise, the cache is cleared from the client and internal actor. ")),(0,r.kt)("p",{parentName:"p"},(0,r.kt)("strong",{parentName:"p"},"Stronghold Procedures"),":"),(0,r.kt)("h5",{parentName:"p"},(0,r.kt)("strong",{parentName:"h5"},"Requests"),":"),(0,r.kt)("ul",{parentName:"p"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"SLIP10Generate"),": Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in the ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),". "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"SLIP10Derive"),": Derive a Slip10 child key from a seed or parent key. Store the output in a specified ",(0,r.kt)("inlineCode",{parentName:"li"},"Location")," and return the corresponding ",(0,r.kt)("inlineCode",{parentName:"li"},"ChainCode"),". "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"BIP39Recover"),": Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover a BIP39 seed and store it in the output ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"BIP39Generate"),": Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a passphrase) and store them in the output ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"BIP39MnemonicSentence"),": Read a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a passphrase) and store them in the output ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Ed25519PublicKey"),": Derive an Ed25519 public key from the corresponding private key stored at the specified ",(0,r.kt)("inlineCode",{parentName:"li"},"Location"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Ed25519Sign"),": Use the specified Ed25519 compatible key to sign the given message. Compatible keys are any record that contain the desired key material in the first 32 bytes, in particular SLIP10 keys are compatible.")),(0,r.kt)("h5",{parentName:"p"},(0,r.kt)("strong",{parentName:"h5"},"Responses"),":"),(0,r.kt)("ul",{parentName:"p"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"SLIP10Generate"),": Returns a ",(0,r.kt)("inlineCode",{parentName:"li"},"StatusMessage")," indicating the result of the request. "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"SLIP10Derive"),": Returns a ",(0,r.kt)("inlineCode",{parentName:"li"},"ResultMessage")," with the ",(0,r.kt)("inlineCode",{parentName:"li"},"ChainCode")," inside of it. "),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"BIP39Recover"),": Returns a ",(0,r.kt)("inlineCode",{parentName:"li"},"StatusMessage")," indicating the result of the request. ."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"BIP39Generate"),": Returns a ",(0,r.kt)("inlineCode",{parentName:"li"},"StatusMessage")," indicating the result of the request."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"BIP39MnemonicSentence"),": Returns the mnemonic sentence for the corresponding seed."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Ed25519PublicKey"),": Returns an Ed25519 public key inside of a ",(0,r.kt)("inlineCode",{parentName:"li"},"ResultMessage"),"."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Ed25519Sign"),": Returns an Ed25519 signature inside of a ",(0,r.kt)("inlineCode",{parentName:"li"},"ResultMessage"),"."))))}m.isMDXComponent=!0},3905:function(e,t,n){"use strict";n.d(t,{Zo:function(){return p},kt:function(){return u}});var a=n(7294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function r(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?r(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):r(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,a,i=function(e,t){if(null==e)return{};var n,a,i={},r=Object.keys(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var s=a.createContext({}),d=function(e){var t=a.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},p=function(e){var t=d(e.components);return a.createElement(s.Provider,{value:t},e.children)},c={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},m=a.forwardRef((function(e,t){var n=e.components,i=e.mdxType,r=e.originalType,s=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),m=d(n),u=i,h=m["".concat(s,".").concat(u)]||m[u]||c[u]||r;return n?a.createElement(h,o(o({ref:t},p),{},{components:n})):a.createElement(h,o({ref:t},p))}));function u(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var r=n.length,o=new Array(r);o[0]=m;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:i,o[1]=l;for(var d=2;d<r;d++)o[d]=n[d];return a.createElement.apply(null,o)}return a.createElement.apply(null,n)}m.displayName="MDXCreateElement"}}]);