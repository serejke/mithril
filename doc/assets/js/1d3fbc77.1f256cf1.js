"use strict";(self.webpackChunkmithril_doc=self.webpackChunkmithril_doc||[]).push([[4163,9531],{3905:(e,t,n)=>{n.d(t,{Zo:()=>s,kt:()=>h});var a=n(7294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)n=i[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var p=a.createContext({}),d=function(e){var t=a.useContext(p),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},s=function(e){var t=d(e.components);return a.createElement(p.Provider,{value:t},e.children)},m="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},k=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,i=e.originalType,p=e.parentName,s=o(e,["components","mdxType","originalType","parentName"]),m=d(n),k=r,h=m["".concat(p,".").concat(k)]||m[k]||u[k]||i;return n?a.createElement(h,l(l({ref:t},s),{},{components:n})):a.createElement(h,l({ref:t},s))}));function h(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=n.length,l=new Array(i);l[0]=k;var o={};for(var p in t)hasOwnProperty.call(t,p)&&(o[p]=t[p]);o.originalType=e,o[m]="string"==typeof e?e:r,l[1]=o;for(var d=2;d<i;d++)l[d]=n[d];return a.createElement.apply(null,l)}return a.createElement.apply(null,n)}k.displayName="MDXCreateElement"},9544:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>d,contentTitle:()=>o,default:()=>u,frontMatter:()=>l,metadata:()=>p,toc:()=>s});var a=n(7462),r=(n(7294),n(3905)),i=n(1900);const l={sidebar_position:2},o="Run a Mithril Signer node (SPO)",p={unversionedId:"manual/getting-started/run-signer-node",id:"manual/getting-started/run-signer-node",title:"Run a Mithril Signer node (SPO)",description:"In this guide, you will learn how to setup a Mithril Signer on top of a Cardano SPO Node for the testnet.",source:"@site/root/manual/getting-started/run-signer-node.md",sourceDirName:"manual/getting-started",slug:"/manual/getting-started/run-signer-node",permalink:"/doc/next/manual/getting-started/run-signer-node",draft:!1,editUrl:"https://github.com/input-output-hk/mithril/edit/main/docs/root/manual/getting-started/run-signer-node.md",tags:[],version:"current",sidebarPosition:2,frontMatter:{sidebar_position:2},sidebar:"docSideBar",previous:{title:"Bootstrap a Cardano Node",permalink:"/doc/next/manual/getting-started/bootstrap-cardano-node"},next:{title:"Run a Private Mithril network",permalink:"/doc/next/manual/getting-started/run-mithril-devnet"}},d={},s=[{value:"Pre-requisites",id:"pre-requisites",level:2},{value:"What you&#39;ll need",id:"what-youll-need",level:2},{value:"Mithril Keys Certification",id:"mithril-keys-certification",level:2},{value:"Stable mode: Certify your Pool Id",id:"stable-mode-certify-your-pool-id",level:3},{value:"Deprecated mode: Declare your Pool Id",id:"deprecated-mode-declare-your-pool-id",level:3},{value:"Building your own executable",id:"building-your-own-executable",level:2},{value:"Download source",id:"download-source",level:3},{value:"Build Mithril Signer binary",id:"build-mithril-signer-binary",level:3},{value:"Verify build",id:"verify-build",level:3},{value:"Move executable",id:"move-executable",level:3},{value:"Setup the service",id:"setup-the-service",level:3}],m={toc:s};function u(e){let{components:t,...n}=e;return(0,r.kt)("wrapper",(0,a.Z)({},m,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"run-a-mithril-signer-node-spo"},"Run a Mithril Signer node (SPO)"),(0,r.kt)("admonition",{type:"info"},(0,r.kt)("p",{parentName:"admonition"},"In this guide, you will learn how to setup a ",(0,r.kt)("strong",{parentName:"p"},"Mithril Signer")," on top of a ",(0,r.kt)("strong",{parentName:"p"},"Cardano SPO Node")," for the ",(0,r.kt)("inlineCode",{parentName:"p"},"testnet"),".")),(0,r.kt)("admonition",{title:"Mithril Networks",type:"note"},(0,r.kt)(i.default,{mdxType:"NetworksMatrix"})),(0,r.kt)("admonition",{type:"danger"},(0,r.kt)("p",{parentName:"admonition"},"This guide is working only on a Linux machine.")),(0,r.kt)("admonition",{type:"tip"},(0,r.kt)("p",{parentName:"admonition"},"For more information about the ",(0,r.kt)("strong",{parentName:"p"},"Mithril Protocol"),", please refer to the ",(0,r.kt)("a",{parentName:"p",href:"/doc/next/mithril/intro"},"About Mithril")," section.")),(0,r.kt)("h2",{id:"pre-requisites"},"Pre-requisites"),(0,r.kt)("h2",{id:"what-youll-need"},"What you'll need"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},"Operating a ",(0,r.kt)("strong",{parentName:"p"},"Cardano Node")," as a ",(0,r.kt)("strong",{parentName:"p"},"Stake Pool"),":"),(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Stable"),":",(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},"The Cardano ",(0,r.kt)("inlineCode",{parentName:"li"},"Operational Certificate")," file of the pool"),(0,r.kt)("li",{parentName:"ul"},"The Cardano ",(0,r.kt)("inlineCode",{parentName:"li"},"KES Secret Key")," file of the pool"))),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Deprecated"),": The Cardano ",(0,r.kt)("inlineCode",{parentName:"li"},"Pool Id")," in a ",(0,r.kt)("inlineCode",{parentName:"li"},"BECH32")," format such as ",(0,r.kt)("inlineCode",{parentName:"li"},"pool1frevxe70aqw2ce58c0muyesnahl88nfjjsp25h85jwakzgd2g2l")))),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},"Access to the file system of a ",(0,r.kt)("inlineCode",{parentName:"p"},"relay")," ",(0,r.kt)("strong",{parentName:"p"},"Cardano Node")," running on the ",(0,r.kt)("inlineCode",{parentName:"p"},"testnet"),":"),(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},"Read rights on the ",(0,r.kt)("inlineCode",{parentName:"li"},"Database")," folder (",(0,r.kt)("inlineCode",{parentName:"li"},"--database-path")," setting of the ",(0,r.kt)("strong",{parentName:"li"},"Cardano Node"),")"),(0,r.kt)("li",{parentName:"ul"},"Read/Write rights on the ",(0,r.kt)("inlineCode",{parentName:"li"},"Inter Process Communication")," file (usually ",(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_NODE_SOCKET_PATH")," env var used to launch the ",(0,r.kt)("strong",{parentName:"li"},"Cardano Node"),")"))),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},"Install a recent version of the ",(0,r.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/cardano-node/releases/tag/1.35.4"},(0,r.kt)("inlineCode",{parentName:"a"},"cardano-cli"))," (version 1.35.4+)")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},"Install a ",(0,r.kt)("a",{parentName:"p",href:"https://www.rust-lang.org/learn/get-started"},"correctly configured")," Rust toolchain (latest stable version).")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},"Install OpenSSL development libraries, for example on Ubuntu/Debian/Mint run ",(0,r.kt)("inlineCode",{parentName:"p"},"apt install libssl-dev"))),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},"Ensure the SQLite3 version is at lease ",(0,r.kt)("inlineCode",{parentName:"p"},"3.35")," (released Apr. 2021)"))),(0,r.kt)("h2",{id:"mithril-keys-certification"},"Mithril Keys Certification"),(0,r.kt)("admonition",{type:"danger"},(0,r.kt)("p",{parentName:"admonition"},"The cryptographic certification of the Mithril keys is an experimental feature. We strongly recommend that you first setup a Mithril Signer node in the stable mode. Once you are able to sign in the stable mode is a good time to start experimenting with the keys certification."),(0,r.kt)("p",{parentName:"admonition"},"Your feedback is very important, so feel free to contact us on the #moria channel on the IOG ",(0,r.kt)("a",{parentName:"p",href:"https://discord.gg/5kaErDKDRq"},"Discord server"),", or to file an issue on GitHub.")),(0,r.kt)("h3",{id:"stable-mode-certify-your-pool-id"},"Stable mode: Certify your Pool Id"),(0,r.kt)("p",null,"In this mode, you declare your Cardano ",(0,r.kt)("inlineCode",{parentName:"p"},"Operational Certificate")," file and ",(0,r.kt)("inlineCode",{parentName:"p"},"KES Secret Key")," file which allows to:"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Compute automatically the ",(0,r.kt)("inlineCode",{parentName:"li"},"PoolId")),(0,r.kt)("li",{parentName:"ul"},"Verify that you are the owner of the ",(0,r.kt)("inlineCode",{parentName:"li"},"PoolId"),", and thus of the associated stakes used by Mithril protocol"),(0,r.kt)("li",{parentName:"ul"},"Verify that you are the owner of the Mithril ",(0,r.kt)("inlineCode",{parentName:"li"},"Signer Secret Key"),", and thus allowed to contribute to the multi-signatures and certificate production of the Mithril network")),(0,r.kt)("p",null,"This mode is displayed with a specific ",(0,r.kt)("strong",{parentName:"p"},"Stable")," mention in this document."),(0,r.kt)("h3",{id:"deprecated-mode-declare-your-pool-id"},"Deprecated mode: Declare your Pool Id"),(0,r.kt)("p",null,"In this mode, the Cardano ",(0,r.kt)("inlineCode",{parentName:"p"},"Pool Id")," that you specify is not strictly verified. It is associated to Cardano stakes based on your declaration. This mode is deprecated and replaced by the certification mode above."),(0,r.kt)("p",null,"This mode is presented in the setup of this document with a specific ",(0,r.kt)("strong",{parentName:"p"},"Deprecated")," mention."),(0,r.kt)("h2",{id:"building-your-own-executable"},"Building your own executable"),(0,r.kt)("h3",{id:"download-source"},"Download source"),(0,r.kt)("p",null,"Download from Github (HTTPS)"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"git clone https://github.com/input-output-hk/mithril.git\n")),(0,r.kt)("p",null,"Or (SSH)"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"git clone git@github.com:input-output-hk/mithril.git\n")),(0,r.kt)("h3",{id:"build-mithril-signer-binary"},"Build Mithril Signer binary"),(0,r.kt)("p",null,"Change directory"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"cd mithril/mithril-signer\n")),(0,r.kt)("p",null,"Run tests (Optional)"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"make test\n")),(0,r.kt)("p",null,"Build executable"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"make build\n")),(0,r.kt)("h3",{id:"verify-build"},"Verify build"),(0,r.kt)("p",null,"Check that the Mithril Signer binary is working fine by running its help"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"./mithril-signer -h\n")),(0,r.kt)("p",null,"You should see"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"mithril-signer \nAn implementation of a Mithril Signer\n\nUSAGE:\n    mithril-signer [OPTIONS]\n\nOPTIONS:\n    -h, --help                   Print help information\n    -r, --run-mode <RUN_MODE>    Run Mode [default: dev]\n    -v, --verbose                Verbosity level\n")),(0,r.kt)("admonition",{type:"tip"},(0,r.kt)("p",{parentName:"admonition"},"If you want to dig deeper, you can get access to several level of logs from the Mithril Signer:"),(0,r.kt)("ul",{parentName:"admonition"},(0,r.kt)("li",{parentName:"ul"},"Add ",(0,r.kt)("inlineCode",{parentName:"li"},"-v")," for some logs (WARN)"),(0,r.kt)("li",{parentName:"ul"},"Add ",(0,r.kt)("inlineCode",{parentName:"li"},"-vv")," for more logs (INFO)"),(0,r.kt)("li",{parentName:"ul"},"Add ",(0,r.kt)("inlineCode",{parentName:"li"},"-vvv")," for even more logs (DEBUG)"),(0,r.kt)("li",{parentName:"ul"},"Add ",(0,r.kt)("inlineCode",{parentName:"li"},"-vvvv")," for all logs (TRACE)"))),(0,r.kt)("h3",{id:"move-executable"},"Move executable"),(0,r.kt)("p",null,"Move executable to /opt/mithril"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo mkdir -p /opt/mithril\nsudo mv mithril-signer /opt/mithril\n")),(0,r.kt)("h3",{id:"setup-the-service"},"Setup the service"),(0,r.kt)("admonition",{type:"caution"},(0,r.kt)("ul",{parentName:"admonition"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},(0,r.kt)("inlineCode",{parentName:"p"},"User=cardano"),":\nReplace this value with the correct user. We assume that the user used to run the ",(0,r.kt)("strong",{parentName:"p"},"Cardano Node")," is ",(0,r.kt)("inlineCode",{parentName:"p"},"cardano"),". The ",(0,r.kt)("strong",{parentName:"p"},"Mithril Signer")," must imperatively run with the same user.")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},(0,r.kt)("strong",{parentName:"p"},"Stable mode"),": in the ",(0,r.kt)("inlineCode",{parentName:"p"},"/opt/mithril/mithril-signer/service.env")," env file:"),(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"KES_SECRET_KEY_PATH=/cardano/keys/kes.skey"),": replace ",(0,r.kt)("inlineCode",{parentName:"li"},"/cardano/keys/kes.skey")," with the path to your Cardano ",(0,r.kt)("inlineCode",{parentName:"li"},"KES Secret Key")," file"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"OPERATIONAL_CERTIFICATE_PATH=/cardano/cert/opcert.cert"),": replace ",(0,r.kt)("inlineCode",{parentName:"li"},"/cardano/cert/opcert.cert")," with the path to your Cardano ",(0,r.kt)("inlineCode",{parentName:"li"},"Operational Certificate")," file"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"DB_DIRECTORY=/cardano/db"),": replace ",(0,r.kt)("inlineCode",{parentName:"li"},"/cardano/db")," with the path to the database folder of the ",(0,r.kt)("strong",{parentName:"li"},"Cardano Node")," (the one in ",(0,r.kt)("inlineCode",{parentName:"li"},"--database-path"),")"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket"),": replace with the path to the IPC file (",(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_NODE_SOCKET_PATH")," env var)"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_CLI_PATH=/app/bin/cardano-cli"),": replace with the path to the ",(0,r.kt)("inlineCode",{parentName:"li"},"cardano-cli")," executable"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"DATA_STORES_DIRECTORY=/opt/mithril/stores"),": replace with the path to a folder where the ",(0,r.kt)("strong",{parentName:"li"},"Mithril Signer")," will store its data (",(0,r.kt)("inlineCode",{parentName:"li"},"/opt/mithril/stores")," e.g.)"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"STORE_RETENTION_LIMIT"),": if set, this will limit the number of records in some internal stores (5 is a good fit)."))),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},(0,r.kt)("strong",{parentName:"p"},"Deprecated mode"),": in the ",(0,r.kt)("inlineCode",{parentName:"p"},"/opt/mithril/mithril-signer/service.env")," env file:"),(0,r.kt)("ul",{parentName:"li"},(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"PARTY_ID=YOUR_POOL_ID_BECH32"),": replace ",(0,r.kt)("inlineCode",{parentName:"li"},"YOUR_POOL_ID_BECH32")," with your BECH32 ",(0,r.kt)("inlineCode",{parentName:"li"},"Pool Id")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"DB_DIRECTORY=/cardano/db"),": replace ",(0,r.kt)("inlineCode",{parentName:"li"},"/cardano/db")," with the path to the database folder of the ",(0,r.kt)("strong",{parentName:"li"},"Cardano Node")," (the one in ",(0,r.kt)("inlineCode",{parentName:"li"},"--database-path"),")"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket"),": replace with the path to the IPC file (",(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_NODE_SOCKET_PATH")," env var)"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"CARDANO_CLI_PATH=/app/bin/cardano-cli"),": replace with the path to the ",(0,r.kt)("inlineCode",{parentName:"li"},"cardano-cli")," executable"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"DATA_STORES_DIRECTORY=/opt/mithril/stores"),": replace with the path to a folder where the ",(0,r.kt)("strong",{parentName:"li"},"Mithril Signer")," will store its data (",(0,r.kt)("inlineCode",{parentName:"li"},"/opt/mithril/stores")," e.g.)"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"STORE_RETENTION_LIMIT"),": if set, this will limit the number of records in some internal stores (5 is a good fit)."))))),(0,r.kt)("p",null,"First create an env file that will be used by the service:"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Stable mode"),":")),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo bash -c 'cat > /opt/mithril/mithril-signer.env << EOF\nKES_SECRET_KEY_PATH=**YOUR_KES_SECRET_KEY_PATH**\nOPERATIONAL_CERTIFICATE_PATH=**YOUR_OPERATIONAL_CERTIFICATE_PATH**\nNETWORK=**YOUR_CARDANO_NETWORK**\nAGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**\nRUN_INTERVAL=60000\nDB_DIRECTORY=/cardano/db\nCARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket\nCARDANO_CLI_PATH=/app/bin/cardano-cli\nDATA_STORES_DIRECTORY=/opt/mithril/stores\nSTORE_RETENTION_LIMIT=5\nEOF'\n")),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Deprecated mode"),":")),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo bash -c 'cat > /opt/mithril/mithril-signer.env << EOF\nPARTY_ID=**YOUR_POOL_ID_BECH32**\nNETWORK=**YOUR_CARDANO_NETWORK**\nAGGREGATOR_ENDPOINT=**YOUR_AGGREGATOR_ENDPOINT**\nRUN_INTERVAL=60000\nDB_DIRECTORY=/cardano/db\nCARDANO_NODE_SOCKET_PATH=/cardano/ipc/node.socket\nCARDANO_CLI_PATH=/app/bin/cardano-cli\nDATA_STORES_DIRECTORY=/opt/mithril/stores\nSTORE_RETENTION_LIMIT=5\nEOF'\n")),(0,r.kt)("p",null,"Then we will create a ",(0,r.kt)("inlineCode",{parentName:"p"},"/etc/systemd/system/mithril-signer.service")," description file for our service"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo bash -c 'cat > /etc/systemd/system/mithril-signer.service << EOF\n[Unit]\nDescription=Mithril Signer service\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=always\nRestartSec=1\nUser=cardano\nEnvironmentFile=/opt/mithril/mithril-signer.env\nExecStart=/opt/mithril/mithril-signer -vvv\n\n[Install]\nWantedBy=multi-user.target\nEOF'\n")),(0,r.kt)("p",null,"Reload the service configuration (Optional)"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo systemctl daemon-reload\n")),(0,r.kt)("p",null,"Then start the service"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo systemctl start mithril-signer\n")),(0,r.kt)("p",null,"Then register the service to start on boot"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"sudo systemctl enable mithril-signer\n")),(0,r.kt)("p",null,"Then monitor status of the service"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"systemctl status mithril-signer.service\n")),(0,r.kt)("p",null,"And monitor the logs of the service"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"tail /var/log/syslog\n")))}u.isMDXComponent=!0},1900:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>p,contentTitle:()=>l,default:()=>m,frontMatter:()=>i,metadata:()=>o,toc:()=>d});var a=n(7462),r=(n(7294),n(3905));const i={unlisted:!0,hide_title:!0,hide_table_of_contents:!0},l=void 0,o={unversionedId:"networks-matrix",id:"networks-matrix",title:"networks-matrix",description:"Here is an up to date list of all the Mithril Networks, their configurations and their status:",source:"@site/root/networks-matrix.md",sourceDirName:".",slug:"/networks-matrix",permalink:"/doc/next/networks-matrix",draft:!1,editUrl:"https://github.com/input-output-hk/mithril/edit/main/docs/root/networks-matrix.md",tags:[],version:"current",frontMatter:{unlisted:!0,hide_title:!0,hide_table_of_contents:!0}},p={},d=[],s={toc:d};function m(e){let{components:t,...n}=e;return(0,r.kt)("wrapper",(0,a.Z)({},s,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("p",null,"Here is an up to date list of all the ",(0,r.kt)("strong",{parentName:"p"},"Mithril Networks"),", their configurations and their status:"),(0,r.kt)("blockquote",null,(0,r.kt)("p",{parentName:"blockquote"},"Last update: 11/14/2022")),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Mithril Network"),(0,r.kt)("th",{parentName:"tr",align:null},"Cardano Network"),(0,r.kt)("th",{parentName:"tr",align:"center"},"Magic Id"),(0,r.kt)("th",{parentName:"tr",align:"center"},"Supported"),(0,r.kt)("th",{parentName:"tr",align:"center"},"Aggregator Endpoint"),(0,r.kt)("th",{parentName:"tr",align:"center"},"Genesis Verification Key"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Note"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"release-mainnet")),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"mainnet")),(0,r.kt)("td",{parentName:"tr",align:"center"},"-"),(0,r.kt)("td",{parentName:"tr",align:"center"},"\u274c"),(0,r.kt)("td",{parentName:"tr",align:"center"},"-"),(0,r.kt)("td",{parentName:"tr",align:"center"},"-"),(0,r.kt)("td",{parentName:"tr",align:"left"},"Not supported yet")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"release-preprod")),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"preprod")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("inlineCode",{parentName:"td"},"1")),(0,r.kt)("td",{parentName:"tr",align:"center"},"\u2714\ufe0f"),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://aggregator.release-preprod.api.mithril.network/aggregator",title:"https://aggregator.release-preprod.api.mithril.network/aggregator"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey",title:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Stable Release")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"pre-release-preview")),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"preview")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("inlineCode",{parentName:"td"},"2")),(0,r.kt)("td",{parentName:"tr",align:"center"},"\u2714\ufe0f"),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://aggregator.pre-release-preview.api.mithril.network/aggregator",title:"https://aggregator.pre-release-preview.api.mithril.network/aggregator"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey",title:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Unstable Pre-Release")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"testing-preview")),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"preview")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("inlineCode",{parentName:"td"},"2")),(0,r.kt)("td",{parentName:"tr",align:"center"},"\u2714\ufe0f"),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://aggregator.testing-preview.api.mithril.network/aggregator",title:"https://aggregator.testing-preview.api.mithril.network/aggregator"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey",title:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Unstable Testing (devs only)")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"dev-devnet")),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"devnet")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("inlineCode",{parentName:"td"},"42")),(0,r.kt)("td",{parentName:"tr",align:"center"},"\u2714\ufe0f"),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"http://localhost:8080/aggregator",title:"http://localhost:8080/aggregator"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"center"},"-"),(0,r.kt)("td",{parentName:"tr",align:"left"},"Supported on the ",(0,r.kt)("inlineCode",{parentName:"td"},"devnet")," only")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"-")),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"testnet")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("inlineCode",{parentName:"td"},"1097911063")),(0,r.kt)("td",{parentName:"tr",align:"center"},"\u274c"),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://aggregator.api.mithril.network/aggregator",title:"https://aggregator.api.mithril.network/aggregator"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"center"},(0,r.kt)("a",{parentName:"td",href:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey",title:"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey"},"\u2197\ufe0f")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Decommissioned, not supported anymore")))),(0,r.kt)("p",null,"\u26a0\ufe0f In this documentation, we use the generic:"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"*",(0,r.kt)("strong",{parentName:"li"},"*YOUR_CARDANO_NETWORK**")," identifier, but you need to replace it with the name of the network that runs on your Cardano node (e.g. ",(0,r.kt)("inlineCode",{parentName:"li"},"preprod"),")"),(0,r.kt)("li",{parentName:"ul"},"*",(0,r.kt)("strong",{parentName:"li"},"*YOUR_AGGREGATOR_ENDPOINT**")," identifier, but you need to replace it with the endpoint of an aggregator that runs on the Cardano network you target (e.g. ",(0,r.kt)("inlineCode",{parentName:"li"},"https://aggregator.release-preprod.api.mithril.network/aggregator"),")"),(0,r.kt)("li",{parentName:"ul"},"*",(0,r.kt)("strong",{parentName:"li"},"*YOUR_GENESIS_VERIFICATION_KEY**")," identifier, but you need to replace it with the genesis verification key url that runs on the Cardano network you target (e.g. ",(0,r.kt)("inlineCode",{parentName:"li"},"https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey"),")")))}m.isMDXComponent=!0}}]);