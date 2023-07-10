"use strict";(self.webpackChunkmithril_doc=self.webpackChunkmithril_doc||[]).push([[546],{3905:(e,t,n)=>{n.d(t,{Zo:()=>d,kt:()=>u});var r=n(67294);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function a(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,o=function(e,t){if(null==e)return{};var n,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var p=r.createContext({}),s=function(e){var t=r.useContext(p),n=t;return e&&(n="function"==typeof e?e(t):a(a({},t),e)),n},d=function(e){var t=s(e.components);return r.createElement(p.Provider,{value:t},e.children)},c="mdxType",m={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},h=r.forwardRef((function(e,t){var n=e.components,o=e.mdxType,i=e.originalType,p=e.parentName,d=l(e,["components","mdxType","originalType","parentName"]),c=s(n),h=o,u=c["".concat(p,".").concat(h)]||c[h]||m[h]||i;return n?r.createElement(u,a(a({ref:t},d),{},{components:n})):r.createElement(u,a({ref:t},d))}));function u(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=n.length,a=new Array(i);a[0]=h;var l={};for(var p in t)hasOwnProperty.call(t,p)&&(l[p]=t[p]);l.originalType=e,l[c]="string"==typeof e?e:o,a[1]=l;for(var s=2;s<i;s++)a[s]=n[s];return r.createElement.apply(null,a)}return r.createElement.apply(null,n)}h.displayName="MDXCreateElement"},27906:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>p,contentTitle:()=>a,default:()=>m,frontMatter:()=>i,metadata:()=>l,toc:()=>s});var r=n(87462),o=(n(67294),n(3905));const i={title:"Mithril Signer Deployment Models",authors:[{name:"Mithril Team"}],tags:["spo","mithril signer","deployment model","production"]},a=void 0,l={permalink:"/doc/dev-blog/2023/06/28/signer-deployment-models",source:"@site/blog/2023-06-28-signer-deployment-models/index.md",title:"Mithril Signer Deployment Models",description:"The new Mithril Signer Deployment Models for SPOs will be introduced soon",date:"2023-06-28T00:00:00.000Z",formattedDate:"June 28, 2023",tags:[{label:"spo",permalink:"/doc/dev-blog/tags/spo"},{label:"mithril signer",permalink:"/doc/dev-blog/tags/mithril-signer"},{label:"deployment model",permalink:"/doc/dev-blog/tags/deployment-model"},{label:"production",permalink:"/doc/dev-blog/tags/production"}],readingTime:1.1,hasTruncateMarker:!1,authors:[{name:"Mithril Team"}],frontMatter:{title:"Mithril Signer Deployment Models",authors:[{name:"Mithril Team"}],tags:["spo","mithril signer","deployment model","production"]},nextItem:{title:"Mithril client has got a brand new interface",permalink:"/doc/dev-blog/2023/06/14/new-client-interface"}},p={authorsImageUrls:[void 0]},s=[{value:"The new Mithril Signer Deployment Models for SPOs will be introduced soon",id:"the-new-mithril-signer-deployment-models-for-spos-will-be-introduced-soon",level:3}],d={toc:s},c="wrapper";function m(e){let{components:t,...i}=e;return(0,o.kt)(c,(0,r.Z)({},d,i,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h3",{id:"the-new-mithril-signer-deployment-models-for-spos-will-be-introduced-soon"},"The new Mithril Signer Deployment Models for SPOs will be introduced soon"),(0,o.kt)("p",null,(0,o.kt)("strong",{parentName:"p"},"Epic"),": ",(0,o.kt)("inlineCode",{parentName:"p"},"Prepare Mithril Signer deployment model for SPO")," ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/mithril/issues/862"},"#862")),(0,o.kt)("p",null,"\u26a0\ufe0f The Mithril Signer Deployment Models is not deployed yet to the ",(0,o.kt)("inlineCode",{parentName:"p"},"pre-release-preview")," and ",(0,o.kt)("inlineCode",{parentName:"p"},"release-preprod")," network. A special announcement will be made on the ",(0,o.kt)("strong",{parentName:"p"},"moria")," Discord channel when a new release candidate distribution is ready."),(0,o.kt)("p",null,"All these information will be available at the updated ",(0,o.kt)("a",{parentName:"p",href:"https://mithril.network/doc/manual/getting-started/run-signer-node"},(0,o.kt)("inlineCode",{parentName:"a"},"Run a Mithril Signer node (SPO)"))," guide. In the mean time, a preview of the Mithril signer setup with the ",(0,o.kt)("strong",{parentName:"p"},"production")," deployment model is available ",(0,o.kt)("a",{parentName:"p",href:"https://mithril.network/doc/next/manual/getting-started/run-signer-node"},"here"),". In the new ",(0,o.kt)("strong",{parentName:"p"},"production")," deployment model, a new ",(0,o.kt)("strong",{parentName:"p"},"Mithril Relay")," has been introduced and requires an extra setup effort versus the ",(0,o.kt)("strong",{parentName:"p"},"naive")," deployment model that is currently ran by the pioneer SPOs on the Mithril test networks."),(0,o.kt)("admonition",{type:"info"},(0,o.kt)("p",{parentName:"admonition"},"We strongly encourage the volunteer SPOs to test the ",(0,o.kt)("strong",{parentName:"p"},"production")," deployment (once it is available of the ",(0,o.kt)("inlineCode",{parentName:"p"},"pre-release-preview")," network) and to give us their feedback on the setup (clarity of the documentation, if you needed some fixes to make it work, ...).")),(0,o.kt)("p",null,"Here is the schema of the ",(0,o.kt)("strong",{parentName:"p"},"production")," deployment for the ",(0,o.kt)("inlineCode",{parentName:"p"},"mainnet"),":\n",(0,o.kt)("a",{target:"_blank",href:n(44865).Z},(0,o.kt)("img",{alt:"Production Mithril Signer Deployment Model",src:n(36957).Z,width:"2179",height:"458"}))),(0,o.kt)("p",null,"and the schema of the ",(0,o.kt)("strong",{parentName:"p"},"naive")," deployment only for the ",(0,o.kt)("inlineCode",{parentName:"p"},"testnet"),":\n",(0,o.kt)("a",{target:"_blank",href:n(51629).Z},(0,o.kt)("img",{alt:"Naive Mithril Signer Deployment Model",src:n(79511).Z,width:"2219",height:"450"}))),(0,o.kt)("p",null,"Feel free to reach out to us on the ",(0,o.kt)("a",{parentName:"p",href:"https://discord.gg/5kaErDKDRq"},"Discord channel")," for questions and/or help."))}m.isMDXComponent=!0},51629:(e,t,n)=>{n.d(t,{Z:()=>r});const r=n.p+"assets/files/signer-deployment-naive-b2092b7ecc1a39c7344fa0cb809c250c.jpg"},44865:(e,t,n)=>{n.d(t,{Z:()=>r});const r=n.p+"assets/files/signer-deployment-production-d33184629147bf7b0c79bb731673cd6c.jpg"},79511:(e,t,n)=>{n.d(t,{Z:()=>r});const r=n.p+"assets/images/signer-deployment-naive-b2092b7ecc1a39c7344fa0cb809c250c.jpg"},36957:(e,t,n)=>{n.d(t,{Z:()=>r});const r=n.p+"assets/images/signer-deployment-production-d33184629147bf7b0c79bb731673cd6c.jpg"}}]);