"use strict";(self.webpackChunkmithril_doc=self.webpackChunkmithril_doc||[]).push([[8071],{3905:(t,e,r)=>{r.d(e,{Zo:()=>m,kt:()=>d});var i=r(7294);function n(t,e,r){return e in t?Object.defineProperty(t,e,{value:r,enumerable:!0,configurable:!0,writable:!0}):t[e]=r,t}function a(t,e){var r=Object.keys(t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);e&&(i=i.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),r.push.apply(r,i)}return r}function o(t){for(var e=1;e<arguments.length;e++){var r=null!=arguments[e]?arguments[e]:{};e%2?a(Object(r),!0).forEach((function(e){n(t,e,r[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(r,e))}))}return t}function l(t,e){if(null==t)return{};var r,i,n=function(t,e){if(null==t)return{};var r,i,n={},a=Object.keys(t);for(i=0;i<a.length;i++)r=a[i],e.indexOf(r)>=0||(n[r]=t[r]);return n}(t,e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(t);for(i=0;i<a.length;i++)r=a[i],e.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(t,r)&&(n[r]=t[r])}return n}var p=i.createContext({}),h=function(t){var e=i.useContext(p),r=e;return t&&(r="function"==typeof t?t(e):o(o({},e),t)),r},m=function(t){var e=h(t.components);return i.createElement(p.Provider,{value:e},t.children)},c="mdxType",s={inlineCode:"code",wrapper:function(t){var e=t.children;return i.createElement(i.Fragment,{},e)}},u=i.forwardRef((function(t,e){var r=t.components,n=t.mdxType,a=t.originalType,p=t.parentName,m=l(t,["components","mdxType","originalType","parentName"]),c=h(r),u=n,d=c["".concat(p,".").concat(u)]||c[u]||s[u]||a;return r?i.createElement(d,o(o({ref:e},m),{},{components:r})):i.createElement(d,o({ref:e},m))}));function d(t,e){var r=arguments,n=e&&e.mdxType;if("string"==typeof t||n){var a=r.length,o=new Array(a);o[0]=u;var l={};for(var p in e)hasOwnProperty.call(e,p)&&(l[p]=e[p]);l.originalType=t,l[c]="string"==typeof t?t:n,o[1]=l;for(var h=2;h<a;h++)o[h]=r[h];return i.createElement.apply(null,o)}return i.createElement.apply(null,r)}u.displayName="MDXCreateElement"},3021:(t,e,r)=>{r.r(e),r.d(e,{assets:()=>p,contentTitle:()=>o,default:()=>c,frontMatter:()=>a,metadata:()=>l,toc:()=>h});var i=r(7462),n=(r(7294),r(3905));const a={sidebar_position:1,sidebar_label:"Introduction"},o="About Mithril",l={unversionedId:"mithril/intro",id:"mithril/intro",title:"About Mithril",description:"Interact with the Mithril Protocol by experiencing with our protocol simulation. This will help you understand how the participants interact to create a multi signature and what's the impact of the protocol parameters.",source:"@site/root/mithril/intro.md",sourceDirName:"mithril",slug:"/mithril/intro",permalink:"/doc/next/mithril/intro",draft:!1,editUrl:"https://github.com/input-output-hk/mithril/edit/main/docs/root/mithril/intro.md",tags:[],version:"current",sidebarPosition:1,frontMatter:{sidebar_position:1,sidebar_label:"Introduction"},sidebar:"mithrilSideBar",next:{title:"Mithril Protocol",permalink:"/doc/next/category/mithril-protocol"}},p={},h=[{value:"Mithril in a nutshell",id:"mithril-in-a-nutshell",level:2},{value:"What you&#39;ll find in this guide",id:"what-youll-find-in-this-guide",level:2}],m={toc:h};function c(t){let{components:e,...r}=t;return(0,n.kt)("wrapper",(0,i.Z)({},m,r,{components:e,mdxType:"MDXLayout"}),(0,n.kt)("h1",{id:"about-mithril"},"About Mithril"),(0,n.kt)("admonition",{title:"New",type:"info"},(0,n.kt)("p",{parentName:"admonition"},"\ud83c\udd95 Interact with the ",(0,n.kt)("strong",{parentName:"p"},"Mithril Protocol")," by experiencing with our ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-protocol/simulation"},"protocol simulation"),". This will help you understand how the participants interact to create a multi signature and what's the impact of the protocol parameters.")),(0,n.kt)("h2",{id:"mithril-in-a-nutshell"},"Mithril in a nutshell"),(0,n.kt)("p",null,(0,n.kt)("strong",{parentName:"p"},"Mithril")," is a research project which goal is to provide ",(0,n.kt)("a",{parentName:"p",href:"https://iohk.io/en/research/library/papers/mithrilstake-based-threshold-multisignatures/"},"Stake-based Threshold Multisignatures")," on top of the ",(0,n.kt)("strong",{parentName:"p"},"Cardano Network"),"."),(0,n.kt)("p",null,"In a nutshell, ",(0,n.kt)("strong",{parentName:"p"},"Mithril")," can be summarized as:"),(0,n.kt)("blockquote",null,(0,n.kt)("p",{parentName:"blockquote"},"A protocol that allows ",(0,n.kt)("strong",{parentName:"p"},"stakeholders")," in a ",(0,n.kt)("strong",{parentName:"p"},"Proof-of-Stake")," blockchain network to individually ",(0,n.kt)("strong",{parentName:"p"},"sign messages")," that are aggregated into a ",(0,n.kt)("strong",{parentName:"p"},"multi signature")," which guarantees that they represent a minimum share of the total stakes.")),(0,n.kt)("p",null,"In other words, an adversarial participant with less than this share of the total stakes will not be able to produce valid multi signatures \ud83d\udd10."),(0,n.kt)("h2",{id:"what-youll-find-in-this-guide"},"What you'll find in this guide"),(0,n.kt)("p",null,"In this ",(0,n.kt)("strong",{parentName:"p"},"About Mithril")," guide, you will find:"),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"Documentation on the ",(0,n.kt)("strong",{parentName:"p"},"Mithril Protocol"),":"),(0,n.kt)("ul",{parentName:"li"},(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"The ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-protocol/protocol"},"Mithril Protocol in depth"))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"The ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-protocol/certificates"},"Mithril Certificate Chain in depth"))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"\ud83c\udd95 An interactive discovery of the protocol with the ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-protocol/simulation"},"Mithril Simulation"))))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"Documentation on the ",(0,n.kt)("strong",{parentName:"p"},"Mithril Network"),":"),(0,n.kt)("ul",{parentName:"li"},(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"The ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-network/architecture"},"Mithril Network architecture"))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"The ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-network/aggregator"},"Mithril Aggregator node"))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"The ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-network/signer"},"Mithril Signer node"))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},"The ",(0,n.kt)("a",{parentName:"p",href:"/doc/next/mithril/mithril-network/client"},"Mithril Client node")))))),(0,n.kt)("admonition",{type:"tip"},(0,n.kt)("p",{parentName:"admonition"},"If you need help, feel free to reach the ",(0,n.kt)("strong",{parentName:"p"},"Mithril")," team:"),(0,n.kt)("ul",{parentName:"admonition"},(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},(0,n.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/mithril/discussions"},"Github Discussions"))),(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("p",{parentName:"li"},(0,n.kt)("a",{parentName:"p",href:"https://cardano.stackexchange.com/questions/tagged/mithril"},"Stack Exchange"))))))}c.isMDXComponent=!0}}]);