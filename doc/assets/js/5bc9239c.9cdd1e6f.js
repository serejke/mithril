"use strict";(self.webpackChunkmithril_doc=self.webpackChunkmithril_doc||[]).push([[5378],{3905:(e,t,r)=>{r.d(t,{Zo:()=>h,kt:()=>d});var i=r(7294);function n(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);t&&(i=i.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,i)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){n(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,i,n=function(e,t){if(null==e)return{};var r,i,n={},a=Object.keys(e);for(i=0;i<a.length;i++)r=a[i],t.indexOf(r)>=0||(n[r]=e[r]);return n}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(i=0;i<a.length;i++)r=a[i],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(n[r]=e[r])}return n}var l=i.createContext({}),p=function(e){var t=i.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},h=function(e){var t=p(e.components);return i.createElement(l.Provider,{value:t},e.children)},c={inlineCode:"code",wrapper:function(e){var t=e.children;return i.createElement(i.Fragment,{},t)}},u=i.forwardRef((function(e,t){var r=e.components,n=e.mdxType,a=e.originalType,l=e.parentName,h=s(e,["components","mdxType","originalType","parentName"]),u=p(r),d=n,m=u["".concat(l,".").concat(d)]||u[d]||c[d]||a;return r?i.createElement(m,o(o({ref:t},h),{},{components:r})):i.createElement(m,o({ref:t},h))}));function d(e,t){var r=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var a=r.length,o=new Array(a);o[0]=u;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s.mdxType="string"==typeof e?e:n,o[1]=s;for(var p=2;p<a;p++)o[p]=r[p];return i.createElement.apply(null,o)}return i.createElement.apply(null,r)}u.displayName="MDXCreateElement"},6256:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>c,frontMatter:()=>a,metadata:()=>s,toc:()=>p});var i=r(7462),n=(r(7294),r(3905));const a={title:"Stake Distribution retrieval fixed",authors:[{name:"Mithril Team"}],tags:["stake-distribution","certificate"]},o=void 0,s={permalink:"/doc/dev-blog/2022/09/13/stake-distribution-retrieval",source:"@site/blog/2022-09-13-stake-distribution-retrieval.md",title:"Stake Distribution retrieval fixed",description:"The way the Mithril nodes retrieve the Stake Distribution is changing",date:"2022-09-13T00:00:00.000Z",formattedDate:"September 13, 2022",tags:[{label:"stake-distribution",permalink:"/doc/dev-blog/tags/stake-distribution"},{label:"certificate",permalink:"/doc/dev-blog/tags/certificate"}],readingTime:1.64,hasTruncateMarker:!1,authors:[{name:"Mithril Team"}],frontMatter:{title:"Stake Distribution retrieval fixed",authors:[{name:"Mithril Team"}],tags:["stake-distribution","certificate"]},nextItem:{title:"Signers list computation in Certificates",permalink:"/doc/dev-blog/2022/09/12/certificate-signers-list"}},l={authorsImageUrls:[void 0]},p=[{value:"The way the Mithril nodes retrieve the Stake Distribution is changing",id:"the-way-the-mithril-nodes-retrieve-the-stake-distribution-is-changing",level:3}],h={toc:p};function c(e){let{components:t,...r}=e;return(0,n.kt)("wrapper",(0,i.Z)({},h,r,{components:t,mdxType:"MDXLayout"}),(0,n.kt)("h3",{id:"the-way-the-mithril-nodes-retrieve-the-stake-distribution-is-changing"},"The way the Mithril nodes retrieve the Stake Distribution is changing"),(0,n.kt)("p",null,(0,n.kt)("strong",{parentName:"p"},"PR"),": ",(0,n.kt)("inlineCode",{parentName:"p"},"Fix Stake Distribution retrieval")," ",(0,n.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/mithril/pull/499"},"#499")),(0,n.kt)("p",null,(0,n.kt)("strong",{parentName:"p"},"Issue"),": ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake distribution discrepancy")," ",(0,n.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/mithril/issues/497"},"#497")),(0,n.kt)("p",null,"We have noticed that the way the Mithril nodes computed the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distribution")," was erroneous: the epoch that was used to make the computation was the ",(0,n.kt)("strong",{parentName:"p"},"current epoch")," instead of the ",(0,n.kt)("strong",{parentName:"p"},"previous epoch"),". This has lead to some de-synchronization between the Signers and the hosted GCP Aggregator for a few epochs."),(0,n.kt)("p",null,"Indeed, the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distribution")," retrieved from the Cardano node depended on the time at which it was done: the nodes where having differents values that prevented them from being able to work together to produce valid multi-signatures. The problem is related to the epoch that is used (",(0,n.kt)("strong",{parentName:"p"},"current epoch"),") to make the computation of the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distribution")," when the ",(0,n.kt)("inlineCode",{parentName:"p"},"cardano-cli query stake-distribution")," command is ran, whereas the Mithril protocol needs to work with the ",(0,n.kt)("strong",{parentName:"p"},"previous epoch"),"."),(0,n.kt)("p",null,"A workaround is being implemented in this fix that will compute differently the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distribution")," to target the ",(0,n.kt)("strong",{parentName:"p"},"previous epoch"),". To do so, the Stake value that is now retrieved sequentially for each pool available in the ",(0,n.kt)("inlineCode",{parentName:"p"},"cardano-cli query stake-distribution")," by using the command ",(0,n.kt)("inlineCode",{parentName:"p"},"cardano-cli query stake-snapshot --stake-pool-id **pool-id*"),". This guarantees that the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distribution")," is computed deterministically on all nodes of the Mithril Network."),(0,n.kt)("p",null,"We will continue our efforts to enhance the way the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distribution")," is retrieved in the future, and so that it works smoothly on the ",(0,n.kt)("inlineCode",{parentName:"p"},"mainnet")," (where the numbers of pools is bigger ",(0,n.kt)("inlineCode",{parentName:"p"},"~3,000")," vs ",(0,n.kt)("inlineCode",{parentName:"p"},"~100")," on the ",(0,n.kt)("inlineCode",{parentName:"p"},"preview")," network)."),(0,n.kt)("p",null,"The SPOs need to recompile their Signer node in order to compute correctly the ",(0,n.kt)("inlineCode",{parentName:"p"},"Stake Distributions")," on their node (as in this ",(0,n.kt)("a",{parentName:"p",href:"https://mithril.network/doc/manual/getting-started/run-signer-node"},"guide"),").\nIt should then take up to ",(0,n.kt)("inlineCode",{parentName:"p"},"2")," epochs before they are able to successfully register their individual signatures with the Aggregator."),(0,n.kt)("p",null,"More information about the ",(0,n.kt)("inlineCode",{parentName:"p"},"Certificate Chain")," and the epochs retrieval requirements is available ",(0,n.kt)("a",{parentName:"p",href:"https://mithril.network/doc/mithril/mithril-protocol/certificates"},"here"),"."),(0,n.kt)("p",null,"Feel free to reach out to us on the ",(0,n.kt)("a",{parentName:"p",href:"https://discord.gg/5kaErDKDRq"},"Discord channel")," for questions and/or help."))}c.isMDXComponent=!0}}]);