"use strict";(self.webpackChunkmithril_doc=self.webpackChunkmithril_doc||[]).push([[3828],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>g});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var s=n.createContext({}),p=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},c=function(e){var t=p(e.components);return n.createElement(s.Provider,{value:t},e.children)},h="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,s=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),h=p(r),m=a,g=h["".concat(s,".").concat(m)]||h[m]||u[m]||i;return r?n.createElement(g,o(o({ref:t},c),{},{components:r})):n.createElement(g,o({ref:t},c))}));function g(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,o=new Array(i);o[0]=m;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[h]="string"==typeof e?e:a,o[1]=l;for(var p=2;p<i;p++)o[p]=r[p];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},7993:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>h,frontMatter:()=>i,metadata:()=>l,toc:()=>p});var n=r(7462),a=(r(7294),r(3905));const i={title:"Genesis Certificate support added",authors:[{name:"Mithril Team"}],tags:["genesis","certificate","breaking-change"]},o=void 0,l={permalink:"/doc/dev-blog/2022/09/07/genesis-certificate-feature",source:"@site/blog/2022-09-07-genesis-certificate-feature.md",title:"Genesis Certificate support added",description:"Update: The PR has been merged and the feature is being deployed on the GCP Mithril Aggregator.",date:"2022-09-07T00:00:00.000Z",formattedDate:"September 7, 2022",tags:[{label:"genesis",permalink:"/doc/dev-blog/tags/genesis"},{label:"certificate",permalink:"/doc/dev-blog/tags/certificate"},{label:"breaking-change",permalink:"/doc/dev-blog/tags/breaking-change"}],readingTime:1.12,hasTruncateMarker:!1,authors:[{name:"Mithril Team"}],frontMatter:{title:"Genesis Certificate support added",authors:[{name:"Mithril Team"}],tags:["genesis","certificate","breaking-change"]},prevItem:{title:"Signers list computation in Certificates",permalink:"/doc/dev-blog/2022/09/12/certificate-signers-list"}},s={authorsImageUrls:[void 0]},p=[{value:"This afternoon, we plan to merge the PR that activates the Genesis Certificate feature on the GCP Mithril Aggregator",id:"this-afternoon-we-plan-to-merge-the-pr-that-activates-the-genesis-certificate-feature-on-the-gcp-mithril-aggregator",level:3}],c={toc:p};function h(e){let{components:t,...r}=e;return(0,a.kt)("wrapper",(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,(0,a.kt)("strong",{parentName:"p"},"Update"),": The PR has been merged and the feature is being deployed on the GCP Mithril Aggregator."),(0,a.kt)("h3",{id:"this-afternoon-we-plan-to-merge-the-pr-that-activates-the-genesis-certificate-feature-on-the-gcp-mithril-aggregator"},"This afternoon, we plan to merge the PR that activates the Genesis Certificate feature on the GCP Mithril Aggregator"),(0,a.kt)("p",null,(0,a.kt)("strong",{parentName:"p"},"PR"),": ",(0,a.kt)("inlineCode",{parentName:"p"},"Implement Real Genesis Certificate")," ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/mithril/pull/438"},"#438")),(0,a.kt)("p",null,(0,a.kt)("strong",{parentName:"p"},"Issue"),": ",(0,a.kt)("inlineCode",{parentName:"p"},"Bootstrap Certificate Chain w/ Genesis Certificate")," ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/input-output-hk/mithril/issues/364"},"#364")),(0,a.kt)("p",null,"This will involve some manual operations that will prevent temporarily the service to be running:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"We will have to reset the stores of the ",(0,a.kt)("inlineCode",{parentName:"p"},"Snapshots")," and ",(0,a.kt)("inlineCode",{parentName:"p"},"Certificates"),". This means that the ",(0,a.kt)("a",{parentName:"p",href:"https://mithril.network/explorer/"},"Mithril Explorer")," will display a ",(0,a.kt)("inlineCode",{parentName:"p"},"No snapshot available")," message.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"The Mithril Signers will have to wait until the next epoch ",(0,a.kt)("inlineCode",{parentName:"p"},"#30")," to be able to sign. This means that we should see the first available ",(0,a.kt)("inlineCode",{parentName:"p"},"Snapshot")," 1 hour after the epoch transition."))),(0,a.kt)("p",null,"The SPOs that are currently running a Mithril Signer will have to recompile their node in order ot take advantage of the latest improvements (such as the registration of the nodes that will take few minutes instead of few hours). However, the previously compiled node will be able to contribute to signatures."),(0,a.kt)("p",null,"In order to restore a Mithril Snapshot, a Mithril Client will now need access to the ",(0,a.kt)("inlineCode",{parentName:"p"},"Genesis Verification Key")," by adding an environment variable when running: ",(0,a.kt)("inlineCode",{parentName:"p"},"GENESIS_VERIFICATION_KEY=$(wget -q -O - https://raw.githubusercontent.com/input-output-hk/mithril/main/TEST_ONLY_genesis.vkey)"),"."),(0,a.kt)("p",null,"Feel free to reach out to us on the ",(0,a.kt)("a",{parentName:"p",href:"https://discord.gg/5kaErDKDRq"},"Discord channel")," for questions and/or help."))}h.isMDXComponent=!0}}]);