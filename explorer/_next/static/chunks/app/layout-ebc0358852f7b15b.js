(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[185],{5891:function(e,t,r){Promise.resolve().then(r.t.bind(r,413,23)),Promise.resolve().then(r.t.bind(r,8326,23)),Promise.resolve().then(r.t.bind(r,5858,23)),Promise.resolve().then(r.t.bind(r,6069,23)),Promise.resolve().then(r.t.bind(r,7891,23)),Promise.resolve().then(r.t.bind(r,8117,23)),Promise.resolve().then(r.bind(r,3620))},1447:function(e,t,r){"use strict";t.Z=["https://aggregator.release-mainnet.api.mithril.network/aggregator","https://aggregator.release-preprod.api.mithril.network/aggregator","https://aggregator.pre-release-preview.api.mithril.network/aggregator","https://aggregator.testing-preview.api.mithril.network/aggregator","http://localhost:8080/aggregator"]},4072:function(e,t,r){"use strict";r.d(t,{W:function(){return o}});let o="aggregator"},1118:function(e,t,r){"use strict";r.d(t,{Mj:function(){return i},Q9:function(){return l},Ux:function(){return n}});var o=r(64),a=r(6023);let n=(0,o.oM)({name:"pools",initialState:{list:[]},reducers:{},extraReducers:e=>e.addCase(l.fulfilled,(e,t)=>{if(t.payload.keep_cached_data)return;let r=poolsForAggregator(e,t.payload.aggregator);r?(r.network=t.payload.network,r.pools=t.payload.pools,r.date=t.payload.date):e.list.push({aggregator:t.payload.aggregator,date:t.payload.date,network:t.payload.network,pools:t.payload.pools})})}),l=(0,o.hg)("pools/updateForAggregator",(e,t)=>{var r;let o=t.getState(),a=poolsForAggregator(o.pools,e),n=Date.now(),l=n-(null!==(r=null==a?void 0:a.date)&&void 0!==r?r:0);return l>216e5?fetch("".concat(e,"/signers/tickers")).then(e=>200===e.status?e.json():{}).then(t=>{var r;return{aggregator:e,date:n,network:t.network,pools:null!==(r=t.signers)&&void 0!==r?r:[]}}):{keep_cached_data:!0}}),poolsForAggregator=(e,t)=>e.list.find(e=>e.aggregator===t),i=(0,a.P1)([e=>e.pools,(e,t,r)=>({aggregator:t,poolId:r})],(e,t)=>{let r=poolsForAggregator(e,t.aggregator),o=null==r?void 0:r.pools.find(e=>e.party_id===t.poolId);return{network:null==r?void 0:r.network,...o}});n.reducer},3620:function(e,t,r){"use strict";r.r(t),r.d(t,{Providers:function(){return Providers}});var o=r(7437),a=r(4072),n=r(64),l=r(1118),i=r(9718),g=r(1447),s=r(3513);let c="Explorer_State",storeBuilder=e=>{var t;return(0,n.xC)({reducer:{settings:i.xj.reducer,pools:l.Ux.reducer},preloadedState:{...t=function(){if(localStorage){let e=localStorage.getItem(c);return e?JSON.parse(e):void 0}}(),settings:function(e,t){var r,o;let a,n=null!=e?e:i.E3,l=(r=n.availableAggregators,o=g.Z,a=r.filter(e=>!o.includes(e)),[...o,...a]);return t&&(0,s.checkUrl)(t)?(l.includes(t)||l.push(t),n={...n,selectedAggregator:t,availableAggregators:l,canRemoveSelected:!g.Z.includes(t)}):n={...n,availableAggregators:l},n}(null==t?void 0:t.settings,e)}})};var u=r(3198),d=r(4033),p=r(2265);function Providers(e){let{children:t}=e,r=(0,d.useSearchParams)(),n=r.get(a.W),[l,i]=(0,p.useState)(storeBuilder(n));return l.subscribe(()=>{var e;return e=l.getState(),void(localStorage&&localStorage.setItem(c,JSON.stringify(e)))}),(0,o.jsx)(u.zt,{store:l,children:t})}},9718:function(e,t,r){"use strict";r.d(t,{E3:function(){return l},JV:function(){return g},OR:function(){return u},VT:function(){return c},k6:function(){return selectedAggregator},uI:function(){return s},xj:function(){return i}});var o=r(64),a=r(1447),n=r(3513);let l={autoUpdate:!0,updateInterval:1e4,selectedAggregator:a.Z[0],availableAggregators:a.Z,canRemoveSelected:!1},i=(0,o.oM)({name:"settings",initialState:l,reducers:{setUpdateInterval:(e,t)=>{e.updateInterval=t.payload},toggleAutoUpdate:e=>{e.autoUpdate=!e.autoUpdate},selectAggregator:(e,t)=>{if(!(0,n.checkUrl)(t.payload))return e;let r=e.availableAggregators.includes(t.payload)?e.availableAggregators:[...e.availableAggregators,t.payload];return{...e,selectedAggregator:t.payload,availableAggregators:r,canRemoveSelected:!a.Z.includes(t.payload)}},removeSelectedAggregator:e=>a.Z.includes(e.selectedAggregator)?e:{...e,selectedAggregator:e.availableAggregators.at(0),availableAggregators:e.availableAggregators.filter(t=>t!==e.selectedAggregator),canRemoveSelected:!a.Z.includes(e.availableAggregators.at(0))}}}),{setUpdateInterval:g,toggleAutoUpdate:s,selectAggregator:c,removeSelectedAggregator:u}=i.actions,selectedAggregator=e=>e.settings.selectedAggregator;i.reducer},3513:function(e){"use strict";let toAda=e=>e/1e6,formatCurrency=function(e){let t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:2;return e.toLocaleString(void 0,{maximumFractionDigits:t})};e.exports={checkUrl:function(e){try{return new URL(e),!0}catch(e){return!1}},formatStake:function(e){let t=toAda(e),r=[{suffix:"B",value:1e9},{suffix:"M",value:1e6},{suffix:"K",value:1e3},{suffix:"",value:1}].find(e=>Math.abs(t)>=e.value-.001);return r?"".concat(formatCurrency(t/r.value)).concat(r.suffix,"₳"):"".concat(formatCurrency(t),"₳")},toAda,formatCurrency,formatBytes:function(e){let t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:2;if(0===e)return"0 Bytes";let r=t<0?0:t,o=Math.floor(Math.log(e)/Math.log(1024));return parseFloat((e/Math.pow(1024,o)).toFixed(r))+" "+["Bytes","KiB","MiB","GiB","TiB","PiB","EiB","ZiB","YiB"][o]},formatPartyId:function(e){return("string"==typeof e||e instanceof String)&&e.length>15?e.slice(0,10)+"…"+e.slice(-5):e},getCExplorerUrlForPool:function(e,t){let r;let o="cexplorer.io/pool/".concat(t);switch(e){case"mainnet":r="https://".concat(o);break;case"preprod":r="https://preprod.".concat(o);break;case"preview":r="https://preview.".concat(o)}return r}}},7891:function(){},8117:function(){},6069:function(){},5858:function(e){e.exports={container:"explorer_container__e4y3J",main:"explorer_main__72BOO",footer:"explorer_footer__NDYaK",title:"explorer_title__4AQZM",code:"explorer_code__d9zj2",logo:"explorer_logo__qsx9l"}}},function(e){e.O(0,[428,621,913,971,472,744],function(){return e(e.s=5891)}),_N_E=e.O()}]);