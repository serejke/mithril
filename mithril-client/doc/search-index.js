var searchIndex = JSON.parse('{\
"mithril_client":{"doc":"Define everything necessary to list, download, and …","t":[3,8,13,4,13,13,3,13,13,13,13,13,13,13,13,13,13,3,4,12,10,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,5,11,10,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,10,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,10,11,11,11,11,11,11,11,11,11,11,11,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,10,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,12,12,12,12,12,12],"n":["AggregatorHTTPClient","AggregatorHandler","AggregatorHandler","AggregatorHandlerError","ArchiveNotFound","CertificateRetriever","Config","DigestDoesntMatch","IOError","ImmutableDigester","InvalidInput","JsonParseFailed","MissingDependency","Protocol","RemoteServerLogical","RemoteServerTechnical","RemoteServerUnreachable","Runtime","RuntimeError","aggregator_endpoint","as_certificate_retriever","as_certificate_retriever","az","az","az","az","az","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","cast_from","cast_from","cast_from","cast_from","cast_from","cell","cell","checked_as","checked_as","checked_as","checked_as","checked_as","checked_cast_from","checked_cast_from","checked_cast_from","checked_cast_from","checked_cast_from","clone","clone","clone_into","clone_into","convert_to_field_items","deserialize","download_snapshot","download_snapshot","download_snapshot","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","genesis_verification_key","get_certificate_details","get_snapshot_details","get_snapshot_details","into","into","into","into","into","into_any","into_any","into_any","into_any","into_any","into_any_arc","into_any_arc","into_any_arc","into_any_arc","into_any_arc","into_any_rc","into_any_rc","into_any_rc","into_any_rc","into_any_rc","list_snapshots","list_snapshots","list_snapshots","lossless_try_into","lossless_try_into","lossless_try_into","lossless_try_into","lossless_try_into","lossy_into","lossy_into","lossy_into","lossy_into","lossy_into","network","network","new","new","overflowing_as","overflowing_as","overflowing_as","overflowing_as","overflowing_as","overflowing_cast_from","overflowing_cast_from","overflowing_cast_from","overflowing_cast_from","overflowing_cast_from","restore_snapshot","row","row","saturating_as","saturating_as","saturating_as","saturating_as","saturating_as","saturating_cast_from","saturating_cast_from","saturating_cast_from","saturating_cast_from","saturating_cast_from","serialize","show_snapshot","source","source","title","to_owned","to_owned","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_name","type_name","type_name","type_name","type_name","unpack_snapshot","unpack_snapshot","unwrapped_as","unwrapped_as","unwrapped_as","unwrapped_as","unwrapped_as","unwrapped_cast_from","unwrapped_cast_from","unwrapped_cast_from","unwrapped_cast_from","unwrapped_cast_from","vzip","vzip","vzip","vzip","vzip","with_digester","wrapping_as","wrapping_as","wrapping_as","wrapping_as","wrapping_as","wrapping_cast_from","wrapping_cast_from","wrapping_cast_from","wrapping_cast_from","wrapping_cast_from","0","0","0","0","0","0","0","0","0","0","0","0","0"],"q":["mithril_client","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","mithril_client::AggregatorHandlerError","","","","","","mithril_client::RuntimeError","","","","","",""],"d":["AggregatorHTTPClient is a http client for an aggregator","AggregatorHandler represents a read interactor with an …","Error raised when an AggregatorHandlerError is caught when …","AggregatorHandler related errors.","Error raised when AggregatorHandler::unpack_snapshot is …","Error raised when a CertificateRetrieverError tries to …","Client configuration","Error raised when the digest stored in the signed message …","Error raised when an IO error occured (ie: snapshot …","Error raised when the digest computation fails.","Error raised when the user provided an invalid input.","Error raised when the json parsing of the aggregator …","Error raised when accessing a missing dependency.","Error raised when verification fails.","Error raised when querying the aggregator returned a 4XX …","Error raised when querying the aggregator returned a 5XX …","Error raised when the aggregator can’t be reached.","Mithril client runtime","Runtime related errors.","Aggregator endpoint","Upcast to a CertificateRetriever","Upcast to a CertificateRetriever","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Convert Snapshot to SnapshotFieldItems routine","","Download snapshot","Download a snapshot by digest","Download Snapshot","","","","","","Returns the argument unchanged.","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","Returns the argument unchanged.","","","Genesis verification key","Get certificate details","Get snapshot details","Get snapshot details","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","List snapshots","List snapshots","List snapshots","","","","","","","","","","","Cardano network","Cardano network","Runtime factory","AggregatorHTTPClient factory","","","","","","","","","","","Restore a snapshot by digest","","","","","","","","","","","","","","Show a snapshot","","","","","","","","","","","","","","","","","","","","","","","","","","","","Unpack snapshot","Unpack snapshot","","","","","","","","","","","","","","","","With Digester","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,1,0,2,1,0,1,2,1,1,2,1,1,2,2,2,0,0,3,4,5,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,2,1,6,2,5,3,1,6,2,5,3,1,5,3,5,3,0,3,4,6,5,2,2,3,1,1,6,2,2,5,3,1,1,1,1,1,3,5,4,5,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,4,6,5,6,2,5,3,1,6,2,5,3,1,6,3,6,5,6,2,5,3,1,6,2,5,3,1,6,3,3,6,2,5,3,1,6,2,5,3,1,3,6,2,1,3,5,3,2,1,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,4,5,6,2,5,3,1,6,2,5,3,1,6,2,5,3,1,6,6,2,5,3,1,6,2,5,3,1,7,8,9,10,11,12,13,14,15,16,17,18,19],"f":[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[["",0]],["arc",3,[["certificateretriever",8]]]],[[["aggregatorhttpclient",3]],["arc",3,[["certificateretriever",8]]]],[[]],[[]],[[]],[[]],[[]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[["",0]],["",0]],[[]],[[]],[[]],[[]],[[]],[[],["cellstruct",3]],[[],["cellstruct",3]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[["aggregatorhttpclient",3]],["aggregatorhttpclient",3]],[[["config",3]],["config",3]],[[["",0],["",0]]],[[["",0],["",0]]],[[["snapshot",3],["string",3]],["vec",3,[["snapshotfielditem",3]]]],[[],["result",4,[["config",3]]]],[[["",0],["str",0],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[["runtime",3],["str",0],["isize",0]],["future",8]],[[["aggregatorhttpclient",3],["str",0],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[["aggregatorhandlererror",4],["formatter",3]],["result",6]],[[["aggregatorhandlererror",4],["formatter",3]],["result",6]],[[["config",3],["formatter",3]],["result",6]],[[["runtimeerror",4],["formatter",3]],["result",6]],[[["runtimeerror",4],["formatter",3]],["result",6]],[[]],[[["error",3]],["aggregatorhandlererror",4]],[[]],[[]],[[]],[[["certificateretrievererror",4]],["runtimeerror",4]],[[["aggregatorhandlererror",4]],["runtimeerror",4]],[[]],[[["certificateverifiererror",4]],["runtimeerror",4]],[[["immutabledigestererror",4]],["runtimeerror",4]],null,[[["aggregatorhttpclient",3],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[["",0],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[["aggregatorhttpclient",3],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[]],[[]],[[]],[[]],[[]],[[["box",3,[["global",3]]]],["box",3,[["any",8],["global",3]]]],[[["box",3,[["global",3]]]],["box",3,[["any",8],["global",3]]]],[[["box",3,[["global",3]]]],["box",3,[["any",8],["global",3]]]],[[["box",3,[["global",3]]]],["box",3,[["any",8],["global",3]]]],[[["box",3,[["global",3]]]],["box",3,[["any",8],["global",3]]]],[[["arc",3]],["arc",3,[["any",8]]]],[[["arc",3]],["arc",3,[["any",8]]]],[[["arc",3]],["arc",3,[["any",8]]]],[[["arc",3]],["arc",3,[["any",8]]]],[[["arc",3]],["arc",3,[["any",8]]]],[[["rc",3]],["rc",3,[["any",8]]]],[[["rc",3]],["rc",3,[["any",8]]]],[[["rc",3]],["rc",3,[["any",8]]]],[[["rc",3]],["rc",3,[["any",8]]]],[[["rc",3]],["rc",3,[["any",8]]]],[[["",0]],["pin",3,[["box",3,[["future",8]]]]]],[[["runtime",3]],["future",8]],[[["aggregatorhttpclient",3]],["pin",3,[["box",3,[["future",8]]]]]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[],["option",4]],[[]],[[]],[[]],[[]],[[]],null,null,[[["string",3],["arc",3,[["aggregatorhandler",8]]],["box",3,[["certificateverifier",8]]],["protocolgenesisverifier",3]],["runtime",3]],[[["string",3],["string",3]],["aggregatorhttpclient",3]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["runtime",3],["str",0]],["future",8]],[[["config",3]],["rowstruct",3]],[[["config",3]],["rowstruct",3]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["config",3]],["result",4]],[[["runtime",3],["str",0]],["future",8]],[[["aggregatorhandlererror",4]],["option",4,[["error",8]]]],[[["runtimeerror",4]],["option",4,[["error",8]]]],[[],["rowstruct",3]],[[["",0]]],[[["",0]]],[[["",0]],["string",3]],[[["",0]],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["typeid",3]],[[["",0]],["str",0]],[[["",0]],["str",0]],[[["",0]],["str",0]],[[["",0]],["str",0]],[[["",0]],["str",0]],[[["",0],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[["aggregatorhttpclient",3],["str",0]],["pin",3,[["box",3,[["future",8]]]]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["runtime",3],["box",3,[["immutabledigester",8]]]],["runtime",3]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,null,null,null,null,null,null,null,null,null,null,null],"p":[[4,"RuntimeError"],[4,"AggregatorHandlerError"],[3,"Config"],[8,"AggregatorHandler"],[3,"AggregatorHTTPClient"],[3,"Runtime"],[13,"RemoteServerTechnical"],[13,"RemoteServerLogical"],[13,"RemoteServerUnreachable"],[13,"JsonParseFailed"],[13,"IOError"],[13,"ArchiveNotFound"],[13,"MissingDependency"],[13,"InvalidInput"],[13,"AggregatorHandler"],[13,"CertificateRetriever"],[13,"ImmutableDigester"],[13,"DigestDoesntMatch"],[13,"Protocol"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
