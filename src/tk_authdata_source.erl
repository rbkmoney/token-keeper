-module(tk_authdata_source).

%% Behaviour

-callback get_authdata(tk_token:token_data(), opts(), woody_context:ctx()) -> authdata() | undefined.

%% API functions

-export([get_authdata/3]).

%% API Types

-type authdata_source() :: claim_source() | storage_source() | legacy_claim_source() | extractor_source().

-type opts() ::
    tk_authdata_source_claim:opts()
    | tk_authdata_source_storage:opts()
    | tk_authdata_source_context_extractor:opts()
    | tk_authdata_source_legacy_claim:opts().

-export_type([authdata_source/0]).

%% Internal types

-type authdata() :: tk_authdata:prototype().

-type claim_source() :: {claim, tk_authdata_source_claim:opts()}.
-type storage_source() :: {storage, tk_authdata_source_storage:opts()}.
-type legacy_claim_source() :: {legacy_claim, tk_authdata_source_legacy_claim:opts()}.
-type extractor_source() :: {extract_context, tk_authdata_source_context_extractor:opts()}.

%% API functions

-spec get_authdata(tk_token:token_data(), authdata_source(), woody_context:ctx()) -> authdata() | undefined.
get_authdata(TokenPayload, AuthdataSource, Context) ->
    {Handler, Opts} = get_source_modopts(AuthdataSource),
    Handler:get_authdata(TokenPayload, Opts, Context).

%% Internal functions

get_source_modopts({SourceType, Opts}) ->
    {get_source_handler(SourceType), Opts}.

get_source_handler(claim) ->
    tk_authdata_source_claim;
get_source_handler(storage) ->
    tk_authdata_source_storage;
get_source_handler(legacy_claim) ->
    tk_authdata_source_legacy_claim;
get_source_handler(extract_context) ->
    tk_authdata_source_context_extractor.
