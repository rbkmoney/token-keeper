-module(tk_storage_claim).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-behaviour(tk_storage).
-export([get/2]).
-export([get_by_claims/2]).
-export([store/1]).
-export([revoke/1]).

-type storage_opts() :: #{
    compatability => {true, MetadataNS :: binary()} | false
}.

-export_type([storage_opts/0]).

%%

-type storable_authdata() :: tk_storage:storable_authdata().
-type authdata_id() :: tk_authority:authdata_id().
-type claim() :: tk_token_jwt:claim().
-type claims() :: tk_token_jwt:claims().

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_TK_METADATA, <<"tk_metadata">>).

-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).
-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

%%

-spec get(authdata_id(), storage_opts()) -> {error, not_found}.
get(_DataID, _Opts) ->
    {error, not_found}.

-spec get_by_claims(claims(), storage_opts()) ->
    {ok, storable_authdata()}
    | {error, not_found | {claim_decode_error, {unsupported, claim()} | {malformed, binary()}}}.
get_by_claims(#{?CLAIM_BOUNCER_CTX := BouncerClaim} = Claims, Opts) ->
    case decode_bouncer_claim(BouncerClaim) of
        {ok, ContextFragment} ->
            case get_metadata(Claims, Opts) of
                {ok, Metadata} ->
                    {ok, create_authdata(ContextFragment, Metadata)};
                {error, no_metadata_claim} ->
                    {error, not_found}
            end;
        {error, Reason} ->
            {error, {claim_decode_error, Reason}}
    end;
get_by_claims(_Claims, _Opts) ->
    {error, not_found}.

-spec store(storable_authdata()) -> {ok, claims()}.
store(#{context := ContextFragment} = AuthData) ->
    {ok, #{
        ?CLAIM_BOUNCER_CTX => encode_bouncer_claim(ContextFragment),
        ?CLAIM_TK_METADATA => encode_metadata(AuthData)
    }}.

-spec revoke(authdata_id()) -> {error, not_found}.
revoke(_DataID) ->
    {error, not_found}.

%% Internal functions

decode_bouncer_claim(#{
    ?CLAIM_CTX_TYPE := ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
    ?CLAIM_CTX_CONTEXT := Content
}) ->
    try
        {ok, #bctx_ContextFragment{
            type = v1_thrift_binary,
            content = base64:decode(Content)
        }}
    catch
        % NOTE
        % The `base64:decode/1` fails in unpredictable ways.
        error:_ ->
            {error, {malformed, Content}}
    end;
decode_bouncer_claim(Ctx) ->
    {error, {unsupported, Ctx}}.

encode_bouncer_claim(
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = Content
    }
) ->
    #{
        ?CLAIM_CTX_TYPE => ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
        ?CLAIM_CTX_CONTEXT => base64:encode(Content)
    }.

encode_metadata(#{metadata := Metadata}) ->
    Metadata;
encode_metadata(#{}) ->
    #{}.

get_metadata(#{?CLAIM_TK_METADATA := Metadata}, _Opts) ->
    {ok, Metadata};
get_metadata(Claims, #{compatability := {true, MetadataNS}}) ->
    {ok, wrap_metadata(create_metadata(Claims), MetadataNS)};
get_metadata(_Claims, _Opts) ->
    {error, no_metadata_claim}.

create_authdata(ContextFragment, Metadata) ->
    genlib_map:compact(#{
        status => active,
        context => ContextFragment,
        metadata => Metadata
    }).

create_metadata(Claims) ->
    Metadata = maps:with(get_passthrough_claim_names(), Claims),
    %% TODO: This is a temporary hack.
    %% When some external services will stop requiring woody user identity to be present it must be removed too
    genlib_map:compact(Metadata#{
        <<"party_id">> => maps:get(<<"sub">>, Claims, undefined)
    }).

wrap_metadata(Metadata, _MetadataNS) when map_size(Metadata) =:= 0 ->
    undefined;
wrap_metadata(Metadata, MetadataNS) ->
    #{MetadataNS => Metadata}.

get_passthrough_claim_names() ->
    [
        %% token consumer
        <<"cons">>
    ].