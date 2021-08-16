-module(tk_token_claim_utils).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([decode_authdata/2]).
-export([encode_authdata/1]).

-type decode_opts() :: #{
    compatibility => {true, compatibility_opts()} | false
}.

-type compatibility_opts() :: #{
    metadata_mappings := #{
        party_id := binary(),
        token_consumer := binary()
    }
}.

-export_type([decode_opts/0]).
-export_type([compatibility_opts/0]).

%%

-type storable_authdata() :: tk_storage:storable_authdata().
-type claim() :: tk_token_jwt:claim().
-type claims() :: tk_token_jwt:claims().

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_TK_METADATA, <<"tk_metadata">>).

-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).
-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

%%

-spec decode_authdata(claims(), decode_opts()) ->
    {ok, storable_authdata()}
    | {error, not_found | {claim_decode_error, {unsupported, claim()} | {malformed, binary()}}}.
decode_authdata(#{?CLAIM_BOUNCER_CTX := BouncerClaim} = Claims, Opts) ->
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
decode_authdata(_Claims, _Opts) ->
    {error, not_found}.

-spec encode_authdata(storable_authdata()) -> claims().
encode_authdata(#{context := ContextFragment} = AuthData) ->
    #{
        ?CLAIM_BOUNCER_CTX => encode_bouncer_claim(ContextFragment),
        ?CLAIM_TK_METADATA => encode_metadata(AuthData)
    }.

%%

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
get_metadata(Claims, #{compatibility := {true, CompatOpts}}) ->
    {ok, create_metadata(Claims, CompatOpts)};
get_metadata(_Claims, _Opts) ->
    {error, no_metadata_claim}.

create_authdata(ContextFragment, Metadata) ->
    genlib_map:compact(#{
        status => active,
        context => ContextFragment,
        metadata => Metadata
    }).

create_metadata(Claims, CompatOpts) ->
    Metadata = #{
        %% TODO: This is a temporary hack.
        %% When some external services will stop requiring woody user identity to be present it must be removed too
        party_id => maps:get(<<"sub">>, Claims, undefined),
        consumer => maps:get(<<"cons">>, Claims, undefined)
    },
    tk_utils:remap(genlib_map:compact(Metadata), maps:get(metadata_mappings, CompatOpts)).
