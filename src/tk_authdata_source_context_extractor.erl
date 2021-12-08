-module(tk_authdata_source_context_extractor).
-behaviour(tk_authdata_source).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% Behaviour

-export([get_authdata/3]).

%% API types

-type opts() :: #{
    methods => tk_context_extractor:methods()
}.

-export_type([opts/0]).

%% Internal types

-type authdata() :: tk_authdata:prototype().

%% Behaviour functions

-spec get_authdata(tk_token:token_data(), opts(), woody_context:ctx()) -> authdata() | undefined.
get_authdata(VerifiedToken, Opts, _Context) ->
    Methods = get_extractor_methods(Opts),
    case extract_context_with(Methods, VerifiedToken) of
        {Context, Metadata} ->
            make_auth_data(Context, Metadata);
        undefined ->
            undefined
    end.

%% Internal functions

get_extractor_methods(Opts) ->
    maps:get(methods, Opts).

extract_context_with([], _VerifiedToken) ->
    undefined;
extract_context_with([MethodOpts | Rest], VerifiedToken) ->
    case tk_context_extractor:extract_context(MethodOpts, VerifiedToken) of
        AuthData when AuthData =/= undefined ->
            AuthData;
        undefined ->
            extract_context_with(Rest, VerifiedToken)
    end.

make_auth_data(ContextFragment, Metadata) ->
    genlib_map:compact(#{
        status => active,
        context => encode_context_fragment(ContextFragment),
        metadata => Metadata
    }).

encode_context_fragment(ContextFragment) ->
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_fragment_content(ContextFragment)
    }.

encode_context_fragment_content(ContextFragment) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.
