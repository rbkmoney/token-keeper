-module(tk_authdata_source_extractor).
-behaviour(tk_authdata_source).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% Behaviour

-export([get_authdata/2]).

%%

-type extracted_authdata() :: #{
    status := tk_authority:status(),
    context := tk_authority:encoded_context_fragment(),
    metadata => tk_authority:metadata()
}.

-type source_opts() :: #{
    methods => tk_extractor:methods()
}.

-export_type([extracted_authdata/0]).
-export_type([source_opts/0]).

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), source_opts()) -> extracted_authdata() | undefined.
get_authdata(Token, Opts) ->
    Methods = get_extractor_methods(Opts),
    case extract_context_with(Methods, Token) of
        {Context, Metadata} ->
            make_auth_data(Context, Metadata);
        undefined ->
            undefined
    end.

%%

get_extractor_methods(Opts) ->
    maps:get(methods, Opts).

extract_context_with([], _Token) ->
    undefined;
extract_context_with([MethodOpts | Rest], Token) ->
    {Method, Opts} = get_method_opts(MethodOpts),
    case tk_extractor:get_context(Method, Token, Opts) of
        AuthData when AuthData =/= undefined ->
            AuthData;
        undefined ->
            extract_context_with(Rest, Token)
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

get_method_opts({_Method, _Opts} = MethodOpts) ->
    MethodOpts;
get_method_opts(Method) when is_atom(Method) ->
    {Method, #{}}.
