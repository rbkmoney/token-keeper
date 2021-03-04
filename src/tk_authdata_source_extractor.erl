-module(tk_authdata_source_extractor).
-behaviour(tk_authdata_source).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% Behaviour

-export([get_authdata/2]).

%% Behaviour functions

-spec get_authdata(tk_token_jwt:t(), tk_authdata_source:source_opts()) -> tk_authdata:authdata() | undefined.
get_authdata(Token, Opts) ->
    Methods = get_extractor_methods(Opts),
    case extract_context_with(Methods, Token) of
        {Context, Metadata} ->
            make_auth_data(Context, Metadata, Opts);
        undefined ->
            undefined
    end.

%%

get_extractor_methods(Opts) ->
    Methods = maps:get(methods, Opts),
    ExtractorOpts = maps:get(extractor_opts, Opts),
    lists:map(
        fun
            ({Mod, ExtractorOpts0}) -> {Mod, maps:merge(ExtractorOpts0, ExtractorOpts)};
            (Mod) when is_atom(Mod) -> {Mod, ExtractorOpts}
        end,
        Methods
    ).

extract_context_with([], _Token) ->
    undefined;
extract_context_with([{Method, Opts} | Rest], Token) ->
    case tk_context_extractor:get_context(Method, Token, Opts) of
        AuthData when AuthData =/= undefined ->
            AuthData;
        undefined ->
            extract_context_with(Rest, Token)
    end.

make_auth_data(ContextFragment, Metadata, SourceOpts) ->
    genlib_map:compact(#{
        status => active,
        context => encode_context_fragment(ContextFragment),
        metadata => wrap_metadata(Metadata, SourceOpts),
        authority => get_authority(SourceOpts)
    }).

wrap_metadata(undefined, _SourceOpts) ->
    undefined;
wrap_metadata(Metadata, SourceOpts) ->
    MetadataNS = maps:get(metadata_ns, SourceOpts),
    #{MetadataNS => Metadata}.

encode_context_fragment({encoded_context_fragment, ContextFragment}) ->
    ContextFragment;
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

get_authority(SourceOpts) ->
    maps:get(authority, SourceOpts).
