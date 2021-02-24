-module(tk_authdata).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% API functions

-export([from_token/2]).

%% API Types

-type authdata() :: #{
    id => id(),
    token => binary(),
    status := status(),
    context := encoded_context_fragment(),
    authority := authority(),
    metadata => metadata()
}.

-type id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type metadata() :: #{metadata_ns() => #{binary() => binary()}}.
-type metadata_ns() :: binary().
-type authority() :: binary().

-export_type([authdata/0]).

-export_type([id/0]).
-export_type([status/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).
-export_type([metadata_ns/0]).
-export_type([authority/0]).

%% API Functions

-spec from_token(tk_token_jwt:t(), tk_authdata_source:source_opts()) ->
    {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
from_token(Token, Opts) ->
    TokenType = get_token_type(Token),
    AuthDataSources = get_auth_data_sources(TokenType, Opts),
    case get_authdata_from_sources(AuthDataSources, Token) of
        AuthData when AuthData =/= undefined ->
            {ok, AuthData};
        undefined ->
            {error, {authdata_not_found, AuthDataSources}}
    end.

%%

get_token_type(Token) ->
    Metadata = tk_token_jwt:get_metadata(Token),
    maps:get(type, Metadata).

get_auth_data_sources(TokenType, Opts) ->
    SourceConfig = application:get_env(token_keeper, authdata_sources, #{}),
    case maps:get(TokenType, SourceConfig, undefined) of
        Sources when Sources =/= undefined ->
            merge_source_opts(Sources, Opts);
        undefined ->
            throw({misconfiguration, {no_authdata_source, TokenType}})
    end.

merge_source_opts(AuthDataSources, Opts) ->
    lists:map(
        fun
            ({Mod, SourceOpts}) -> {Mod, maps:merge(SourceOpts, Opts)};
            (Mod) when is_atom(Mod) -> {Mod, Opts}
        end,
        AuthDataSources
    ).

get_authdata_from_sources([], _Token) ->
    undefined;
get_authdata_from_sources([{Source, Opts} | Rest], Token) ->
    case tk_authdata_source:get_authdata(Source, Token, Opts) of
        AuthData when AuthData =/= undefined ->
            AuthData;
        undefined ->
            get_authdata_from_sources(Rest, Token)
    end.
