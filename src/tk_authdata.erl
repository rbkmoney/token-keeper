-module(tk_authdata).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% API functions

-export([from_token/1]).

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

-spec from_token(tk_token_jwt:t()) -> {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
from_token(Token) ->
    Authority = get_token_authority(Token),
    AuthDataSources = get_auth_data_sources(Authority),
    case get_authdata_from_sources(AuthDataSources, Token) of
        AuthData when AuthData =/= undefined ->
            {ok, AuthData};
        undefined ->
            {error, {authdata_not_found, AuthDataSources}}
    end.

%%

get_token_authority(Token) ->
    Metadata = tk_token_jwt:get_metadata(Token),
    maps:get(authority, Metadata).

get_auth_data_sources(Authority) ->
    AuthorityConfig = get_authority_config(Authority),
    case maps:get(authdata_sources, AuthorityConfig, undefined) of
        Sources when Sources =/= undefined ->
            Sources;
        undefined ->
            throw({misconfiguration, {no_authdata_sources, Authority}})
    end.

get_authority_config(Authority) ->
    Authorities = application:get_env(token_keeper, authorities, #{}),
    case maps:get(Authority, Authorities, undefined) of
        Config when Config =/= undefined ->
            Config;
        undefined ->
            throw({misconfiguration, {no_such_authority, Authority}})
    end.

get_authdata_from_sources([], _Token) ->
    undefined;
get_authdata_from_sources([SourceOpts | Rest], Token) ->
    {Source, Opts} = get_source_opts(SourceOpts),
    case tk_authdata_source:get_authdata(Source, Token, Opts) of
        AuthData when AuthData =/= undefined ->
            AuthData;
        undefined ->
            get_authdata_from_sources(Rest, Token)
    end.

get_source_opts({_Source, _Opts} = SourceOpts) ->
    SourceOpts;
get_source_opts(Source) when is_atom(Source) ->
    {Source, #{}}.
