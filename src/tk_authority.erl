-module(tk_authority).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% API functions

-export([get_authdata_by_token/2]).

%% API Types

-type authority() :: #{
    id := autority_id(),
    authdata_sources := [tk_authdata_source:authdata_source()]
}.

-type authdata() :: #{
    id => id(),
    status := status(),
    context := encoded_context_fragment(),
    authority := autority_id(),
    metadata => metadata()
}.

-type id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type metadata() :: #{metadata_ns() => #{binary() => binary()}}.
-type metadata_ns() :: binary().
-type autority_id() :: binary().

-export_type([authority/0]).

-export_type([authdata/0]).
-export_type([id/0]).
-export_type([status/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).
-export_type([metadata_ns/0]).
-export_type([autority_id/0]).

%% API Functions

-spec get_authdata_by_token(tk_token_jwt:t(), authority()) ->
    {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
get_authdata_by_token(Token, Authority) ->
    AuthDataSources = get_auth_data_sources(Authority),
    case get_authdata_from_sources(AuthDataSources, Token) of
        AuthData when AuthData =/= undefined ->
            {ok, add_authority_id(AuthData, Authority)};
        undefined ->
            {error, {authdata_not_found, AuthDataSources}}
    end.

%%

get_auth_data_sources(Authority) ->
    case maps:get(authdata_sources, Authority, undefined) of
        Sources when Sources =/= undefined ->
            Sources;
        undefined ->
            throw({misconfiguration, {no_authdata_sources, Authority}})
    end.

get_authdata_from_sources([], _Token) ->
    undefined;
get_authdata_from_sources([SourceOpts | Rest], Token) ->
    case tk_authdata_source:get_authdata(SourceOpts, Token) of
        AuthData when AuthData =/= undefined ->
            AuthData;
        undefined ->
            get_authdata_from_sources(Rest, Token)
    end.

add_authority_id(AuthData, Authority) ->
    AuthData#{authority => maps:get(id, Authority)}.
