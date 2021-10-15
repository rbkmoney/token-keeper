-module(tk_authority).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").

%% API functions

-export([get_id/1]).
-export([get_authdata_id/1]).
-export([get_signer/1]).
-export([create_authdata/4]).
-export([get_authdata_by_token/3]).

%% API Types

-type authority() :: #{
    id := autority_id(),
    signer => tk_token_jwt:keyname(),
    authdata_sources := authdata_sources()
}.

-type authdata_sources() :: [tk_authdata_source:authdata_source()].

-type autority_id() :: binary().

-type authdata() :: #{
    id => authdata_id(),
    status := status(),
    context := encoded_context_fragment(),
    authority := autority_id(),
    metadata => metadata()
}.

-type authdata_id() :: binary().
-type status() :: active | revoked.
-type encoded_context_fragment() :: tk_context_thrift:'ContextFragment'().
-type metadata() :: #{binary() => binary()}.

-export_type([authority/0]).

-export_type([authdata/0]).
-export_type([authdata_id/0]).
-export_type([status/0]).
-export_type([encoded_context_fragment/0]).
-export_type([metadata/0]).
-export_type([autority_id/0]).

%% API Functions

-spec get_id(authority()) -> autority_id().
get_id(Authority) ->
    maps:get(id, Authority).

-spec get_authdata_id(authdata()) -> authdata_id().
get_authdata_id(AuthData) ->
    maps:get(id, AuthData).

-spec get_signer(authority()) -> tk_token_jwt:keyname().
get_signer(Authority) ->
    maps:get(signer, Authority).

-spec create_authdata(authdata_id() | undefined, encoded_context_fragment(), metadata(), authority()) -> authdata().
create_authdata(ID, ContextFragment, Metadata, Authority) ->
    AuthData = #{
        status => active,
        context => ContextFragment,
        metadata => Metadata
    },
    add_authority_id(add_id(AuthData, ID), Authority).

-spec get_authdata_by_token(tk_token_jwt:t(), authority(), tk_woody_handler:handle_ctx()) ->
    {ok, authdata()} | {error, {authdata_not_found, _Sources}}.
get_authdata_by_token(Token, Authority, Ctx) ->
    AuthDataSources = get_auth_data_sources(Authority),
    case get_authdata_from_sources(AuthDataSources, Token, Ctx) of
        #{} = AuthData ->
            {ok, maybe_add_authority_id(AuthData, Authority)};
        undefined ->
            {error, {authdata_not_found, AuthDataSources}}
    end.

%%-------------------------------------
%% private functions

-spec get_auth_data_sources(authority()) -> authdata_sources().
get_auth_data_sources(Authority) ->
    case maps:get(authdata_sources, Authority, undefined) of
        Sources when is_list(Sources) ->
            Sources;
        undefined ->
            throw({misconfiguration, {no_authdata_sources, Authority}})
    end.

get_authdata_from_sources([], _Token, _Ctx) ->
    undefined;
get_authdata_from_sources([SourceOpts | Rest], Token, Ctx) ->
    case tk_authdata_source:get_authdata(SourceOpts, Token, Ctx) of
        undefined ->
            get_authdata_from_sources(Rest, Token, Ctx);
        AuthData ->
            AuthData
    end.

maybe_add_authority_id(AuthData = #{authority := _}, _Authority) ->
    AuthData;
maybe_add_authority_id(AuthData, Authority) ->
    add_authority_id(AuthData, Authority).

add_id(AuthData, undefined) ->
    AuthData;
add_id(AuthData, ID) ->
    AuthData#{id => ID}.

add_authority_id(AuthData, Authority) when is_map(Authority) ->
    AuthData#{authority => maps:get(id, Authority)}.
