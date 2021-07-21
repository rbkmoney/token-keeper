-module(tk_extractor_user_session_token).
-behaviour(tk_extractor).

-export([get_context/2]).

%%

-type extractor_opts() :: #{
    metadata_ns := binary(),
    user_realm := binary()
}.

-export_type([extractor_opts/0]).

%% API functions

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_extractor:extracted_context().
get_context(Token, ExtractorOpts) ->
    UserID = tk_token_jwt:get_subject_id(Token),
    Email = tk_token_jwt:get_subject_email(Token),
    Expiration = tk_token_jwt:get_expires_at(Token),
    UserRealm = maps:get(user_realm, ExtractorOpts, undefined),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_user(
        #{
            id => UserID,
            email => Email,
            realm => #{id => UserRealm}
        },
        Acc0
    ),
    Acc2 = bouncer_context_helpers:add_auth(
        #{
            method => <<"SessionToken">>,
            expiration => make_auth_expiration(Expiration),
            token => #{id => tk_token_jwt:get_token_id(Token)}
        },
        Acc1
    ),
    {Acc2,
        wrap_metadata(
            genlib_map:compact(#{
                <<"user_id">> => UserID,
                <<"user_email">> => Email,
                <<"user_realm">> => UserRealm
            }),
            ExtractorOpts
        )}.

%% Internal functions

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

wrap_metadata(Metadata, ExtractorOpts) ->
    MetadataNS = maps:get(metadata_ns, ExtractorOpts),
    #{MetadataNS => Metadata}.
