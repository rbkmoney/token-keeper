-module(tk_extractor_user_session_token).
-behaviour(tk_context_extractor).

-export([get_context/2]).

%% API functions

-spec get_context(tk_token_jwt:t(), tk_context_extractor:extractor_opts()) -> tk_context_extractor:extracted_context().
get_context(Token, ExtractorOpts) ->
    UserID = tk_token_jwt:get_subject_id(Token),
    Expiration = tk_token_jwt:get_expires_at(Token),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_user(
        #{
            id => UserID,
            email => tk_token_jwt:get_subject_email(Token),
            realm => #{id => maps:get(user_realm, ExtractorOpts, undefined)}
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
    {Acc2, undefined}.

%% Internal functions

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.