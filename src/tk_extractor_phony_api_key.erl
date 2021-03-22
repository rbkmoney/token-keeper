-module(tk_extractor_phony_api_key).
-behaviour(tk_context_extractor).

-export([get_context/2]).

%% API functions

-spec get_context(tk_token_jwt:t(), tk_context_extractor:extractor_opts()) -> tk_context_extractor:extracted_context().
get_context(Token, _ExtractorOpts) ->
    UserID = tk_token_jwt:get_subject_id(Token),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_auth(
        #{
            method => <<"ApiKeyToken">>,
            token => #{id => tk_token_jwt:get_token_id(Token)},
            scope => [#{party => #{id => UserID}}]
        },
        Acc0
    ),
    {Acc1, #{<<"party_id">> => UserID}}.
