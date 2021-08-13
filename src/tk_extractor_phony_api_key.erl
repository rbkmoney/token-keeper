-module(tk_extractor_phony_api_key).
-behaviour(tk_extractor).

-export([get_context/2]).

%%

-type extractor_opts() :: #{
    metadata_mappings := #{
        party_id := binary()
    }
}.

-export_type([extractor_opts/0]).

%% API functions

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_extractor:extracted_context().
get_context(Token, ExtractorOpts) ->
    PartyID = tk_token_jwt:get_subject_id(Token),
    Acc0 = bouncer_context_helpers:empty(),
    Acc1 = bouncer_context_helpers:add_auth(
        #{
            method => <<"ApiKeyToken">>,
            token => #{id => tk_token_jwt:get_token_id(Token)},
            scope => [#{party => #{id => PartyID}}]
        },
        Acc0
    ),
    {Acc1,
        make_metadata(
            #{
                party_id => PartyID
            },
            ExtractorOpts
        )}.

%%

make_metadata(Metadata, ExtractorOpts) ->
    Mappings = maps:get(metadata_mappings, ExtractorOpts),
    tk_utils:remap(genlib_map:compact(Metadata), Mappings).
