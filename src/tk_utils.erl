-module(tk_utils).

-export([remap/2]).

-spec remap(Map :: map(), KeyMap :: map()) -> map().
remap(Map, KeyMap) ->
    maps:fold(
        fun(Key, Value, Acc) ->
            case maps:get(Key, KeyMap, undefined) of
                NewKey when NewKey =/= undefined ->
                    Acc#{NewKey => Value};
                undefined ->
                    error({badarg, {no_mapping, Key}})
            end
        end,
        maps:new(),
        Map
    ).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec remap_test() -> _.
remap_test() ->
    ?assertEqual(
        #{
            <<"a">> => a,
            <<"b">> => b,
            <<"c">> => c
        },
        remap(
            #{
                a => a,
                b => b,
                c => c
            },
            #{
                a => <<"a">>,
                b => <<"b">>,
                c => <<"c">>
            }
        )
    ).

-spec remap_no_mapping_test() -> _.
remap_no_mapping_test() ->
    ?assertError(
        {badarg, {no_mapping, c}},
        remap(
            #{
                a => a,
                b => b,
                c => c
            },
            #{
                a => <<"a">>,
                b => <<"b">>
            }
        )
    ).

-endif.
