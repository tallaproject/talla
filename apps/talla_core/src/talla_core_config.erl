%%%
%%% Copyright (c) 2015 The Talla Authors. All rights reserved.
%%% Use of this source code is governed by a BSD-style
%%% license that can be found in the LICENSE file.
%%%
%%% -----------------------------------------------------------
%%% @author Alexander Færøy <ahf@0x90.dk>
%%% @doc Talla Core Config API.
%%% @end
%%% -----------------------------------------------------------
-module(talla_core_config).

%% API.
-export([data_dir/0,
         authorities/0
        ]).

%% @doc Get data directory.
-spec data_dir() -> file:filename().
data_dir() ->
    onion_file:expand_tilde(onion_config:get_string(talla_core, data_dir, "~/.talla")).

%% @doc Get the default authorities.
-spec authorities() -> [term()].
authorities() ->
    case onion_config:get_value(talla_core, authorities) of
        not_found ->
            default_authorities();

        Value when is_list(Value) ->
            Path = onion_file:expand_tilde(Value),
            case filelib:is_file(Path) of
                true ->
                    {ok, Data} = file:consult(Path),
                    Data;

                false ->
                    %% We assume the user added valid authorities to the config.
                    Value
            end
    end.

%% @private
-spec default_authorities() -> [term()].
default_authorities() ->
    [
        #{ nickname    => "moria1",
           or_port     => 9101,
           v3_identity => "D586D18309DED4CD6D57C18FDB97EFA96D330566",
           address     => {128, 31, 0, 39},
           dir_port    => 9131,
           fingerprint => "9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31"
         },
        #{ nickname    => "tor26",
           or_port     => 443,
           v3_identity => "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4",
           address     => {86, 59, 21, 38},
           dir_port    => 80,
           fingerprint => "847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D"
         },
        #{ nickname    => "dizum",
           or_port     => 443,
           v3_identity => "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
           address     => {194, 109, 206, 212},
           dir_port    => 80,
           fingerprint => "7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755"
         },
        #{ nickname    => "Tonga",
           or_port     => 443,
           address     => {82, 94, 251, 203},
           dir_port    => 80,
           fingerprint => "4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D"
         }
        #{ nickname    => "gabelmoo",
           or_port     => 443,
           v3_identity => "ED03BB616EB2F60BEC80151114BB25CEF515B226",
           address     => {131, 188, 40, 189},
           dir_port    => 80,
           fingerprint => "F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281"
         },
        #{ nickname    => "dannenberg",
           or_port     => 443,
           v3_identity => "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
           address     => {193, 23, 244, 244},
           dir_port    => 80,
           fingerprint => "7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123"
         },
        #{ nickname    => "urras",
           or_port     => 80,
           v3_identity => "80550987E1D626E3EBA5E5E75A458DE0626D088C",
           address     => {208, 83, 223, 34},
           dir_port    => 443,
           fingerprint =>  "0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417"
         },
        #{ nickname    => "maatuska",
           or_port     => 80,
           v3_identity => "49015F787433103580E3B66A1707A00E60F2D15B",
           address     => {171, 25, 193, 9},
           dir_port    => 443,
           fingerprint => "BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810"
         },
        #{ nickname    => "Faravahar",
           or_port     => 443,
           v3_identity => "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97",
           address     => {154, 35, 175, 225},
           dir_port    => 80,
           fingerprint => "CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC"
         },
        #{ nickname    => "longclaw",
           or_port     => 443,
           v3_identity => "23D15D965BC35114467363C165C4F724B64B4F66",
           address     => {199, 254, 238, 52},
           dir_port    => 80,
           fingerprint => "74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145"
         }
    ].

