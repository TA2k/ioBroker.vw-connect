.class public abstract Llp/aa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;
    .locals 11

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getKeyStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    invoke-static {p0}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getGearStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-static {p0}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getObstacleStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-static {p0}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getStoppingReasonStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-static {p0}, Llp/fd;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->isParkingReversible()Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    invoke-static {p0}, Llp/fd;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PHighPrioMessageMEB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionStatusMEB;

    .line 55
    .line 56
    if-ne v0, v1, :cond_0

    .line 57
    .line 58
    const/4 v0, 0x1

    .line 59
    :goto_0
    move v7, v0

    .line 60
    goto :goto_1

    .line 61
    :cond_0
    const/4 v0, 0x0

    .line 62
    goto :goto_0

    .line 63
    :goto_1
    invoke-static {p0}, Llp/fd;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PNormalPrioManeuverInfoMessageMEB;->getParkingManeuverActiveStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 68
    .line 69
    .line 70
    move-result-object v8

    .line 71
    invoke-static {p0}, Llp/fd;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/C2PVehicleDataResponseMessageMEB;->isElectricalVehicle()Z

    .line 76
    .line 77
    .line 78
    move-result v9

    .line 79
    invoke-static {p0}, Llp/ed;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ls71/k;

    .line 80
    .line 81
    .line 82
    move-result-object v10

    .line 83
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 84
    .line 85
    invoke-direct/range {v1 .. v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;ZLs71/k;)V

    .line 86
    .line 87
    .line 88
    return-object v1
.end method

.method public static final b(Lur0/i;)Lyr0/e;
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "<this>"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v2, v1, Lur0/i;->b:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v3, v1, Lur0/i;->c:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v4, v1, Lur0/i;->d:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v5, v1, Lur0/i;->e:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v6, v1, Lur0/i;->f:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v0, v1, Lur0/i;->g:Ljava/lang/String;

    .line 19
    .line 20
    const-string v7, "Iso code doesn\'t match ISO 3166-1 Alpha-2"

    .line 21
    .line 22
    const-string v8, "toUpperCase(...)"

    .line 23
    .line 24
    const/4 v9, 0x2

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 28
    .line 29
    .line 30
    move-result v11

    .line 31
    if-ne v11, v9, :cond_0

    .line 32
    .line 33
    sget-object v11, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 34
    .line 35
    invoke-virtual {v0, v11}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    move-object v11, v0

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 45
    .line 46
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0

    .line 50
    :cond_1
    const/4 v11, 0x0

    .line 51
    :goto_0
    iget-object v0, v1, Lur0/i;->h:Ljava/lang/String;

    .line 52
    .line 53
    if-eqz v0, :cond_3

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 56
    .line 57
    .line 58
    move-result v12

    .line 59
    if-ne v12, v9, :cond_2

    .line 60
    .line 61
    sget-object v7, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 62
    .line 63
    invoke-virtual {v0, v7}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    move-object v8, v0

    .line 71
    goto :goto_1

    .line 72
    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 73
    .line 74
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0

    .line 78
    :cond_3
    const/4 v8, 0x0

    .line 79
    :goto_1
    iget-object v0, v1, Lur0/i;->i:Ljava/lang/String;

    .line 80
    .line 81
    if-eqz v0, :cond_5

    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 84
    .line 85
    .line 86
    move-result v7

    .line 87
    if-ne v7, v9, :cond_4

    .line 88
    .line 89
    sget-object v7, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 90
    .line 91
    invoke-virtual {v0, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    const-string v7, "toLowerCase(...)"

    .line 96
    .line 97
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    move-object v9, v0

    .line 101
    goto :goto_2

    .line 102
    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 103
    .line 104
    const-string v1, "Iso code doesn\'t match ISO 639-1 code"

    .line 105
    .line 106
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw v0

    .line 110
    :cond_5
    const/4 v9, 0x0

    .line 111
    :goto_2
    iget-object v7, v1, Lur0/i;->j:Ljava/time/LocalDate;

    .line 112
    .line 113
    move-object v12, v7

    .line 114
    move-object v7, v11

    .line 115
    iget-object v11, v1, Lur0/i;->k:Ljava/lang/String;

    .line 116
    .line 117
    iget-object v14, v1, Lur0/i;->n:Ljava/lang/String;

    .line 118
    .line 119
    if-eqz v14, :cond_6

    .line 120
    .line 121
    iget-object v15, v1, Lur0/i;->o:Ljava/lang/String;

    .line 122
    .line 123
    if-eqz v15, :cond_6

    .line 124
    .line 125
    new-instance v13, Lyr0/a;

    .line 126
    .line 127
    iget-object v0, v1, Lur0/i;->p:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v10, v1, Lur0/i;->q:Ljava/lang/String;

    .line 130
    .line 131
    move-object/from16 v16, v0

    .line 132
    .line 133
    iget-object v0, v1, Lur0/i;->r:Ljava/lang/String;

    .line 134
    .line 135
    move-object/from16 v18, v0

    .line 136
    .line 137
    move-object/from16 v17, v10

    .line 138
    .line 139
    invoke-direct/range {v13 .. v18}, Lyr0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_6
    const/4 v13, 0x0

    .line 144
    :goto_3
    iget-object v10, v1, Lur0/i;->l:Lyr0/c;

    .line 145
    .line 146
    iget-object v14, v1, Lur0/i;->m:Ljava/lang/String;

    .line 147
    .line 148
    iget-object v0, v1, Lur0/i;->s:Ljava/lang/String;

    .line 149
    .line 150
    if-eqz v0, :cond_a

    .line 151
    .line 152
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 153
    .line 154
    .line 155
    move-result v15

    .line 156
    if-lez v15, :cond_7

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_7
    const/4 v0, 0x0

    .line 160
    :goto_4
    if-eqz v0, :cond_a

    .line 161
    .line 162
    const-string v15, ","

    .line 163
    .line 164
    filled-new-array {v15}, [Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v15

    .line 168
    move-object/from16 v16, v2

    .line 169
    .line 170
    const/4 v2, 0x6

    .line 171
    invoke-static {v0, v15, v2}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    check-cast v0, Ljava/lang/Iterable;

    .line 176
    .line 177
    new-instance v2, Ljava/util/ArrayList;

    .line 178
    .line 179
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 180
    .line 181
    .line 182
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 183
    .line 184
    .line 185
    move-result-object v15

    .line 186
    :goto_5
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    if-eqz v0, :cond_9

    .line 191
    .line 192
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    check-cast v0, Ljava/lang/String;

    .line 197
    .line 198
    :try_start_0
    invoke-static {v0}, Lyr0/f;->valueOf(Ljava/lang/String;)Lyr0/f;

    .line 199
    .line 200
    .line 201
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 202
    move-object/from16 v17, v3

    .line 203
    .line 204
    move-object/from16 v18, v4

    .line 205
    .line 206
    const/4 v4, 0x0

    .line 207
    goto :goto_6

    .line 208
    :catch_0
    move-exception v0

    .line 209
    move-object/from16 v17, v3

    .line 210
    .line 211
    new-instance v3, Lgd0/b;

    .line 212
    .line 213
    move-object/from16 v18, v4

    .line 214
    .line 215
    const/4 v4, 0x2

    .line 216
    invoke-direct {v3, v4, v0}, Lgd0/b;-><init>(ILjava/lang/IllegalArgumentException;)V

    .line 217
    .line 218
    .line 219
    const/4 v4, 0x0

    .line 220
    invoke-static {v4, v1, v3}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 221
    .line 222
    .line 223
    move-object v0, v4

    .line 224
    :goto_6
    if-eqz v0, :cond_8

    .line 225
    .line 226
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    :cond_8
    move-object/from16 v3, v17

    .line 230
    .line 231
    move-object/from16 v4, v18

    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_9
    move-object/from16 v17, v3

    .line 235
    .line 236
    move-object/from16 v18, v4

    .line 237
    .line 238
    :goto_7
    move-object v15, v2

    .line 239
    goto :goto_8

    .line 240
    :cond_a
    move-object/from16 v16, v2

    .line 241
    .line 242
    move-object/from16 v17, v3

    .line 243
    .line 244
    move-object/from16 v18, v4

    .line 245
    .line 246
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 247
    .line 248
    goto :goto_7

    .line 249
    :goto_8
    new-instance v1, Lyr0/e;

    .line 250
    .line 251
    move-object v2, v13

    .line 252
    move-object v13, v10

    .line 253
    move-object v10, v12

    .line 254
    move-object v12, v2

    .line 255
    move-object/from16 v2, v16

    .line 256
    .line 257
    move-object/from16 v3, v17

    .line 258
    .line 259
    move-object/from16 v4, v18

    .line 260
    .line 261
    invoke-direct/range {v1 .. v15}, Lyr0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Ljava/lang/String;Lyr0/a;Lyr0/c;Ljava/lang/String;Ljava/util/List;)V

    .line 262
    .line 263
    .line 264
    return-object v1
.end method
