.class public abstract synthetic Ly81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I

.field public static final synthetic b:[I

.field public static final synthetic c:[I

.field public static final synthetic d:[I

.field public static final synthetic e:[I


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    :try_start_0
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    :catch_0
    const/4 v2, 0x2

    .line 18
    :try_start_1
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->MALFUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    aput v2, v0, v3
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 25
    .line 26
    :catch_1
    const/4 v3, 0x3

    .line 27
    :try_start_2
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->FUNCTION_NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 28
    .line 29
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    aput v3, v0, v4
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 34
    .line 35
    :catch_2
    const/4 v4, 0x4

    .line 36
    :try_start_3
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->DOORS_AND_FLAPS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 37
    .line 38
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    aput v4, v0, v5
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 43
    .line 44
    :catch_3
    const/4 v5, 0x5

    .line 45
    :try_start_4
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TRAFFIC_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 46
    .line 47
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    aput v5, v0, v6
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 52
    .line 53
    :catch_4
    const/4 v6, 0x6

    .line 54
    :try_start_5
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->INTERACTION_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 55
    .line 56
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    aput v6, v0, v7
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 61
    .line 62
    :catch_5
    const/4 v7, 0x7

    .line 63
    :try_start_6
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->INTRUSION_VEHICLE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 64
    .line 65
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    aput v7, v0, v8
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 70
    .line 71
    :catch_6
    const/16 v8, 0x8

    .line 72
    .line 73
    :try_start_7
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TIMEOUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 74
    .line 75
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 76
    .line 77
    .line 78
    move-result v9

    .line 79
    aput v8, v0, v9
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 80
    .line 81
    :catch_7
    const/16 v9, 0x9

    .line 82
    .line 83
    :try_start_8
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_CONTINUATION_OF_THE_JOURNEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 84
    .line 85
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 86
    .line 87
    .line 88
    move-result v10

    .line 89
    aput v9, v0, v10
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 90
    .line 91
    :catch_8
    const/16 v10, 0xa

    .line 92
    .line 93
    :try_start_9
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->CHARGING_PLUG_PLUGGED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 94
    .line 95
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 96
    .line 97
    .line 98
    move-result v11

    .line 99
    aput v10, v0, v11
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 100
    .line 101
    :catch_9
    const/16 v11, 0xb

    .line 102
    .line 103
    :try_start_a
    sget-object v12, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->RECEPTION_OBSTRUCTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 104
    .line 105
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 106
    .line 107
    .line 108
    move-result v12

    .line 109
    aput v11, v0, v12
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 110
    .line 111
    :catch_a
    const/16 v12, 0xc

    .line 112
    .line 113
    :try_start_b
    sget-object v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->CHARGE_LEVEL_LOW:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 114
    .line 115
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 116
    .line 117
    .line 118
    move-result v13

    .line 119
    aput v12, v0, v13
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 120
    .line 121
    :catch_b
    const/16 v13, 0xd

    .line 122
    .line 123
    :try_start_c
    sget-object v14, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->COUNTRY_NOT_ALLOWED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 124
    .line 125
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 126
    .line 127
    .line 128
    move-result v14

    .line 129
    aput v13, v0, v14
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 130
    .line 131
    :catch_c
    const/16 v14, 0xe

    .line 132
    .line 133
    :try_start_d
    sget-object v15, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->KEY_SWITCH_OPERATED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 134
    .line 135
    invoke-virtual {v15}, Ljava/lang/Enum;->ordinal()I

    .line 136
    .line 137
    .line 138
    move-result v15

    .line 139
    aput v14, v0, v15
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 140
    .line 141
    :catch_d
    const/16 v15, 0xf

    .line 142
    .line 143
    :try_start_e
    sget-object v16, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->ROUTE_NOT_TRAINED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 144
    .line 145
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Enum;->ordinal()I

    .line 146
    .line 147
    .line 148
    move-result v16

    .line 149
    aput v15, v0, v16
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 150
    .line 151
    :catch_e
    const/16 v16, 0x10

    .line 152
    .line 153
    :try_start_f
    sget-object v17, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->GARAGE_DOOR_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 154
    .line 155
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Enum;->ordinal()I

    .line 156
    .line 157
    .line 158
    move-result v17

    .line 159
    aput v16, v0, v17
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 160
    .line 161
    :catch_f
    const/16 v17, 0x11

    .line 162
    .line 163
    :try_start_10
    sget-object v18, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->KEY_INSIDE_INTERIOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 164
    .line 165
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Enum;->ordinal()I

    .line 166
    .line 167
    .line 168
    move-result v18

    .line 169
    aput v17, v0, v18
    :try_end_10
    .catch Ljava/lang/NoSuchFieldError; {:try_start_10 .. :try_end_10} :catch_10

    .line 170
    .line 171
    :catch_10
    const/16 v18, 0x12

    .line 172
    .line 173
    :try_start_11
    sget-object v19, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->MULTIPLE_KEYS_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 174
    .line 175
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Enum;->ordinal()I

    .line 176
    .line 177
    .line 178
    move-result v19

    .line 179
    aput v18, v0, v19
    :try_end_11
    .catch Ljava/lang/NoSuchFieldError; {:try_start_11 .. :try_end_11} :catch_11

    .line 180
    .line 181
    :catch_11
    const/16 v19, 0x13

    .line 182
    .line 183
    :try_start_12
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->OFF_ROAD_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 184
    .line 185
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 186
    .line 187
    .line 188
    move-result v20

    .line 189
    aput v19, v0, v20
    :try_end_12
    .catch Ljava/lang/NoSuchFieldError; {:try_start_12 .. :try_end_12} :catch_12

    .line 190
    .line 191
    :catch_12
    :try_start_13
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->AIR_SUSPENSION_HEIGHT_NIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 192
    .line 193
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 194
    .line 195
    .line 196
    move-result v20

    .line 197
    const/16 v21, 0x14

    .line 198
    .line 199
    aput v21, v0, v20
    :try_end_13
    .catch Ljava/lang/NoSuchFieldError; {:try_start_13 .. :try_end_13} :catch_13

    .line 200
    .line 201
    :catch_13
    :try_start_14
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->MAX_DISTANCE_REACHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 202
    .line 203
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 204
    .line 205
    .line 206
    move-result v20

    .line 207
    const/16 v21, 0x15

    .line 208
    .line 209
    aput v21, v0, v20
    :try_end_14
    .catch Ljava/lang/NoSuchFieldError; {:try_start_14 .. :try_end_14} :catch_14

    .line 210
    .line 211
    :catch_14
    :try_start_15
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->SHUNTING_AREA_TOO_SMALL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 212
    .line 213
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 214
    .line 215
    .line 216
    move-result v20

    .line 217
    const/16 v21, 0x16

    .line 218
    .line 219
    aput v21, v0, v20
    :try_end_15
    .catch Ljava/lang/NoSuchFieldError; {:try_start_15 .. :try_end_15} :catch_15

    .line 220
    .line 221
    :catch_15
    :try_start_16
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TERMINATION_BY_GWSM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 222
    .line 223
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 224
    .line 225
    .line 226
    move-result v20

    .line 227
    const/16 v21, 0x17

    .line 228
    .line 229
    aput v21, v0, v20
    :try_end_16
    .catch Ljava/lang/NoSuchFieldError; {:try_start_16 .. :try_end_16} :catch_16

    .line 230
    .line 231
    :catch_16
    :try_start_17
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->MAX_MOVES_REACHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 232
    .line 233
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 234
    .line 235
    .line 236
    move-result v20

    .line 237
    const/16 v21, 0x18

    .line 238
    .line 239
    aput v21, v0, v20
    :try_end_17
    .catch Ljava/lang/NoSuchFieldError; {:try_start_17 .. :try_end_17} :catch_17

    .line 240
    .line 241
    :catch_17
    :try_start_18
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->PARKING_SPACE_TOO_SMALL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 242
    .line 243
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 244
    .line 245
    .line 246
    move-result v20

    .line 247
    const/16 v21, 0x19

    .line 248
    .line 249
    aput v21, v0, v20
    :try_end_18
    .catch Ljava/lang/NoSuchFieldError; {:try_start_18 .. :try_end_18} :catch_18

    .line 250
    .line 251
    :catch_18
    :try_start_19
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 252
    .line 253
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 254
    .line 255
    .line 256
    move-result v20

    .line 257
    const/16 v21, 0x1a

    .line 258
    .line 259
    aput v21, v0, v20
    :try_end_19
    .catch Ljava/lang/NoSuchFieldError; {:try_start_19 .. :try_end_19} :catch_19

    .line 260
    .line 261
    :catch_19
    :try_start_1a
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 262
    .line 263
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 264
    .line 265
    .line 266
    move-result v20

    .line 267
    const/16 v21, 0x1b

    .line 268
    .line 269
    aput v21, v0, v20
    :try_end_1a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1a .. :try_end_1a} :catch_1a

    .line 270
    .line 271
    :catch_1a
    :try_start_1b
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TRAILER_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 272
    .line 273
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 274
    .line 275
    .line 276
    move-result v20

    .line 277
    const/16 v21, 0x1c

    .line 278
    .line 279
    aput v21, v0, v20
    :try_end_1b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1b .. :try_end_1b} :catch_1b

    .line 280
    .line 281
    :catch_1b
    :try_start_1c
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TERMINATION_ESC_INTERVENTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 282
    .line 283
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 284
    .line 285
    .line 286
    move-result v20

    .line 287
    const/16 v21, 0x1d

    .line 288
    .line 289
    aput v21, v0, v20
    :try_end_1c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1c .. :try_end_1c} :catch_1c

    .line 290
    .line 291
    :catch_1c
    :try_start_1d
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->PP_ERROR_KEY_AUTHORIZER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 292
    .line 293
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 294
    .line 295
    .line 296
    move-result v20

    .line 297
    const/16 v21, 0x1e

    .line 298
    .line 299
    aput v21, v0, v20
    :try_end_1d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1d .. :try_end_1d} :catch_1d

    .line 300
    .line 301
    :catch_1d
    :try_start_1e
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->PP_LOSS_POS_OK:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 302
    .line 303
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 304
    .line 305
    .line 306
    move-result v20

    .line 307
    const/16 v21, 0x1f

    .line 308
    .line 309
    aput v21, v0, v20
    :try_end_1e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1e .. :try_end_1e} :catch_1e

    .line 310
    .line 311
    :catch_1e
    :try_start_1f
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TERMINATION_TSK_GRADIENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 312
    .line 313
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 314
    .line 315
    .line 316
    move-result v20

    .line 317
    const/16 v21, 0x20

    .line 318
    .line 319
    aput v21, v0, v20
    :try_end_1f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1f .. :try_end_1f} :catch_1f

    .line 320
    .line 321
    :catch_1f
    :try_start_20
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->STANDBY_INCREASED_DRIVING_RESISTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 322
    .line 323
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 324
    .line 325
    .line 326
    move-result v20

    .line 327
    const/16 v21, 0x21

    .line 328
    .line 329
    aput v21, v0, v20
    :try_end_20
    .catch Ljava/lang/NoSuchFieldError; {:try_start_20 .. :try_end_20} :catch_20

    .line 330
    .line 331
    :catch_20
    :try_start_21
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->TERMINATION_INCREASED_DRIVING_RESISTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 332
    .line 333
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 334
    .line 335
    .line 336
    move-result v20

    .line 337
    const/16 v21, 0x22

    .line 338
    .line 339
    aput v21, v0, v20
    :try_end_21
    .catch Ljava/lang/NoSuchFieldError; {:try_start_21 .. :try_end_21} :catch_21

    .line 340
    .line 341
    :catch_21
    :try_start_22
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->KAB_VOKO_VKM_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 342
    .line 343
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 344
    .line 345
    .line 346
    move-result v20

    .line 347
    const/16 v21, 0x23

    .line 348
    .line 349
    aput v21, v0, v20
    :try_end_22
    .catch Ljava/lang/NoSuchFieldError; {:try_start_22 .. :try_end_22} :catch_22

    .line 350
    .line 351
    :catch_22
    :try_start_23
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->KAB_VOKO_VKM_ON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 352
    .line 353
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 354
    .line 355
    .line 356
    move-result v20

    .line 357
    const/16 v21, 0x24

    .line 358
    .line 359
    aput v21, v0, v20
    :try_end_23
    .catch Ljava/lang/NoSuchFieldError; {:try_start_23 .. :try_end_23} :catch_23

    .line 360
    .line 361
    :catch_23
    sput-object v0, Ly81/a;->a:[I

    .line 362
    .line 363
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 364
    .line 365
    .line 366
    move-result-object v0

    .line 367
    array-length v0, v0

    .line 368
    new-array v0, v0, [I

    .line 369
    .line 370
    :try_start_24
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 371
    .line 372
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 373
    .line 374
    .line 375
    move-result v20

    .line 376
    aput v1, v0, v20
    :try_end_24
    .catch Ljava/lang/NoSuchFieldError; {:try_start_24 .. :try_end_24} :catch_24

    .line 377
    .line 378
    :catch_24
    :try_start_25
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 379
    .line 380
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 381
    .line 382
    .line 383
    move-result v20

    .line 384
    aput v2, v0, v20
    :try_end_25
    .catch Ljava/lang/NoSuchFieldError; {:try_start_25 .. :try_end_25} :catch_25

    .line 385
    .line 386
    :catch_25
    :try_start_26
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_LEAVING_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 387
    .line 388
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 389
    .line 390
    .line 391
    move-result v20

    .line 392
    aput v3, v0, v20
    :try_end_26
    .catch Ljava/lang/NoSuchFieldError; {:try_start_26 .. :try_end_26} :catch_26

    .line 393
    .line 394
    :catch_26
    :try_start_27
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 395
    .line 396
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 397
    .line 398
    .line 399
    move-result v20

    .line 400
    aput v4, v0, v20
    :try_end_27
    .catch Ljava/lang/NoSuchFieldError; {:try_start_27 .. :try_end_27} :catch_27

    .line 401
    .line 402
    :catch_27
    :try_start_28
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 403
    .line 404
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 405
    .line 406
    .line 407
    move-result v20

    .line 408
    aput v5, v0, v20
    :try_end_28
    .catch Ljava/lang/NoSuchFieldError; {:try_start_28 .. :try_end_28} :catch_28

    .line 409
    .line 410
    :catch_28
    :try_start_29
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_INSIDE_CAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 411
    .line 412
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 413
    .line 414
    .line 415
    move-result v20

    .line 416
    aput v6, v0, v20
    :try_end_29
    .catch Ljava/lang/NoSuchFieldError; {:try_start_29 .. :try_end_29} :catch_29

    .line 417
    .line 418
    :catch_29
    :try_start_2a
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->MULTIPLE_CAR_KEYS_FOUND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 419
    .line 420
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 421
    .line 422
    .line 423
    move-result v20

    .line 424
    aput v7, v0, v20
    :try_end_2a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2a .. :try_end_2a} :catch_2a

    .line 425
    .line 426
    :catch_2a
    sput-object v0, Ly81/a;->b:[I

    .line 427
    .line 428
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    array-length v0, v0

    .line 433
    new-array v0, v0, [I

    .line 434
    .line 435
    :try_start_2b
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 436
    .line 437
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 438
    .line 439
    .line 440
    move-result v20

    .line 441
    aput v1, v0, v20
    :try_end_2b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2b .. :try_end_2b} :catch_2b

    .line 442
    .line 443
    :catch_2b
    :try_start_2c
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 444
    .line 445
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 446
    .line 447
    .line 448
    move-result v20

    .line 449
    aput v2, v0, v20
    :try_end_2c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2c .. :try_end_2c} :catch_2c

    .line 450
    .line 451
    :catch_2c
    :try_start_2d
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 452
    .line 453
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 454
    .line 455
    .line 456
    move-result v20

    .line 457
    aput v3, v0, v20
    :try_end_2d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2d .. :try_end_2d} :catch_2d

    .line 458
    .line 459
    :catch_2d
    :try_start_2e
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 460
    .line 461
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 462
    .line 463
    .line 464
    move-result v20

    .line 465
    aput v4, v0, v20
    :try_end_2e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2e .. :try_end_2e} :catch_2e

    .line 466
    .line 467
    :catch_2e
    :try_start_2f
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 468
    .line 469
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 470
    .line 471
    .line 472
    move-result v20

    .line 473
    aput v5, v0, v20
    :try_end_2f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2f .. :try_end_2f} :catch_2f

    .line 474
    .line 475
    :catch_2f
    :try_start_30
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 476
    .line 477
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 478
    .line 479
    .line 480
    move-result v20

    .line 481
    aput v6, v0, v20
    :try_end_30
    .catch Ljava/lang/NoSuchFieldError; {:try_start_30 .. :try_end_30} :catch_30

    .line 482
    .line 483
    :catch_30
    :try_start_31
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 484
    .line 485
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 486
    .line 487
    .line 488
    move-result v20

    .line 489
    aput v7, v0, v20
    :try_end_31
    .catch Ljava/lang/NoSuchFieldError; {:try_start_31 .. :try_end_31} :catch_31

    .line 490
    .line 491
    :catch_31
    :try_start_32
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->AAA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 492
    .line 493
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 494
    .line 495
    .line 496
    move-result v20

    .line 497
    aput v8, v0, v20
    :try_end_32
    .catch Ljava/lang/NoSuchFieldError; {:try_start_32 .. :try_end_32} :catch_32

    .line 498
    .line 499
    :catch_32
    sput-object v0, Ly81/a;->c:[I

    .line 500
    .line 501
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 502
    .line 503
    .line 504
    move-result-object v0

    .line 505
    array-length v0, v0

    .line 506
    new-array v0, v0, [I

    .line 507
    .line 508
    :try_start_33
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 509
    .line 510
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 511
    .line 512
    .line 513
    move-result v20

    .line 514
    aput v1, v0, v20
    :try_end_33
    .catch Ljava/lang/NoSuchFieldError; {:try_start_33 .. :try_end_33} :catch_33

    .line 515
    .line 516
    :catch_33
    :try_start_34
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->TRAINED_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 517
    .line 518
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 519
    .line 520
    .line 521
    move-result v20

    .line 522
    aput v2, v0, v20
    :try_end_34
    .catch Ljava/lang/NoSuchFieldError; {:try_start_34 .. :try_end_34} :catch_34

    .line 523
    .line 524
    :catch_34
    :try_start_35
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->TRAINED_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 525
    .line 526
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 527
    .line 528
    .line 529
    move-result v20

    .line 530
    aput v3, v0, v20
    :try_end_35
    .catch Ljava/lang/NoSuchFieldError; {:try_start_35 .. :try_end_35} :catch_35

    .line 531
    .line 532
    :catch_35
    :try_start_36
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 533
    .line 534
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 535
    .line 536
    .line 537
    move-result v20

    .line 538
    aput v4, v0, v20
    :try_end_36
    .catch Ljava/lang/NoSuchFieldError; {:try_start_36 .. :try_end_36} :catch_36

    .line 539
    .line 540
    :catch_36
    :try_start_37
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 541
    .line 542
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 543
    .line 544
    .line 545
    move-result v20

    .line 546
    aput v5, v0, v20
    :try_end_37
    .catch Ljava/lang/NoSuchFieldError; {:try_start_37 .. :try_end_37} :catch_37

    .line 547
    .line 548
    :catch_37
    :try_start_38
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 549
    .line 550
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 551
    .line 552
    .line 553
    move-result v20

    .line 554
    aput v6, v0, v20
    :try_end_38
    .catch Ljava/lang/NoSuchFieldError; {:try_start_38 .. :try_end_38} :catch_38

    .line 555
    .line 556
    :catch_38
    :try_start_39
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 557
    .line 558
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 559
    .line 560
    .line 561
    move-result v20

    .line 562
    aput v7, v0, v20
    :try_end_39
    .catch Ljava/lang/NoSuchFieldError; {:try_start_39 .. :try_end_39} :catch_39

    .line 563
    .line 564
    :catch_39
    :try_start_3a
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 565
    .line 566
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 567
    .line 568
    .line 569
    move-result v20

    .line 570
    aput v8, v0, v20
    :try_end_3a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3a .. :try_end_3a} :catch_3a

    .line 571
    .line 572
    :catch_3a
    :try_start_3b
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 573
    .line 574
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 575
    .line 576
    .line 577
    move-result v20

    .line 578
    aput v9, v0, v20
    :try_end_3b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3b .. :try_end_3b} :catch_3b

    .line 579
    .line 580
    :catch_3b
    :try_start_3c
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->STRAIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 581
    .line 582
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 583
    .line 584
    .line 585
    move-result v20

    .line 586
    aput v10, v0, v20
    :try_end_3c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3c .. :try_end_3c} :catch_3c

    .line 587
    .line 588
    :catch_3c
    :try_start_3d
    sget-object v20, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->STRAIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 589
    .line 590
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Enum;->ordinal()I

    .line 591
    .line 592
    .line 593
    move-result v20

    .line 594
    aput v11, v0, v20
    :try_end_3d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3d .. :try_end_3d} :catch_3d

    .line 595
    .line 596
    :catch_3d
    :try_start_3e
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->STRAIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 597
    .line 598
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 599
    .line 600
    .line 601
    move-result v11

    .line 602
    aput v12, v0, v11
    :try_end_3e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3e .. :try_end_3e} :catch_3e

    .line 603
    .line 604
    :catch_3e
    :try_start_3f
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->STRAIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 605
    .line 606
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 607
    .line 608
    .line 609
    move-result v11

    .line 610
    aput v13, v0, v11
    :try_end_3f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3f .. :try_end_3f} :catch_3f

    .line 611
    .line 612
    :catch_3f
    :try_start_40
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 613
    .line 614
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 615
    .line 616
    .line 617
    move-result v11

    .line 618
    aput v14, v0, v11
    :try_end_40
    .catch Ljava/lang/NoSuchFieldError; {:try_start_40 .. :try_end_40} :catch_40

    .line 619
    .line 620
    :catch_40
    :try_start_41
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 621
    .line 622
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 623
    .line 624
    .line 625
    move-result v11

    .line 626
    aput v15, v0, v11
    :try_end_41
    .catch Ljava/lang/NoSuchFieldError; {:try_start_41 .. :try_end_41} :catch_41

    .line 627
    .line 628
    :catch_41
    :try_start_42
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 629
    .line 630
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 631
    .line 632
    .line 633
    move-result v11

    .line 634
    aput v16, v0, v11
    :try_end_42
    .catch Ljava/lang/NoSuchFieldError; {:try_start_42 .. :try_end_42} :catch_42

    .line 635
    .line 636
    :catch_42
    :try_start_43
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_FORWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 637
    .line 638
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 639
    .line 640
    .line 641
    move-result v11

    .line 642
    aput v17, v0, v11
    :try_end_43
    .catch Ljava/lang/NoSuchFieldError; {:try_start_43 .. :try_end_43} :catch_43

    .line 643
    .line 644
    :catch_43
    :try_start_44
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_BACKWARD_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 645
    .line 646
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 647
    .line 648
    .line 649
    move-result v11

    .line 650
    aput v18, v0, v11
    :try_end_44
    .catch Ljava/lang/NoSuchFieldError; {:try_start_44 .. :try_end_44} :catch_44

    .line 651
    .line 652
    :catch_44
    :try_start_45
    sget-object v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_PARALLEL_PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 653
    .line 654
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 655
    .line 656
    .line 657
    move-result v11

    .line 658
    aput v19, v0, v11
    :try_end_45
    .catch Ljava/lang/NoSuchFieldError; {:try_start_45 .. :try_end_45} :catch_45

    .line 659
    .line 660
    :catch_45
    sput-object v0, Ly81/a;->d:[I

    .line 661
    .line 662
    invoke-static {}, Ls71/k;->values()[Ls71/k;

    .line 663
    .line 664
    .line 665
    move-result-object v0

    .line 666
    array-length v0, v0

    .line 667
    new-array v0, v0, [I

    .line 668
    .line 669
    const/4 v11, 0x0

    .line 670
    :try_start_46
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 671
    .line 672
    aput v1, v0, v11
    :try_end_46
    .catch Ljava/lang/NoSuchFieldError; {:try_start_46 .. :try_end_46} :catch_46

    .line 673
    .line 674
    :catch_46
    :try_start_47
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 675
    .line 676
    aput v2, v0, v9
    :try_end_47
    .catch Ljava/lang/NoSuchFieldError; {:try_start_47 .. :try_end_47} :catch_47

    .line 677
    .line 678
    :catch_47
    :try_start_48
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 679
    .line 680
    aput v3, v0, v1
    :try_end_48
    .catch Ljava/lang/NoSuchFieldError; {:try_start_48 .. :try_end_48} :catch_48

    .line 681
    .line 682
    :catch_48
    :try_start_49
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 683
    .line 684
    aput v4, v0, v2
    :try_end_49
    .catch Ljava/lang/NoSuchFieldError; {:try_start_49 .. :try_end_49} :catch_49

    .line 685
    .line 686
    :catch_49
    :try_start_4a
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 687
    .line 688
    aput v5, v0, v3
    :try_end_4a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4a .. :try_end_4a} :catch_4a

    .line 689
    .line 690
    :catch_4a
    :try_start_4b
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 691
    .line 692
    aput v6, v0, v4
    :try_end_4b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4b .. :try_end_4b} :catch_4b

    .line 693
    .line 694
    :catch_4b
    :try_start_4c
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 695
    .line 696
    aput v7, v0, v5
    :try_end_4c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4c .. :try_end_4c} :catch_4c

    .line 697
    .line 698
    :catch_4c
    :try_start_4d
    sget-object v12, Ls71/k;->d:Lwe0/b;

    .line 699
    .line 700
    aput v8, v0, v6
    :try_end_4d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4d .. :try_end_4d} :catch_4d

    .line 701
    .line 702
    :catch_4d
    :try_start_4e
    sget-object v6, Ls71/k;->d:Lwe0/b;

    .line 703
    .line 704
    aput v9, v0, v7
    :try_end_4e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4e .. :try_end_4e} :catch_4e

    .line 705
    .line 706
    :catch_4e
    :try_start_4f
    sget-object v6, Ls71/k;->d:Lwe0/b;

    .line 707
    .line 708
    aput v10, v0, v8
    :try_end_4f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4f .. :try_end_4f} :catch_4f

    .line 709
    .line 710
    :catch_4f
    invoke-static {}, Ls71/h;->values()[Ls71/h;

    .line 711
    .line 712
    .line 713
    move-result-object v0

    .line 714
    array-length v0, v0

    .line 715
    new-array v0, v0, [I

    .line 716
    .line 717
    :try_start_50
    sget-object v6, Ls71/h;->d:Ls71/h;

    .line 718
    .line 719
    aput v1, v0, v11
    :try_end_50
    .catch Ljava/lang/NoSuchFieldError; {:try_start_50 .. :try_end_50} :catch_50

    .line 720
    .line 721
    :catch_50
    :try_start_51
    sget-object v6, Ls71/h;->d:Ls71/h;

    .line 722
    .line 723
    aput v2, v0, v3
    :try_end_51
    .catch Ljava/lang/NoSuchFieldError; {:try_start_51 .. :try_end_51} :catch_51

    .line 724
    .line 725
    :catch_51
    :try_start_52
    sget-object v6, Ls71/h;->d:Ls71/h;

    .line 726
    .line 727
    aput v3, v0, v4
    :try_end_52
    .catch Ljava/lang/NoSuchFieldError; {:try_start_52 .. :try_end_52} :catch_52

    .line 728
    .line 729
    :catch_52
    :try_start_53
    sget-object v6, Ls71/h;->d:Ls71/h;

    .line 730
    .line 731
    aput v4, v0, v1
    :try_end_53
    .catch Ljava/lang/NoSuchFieldError; {:try_start_53 .. :try_end_53} :catch_53

    .line 732
    .line 733
    :catch_53
    :try_start_54
    sget-object v6, Ls71/h;->d:Ls71/h;

    .line 734
    .line 735
    aput v5, v0, v2
    :try_end_54
    .catch Ljava/lang/NoSuchFieldError; {:try_start_54 .. :try_end_54} :catch_54

    .line 736
    .line 737
    :catch_54
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 738
    .line 739
    .line 740
    move-result-object v0

    .line 741
    array-length v0, v0

    .line 742
    new-array v0, v0, [I

    .line 743
    .line 744
    :try_start_55
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 745
    .line 746
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 747
    .line 748
    .line 749
    move-result v5

    .line 750
    aput v1, v0, v5
    :try_end_55
    .catch Ljava/lang/NoSuchFieldError; {:try_start_55 .. :try_end_55} :catch_55

    .line 751
    .line 752
    :catch_55
    :try_start_56
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;->BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 753
    .line 754
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 755
    .line 756
    .line 757
    move-result v1

    .line 758
    aput v2, v0, v1
    :try_end_56
    .catch Ljava/lang/NoSuchFieldError; {:try_start_56 .. :try_end_56} :catch_56

    .line 759
    .line 760
    :catch_56
    :try_start_57
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;->STILLSTAND:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 761
    .line 762
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 763
    .line 764
    .line 765
    move-result v1

    .line 766
    aput v3, v0, v1
    :try_end_57
    .catch Ljava/lang/NoSuchFieldError; {:try_start_57 .. :try_end_57} :catch_57

    .line 767
    .line 768
    :catch_57
    :try_start_58
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;->PARKING:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/TrajectoryDirectionPPE;

    .line 769
    .line 770
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 771
    .line 772
    .line 773
    move-result v1

    .line 774
    aput v4, v0, v1
    :try_end_58
    .catch Ljava/lang/NoSuchFieldError; {:try_start_58 .. :try_end_58} :catch_58

    .line 775
    .line 776
    :catch_58
    sput-object v0, Ly81/a;->e:[I

    .line 777
    .line 778
    return-void
.end method
