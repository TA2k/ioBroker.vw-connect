.class public abstract synthetic Lr81/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I

.field public static final synthetic b:[I

.field public static final synthetic c:[I

.field public static final synthetic d:[I

.field public static final synthetic e:[I

.field public static final synthetic f:[I

.field public static final synthetic g:[I

.field public static final synthetic h:[I


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->MALFUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->FUNCTION_NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->DOORS_AND_FLAPS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TRAFFIC_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->INTERACTION_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->INTRUSION_VEHICLE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TIMEOUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->NO_CONTINUATION_OF_THE_JOURNEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

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
    :try_start_9
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->CHARGING_PLUG_PLUGGED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 92
    .line 93
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 94
    .line 95
    .line 96
    move-result v10

    .line 97
    const/16 v11, 0xa

    .line 98
    .line 99
    aput v11, v0, v10
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 100
    .line 101
    :catch_9
    :try_start_a
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->RECEPTION_OBSTRUCTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 102
    .line 103
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 104
    .line 105
    .line 106
    move-result v10

    .line 107
    const/16 v11, 0xb

    .line 108
    .line 109
    aput v11, v0, v10
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 110
    .line 111
    :catch_a
    :try_start_b
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->CHARGE_LEVEL_LOW:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 112
    .line 113
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    const/16 v11, 0xc

    .line 118
    .line 119
    aput v11, v0, v10
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 120
    .line 121
    :catch_b
    :try_start_c
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->COUNTRY_NOT_ALLOWED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 122
    .line 123
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 124
    .line 125
    .line 126
    move-result v10

    .line 127
    const/16 v11, 0xd

    .line 128
    .line 129
    aput v11, v0, v10
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 130
    .line 131
    :catch_c
    :try_start_d
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->KEY_SWITCH_OPERATED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 132
    .line 133
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    const/16 v11, 0xe

    .line 138
    .line 139
    aput v11, v0, v10
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 140
    .line 141
    :catch_d
    :try_start_e
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->ROUTE_NOT_TRAINED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 142
    .line 143
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 144
    .line 145
    .line 146
    move-result v10

    .line 147
    const/16 v11, 0xf

    .line 148
    .line 149
    aput v11, v0, v10
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 150
    .line 151
    :catch_e
    :try_start_f
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->GARAGE_DOOR_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 152
    .line 153
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 154
    .line 155
    .line 156
    move-result v10

    .line 157
    const/16 v11, 0x10

    .line 158
    .line 159
    aput v11, v0, v10
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 160
    .line 161
    :catch_f
    :try_start_10
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->KEY_INSIDE_INTERIOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 162
    .line 163
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 164
    .line 165
    .line 166
    move-result v10

    .line 167
    const/16 v11, 0x11

    .line 168
    .line 169
    aput v11, v0, v10
    :try_end_10
    .catch Ljava/lang/NoSuchFieldError; {:try_start_10 .. :try_end_10} :catch_10

    .line 170
    .line 171
    :catch_10
    :try_start_11
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->MULTIPLE_KEYS_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 172
    .line 173
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 174
    .line 175
    .line 176
    move-result v10

    .line 177
    const/16 v11, 0x12

    .line 178
    .line 179
    aput v11, v0, v10
    :try_end_11
    .catch Ljava/lang/NoSuchFieldError; {:try_start_11 .. :try_end_11} :catch_11

    .line 180
    .line 181
    :catch_11
    :try_start_12
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->OFF_ROAD_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 182
    .line 183
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 184
    .line 185
    .line 186
    move-result v10

    .line 187
    const/16 v11, 0x13

    .line 188
    .line 189
    aput v11, v0, v10
    :try_end_12
    .catch Ljava/lang/NoSuchFieldError; {:try_start_12 .. :try_end_12} :catch_12

    .line 190
    .line 191
    :catch_12
    :try_start_13
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->AIR_SUSPENSION_HEIGHT_NIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 192
    .line 193
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 194
    .line 195
    .line 196
    move-result v10

    .line 197
    const/16 v11, 0x14

    .line 198
    .line 199
    aput v11, v0, v10
    :try_end_13
    .catch Ljava/lang/NoSuchFieldError; {:try_start_13 .. :try_end_13} :catch_13

    .line 200
    .line 201
    :catch_13
    :try_start_14
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->MAX_DISTANCE_REACHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 202
    .line 203
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 204
    .line 205
    .line 206
    move-result v10

    .line 207
    const/16 v11, 0x15

    .line 208
    .line 209
    aput v11, v0, v10
    :try_end_14
    .catch Ljava/lang/NoSuchFieldError; {:try_start_14 .. :try_end_14} :catch_14

    .line 210
    .line 211
    :catch_14
    :try_start_15
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->SHUNTING_AREA_TOO_SMALL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 212
    .line 213
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 214
    .line 215
    .line 216
    move-result v10

    .line 217
    const/16 v11, 0x16

    .line 218
    .line 219
    aput v11, v0, v10
    :try_end_15
    .catch Ljava/lang/NoSuchFieldError; {:try_start_15 .. :try_end_15} :catch_15

    .line 220
    .line 221
    :catch_15
    :try_start_16
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TERMINATION_BY_GWSM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 222
    .line 223
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 224
    .line 225
    .line 226
    move-result v10

    .line 227
    const/16 v11, 0x17

    .line 228
    .line 229
    aput v11, v0, v10
    :try_end_16
    .catch Ljava/lang/NoSuchFieldError; {:try_start_16 .. :try_end_16} :catch_16

    .line 230
    .line 231
    :catch_16
    :try_start_17
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->MAX_MOVES_REACHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 232
    .line 233
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 234
    .line 235
    .line 236
    move-result v10

    .line 237
    const/16 v11, 0x18

    .line 238
    .line 239
    aput v11, v0, v10
    :try_end_17
    .catch Ljava/lang/NoSuchFieldError; {:try_start_17 .. :try_end_17} :catch_17

    .line 240
    .line 241
    :catch_17
    :try_start_18
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->PARKING_SPACE_TOO_SMALL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 242
    .line 243
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 244
    .line 245
    .line 246
    move-result v10

    .line 247
    const/16 v11, 0x19

    .line 248
    .line 249
    aput v11, v0, v10
    :try_end_18
    .catch Ljava/lang/NoSuchFieldError; {:try_start_18 .. :try_end_18} :catch_18

    .line 250
    .line 251
    :catch_18
    :try_start_19
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 252
    .line 253
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 254
    .line 255
    .line 256
    move-result v10

    .line 257
    const/16 v11, 0x1a

    .line 258
    .line 259
    aput v11, v0, v10
    :try_end_19
    .catch Ljava/lang/NoSuchFieldError; {:try_start_19 .. :try_end_19} :catch_19

    .line 260
    .line 261
    :catch_19
    :try_start_1a
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 262
    .line 263
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 264
    .line 265
    .line 266
    move-result v10

    .line 267
    const/16 v11, 0x1b

    .line 268
    .line 269
    aput v11, v0, v10
    :try_end_1a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1a .. :try_end_1a} :catch_1a

    .line 270
    .line 271
    :catch_1a
    :try_start_1b
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TRAILER_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 272
    .line 273
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 274
    .line 275
    .line 276
    move-result v10

    .line 277
    const/16 v11, 0x1c

    .line 278
    .line 279
    aput v11, v0, v10
    :try_end_1b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1b .. :try_end_1b} :catch_1b

    .line 280
    .line 281
    :catch_1b
    :try_start_1c
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TERMINATION_ESC_INTERVENTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 282
    .line 283
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 284
    .line 285
    .line 286
    move-result v10

    .line 287
    const/16 v11, 0x1d

    .line 288
    .line 289
    aput v11, v0, v10
    :try_end_1c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1c .. :try_end_1c} :catch_1c

    .line 290
    .line 291
    :catch_1c
    :try_start_1d
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->PP_ERROR_KEY_AUTHORIZER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 292
    .line 293
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 294
    .line 295
    .line 296
    move-result v10

    .line 297
    const/16 v11, 0x1e

    .line 298
    .line 299
    aput v11, v0, v10
    :try_end_1d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1d .. :try_end_1d} :catch_1d

    .line 300
    .line 301
    :catch_1d
    :try_start_1e
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->PP_LOSS_POS_OK:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 302
    .line 303
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 304
    .line 305
    .line 306
    move-result v10

    .line 307
    const/16 v11, 0x1f

    .line 308
    .line 309
    aput v11, v0, v10
    :try_end_1e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1e .. :try_end_1e} :catch_1e

    .line 310
    .line 311
    :catch_1e
    :try_start_1f
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TERMINATION_TSK_GRADIENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 312
    .line 313
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 314
    .line 315
    .line 316
    move-result v10

    .line 317
    const/16 v11, 0x20

    .line 318
    .line 319
    aput v11, v0, v10
    :try_end_1f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1f .. :try_end_1f} :catch_1f

    .line 320
    .line 321
    :catch_1f
    :try_start_20
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->STANDBY_INCREASED_DRIVING_RESISTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 322
    .line 323
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 324
    .line 325
    .line 326
    move-result v10

    .line 327
    const/16 v11, 0x21

    .line 328
    .line 329
    aput v11, v0, v10
    :try_end_20
    .catch Ljava/lang/NoSuchFieldError; {:try_start_20 .. :try_end_20} :catch_20

    .line 330
    .line 331
    :catch_20
    :try_start_21
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->TERMINATION_INCREASED_DRIVING_RESISTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 332
    .line 333
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 334
    .line 335
    .line 336
    move-result v10

    .line 337
    const/16 v11, 0x22

    .line 338
    .line 339
    aput v11, v0, v10
    :try_end_21
    .catch Ljava/lang/NoSuchFieldError; {:try_start_21 .. :try_end_21} :catch_21

    .line 340
    .line 341
    :catch_21
    :try_start_22
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->KAB_VOKO_VKM_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 342
    .line 343
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 344
    .line 345
    .line 346
    move-result v10

    .line 347
    const/16 v11, 0x23

    .line 348
    .line 349
    aput v11, v0, v10
    :try_end_22
    .catch Ljava/lang/NoSuchFieldError; {:try_start_22 .. :try_end_22} :catch_22

    .line 350
    .line 351
    :catch_22
    :try_start_23
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;->KAB_VOKO_VKM_ON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 352
    .line 353
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 354
    .line 355
    .line 356
    move-result v10

    .line 357
    const/16 v11, 0x24

    .line 358
    .line 359
    aput v11, v0, v10
    :try_end_23
    .catch Ljava/lang/NoSuchFieldError; {:try_start_23 .. :try_end_23} :catch_23

    .line 360
    .line 361
    :catch_23
    sput-object v0, Lr81/a;->a:[I

    .line 362
    .line 363
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 371
    .line 372
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 373
    .line 374
    .line 375
    move-result v10

    .line 376
    aput v1, v0, v10
    :try_end_24
    .catch Ljava/lang/NoSuchFieldError; {:try_start_24 .. :try_end_24} :catch_24

    .line 377
    .line 378
    :catch_24
    :try_start_25
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 379
    .line 380
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 381
    .line 382
    .line 383
    move-result v10

    .line 384
    aput v2, v0, v10
    :try_end_25
    .catch Ljava/lang/NoSuchFieldError; {:try_start_25 .. :try_end_25} :catch_25

    .line 385
    .line 386
    :catch_25
    :try_start_26
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_LEAVING_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 387
    .line 388
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 389
    .line 390
    .line 391
    move-result v10

    .line 392
    aput v3, v0, v10
    :try_end_26
    .catch Ljava/lang/NoSuchFieldError; {:try_start_26 .. :try_end_26} :catch_26

    .line 393
    .line 394
    :catch_26
    :try_start_27
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 395
    .line 396
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 397
    .line 398
    .line 399
    move-result v10

    .line 400
    aput v4, v0, v10
    :try_end_27
    .catch Ljava/lang/NoSuchFieldError; {:try_start_27 .. :try_end_27} :catch_27

    .line 401
    .line 402
    :catch_27
    :try_start_28
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;->KEY_INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 403
    .line 404
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 405
    .line 406
    .line 407
    move-result v10

    .line 408
    aput v5, v0, v10
    :try_end_28
    .catch Ljava/lang/NoSuchFieldError; {:try_start_28 .. :try_end_28} :catch_28

    .line 409
    .line 410
    :catch_28
    sput-object v0, Lr81/a;->b:[I

    .line 411
    .line 412
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    array-length v0, v0

    .line 417
    new-array v0, v0, [I

    .line 418
    .line 419
    :try_start_29
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;->R:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 420
    .line 421
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 422
    .line 423
    .line 424
    move-result v10

    .line 425
    aput v1, v0, v10
    :try_end_29
    .catch Ljava/lang/NoSuchFieldError; {:try_start_29 .. :try_end_29} :catch_29

    .line 426
    .line 427
    :catch_29
    :try_start_2a
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;->S:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 428
    .line 429
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 430
    .line 431
    .line 432
    move-result v10

    .line 433
    aput v2, v0, v10
    :try_end_2a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2a .. :try_end_2a} :catch_2a

    .line 434
    .line 435
    :catch_2a
    :try_start_2b
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;->D:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 436
    .line 437
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 438
    .line 439
    .line 440
    move-result v10

    .line 441
    aput v3, v0, v10
    :try_end_2b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2b .. :try_end_2b} :catch_2b

    .line 442
    .line 443
    :catch_2b
    sput-object v0, Lr81/a;->c:[I

    .line 444
    .line 445
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 446
    .line 447
    .line 448
    move-result-object v0

    .line 449
    array-length v0, v0

    .line 450
    new-array v0, v0, [I

    .line 451
    .line 452
    :try_start_2c
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;->NOT_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 453
    .line 454
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 455
    .line 456
    .line 457
    move-result v10

    .line 458
    aput v1, v0, v10
    :try_end_2c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2c .. :try_end_2c} :catch_2c

    .line 459
    .line 460
    :catch_2c
    sput-object v0, Lr81/a;->d:[I

    .line 461
    .line 462
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 463
    .line 464
    .line 465
    move-result-object v0

    .line 466
    array-length v0, v0

    .line 467
    new-array v0, v0, [I

    .line 468
    .line 469
    :try_start_2d
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 470
    .line 471
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 472
    .line 473
    .line 474
    move-result v10

    .line 475
    aput v1, v0, v10
    :try_end_2d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2d .. :try_end_2d} :catch_2d

    .line 476
    .line 477
    :catch_2d
    :try_start_2e
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;->BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;

    .line 478
    .line 479
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 480
    .line 481
    .line 482
    move-result v10

    .line 483
    aput v2, v0, v10
    :try_end_2e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2e .. :try_end_2e} :catch_2e

    .line 484
    .line 485
    :catch_2e
    sput-object v0, Lr81/a;->e:[I

    .line 486
    .line 487
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 488
    .line 489
    .line 490
    move-result-object v0

    .line 491
    array-length v0, v0

    .line 492
    new-array v0, v0, [I

    .line 493
    .line 494
    :try_start_2f
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 495
    .line 496
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 497
    .line 498
    .line 499
    move-result v10

    .line 500
    aput v1, v0, v10
    :try_end_2f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2f .. :try_end_2f} :catch_2f

    .line 501
    .line 502
    :catch_2f
    :try_start_30
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 503
    .line 504
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 505
    .line 506
    .line 507
    move-result v10

    .line 508
    aput v2, v0, v10
    :try_end_30
    .catch Ljava/lang/NoSuchFieldError; {:try_start_30 .. :try_end_30} :catch_30

    .line 509
    .line 510
    :catch_30
    :try_start_31
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 511
    .line 512
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 513
    .line 514
    .line 515
    move-result v10

    .line 516
    aput v3, v0, v10
    :try_end_31
    .catch Ljava/lang/NoSuchFieldError; {:try_start_31 .. :try_end_31} :catch_31

    .line 517
    .line 518
    :catch_31
    :try_start_32
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;->STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 519
    .line 520
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 521
    .line 522
    .line 523
    move-result v10

    .line 524
    aput v4, v0, v10
    :try_end_32
    .catch Ljava/lang/NoSuchFieldError; {:try_start_32 .. :try_end_32} :catch_32

    .line 525
    .line 526
    :catch_32
    sput-object v0, Lr81/a;->f:[I

    .line 527
    .line 528
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    array-length v0, v0

    .line 533
    new-array v0, v0, [I

    .line 534
    .line 535
    :try_start_33
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 536
    .line 537
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 538
    .line 539
    .line 540
    move-result v10

    .line 541
    aput v1, v0, v10
    :try_end_33
    .catch Ljava/lang/NoSuchFieldError; {:try_start_33 .. :try_end_33} :catch_33

    .line 542
    .line 543
    :catch_33
    :try_start_34
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 544
    .line 545
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 546
    .line 547
    .line 548
    move-result v10

    .line 549
    aput v2, v0, v10
    :try_end_34
    .catch Ljava/lang/NoSuchFieldError; {:try_start_34 .. :try_end_34} :catch_34

    .line 550
    .line 551
    :catch_34
    :try_start_35
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;->BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;

    .line 552
    .line 553
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 554
    .line 555
    .line 556
    move-result v10

    .line 557
    aput v3, v0, v10
    :try_end_35
    .catch Ljava/lang/NoSuchFieldError; {:try_start_35 .. :try_end_35} :catch_35

    .line 558
    .line 559
    :catch_35
    sput-object v0, Lr81/a;->g:[I

    .line 560
    .line 561
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 562
    .line 563
    .line 564
    move-result-object v0

    .line 565
    array-length v0, v0

    .line 566
    new-array v0, v0, [I

    .line 567
    .line 568
    :try_start_36
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 569
    .line 570
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 571
    .line 572
    .line 573
    move-result v10

    .line 574
    aput v1, v0, v10
    :try_end_36
    .catch Ljava/lang/NoSuchFieldError; {:try_start_36 .. :try_end_36} :catch_36

    .line 575
    .line 576
    :catch_36
    :try_start_37
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 577
    .line 578
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 579
    .line 580
    .line 581
    move-result v10

    .line 582
    aput v2, v0, v10
    :try_end_37
    .catch Ljava/lang/NoSuchFieldError; {:try_start_37 .. :try_end_37} :catch_37

    .line 583
    .line 584
    :catch_37
    :try_start_38
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 585
    .line 586
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 587
    .line 588
    .line 589
    move-result v10

    .line 590
    aput v3, v0, v10
    :try_end_38
    .catch Ljava/lang/NoSuchFieldError; {:try_start_38 .. :try_end_38} :catch_38

    .line 591
    .line 592
    :catch_38
    :try_start_39
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 593
    .line 594
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 595
    .line 596
    .line 597
    move-result v10

    .line 598
    aput v4, v0, v10
    :try_end_39
    .catch Ljava/lang/NoSuchFieldError; {:try_start_39 .. :try_end_39} :catch_39

    .line 599
    .line 600
    :catch_39
    :try_start_3a
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 601
    .line 602
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 603
    .line 604
    .line 605
    move-result v10

    .line 606
    aput v5, v0, v10
    :try_end_3a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3a .. :try_end_3a} :catch_3a

    .line 607
    .line 608
    :catch_3a
    :try_start_3b
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;

    .line 609
    .line 610
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 611
    .line 612
    .line 613
    move-result v10

    .line 614
    aput v6, v0, v10
    :try_end_3b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3b .. :try_end_3b} :catch_3b

    .line 615
    .line 616
    :catch_3b
    sput-object v0, Lr81/a;->h:[I

    .line 617
    .line 618
    invoke-static {}, Ls71/j;->values()[Ls71/j;

    .line 619
    .line 620
    .line 621
    move-result-object v0

    .line 622
    array-length v0, v0

    .line 623
    new-array v0, v0, [I

    .line 624
    .line 625
    const/4 v10, 0x0

    .line 626
    :try_start_3c
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 627
    .line 628
    aput v1, v0, v10
    :try_end_3c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3c .. :try_end_3c} :catch_3c

    .line 629
    .line 630
    :catch_3c
    :try_start_3d
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 631
    .line 632
    aput v2, v0, v1
    :try_end_3d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3d .. :try_end_3d} :catch_3d

    .line 633
    .line 634
    :catch_3d
    :try_start_3e
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 635
    .line 636
    aput v3, v0, v2
    :try_end_3e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3e .. :try_end_3e} :catch_3e

    .line 637
    .line 638
    :catch_3e
    :try_start_3f
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 639
    .line 640
    aput v4, v0, v3
    :try_end_3f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3f .. :try_end_3f} :catch_3f

    .line 641
    .line 642
    :catch_3f
    invoke-static {}, Ls71/g;->values()[Ls71/g;

    .line 643
    .line 644
    .line 645
    move-result-object v0

    .line 646
    array-length v0, v0

    .line 647
    new-array v0, v0, [I

    .line 648
    .line 649
    :try_start_40
    sget-object v11, Ls71/g;->d:Ls71/g;

    .line 650
    .line 651
    aput v1, v0, v10
    :try_end_40
    .catch Ljava/lang/NoSuchFieldError; {:try_start_40 .. :try_end_40} :catch_40

    .line 652
    .line 653
    :catch_40
    :try_start_41
    sget-object v11, Ls71/g;->d:Ls71/g;

    .line 654
    .line 655
    aput v2, v0, v1
    :try_end_41
    .catch Ljava/lang/NoSuchFieldError; {:try_start_41 .. :try_end_41} :catch_41

    .line 656
    .line 657
    :catch_41
    :try_start_42
    sget-object v11, Ls71/g;->d:Ls71/g;

    .line 658
    .line 659
    aput v3, v0, v2
    :try_end_42
    .catch Ljava/lang/NoSuchFieldError; {:try_start_42 .. :try_end_42} :catch_42

    .line 660
    .line 661
    :catch_42
    invoke-static {}, Ls71/i;->values()[Ls71/i;

    .line 662
    .line 663
    .line 664
    move-result-object v0

    .line 665
    array-length v0, v0

    .line 666
    new-array v0, v0, [I

    .line 667
    .line 668
    :try_start_43
    sget-object v11, Ls71/i;->d:Ls71/i;

    .line 669
    .line 670
    aput v1, v0, v10
    :try_end_43
    .catch Ljava/lang/NoSuchFieldError; {:try_start_43 .. :try_end_43} :catch_43

    .line 671
    .line 672
    :catch_43
    :try_start_44
    sget-object v10, Ls71/i;->d:Ls71/i;

    .line 673
    .line 674
    aput v2, v0, v6
    :try_end_44
    .catch Ljava/lang/NoSuchFieldError; {:try_start_44 .. :try_end_44} :catch_44

    .line 675
    .line 676
    :catch_44
    :try_start_45
    sget-object v10, Ls71/i;->d:Ls71/i;

    .line 677
    .line 678
    aput v3, v0, v7
    :try_end_45
    .catch Ljava/lang/NoSuchFieldError; {:try_start_45 .. :try_end_45} :catch_45

    .line 679
    .line 680
    :catch_45
    :try_start_46
    sget-object v10, Ls71/i;->d:Ls71/i;

    .line 681
    .line 682
    aput v4, v0, v8
    :try_end_46
    .catch Ljava/lang/NoSuchFieldError; {:try_start_46 .. :try_end_46} :catch_46

    .line 683
    .line 684
    :catch_46
    :try_start_47
    sget-object v10, Ls71/i;->d:Ls71/i;

    .line 685
    .line 686
    aput v5, v0, v1
    :try_end_47
    .catch Ljava/lang/NoSuchFieldError; {:try_start_47 .. :try_end_47} :catch_47

    .line 687
    .line 688
    :catch_47
    :try_start_48
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 689
    .line 690
    aput v6, v0, v2
    :try_end_48
    .catch Ljava/lang/NoSuchFieldError; {:try_start_48 .. :try_end_48} :catch_48

    .line 691
    .line 692
    :catch_48
    :try_start_49
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 693
    .line 694
    aput v7, v0, v3
    :try_end_49
    .catch Ljava/lang/NoSuchFieldError; {:try_start_49 .. :try_end_49} :catch_49

    .line 695
    .line 696
    :catch_49
    :try_start_4a
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 697
    .line 698
    aput v8, v0, v4
    :try_end_4a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4a .. :try_end_4a} :catch_4a

    .line 699
    .line 700
    :catch_4a
    :try_start_4b
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 701
    .line 702
    aput v9, v0, v5
    :try_end_4b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4b .. :try_end_4b} :catch_4b

    .line 703
    .line 704
    :catch_4b
    return-void
.end method
