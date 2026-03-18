.class public abstract synthetic Lk81/a;
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


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->NO_ERROR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->MALFUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->FUNCTION_NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->DOORS_AND_FLAPS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TRAFFIC_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->INTERACTION_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->INTRUSION_VEHICLE_SYSTEM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TIMEOUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->NO_CONTINUATION_OF_THE_JOURNEY:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->CHARGING_PLUG_PLUGGED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->RECEPTION_OBSTRUCTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->CHARGE_LEVEL_LOW:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->COUNTRY_NOT_ALLOWED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->KEY_SWITCH_OPERATED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->ROUTE_NOT_TRAINED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->GARAGE_DOOR_OPEN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->KEY_INSIDE_INTERIOR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->MULTIPLE_KEYS_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->OFF_ROAD_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->AIR_SUSPENSION_HEIGHT_NIO:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->MAX_DISTANCE_REACHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->SHUNTING_AREA_TOO_SMALL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TERMINATION_BY_GWSM:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->MAX_MOVES_REACHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->PARKING_SPACE_TOO_SMALL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->OBSTACLE_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TRAILER_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TERMINATION_ESC_INTERVENTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->PP_ERROR_KEY_AUTHORIZER:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->PP_LOSS_POS_OK:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TERMINATION_TSK_GRADIENT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->STANDBY_INCREASED_DRIVING_RESISTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->TERMINATION_INCREASED_DRIVING_RESISTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->KAB_VOKO_VKM_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->KAB_VOKO_VKM_ON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

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
    sput-object v0, Lk81/a;->a:[I

    .line 362
    .line 363
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_IN_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_LEAVING_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;->KEY_INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/KeyStatusMEB;

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
    sput-object v0, Lk81/a;->b:[I

    .line 411
    .line 412
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;->D:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;

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
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;->R:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/GearStatusMEB;

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
    sput-object v0, Lk81/a;->c:[I

    .line 436
    .line 437
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    array-length v0, v0

    .line 442
    new-array v0, v0, [I

    .line 443
    .line 444
    :try_start_2b
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->NON_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 445
    .line 446
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 447
    .line 448
    .line 449
    move-result v10

    .line 450
    aput v1, v0, v10
    :try_end_2b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2b .. :try_end_2b} :catch_2b

    .line 451
    .line 452
    :catch_2b
    :try_start_2c
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->DETECTED_IN_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 453
    .line 454
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 455
    .line 456
    .line 457
    move-result v10

    .line 458
    aput v2, v0, v10
    :try_end_2c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2c .. :try_end_2c} :catch_2c

    .line 459
    .line 460
    :catch_2c
    :try_start_2d
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->DETECTED_AGAINST_DRIVING_DIRECTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 461
    .line 462
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 463
    .line 464
    .line 465
    move-result v10

    .line 466
    aput v3, v0, v10
    :try_end_2d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2d .. :try_end_2d} :catch_2d

    .line 467
    .line 468
    :catch_2d
    :try_start_2e
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;->DETECTED_IN_BOTH_DIRECTIONS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ObstacleStatusMEB;

    .line 469
    .line 470
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 471
    .line 472
    .line 473
    move-result v10

    .line 474
    aput v4, v0, v10
    :try_end_2e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2e .. :try_end_2e} :catch_2e

    .line 475
    .line 476
    :catch_2e
    sput-object v0, Lk81/a;->d:[I

    .line 477
    .line 478
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 479
    .line 480
    .line 481
    move-result-object v0

    .line 482
    array-length v0, v0

    .line 483
    new-array v0, v0, [I

    .line 484
    .line 485
    :try_start_2f
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 486
    .line 487
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 488
    .line 489
    .line 490
    move-result v10

    .line 491
    aput v1, v0, v10
    :try_end_2f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2f .. :try_end_2f} :catch_2f

    .line 492
    .line 493
    :catch_2f
    :try_start_30
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->LEFT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 494
    .line 495
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 496
    .line 497
    .line 498
    move-result v10

    .line 499
    aput v2, v0, v10
    :try_end_30
    .catch Ljava/lang/NoSuchFieldError; {:try_start_30 .. :try_end_30} :catch_30

    .line 500
    .line 501
    :catch_30
    :try_start_31
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->RIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 502
    .line 503
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 504
    .line 505
    .line 506
    move-result v10

    .line 507
    aput v3, v0, v10
    :try_end_31
    .catch Ljava/lang/NoSuchFieldError; {:try_start_31 .. :try_end_31} :catch_31

    .line 508
    .line 509
    :catch_31
    :try_start_32
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;->STRAIGHT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingSideActiveStatusMEB;

    .line 510
    .line 511
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 512
    .line 513
    .line 514
    move-result v10

    .line 515
    aput v4, v0, v10
    :try_end_32
    .catch Ljava/lang/NoSuchFieldError; {:try_start_32 .. :try_end_32} :catch_32

    .line 516
    .line 517
    :catch_32
    sput-object v0, Lk81/a;->e:[I

    .line 518
    .line 519
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    array-length v0, v0

    .line 524
    new-array v0, v0, [I

    .line 525
    .line 526
    :try_start_33
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 527
    .line 528
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 529
    .line 530
    .line 531
    move-result v10

    .line 532
    aput v1, v0, v10
    :try_end_33
    .catch Ljava/lang/NoSuchFieldError; {:try_start_33 .. :try_end_33} :catch_33

    .line 533
    .line 534
    :catch_33
    :try_start_34
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->FORWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 535
    .line 536
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 537
    .line 538
    .line 539
    move-result v10

    .line 540
    aput v2, v0, v10
    :try_end_34
    .catch Ljava/lang/NoSuchFieldError; {:try_start_34 .. :try_end_34} :catch_34

    .line 541
    .line 542
    :catch_34
    :try_start_35
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;->BACKWARD:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingDirectionActiveStatusMEB;

    .line 543
    .line 544
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 545
    .line 546
    .line 547
    move-result v10

    .line 548
    aput v3, v0, v10
    :try_end_35
    .catch Ljava/lang/NoSuchFieldError; {:try_start_35 .. :try_end_35} :catch_35

    .line 549
    .line 550
    :catch_35
    sput-object v0, Lk81/a;->f:[I

    .line 551
    .line 552
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 553
    .line 554
    .line 555
    move-result-object v0

    .line 556
    array-length v0, v0

    .line 557
    new-array v0, v0, [I

    .line 558
    .line 559
    :try_start_36
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 560
    .line 561
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 562
    .line 563
    .line 564
    move-result v10

    .line 565
    aput v1, v0, v10
    :try_end_36
    .catch Ljava/lang/NoSuchFieldError; {:try_start_36 .. :try_end_36} :catch_36

    .line 566
    .line 567
    :catch_36
    :try_start_37
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 568
    .line 569
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 570
    .line 571
    .line 572
    move-result v10

    .line 573
    aput v2, v0, v10
    :try_end_37
    .catch Ljava/lang/NoSuchFieldError; {:try_start_37 .. :try_end_37} :catch_37

    .line 574
    .line 575
    :catch_37
    :try_start_38
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->PERPENDICULAR:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 576
    .line 577
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 578
    .line 579
    .line 580
    move-result v10

    .line 581
    aput v3, v0, v10
    :try_end_38
    .catch Ljava/lang/NoSuchFieldError; {:try_start_38 .. :try_end_38} :catch_38

    .line 582
    .line 583
    :catch_38
    :try_start_39
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->GARAGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 584
    .line 585
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 586
    .line 587
    .line 588
    move-result v10

    .line 589
    aput v4, v0, v10
    :try_end_39
    .catch Ljava/lang/NoSuchFieldError; {:try_start_39 .. :try_end_39} :catch_39

    .line 590
    .line 591
    :catch_39
    :try_start_3a
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->BASIC:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 592
    .line 593
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 594
    .line 595
    .line 596
    move-result v10

    .line 597
    aput v5, v0, v10
    :try_end_3a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3a .. :try_end_3a} :catch_3a

    .line 598
    .line 599
    :catch_3a
    :try_start_3b
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->CUSTOM_DRIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 600
    .line 601
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 602
    .line 603
    .line 604
    move-result v10

    .line 605
    aput v6, v0, v10
    :try_end_3b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3b .. :try_end_3b} :catch_3b

    .line 606
    .line 607
    :catch_3b
    :try_start_3c
    sget-object v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;->TPA_OR_AAA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingScenarioActiveStatusMEB;

    .line 608
    .line 609
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 610
    .line 611
    .line 612
    move-result v10

    .line 613
    aput v7, v0, v10
    :try_end_3c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3c .. :try_end_3c} :catch_3c

    .line 614
    .line 615
    :catch_3c
    sput-object v0, Lk81/a;->g:[I

    .line 616
    .line 617
    invoke-static {}, Ls71/j;->values()[Ls71/j;

    .line 618
    .line 619
    .line 620
    move-result-object v0

    .line 621
    array-length v0, v0

    .line 622
    new-array v0, v0, [I

    .line 623
    .line 624
    const/4 v10, 0x0

    .line 625
    :try_start_3d
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 626
    .line 627
    aput v1, v0, v10
    :try_end_3d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3d .. :try_end_3d} :catch_3d

    .line 628
    .line 629
    :catch_3d
    :try_start_3e
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 630
    .line 631
    aput v2, v0, v1
    :try_end_3e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3e .. :try_end_3e} :catch_3e

    .line 632
    .line 633
    :catch_3e
    :try_start_3f
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 634
    .line 635
    aput v3, v0, v2
    :try_end_3f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3f .. :try_end_3f} :catch_3f

    .line 636
    .line 637
    :catch_3f
    :try_start_40
    sget-object v11, Ls71/j;->d:Ls71/j;

    .line 638
    .line 639
    aput v4, v0, v3
    :try_end_40
    .catch Ljava/lang/NoSuchFieldError; {:try_start_40 .. :try_end_40} :catch_40

    .line 640
    .line 641
    :catch_40
    invoke-static {}, Ls71/g;->values()[Ls71/g;

    .line 642
    .line 643
    .line 644
    move-result-object v0

    .line 645
    array-length v0, v0

    .line 646
    new-array v0, v0, [I

    .line 647
    .line 648
    :try_start_41
    sget-object v11, Ls71/g;->d:Ls71/g;

    .line 649
    .line 650
    aput v1, v0, v10
    :try_end_41
    .catch Ljava/lang/NoSuchFieldError; {:try_start_41 .. :try_end_41} :catch_41

    .line 651
    .line 652
    :catch_41
    :try_start_42
    sget-object v11, Ls71/g;->d:Ls71/g;

    .line 653
    .line 654
    aput v2, v0, v1
    :try_end_42
    .catch Ljava/lang/NoSuchFieldError; {:try_start_42 .. :try_end_42} :catch_42

    .line 655
    .line 656
    :catch_42
    :try_start_43
    sget-object v11, Ls71/g;->d:Ls71/g;

    .line 657
    .line 658
    aput v3, v0, v2
    :try_end_43
    .catch Ljava/lang/NoSuchFieldError; {:try_start_43 .. :try_end_43} :catch_43

    .line 659
    .line 660
    :catch_43
    invoke-static {}, Ls71/i;->values()[Ls71/i;

    .line 661
    .line 662
    .line 663
    move-result-object v0

    .line 664
    array-length v0, v0

    .line 665
    new-array v0, v0, [I

    .line 666
    .line 667
    :try_start_44
    sget-object v11, Ls71/i;->d:Ls71/i;

    .line 668
    .line 669
    aput v1, v0, v10
    :try_end_44
    .catch Ljava/lang/NoSuchFieldError; {:try_start_44 .. :try_end_44} :catch_44

    .line 670
    .line 671
    :catch_44
    :try_start_45
    sget-object v10, Ls71/i;->d:Ls71/i;

    .line 672
    .line 673
    aput v2, v0, v1
    :try_end_45
    .catch Ljava/lang/NoSuchFieldError; {:try_start_45 .. :try_end_45} :catch_45

    .line 674
    .line 675
    :catch_45
    :try_start_46
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 676
    .line 677
    aput v3, v0, v2
    :try_end_46
    .catch Ljava/lang/NoSuchFieldError; {:try_start_46 .. :try_end_46} :catch_46

    .line 678
    .line 679
    :catch_46
    :try_start_47
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 680
    .line 681
    aput v4, v0, v3
    :try_end_47
    .catch Ljava/lang/NoSuchFieldError; {:try_start_47 .. :try_end_47} :catch_47

    .line 682
    .line 683
    :catch_47
    :try_start_48
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 684
    .line 685
    aput v5, v0, v4
    :try_end_48
    .catch Ljava/lang/NoSuchFieldError; {:try_start_48 .. :try_end_48} :catch_48

    .line 686
    .line 687
    :catch_48
    :try_start_49
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 688
    .line 689
    aput v6, v0, v5
    :try_end_49
    .catch Ljava/lang/NoSuchFieldError; {:try_start_49 .. :try_end_49} :catch_49

    .line 690
    .line 691
    :catch_49
    :try_start_4a
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 692
    .line 693
    aput v7, v0, v6
    :try_end_4a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4a .. :try_end_4a} :catch_4a

    .line 694
    .line 695
    :catch_4a
    :try_start_4b
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 696
    .line 697
    aput v8, v0, v8
    :try_end_4b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4b .. :try_end_4b} :catch_4b

    .line 698
    .line 699
    :catch_4b
    :try_start_4c
    sget-object v1, Ls71/i;->d:Ls71/i;

    .line 700
    .line 701
    aput v9, v0, v7
    :try_end_4c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4c .. :try_end_4c} :catch_4c

    .line 702
    .line 703
    :catch_4c
    return-void
.end method
