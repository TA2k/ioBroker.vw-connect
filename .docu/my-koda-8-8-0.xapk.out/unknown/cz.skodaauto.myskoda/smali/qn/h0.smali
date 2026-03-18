.class public final enum Lqn/h0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Landroid/util/SparseArray;

.field public static final synthetic e:[Lqn/h0;


# direct methods
.method static constructor <clinit>()V
    .locals 34

    .line 1
    new-instance v1, Lqn/h0;

    .line 2
    .line 3
    const-string v0, "UNKNOWN_MOBILE_SUBTYPE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, v0, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    move v0, v2

    .line 10
    new-instance v2, Lqn/h0;

    .line 11
    .line 12
    const-string v3, "GPRS"

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    new-instance v3, Lqn/h0;

    .line 19
    .line 20
    const-string v5, "EDGE"

    .line 21
    .line 22
    const/4 v6, 0x2

    .line 23
    invoke-direct {v3, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 24
    .line 25
    .line 26
    move v5, v4

    .line 27
    new-instance v4, Lqn/h0;

    .line 28
    .line 29
    const-string v7, "UMTS"

    .line 30
    .line 31
    const/4 v8, 0x3

    .line 32
    invoke-direct {v4, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    move v7, v5

    .line 36
    new-instance v5, Lqn/h0;

    .line 37
    .line 38
    const-string v9, "CDMA"

    .line 39
    .line 40
    const/4 v10, 0x4

    .line 41
    invoke-direct {v5, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 42
    .line 43
    .line 44
    move v9, v6

    .line 45
    new-instance v6, Lqn/h0;

    .line 46
    .line 47
    const-string v11, "EVDO_0"

    .line 48
    .line 49
    const/4 v12, 0x5

    .line 50
    invoke-direct {v6, v11, v12}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 51
    .line 52
    .line 53
    move v11, v7

    .line 54
    new-instance v7, Lqn/h0;

    .line 55
    .line 56
    const-string v13, "EVDO_A"

    .line 57
    .line 58
    const/4 v14, 0x6

    .line 59
    invoke-direct {v7, v13, v14}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 60
    .line 61
    .line 62
    move v13, v8

    .line 63
    new-instance v8, Lqn/h0;

    .line 64
    .line 65
    const-string v15, "RTT"

    .line 66
    .line 67
    const/4 v0, 0x7

    .line 68
    invoke-direct {v8, v15, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 69
    .line 70
    .line 71
    move v15, v9

    .line 72
    new-instance v9, Lqn/h0;

    .line 73
    .line 74
    const-string v10, "HSDPA"

    .line 75
    .line 76
    const/16 v0, 0x8

    .line 77
    .line 78
    invoke-direct {v9, v10, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 79
    .line 80
    .line 81
    new-instance v10, Lqn/h0;

    .line 82
    .line 83
    const-string v11, "HSUPA"

    .line 84
    .line 85
    const/16 v0, 0x9

    .line 86
    .line 87
    invoke-direct {v10, v11, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    new-instance v11, Lqn/h0;

    .line 91
    .line 92
    const-string v12, "HSPA"

    .line 93
    .line 94
    const/16 v0, 0xa

    .line 95
    .line 96
    invoke-direct {v11, v12, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 97
    .line 98
    .line 99
    new-instance v12, Lqn/h0;

    .line 100
    .line 101
    const-string v13, "IDEN"

    .line 102
    .line 103
    const/16 v0, 0xb

    .line 104
    .line 105
    invoke-direct {v12, v13, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    new-instance v13, Lqn/h0;

    .line 109
    .line 110
    const-string v14, "EVDO_B"

    .line 111
    .line 112
    const/16 v0, 0xc

    .line 113
    .line 114
    invoke-direct {v13, v14, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 115
    .line 116
    .line 117
    new-instance v14, Lqn/h0;

    .line 118
    .line 119
    const-string v15, "LTE"

    .line 120
    .line 121
    const/16 v0, 0xd

    .line 122
    .line 123
    invoke-direct {v14, v15, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 124
    .line 125
    .line 126
    new-instance v15, Lqn/h0;

    .line 127
    .line 128
    const-string v0, "EHRPD"

    .line 129
    .line 130
    move-object/from16 v22, v1

    .line 131
    .line 132
    const/16 v1, 0xe

    .line 133
    .line 134
    invoke-direct {v15, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 135
    .line 136
    .line 137
    new-instance v0, Lqn/h0;

    .line 138
    .line 139
    const-string v1, "HSPAP"

    .line 140
    .line 141
    move-object/from16 v23, v2

    .line 142
    .line 143
    const/16 v2, 0xf

    .line 144
    .line 145
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 146
    .line 147
    .line 148
    new-instance v1, Lqn/h0;

    .line 149
    .line 150
    const-string v2, "GSM"

    .line 151
    .line 152
    move-object/from16 v24, v0

    .line 153
    .line 154
    const/16 v0, 0x10

    .line 155
    .line 156
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 157
    .line 158
    .line 159
    new-instance v2, Lqn/h0;

    .line 160
    .line 161
    const-string v0, "TD_SCDMA"

    .line 162
    .line 163
    move-object/from16 v25, v1

    .line 164
    .line 165
    const/16 v1, 0x11

    .line 166
    .line 167
    invoke-direct {v2, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 168
    .line 169
    .line 170
    new-instance v0, Lqn/h0;

    .line 171
    .line 172
    const-string v1, "IWLAN"

    .line 173
    .line 174
    move-object/from16 v26, v2

    .line 175
    .line 176
    const/16 v2, 0x12

    .line 177
    .line 178
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 179
    .line 180
    .line 181
    new-instance v1, Lqn/h0;

    .line 182
    .line 183
    const-string v2, "LTE_CA"

    .line 184
    .line 185
    move-object/from16 v27, v0

    .line 186
    .line 187
    const/16 v0, 0x13

    .line 188
    .line 189
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 190
    .line 191
    .line 192
    new-instance v2, Lqn/h0;

    .line 193
    .line 194
    const-string v0, "COMBINED"

    .line 195
    .line 196
    move-object/from16 v28, v1

    .line 197
    .line 198
    const/16 v1, 0x14

    .line 199
    .line 200
    invoke-direct {v2, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 201
    .line 202
    .line 203
    move-object/from16 v21, v2

    .line 204
    .line 205
    move-object/from16 v1, v22

    .line 206
    .line 207
    move-object/from16 v2, v23

    .line 208
    .line 209
    move-object/from16 v16, v24

    .line 210
    .line 211
    move-object/from16 v17, v25

    .line 212
    .line 213
    move-object/from16 v18, v26

    .line 214
    .line 215
    move-object/from16 v19, v27

    .line 216
    .line 217
    move-object/from16 v20, v28

    .line 218
    .line 219
    const/4 v0, 0x0

    .line 220
    filled-new-array/range {v1 .. v21}, [Lqn/h0;

    .line 221
    .line 222
    .line 223
    move-result-object v21

    .line 224
    move-object/from16 v29, v16

    .line 225
    .line 226
    move-object/from16 v30, v17

    .line 227
    .line 228
    move-object/from16 v31, v18

    .line 229
    .line 230
    move-object/from16 v32, v19

    .line 231
    .line 232
    move-object/from16 v33, v20

    .line 233
    .line 234
    sput-object v21, Lqn/h0;->e:[Lqn/h0;

    .line 235
    .line 236
    new-instance v0, Landroid/util/SparseArray;

    .line 237
    .line 238
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 239
    .line 240
    .line 241
    sput-object v0, Lqn/h0;->d:Landroid/util/SparseArray;

    .line 242
    .line 243
    move-object/from16 v17, v15

    .line 244
    .line 245
    const/4 v15, 0x0

    .line 246
    invoke-virtual {v0, v15, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    const/4 v1, 0x1

    .line 250
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    const/4 v15, 0x2

    .line 254
    invoke-virtual {v0, v15, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    const/4 v1, 0x3

    .line 258
    invoke-virtual {v0, v1, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 259
    .line 260
    .line 261
    const/4 v1, 0x4

    .line 262
    invoke-virtual {v0, v1, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    const/4 v1, 0x5

    .line 266
    invoke-virtual {v0, v1, v6}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    const/4 v1, 0x6

    .line 270
    invoke-virtual {v0, v1, v7}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    const/4 v1, 0x7

    .line 274
    invoke-virtual {v0, v1, v8}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    const/16 v1, 0x8

    .line 278
    .line 279
    invoke-virtual {v0, v1, v9}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    const/16 v1, 0x9

    .line 283
    .line 284
    invoke-virtual {v0, v1, v10}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    const/16 v1, 0xa

    .line 288
    .line 289
    invoke-virtual {v0, v1, v11}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    const/16 v1, 0xb

    .line 293
    .line 294
    invoke-virtual {v0, v1, v12}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    const/16 v1, 0xc

    .line 298
    .line 299
    invoke-virtual {v0, v1, v13}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    const/16 v1, 0xd

    .line 303
    .line 304
    invoke-virtual {v0, v1, v14}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    move-object/from16 v15, v17

    .line 308
    .line 309
    const/16 v1, 0xe

    .line 310
    .line 311
    invoke-virtual {v0, v1, v15}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    move-object/from16 v1, v29

    .line 315
    .line 316
    const/16 v2, 0xf

    .line 317
    .line 318
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    move-object/from16 v1, v30

    .line 322
    .line 323
    const/16 v2, 0x10

    .line 324
    .line 325
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    move-object/from16 v1, v31

    .line 329
    .line 330
    const/16 v2, 0x11

    .line 331
    .line 332
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    move-object/from16 v1, v32

    .line 336
    .line 337
    const/16 v2, 0x12

    .line 338
    .line 339
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 340
    .line 341
    .line 342
    move-object/from16 v1, v33

    .line 343
    .line 344
    const/16 v2, 0x13

    .line 345
    .line 346
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqn/h0;
    .locals 1

    .line 1
    const-class v0, Lqn/h0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqn/h0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqn/h0;
    .locals 1

    .line 1
    sget-object v0, Lqn/h0;->e:[Lqn/h0;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lqn/h0;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqn/h0;

    .line 8
    .line 9
    return-object v0
.end method
