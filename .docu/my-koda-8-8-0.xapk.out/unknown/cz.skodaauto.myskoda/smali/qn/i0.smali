.class public final enum Lqn/i0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Landroid/util/SparseArray;

.field public static final synthetic e:[Lqn/i0;


# direct methods
.method static constructor <clinit>()V
    .locals 30

    .line 1
    new-instance v1, Lqn/i0;

    .line 2
    .line 3
    const-string v0, "MOBILE"

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
    new-instance v2, Lqn/i0;

    .line 11
    .line 12
    const-string v3, "WIFI"

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    new-instance v3, Lqn/i0;

    .line 19
    .line 20
    const-string v5, "MOBILE_MMS"

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
    new-instance v4, Lqn/i0;

    .line 28
    .line 29
    const-string v7, "MOBILE_SUPL"

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
    new-instance v5, Lqn/i0;

    .line 37
    .line 38
    const-string v9, "MOBILE_DUN"

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
    new-instance v6, Lqn/i0;

    .line 46
    .line 47
    const-string v11, "MOBILE_HIPRI"

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
    new-instance v7, Lqn/i0;

    .line 55
    .line 56
    const-string v13, "WIMAX"

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
    new-instance v8, Lqn/i0;

    .line 64
    .line 65
    const-string v15, "BLUETOOTH"

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
    new-instance v9, Lqn/i0;

    .line 73
    .line 74
    const-string v10, "DUMMY"

    .line 75
    .line 76
    const/16 v0, 0x8

    .line 77
    .line 78
    invoke-direct {v9, v10, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 79
    .line 80
    .line 81
    new-instance v10, Lqn/i0;

    .line 82
    .line 83
    const-string v11, "ETHERNET"

    .line 84
    .line 85
    const/16 v0, 0x9

    .line 86
    .line 87
    invoke-direct {v10, v11, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    new-instance v11, Lqn/i0;

    .line 91
    .line 92
    const-string v12, "MOBILE_FOTA"

    .line 93
    .line 94
    const/16 v0, 0xa

    .line 95
    .line 96
    invoke-direct {v11, v12, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 97
    .line 98
    .line 99
    new-instance v12, Lqn/i0;

    .line 100
    .line 101
    const-string v13, "MOBILE_IMS"

    .line 102
    .line 103
    const/16 v0, 0xb

    .line 104
    .line 105
    invoke-direct {v12, v13, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    new-instance v13, Lqn/i0;

    .line 109
    .line 110
    const-string v14, "MOBILE_CBS"

    .line 111
    .line 112
    const/16 v0, 0xc

    .line 113
    .line 114
    invoke-direct {v13, v14, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 115
    .line 116
    .line 117
    new-instance v14, Lqn/i0;

    .line 118
    .line 119
    const-string v15, "WIFI_P2P"

    .line 120
    .line 121
    const/16 v0, 0xd

    .line 122
    .line 123
    invoke-direct {v14, v15, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 124
    .line 125
    .line 126
    new-instance v15, Lqn/i0;

    .line 127
    .line 128
    const-string v0, "MOBILE_IA"

    .line 129
    .line 130
    move-object/from16 v21, v1

    .line 131
    .line 132
    const/16 v1, 0xe

    .line 133
    .line 134
    invoke-direct {v15, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 135
    .line 136
    .line 137
    new-instance v0, Lqn/i0;

    .line 138
    .line 139
    const-string v1, "MOBILE_EMERGENCY"

    .line 140
    .line 141
    move-object/from16 v22, v2

    .line 142
    .line 143
    const/16 v2, 0xf

    .line 144
    .line 145
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 146
    .line 147
    .line 148
    new-instance v1, Lqn/i0;

    .line 149
    .line 150
    const-string v2, "PROXY"

    .line 151
    .line 152
    move-object/from16 v23, v0

    .line 153
    .line 154
    const/16 v0, 0x10

    .line 155
    .line 156
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 157
    .line 158
    .line 159
    new-instance v2, Lqn/i0;

    .line 160
    .line 161
    const-string v0, "VPN"

    .line 162
    .line 163
    move-object/from16 v24, v1

    .line 164
    .line 165
    const/16 v1, 0x11

    .line 166
    .line 167
    invoke-direct {v2, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 168
    .line 169
    .line 170
    new-instance v0, Lqn/i0;

    .line 171
    .line 172
    const-string v1, "NONE"

    .line 173
    .line 174
    move-object/from16 v25, v2

    .line 175
    .line 176
    const/16 v2, 0x12

    .line 177
    .line 178
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 179
    .line 180
    .line 181
    move-object/from16 v19, v0

    .line 182
    .line 183
    move-object/from16 v1, v21

    .line 184
    .line 185
    move-object/from16 v2, v22

    .line 186
    .line 187
    move-object/from16 v16, v23

    .line 188
    .line 189
    move-object/from16 v17, v24

    .line 190
    .line 191
    move-object/from16 v18, v25

    .line 192
    .line 193
    const/4 v0, 0x0

    .line 194
    filled-new-array/range {v1 .. v19}, [Lqn/i0;

    .line 195
    .line 196
    .line 197
    move-result-object v20

    .line 198
    move-object/from16 v26, v16

    .line 199
    .line 200
    move-object/from16 v27, v17

    .line 201
    .line 202
    move-object/from16 v28, v18

    .line 203
    .line 204
    move-object/from16 v29, v19

    .line 205
    .line 206
    sput-object v20, Lqn/i0;->e:[Lqn/i0;

    .line 207
    .line 208
    new-instance v0, Landroid/util/SparseArray;

    .line 209
    .line 210
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 211
    .line 212
    .line 213
    sput-object v0, Lqn/i0;->d:Landroid/util/SparseArray;

    .line 214
    .line 215
    move-object/from16 v17, v15

    .line 216
    .line 217
    const/4 v15, 0x0

    .line 218
    invoke-virtual {v0, v15, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    const/4 v1, 0x1

    .line 222
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    const/4 v15, 0x2

    .line 226
    invoke-virtual {v0, v15, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    const/4 v1, 0x3

    .line 230
    invoke-virtual {v0, v1, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    const/4 v1, 0x4

    .line 234
    invoke-virtual {v0, v1, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    const/4 v1, 0x5

    .line 238
    invoke-virtual {v0, v1, v6}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    const/4 v1, 0x6

    .line 242
    invoke-virtual {v0, v1, v7}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    const/4 v1, 0x7

    .line 246
    invoke-virtual {v0, v1, v8}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    const/16 v1, 0x8

    .line 250
    .line 251
    invoke-virtual {v0, v1, v9}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    const/16 v1, 0x9

    .line 255
    .line 256
    invoke-virtual {v0, v1, v10}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    const/16 v1, 0xa

    .line 260
    .line 261
    invoke-virtual {v0, v1, v11}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 262
    .line 263
    .line 264
    const/16 v1, 0xb

    .line 265
    .line 266
    invoke-virtual {v0, v1, v12}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    const/16 v1, 0xc

    .line 270
    .line 271
    invoke-virtual {v0, v1, v13}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    const/16 v1, 0xd

    .line 275
    .line 276
    invoke-virtual {v0, v1, v14}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 277
    .line 278
    .line 279
    move-object/from16 v15, v17

    .line 280
    .line 281
    const/16 v1, 0xe

    .line 282
    .line 283
    invoke-virtual {v0, v1, v15}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    move-object/from16 v1, v26

    .line 287
    .line 288
    const/16 v2, 0xf

    .line 289
    .line 290
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    move-object/from16 v1, v27

    .line 294
    .line 295
    const/16 v2, 0x10

    .line 296
    .line 297
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 298
    .line 299
    .line 300
    move-object/from16 v1, v28

    .line 301
    .line 302
    const/16 v2, 0x11

    .line 303
    .line 304
    invoke-virtual {v0, v2, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    const/4 v1, -0x1

    .line 308
    move-object/from16 v2, v29

    .line 309
    .line 310
    invoke-virtual {v0, v1, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lqn/i0;
    .locals 1

    .line 1
    const-class v0, Lqn/i0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqn/i0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lqn/i0;
    .locals 1

    .line 1
    sget-object v0, Lqn/i0;->e:[Lqn/i0;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lqn/i0;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lqn/i0;

    .line 8
    .line 9
    return-object v0
.end method
