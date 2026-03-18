.class public final enum Lin/h;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lin/h;

.field public static final enum e:Lin/h;

.field public static final enum f:Lin/h;

.field public static final enum g:Lin/h;

.field public static final h:Ljava/util/HashMap;

.field public static final synthetic i:[Lin/h;


# direct methods
.method static constructor <clinit>()V
    .locals 28

    .line 1
    new-instance v1, Lin/h;

    .line 2
    .line 3
    const-string v0, "target"

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
    new-instance v2, Lin/h;

    .line 11
    .line 12
    const-string v3, "root"

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    new-instance v3, Lin/h;

    .line 19
    .line 20
    const-string v4, "nth_child"

    .line 21
    .line 22
    const/4 v5, 0x2

    .line 23
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 24
    .line 25
    .line 26
    sput-object v3, Lin/h;->d:Lin/h;

    .line 27
    .line 28
    new-instance v4, Lin/h;

    .line 29
    .line 30
    const-string v5, "nth_last_child"

    .line 31
    .line 32
    const/4 v6, 0x3

    .line 33
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 34
    .line 35
    .line 36
    new-instance v5, Lin/h;

    .line 37
    .line 38
    const-string v6, "nth_of_type"

    .line 39
    .line 40
    const/4 v7, 0x4

    .line 41
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 42
    .line 43
    .line 44
    sput-object v5, Lin/h;->e:Lin/h;

    .line 45
    .line 46
    new-instance v6, Lin/h;

    .line 47
    .line 48
    const-string v7, "nth_last_of_type"

    .line 49
    .line 50
    const/4 v8, 0x5

    .line 51
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 52
    .line 53
    .line 54
    sput-object v6, Lin/h;->f:Lin/h;

    .line 55
    .line 56
    new-instance v7, Lin/h;

    .line 57
    .line 58
    const-string v8, "first_child"

    .line 59
    .line 60
    const/4 v9, 0x6

    .line 61
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 62
    .line 63
    .line 64
    new-instance v8, Lin/h;

    .line 65
    .line 66
    const-string v9, "last_child"

    .line 67
    .line 68
    const/4 v10, 0x7

    .line 69
    invoke-direct {v8, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 70
    .line 71
    .line 72
    new-instance v9, Lin/h;

    .line 73
    .line 74
    const-string v10, "first_of_type"

    .line 75
    .line 76
    const/16 v11, 0x8

    .line 77
    .line 78
    invoke-direct {v9, v10, v11}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 79
    .line 80
    .line 81
    new-instance v10, Lin/h;

    .line 82
    .line 83
    const-string v11, "last_of_type"

    .line 84
    .line 85
    const/16 v12, 0x9

    .line 86
    .line 87
    invoke-direct {v10, v11, v12}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    new-instance v11, Lin/h;

    .line 91
    .line 92
    const-string v12, "only_child"

    .line 93
    .line 94
    const/16 v13, 0xa

    .line 95
    .line 96
    invoke-direct {v11, v12, v13}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 97
    .line 98
    .line 99
    new-instance v12, Lin/h;

    .line 100
    .line 101
    const-string v13, "only_of_type"

    .line 102
    .line 103
    const/16 v14, 0xb

    .line 104
    .line 105
    invoke-direct {v12, v13, v14}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    new-instance v13, Lin/h;

    .line 109
    .line 110
    const-string v14, "empty"

    .line 111
    .line 112
    const/16 v15, 0xc

    .line 113
    .line 114
    invoke-direct {v13, v14, v15}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 115
    .line 116
    .line 117
    new-instance v14, Lin/h;

    .line 118
    .line 119
    const-string v15, "not"

    .line 120
    .line 121
    const/16 v0, 0xd

    .line 122
    .line 123
    invoke-direct {v14, v15, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 124
    .line 125
    .line 126
    new-instance v15, Lin/h;

    .line 127
    .line 128
    const-string v0, "lang"

    .line 129
    .line 130
    move-object/from16 v17, v1

    .line 131
    .line 132
    const/16 v1, 0xe

    .line 133
    .line 134
    invoke-direct {v15, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 135
    .line 136
    .line 137
    new-instance v0, Lin/h;

    .line 138
    .line 139
    const-string v1, "link"

    .line 140
    .line 141
    move-object/from16 v18, v2

    .line 142
    .line 143
    const/16 v2, 0xf

    .line 144
    .line 145
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 146
    .line 147
    .line 148
    new-instance v1, Lin/h;

    .line 149
    .line 150
    const-string v2, "visited"

    .line 151
    .line 152
    move-object/from16 v19, v0

    .line 153
    .line 154
    const/16 v0, 0x10

    .line 155
    .line 156
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 157
    .line 158
    .line 159
    new-instance v0, Lin/h;

    .line 160
    .line 161
    const-string v2, "hover"

    .line 162
    .line 163
    move-object/from16 v20, v1

    .line 164
    .line 165
    const/16 v1, 0x11

    .line 166
    .line 167
    invoke-direct {v0, v2, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 168
    .line 169
    .line 170
    new-instance v1, Lin/h;

    .line 171
    .line 172
    const-string v2, "active"

    .line 173
    .line 174
    move-object/from16 v21, v0

    .line 175
    .line 176
    const/16 v0, 0x12

    .line 177
    .line 178
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 179
    .line 180
    .line 181
    new-instance v0, Lin/h;

    .line 182
    .line 183
    const-string v2, "focus"

    .line 184
    .line 185
    move-object/from16 v22, v1

    .line 186
    .line 187
    const/16 v1, 0x13

    .line 188
    .line 189
    invoke-direct {v0, v2, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 190
    .line 191
    .line 192
    new-instance v1, Lin/h;

    .line 193
    .line 194
    const-string v2, "enabled"

    .line 195
    .line 196
    move-object/from16 v23, v0

    .line 197
    .line 198
    const/16 v0, 0x14

    .line 199
    .line 200
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 201
    .line 202
    .line 203
    new-instance v0, Lin/h;

    .line 204
    .line 205
    const-string v2, "disabled"

    .line 206
    .line 207
    move-object/from16 v24, v1

    .line 208
    .line 209
    const/16 v1, 0x15

    .line 210
    .line 211
    invoke-direct {v0, v2, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 212
    .line 213
    .line 214
    new-instance v1, Lin/h;

    .line 215
    .line 216
    const-string v2, "checked"

    .line 217
    .line 218
    move-object/from16 v25, v0

    .line 219
    .line 220
    const/16 v0, 0x16

    .line 221
    .line 222
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 223
    .line 224
    .line 225
    new-instance v0, Lin/h;

    .line 226
    .line 227
    const-string v2, "indeterminate"

    .line 228
    .line 229
    move-object/from16 v26, v1

    .line 230
    .line 231
    const/16 v1, 0x17

    .line 232
    .line 233
    invoke-direct {v0, v2, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 234
    .line 235
    .line 236
    new-instance v1, Lin/h;

    .line 237
    .line 238
    const-string v2, "UNSUPPORTED"

    .line 239
    .line 240
    move-object/from16 v27, v0

    .line 241
    .line 242
    const/16 v0, 0x18

    .line 243
    .line 244
    invoke-direct {v1, v2, v0}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 245
    .line 246
    .line 247
    sput-object v1, Lin/h;->g:Lin/h;

    .line 248
    .line 249
    move-object/from16 v2, v18

    .line 250
    .line 251
    move-object/from16 v16, v19

    .line 252
    .line 253
    move-object/from16 v18, v21

    .line 254
    .line 255
    move-object/from16 v19, v22

    .line 256
    .line 257
    move-object/from16 v21, v24

    .line 258
    .line 259
    move-object/from16 v22, v25

    .line 260
    .line 261
    move-object/from16 v24, v27

    .line 262
    .line 263
    const/4 v0, 0x0

    .line 264
    move-object/from16 v25, v1

    .line 265
    .line 266
    move-object/from16 v1, v17

    .line 267
    .line 268
    move-object/from16 v17, v20

    .line 269
    .line 270
    move-object/from16 v20, v23

    .line 271
    .line 272
    move-object/from16 v23, v26

    .line 273
    .line 274
    filled-new-array/range {v1 .. v25}, [Lin/h;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    sput-object v1, Lin/h;->i:[Lin/h;

    .line 279
    .line 280
    new-instance v1, Ljava/util/HashMap;

    .line 281
    .line 282
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 283
    .line 284
    .line 285
    sput-object v1, Lin/h;->h:Ljava/util/HashMap;

    .line 286
    .line 287
    invoke-static {}, Lin/h;->values()[Lin/h;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    array-length v2, v1

    .line 292
    :goto_0
    if-ge v0, v2, :cond_1

    .line 293
    .line 294
    aget-object v3, v1, v0

    .line 295
    .line 296
    sget-object v4, Lin/h;->g:Lin/h;

    .line 297
    .line 298
    if-eq v3, v4, :cond_0

    .line 299
    .line 300
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object v4

    .line 304
    const/16 v5, 0x5f

    .line 305
    .line 306
    const/16 v6, 0x2d

    .line 307
    .line 308
    invoke-virtual {v4, v5, v6}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v4

    .line 312
    sget-object v5, Lin/h;->h:Ljava/util/HashMap;

    .line 313
    .line 314
    invoke-virtual {v5, v4, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 318
    .line 319
    goto :goto_0

    .line 320
    :cond_1
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lin/h;
    .locals 1

    .line 1
    const-class v0, Lin/h;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lin/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lin/h;
    .locals 1

    .line 1
    sget-object v0, Lin/h;->i:[Lin/h;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lin/h;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lin/h;

    .line 8
    .line 9
    return-object v0
.end method
