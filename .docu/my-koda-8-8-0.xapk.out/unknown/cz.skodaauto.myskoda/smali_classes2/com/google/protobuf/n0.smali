.class public final Lcom/google/protobuf/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/protobuf/w0;


# static fields
.field public static final j:[I

.field public static final k:Lsun/misc/Unsafe;


# instance fields
.field public final a:[I

.field public final b:[Ljava/lang/Object;

.field public final c:Lcom/google/protobuf/a;

.field public final d:[I

.field public final e:I

.field public final f:Lcom/google/protobuf/p0;

.field public final g:Lcom/google/protobuf/c0;

.field public final h:Lcom/google/protobuf/e1;

.field public final i:Lcom/google/protobuf/j0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    sput-object v0, Lcom/google/protobuf/n0;->j:[I

    .line 5
    .line 6
    invoke-static {}, Lcom/google/protobuf/m1;->j()Lsun/misc/Unsafe;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>([I[Ljava/lang/Object;Lcom/google/protobuf/a;[IILcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/protobuf/n0;->a:[I

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/protobuf/n0;->b:[Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p4, p0, Lcom/google/protobuf/n0;->d:[I

    .line 9
    .line 10
    iput p5, p0, Lcom/google/protobuf/n0;->e:I

    .line 11
    .line 12
    iput-object p6, p0, Lcom/google/protobuf/n0;->f:Lcom/google/protobuf/p0;

    .line 13
    .line 14
    iput-object p7, p0, Lcom/google/protobuf/n0;->g:Lcom/google/protobuf/c0;

    .line 15
    .line 16
    iput-object p8, p0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 17
    .line 18
    iput-object p3, p0, Lcom/google/protobuf/n0;->c:Lcom/google/protobuf/a;

    .line 19
    .line 20
    iput-object p10, p0, Lcom/google/protobuf/n0;->i:Lcom/google/protobuf/j0;

    .line 21
    .line 22
    return-void
.end method

.method public static m(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p0, Lcom/google/protobuf/p;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p0, Lcom/google/protobuf/p;

    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/protobuf/p;->n()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_1
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public static q(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;
    .locals 1

    .line 1
    instance-of v0, p0, Lcom/google/protobuf/v0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static/range {p0 .. p5}, Lcom/google/protobuf/n0;->r(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    new-instance p0, Ljava/lang/ClassCastException;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public static r(Lcom/google/protobuf/v0;Lcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)Lcom/google/protobuf/n0;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/protobuf/v0;->b:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 11
    .line 12
    .line 13
    move-result v4

    .line 14
    const v6, 0xd800

    .line 15
    .line 16
    .line 17
    if-lt v4, v6, :cond_0

    .line 18
    .line 19
    const/4 v4, 0x1

    .line 20
    :goto_0
    add-int/lit8 v7, v4, 0x1

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-lt v4, v6, :cond_1

    .line 27
    .line 28
    move v4, v7

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v7, 0x1

    .line 31
    :cond_1
    add-int/lit8 v4, v7, 0x1

    .line 32
    .line 33
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    if-lt v7, v6, :cond_3

    .line 38
    .line 39
    and-int/lit16 v7, v7, 0x1fff

    .line 40
    .line 41
    const/16 v9, 0xd

    .line 42
    .line 43
    :goto_1
    add-int/lit8 v10, v4, 0x1

    .line 44
    .line 45
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-lt v4, v6, :cond_2

    .line 50
    .line 51
    and-int/lit16 v4, v4, 0x1fff

    .line 52
    .line 53
    shl-int/2addr v4, v9

    .line 54
    or-int/2addr v7, v4

    .line 55
    add-int/lit8 v9, v9, 0xd

    .line 56
    .line 57
    move v4, v10

    .line 58
    goto :goto_1

    .line 59
    :cond_2
    shl-int/2addr v4, v9

    .line 60
    or-int/2addr v7, v4

    .line 61
    move v4, v10

    .line 62
    :cond_3
    if-nez v7, :cond_4

    .line 63
    .line 64
    sget-object v7, Lcom/google/protobuf/n0;->j:[I

    .line 65
    .line 66
    move v9, v3

    .line 67
    move v10, v9

    .line 68
    move v11, v10

    .line 69
    move v14, v11

    .line 70
    move-object v13, v7

    .line 71
    move v7, v14

    .line 72
    goto/16 :goto_a

    .line 73
    .line 74
    :cond_4
    add-int/lit8 v7, v4, 0x1

    .line 75
    .line 76
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-lt v4, v6, :cond_6

    .line 81
    .line 82
    and-int/lit16 v4, v4, 0x1fff

    .line 83
    .line 84
    const/16 v9, 0xd

    .line 85
    .line 86
    :goto_2
    add-int/lit8 v10, v7, 0x1

    .line 87
    .line 88
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v7

    .line 92
    if-lt v7, v6, :cond_5

    .line 93
    .line 94
    and-int/lit16 v7, v7, 0x1fff

    .line 95
    .line 96
    shl-int/2addr v7, v9

    .line 97
    or-int/2addr v4, v7

    .line 98
    add-int/lit8 v9, v9, 0xd

    .line 99
    .line 100
    move v7, v10

    .line 101
    goto :goto_2

    .line 102
    :cond_5
    shl-int/2addr v7, v9

    .line 103
    or-int/2addr v4, v7

    .line 104
    move v7, v10

    .line 105
    :cond_6
    add-int/lit8 v9, v7, 0x1

    .line 106
    .line 107
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 108
    .line 109
    .line 110
    move-result v7

    .line 111
    if-lt v7, v6, :cond_8

    .line 112
    .line 113
    and-int/lit16 v7, v7, 0x1fff

    .line 114
    .line 115
    const/16 v10, 0xd

    .line 116
    .line 117
    :goto_3
    add-int/lit8 v11, v9, 0x1

    .line 118
    .line 119
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 120
    .line 121
    .line 122
    move-result v9

    .line 123
    if-lt v9, v6, :cond_7

    .line 124
    .line 125
    and-int/lit16 v9, v9, 0x1fff

    .line 126
    .line 127
    shl-int/2addr v9, v10

    .line 128
    or-int/2addr v7, v9

    .line 129
    add-int/lit8 v10, v10, 0xd

    .line 130
    .line 131
    move v9, v11

    .line 132
    goto :goto_3

    .line 133
    :cond_7
    shl-int/2addr v9, v10

    .line 134
    or-int/2addr v7, v9

    .line 135
    move v9, v11

    .line 136
    :cond_8
    add-int/lit8 v10, v9, 0x1

    .line 137
    .line 138
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 139
    .line 140
    .line 141
    move-result v9

    .line 142
    if-lt v9, v6, :cond_a

    .line 143
    .line 144
    :goto_4
    add-int/lit8 v9, v10, 0x1

    .line 145
    .line 146
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 147
    .line 148
    .line 149
    move-result v10

    .line 150
    if-lt v10, v6, :cond_9

    .line 151
    .line 152
    move v10, v9

    .line 153
    goto :goto_4

    .line 154
    :cond_9
    move v10, v9

    .line 155
    :cond_a
    add-int/lit8 v9, v10, 0x1

    .line 156
    .line 157
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 158
    .line 159
    .line 160
    move-result v10

    .line 161
    if-lt v10, v6, :cond_c

    .line 162
    .line 163
    :goto_5
    add-int/lit8 v10, v9, 0x1

    .line 164
    .line 165
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 166
    .line 167
    .line 168
    move-result v9

    .line 169
    if-lt v9, v6, :cond_b

    .line 170
    .line 171
    move v9, v10

    .line 172
    goto :goto_5

    .line 173
    :cond_b
    move v9, v10

    .line 174
    :cond_c
    add-int/lit8 v10, v9, 0x1

    .line 175
    .line 176
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    if-lt v9, v6, :cond_e

    .line 181
    .line 182
    and-int/lit16 v9, v9, 0x1fff

    .line 183
    .line 184
    const/16 v11, 0xd

    .line 185
    .line 186
    :goto_6
    add-int/lit8 v12, v10, 0x1

    .line 187
    .line 188
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 189
    .line 190
    .line 191
    move-result v10

    .line 192
    if-lt v10, v6, :cond_d

    .line 193
    .line 194
    and-int/lit16 v10, v10, 0x1fff

    .line 195
    .line 196
    shl-int/2addr v10, v11

    .line 197
    or-int/2addr v9, v10

    .line 198
    add-int/lit8 v11, v11, 0xd

    .line 199
    .line 200
    move v10, v12

    .line 201
    goto :goto_6

    .line 202
    :cond_d
    shl-int/2addr v10, v11

    .line 203
    or-int/2addr v9, v10

    .line 204
    move v10, v12

    .line 205
    :cond_e
    add-int/lit8 v11, v10, 0x1

    .line 206
    .line 207
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 208
    .line 209
    .line 210
    move-result v10

    .line 211
    if-lt v10, v6, :cond_10

    .line 212
    .line 213
    and-int/lit16 v10, v10, 0x1fff

    .line 214
    .line 215
    const/16 v12, 0xd

    .line 216
    .line 217
    :goto_7
    add-int/lit8 v13, v11, 0x1

    .line 218
    .line 219
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 220
    .line 221
    .line 222
    move-result v11

    .line 223
    if-lt v11, v6, :cond_f

    .line 224
    .line 225
    and-int/lit16 v11, v11, 0x1fff

    .line 226
    .line 227
    shl-int/2addr v11, v12

    .line 228
    or-int/2addr v10, v11

    .line 229
    add-int/lit8 v12, v12, 0xd

    .line 230
    .line 231
    move v11, v13

    .line 232
    goto :goto_7

    .line 233
    :cond_f
    shl-int/2addr v11, v12

    .line 234
    or-int/2addr v10, v11

    .line 235
    move v11, v13

    .line 236
    :cond_10
    add-int/lit8 v12, v11, 0x1

    .line 237
    .line 238
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 239
    .line 240
    .line 241
    move-result v11

    .line 242
    if-lt v11, v6, :cond_12

    .line 243
    .line 244
    and-int/lit16 v11, v11, 0x1fff

    .line 245
    .line 246
    const/16 v13, 0xd

    .line 247
    .line 248
    :goto_8
    add-int/lit8 v14, v12, 0x1

    .line 249
    .line 250
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 251
    .line 252
    .line 253
    move-result v12

    .line 254
    if-lt v12, v6, :cond_11

    .line 255
    .line 256
    and-int/lit16 v12, v12, 0x1fff

    .line 257
    .line 258
    shl-int/2addr v12, v13

    .line 259
    or-int/2addr v11, v12

    .line 260
    add-int/lit8 v13, v13, 0xd

    .line 261
    .line 262
    move v12, v14

    .line 263
    goto :goto_8

    .line 264
    :cond_11
    shl-int/2addr v12, v13

    .line 265
    or-int/2addr v11, v12

    .line 266
    move v12, v14

    .line 267
    :cond_12
    add-int/lit8 v13, v12, 0x1

    .line 268
    .line 269
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 270
    .line 271
    .line 272
    move-result v12

    .line 273
    if-lt v12, v6, :cond_14

    .line 274
    .line 275
    and-int/lit16 v12, v12, 0x1fff

    .line 276
    .line 277
    const/16 v14, 0xd

    .line 278
    .line 279
    :goto_9
    add-int/lit8 v15, v13, 0x1

    .line 280
    .line 281
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 282
    .line 283
    .line 284
    move-result v13

    .line 285
    if-lt v13, v6, :cond_13

    .line 286
    .line 287
    and-int/lit16 v13, v13, 0x1fff

    .line 288
    .line 289
    shl-int/2addr v13, v14

    .line 290
    or-int/2addr v12, v13

    .line 291
    add-int/lit8 v14, v14, 0xd

    .line 292
    .line 293
    move v13, v15

    .line 294
    goto :goto_9

    .line 295
    :cond_13
    shl-int/2addr v13, v14

    .line 296
    or-int/2addr v12, v13

    .line 297
    move v13, v15

    .line 298
    :cond_14
    add-int v14, v12, v10

    .line 299
    .line 300
    add-int/2addr v14, v11

    .line 301
    new-array v11, v14, [I

    .line 302
    .line 303
    mul-int/lit8 v14, v4, 0x2

    .line 304
    .line 305
    add-int/2addr v14, v7

    .line 306
    move v7, v4

    .line 307
    move v4, v13

    .line 308
    move-object v13, v11

    .line 309
    move v11, v14

    .line 310
    move v14, v12

    .line 311
    :goto_a
    sget-object v12, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 312
    .line 313
    iget-object v15, v0, Lcom/google/protobuf/v0;->c:[Ljava/lang/Object;

    .line 314
    .line 315
    iget-object v3, v0, Lcom/google/protobuf/v0;->a:Lcom/google/protobuf/a;

    .line 316
    .line 317
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 318
    .line 319
    .line 320
    move-result-object v3

    .line 321
    mul-int/lit8 v8, v9, 0x3

    .line 322
    .line 323
    new-array v8, v8, [I

    .line 324
    .line 325
    const/4 v5, 0x2

    .line 326
    mul-int/2addr v9, v5

    .line 327
    new-array v9, v9, [Ljava/lang/Object;

    .line 328
    .line 329
    add-int/2addr v10, v14

    .line 330
    move/from16 v21, v14

    .line 331
    .line 332
    const/4 v5, 0x0

    .line 333
    const/16 v19, 0x0

    .line 334
    .line 335
    :goto_b
    if-ge v4, v2, :cond_36

    .line 336
    .line 337
    add-int/lit8 v22, v4, 0x1

    .line 338
    .line 339
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 340
    .line 341
    .line 342
    move-result v4

    .line 343
    if-lt v4, v6, :cond_16

    .line 344
    .line 345
    and-int/lit16 v4, v4, 0x1fff

    .line 346
    .line 347
    move/from16 v6, v22

    .line 348
    .line 349
    const/16 v22, 0xd

    .line 350
    .line 351
    :goto_c
    add-int/lit8 v24, v6, 0x1

    .line 352
    .line 353
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 354
    .line 355
    .line 356
    move-result v6

    .line 357
    move/from16 v25, v2

    .line 358
    .line 359
    const v2, 0xd800

    .line 360
    .line 361
    .line 362
    if-lt v6, v2, :cond_15

    .line 363
    .line 364
    and-int/lit16 v2, v6, 0x1fff

    .line 365
    .line 366
    shl-int v2, v2, v22

    .line 367
    .line 368
    or-int/2addr v4, v2

    .line 369
    add-int/lit8 v22, v22, 0xd

    .line 370
    .line 371
    move/from16 v6, v24

    .line 372
    .line 373
    move/from16 v2, v25

    .line 374
    .line 375
    goto :goto_c

    .line 376
    :cond_15
    shl-int v2, v6, v22

    .line 377
    .line 378
    or-int/2addr v4, v2

    .line 379
    move/from16 v2, v24

    .line 380
    .line 381
    goto :goto_d

    .line 382
    :cond_16
    move/from16 v25, v2

    .line 383
    .line 384
    move/from16 v2, v22

    .line 385
    .line 386
    :goto_d
    add-int/lit8 v6, v2, 0x1

    .line 387
    .line 388
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 389
    .line 390
    .line 391
    move-result v2

    .line 392
    move/from16 v22, v4

    .line 393
    .line 394
    const v4, 0xd800

    .line 395
    .line 396
    .line 397
    if-lt v2, v4, :cond_18

    .line 398
    .line 399
    and-int/lit16 v2, v2, 0x1fff

    .line 400
    .line 401
    const/16 v24, 0xd

    .line 402
    .line 403
    :goto_e
    add-int/lit8 v26, v6, 0x1

    .line 404
    .line 405
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 406
    .line 407
    .line 408
    move-result v6

    .line 409
    if-lt v6, v4, :cond_17

    .line 410
    .line 411
    and-int/lit16 v4, v6, 0x1fff

    .line 412
    .line 413
    shl-int v4, v4, v24

    .line 414
    .line 415
    or-int/2addr v2, v4

    .line 416
    add-int/lit8 v24, v24, 0xd

    .line 417
    .line 418
    move/from16 v6, v26

    .line 419
    .line 420
    const v4, 0xd800

    .line 421
    .line 422
    .line 423
    goto :goto_e

    .line 424
    :cond_17
    shl-int v4, v6, v24

    .line 425
    .line 426
    or-int/2addr v2, v4

    .line 427
    move/from16 v6, v26

    .line 428
    .line 429
    :cond_18
    and-int/lit16 v4, v2, 0xff

    .line 430
    .line 431
    move/from16 v24, v7

    .line 432
    .line 433
    and-int/lit16 v7, v2, 0x400

    .line 434
    .line 435
    if-eqz v7, :cond_19

    .line 436
    .line 437
    add-int/lit8 v7, v19, 0x1

    .line 438
    .line 439
    aput v5, v13, v19

    .line 440
    .line 441
    move/from16 v19, v7

    .line 442
    .line 443
    :cond_19
    const/16 v7, 0x33

    .line 444
    .line 445
    move-object/from16 v28, v8

    .line 446
    .line 447
    if-lt v4, v7, :cond_23

    .line 448
    .line 449
    add-int/lit8 v7, v6, 0x1

    .line 450
    .line 451
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 452
    .line 453
    .line 454
    move-result v6

    .line 455
    const v8, 0xd800

    .line 456
    .line 457
    .line 458
    if-lt v6, v8, :cond_1b

    .line 459
    .line 460
    and-int/lit16 v6, v6, 0x1fff

    .line 461
    .line 462
    const/16 v30, 0xd

    .line 463
    .line 464
    :goto_f
    add-int/lit8 v31, v7, 0x1

    .line 465
    .line 466
    invoke-virtual {v1, v7}, Ljava/lang/String;->charAt(I)C

    .line 467
    .line 468
    .line 469
    move-result v7

    .line 470
    if-lt v7, v8, :cond_1a

    .line 471
    .line 472
    and-int/lit16 v7, v7, 0x1fff

    .line 473
    .line 474
    shl-int v7, v7, v30

    .line 475
    .line 476
    or-int/2addr v6, v7

    .line 477
    add-int/lit8 v30, v30, 0xd

    .line 478
    .line 479
    move/from16 v7, v31

    .line 480
    .line 481
    const v8, 0xd800

    .line 482
    .line 483
    .line 484
    goto :goto_f

    .line 485
    :cond_1a
    shl-int v7, v7, v30

    .line 486
    .line 487
    or-int/2addr v6, v7

    .line 488
    move/from16 v7, v31

    .line 489
    .line 490
    :cond_1b
    add-int/lit8 v8, v4, -0x33

    .line 491
    .line 492
    move/from16 v30, v6

    .line 493
    .line 494
    const/16 v6, 0x9

    .line 495
    .line 496
    if-eq v8, v6, :cond_1c

    .line 497
    .line 498
    const/16 v6, 0x11

    .line 499
    .line 500
    if-ne v8, v6, :cond_1d

    .line 501
    .line 502
    :cond_1c
    move/from16 v26, v7

    .line 503
    .line 504
    const/4 v6, 0x3

    .line 505
    const/4 v7, 0x2

    .line 506
    const/4 v8, 0x1

    .line 507
    goto :goto_12

    .line 508
    :cond_1d
    const/16 v6, 0xc

    .line 509
    .line 510
    if-ne v8, v6, :cond_20

    .line 511
    .line 512
    invoke-virtual {v0}, Lcom/google/protobuf/v0;->a()I

    .line 513
    .line 514
    .line 515
    move-result v6

    .line 516
    const/4 v8, 0x1

    .line 517
    invoke-static {v6, v8}, Lu/w;->a(II)Z

    .line 518
    .line 519
    .line 520
    move-result v6

    .line 521
    if-nez v6, :cond_1e

    .line 522
    .line 523
    and-int/lit16 v6, v2, 0x800

    .line 524
    .line 525
    if-eqz v6, :cond_1f

    .line 526
    .line 527
    :cond_1e
    move/from16 v26, v7

    .line 528
    .line 529
    const/4 v6, 0x3

    .line 530
    const/4 v7, 0x2

    .line 531
    goto :goto_11

    .line 532
    :cond_1f
    :goto_10
    move/from16 v26, v7

    .line 533
    .line 534
    const/4 v7, 0x2

    .line 535
    goto :goto_13

    .line 536
    :goto_11
    invoke-static {v5, v6, v7, v8}, La7/g0;->d(IIII)I

    .line 537
    .line 538
    .line 539
    move-result v6

    .line 540
    add-int/lit8 v18, v11, 0x1

    .line 541
    .line 542
    aget-object v11, v15, v11

    .line 543
    .line 544
    aput-object v11, v9, v6

    .line 545
    .line 546
    move/from16 v11, v18

    .line 547
    .line 548
    goto :goto_13

    .line 549
    :cond_20
    const/4 v8, 0x1

    .line 550
    goto :goto_10

    .line 551
    :goto_12
    invoke-static {v5, v6, v7, v8}, La7/g0;->d(IIII)I

    .line 552
    .line 553
    .line 554
    move-result v6

    .line 555
    add-int/lit8 v8, v11, 0x1

    .line 556
    .line 557
    aget-object v11, v15, v11

    .line 558
    .line 559
    aput-object v11, v9, v6

    .line 560
    .line 561
    move v11, v8

    .line 562
    :goto_13
    mul-int/lit8 v6, v30, 0x2

    .line 563
    .line 564
    aget-object v7, v15, v6

    .line 565
    .line 566
    instance-of v8, v7, Ljava/lang/reflect/Field;

    .line 567
    .line 568
    if-eqz v8, :cond_21

    .line 569
    .line 570
    check-cast v7, Ljava/lang/reflect/Field;

    .line 571
    .line 572
    goto :goto_14

    .line 573
    :cond_21
    check-cast v7, Ljava/lang/String;

    .line 574
    .line 575
    invoke-static {v3, v7}, Lcom/google/protobuf/n0;->u(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 576
    .line 577
    .line 578
    move-result-object v7

    .line 579
    aput-object v7, v15, v6

    .line 580
    .line 581
    :goto_14
    invoke-virtual {v12, v7}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 582
    .line 583
    .line 584
    move-result-wide v7

    .line 585
    long-to-int v7, v7

    .line 586
    add-int/lit8 v6, v6, 0x1

    .line 587
    .line 588
    aget-object v8, v15, v6

    .line 589
    .line 590
    move/from16 v27, v6

    .line 591
    .line 592
    instance-of v6, v8, Ljava/lang/reflect/Field;

    .line 593
    .line 594
    if-eqz v6, :cond_22

    .line 595
    .line 596
    check-cast v8, Ljava/lang/reflect/Field;

    .line 597
    .line 598
    :goto_15
    move/from16 v27, v7

    .line 599
    .line 600
    goto :goto_16

    .line 601
    :cond_22
    check-cast v8, Ljava/lang/String;

    .line 602
    .line 603
    invoke-static {v3, v8}, Lcom/google/protobuf/n0;->u(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 604
    .line 605
    .line 606
    move-result-object v8

    .line 607
    aput-object v8, v15, v27

    .line 608
    .line 609
    goto :goto_15

    .line 610
    :goto_16
    invoke-virtual {v12, v8}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 611
    .line 612
    .line 613
    move-result-wide v6

    .line 614
    long-to-int v6, v6

    .line 615
    move/from16 v18, v10

    .line 616
    .line 617
    move v8, v11

    .line 618
    move/from16 v10, v26

    .line 619
    .line 620
    move/from16 v7, v27

    .line 621
    .line 622
    const/16 v20, 0x2

    .line 623
    .line 624
    move v11, v5

    .line 625
    move v5, v6

    .line 626
    move-object/from16 v26, v9

    .line 627
    .line 628
    const/4 v6, 0x0

    .line 629
    goto/16 :goto_23

    .line 630
    .line 631
    :cond_23
    add-int/lit8 v7, v11, 0x1

    .line 632
    .line 633
    aget-object v8, v15, v11

    .line 634
    .line 635
    check-cast v8, Ljava/lang/String;

    .line 636
    .line 637
    invoke-static {v3, v8}, Lcom/google/protobuf/n0;->u(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 638
    .line 639
    .line 640
    move-result-object v8

    .line 641
    move/from16 v30, v7

    .line 642
    .line 643
    const/16 v7, 0x9

    .line 644
    .line 645
    if-eq v4, v7, :cond_24

    .line 646
    .line 647
    const/16 v7, 0x11

    .line 648
    .line 649
    if-ne v4, v7, :cond_25

    .line 650
    .line 651
    :cond_24
    move-object/from16 v26, v9

    .line 652
    .line 653
    move/from16 v18, v10

    .line 654
    .line 655
    const/4 v7, 0x3

    .line 656
    const/4 v9, 0x1

    .line 657
    const/4 v10, 0x2

    .line 658
    goto/16 :goto_1c

    .line 659
    .line 660
    :cond_25
    const/16 v7, 0x1b

    .line 661
    .line 662
    if-eq v4, v7, :cond_26

    .line 663
    .line 664
    const/16 v7, 0x31

    .line 665
    .line 666
    if-ne v4, v7, :cond_27

    .line 667
    .line 668
    :cond_26
    move-object/from16 v26, v9

    .line 669
    .line 670
    move/from16 v18, v10

    .line 671
    .line 672
    const/4 v7, 0x3

    .line 673
    const/4 v9, 0x1

    .line 674
    const/4 v10, 0x2

    .line 675
    goto/16 :goto_1b

    .line 676
    .line 677
    :cond_27
    const/16 v7, 0xc

    .line 678
    .line 679
    if-eq v4, v7, :cond_2b

    .line 680
    .line 681
    const/16 v7, 0x1e

    .line 682
    .line 683
    if-eq v4, v7, :cond_2b

    .line 684
    .line 685
    const/16 v7, 0x2c

    .line 686
    .line 687
    if-ne v4, v7, :cond_28

    .line 688
    .line 689
    goto :goto_18

    .line 690
    :cond_28
    const/16 v7, 0x32

    .line 691
    .line 692
    if-ne v4, v7, :cond_2a

    .line 693
    .line 694
    add-int/lit8 v7, v21, 0x1

    .line 695
    .line 696
    aput v5, v13, v21

    .line 697
    .line 698
    div-int/lit8 v21, v5, 0x3

    .line 699
    .line 700
    const/16 v20, 0x2

    .line 701
    .line 702
    mul-int/lit8 v21, v21, 0x2

    .line 703
    .line 704
    add-int/lit8 v26, v11, 0x2

    .line 705
    .line 706
    aget-object v27, v15, v30

    .line 707
    .line 708
    aput-object v27, v9, v21

    .line 709
    .line 710
    move/from16 v27, v7

    .line 711
    .line 712
    and-int/lit16 v7, v2, 0x800

    .line 713
    .line 714
    if-eqz v7, :cond_29

    .line 715
    .line 716
    add-int/lit8 v21, v21, 0x1

    .line 717
    .line 718
    add-int/lit8 v7, v11, 0x3

    .line 719
    .line 720
    aget-object v11, v15, v26

    .line 721
    .line 722
    aput-object v11, v9, v21

    .line 723
    .line 724
    move-object/from16 v26, v9

    .line 725
    .line 726
    move/from16 v18, v10

    .line 727
    .line 728
    move/from16 v21, v27

    .line 729
    .line 730
    :goto_17
    const/4 v9, 0x1

    .line 731
    goto :goto_1e

    .line 732
    :cond_29
    move/from16 v18, v10

    .line 733
    .line 734
    move/from16 v7, v26

    .line 735
    .line 736
    move/from16 v21, v27

    .line 737
    .line 738
    move-object/from16 v26, v9

    .line 739
    .line 740
    goto :goto_17

    .line 741
    :cond_2a
    move-object/from16 v26, v9

    .line 742
    .line 743
    move/from16 v18, v10

    .line 744
    .line 745
    const/4 v9, 0x1

    .line 746
    goto :goto_1d

    .line 747
    :cond_2b
    :goto_18
    invoke-virtual {v0}, Lcom/google/protobuf/v0;->a()I

    .line 748
    .line 749
    .line 750
    move-result v7

    .line 751
    move-object/from16 v26, v9

    .line 752
    .line 753
    const/4 v9, 0x1

    .line 754
    if-eq v7, v9, :cond_2c

    .line 755
    .line 756
    and-int/lit16 v7, v2, 0x800

    .line 757
    .line 758
    if-eqz v7, :cond_2d

    .line 759
    .line 760
    :cond_2c
    move/from16 v18, v10

    .line 761
    .line 762
    const/4 v7, 0x3

    .line 763
    const/4 v10, 0x2

    .line 764
    goto :goto_19

    .line 765
    :cond_2d
    move/from16 v18, v10

    .line 766
    .line 767
    goto :goto_1d

    .line 768
    :goto_19
    invoke-static {v5, v7, v10, v9}, La7/g0;->d(IIII)I

    .line 769
    .line 770
    .line 771
    move-result v7

    .line 772
    add-int/lit8 v11, v11, 0x2

    .line 773
    .line 774
    aget-object v20, v15, v30

    .line 775
    .line 776
    aput-object v20, v26, v7

    .line 777
    .line 778
    :goto_1a
    move v7, v11

    .line 779
    goto :goto_1e

    .line 780
    :goto_1b
    invoke-static {v5, v7, v10, v9}, La7/g0;->d(IIII)I

    .line 781
    .line 782
    .line 783
    move-result v7

    .line 784
    add-int/lit8 v11, v11, 0x2

    .line 785
    .line 786
    aget-object v20, v15, v30

    .line 787
    .line 788
    aput-object v20, v26, v7

    .line 789
    .line 790
    goto :goto_1a

    .line 791
    :goto_1c
    invoke-static {v5, v7, v10, v9}, La7/g0;->d(IIII)I

    .line 792
    .line 793
    .line 794
    move-result v7

    .line 795
    invoke-virtual {v8}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 796
    .line 797
    .line 798
    move-result-object v10

    .line 799
    aput-object v10, v26, v7

    .line 800
    .line 801
    :goto_1d
    move/from16 v7, v30

    .line 802
    .line 803
    :goto_1e
    invoke-virtual {v12, v8}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 804
    .line 805
    .line 806
    move-result-wide v10

    .line 807
    long-to-int v8, v10

    .line 808
    and-int/lit16 v10, v2, 0x1000

    .line 809
    .line 810
    if-eqz v10, :cond_31

    .line 811
    .line 812
    const/16 v10, 0x11

    .line 813
    .line 814
    if-gt v4, v10, :cond_31

    .line 815
    .line 816
    add-int/lit8 v10, v6, 0x1

    .line 817
    .line 818
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 819
    .line 820
    .line 821
    move-result v6

    .line 822
    const v11, 0xd800

    .line 823
    .line 824
    .line 825
    if-lt v6, v11, :cond_2f

    .line 826
    .line 827
    and-int/lit16 v6, v6, 0x1fff

    .line 828
    .line 829
    const/16 v23, 0xd

    .line 830
    .line 831
    :goto_1f
    add-int/lit8 v27, v10, 0x1

    .line 832
    .line 833
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 834
    .line 835
    .line 836
    move-result v10

    .line 837
    if-lt v10, v11, :cond_2e

    .line 838
    .line 839
    and-int/lit16 v10, v10, 0x1fff

    .line 840
    .line 841
    shl-int v10, v10, v23

    .line 842
    .line 843
    or-int/2addr v6, v10

    .line 844
    add-int/lit8 v23, v23, 0xd

    .line 845
    .line 846
    move/from16 v10, v27

    .line 847
    .line 848
    goto :goto_1f

    .line 849
    :cond_2e
    shl-int v10, v10, v23

    .line 850
    .line 851
    or-int/2addr v6, v10

    .line 852
    move/from16 v10, v27

    .line 853
    .line 854
    :cond_2f
    const/16 v20, 0x2

    .line 855
    .line 856
    mul-int/lit8 v23, v24, 0x2

    .line 857
    .line 858
    div-int/lit8 v27, v6, 0x20

    .line 859
    .line 860
    add-int v27, v27, v23

    .line 861
    .line 862
    aget-object v9, v15, v27

    .line 863
    .line 864
    instance-of v11, v9, Ljava/lang/reflect/Field;

    .line 865
    .line 866
    if-eqz v11, :cond_30

    .line 867
    .line 868
    check-cast v9, Ljava/lang/reflect/Field;

    .line 869
    .line 870
    :goto_20
    move v11, v5

    .line 871
    move/from16 v27, v6

    .line 872
    .line 873
    goto :goto_21

    .line 874
    :cond_30
    check-cast v9, Ljava/lang/String;

    .line 875
    .line 876
    invoke-static {v3, v9}, Lcom/google/protobuf/n0;->u(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 877
    .line 878
    .line 879
    move-result-object v9

    .line 880
    aput-object v9, v15, v27

    .line 881
    .line 882
    goto :goto_20

    .line 883
    :goto_21
    invoke-virtual {v12, v9}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 884
    .line 885
    .line 886
    move-result-wide v5

    .line 887
    long-to-int v5, v5

    .line 888
    rem-int/lit8 v6, v27, 0x20

    .line 889
    .line 890
    goto :goto_22

    .line 891
    :cond_31
    move v11, v5

    .line 892
    const/16 v20, 0x2

    .line 893
    .line 894
    const v5, 0xfffff

    .line 895
    .line 896
    .line 897
    move v10, v6

    .line 898
    const/4 v6, 0x0

    .line 899
    :goto_22
    const/16 v9, 0x12

    .line 900
    .line 901
    if-lt v4, v9, :cond_32

    .line 902
    .line 903
    const/16 v9, 0x31

    .line 904
    .line 905
    if-gt v4, v9, :cond_32

    .line 906
    .line 907
    add-int/lit8 v9, v18, 0x1

    .line 908
    .line 909
    aput v8, v13, v18

    .line 910
    .line 911
    move/from16 v18, v8

    .line 912
    .line 913
    move v8, v7

    .line 914
    move/from16 v7, v18

    .line 915
    .line 916
    move/from16 v18, v9

    .line 917
    .line 918
    goto :goto_23

    .line 919
    :cond_32
    move/from16 v32, v8

    .line 920
    .line 921
    move v8, v7

    .line 922
    move/from16 v7, v32

    .line 923
    .line 924
    :goto_23
    add-int/lit8 v9, v11, 0x1

    .line 925
    .line 926
    aput v22, v28, v11

    .line 927
    .line 928
    add-int/lit8 v22, v11, 0x2

    .line 929
    .line 930
    move-object/from16 v27, v1

    .line 931
    .line 932
    and-int/lit16 v1, v2, 0x200

    .line 933
    .line 934
    if-eqz v1, :cond_33

    .line 935
    .line 936
    const/high16 v1, 0x20000000

    .line 937
    .line 938
    goto :goto_24

    .line 939
    :cond_33
    const/4 v1, 0x0

    .line 940
    :goto_24
    move/from16 v29, v1

    .line 941
    .line 942
    and-int/lit16 v1, v2, 0x100

    .line 943
    .line 944
    if-eqz v1, :cond_34

    .line 945
    .line 946
    const/high16 v1, 0x10000000

    .line 947
    .line 948
    goto :goto_25

    .line 949
    :cond_34
    const/4 v1, 0x0

    .line 950
    :goto_25
    or-int v1, v29, v1

    .line 951
    .line 952
    and-int/lit16 v2, v2, 0x800

    .line 953
    .line 954
    if-eqz v2, :cond_35

    .line 955
    .line 956
    const/high16 v2, -0x80000000

    .line 957
    .line 958
    goto :goto_26

    .line 959
    :cond_35
    const/4 v2, 0x0

    .line 960
    :goto_26
    or-int/2addr v1, v2

    .line 961
    shl-int/lit8 v2, v4, 0x14

    .line 962
    .line 963
    or-int/2addr v1, v2

    .line 964
    or-int/2addr v1, v7

    .line 965
    aput v1, v28, v9

    .line 966
    .line 967
    add-int/lit8 v1, v11, 0x3

    .line 968
    .line 969
    shl-int/lit8 v2, v6, 0x14

    .line 970
    .line 971
    or-int/2addr v2, v5

    .line 972
    aput v2, v28, v22

    .line 973
    .line 974
    move v5, v1

    .line 975
    move v11, v8

    .line 976
    move v4, v10

    .line 977
    move/from16 v10, v18

    .line 978
    .line 979
    move/from16 v7, v24

    .line 980
    .line 981
    move/from16 v2, v25

    .line 982
    .line 983
    move-object/from16 v9, v26

    .line 984
    .line 985
    move-object/from16 v1, v27

    .line 986
    .line 987
    move-object/from16 v8, v28

    .line 988
    .line 989
    const v6, 0xd800

    .line 990
    .line 991
    .line 992
    goto/16 :goto_b

    .line 993
    .line 994
    :cond_36
    move-object/from16 v28, v8

    .line 995
    .line 996
    move-object/from16 v26, v9

    .line 997
    .line 998
    new-instance v9, Lcom/google/protobuf/n0;

    .line 999
    .line 1000
    iget-object v12, v0, Lcom/google/protobuf/v0;->a:Lcom/google/protobuf/a;

    .line 1001
    .line 1002
    move-object/from16 v15, p1

    .line 1003
    .line 1004
    move-object/from16 v16, p2

    .line 1005
    .line 1006
    move-object/from16 v17, p3

    .line 1007
    .line 1008
    move-object/from16 v18, p4

    .line 1009
    .line 1010
    move-object/from16 v19, p5

    .line 1011
    .line 1012
    move-object/from16 v11, v26

    .line 1013
    .line 1014
    move-object/from16 v10, v28

    .line 1015
    .line 1016
    invoke-direct/range {v9 .. v19}, Lcom/google/protobuf/n0;-><init>([I[Ljava/lang/Object;Lcom/google/protobuf/a;[IILcom/google/protobuf/p0;Lcom/google/protobuf/c0;Lcom/google/protobuf/e1;Lcom/google/protobuf/i;Lcom/google/protobuf/j0;)V

    .line 1017
    .line 1018
    .line 1019
    return-object v9
.end method

.method public static s(JLjava/lang/Object;)I
    .locals 1

    .line 1
    sget-object v0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static t(JLjava/lang/Object;)J
    .locals 1

    .line 1
    sget-object v0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Long;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    return-wide p0
.end method

.method public static u(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;
    .locals 5

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NoSuchFieldException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    invoke-virtual {p0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    aget-object v3, v0, v2

    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-virtual {p1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    return-object v3

    .line 27
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    new-instance v1, Ljava/lang/RuntimeException;

    .line 31
    .line 32
    const-string v2, "Field "

    .line 33
    .line 34
    const-string v3, " for "

    .line 35
    .line 36
    invoke-static {v2, p1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, " not found. Known fields are "

    .line 48
    .line 49
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-static {v0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v1
.end method

.method public static w(I)I
    .locals 1

    .line 1
    const/high16 v0, 0xff00000

    .line 2
    .line 3
    and-int/2addr p0, v0

    .line 4
    ushr-int/lit8 p0, p0, 0x14

    .line 5
    .line 6
    return p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 9

    .line 1
    invoke-static {p1}, Lcom/google/protobuf/n0;->m(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto/16 :goto_2

    .line 8
    .line 9
    :cond_0
    instance-of v0, p1, Lcom/google/protobuf/p;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    move-object v0, p1

    .line 15
    check-cast v0, Lcom/google/protobuf/p;

    .line 16
    .line 17
    const v2, 0x7fffffff

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v2}, Lcom/google/protobuf/p;->r(I)V

    .line 21
    .line 22
    .line 23
    iput v1, v0, Lcom/google/protobuf/a;->memoizedHashCode:I

    .line 24
    .line 25
    invoke-virtual {v0}, Lcom/google/protobuf/p;->o()V

    .line 26
    .line 27
    .line 28
    :cond_1
    iget-object v0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 29
    .line 30
    array-length v2, v0

    .line 31
    move v3, v1

    .line 32
    :goto_0
    if-ge v3, v2, :cond_5

    .line 33
    .line 34
    invoke-virtual {p0, v3}, Lcom/google/protobuf/n0;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    const v5, 0xfffff

    .line 39
    .line 40
    .line 41
    and-int/2addr v5, v4

    .line 42
    int-to-long v5, v5

    .line 43
    invoke-static {v4}, Lcom/google/protobuf/n0;->w(I)I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    const/16 v7, 0x9

    .line 48
    .line 49
    if-eq v4, v7, :cond_3

    .line 50
    .line 51
    const/16 v7, 0x3c

    .line 52
    .line 53
    if-eq v4, v7, :cond_2

    .line 54
    .line 55
    const/16 v7, 0x44

    .line 56
    .line 57
    if-eq v4, v7, :cond_2

    .line 58
    .line 59
    packed-switch v4, :pswitch_data_0

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :pswitch_0
    sget-object v4, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 64
    .line 65
    invoke-virtual {v4, p1, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    if-eqz v7, :cond_4

    .line 70
    .line 71
    iget-object v8, p0, Lcom/google/protobuf/n0;->i:Lcom/google/protobuf/j0;

    .line 72
    .line 73
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    move-object v8, v7

    .line 77
    check-cast v8, Lcom/google/protobuf/i0;

    .line 78
    .line 79
    iput-boolean v1, v8, Lcom/google/protobuf/i0;->d:Z

    .line 80
    .line 81
    invoke-virtual {v4, p1, v5, v6, v7}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    goto :goto_1

    .line 85
    :pswitch_1
    iget-object v4, p0, Lcom/google/protobuf/n0;->g:Lcom/google/protobuf/c0;

    .line 86
    .line 87
    invoke-virtual {v4, v5, v6, p1}, Lcom/google/protobuf/c0;->a(JLjava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    aget v4, v0, v3

    .line 92
    .line 93
    invoke-virtual {p0, v4, p1, v3}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    if-eqz v4, :cond_4

    .line 98
    .line 99
    invoke-virtual {p0, v3}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    sget-object v7, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 104
    .line 105
    invoke-virtual {v7, p1, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v5

    .line 109
    invoke-interface {v4, v5}, Lcom/google/protobuf/w0;->a(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_3
    :pswitch_2
    invoke-virtual {p0, v3, p1}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-eqz v4, :cond_4

    .line 118
    .line 119
    invoke-virtual {p0, v3}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    sget-object v7, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 124
    .line 125
    invoke-virtual {v7, p1, v5, v6}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    invoke-interface {v4, v5}, Lcom/google/protobuf/w0;->a(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_4
    :goto_1
    add-int/lit8 v3, v3, 0x3

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_5
    iget-object p0, p0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 136
    .line 137
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    check-cast p1, Lcom/google/protobuf/p;

    .line 141
    .line 142
    iget-object p0, p1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 143
    .line 144
    iget-boolean p1, p0, Lcom/google/protobuf/d1;->e:Z

    .line 145
    .line 146
    if-eqz p1, :cond_6

    .line 147
    .line 148
    iput-boolean v1, p0, Lcom/google/protobuf/d1;->e:Z

    .line 149
    .line 150
    :cond_6
    :goto_2
    return-void

    .line 151
    :pswitch_data_0
    .packed-switch 0x11
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Ljava/lang/Object;)Z
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const v6, 0xfffff

    .line 6
    .line 7
    .line 8
    const/4 v7, 0x0

    .line 9
    move v2, v6

    .line 10
    move v3, v7

    .line 11
    move v8, v3

    .line 12
    :goto_0
    iget v4, v0, Lcom/google/protobuf/n0;->e:I

    .line 13
    .line 14
    const/4 v5, 0x1

    .line 15
    if-ge v8, v4, :cond_e

    .line 16
    .line 17
    iget-object v4, v0, Lcom/google/protobuf/n0;->d:[I

    .line 18
    .line 19
    aget v4, v4, v8

    .line 20
    .line 21
    iget-object v9, v0, Lcom/google/protobuf/n0;->a:[I

    .line 22
    .line 23
    aget v10, v9, v4

    .line 24
    .line 25
    invoke-virtual {v0, v4}, Lcom/google/protobuf/n0;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result v11

    .line 29
    add-int/lit8 v12, v4, 0x2

    .line 30
    .line 31
    aget v9, v9, v12

    .line 32
    .line 33
    and-int v12, v9, v6

    .line 34
    .line 35
    ushr-int/lit8 v9, v9, 0x14

    .line 36
    .line 37
    shl-int/2addr v5, v9

    .line 38
    if-eq v12, v2, :cond_1

    .line 39
    .line 40
    if-eq v12, v6, :cond_0

    .line 41
    .line 42
    sget-object v2, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 43
    .line 44
    int-to-long v13, v12

    .line 45
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    :cond_0
    move v2, v4

    .line 50
    move v4, v3

    .line 51
    move v3, v12

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v15, v3

    .line 54
    move v3, v2

    .line 55
    move v2, v4

    .line 56
    move v4, v15

    .line 57
    :goto_1
    const/high16 v9, 0x10000000

    .line 58
    .line 59
    and-int/2addr v9, v11

    .line 60
    if-eqz v9, :cond_2

    .line 61
    .line 62
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    if-nez v9, :cond_2

    .line 67
    .line 68
    goto/16 :goto_3

    .line 69
    .line 70
    :cond_2
    invoke-static {v11}, Lcom/google/protobuf/n0;->w(I)I

    .line 71
    .line 72
    .line 73
    move-result v9

    .line 74
    const/16 v12, 0x9

    .line 75
    .line 76
    if-eq v9, v12, :cond_c

    .line 77
    .line 78
    const/16 v12, 0x11

    .line 79
    .line 80
    if-eq v9, v12, :cond_c

    .line 81
    .line 82
    const/16 v5, 0x1b

    .line 83
    .line 84
    if-eq v9, v5, :cond_9

    .line 85
    .line 86
    const/16 v5, 0x3c

    .line 87
    .line 88
    if-eq v9, v5, :cond_8

    .line 89
    .line 90
    const/16 v5, 0x44

    .line 91
    .line 92
    if-eq v9, v5, :cond_8

    .line 93
    .line 94
    const/16 v5, 0x31

    .line 95
    .line 96
    if-eq v9, v5, :cond_9

    .line 97
    .line 98
    const/16 v5, 0x32

    .line 99
    .line 100
    if-eq v9, v5, :cond_3

    .line 101
    .line 102
    goto/16 :goto_4

    .line 103
    .line 104
    :cond_3
    and-int v5, v11, v6

    .line 105
    .line 106
    int-to-long v9, v5

    .line 107
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 108
    .line 109
    invoke-virtual {v5, v1, v9, v10}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    iget-object v9, v0, Lcom/google/protobuf/n0;->i:Lcom/google/protobuf/j0;

    .line 114
    .line 115
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    check-cast v5, Lcom/google/protobuf/i0;

    .line 119
    .line 120
    invoke-virtual {v5}, Ljava/util/HashMap;->isEmpty()Z

    .line 121
    .line 122
    .line 123
    move-result v9

    .line 124
    if-eqz v9, :cond_4

    .line 125
    .line 126
    goto/16 :goto_4

    .line 127
    .line 128
    :cond_4
    div-int/lit8 v2, v2, 0x3

    .line 129
    .line 130
    mul-int/lit8 v2, v2, 0x2

    .line 131
    .line 132
    iget-object v9, v0, Lcom/google/protobuf/n0;->b:[Ljava/lang/Object;

    .line 133
    .line 134
    aget-object v2, v9, v2

    .line 135
    .line 136
    check-cast v2, Lcom/google/protobuf/h0;

    .line 137
    .line 138
    iget-object v2, v2, Lcom/google/protobuf/h0;->a:Lcom/google/protobuf/g0;

    .line 139
    .line 140
    iget-object v2, v2, Lcom/google/protobuf/g0;->b:Lcom/google/protobuf/u1;

    .line 141
    .line 142
    iget-object v2, v2, Lcom/google/protobuf/u1;->d:Lcom/google/protobuf/v1;

    .line 143
    .line 144
    sget-object v9, Lcom/google/protobuf/v1;->l:Lcom/google/protobuf/v1;

    .line 145
    .line 146
    if-eq v2, v9, :cond_5

    .line 147
    .line 148
    goto/16 :goto_4

    .line 149
    .line 150
    :cond_5
    invoke-virtual {v5}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    const/4 v5, 0x0

    .line 159
    :cond_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    if-eqz v9, :cond_d

    .line 164
    .line 165
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v9

    .line 169
    if-nez v5, :cond_7

    .line 170
    .line 171
    sget-object v5, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 172
    .line 173
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    move-result-object v10

    .line 177
    invoke-virtual {v5, v10}, Lcom/google/protobuf/t0;->a(Ljava/lang/Class;)Lcom/google/protobuf/w0;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    :cond_7
    invoke-interface {v5, v9}, Lcom/google/protobuf/w0;->b(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v9

    .line 185
    if-nez v9, :cond_6

    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_8
    invoke-virtual {v0, v10, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 189
    .line 190
    .line 191
    move-result v5

    .line 192
    if-eqz v5, :cond_d

    .line 193
    .line 194
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    and-int v5, v11, v6

    .line 199
    .line 200
    int-to-long v9, v5

    .line 201
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 202
    .line 203
    invoke-virtual {v5, v1, v9, v10}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v5

    .line 207
    invoke-interface {v2, v5}, Lcom/google/protobuf/w0;->b(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v2

    .line 211
    if-nez v2, :cond_d

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_9
    and-int v5, v11, v6

    .line 215
    .line 216
    int-to-long v9, v5

    .line 217
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 218
    .line 219
    invoke-virtual {v5, v1, v9, v10}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v5

    .line 223
    check-cast v5, Ljava/util/List;

    .line 224
    .line 225
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 226
    .line 227
    .line 228
    move-result v9

    .line 229
    if-eqz v9, :cond_a

    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_a
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    move v9, v7

    .line 237
    :goto_2
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 238
    .line 239
    .line 240
    move-result v10

    .line 241
    if-ge v9, v10, :cond_d

    .line 242
    .line 243
    invoke-interface {v5, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v10

    .line 247
    invoke-interface {v2, v10}, Lcom/google/protobuf/w0;->b(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v10

    .line 251
    if-nez v10, :cond_b

    .line 252
    .line 253
    goto :goto_3

    .line 254
    :cond_b
    add-int/lit8 v9, v9, 0x1

    .line 255
    .line 256
    goto :goto_2

    .line 257
    :cond_c
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 258
    .line 259
    .line 260
    move-result v5

    .line 261
    if-eqz v5, :cond_d

    .line 262
    .line 263
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    and-int v5, v11, v6

    .line 268
    .line 269
    int-to-long v9, v5

    .line 270
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 271
    .line 272
    invoke-virtual {v5, v1, v9, v10}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v5

    .line 276
    invoke-interface {v2, v5}, Lcom/google/protobuf/w0;->b(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v2

    .line 280
    if-nez v2, :cond_d

    .line 281
    .line 282
    :goto_3
    return v7

    .line 283
    :cond_d
    :goto_4
    add-int/lit8 v8, v8, 0x1

    .line 284
    .line 285
    move v2, v3

    .line 286
    move v3, v4

    .line 287
    goto/16 :goto_0

    .line 288
    .line 289
    :cond_e
    return v5
.end method

.method public final c()Lcom/google/protobuf/p;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n0;->f:Lcom/google/protobuf/p0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/protobuf/n0;->c:Lcom/google/protobuf/a;

    .line 7
    .line 8
    check-cast p0, Lcom/google/protobuf/p;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-virtual {p0, v0}, Lcom/google/protobuf/p;->k(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lcom/google/protobuf/p;

    .line 16
    .line 17
    return-object p0
.end method

.method public final d(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 13

    .line 1
    invoke-static {p1}, Lcom/google/protobuf/n0;->m(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_5

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    :goto_0
    iget-object v1, p0, Lcom/google/protobuf/n0;->a:[I

    .line 12
    .line 13
    array-length v2, v1

    .line 14
    if-ge v0, v2, :cond_4

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lcom/google/protobuf/n0;->x(I)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const v3, 0xfffff

    .line 21
    .line 22
    .line 23
    and-int v4, v2, v3

    .line 24
    .line 25
    int-to-long v6, v4

    .line 26
    aget v4, v1, v0

    .line 27
    .line 28
    invoke-static {v2}, Lcom/google/protobuf/n0;->w(I)I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    packed-switch v2, :pswitch_data_0

    .line 33
    .line 34
    .line 35
    goto :goto_1

    .line 36
    :pswitch_0
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/protobuf/n0;->p(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_0
    :goto_1
    move-object v8, p1

    .line 40
    goto/16 :goto_2

    .line 41
    .line 42
    :pswitch_1
    invoke-virtual {p0, v4, p2, v0}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    sget-object v2, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 49
    .line 50
    invoke-virtual {v2, p2, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-static {p1, v6, v7, v2}, Lcom/google/protobuf/m1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    add-int/lit8 v2, v0, 0x2

    .line 58
    .line 59
    aget v1, v1, v2

    .line 60
    .line 61
    and-int/2addr v1, v3

    .line 62
    int-to-long v1, v1

    .line 63
    invoke-static {v1, v2, p1, v4}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :pswitch_2
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/protobuf/n0;->p(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :pswitch_3
    invoke-virtual {p0, v4, p2, v0}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-eqz v2, :cond_0

    .line 76
    .line 77
    sget-object v2, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 78
    .line 79
    invoke-virtual {v2, p2, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    invoke-static {p1, v6, v7, v2}, Lcom/google/protobuf/m1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    add-int/lit8 v2, v0, 0x2

    .line 87
    .line 88
    aget v1, v1, v2

    .line 89
    .line 90
    and-int/2addr v1, v3

    .line 91
    int-to-long v1, v1

    .line 92
    invoke-static {v1, v2, p1, v4}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :pswitch_4
    sget-object v1, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 97
    .line 98
    sget-object v1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 99
    .line 100
    invoke-virtual {v1, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    iget-object v3, p0, Lcom/google/protobuf/n0;->i:Lcom/google/protobuf/j0;

    .line 109
    .line 110
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    check-cast v2, Lcom/google/protobuf/i0;

    .line 114
    .line 115
    check-cast v1, Lcom/google/protobuf/i0;

    .line 116
    .line 117
    invoke-virtual {v1}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-nez v3, :cond_2

    .line 122
    .line 123
    iget-boolean v3, v2, Lcom/google/protobuf/i0;->d:Z

    .line 124
    .line 125
    if-nez v3, :cond_1

    .line 126
    .line 127
    invoke-virtual {v2}, Lcom/google/protobuf/i0;->c()Lcom/google/protobuf/i0;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    :cond_1
    invoke-virtual {v2}, Lcom/google/protobuf/i0;->b()V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    if-nez v3, :cond_2

    .line 139
    .line 140
    invoke-virtual {v2, v1}, Lcom/google/protobuf/i0;->putAll(Ljava/util/Map;)V

    .line 141
    .line 142
    .line 143
    :cond_2
    invoke-static {p1, v6, v7, v2}, Lcom/google/protobuf/m1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    goto :goto_1

    .line 147
    :pswitch_5
    iget-object v1, p0, Lcom/google/protobuf/n0;->g:Lcom/google/protobuf/c0;

    .line 148
    .line 149
    invoke-virtual {v1, p1, v6, v7, p2}, Lcom/google/protobuf/c0;->b(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    goto :goto_1

    .line 153
    :pswitch_6
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/protobuf/n0;->o(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_1

    .line 157
    :pswitch_7
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v1

    .line 161
    if-eqz v1, :cond_0

    .line 162
    .line 163
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 164
    .line 165
    invoke-virtual {v5, p2, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 166
    .line 167
    .line 168
    move-result-wide v9

    .line 169
    move-object v8, p1

    .line 170
    invoke-virtual/range {v5 .. v10}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    goto/16 :goto_2

    .line 177
    .line 178
    :pswitch_8
    move-object v8, p1

    .line 179
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result p1

    .line 183
    if-eqz p1, :cond_3

    .line 184
    .line 185
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 186
    .line 187
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 188
    .line 189
    .line 190
    move-result p1

    .line 191
    invoke-static {v6, v7, v8, p1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    goto/16 :goto_2

    .line 198
    .line 199
    :pswitch_9
    move-object v8, p1

    .line 200
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result p1

    .line 204
    if-eqz p1, :cond_3

    .line 205
    .line 206
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 207
    .line 208
    invoke-virtual {v5, p2, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 209
    .line 210
    .line 211
    move-result-wide v9

    .line 212
    invoke-virtual/range {v5 .. v10}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    goto/16 :goto_2

    .line 219
    .line 220
    :pswitch_a
    move-object v8, p1

    .line 221
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result p1

    .line 225
    if-eqz p1, :cond_3

    .line 226
    .line 227
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 228
    .line 229
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 230
    .line 231
    .line 232
    move-result p1

    .line 233
    invoke-static {v6, v7, v8, p1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    goto/16 :goto_2

    .line 240
    .line 241
    :pswitch_b
    move-object v8, p1

    .line 242
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result p1

    .line 246
    if-eqz p1, :cond_3

    .line 247
    .line 248
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 249
    .line 250
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 251
    .line 252
    .line 253
    move-result p1

    .line 254
    invoke-static {v6, v7, v8, p1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    goto/16 :goto_2

    .line 261
    .line 262
    :pswitch_c
    move-object v8, p1

    .line 263
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result p1

    .line 267
    if-eqz p1, :cond_3

    .line 268
    .line 269
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 270
    .line 271
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 272
    .line 273
    .line 274
    move-result p1

    .line 275
    invoke-static {v6, v7, v8, p1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    goto/16 :goto_2

    .line 282
    .line 283
    :pswitch_d
    move-object v8, p1

    .line 284
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result p1

    .line 288
    if-eqz p1, :cond_3

    .line 289
    .line 290
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 291
    .line 292
    invoke-virtual {p1, p2, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object p1

    .line 296
    invoke-static {v8, v6, v7, p1}, Lcom/google/protobuf/m1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    goto/16 :goto_2

    .line 303
    .line 304
    :pswitch_e
    move-object v8, p1

    .line 305
    invoke-virtual {p0, v0, v8, p2}, Lcom/google/protobuf/n0;->o(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 306
    .line 307
    .line 308
    goto/16 :goto_2

    .line 309
    .line 310
    :pswitch_f
    move-object v8, p1

    .line 311
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result p1

    .line 315
    if-eqz p1, :cond_3

    .line 316
    .line 317
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 318
    .line 319
    invoke-virtual {p1, p2, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object p1

    .line 323
    invoke-static {v8, v6, v7, p1}, Lcom/google/protobuf/m1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    goto/16 :goto_2

    .line 330
    .line 331
    :pswitch_10
    move-object v8, p1

    .line 332
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 333
    .line 334
    .line 335
    move-result p1

    .line 336
    if-eqz p1, :cond_3

    .line 337
    .line 338
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 339
    .line 340
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->c(JLjava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v1

    .line 344
    invoke-virtual {p1, v8, v6, v7, v1}, Lcom/google/protobuf/l1;->k(Ljava/lang/Object;JZ)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 348
    .line 349
    .line 350
    goto/16 :goto_2

    .line 351
    .line 352
    :pswitch_11
    move-object v8, p1

    .line 353
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    move-result p1

    .line 357
    if-eqz p1, :cond_3

    .line 358
    .line 359
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 360
    .line 361
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 362
    .line 363
    .line 364
    move-result p1

    .line 365
    invoke-static {v6, v7, v8, p1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    goto/16 :goto_2

    .line 372
    .line 373
    :pswitch_12
    move-object v8, p1

    .line 374
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 375
    .line 376
    .line 377
    move-result p1

    .line 378
    if-eqz p1, :cond_3

    .line 379
    .line 380
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 381
    .line 382
    invoke-virtual {v5, p2, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 383
    .line 384
    .line 385
    move-result-wide v9

    .line 386
    invoke-virtual/range {v5 .. v10}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 390
    .line 391
    .line 392
    goto/16 :goto_2

    .line 393
    .line 394
    :pswitch_13
    move-object v8, p1

    .line 395
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 396
    .line 397
    .line 398
    move-result p1

    .line 399
    if-eqz p1, :cond_3

    .line 400
    .line 401
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 402
    .line 403
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 404
    .line 405
    .line 406
    move-result p1

    .line 407
    invoke-static {v6, v7, v8, p1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 411
    .line 412
    .line 413
    goto :goto_2

    .line 414
    :pswitch_14
    move-object v8, p1

    .line 415
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 416
    .line 417
    .line 418
    move-result p1

    .line 419
    if-eqz p1, :cond_3

    .line 420
    .line 421
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 422
    .line 423
    invoke-virtual {v5, p2, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 424
    .line 425
    .line 426
    move-result-wide v9

    .line 427
    invoke-virtual/range {v5 .. v10}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 428
    .line 429
    .line 430
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    goto :goto_2

    .line 434
    :pswitch_15
    move-object v8, p1

    .line 435
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 436
    .line 437
    .line 438
    move-result p1

    .line 439
    if-eqz p1, :cond_3

    .line 440
    .line 441
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 442
    .line 443
    invoke-virtual {v5, p2, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 444
    .line 445
    .line 446
    move-result-wide v9

    .line 447
    invoke-virtual/range {v5 .. v10}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 448
    .line 449
    .line 450
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 451
    .line 452
    .line 453
    goto :goto_2

    .line 454
    :pswitch_16
    move-object v8, p1

    .line 455
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 456
    .line 457
    .line 458
    move-result p1

    .line 459
    if-eqz p1, :cond_3

    .line 460
    .line 461
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 462
    .line 463
    invoke-virtual {p1, v6, v7, p2}, Lcom/google/protobuf/l1;->f(JLjava/lang/Object;)F

    .line 464
    .line 465
    .line 466
    move-result v1

    .line 467
    invoke-virtual {p1, v8, v6, v7, v1}, Lcom/google/protobuf/l1;->n(Ljava/lang/Object;JF)V

    .line 468
    .line 469
    .line 470
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    goto :goto_2

    .line 474
    :pswitch_17
    move-object v8, p1

    .line 475
    invoke-virtual {p0, v0, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    move-result p1

    .line 479
    if-eqz p1, :cond_3

    .line 480
    .line 481
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 482
    .line 483
    invoke-virtual {v5, v6, v7, p2}, Lcom/google/protobuf/l1;->e(JLjava/lang/Object;)D

    .line 484
    .line 485
    .line 486
    move-result-wide v9

    .line 487
    move-wide v11, v6

    .line 488
    move-object v6, v8

    .line 489
    move-wide v7, v11

    .line 490
    invoke-virtual/range {v5 .. v10}, Lcom/google/protobuf/l1;->m(Ljava/lang/Object;JD)V

    .line 491
    .line 492
    .line 493
    move-object v8, v6

    .line 494
    invoke-virtual {p0, v0, v8}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 495
    .line 496
    .line 497
    :cond_3
    :goto_2
    add-int/lit8 v0, v0, 0x3

    .line 498
    .line 499
    move-object p1, v8

    .line 500
    goto/16 :goto_0

    .line 501
    .line 502
    :cond_4
    move-object v8, p1

    .line 503
    iget-object p0, p0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 504
    .line 505
    invoke-static {p0, v8, p2}, Lcom/google/protobuf/x0;->j(Lcom/google/protobuf/e1;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 506
    .line 507
    .line 508
    return-void

    .line 509
    :cond_5
    move-object v8, p1

    .line 510
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 511
    .line 512
    const-string p1, "Mutating immutable message: "

    .line 513
    .line 514
    invoke-static {v8, p1}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 515
    .line 516
    .line 517
    move-result-object p1

    .line 518
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 519
    .line 520
    .line 521
    throw p0

    .line 522
    nop

    .line 523
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Ljava/lang/Object;Lcom/google/protobuf/f0;)V
    .locals 0

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/n0;->y(Ljava/lang/Object;Lcom/google/protobuf/f0;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final f(Lcom/google/protobuf/p;)I
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    if-ge v2, v1, :cond_3

    .line 7
    .line 8
    invoke-virtual {p0, v2}, Lcom/google/protobuf/n0;->x(I)I

    .line 9
    .line 10
    .line 11
    move-result v4

    .line 12
    aget v5, v0, v2

    .line 13
    .line 14
    const v6, 0xfffff

    .line 15
    .line 16
    .line 17
    and-int/2addr v6, v4

    .line 18
    int-to-long v6, v6

    .line 19
    invoke-static {v4}, Lcom/google/protobuf/n0;->w(I)I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    const/16 v8, 0x4d5

    .line 24
    .line 25
    const/16 v9, 0x4cf

    .line 26
    .line 27
    const/16 v10, 0x25

    .line 28
    .line 29
    packed-switch v4, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    goto/16 :goto_4

    .line 33
    .line 34
    :pswitch_0
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 41
    .line 42
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    mul-int/lit8 v3, v3, 0x35

    .line 47
    .line 48
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    :goto_1
    add-int/2addr v4, v3

    .line 53
    move v3, v4

    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :pswitch_1
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_2

    .line 61
    .line 62
    mul-int/lit8 v3, v3, 0x35

    .line 63
    .line 64
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 65
    .line 66
    .line 67
    move-result-wide v4

    .line 68
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    goto :goto_1

    .line 73
    :pswitch_2
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_2

    .line 78
    .line 79
    mul-int/lit8 v3, v3, 0x35

    .line 80
    .line 81
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    goto :goto_1

    .line 86
    :pswitch_3
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_2

    .line 91
    .line 92
    mul-int/lit8 v3, v3, 0x35

    .line 93
    .line 94
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 95
    .line 96
    .line 97
    move-result-wide v4

    .line 98
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    goto :goto_1

    .line 103
    :pswitch_4
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    if-eqz v4, :cond_2

    .line 108
    .line 109
    mul-int/lit8 v3, v3, 0x35

    .line 110
    .line 111
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    goto :goto_1

    .line 116
    :pswitch_5
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    if-eqz v4, :cond_2

    .line 121
    .line 122
    mul-int/lit8 v3, v3, 0x35

    .line 123
    .line 124
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    goto :goto_1

    .line 129
    :pswitch_6
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-eqz v4, :cond_2

    .line 134
    .line 135
    mul-int/lit8 v3, v3, 0x35

    .line 136
    .line 137
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    goto :goto_1

    .line 142
    :pswitch_7
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-eqz v4, :cond_2

    .line 147
    .line 148
    mul-int/lit8 v3, v3, 0x35

    .line 149
    .line 150
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 151
    .line 152
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    goto :goto_1

    .line 161
    :pswitch_8
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_2

    .line 166
    .line 167
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 168
    .line 169
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    mul-int/lit8 v3, v3, 0x35

    .line 174
    .line 175
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    goto :goto_1

    .line 180
    :pswitch_9
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    if-eqz v4, :cond_2

    .line 185
    .line 186
    mul-int/lit8 v3, v3, 0x35

    .line 187
    .line 188
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 189
    .line 190
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    check-cast v4, Ljava/lang/String;

    .line 195
    .line 196
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    goto/16 :goto_1

    .line 201
    .line 202
    :pswitch_a
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 203
    .line 204
    .line 205
    move-result v4

    .line 206
    if-eqz v4, :cond_2

    .line 207
    .line 208
    mul-int/lit8 v3, v3, 0x35

    .line 209
    .line 210
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 211
    .line 212
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    check-cast v4, Ljava/lang/Boolean;

    .line 217
    .line 218
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    sget-object v5, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 223
    .line 224
    if-eqz v4, :cond_0

    .line 225
    .line 226
    :goto_2
    move v8, v9

    .line 227
    :cond_0
    add-int/2addr v8, v3

    .line 228
    move v3, v8

    .line 229
    goto/16 :goto_4

    .line 230
    .line 231
    :pswitch_b
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 232
    .line 233
    .line 234
    move-result v4

    .line 235
    if-eqz v4, :cond_2

    .line 236
    .line 237
    mul-int/lit8 v3, v3, 0x35

    .line 238
    .line 239
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 240
    .line 241
    .line 242
    move-result v4

    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :pswitch_c
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    if-eqz v4, :cond_2

    .line 250
    .line 251
    mul-int/lit8 v3, v3, 0x35

    .line 252
    .line 253
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 254
    .line 255
    .line 256
    move-result-wide v4

    .line 257
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    goto/16 :goto_1

    .line 262
    .line 263
    :pswitch_d
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 264
    .line 265
    .line 266
    move-result v4

    .line 267
    if-eqz v4, :cond_2

    .line 268
    .line 269
    mul-int/lit8 v3, v3, 0x35

    .line 270
    .line 271
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 272
    .line 273
    .line 274
    move-result v4

    .line 275
    goto/16 :goto_1

    .line 276
    .line 277
    :pswitch_e
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 278
    .line 279
    .line 280
    move-result v4

    .line 281
    if-eqz v4, :cond_2

    .line 282
    .line 283
    mul-int/lit8 v3, v3, 0x35

    .line 284
    .line 285
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 286
    .line 287
    .line 288
    move-result-wide v4

    .line 289
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 290
    .line 291
    .line 292
    move-result v4

    .line 293
    goto/16 :goto_1

    .line 294
    .line 295
    :pswitch_f
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 296
    .line 297
    .line 298
    move-result v4

    .line 299
    if-eqz v4, :cond_2

    .line 300
    .line 301
    mul-int/lit8 v3, v3, 0x35

    .line 302
    .line 303
    invoke-static {v6, v7, p1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 304
    .line 305
    .line 306
    move-result-wide v4

    .line 307
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    goto/16 :goto_1

    .line 312
    .line 313
    :pswitch_10
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 314
    .line 315
    .line 316
    move-result v4

    .line 317
    if-eqz v4, :cond_2

    .line 318
    .line 319
    mul-int/lit8 v3, v3, 0x35

    .line 320
    .line 321
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 322
    .line 323
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v4

    .line 327
    check-cast v4, Ljava/lang/Float;

    .line 328
    .line 329
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 330
    .line 331
    .line 332
    move-result v4

    .line 333
    invoke-static {v4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 334
    .line 335
    .line 336
    move-result v4

    .line 337
    goto/16 :goto_1

    .line 338
    .line 339
    :pswitch_11
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 340
    .line 341
    .line 342
    move-result v4

    .line 343
    if-eqz v4, :cond_2

    .line 344
    .line 345
    mul-int/lit8 v3, v3, 0x35

    .line 346
    .line 347
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 348
    .line 349
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v4

    .line 353
    check-cast v4, Ljava/lang/Double;

    .line 354
    .line 355
    invoke-virtual {v4}, Ljava/lang/Double;->doubleValue()D

    .line 356
    .line 357
    .line 358
    move-result-wide v4

    .line 359
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 360
    .line 361
    .line 362
    move-result-wide v4

    .line 363
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 364
    .line 365
    .line 366
    move-result v4

    .line 367
    goto/16 :goto_1

    .line 368
    .line 369
    :pswitch_12
    mul-int/lit8 v3, v3, 0x35

    .line 370
    .line 371
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 372
    .line 373
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v4

    .line 377
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 378
    .line 379
    .line 380
    move-result v4

    .line 381
    goto/16 :goto_1

    .line 382
    .line 383
    :pswitch_13
    mul-int/lit8 v3, v3, 0x35

    .line 384
    .line 385
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 386
    .line 387
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v4

    .line 391
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    goto/16 :goto_1

    .line 396
    .line 397
    :pswitch_14
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 398
    .line 399
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v4

    .line 403
    if-eqz v4, :cond_1

    .line 404
    .line 405
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 406
    .line 407
    .line 408
    move-result v10

    .line 409
    :cond_1
    :goto_3
    mul-int/lit8 v3, v3, 0x35

    .line 410
    .line 411
    add-int/2addr v3, v10

    .line 412
    goto/16 :goto_4

    .line 413
    .line 414
    :pswitch_15
    mul-int/lit8 v3, v3, 0x35

    .line 415
    .line 416
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 417
    .line 418
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 419
    .line 420
    .line 421
    move-result-wide v4

    .line 422
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 423
    .line 424
    .line 425
    move-result v4

    .line 426
    goto/16 :goto_1

    .line 427
    .line 428
    :pswitch_16
    mul-int/lit8 v3, v3, 0x35

    .line 429
    .line 430
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 431
    .line 432
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 433
    .line 434
    .line 435
    move-result v4

    .line 436
    goto/16 :goto_1

    .line 437
    .line 438
    :pswitch_17
    mul-int/lit8 v3, v3, 0x35

    .line 439
    .line 440
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 441
    .line 442
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 443
    .line 444
    .line 445
    move-result-wide v4

    .line 446
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 447
    .line 448
    .line 449
    move-result v4

    .line 450
    goto/16 :goto_1

    .line 451
    .line 452
    :pswitch_18
    mul-int/lit8 v3, v3, 0x35

    .line 453
    .line 454
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 455
    .line 456
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 457
    .line 458
    .line 459
    move-result v4

    .line 460
    goto/16 :goto_1

    .line 461
    .line 462
    :pswitch_19
    mul-int/lit8 v3, v3, 0x35

    .line 463
    .line 464
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 465
    .line 466
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 467
    .line 468
    .line 469
    move-result v4

    .line 470
    goto/16 :goto_1

    .line 471
    .line 472
    :pswitch_1a
    mul-int/lit8 v3, v3, 0x35

    .line 473
    .line 474
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 475
    .line 476
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 477
    .line 478
    .line 479
    move-result v4

    .line 480
    goto/16 :goto_1

    .line 481
    .line 482
    :pswitch_1b
    mul-int/lit8 v3, v3, 0x35

    .line 483
    .line 484
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 485
    .line 486
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v4

    .line 490
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 491
    .line 492
    .line 493
    move-result v4

    .line 494
    goto/16 :goto_1

    .line 495
    .line 496
    :pswitch_1c
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 497
    .line 498
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v4

    .line 502
    if-eqz v4, :cond_1

    .line 503
    .line 504
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 505
    .line 506
    .line 507
    move-result v10

    .line 508
    goto :goto_3

    .line 509
    :pswitch_1d
    mul-int/lit8 v3, v3, 0x35

    .line 510
    .line 511
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 512
    .line 513
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v4

    .line 517
    check-cast v4, Ljava/lang/String;

    .line 518
    .line 519
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 520
    .line 521
    .line 522
    move-result v4

    .line 523
    goto/16 :goto_1

    .line 524
    .line 525
    :pswitch_1e
    mul-int/lit8 v3, v3, 0x35

    .line 526
    .line 527
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 528
    .line 529
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->c(JLjava/lang/Object;)Z

    .line 530
    .line 531
    .line 532
    move-result v4

    .line 533
    sget-object v5, Lcom/google/protobuf/u;->a:Ljava/nio/charset/Charset;

    .line 534
    .line 535
    if-eqz v4, :cond_0

    .line 536
    .line 537
    goto/16 :goto_2

    .line 538
    .line 539
    :pswitch_1f
    mul-int/lit8 v3, v3, 0x35

    .line 540
    .line 541
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 542
    .line 543
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 544
    .line 545
    .line 546
    move-result v4

    .line 547
    goto/16 :goto_1

    .line 548
    .line 549
    :pswitch_20
    mul-int/lit8 v3, v3, 0x35

    .line 550
    .line 551
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 552
    .line 553
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 554
    .line 555
    .line 556
    move-result-wide v4

    .line 557
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 558
    .line 559
    .line 560
    move-result v4

    .line 561
    goto/16 :goto_1

    .line 562
    .line 563
    :pswitch_21
    mul-int/lit8 v3, v3, 0x35

    .line 564
    .line 565
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 566
    .line 567
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 568
    .line 569
    .line 570
    move-result v4

    .line 571
    goto/16 :goto_1

    .line 572
    .line 573
    :pswitch_22
    mul-int/lit8 v3, v3, 0x35

    .line 574
    .line 575
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 576
    .line 577
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 578
    .line 579
    .line 580
    move-result-wide v4

    .line 581
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 582
    .line 583
    .line 584
    move-result v4

    .line 585
    goto/16 :goto_1

    .line 586
    .line 587
    :pswitch_23
    mul-int/lit8 v3, v3, 0x35

    .line 588
    .line 589
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 590
    .line 591
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 592
    .line 593
    .line 594
    move-result-wide v4

    .line 595
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 596
    .line 597
    .line 598
    move-result v4

    .line 599
    goto/16 :goto_1

    .line 600
    .line 601
    :pswitch_24
    mul-int/lit8 v3, v3, 0x35

    .line 602
    .line 603
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 604
    .line 605
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->f(JLjava/lang/Object;)F

    .line 606
    .line 607
    .line 608
    move-result v4

    .line 609
    invoke-static {v4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 610
    .line 611
    .line 612
    move-result v4

    .line 613
    goto/16 :goto_1

    .line 614
    .line 615
    :pswitch_25
    mul-int/lit8 v3, v3, 0x35

    .line 616
    .line 617
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 618
    .line 619
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/protobuf/l1;->e(JLjava/lang/Object;)D

    .line 620
    .line 621
    .line 622
    move-result-wide v4

    .line 623
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 624
    .line 625
    .line 626
    move-result-wide v4

    .line 627
    invoke-static {v4, v5}, Lcom/google/protobuf/u;->a(J)I

    .line 628
    .line 629
    .line 630
    move-result v4

    .line 631
    goto/16 :goto_1

    .line 632
    .line 633
    :cond_2
    :goto_4
    add-int/lit8 v2, v2, 0x3

    .line 634
    .line 635
    goto/16 :goto_0

    .line 636
    .line 637
    :cond_3
    mul-int/lit8 v3, v3, 0x35

    .line 638
    .line 639
    iget-object p0, p0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 640
    .line 641
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 642
    .line 643
    .line 644
    iget-object p0, p1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 645
    .line 646
    invoke-virtual {p0}, Lcom/google/protobuf/d1;->hashCode()I

    .line 647
    .line 648
    .line 649
    move-result p0

    .line 650
    add-int/2addr p0, v3

    .line 651
    return p0

    .line 652
    nop

    .line 653
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final g(Lcom/google/protobuf/p;)I
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v6, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 6
    .line 7
    const v8, 0xfffff

    .line 8
    .line 9
    .line 10
    move v3, v8

    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v4, 0x0

    .line 13
    const/4 v9, 0x0

    .line 14
    :goto_0
    iget-object v5, v0, Lcom/google/protobuf/n0;->a:[I

    .line 15
    .line 16
    array-length v10, v5

    .line 17
    if-ge v2, v10, :cond_26

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->x(I)I

    .line 20
    .line 21
    .line 22
    move-result v10

    .line 23
    invoke-static {v10}, Lcom/google/protobuf/n0;->w(I)I

    .line 24
    .line 25
    .line 26
    move-result v11

    .line 27
    aget v12, v5, v2

    .line 28
    .line 29
    add-int/lit8 v13, v2, 0x2

    .line 30
    .line 31
    aget v5, v5, v13

    .line 32
    .line 33
    and-int v13, v5, v8

    .line 34
    .line 35
    const/16 v14, 0x11

    .line 36
    .line 37
    const/4 v15, 0x1

    .line 38
    if-gt v11, v14, :cond_2

    .line 39
    .line 40
    if-eq v13, v3, :cond_1

    .line 41
    .line 42
    if-ne v13, v8, :cond_0

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    int-to-long v3, v13

    .line 47
    invoke-virtual {v6, v1, v3, v4}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    move v4, v3

    .line 52
    :goto_1
    move v3, v13

    .line 53
    :cond_1
    ushr-int/lit8 v5, v5, 0x14

    .line 54
    .line 55
    shl-int v5, v15, v5

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/4 v5, 0x0

    .line 59
    :goto_2
    and-int/2addr v10, v8

    .line 60
    int-to-long v13, v10

    .line 61
    sget-object v10, Lcom/google/protobuf/l;->e:Lcom/google/protobuf/l;

    .line 62
    .line 63
    iget v10, v10, Lcom/google/protobuf/l;->d:I

    .line 64
    .line 65
    if-lt v11, v10, :cond_3

    .line 66
    .line 67
    sget-object v10, Lcom/google/protobuf/l;->f:Lcom/google/protobuf/l;

    .line 68
    .line 69
    iget v10, v10, Lcom/google/protobuf/l;->d:I

    .line 70
    .line 71
    :cond_3
    const/16 v10, 0x3f

    .line 72
    .line 73
    const/16 v16, 0x2

    .line 74
    .line 75
    const/16 v17, 0x4

    .line 76
    .line 77
    const/16 v18, 0x8

    .line 78
    .line 79
    packed-switch v11, :pswitch_data_0

    .line 80
    .line 81
    .line 82
    goto/16 :goto_29

    .line 83
    .line 84
    :pswitch_0
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    if-eqz v5, :cond_25

    .line 89
    .line 90
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    check-cast v5, Lcom/google/protobuf/a;

    .line 95
    .line 96
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 97
    .line 98
    .line 99
    move-result-object v10

    .line 100
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 101
    .line 102
    .line 103
    move-result v11

    .line 104
    mul-int/lit8 v11, v11, 0x2

    .line 105
    .line 106
    invoke-virtual {v5, v10}, Lcom/google/protobuf/a;->h(Lcom/google/protobuf/w0;)I

    .line 107
    .line 108
    .line 109
    move-result v5

    .line 110
    add-int/2addr v5, v11

    .line 111
    :goto_3
    add-int/2addr v9, v5

    .line 112
    goto/16 :goto_29

    .line 113
    .line 114
    :pswitch_1
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    if-eqz v5, :cond_25

    .line 119
    .line 120
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 121
    .line 122
    .line 123
    move-result-wide v13

    .line 124
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    shl-long v11, v13, v15

    .line 129
    .line 130
    shr-long/2addr v13, v10

    .line 131
    xor-long v10, v11, v13

    .line 132
    .line 133
    invoke-static {v10, v11}, Lcom/google/protobuf/f;->h(J)I

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    :goto_4
    add-int/2addr v10, v5

    .line 138
    add-int/2addr v9, v10

    .line 139
    goto/16 :goto_29

    .line 140
    .line 141
    :pswitch_2
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-eqz v5, :cond_25

    .line 146
    .line 147
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 148
    .line 149
    .line 150
    move-result v5

    .line 151
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    shl-int/lit8 v11, v5, 0x1

    .line 156
    .line 157
    shr-int/lit8 v5, v5, 0x1f

    .line 158
    .line 159
    xor-int/2addr v5, v11

    .line 160
    invoke-static {v5}, Lcom/google/protobuf/f;->g(I)I

    .line 161
    .line 162
    .line 163
    move-result v5

    .line 164
    :goto_5
    add-int/2addr v5, v10

    .line 165
    goto :goto_3

    .line 166
    :pswitch_3
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 167
    .line 168
    .line 169
    move-result v5

    .line 170
    if-eqz v5, :cond_25

    .line 171
    .line 172
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 173
    .line 174
    .line 175
    move-result v5

    .line 176
    :goto_6
    add-int/lit8 v5, v5, 0x8

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :pswitch_4
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 180
    .line 181
    .line 182
    move-result v5

    .line 183
    if-eqz v5, :cond_25

    .line 184
    .line 185
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    :goto_7
    add-int/lit8 v5, v5, 0x4

    .line 190
    .line 191
    goto :goto_3

    .line 192
    :pswitch_5
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 193
    .line 194
    .line 195
    move-result v5

    .line 196
    if-eqz v5, :cond_25

    .line 197
    .line 198
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 199
    .line 200
    .line 201
    move-result v5

    .line 202
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 203
    .line 204
    .line 205
    move-result v10

    .line 206
    invoke-static {v5}, Lcom/google/protobuf/f;->d(I)I

    .line 207
    .line 208
    .line 209
    move-result v5

    .line 210
    goto :goto_5

    .line 211
    :pswitch_6
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 212
    .line 213
    .line 214
    move-result v5

    .line 215
    if-eqz v5, :cond_25

    .line 216
    .line 217
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 222
    .line 223
    .line 224
    move-result v10

    .line 225
    invoke-static {v5}, Lcom/google/protobuf/f;->g(I)I

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    goto :goto_5

    .line 230
    :pswitch_7
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 231
    .line 232
    .line 233
    move-result v5

    .line 234
    if-eqz v5, :cond_25

    .line 235
    .line 236
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v5

    .line 240
    check-cast v5, Lcom/google/protobuf/e;

    .line 241
    .line 242
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 243
    .line 244
    .line 245
    move-result v10

    .line 246
    invoke-virtual {v5}, Lcom/google/protobuf/e;->size()I

    .line 247
    .line 248
    .line 249
    move-result v5

    .line 250
    invoke-static {v5, v5, v10, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 251
    .line 252
    .line 253
    move-result v9

    .line 254
    goto/16 :goto_29

    .line 255
    .line 256
    :pswitch_8
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 257
    .line 258
    .line 259
    move-result v5

    .line 260
    if-eqz v5, :cond_25

    .line 261
    .line 262
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v5

    .line 266
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 267
    .line 268
    .line 269
    move-result-object v10

    .line 270
    sget-object v11, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 271
    .line 272
    check-cast v5, Lcom/google/protobuf/a;

    .line 273
    .line 274
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 275
    .line 276
    .line 277
    move-result v11

    .line 278
    invoke-virtual {v5, v10}, Lcom/google/protobuf/a;->h(Lcom/google/protobuf/w0;)I

    .line 279
    .line 280
    .line 281
    move-result v5

    .line 282
    invoke-static {v5, v5, v11, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 283
    .line 284
    .line 285
    move-result v9

    .line 286
    goto/16 :goto_29

    .line 287
    .line 288
    :pswitch_9
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 289
    .line 290
    .line 291
    move-result v5

    .line 292
    if-eqz v5, :cond_25

    .line 293
    .line 294
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v5

    .line 298
    instance-of v10, v5, Lcom/google/protobuf/e;

    .line 299
    .line 300
    if-eqz v10, :cond_4

    .line 301
    .line 302
    check-cast v5, Lcom/google/protobuf/e;

    .line 303
    .line 304
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 305
    .line 306
    .line 307
    move-result v10

    .line 308
    invoke-virtual {v5}, Lcom/google/protobuf/e;->size()I

    .line 309
    .line 310
    .line 311
    move-result v5

    .line 312
    invoke-static {v5, v5, v10, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 313
    .line 314
    .line 315
    move-result v5

    .line 316
    :goto_8
    move v9, v5

    .line 317
    goto/16 :goto_29

    .line 318
    .line 319
    :cond_4
    check-cast v5, Ljava/lang/String;

    .line 320
    .line 321
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 322
    .line 323
    .line 324
    move-result v10

    .line 325
    invoke-static {v5}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 326
    .line 327
    .line 328
    move-result v5

    .line 329
    add-int/2addr v5, v10

    .line 330
    add-int/2addr v5, v9

    .line 331
    goto :goto_8

    .line 332
    :pswitch_a
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 333
    .line 334
    .line 335
    move-result v5

    .line 336
    if-eqz v5, :cond_25

    .line 337
    .line 338
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 339
    .line 340
    .line 341
    move-result v5

    .line 342
    add-int/2addr v5, v15

    .line 343
    goto/16 :goto_3

    .line 344
    .line 345
    :pswitch_b
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 346
    .line 347
    .line 348
    move-result v5

    .line 349
    if-eqz v5, :cond_25

    .line 350
    .line 351
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 352
    .line 353
    .line 354
    move-result v5

    .line 355
    goto/16 :goto_7

    .line 356
    .line 357
    :pswitch_c
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    if-eqz v5, :cond_25

    .line 362
    .line 363
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 364
    .line 365
    .line 366
    move-result v5

    .line 367
    goto/16 :goto_6

    .line 368
    .line 369
    :pswitch_d
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 370
    .line 371
    .line 372
    move-result v5

    .line 373
    if-eqz v5, :cond_25

    .line 374
    .line 375
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 376
    .line 377
    .line 378
    move-result v5

    .line 379
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 380
    .line 381
    .line 382
    move-result v10

    .line 383
    invoke-static {v5}, Lcom/google/protobuf/f;->d(I)I

    .line 384
    .line 385
    .line 386
    move-result v5

    .line 387
    goto/16 :goto_5

    .line 388
    .line 389
    :pswitch_e
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    if-eqz v5, :cond_25

    .line 394
    .line 395
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 396
    .line 397
    .line 398
    move-result-wide v10

    .line 399
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 400
    .line 401
    .line 402
    move-result v5

    .line 403
    invoke-static {v10, v11}, Lcom/google/protobuf/f;->h(J)I

    .line 404
    .line 405
    .line 406
    move-result v10

    .line 407
    goto/16 :goto_4

    .line 408
    .line 409
    :pswitch_f
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 410
    .line 411
    .line 412
    move-result v5

    .line 413
    if-eqz v5, :cond_25

    .line 414
    .line 415
    invoke-static {v13, v14, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 416
    .line 417
    .line 418
    move-result-wide v10

    .line 419
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 420
    .line 421
    .line 422
    move-result v5

    .line 423
    invoke-static {v10, v11}, Lcom/google/protobuf/f;->h(J)I

    .line 424
    .line 425
    .line 426
    move-result v10

    .line 427
    goto/16 :goto_4

    .line 428
    .line 429
    :pswitch_10
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 430
    .line 431
    .line 432
    move-result v5

    .line 433
    if-eqz v5, :cond_25

    .line 434
    .line 435
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 436
    .line 437
    .line 438
    move-result v5

    .line 439
    goto/16 :goto_7

    .line 440
    .line 441
    :pswitch_11
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 442
    .line 443
    .line 444
    move-result v5

    .line 445
    if-eqz v5, :cond_25

    .line 446
    .line 447
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 448
    .line 449
    .line 450
    move-result v5

    .line 451
    goto/16 :goto_6

    .line 452
    .line 453
    :pswitch_12
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    move-result-object v5

    .line 457
    div-int/lit8 v11, v2, 0x3

    .line 458
    .line 459
    mul-int/lit8 v11, v11, 0x2

    .line 460
    .line 461
    iget-object v13, v0, Lcom/google/protobuf/n0;->b:[Ljava/lang/Object;

    .line 462
    .line 463
    aget-object v11, v13, v11

    .line 464
    .line 465
    iget-object v13, v0, Lcom/google/protobuf/n0;->i:Lcom/google/protobuf/j0;

    .line 466
    .line 467
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 468
    .line 469
    .line 470
    check-cast v5, Lcom/google/protobuf/i0;

    .line 471
    .line 472
    check-cast v11, Lcom/google/protobuf/h0;

    .line 473
    .line 474
    invoke-virtual {v5}, Ljava/util/AbstractMap;->isEmpty()Z

    .line 475
    .line 476
    .line 477
    move-result v13

    .line 478
    if-eqz v13, :cond_6

    .line 479
    .line 480
    const/4 v13, 0x0

    .line 481
    :cond_5
    move/from16 v22, v3

    .line 482
    .line 483
    move/from16 v23, v4

    .line 484
    .line 485
    goto/16 :goto_12

    .line 486
    .line 487
    :cond_6
    invoke-virtual {v5}, Lcom/google/protobuf/i0;->entrySet()Ljava/util/Set;

    .line 488
    .line 489
    .line 490
    move-result-object v5

    .line 491
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 492
    .line 493
    .line 494
    move-result-object v5

    .line 495
    const/4 v13, 0x0

    .line 496
    :goto_9
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 497
    .line 498
    .line 499
    move-result v14

    .line 500
    if-eqz v14, :cond_5

    .line 501
    .line 502
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object v14

    .line 506
    check-cast v14, Ljava/util/Map$Entry;

    .line 507
    .line 508
    invoke-interface {v14}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v7

    .line 512
    invoke-interface {v14}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v14

    .line 516
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 517
    .line 518
    .line 519
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 520
    .line 521
    .line 522
    move-result v8

    .line 523
    move/from16 v19, v10

    .line 524
    .line 525
    iget-object v10, v11, Lcom/google/protobuf/h0;->a:Lcom/google/protobuf/g0;

    .line 526
    .line 527
    move/from16 v20, v15

    .line 528
    .line 529
    iget-object v15, v10, Lcom/google/protobuf/g0;->a:Lcom/google/protobuf/u1;

    .line 530
    .line 531
    sget v21, Lcom/google/protobuf/k;->c:I

    .line 532
    .line 533
    invoke-static/range {v20 .. v20}, Lcom/google/protobuf/f;->f(I)I

    .line 534
    .line 535
    .line 536
    move-result v21

    .line 537
    move/from16 v22, v3

    .line 538
    .line 539
    sget-object v3, Lcom/google/protobuf/u1;->h:Lcom/google/protobuf/r1;

    .line 540
    .line 541
    if-ne v15, v3, :cond_7

    .line 542
    .line 543
    mul-int/lit8 v21, v21, 0x2

    .line 544
    .line 545
    :cond_7
    invoke-virtual {v15}, Ljava/lang/Enum;->ordinal()I

    .line 546
    .line 547
    .line 548
    move-result v15

    .line 549
    move/from16 v23, v4

    .line 550
    .line 551
    const-string v4, "There is no way to get here, but the compiler thinks otherwise."

    .line 552
    .line 553
    move-object/from16 v24, v5

    .line 554
    .line 555
    const/4 v5, 0x0

    .line 556
    packed-switch v15, :pswitch_data_1

    .line 557
    .line 558
    .line 559
    new-instance v0, Ljava/lang/RuntimeException;

    .line 560
    .line 561
    invoke-direct {v0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    throw v0

    .line 565
    :pswitch_13
    check-cast v7, Ljava/lang/Long;

    .line 566
    .line 567
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 568
    .line 569
    .line 570
    move-result-wide v25

    .line 571
    shl-long v27, v25, v20

    .line 572
    .line 573
    shr-long v25, v25, v19

    .line 574
    .line 575
    xor-long v25, v27, v25

    .line 576
    .line 577
    invoke-static/range {v25 .. v26}, Lcom/google/protobuf/f;->h(J)I

    .line 578
    .line 579
    .line 580
    move-result v7

    .line 581
    goto/16 :goto_d

    .line 582
    .line 583
    :pswitch_14
    check-cast v7, Ljava/lang/Integer;

    .line 584
    .line 585
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 586
    .line 587
    .line 588
    move-result v7

    .line 589
    shl-int/lit8 v15, v7, 0x1

    .line 590
    .line 591
    shr-int/lit8 v7, v7, 0x1f

    .line 592
    .line 593
    xor-int/2addr v7, v15

    .line 594
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 595
    .line 596
    .line 597
    move-result v7

    .line 598
    goto/16 :goto_d

    .line 599
    .line 600
    :pswitch_15
    check-cast v7, Ljava/lang/Long;

    .line 601
    .line 602
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 603
    .line 604
    .line 605
    :goto_a
    move/from16 v7, v18

    .line 606
    .line 607
    goto/16 :goto_d

    .line 608
    .line 609
    :pswitch_16
    check-cast v7, Ljava/lang/Integer;

    .line 610
    .line 611
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 612
    .line 613
    .line 614
    :goto_b
    move/from16 v7, v17

    .line 615
    .line 616
    goto/16 :goto_d

    .line 617
    .line 618
    :pswitch_17
    instance-of v15, v7, Lau/i;

    .line 619
    .line 620
    if-eqz v15, :cond_8

    .line 621
    .line 622
    check-cast v7, Lau/i;

    .line 623
    .line 624
    iget v7, v7, Lau/i;->d:I

    .line 625
    .line 626
    invoke-static {v7}, Lcom/google/protobuf/f;->d(I)I

    .line 627
    .line 628
    .line 629
    move-result v7

    .line 630
    goto/16 :goto_d

    .line 631
    .line 632
    :cond_8
    check-cast v7, Ljava/lang/Integer;

    .line 633
    .line 634
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 635
    .line 636
    .line 637
    move-result v7

    .line 638
    invoke-static {v7}, Lcom/google/protobuf/f;->d(I)I

    .line 639
    .line 640
    .line 641
    move-result v7

    .line 642
    goto/16 :goto_d

    .line 643
    .line 644
    :pswitch_18
    check-cast v7, Ljava/lang/Integer;

    .line 645
    .line 646
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 647
    .line 648
    .line 649
    move-result v7

    .line 650
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 651
    .line 652
    .line 653
    move-result v7

    .line 654
    goto/16 :goto_d

    .line 655
    .line 656
    :pswitch_19
    instance-of v15, v7, Lcom/google/protobuf/e;

    .line 657
    .line 658
    if-eqz v15, :cond_9

    .line 659
    .line 660
    check-cast v7, Lcom/google/protobuf/e;

    .line 661
    .line 662
    invoke-virtual {v7}, Lcom/google/protobuf/e;->size()I

    .line 663
    .line 664
    .line 665
    move-result v7

    .line 666
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 667
    .line 668
    .line 669
    move-result v15

    .line 670
    :goto_c
    add-int/2addr v7, v15

    .line 671
    goto/16 :goto_d

    .line 672
    .line 673
    :cond_9
    check-cast v7, [B

    .line 674
    .line 675
    array-length v7, v7

    .line 676
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 677
    .line 678
    .line 679
    move-result v15

    .line 680
    goto :goto_c

    .line 681
    :pswitch_1a
    check-cast v7, Lcom/google/protobuf/a;

    .line 682
    .line 683
    check-cast v7, Lcom/google/protobuf/p;

    .line 684
    .line 685
    invoke-virtual {v7, v5}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 686
    .line 687
    .line 688
    move-result v7

    .line 689
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 690
    .line 691
    .line 692
    move-result v15

    .line 693
    goto :goto_c

    .line 694
    :pswitch_1b
    check-cast v7, Lcom/google/protobuf/a;

    .line 695
    .line 696
    check-cast v7, Lcom/google/protobuf/p;

    .line 697
    .line 698
    invoke-virtual {v7, v5}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 699
    .line 700
    .line 701
    move-result v7

    .line 702
    goto :goto_d

    .line 703
    :pswitch_1c
    instance-of v15, v7, Lcom/google/protobuf/e;

    .line 704
    .line 705
    if-eqz v15, :cond_a

    .line 706
    .line 707
    check-cast v7, Lcom/google/protobuf/e;

    .line 708
    .line 709
    invoke-virtual {v7}, Lcom/google/protobuf/e;->size()I

    .line 710
    .line 711
    .line 712
    move-result v7

    .line 713
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 714
    .line 715
    .line 716
    move-result v15

    .line 717
    goto :goto_c

    .line 718
    :cond_a
    check-cast v7, Ljava/lang/String;

    .line 719
    .line 720
    invoke-static {v7}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 721
    .line 722
    .line 723
    move-result v7

    .line 724
    goto :goto_d

    .line 725
    :pswitch_1d
    check-cast v7, Ljava/lang/Boolean;

    .line 726
    .line 727
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 728
    .line 729
    .line 730
    move/from16 v7, v20

    .line 731
    .line 732
    goto :goto_d

    .line 733
    :pswitch_1e
    check-cast v7, Ljava/lang/Integer;

    .line 734
    .line 735
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 736
    .line 737
    .line 738
    goto :goto_b

    .line 739
    :pswitch_1f
    check-cast v7, Ljava/lang/Long;

    .line 740
    .line 741
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 742
    .line 743
    .line 744
    goto/16 :goto_a

    .line 745
    .line 746
    :pswitch_20
    check-cast v7, Ljava/lang/Integer;

    .line 747
    .line 748
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 749
    .line 750
    .line 751
    move-result v7

    .line 752
    invoke-static {v7}, Lcom/google/protobuf/f;->d(I)I

    .line 753
    .line 754
    .line 755
    move-result v7

    .line 756
    goto :goto_d

    .line 757
    :pswitch_21
    check-cast v7, Ljava/lang/Long;

    .line 758
    .line 759
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 760
    .line 761
    .line 762
    move-result-wide v25

    .line 763
    invoke-static/range {v25 .. v26}, Lcom/google/protobuf/f;->h(J)I

    .line 764
    .line 765
    .line 766
    move-result v7

    .line 767
    goto :goto_d

    .line 768
    :pswitch_22
    check-cast v7, Ljava/lang/Long;

    .line 769
    .line 770
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 771
    .line 772
    .line 773
    move-result-wide v25

    .line 774
    invoke-static/range {v25 .. v26}, Lcom/google/protobuf/f;->h(J)I

    .line 775
    .line 776
    .line 777
    move-result v7

    .line 778
    goto :goto_d

    .line 779
    :pswitch_23
    check-cast v7, Ljava/lang/Float;

    .line 780
    .line 781
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 782
    .line 783
    .line 784
    goto/16 :goto_b

    .line 785
    .line 786
    :pswitch_24
    check-cast v7, Ljava/lang/Double;

    .line 787
    .line 788
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 789
    .line 790
    .line 791
    goto/16 :goto_a

    .line 792
    .line 793
    :goto_d
    add-int v7, v7, v21

    .line 794
    .line 795
    iget-object v10, v10, Lcom/google/protobuf/g0;->b:Lcom/google/protobuf/u1;

    .line 796
    .line 797
    invoke-static/range {v16 .. v16}, Lcom/google/protobuf/f;->f(I)I

    .line 798
    .line 799
    .line 800
    move-result v15

    .line 801
    if-ne v10, v3, :cond_b

    .line 802
    .line 803
    mul-int/lit8 v15, v15, 0x2

    .line 804
    .line 805
    :cond_b
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 806
    .line 807
    .line 808
    move-result v3

    .line 809
    packed-switch v3, :pswitch_data_2

    .line 810
    .line 811
    .line 812
    new-instance v0, Ljava/lang/RuntimeException;

    .line 813
    .line 814
    invoke-direct {v0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 815
    .line 816
    .line 817
    throw v0

    .line 818
    :pswitch_25
    check-cast v14, Ljava/lang/Long;

    .line 819
    .line 820
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 821
    .line 822
    .line 823
    move-result-wide v3

    .line 824
    shl-long v25, v3, v20

    .line 825
    .line 826
    shr-long v3, v3, v19

    .line 827
    .line 828
    xor-long v3, v25, v3

    .line 829
    .line 830
    invoke-static {v3, v4}, Lcom/google/protobuf/f;->h(J)I

    .line 831
    .line 832
    .line 833
    move-result v3

    .line 834
    goto/16 :goto_11

    .line 835
    .line 836
    :pswitch_26
    check-cast v14, Ljava/lang/Integer;

    .line 837
    .line 838
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 839
    .line 840
    .line 841
    move-result v3

    .line 842
    shl-int/lit8 v4, v3, 0x1

    .line 843
    .line 844
    shr-int/lit8 v3, v3, 0x1f

    .line 845
    .line 846
    xor-int/2addr v3, v4

    .line 847
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 848
    .line 849
    .line 850
    move-result v3

    .line 851
    goto/16 :goto_11

    .line 852
    .line 853
    :pswitch_27
    check-cast v14, Ljava/lang/Long;

    .line 854
    .line 855
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 856
    .line 857
    .line 858
    :goto_e
    move/from16 v3, v18

    .line 859
    .line 860
    goto/16 :goto_11

    .line 861
    .line 862
    :pswitch_28
    check-cast v14, Ljava/lang/Integer;

    .line 863
    .line 864
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 865
    .line 866
    .line 867
    :goto_f
    move/from16 v3, v17

    .line 868
    .line 869
    goto/16 :goto_11

    .line 870
    .line 871
    :pswitch_29
    instance-of v3, v14, Lau/i;

    .line 872
    .line 873
    if-eqz v3, :cond_c

    .line 874
    .line 875
    check-cast v14, Lau/i;

    .line 876
    .line 877
    iget v3, v14, Lau/i;->d:I

    .line 878
    .line 879
    invoke-static {v3}, Lcom/google/protobuf/f;->d(I)I

    .line 880
    .line 881
    .line 882
    move-result v3

    .line 883
    goto/16 :goto_11

    .line 884
    .line 885
    :cond_c
    check-cast v14, Ljava/lang/Integer;

    .line 886
    .line 887
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 888
    .line 889
    .line 890
    move-result v3

    .line 891
    invoke-static {v3}, Lcom/google/protobuf/f;->d(I)I

    .line 892
    .line 893
    .line 894
    move-result v3

    .line 895
    goto/16 :goto_11

    .line 896
    .line 897
    :pswitch_2a
    check-cast v14, Ljava/lang/Integer;

    .line 898
    .line 899
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 900
    .line 901
    .line 902
    move-result v3

    .line 903
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 904
    .line 905
    .line 906
    move-result v3

    .line 907
    goto/16 :goto_11

    .line 908
    .line 909
    :pswitch_2b
    instance-of v3, v14, Lcom/google/protobuf/e;

    .line 910
    .line 911
    if-eqz v3, :cond_d

    .line 912
    .line 913
    check-cast v14, Lcom/google/protobuf/e;

    .line 914
    .line 915
    invoke-virtual {v14}, Lcom/google/protobuf/e;->size()I

    .line 916
    .line 917
    .line 918
    move-result v3

    .line 919
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 920
    .line 921
    .line 922
    move-result v4

    .line 923
    :goto_10
    add-int/2addr v3, v4

    .line 924
    goto/16 :goto_11

    .line 925
    .line 926
    :cond_d
    check-cast v14, [B

    .line 927
    .line 928
    array-length v3, v14

    .line 929
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 930
    .line 931
    .line 932
    move-result v4

    .line 933
    goto :goto_10

    .line 934
    :pswitch_2c
    check-cast v14, Lcom/google/protobuf/a;

    .line 935
    .line 936
    check-cast v14, Lcom/google/protobuf/p;

    .line 937
    .line 938
    invoke-virtual {v14, v5}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 939
    .line 940
    .line 941
    move-result v3

    .line 942
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 943
    .line 944
    .line 945
    move-result v4

    .line 946
    goto :goto_10

    .line 947
    :pswitch_2d
    check-cast v14, Lcom/google/protobuf/a;

    .line 948
    .line 949
    check-cast v14, Lcom/google/protobuf/p;

    .line 950
    .line 951
    invoke-virtual {v14, v5}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 952
    .line 953
    .line 954
    move-result v3

    .line 955
    goto :goto_11

    .line 956
    :pswitch_2e
    instance-of v3, v14, Lcom/google/protobuf/e;

    .line 957
    .line 958
    if-eqz v3, :cond_e

    .line 959
    .line 960
    check-cast v14, Lcom/google/protobuf/e;

    .line 961
    .line 962
    invoke-virtual {v14}, Lcom/google/protobuf/e;->size()I

    .line 963
    .line 964
    .line 965
    move-result v3

    .line 966
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 967
    .line 968
    .line 969
    move-result v4

    .line 970
    goto :goto_10

    .line 971
    :cond_e
    check-cast v14, Ljava/lang/String;

    .line 972
    .line 973
    invoke-static {v14}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 974
    .line 975
    .line 976
    move-result v3

    .line 977
    goto :goto_11

    .line 978
    :pswitch_2f
    check-cast v14, Ljava/lang/Boolean;

    .line 979
    .line 980
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 981
    .line 982
    .line 983
    move/from16 v3, v20

    .line 984
    .line 985
    goto :goto_11

    .line 986
    :pswitch_30
    check-cast v14, Ljava/lang/Integer;

    .line 987
    .line 988
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 989
    .line 990
    .line 991
    goto :goto_f

    .line 992
    :pswitch_31
    check-cast v14, Ljava/lang/Long;

    .line 993
    .line 994
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 995
    .line 996
    .line 997
    goto/16 :goto_e

    .line 998
    .line 999
    :pswitch_32
    check-cast v14, Ljava/lang/Integer;

    .line 1000
    .line 1001
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 1002
    .line 1003
    .line 1004
    move-result v3

    .line 1005
    invoke-static {v3}, Lcom/google/protobuf/f;->d(I)I

    .line 1006
    .line 1007
    .line 1008
    move-result v3

    .line 1009
    goto :goto_11

    .line 1010
    :pswitch_33
    check-cast v14, Ljava/lang/Long;

    .line 1011
    .line 1012
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 1013
    .line 1014
    .line 1015
    move-result-wide v3

    .line 1016
    invoke-static {v3, v4}, Lcom/google/protobuf/f;->h(J)I

    .line 1017
    .line 1018
    .line 1019
    move-result v3

    .line 1020
    goto :goto_11

    .line 1021
    :pswitch_34
    check-cast v14, Ljava/lang/Long;

    .line 1022
    .line 1023
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 1024
    .line 1025
    .line 1026
    move-result-wide v3

    .line 1027
    invoke-static {v3, v4}, Lcom/google/protobuf/f;->h(J)I

    .line 1028
    .line 1029
    .line 1030
    move-result v3

    .line 1031
    goto :goto_11

    .line 1032
    :pswitch_35
    check-cast v14, Ljava/lang/Float;

    .line 1033
    .line 1034
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1035
    .line 1036
    .line 1037
    goto/16 :goto_f

    .line 1038
    .line 1039
    :pswitch_36
    check-cast v14, Ljava/lang/Double;

    .line 1040
    .line 1041
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1042
    .line 1043
    .line 1044
    goto/16 :goto_e

    .line 1045
    .line 1046
    :goto_11
    add-int/2addr v3, v15

    .line 1047
    add-int/2addr v3, v7

    .line 1048
    invoke-static {v3, v3, v8, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1049
    .line 1050
    .line 1051
    move-result v13

    .line 1052
    move/from16 v10, v19

    .line 1053
    .line 1054
    move/from16 v15, v20

    .line 1055
    .line 1056
    move/from16 v3, v22

    .line 1057
    .line 1058
    move/from16 v4, v23

    .line 1059
    .line 1060
    move-object/from16 v5, v24

    .line 1061
    .line 1062
    const v8, 0xfffff

    .line 1063
    .line 1064
    .line 1065
    goto/16 :goto_9

    .line 1066
    .line 1067
    :goto_12
    add-int/2addr v9, v13

    .line 1068
    :cond_f
    :goto_13
    move/from16 v3, v22

    .line 1069
    .line 1070
    move/from16 v4, v23

    .line 1071
    .line 1072
    goto/16 :goto_29

    .line 1073
    .line 1074
    :pswitch_37
    move/from16 v22, v3

    .line 1075
    .line 1076
    move/from16 v23, v4

    .line 1077
    .line 1078
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v3

    .line 1082
    check-cast v3, Ljava/util/List;

    .line 1083
    .line 1084
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 1085
    .line 1086
    .line 1087
    move-result-object v4

    .line 1088
    sget-object v5, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1089
    .line 1090
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1091
    .line 1092
    .line 1093
    move-result v5

    .line 1094
    if-nez v5, :cond_10

    .line 1095
    .line 1096
    const/4 v8, 0x0

    .line 1097
    goto :goto_15

    .line 1098
    :cond_10
    const/4 v7, 0x0

    .line 1099
    const/4 v8, 0x0

    .line 1100
    :goto_14
    if-ge v7, v5, :cond_11

    .line 1101
    .line 1102
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v10

    .line 1106
    check-cast v10, Lcom/google/protobuf/a;

    .line 1107
    .line 1108
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1109
    .line 1110
    .line 1111
    move-result v11

    .line 1112
    mul-int/lit8 v11, v11, 0x2

    .line 1113
    .line 1114
    invoke-virtual {v10, v4}, Lcom/google/protobuf/a;->h(Lcom/google/protobuf/w0;)I

    .line 1115
    .line 1116
    .line 1117
    move-result v10

    .line 1118
    add-int/2addr v10, v11

    .line 1119
    add-int/2addr v8, v10

    .line 1120
    add-int/lit8 v7, v7, 0x1

    .line 1121
    .line 1122
    goto :goto_14

    .line 1123
    :cond_11
    :goto_15
    add-int/2addr v9, v8

    .line 1124
    goto :goto_13

    .line 1125
    :pswitch_38
    move/from16 v22, v3

    .line 1126
    .line 1127
    move/from16 v23, v4

    .line 1128
    .line 1129
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v3

    .line 1133
    check-cast v3, Ljava/util/List;

    .line 1134
    .line 1135
    invoke-static {v3}, Lcom/google/protobuf/x0;->g(Ljava/util/List;)I

    .line 1136
    .line 1137
    .line 1138
    move-result v3

    .line 1139
    if-lez v3, :cond_f

    .line 1140
    .line 1141
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1142
    .line 1143
    .line 1144
    move-result v4

    .line 1145
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1146
    .line 1147
    .line 1148
    move-result v9

    .line 1149
    goto :goto_13

    .line 1150
    :pswitch_39
    move/from16 v22, v3

    .line 1151
    .line 1152
    move/from16 v23, v4

    .line 1153
    .line 1154
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v3

    .line 1158
    check-cast v3, Ljava/util/List;

    .line 1159
    .line 1160
    invoke-static {v3}, Lcom/google/protobuf/x0;->f(Ljava/util/List;)I

    .line 1161
    .line 1162
    .line 1163
    move-result v3

    .line 1164
    if-lez v3, :cond_f

    .line 1165
    .line 1166
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1167
    .line 1168
    .line 1169
    move-result v4

    .line 1170
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1171
    .line 1172
    .line 1173
    move-result v9

    .line 1174
    goto :goto_13

    .line 1175
    :pswitch_3a
    move/from16 v22, v3

    .line 1176
    .line 1177
    move/from16 v23, v4

    .line 1178
    .line 1179
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v3

    .line 1183
    check-cast v3, Ljava/util/List;

    .line 1184
    .line 1185
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1186
    .line 1187
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1188
    .line 1189
    .line 1190
    move-result v3

    .line 1191
    mul-int/lit8 v3, v3, 0x8

    .line 1192
    .line 1193
    if-lez v3, :cond_f

    .line 1194
    .line 1195
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1196
    .line 1197
    .line 1198
    move-result v4

    .line 1199
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1200
    .line 1201
    .line 1202
    move-result v9

    .line 1203
    goto/16 :goto_13

    .line 1204
    .line 1205
    :pswitch_3b
    move/from16 v22, v3

    .line 1206
    .line 1207
    move/from16 v23, v4

    .line 1208
    .line 1209
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1210
    .line 1211
    .line 1212
    move-result-object v3

    .line 1213
    check-cast v3, Ljava/util/List;

    .line 1214
    .line 1215
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1216
    .line 1217
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1218
    .line 1219
    .line 1220
    move-result v3

    .line 1221
    mul-int/lit8 v3, v3, 0x4

    .line 1222
    .line 1223
    if-lez v3, :cond_f

    .line 1224
    .line 1225
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1226
    .line 1227
    .line 1228
    move-result v4

    .line 1229
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1230
    .line 1231
    .line 1232
    move-result v9

    .line 1233
    goto/16 :goto_13

    .line 1234
    .line 1235
    :pswitch_3c
    move/from16 v22, v3

    .line 1236
    .line 1237
    move/from16 v23, v4

    .line 1238
    .line 1239
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1240
    .line 1241
    .line 1242
    move-result-object v3

    .line 1243
    check-cast v3, Ljava/util/List;

    .line 1244
    .line 1245
    invoke-static {v3}, Lcom/google/protobuf/x0;->a(Ljava/util/List;)I

    .line 1246
    .line 1247
    .line 1248
    move-result v3

    .line 1249
    if-lez v3, :cond_f

    .line 1250
    .line 1251
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1252
    .line 1253
    .line 1254
    move-result v4

    .line 1255
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1256
    .line 1257
    .line 1258
    move-result v9

    .line 1259
    goto/16 :goto_13

    .line 1260
    .line 1261
    :pswitch_3d
    move/from16 v22, v3

    .line 1262
    .line 1263
    move/from16 v23, v4

    .line 1264
    .line 1265
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1266
    .line 1267
    .line 1268
    move-result-object v3

    .line 1269
    check-cast v3, Ljava/util/List;

    .line 1270
    .line 1271
    invoke-static {v3}, Lcom/google/protobuf/x0;->h(Ljava/util/List;)I

    .line 1272
    .line 1273
    .line 1274
    move-result v3

    .line 1275
    if-lez v3, :cond_f

    .line 1276
    .line 1277
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1278
    .line 1279
    .line 1280
    move-result v4

    .line 1281
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1282
    .line 1283
    .line 1284
    move-result v9

    .line 1285
    goto/16 :goto_13

    .line 1286
    .line 1287
    :pswitch_3e
    move/from16 v22, v3

    .line 1288
    .line 1289
    move/from16 v23, v4

    .line 1290
    .line 1291
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1292
    .line 1293
    .line 1294
    move-result-object v3

    .line 1295
    check-cast v3, Ljava/util/List;

    .line 1296
    .line 1297
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1298
    .line 1299
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1300
    .line 1301
    .line 1302
    move-result v3

    .line 1303
    if-lez v3, :cond_f

    .line 1304
    .line 1305
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1306
    .line 1307
    .line 1308
    move-result v4

    .line 1309
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1310
    .line 1311
    .line 1312
    move-result v9

    .line 1313
    goto/16 :goto_13

    .line 1314
    .line 1315
    :pswitch_3f
    move/from16 v22, v3

    .line 1316
    .line 1317
    move/from16 v23, v4

    .line 1318
    .line 1319
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1320
    .line 1321
    .line 1322
    move-result-object v3

    .line 1323
    check-cast v3, Ljava/util/List;

    .line 1324
    .line 1325
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1326
    .line 1327
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1328
    .line 1329
    .line 1330
    move-result v3

    .line 1331
    mul-int/lit8 v3, v3, 0x4

    .line 1332
    .line 1333
    if-lez v3, :cond_f

    .line 1334
    .line 1335
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1336
    .line 1337
    .line 1338
    move-result v4

    .line 1339
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1340
    .line 1341
    .line 1342
    move-result v9

    .line 1343
    goto/16 :goto_13

    .line 1344
    .line 1345
    :pswitch_40
    move/from16 v22, v3

    .line 1346
    .line 1347
    move/from16 v23, v4

    .line 1348
    .line 1349
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v3

    .line 1353
    check-cast v3, Ljava/util/List;

    .line 1354
    .line 1355
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1356
    .line 1357
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1358
    .line 1359
    .line 1360
    move-result v3

    .line 1361
    mul-int/lit8 v3, v3, 0x8

    .line 1362
    .line 1363
    if-lez v3, :cond_f

    .line 1364
    .line 1365
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1366
    .line 1367
    .line 1368
    move-result v4

    .line 1369
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1370
    .line 1371
    .line 1372
    move-result v9

    .line 1373
    goto/16 :goto_13

    .line 1374
    .line 1375
    :pswitch_41
    move/from16 v22, v3

    .line 1376
    .line 1377
    move/from16 v23, v4

    .line 1378
    .line 1379
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1380
    .line 1381
    .line 1382
    move-result-object v3

    .line 1383
    check-cast v3, Ljava/util/List;

    .line 1384
    .line 1385
    invoke-static {v3}, Lcom/google/protobuf/x0;->d(Ljava/util/List;)I

    .line 1386
    .line 1387
    .line 1388
    move-result v3

    .line 1389
    if-lez v3, :cond_f

    .line 1390
    .line 1391
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1392
    .line 1393
    .line 1394
    move-result v4

    .line 1395
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1396
    .line 1397
    .line 1398
    move-result v9

    .line 1399
    goto/16 :goto_13

    .line 1400
    .line 1401
    :pswitch_42
    move/from16 v22, v3

    .line 1402
    .line 1403
    move/from16 v23, v4

    .line 1404
    .line 1405
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1406
    .line 1407
    .line 1408
    move-result-object v3

    .line 1409
    check-cast v3, Ljava/util/List;

    .line 1410
    .line 1411
    invoke-static {v3}, Lcom/google/protobuf/x0;->i(Ljava/util/List;)I

    .line 1412
    .line 1413
    .line 1414
    move-result v3

    .line 1415
    if-lez v3, :cond_f

    .line 1416
    .line 1417
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1418
    .line 1419
    .line 1420
    move-result v4

    .line 1421
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1422
    .line 1423
    .line 1424
    move-result v9

    .line 1425
    goto/16 :goto_13

    .line 1426
    .line 1427
    :pswitch_43
    move/from16 v22, v3

    .line 1428
    .line 1429
    move/from16 v23, v4

    .line 1430
    .line 1431
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1432
    .line 1433
    .line 1434
    move-result-object v3

    .line 1435
    check-cast v3, Ljava/util/List;

    .line 1436
    .line 1437
    invoke-static {v3}, Lcom/google/protobuf/x0;->e(Ljava/util/List;)I

    .line 1438
    .line 1439
    .line 1440
    move-result v3

    .line 1441
    if-lez v3, :cond_f

    .line 1442
    .line 1443
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1444
    .line 1445
    .line 1446
    move-result v4

    .line 1447
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1448
    .line 1449
    .line 1450
    move-result v9

    .line 1451
    goto/16 :goto_13

    .line 1452
    .line 1453
    :pswitch_44
    move/from16 v22, v3

    .line 1454
    .line 1455
    move/from16 v23, v4

    .line 1456
    .line 1457
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1458
    .line 1459
    .line 1460
    move-result-object v3

    .line 1461
    check-cast v3, Ljava/util/List;

    .line 1462
    .line 1463
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1464
    .line 1465
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1466
    .line 1467
    .line 1468
    move-result v3

    .line 1469
    mul-int/lit8 v3, v3, 0x4

    .line 1470
    .line 1471
    if-lez v3, :cond_f

    .line 1472
    .line 1473
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1474
    .line 1475
    .line 1476
    move-result v4

    .line 1477
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1478
    .line 1479
    .line 1480
    move-result v9

    .line 1481
    goto/16 :goto_13

    .line 1482
    .line 1483
    :pswitch_45
    move/from16 v22, v3

    .line 1484
    .line 1485
    move/from16 v23, v4

    .line 1486
    .line 1487
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1488
    .line 1489
    .line 1490
    move-result-object v3

    .line 1491
    check-cast v3, Ljava/util/List;

    .line 1492
    .line 1493
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1494
    .line 1495
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1496
    .line 1497
    .line 1498
    move-result v3

    .line 1499
    mul-int/lit8 v3, v3, 0x8

    .line 1500
    .line 1501
    if-lez v3, :cond_f

    .line 1502
    .line 1503
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1504
    .line 1505
    .line 1506
    move-result v4

    .line 1507
    invoke-static {v3, v4, v3, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 1508
    .line 1509
    .line 1510
    move-result v9

    .line 1511
    goto/16 :goto_13

    .line 1512
    .line 1513
    :pswitch_46
    move/from16 v22, v3

    .line 1514
    .line 1515
    move/from16 v23, v4

    .line 1516
    .line 1517
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v3

    .line 1521
    check-cast v3, Ljava/util/List;

    .line 1522
    .line 1523
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1524
    .line 1525
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1526
    .line 1527
    .line 1528
    move-result v4

    .line 1529
    if-nez v4, :cond_12

    .line 1530
    .line 1531
    :goto_16
    const/4 v5, 0x0

    .line 1532
    goto :goto_18

    .line 1533
    :cond_12
    invoke-static {v3}, Lcom/google/protobuf/x0;->g(Ljava/util/List;)I

    .line 1534
    .line 1535
    .line 1536
    move-result v3

    .line 1537
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1538
    .line 1539
    .line 1540
    move-result v5

    .line 1541
    :goto_17
    mul-int/2addr v5, v4

    .line 1542
    add-int/2addr v5, v3

    .line 1543
    :cond_13
    :goto_18
    add-int/2addr v9, v5

    .line 1544
    goto/16 :goto_13

    .line 1545
    .line 1546
    :pswitch_47
    move/from16 v22, v3

    .line 1547
    .line 1548
    move/from16 v23, v4

    .line 1549
    .line 1550
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1551
    .line 1552
    .line 1553
    move-result-object v3

    .line 1554
    check-cast v3, Ljava/util/List;

    .line 1555
    .line 1556
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1557
    .line 1558
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1559
    .line 1560
    .line 1561
    move-result v4

    .line 1562
    if-nez v4, :cond_14

    .line 1563
    .line 1564
    goto :goto_16

    .line 1565
    :cond_14
    invoke-static {v3}, Lcom/google/protobuf/x0;->f(Ljava/util/List;)I

    .line 1566
    .line 1567
    .line 1568
    move-result v3

    .line 1569
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1570
    .line 1571
    .line 1572
    move-result v5

    .line 1573
    goto :goto_17

    .line 1574
    :pswitch_48
    move/from16 v22, v3

    .line 1575
    .line 1576
    move/from16 v23, v4

    .line 1577
    .line 1578
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1579
    .line 1580
    .line 1581
    move-result-object v3

    .line 1582
    check-cast v3, Ljava/util/List;

    .line 1583
    .line 1584
    invoke-static {v12, v3}, Lcom/google/protobuf/x0;->c(ILjava/util/List;)I

    .line 1585
    .line 1586
    .line 1587
    move-result v3

    .line 1588
    :goto_19
    add-int/2addr v9, v3

    .line 1589
    move/from16 v3, v22

    .line 1590
    .line 1591
    goto/16 :goto_29

    .line 1592
    .line 1593
    :pswitch_49
    move/from16 v22, v3

    .line 1594
    .line 1595
    move/from16 v23, v4

    .line 1596
    .line 1597
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1598
    .line 1599
    .line 1600
    move-result-object v3

    .line 1601
    check-cast v3, Ljava/util/List;

    .line 1602
    .line 1603
    invoke-static {v12, v3}, Lcom/google/protobuf/x0;->b(ILjava/util/List;)I

    .line 1604
    .line 1605
    .line 1606
    move-result v3

    .line 1607
    goto :goto_19

    .line 1608
    :pswitch_4a
    move/from16 v22, v3

    .line 1609
    .line 1610
    move/from16 v23, v4

    .line 1611
    .line 1612
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1613
    .line 1614
    .line 1615
    move-result-object v3

    .line 1616
    check-cast v3, Ljava/util/List;

    .line 1617
    .line 1618
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1619
    .line 1620
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1621
    .line 1622
    .line 1623
    move-result v4

    .line 1624
    if-nez v4, :cond_15

    .line 1625
    .line 1626
    goto :goto_16

    .line 1627
    :cond_15
    invoke-static {v3}, Lcom/google/protobuf/x0;->a(Ljava/util/List;)I

    .line 1628
    .line 1629
    .line 1630
    move-result v3

    .line 1631
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1632
    .line 1633
    .line 1634
    move-result v5

    .line 1635
    goto :goto_17

    .line 1636
    :pswitch_4b
    move/from16 v22, v3

    .line 1637
    .line 1638
    move/from16 v23, v4

    .line 1639
    .line 1640
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1641
    .line 1642
    .line 1643
    move-result-object v3

    .line 1644
    check-cast v3, Ljava/util/List;

    .line 1645
    .line 1646
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1647
    .line 1648
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1649
    .line 1650
    .line 1651
    move-result v4

    .line 1652
    if-nez v4, :cond_16

    .line 1653
    .line 1654
    goto :goto_16

    .line 1655
    :cond_16
    invoke-static {v3}, Lcom/google/protobuf/x0;->h(Ljava/util/List;)I

    .line 1656
    .line 1657
    .line 1658
    move-result v3

    .line 1659
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1660
    .line 1661
    .line 1662
    move-result v5

    .line 1663
    goto :goto_17

    .line 1664
    :pswitch_4c
    move/from16 v22, v3

    .line 1665
    .line 1666
    move/from16 v23, v4

    .line 1667
    .line 1668
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1669
    .line 1670
    .line 1671
    move-result-object v3

    .line 1672
    check-cast v3, Ljava/util/List;

    .line 1673
    .line 1674
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1675
    .line 1676
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1677
    .line 1678
    .line 1679
    move-result v4

    .line 1680
    if-nez v4, :cond_17

    .line 1681
    .line 1682
    goto/16 :goto_16

    .line 1683
    .line 1684
    :cond_17
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1685
    .line 1686
    .line 1687
    move-result v5

    .line 1688
    mul-int/2addr v5, v4

    .line 1689
    const/4 v4, 0x0

    .line 1690
    :goto_1a
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1691
    .line 1692
    .line 1693
    move-result v7

    .line 1694
    if-ge v4, v7, :cond_13

    .line 1695
    .line 1696
    invoke-interface {v3, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1697
    .line 1698
    .line 1699
    move-result-object v7

    .line 1700
    check-cast v7, Lcom/google/protobuf/e;

    .line 1701
    .line 1702
    invoke-virtual {v7}, Lcom/google/protobuf/e;->size()I

    .line 1703
    .line 1704
    .line 1705
    move-result v7

    .line 1706
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 1707
    .line 1708
    .line 1709
    move-result v8

    .line 1710
    add-int/2addr v8, v7

    .line 1711
    add-int/2addr v5, v8

    .line 1712
    add-int/lit8 v4, v4, 0x1

    .line 1713
    .line 1714
    goto :goto_1a

    .line 1715
    :pswitch_4d
    move/from16 v22, v3

    .line 1716
    .line 1717
    move/from16 v23, v4

    .line 1718
    .line 1719
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1720
    .line 1721
    .line 1722
    move-result-object v3

    .line 1723
    check-cast v3, Ljava/util/List;

    .line 1724
    .line 1725
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 1726
    .line 1727
    .line 1728
    move-result-object v4

    .line 1729
    sget-object v5, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1730
    .line 1731
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1732
    .line 1733
    .line 1734
    move-result v5

    .line 1735
    if-nez v5, :cond_18

    .line 1736
    .line 1737
    const/4 v7, 0x0

    .line 1738
    goto :goto_1c

    .line 1739
    :cond_18
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1740
    .line 1741
    .line 1742
    move-result v7

    .line 1743
    mul-int/2addr v7, v5

    .line 1744
    const/4 v8, 0x0

    .line 1745
    :goto_1b
    if-ge v8, v5, :cond_19

    .line 1746
    .line 1747
    invoke-interface {v3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1748
    .line 1749
    .line 1750
    move-result-object v10

    .line 1751
    check-cast v10, Lcom/google/protobuf/a;

    .line 1752
    .line 1753
    invoke-virtual {v10, v4}, Lcom/google/protobuf/a;->h(Lcom/google/protobuf/w0;)I

    .line 1754
    .line 1755
    .line 1756
    move-result v10

    .line 1757
    invoke-static {v10}, Lcom/google/protobuf/f;->g(I)I

    .line 1758
    .line 1759
    .line 1760
    move-result v11

    .line 1761
    add-int/2addr v11, v10

    .line 1762
    add-int/2addr v7, v11

    .line 1763
    add-int/lit8 v8, v8, 0x1

    .line 1764
    .line 1765
    goto :goto_1b

    .line 1766
    :cond_19
    :goto_1c
    add-int/2addr v9, v7

    .line 1767
    goto/16 :goto_13

    .line 1768
    .line 1769
    :pswitch_4e
    move/from16 v22, v3

    .line 1770
    .line 1771
    move/from16 v23, v4

    .line 1772
    .line 1773
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1774
    .line 1775
    .line 1776
    move-result-object v3

    .line 1777
    check-cast v3, Ljava/util/List;

    .line 1778
    .line 1779
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1780
    .line 1781
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1782
    .line 1783
    .line 1784
    move-result v4

    .line 1785
    if-nez v4, :cond_1a

    .line 1786
    .line 1787
    goto/16 :goto_16

    .line 1788
    .line 1789
    :cond_1a
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1790
    .line 1791
    .line 1792
    move-result v5

    .line 1793
    mul-int/2addr v5, v4

    .line 1794
    instance-of v7, v3, Lcom/google/protobuf/z;

    .line 1795
    .line 1796
    if-eqz v7, :cond_1c

    .line 1797
    .line 1798
    check-cast v3, Lcom/google/protobuf/z;

    .line 1799
    .line 1800
    const/4 v7, 0x0

    .line 1801
    :goto_1d
    if-ge v7, v4, :cond_13

    .line 1802
    .line 1803
    invoke-interface {v3, v7}, Lcom/google/protobuf/z;->b(I)Ljava/lang/Object;

    .line 1804
    .line 1805
    .line 1806
    move-result-object v8

    .line 1807
    instance-of v10, v8, Lcom/google/protobuf/e;

    .line 1808
    .line 1809
    if-eqz v10, :cond_1b

    .line 1810
    .line 1811
    check-cast v8, Lcom/google/protobuf/e;

    .line 1812
    .line 1813
    invoke-virtual {v8}, Lcom/google/protobuf/e;->size()I

    .line 1814
    .line 1815
    .line 1816
    move-result v8

    .line 1817
    invoke-static {v8}, Lcom/google/protobuf/f;->g(I)I

    .line 1818
    .line 1819
    .line 1820
    move-result v10

    .line 1821
    add-int/2addr v10, v8

    .line 1822
    add-int/2addr v10, v5

    .line 1823
    move v5, v10

    .line 1824
    goto :goto_1e

    .line 1825
    :cond_1b
    check-cast v8, Ljava/lang/String;

    .line 1826
    .line 1827
    invoke-static {v8}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 1828
    .line 1829
    .line 1830
    move-result v8

    .line 1831
    add-int/2addr v8, v5

    .line 1832
    move v5, v8

    .line 1833
    :goto_1e
    add-int/lit8 v7, v7, 0x1

    .line 1834
    .line 1835
    goto :goto_1d

    .line 1836
    :cond_1c
    const/4 v7, 0x0

    .line 1837
    :goto_1f
    if-ge v7, v4, :cond_13

    .line 1838
    .line 1839
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1840
    .line 1841
    .line 1842
    move-result-object v8

    .line 1843
    instance-of v10, v8, Lcom/google/protobuf/e;

    .line 1844
    .line 1845
    if-eqz v10, :cond_1d

    .line 1846
    .line 1847
    check-cast v8, Lcom/google/protobuf/e;

    .line 1848
    .line 1849
    invoke-virtual {v8}, Lcom/google/protobuf/e;->size()I

    .line 1850
    .line 1851
    .line 1852
    move-result v8

    .line 1853
    invoke-static {v8}, Lcom/google/protobuf/f;->g(I)I

    .line 1854
    .line 1855
    .line 1856
    move-result v10

    .line 1857
    add-int/2addr v10, v8

    .line 1858
    add-int/2addr v10, v5

    .line 1859
    move v5, v10

    .line 1860
    goto :goto_20

    .line 1861
    :cond_1d
    check-cast v8, Ljava/lang/String;

    .line 1862
    .line 1863
    invoke-static {v8}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 1864
    .line 1865
    .line 1866
    move-result v8

    .line 1867
    add-int/2addr v8, v5

    .line 1868
    move v5, v8

    .line 1869
    :goto_20
    add-int/lit8 v7, v7, 0x1

    .line 1870
    .line 1871
    goto :goto_1f

    .line 1872
    :pswitch_4f
    move/from16 v22, v3

    .line 1873
    .line 1874
    move/from16 v23, v4

    .line 1875
    .line 1876
    move/from16 v20, v15

    .line 1877
    .line 1878
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1879
    .line 1880
    .line 1881
    move-result-object v3

    .line 1882
    check-cast v3, Ljava/util/List;

    .line 1883
    .line 1884
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1885
    .line 1886
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1887
    .line 1888
    .line 1889
    move-result v3

    .line 1890
    if-nez v3, :cond_1e

    .line 1891
    .line 1892
    const/4 v4, 0x0

    .line 1893
    goto :goto_21

    .line 1894
    :cond_1e
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1895
    .line 1896
    .line 1897
    move-result v4

    .line 1898
    add-int/lit8 v4, v4, 0x1

    .line 1899
    .line 1900
    mul-int/2addr v4, v3

    .line 1901
    :goto_21
    add-int/2addr v9, v4

    .line 1902
    goto/16 :goto_13

    .line 1903
    .line 1904
    :pswitch_50
    move/from16 v22, v3

    .line 1905
    .line 1906
    move/from16 v23, v4

    .line 1907
    .line 1908
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1909
    .line 1910
    .line 1911
    move-result-object v3

    .line 1912
    check-cast v3, Ljava/util/List;

    .line 1913
    .line 1914
    invoke-static {v12, v3}, Lcom/google/protobuf/x0;->b(ILjava/util/List;)I

    .line 1915
    .line 1916
    .line 1917
    move-result v3

    .line 1918
    goto/16 :goto_19

    .line 1919
    .line 1920
    :pswitch_51
    move/from16 v22, v3

    .line 1921
    .line 1922
    move/from16 v23, v4

    .line 1923
    .line 1924
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1925
    .line 1926
    .line 1927
    move-result-object v3

    .line 1928
    check-cast v3, Ljava/util/List;

    .line 1929
    .line 1930
    invoke-static {v12, v3}, Lcom/google/protobuf/x0;->c(ILjava/util/List;)I

    .line 1931
    .line 1932
    .line 1933
    move-result v3

    .line 1934
    goto/16 :goto_19

    .line 1935
    .line 1936
    :pswitch_52
    move/from16 v22, v3

    .line 1937
    .line 1938
    move/from16 v23, v4

    .line 1939
    .line 1940
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1941
    .line 1942
    .line 1943
    move-result-object v3

    .line 1944
    check-cast v3, Ljava/util/List;

    .line 1945
    .line 1946
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1947
    .line 1948
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1949
    .line 1950
    .line 1951
    move-result v4

    .line 1952
    if-nez v4, :cond_1f

    .line 1953
    .line 1954
    goto/16 :goto_16

    .line 1955
    .line 1956
    :cond_1f
    invoke-static {v3}, Lcom/google/protobuf/x0;->d(Ljava/util/List;)I

    .line 1957
    .line 1958
    .line 1959
    move-result v3

    .line 1960
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1961
    .line 1962
    .line 1963
    move-result v5

    .line 1964
    goto/16 :goto_17

    .line 1965
    .line 1966
    :pswitch_53
    move/from16 v22, v3

    .line 1967
    .line 1968
    move/from16 v23, v4

    .line 1969
    .line 1970
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1971
    .line 1972
    .line 1973
    move-result-object v3

    .line 1974
    check-cast v3, Ljava/util/List;

    .line 1975
    .line 1976
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1977
    .line 1978
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1979
    .line 1980
    .line 1981
    move-result v4

    .line 1982
    if-nez v4, :cond_20

    .line 1983
    .line 1984
    goto/16 :goto_16

    .line 1985
    .line 1986
    :cond_20
    invoke-static {v3}, Lcom/google/protobuf/x0;->i(Ljava/util/List;)I

    .line 1987
    .line 1988
    .line 1989
    move-result v3

    .line 1990
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 1991
    .line 1992
    .line 1993
    move-result v5

    .line 1994
    goto/16 :goto_17

    .line 1995
    .line 1996
    :pswitch_54
    move/from16 v22, v3

    .line 1997
    .line 1998
    move/from16 v23, v4

    .line 1999
    .line 2000
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2001
    .line 2002
    .line 2003
    move-result-object v3

    .line 2004
    check-cast v3, Ljava/util/List;

    .line 2005
    .line 2006
    sget-object v4, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 2007
    .line 2008
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 2009
    .line 2010
    .line 2011
    move-result v4

    .line 2012
    if-nez v4, :cond_21

    .line 2013
    .line 2014
    goto/16 :goto_16

    .line 2015
    .line 2016
    :cond_21
    invoke-static {v3}, Lcom/google/protobuf/x0;->e(Ljava/util/List;)I

    .line 2017
    .line 2018
    .line 2019
    move-result v4

    .line 2020
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 2021
    .line 2022
    .line 2023
    move-result v3

    .line 2024
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2025
    .line 2026
    .line 2027
    move-result v5

    .line 2028
    mul-int/2addr v5, v3

    .line 2029
    add-int/2addr v5, v4

    .line 2030
    goto/16 :goto_18

    .line 2031
    .line 2032
    :pswitch_55
    move/from16 v22, v3

    .line 2033
    .line 2034
    move/from16 v23, v4

    .line 2035
    .line 2036
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2037
    .line 2038
    .line 2039
    move-result-object v3

    .line 2040
    check-cast v3, Ljava/util/List;

    .line 2041
    .line 2042
    invoke-static {v12, v3}, Lcom/google/protobuf/x0;->b(ILjava/util/List;)I

    .line 2043
    .line 2044
    .line 2045
    move-result v3

    .line 2046
    goto/16 :goto_19

    .line 2047
    .line 2048
    :pswitch_56
    move/from16 v22, v3

    .line 2049
    .line 2050
    move/from16 v23, v4

    .line 2051
    .line 2052
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2053
    .line 2054
    .line 2055
    move-result-object v3

    .line 2056
    check-cast v3, Ljava/util/List;

    .line 2057
    .line 2058
    invoke-static {v12, v3}, Lcom/google/protobuf/x0;->c(ILjava/util/List;)I

    .line 2059
    .line 2060
    .line 2061
    move-result v3

    .line 2062
    goto/16 :goto_19

    .line 2063
    .line 2064
    :pswitch_57
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2065
    .line 2066
    .line 2067
    move-result v5

    .line 2068
    if-eqz v5, :cond_25

    .line 2069
    .line 2070
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2071
    .line 2072
    .line 2073
    move-result-object v5

    .line 2074
    check-cast v5, Lcom/google/protobuf/a;

    .line 2075
    .line 2076
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 2077
    .line 2078
    .line 2079
    move-result-object v7

    .line 2080
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2081
    .line 2082
    .line 2083
    move-result v8

    .line 2084
    mul-int/lit8 v8, v8, 0x2

    .line 2085
    .line 2086
    invoke-virtual {v5, v7}, Lcom/google/protobuf/a;->h(Lcom/google/protobuf/w0;)I

    .line 2087
    .line 2088
    .line 2089
    move-result v5

    .line 2090
    add-int/2addr v5, v8

    .line 2091
    goto/16 :goto_3

    .line 2092
    .line 2093
    :pswitch_58
    move/from16 v19, v10

    .line 2094
    .line 2095
    move/from16 v20, v15

    .line 2096
    .line 2097
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2098
    .line 2099
    .line 2100
    move-result v5

    .line 2101
    if-eqz v5, :cond_22

    .line 2102
    .line 2103
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2104
    .line 2105
    .line 2106
    move-result-wide v7

    .line 2107
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2108
    .line 2109
    .line 2110
    move-result v0

    .line 2111
    shl-long v10, v7, v20

    .line 2112
    .line 2113
    shr-long v7, v7, v19

    .line 2114
    .line 2115
    xor-long/2addr v7, v10

    .line 2116
    invoke-static {v7, v8}, Lcom/google/protobuf/f;->h(J)I

    .line 2117
    .line 2118
    .line 2119
    move-result v5

    .line 2120
    :goto_22
    add-int/2addr v5, v0

    .line 2121
    add-int/2addr v9, v5

    .line 2122
    :cond_22
    :goto_23
    move-object/from16 v0, p0

    .line 2123
    .line 2124
    goto/16 :goto_29

    .line 2125
    .line 2126
    :pswitch_59
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2127
    .line 2128
    .line 2129
    move-result v5

    .line 2130
    if-eqz v5, :cond_22

    .line 2131
    .line 2132
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2133
    .line 2134
    .line 2135
    move-result v0

    .line 2136
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2137
    .line 2138
    .line 2139
    move-result v5

    .line 2140
    shl-int/lit8 v7, v0, 0x1

    .line 2141
    .line 2142
    shr-int/lit8 v0, v0, 0x1f

    .line 2143
    .line 2144
    xor-int/2addr v0, v7

    .line 2145
    invoke-static {v0}, Lcom/google/protobuf/f;->g(I)I

    .line 2146
    .line 2147
    .line 2148
    move-result v0

    .line 2149
    :goto_24
    add-int/2addr v0, v5

    .line 2150
    add-int/2addr v9, v0

    .line 2151
    goto :goto_23

    .line 2152
    :pswitch_5a
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2153
    .line 2154
    .line 2155
    move-result v5

    .line 2156
    if-eqz v5, :cond_23

    .line 2157
    .line 2158
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2159
    .line 2160
    .line 2161
    move-result v0

    .line 2162
    :goto_25
    add-int/lit8 v0, v0, 0x8

    .line 2163
    .line 2164
    :goto_26
    add-int/2addr v9, v0

    .line 2165
    :cond_23
    move-object/from16 v0, p0

    .line 2166
    .line 2167
    move-object/from16 v1, p1

    .line 2168
    .line 2169
    goto/16 :goto_29

    .line 2170
    .line 2171
    :pswitch_5b
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2172
    .line 2173
    .line 2174
    move-result v5

    .line 2175
    if-eqz v5, :cond_23

    .line 2176
    .line 2177
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2178
    .line 2179
    .line 2180
    move-result v0

    .line 2181
    :goto_27
    add-int/lit8 v0, v0, 0x4

    .line 2182
    .line 2183
    goto :goto_26

    .line 2184
    :pswitch_5c
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2185
    .line 2186
    .line 2187
    move-result v5

    .line 2188
    if-eqz v5, :cond_22

    .line 2189
    .line 2190
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2191
    .line 2192
    .line 2193
    move-result v0

    .line 2194
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2195
    .line 2196
    .line 2197
    move-result v5

    .line 2198
    invoke-static {v0}, Lcom/google/protobuf/f;->d(I)I

    .line 2199
    .line 2200
    .line 2201
    move-result v0

    .line 2202
    goto :goto_24

    .line 2203
    :pswitch_5d
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2204
    .line 2205
    .line 2206
    move-result v5

    .line 2207
    if-eqz v5, :cond_22

    .line 2208
    .line 2209
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2210
    .line 2211
    .line 2212
    move-result v0

    .line 2213
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2214
    .line 2215
    .line 2216
    move-result v5

    .line 2217
    invoke-static {v0}, Lcom/google/protobuf/f;->g(I)I

    .line 2218
    .line 2219
    .line 2220
    move-result v0

    .line 2221
    goto :goto_24

    .line 2222
    :pswitch_5e
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2223
    .line 2224
    .line 2225
    move-result v5

    .line 2226
    if-eqz v5, :cond_22

    .line 2227
    .line 2228
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2229
    .line 2230
    .line 2231
    move-result-object v0

    .line 2232
    check-cast v0, Lcom/google/protobuf/e;

    .line 2233
    .line 2234
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2235
    .line 2236
    .line 2237
    move-result v5

    .line 2238
    invoke-virtual {v0}, Lcom/google/protobuf/e;->size()I

    .line 2239
    .line 2240
    .line 2241
    move-result v0

    .line 2242
    invoke-static {v0, v0, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 2243
    .line 2244
    .line 2245
    move-result v9

    .line 2246
    goto :goto_23

    .line 2247
    :pswitch_5f
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2248
    .line 2249
    .line 2250
    move-result v5

    .line 2251
    if-eqz v5, :cond_25

    .line 2252
    .line 2253
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2254
    .line 2255
    .line 2256
    move-result-object v5

    .line 2257
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 2258
    .line 2259
    .line 2260
    move-result-object v7

    .line 2261
    sget-object v8, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 2262
    .line 2263
    check-cast v5, Lcom/google/protobuf/a;

    .line 2264
    .line 2265
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2266
    .line 2267
    .line 2268
    move-result v8

    .line 2269
    invoke-virtual {v5, v7}, Lcom/google/protobuf/a;->h(Lcom/google/protobuf/w0;)I

    .line 2270
    .line 2271
    .line 2272
    move-result v5

    .line 2273
    invoke-static {v5, v5, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 2274
    .line 2275
    .line 2276
    move-result v9

    .line 2277
    goto/16 :goto_29

    .line 2278
    .line 2279
    :pswitch_60
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2280
    .line 2281
    .line 2282
    move-result v5

    .line 2283
    if-eqz v5, :cond_22

    .line 2284
    .line 2285
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2286
    .line 2287
    .line 2288
    move-result-object v0

    .line 2289
    instance-of v5, v0, Lcom/google/protobuf/e;

    .line 2290
    .line 2291
    if-eqz v5, :cond_24

    .line 2292
    .line 2293
    check-cast v0, Lcom/google/protobuf/e;

    .line 2294
    .line 2295
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2296
    .line 2297
    .line 2298
    move-result v5

    .line 2299
    invoke-virtual {v0}, Lcom/google/protobuf/e;->size()I

    .line 2300
    .line 2301
    .line 2302
    move-result v0

    .line 2303
    invoke-static {v0, v0, v5, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->B(IIII)I

    .line 2304
    .line 2305
    .line 2306
    move-result v0

    .line 2307
    :goto_28
    move v9, v0

    .line 2308
    goto/16 :goto_23

    .line 2309
    .line 2310
    :cond_24
    check-cast v0, Ljava/lang/String;

    .line 2311
    .line 2312
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2313
    .line 2314
    .line 2315
    move-result v5

    .line 2316
    invoke-static {v0}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 2317
    .line 2318
    .line 2319
    move-result v0

    .line 2320
    add-int/2addr v0, v5

    .line 2321
    add-int/2addr v0, v9

    .line 2322
    goto :goto_28

    .line 2323
    :pswitch_61
    move/from16 v20, v15

    .line 2324
    .line 2325
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2326
    .line 2327
    .line 2328
    move-result v5

    .line 2329
    if-eqz v5, :cond_23

    .line 2330
    .line 2331
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2332
    .line 2333
    .line 2334
    move-result v0

    .line 2335
    add-int/lit8 v0, v0, 0x1

    .line 2336
    .line 2337
    goto/16 :goto_26

    .line 2338
    .line 2339
    :pswitch_62
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2340
    .line 2341
    .line 2342
    move-result v5

    .line 2343
    if-eqz v5, :cond_23

    .line 2344
    .line 2345
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2346
    .line 2347
    .line 2348
    move-result v0

    .line 2349
    goto/16 :goto_27

    .line 2350
    .line 2351
    :pswitch_63
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2352
    .line 2353
    .line 2354
    move-result v5

    .line 2355
    if-eqz v5, :cond_23

    .line 2356
    .line 2357
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2358
    .line 2359
    .line 2360
    move-result v0

    .line 2361
    goto/16 :goto_25

    .line 2362
    .line 2363
    :pswitch_64
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2364
    .line 2365
    .line 2366
    move-result v5

    .line 2367
    if-eqz v5, :cond_22

    .line 2368
    .line 2369
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2370
    .line 2371
    .line 2372
    move-result v0

    .line 2373
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2374
    .line 2375
    .line 2376
    move-result v5

    .line 2377
    invoke-static {v0}, Lcom/google/protobuf/f;->d(I)I

    .line 2378
    .line 2379
    .line 2380
    move-result v0

    .line 2381
    goto/16 :goto_24

    .line 2382
    .line 2383
    :pswitch_65
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2384
    .line 2385
    .line 2386
    move-result v5

    .line 2387
    if-eqz v5, :cond_22

    .line 2388
    .line 2389
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2390
    .line 2391
    .line 2392
    move-result-wide v7

    .line 2393
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2394
    .line 2395
    .line 2396
    move-result v0

    .line 2397
    invoke-static {v7, v8}, Lcom/google/protobuf/f;->h(J)I

    .line 2398
    .line 2399
    .line 2400
    move-result v5

    .line 2401
    goto/16 :goto_22

    .line 2402
    .line 2403
    :pswitch_66
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2404
    .line 2405
    .line 2406
    move-result v5

    .line 2407
    if-eqz v5, :cond_22

    .line 2408
    .line 2409
    invoke-virtual {v6, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2410
    .line 2411
    .line 2412
    move-result-wide v7

    .line 2413
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2414
    .line 2415
    .line 2416
    move-result v0

    .line 2417
    invoke-static {v7, v8}, Lcom/google/protobuf/f;->h(J)I

    .line 2418
    .line 2419
    .line 2420
    move-result v5

    .line 2421
    goto/16 :goto_22

    .line 2422
    .line 2423
    :pswitch_67
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2424
    .line 2425
    .line 2426
    move-result v5

    .line 2427
    if-eqz v5, :cond_23

    .line 2428
    .line 2429
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2430
    .line 2431
    .line 2432
    move-result v0

    .line 2433
    goto/16 :goto_27

    .line 2434
    .line 2435
    :pswitch_68
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2436
    .line 2437
    .line 2438
    move-result v5

    .line 2439
    if-eqz v5, :cond_25

    .line 2440
    .line 2441
    invoke-static {v12}, Lcom/google/protobuf/f;->f(I)I

    .line 2442
    .line 2443
    .line 2444
    move-result v5

    .line 2445
    goto/16 :goto_6

    .line 2446
    .line 2447
    :cond_25
    :goto_29
    add-int/lit8 v2, v2, 0x3

    .line 2448
    .line 2449
    const v8, 0xfffff

    .line 2450
    .line 2451
    .line 2452
    goto/16 :goto_0

    .line 2453
    .line 2454
    :cond_26
    iget-object v0, v0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 2455
    .line 2456
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2457
    .line 2458
    .line 2459
    iget-object v0, v1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 2460
    .line 2461
    invoke-virtual {v0}, Lcom/google/protobuf/d1;->a()I

    .line 2462
    .line 2463
    .line 2464
    move-result v0

    .line 2465
    add-int/2addr v0, v9

    .line 2466
    return v0

    .line 2467
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_68
        :pswitch_67
        :pswitch_66
        :pswitch_65
        :pswitch_64
        :pswitch_63
        :pswitch_62
        :pswitch_61
        :pswitch_60
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_55
        :pswitch_54
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2468
    .line 2469
    .line 2470
    .line 2471
    .line 2472
    .line 2473
    .line 2474
    .line 2475
    .line 2476
    .line 2477
    .line 2478
    .line 2479
    .line 2480
    .line 2481
    .line 2482
    .line 2483
    .line 2484
    .line 2485
    .line 2486
    .line 2487
    .line 2488
    .line 2489
    .line 2490
    .line 2491
    .line 2492
    .line 2493
    .line 2494
    .line 2495
    .line 2496
    .line 2497
    .line 2498
    .line 2499
    .line 2500
    .line 2501
    .line 2502
    .line 2503
    .line 2504
    .line 2505
    .line 2506
    .line 2507
    .line 2508
    .line 2509
    .line 2510
    .line 2511
    .line 2512
    .line 2513
    .line 2514
    .line 2515
    .line 2516
    .line 2517
    .line 2518
    .line 2519
    .line 2520
    .line 2521
    .line 2522
    .line 2523
    .line 2524
    .line 2525
    .line 2526
    .line 2527
    .line 2528
    .line 2529
    .line 2530
    .line 2531
    .line 2532
    .line 2533
    .line 2534
    .line 2535
    .line 2536
    .line 2537
    .line 2538
    .line 2539
    .line 2540
    .line 2541
    .line 2542
    .line 2543
    .line 2544
    .line 2545
    .line 2546
    .line 2547
    .line 2548
    .line 2549
    .line 2550
    .line 2551
    .line 2552
    .line 2553
    .line 2554
    .line 2555
    .line 2556
    .line 2557
    .line 2558
    .line 2559
    .line 2560
    .line 2561
    .line 2562
    .line 2563
    .line 2564
    .line 2565
    .line 2566
    .line 2567
    .line 2568
    .line 2569
    .line 2570
    .line 2571
    .line 2572
    .line 2573
    .line 2574
    .line 2575
    .line 2576
    .line 2577
    .line 2578
    .line 2579
    .line 2580
    .line 2581
    .line 2582
    .line 2583
    .line 2584
    .line 2585
    .line 2586
    .line 2587
    .line 2588
    .line 2589
    .line 2590
    .line 2591
    .line 2592
    .line 2593
    .line 2594
    .line 2595
    .line 2596
    .line 2597
    .line 2598
    .line 2599
    .line 2600
    .line 2601
    .line 2602
    .line 2603
    .line 2604
    .line 2605
    .line 2606
    .line 2607
    .line 2608
    .line 2609
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
    .end packed-switch

    .line 2610
    .line 2611
    .line 2612
    .line 2613
    .line 2614
    .line 2615
    .line 2616
    .line 2617
    .line 2618
    .line 2619
    .line 2620
    .line 2621
    .line 2622
    .line 2623
    .line 2624
    .line 2625
    .line 2626
    .line 2627
    .line 2628
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
    .end packed-switch
.end method

.method public final h(Lcom/google/protobuf/p;Lcom/google/protobuf/p;)Z
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    const/4 v4, 0x1

    .line 7
    if-ge v3, v1, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, v3}, Lcom/google/protobuf/n0;->x(I)I

    .line 10
    .line 11
    .line 12
    move-result v5

    .line 13
    const v6, 0xfffff

    .line 14
    .line 15
    .line 16
    and-int v7, v5, v6

    .line 17
    .line 18
    int-to-long v7, v7

    .line 19
    invoke-static {v5}, Lcom/google/protobuf/n0;->w(I)I

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    packed-switch v5, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    goto/16 :goto_1

    .line 27
    .line 28
    :pswitch_0
    add-int/lit8 v5, v3, 0x2

    .line 29
    .line 30
    aget v5, v0, v5

    .line 31
    .line 32
    and-int/2addr v5, v6

    .line 33
    int-to-long v5, v5

    .line 34
    sget-object v9, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 35
    .line 36
    invoke-virtual {v9, v5, v6, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 37
    .line 38
    .line 39
    move-result v10

    .line 40
    invoke-virtual {v9, v5, v6, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-ne v10, v5, :cond_0

    .line 45
    .line 46
    invoke-virtual {v9, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    invoke-virtual {v9, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v6

    .line 54
    invoke-static {v5, v6}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_0

    .line 59
    .line 60
    goto/16 :goto_1

    .line 61
    .line 62
    :cond_0
    move v4, v2

    .line 63
    goto/16 :goto_1

    .line 64
    .line 65
    :pswitch_1
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 66
    .line 67
    invoke-virtual {v4, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-virtual {v4, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    invoke-static {v5, v4}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    goto/16 :goto_1

    .line 80
    .line 81
    :pswitch_2
    sget-object v4, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 82
    .line 83
    invoke-virtual {v4, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    invoke-virtual {v4, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    invoke-static {v5, v4}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    goto/16 :goto_1

    .line 96
    .line 97
    :pswitch_3
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 98
    .line 99
    .line 100
    move-result v5

    .line 101
    if-eqz v5, :cond_0

    .line 102
    .line 103
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 104
    .line 105
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    invoke-static {v6, v5}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_0

    .line 118
    .line 119
    goto/16 :goto_1

    .line 120
    .line 121
    :pswitch_4
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    if-eqz v5, :cond_0

    .line 126
    .line 127
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 128
    .line 129
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 130
    .line 131
    .line 132
    move-result-wide v9

    .line 133
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 134
    .line 135
    .line 136
    move-result-wide v5

    .line 137
    cmp-long v5, v9, v5

    .line 138
    .line 139
    if-nez v5, :cond_0

    .line 140
    .line 141
    goto/16 :goto_1

    .line 142
    .line 143
    :pswitch_5
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-eqz v5, :cond_0

    .line 148
    .line 149
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 150
    .line 151
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-ne v6, v5, :cond_0

    .line 160
    .line 161
    goto/16 :goto_1

    .line 162
    .line 163
    :pswitch_6
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    if-eqz v5, :cond_0

    .line 168
    .line 169
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 170
    .line 171
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 172
    .line 173
    .line 174
    move-result-wide v9

    .line 175
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 176
    .line 177
    .line 178
    move-result-wide v5

    .line 179
    cmp-long v5, v9, v5

    .line 180
    .line 181
    if-nez v5, :cond_0

    .line 182
    .line 183
    goto/16 :goto_1

    .line 184
    .line 185
    :pswitch_7
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    if-eqz v5, :cond_0

    .line 190
    .line 191
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 192
    .line 193
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 194
    .line 195
    .line 196
    move-result v6

    .line 197
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-ne v6, v5, :cond_0

    .line 202
    .line 203
    goto/16 :goto_1

    .line 204
    .line 205
    :pswitch_8
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    if-eqz v5, :cond_0

    .line 210
    .line 211
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 212
    .line 213
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    if-ne v6, v5, :cond_0

    .line 222
    .line 223
    goto/16 :goto_1

    .line 224
    .line 225
    :pswitch_9
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    if-eqz v5, :cond_0

    .line 230
    .line 231
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 232
    .line 233
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 234
    .line 235
    .line 236
    move-result v6

    .line 237
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 238
    .line 239
    .line 240
    move-result v5

    .line 241
    if-ne v6, v5, :cond_0

    .line 242
    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :pswitch_a
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 246
    .line 247
    .line 248
    move-result v5

    .line 249
    if-eqz v5, :cond_0

    .line 250
    .line 251
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 252
    .line 253
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v6

    .line 257
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    invoke-static {v6, v5}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v5

    .line 265
    if-eqz v5, :cond_0

    .line 266
    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :pswitch_b
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 270
    .line 271
    .line 272
    move-result v5

    .line 273
    if-eqz v5, :cond_0

    .line 274
    .line 275
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 276
    .line 277
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v6

    .line 281
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v5

    .line 285
    invoke-static {v6, v5}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v5

    .line 289
    if-eqz v5, :cond_0

    .line 290
    .line 291
    goto/16 :goto_1

    .line 292
    .line 293
    :pswitch_c
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    if-eqz v5, :cond_0

    .line 298
    .line 299
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 300
    .line 301
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v5

    .line 309
    invoke-static {v6, v5}, Lcom/google/protobuf/x0;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    move-result v5

    .line 313
    if-eqz v5, :cond_0

    .line 314
    .line 315
    goto/16 :goto_1

    .line 316
    .line 317
    :pswitch_d
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 318
    .line 319
    .line 320
    move-result v5

    .line 321
    if-eqz v5, :cond_0

    .line 322
    .line 323
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 324
    .line 325
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->c(JLjava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->c(JLjava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v5

    .line 333
    if-ne v6, v5, :cond_0

    .line 334
    .line 335
    goto/16 :goto_1

    .line 336
    .line 337
    :pswitch_e
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    if-eqz v5, :cond_0

    .line 342
    .line 343
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 344
    .line 345
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 350
    .line 351
    .line 352
    move-result v5

    .line 353
    if-ne v6, v5, :cond_0

    .line 354
    .line 355
    goto/16 :goto_1

    .line 356
    .line 357
    :pswitch_f
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    if-eqz v5, :cond_0

    .line 362
    .line 363
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 364
    .line 365
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 366
    .line 367
    .line 368
    move-result-wide v9

    .line 369
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 370
    .line 371
    .line 372
    move-result-wide v5

    .line 373
    cmp-long v5, v9, v5

    .line 374
    .line 375
    if-nez v5, :cond_0

    .line 376
    .line 377
    goto/16 :goto_1

    .line 378
    .line 379
    :pswitch_10
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 380
    .line 381
    .line 382
    move-result v5

    .line 383
    if-eqz v5, :cond_0

    .line 384
    .line 385
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 386
    .line 387
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 388
    .line 389
    .line 390
    move-result v6

    .line 391
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 392
    .line 393
    .line 394
    move-result v5

    .line 395
    if-ne v6, v5, :cond_0

    .line 396
    .line 397
    goto :goto_1

    .line 398
    :pswitch_11
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 399
    .line 400
    .line 401
    move-result v5

    .line 402
    if-eqz v5, :cond_0

    .line 403
    .line 404
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 405
    .line 406
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 407
    .line 408
    .line 409
    move-result-wide v9

    .line 410
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 411
    .line 412
    .line 413
    move-result-wide v5

    .line 414
    cmp-long v5, v9, v5

    .line 415
    .line 416
    if-nez v5, :cond_0

    .line 417
    .line 418
    goto :goto_1

    .line 419
    :pswitch_12
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 420
    .line 421
    .line 422
    move-result v5

    .line 423
    if-eqz v5, :cond_0

    .line 424
    .line 425
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 426
    .line 427
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 428
    .line 429
    .line 430
    move-result-wide v9

    .line 431
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 432
    .line 433
    .line 434
    move-result-wide v5

    .line 435
    cmp-long v5, v9, v5

    .line 436
    .line 437
    if-nez v5, :cond_0

    .line 438
    .line 439
    goto :goto_1

    .line 440
    :pswitch_13
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 441
    .line 442
    .line 443
    move-result v5

    .line 444
    if-eqz v5, :cond_0

    .line 445
    .line 446
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 447
    .line 448
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->f(JLjava/lang/Object;)F

    .line 449
    .line 450
    .line 451
    move-result v6

    .line 452
    invoke-static {v6}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 453
    .line 454
    .line 455
    move-result v6

    .line 456
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->f(JLjava/lang/Object;)F

    .line 457
    .line 458
    .line 459
    move-result v5

    .line 460
    invoke-static {v5}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 461
    .line 462
    .line 463
    move-result v5

    .line 464
    if-ne v6, v5, :cond_0

    .line 465
    .line 466
    goto :goto_1

    .line 467
    :pswitch_14
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/protobuf/n0;->i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z

    .line 468
    .line 469
    .line 470
    move-result v5

    .line 471
    if-eqz v5, :cond_0

    .line 472
    .line 473
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 474
    .line 475
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/protobuf/l1;->e(JLjava/lang/Object;)D

    .line 476
    .line 477
    .line 478
    move-result-wide v9

    .line 479
    invoke-static {v9, v10}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 480
    .line 481
    .line 482
    move-result-wide v9

    .line 483
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/protobuf/l1;->e(JLjava/lang/Object;)D

    .line 484
    .line 485
    .line 486
    move-result-wide v5

    .line 487
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 488
    .line 489
    .line 490
    move-result-wide v5

    .line 491
    cmp-long v5, v9, v5

    .line 492
    .line 493
    if-nez v5, :cond_0

    .line 494
    .line 495
    :goto_1
    if-nez v4, :cond_1

    .line 496
    .line 497
    goto :goto_2

    .line 498
    :cond_1
    add-int/lit8 v3, v3, 0x3

    .line 499
    .line 500
    goto/16 :goto_0

    .line 501
    .line 502
    :cond_2
    iget-object p0, p0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 503
    .line 504
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 505
    .line 506
    .line 507
    iget-object p0, p1, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 508
    .line 509
    iget-object p1, p2, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 510
    .line 511
    invoke-virtual {p0, p1}, Lcom/google/protobuf/d1;->equals(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result p0

    .line 515
    if-nez p0, :cond_3

    .line 516
    .line 517
    :goto_2
    return v2

    .line 518
    :cond_3
    return v4

    .line 519
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Lcom/google/protobuf/p;Lcom/google/protobuf/p;I)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p3, p1}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0, p3, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-ne p1, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final j(I)Lcom/google/protobuf/w0;
    .locals 2

    .line 1
    div-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    mul-int/lit8 p1, p1, 0x2

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/protobuf/n0;->b:[Ljava/lang/Object;

    .line 6
    .line 7
    aget-object v0, p0, p1

    .line 8
    .line 9
    check-cast v0, Lcom/google/protobuf/w0;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    sget-object v0, Lcom/google/protobuf/t0;->c:Lcom/google/protobuf/t0;

    .line 15
    .line 16
    add-int/lit8 v1, p1, 0x1

    .line 17
    .line 18
    aget-object v1, p0, v1

    .line 19
    .line 20
    check-cast v1, Ljava/lang/Class;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lcom/google/protobuf/t0;->a(Ljava/lang/Class;)Lcom/google/protobuf/w0;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    aput-object v0, p0, p1

    .line 27
    .line 28
    return-object v0
.end method

.method public final k(ILjava/lang/Object;)Z
    .locals 6

    .line 1
    add-int/lit8 v0, p1, 0x2

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/protobuf/n0;->a:[I

    .line 4
    .line 5
    aget v0, v1, v0

    .line 6
    .line 7
    const v1, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int v2, v0, v1

    .line 11
    .line 12
    int-to-long v2, v2

    .line 13
    const-wide/32 v4, 0xfffff

    .line 14
    .line 15
    .line 16
    cmp-long v4, v2, v4

    .line 17
    .line 18
    const/4 v5, 0x1

    .line 19
    if-nez v4, :cond_2

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lcom/google/protobuf/n0;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    and-int p1, p0, v1

    .line 26
    .line 27
    int-to-long v0, p1

    .line 28
    invoke-static {p0}, Lcom/google/protobuf/n0;->w(I)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    const-wide/16 v2, 0x0

    .line 33
    .line 34
    packed-switch p0, :pswitch_data_0

    .line 35
    .line 36
    .line 37
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 38
    .line 39
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :pswitch_0
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 44
    .line 45
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :pswitch_1
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 54
    .line 55
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 56
    .line 57
    .line 58
    move-result-wide p0

    .line 59
    cmp-long p0, p0, v2

    .line 60
    .line 61
    if-eqz p0, :cond_3

    .line 62
    .line 63
    goto/16 :goto_0

    .line 64
    .line 65
    :pswitch_2
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 66
    .line 67
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    goto/16 :goto_0

    .line 74
    .line 75
    :pswitch_3
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 76
    .line 77
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 78
    .line 79
    .line 80
    move-result-wide p0

    .line 81
    cmp-long p0, p0, v2

    .line 82
    .line 83
    if-eqz p0, :cond_3

    .line 84
    .line 85
    goto/16 :goto_0

    .line 86
    .line 87
    :pswitch_4
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 88
    .line 89
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_3

    .line 94
    .line 95
    goto/16 :goto_0

    .line 96
    .line 97
    :pswitch_5
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 98
    .line 99
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    if-eqz p0, :cond_3

    .line 104
    .line 105
    goto/16 :goto_0

    .line 106
    .line 107
    :pswitch_6
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 108
    .line 109
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    if-eqz p0, :cond_3

    .line 114
    .line 115
    goto/16 :goto_0

    .line 116
    .line 117
    :pswitch_7
    sget-object p0, Lcom/google/protobuf/e;->f:Lcom/google/protobuf/e;

    .line 118
    .line 119
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 120
    .line 121
    invoke-virtual {p1, p2, v0, v1}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {p0, p1}, Lcom/google/protobuf/e;->equals(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    xor-int/2addr p0, v5

    .line 130
    return p0

    .line 131
    :pswitch_8
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 132
    .line 133
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-eqz p0, :cond_3

    .line 138
    .line 139
    goto/16 :goto_0

    .line 140
    .line 141
    :pswitch_9
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 142
    .line 143
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    instance-of p1, p0, Ljava/lang/String;

    .line 148
    .line 149
    if-eqz p1, :cond_0

    .line 150
    .line 151
    check-cast p0, Ljava/lang/String;

    .line 152
    .line 153
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    xor-int/2addr p0, v5

    .line 158
    return p0

    .line 159
    :cond_0
    instance-of p1, p0, Lcom/google/protobuf/e;

    .line 160
    .line 161
    if-eqz p1, :cond_1

    .line 162
    .line 163
    sget-object p1, Lcom/google/protobuf/e;->f:Lcom/google/protobuf/e;

    .line 164
    .line 165
    invoke-virtual {p1, p0}, Lcom/google/protobuf/e;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result p0

    .line 169
    xor-int/2addr p0, v5

    .line 170
    return p0

    .line 171
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 172
    .line 173
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 174
    .line 175
    .line 176
    throw p0

    .line 177
    :pswitch_a
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 178
    .line 179
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->c(JLjava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result p0

    .line 183
    return p0

    .line 184
    :pswitch_b
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 185
    .line 186
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 187
    .line 188
    .line 189
    move-result p0

    .line 190
    if-eqz p0, :cond_3

    .line 191
    .line 192
    goto :goto_0

    .line 193
    :pswitch_c
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 194
    .line 195
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 196
    .line 197
    .line 198
    move-result-wide p0

    .line 199
    cmp-long p0, p0, v2

    .line 200
    .line 201
    if-eqz p0, :cond_3

    .line 202
    .line 203
    goto :goto_0

    .line 204
    :pswitch_d
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 205
    .line 206
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    if-eqz p0, :cond_3

    .line 211
    .line 212
    goto :goto_0

    .line 213
    :pswitch_e
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 214
    .line 215
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 216
    .line 217
    .line 218
    move-result-wide p0

    .line 219
    cmp-long p0, p0, v2

    .line 220
    .line 221
    if-eqz p0, :cond_3

    .line 222
    .line 223
    goto :goto_0

    .line 224
    :pswitch_f
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 225
    .line 226
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 227
    .line 228
    .line 229
    move-result-wide p0

    .line 230
    cmp-long p0, p0, v2

    .line 231
    .line 232
    if-eqz p0, :cond_3

    .line 233
    .line 234
    goto :goto_0

    .line 235
    :pswitch_10
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 236
    .line 237
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->f(JLjava/lang/Object;)F

    .line 238
    .line 239
    .line 240
    move-result p0

    .line 241
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    if-eqz p0, :cond_3

    .line 246
    .line 247
    goto :goto_0

    .line 248
    :pswitch_11
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 249
    .line 250
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->e(JLjava/lang/Object;)D

    .line 251
    .line 252
    .line 253
    move-result-wide p0

    .line 254
    invoke-static {p0, p1}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 255
    .line 256
    .line 257
    move-result-wide p0

    .line 258
    cmp-long p0, p0, v2

    .line 259
    .line 260
    if-eqz p0, :cond_3

    .line 261
    .line 262
    goto :goto_0

    .line 263
    :cond_2
    ushr-int/lit8 p0, v0, 0x14

    .line 264
    .line 265
    shl-int p0, v5, p0

    .line 266
    .line 267
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 268
    .line 269
    invoke-virtual {p1, v2, v3, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 270
    .line 271
    .line 272
    move-result p1

    .line 273
    and-int/2addr p0, p1

    .line 274
    if-eqz p0, :cond_3

    .line 275
    .line 276
    :goto_0
    return v5

    .line 277
    :cond_3
    const/4 p0, 0x0

    .line 278
    return p0

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final l(Ljava/lang/Object;IIII)Z
    .locals 1

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    if-ne p3, v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0, p2, p1}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :cond_0
    and-int p0, p4, p5

    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_1
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final n(ILjava/lang/Object;I)Z
    .locals 2

    .line 1
    add-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p3

    .line 6
    .line 7
    const p3, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p0, p3

    .line 11
    int-to-long v0, p0

    .line 12
    sget-object p0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final o(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    invoke-virtual {p0, p1, p3}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/protobuf/n0;->x(I)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const v1, 0xfffff

    .line 13
    .line 14
    .line 15
    and-int/2addr v0, v1

    .line 16
    int-to-long v0, v0

    .line 17
    sget-object v2, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 18
    .line 19
    invoke-virtual {v2, p3, v0, v1}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    if-eqz v3, :cond_4

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/n0;->k(ILjava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    if-nez v4, :cond_2

    .line 34
    .line 35
    invoke-static {v3}, Lcom/google/protobuf/n0;->m(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-nez v4, :cond_1

    .line 40
    .line 41
    invoke-virtual {v2, p2, v0, v1, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    invoke-interface {p3}, Lcom/google/protobuf/w0;->c()Lcom/google/protobuf/p;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-interface {p3, v4, v3}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2, p2, v0, v1, v4}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :goto_0
    invoke-virtual {p0, p1, p2}, Lcom/google/protobuf/n0;->v(ILjava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    invoke-virtual {v2, p2, v0, v1}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Lcom/google/protobuf/n0;->m(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-nez p1, :cond_3

    .line 68
    .line 69
    invoke-interface {p3}, Lcom/google/protobuf/w0;->c()Lcom/google/protobuf/p;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-interface {p3, p1, p0}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2, p2, v0, v1, p1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move-object p0, p1

    .line 80
    :cond_3
    invoke-interface {p3, p0, v3}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_4
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    new-instance v0, Ljava/lang/StringBuilder;

    .line 87
    .line 88
    const-string v1, "Source subfield "

    .line 89
    .line 90
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 94
    .line 95
    aget p0, p0, p1

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string p0, " is present but null: "

    .line 101
    .line 102
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-direct {p2, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p2
.end method

.method public final p(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 2
    .line 3
    aget v1, v0, p1

    .line 4
    .line 5
    invoke-virtual {p0, v1, p3, p1}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/protobuf/n0;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const v3, 0xfffff

    .line 17
    .line 18
    .line 19
    and-int/2addr v2, v3

    .line 20
    int-to-long v4, v2

    .line 21
    sget-object v2, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 22
    .line 23
    invoke-virtual {v2, p3, v4, v5}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    if-eqz v6, :cond_4

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    invoke-virtual {p0, v1, p2, p1}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-nez p0, :cond_2

    .line 38
    .line 39
    invoke-static {v6}, Lcom/google/protobuf/n0;->m(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_1

    .line 44
    .line 45
    invoke-virtual {v2, p2, v4, v5, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-interface {p3}, Lcom/google/protobuf/w0;->c()Lcom/google/protobuf/p;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-interface {p3, p0, v6}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v2, p2, v4, v5, p0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :goto_0
    add-int/lit8 p1, p1, 0x2

    .line 60
    .line 61
    aget p0, v0, p1

    .line 62
    .line 63
    and-int/2addr p0, v3

    .line 64
    int-to-long p0, p0

    .line 65
    invoke-static {p0, p1, p2, v1}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_2
    invoke-virtual {v2, p2, v4, v5}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-static {p0}, Lcom/google/protobuf/n0;->m(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    if-nez p1, :cond_3

    .line 78
    .line 79
    invoke-interface {p3}, Lcom/google/protobuf/w0;->c()Lcom/google/protobuf/p;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-interface {p3, p1, p0}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2, p2, v4, v5, p1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move-object p0, p1

    .line 90
    :cond_3
    invoke-interface {p3, p0, v6}, Lcom/google/protobuf/w0;->d(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    new-instance p2, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    const-string v1, "Source subfield "

    .line 99
    .line 100
    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    aget p1, v0, p1

    .line 104
    .line 105
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    const-string p1, " is present but null: "

    .line 109
    .line 110
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method

.method public final v(ILjava/lang/Object;)V
    .locals 4

    .line 1
    add-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    const p1, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p1, p0

    .line 11
    int-to-long v0, p1

    .line 12
    const-wide/32 v2, 0xfffff

    .line 13
    .line 14
    .line 15
    cmp-long p1, v0, v2

    .line 16
    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    ushr-int/lit8 p0, p0, 0x14

    .line 21
    .line 22
    const/4 p1, 0x1

    .line 23
    shl-int p0, p1, p0

    .line 24
    .line 25
    sget-object p1, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 26
    .line 27
    invoke-virtual {p1, v0, v1, p2}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    or-int/2addr p0, p1

    .line 32
    invoke-static {v0, v1, p2, p0}, Lcom/google/protobuf/m1;->n(JLjava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final x(I)I
    .locals 0

    .line 1
    add-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/protobuf/n0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    return p0
.end method

.method public final y(Ljava/lang/Object;Lcom/google/protobuf/f0;)V
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v6, p2

    .line 6
    .line 7
    iget-object v7, v0, Lcom/google/protobuf/n0;->a:[I

    .line 8
    .line 9
    array-length v8, v7

    .line 10
    sget-object v9, Lcom/google/protobuf/n0;->k:Lsun/misc/Unsafe;

    .line 11
    .line 12
    const v10, 0xfffff

    .line 13
    .line 14
    .line 15
    move v3, v10

    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    :goto_0
    if-ge v2, v8, :cond_17

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    aget v12, v7, v2

    .line 25
    .line 26
    invoke-static {v5}, Lcom/google/protobuf/n0;->w(I)I

    .line 27
    .line 28
    .line 29
    move-result v13

    .line 30
    const/16 v14, 0x11

    .line 31
    .line 32
    if-gt v13, v14, :cond_2

    .line 33
    .line 34
    add-int/lit8 v14, v2, 0x2

    .line 35
    .line 36
    aget v14, v7, v14

    .line 37
    .line 38
    const/16 v16, 0x1

    .line 39
    .line 40
    and-int v15, v14, v10

    .line 41
    .line 42
    if-eq v15, v3, :cond_1

    .line 43
    .line 44
    if-ne v15, v10, :cond_0

    .line 45
    .line 46
    const/4 v4, 0x0

    .line 47
    goto :goto_1

    .line 48
    :cond_0
    int-to-long v3, v15

    .line 49
    invoke-virtual {v9, v1, v3, v4}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    move v4, v3

    .line 54
    :goto_1
    move v3, v15

    .line 55
    :cond_1
    ushr-int/lit8 v14, v14, 0x14

    .line 56
    .line 57
    shl-int v14, v16, v14

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    const/16 v16, 0x1

    .line 61
    .line 62
    const/4 v14, 0x0

    .line 63
    :goto_2
    and-int/2addr v5, v10

    .line 64
    int-to-long v10, v5

    .line 65
    const/16 v17, 0x3f

    .line 66
    .line 67
    const/4 v5, 0x2

    .line 68
    packed-switch v13, :pswitch_data_0

    .line 69
    .line 70
    .line 71
    :cond_3
    :goto_3
    move-object/from16 v26, v7

    .line 72
    .line 73
    :cond_4
    :goto_4
    const/4 v13, 0x0

    .line 74
    goto/16 :goto_19

    .line 75
    .line 76
    :pswitch_0
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eqz v5, :cond_3

    .line 81
    .line 82
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 87
    .line 88
    .line 89
    move-result-object v10

    .line 90
    invoke-virtual {v6, v12, v5, v10}, Lcom/google/protobuf/f0;->a(ILjava/lang/Object;Lcom/google/protobuf/w0;)V

    .line 91
    .line 92
    .line 93
    goto :goto_3

    .line 94
    :pswitch_1
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    if-eqz v5, :cond_3

    .line 99
    .line 100
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 101
    .line 102
    .line 103
    move-result-wide v10

    .line 104
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v5, Lcom/google/protobuf/f;

    .line 107
    .line 108
    shl-long v13, v10, v16

    .line 109
    .line 110
    shr-long v10, v10, v17

    .line 111
    .line 112
    xor-long/2addr v10, v13

    .line 113
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->t(IJ)V

    .line 114
    .line 115
    .line 116
    goto :goto_3

    .line 117
    :pswitch_2
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    if-eqz v5, :cond_3

    .line 122
    .line 123
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v10, Lcom/google/protobuf/f;

    .line 130
    .line 131
    shl-int/lit8 v11, v5, 0x1

    .line 132
    .line 133
    shr-int/lit8 v5, v5, 0x1f

    .line 134
    .line 135
    xor-int/2addr v5, v11

    .line 136
    const/4 v11, 0x0

    .line 137
    invoke-virtual {v10, v12, v11}, Lcom/google/protobuf/f;->r(II)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v10, v5}, Lcom/google/protobuf/f;->s(I)V

    .line 141
    .line 142
    .line 143
    goto :goto_3

    .line 144
    :pswitch_3
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 145
    .line 146
    .line 147
    move-result v5

    .line 148
    if-eqz v5, :cond_3

    .line 149
    .line 150
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 151
    .line 152
    .line 153
    move-result-wide v10

    .line 154
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v5, Lcom/google/protobuf/f;

    .line 157
    .line 158
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->n(IJ)V

    .line 159
    .line 160
    .line 161
    goto :goto_3

    .line 162
    :pswitch_4
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 163
    .line 164
    .line 165
    move-result v5

    .line 166
    if-eqz v5, :cond_3

    .line 167
    .line 168
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 169
    .line 170
    .line 171
    move-result v5

    .line 172
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v10, Lcom/google/protobuf/f;

    .line 175
    .line 176
    invoke-virtual {v10, v12, v5}, Lcom/google/protobuf/f;->l(II)V

    .line 177
    .line 178
    .line 179
    goto :goto_3

    .line 180
    :pswitch_5
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    if-eqz v5, :cond_3

    .line 185
    .line 186
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 187
    .line 188
    .line 189
    move-result v5

    .line 190
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v10, Lcom/google/protobuf/f;

    .line 193
    .line 194
    const/4 v13, 0x0

    .line 195
    invoke-virtual {v10, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v10, v5}, Lcom/google/protobuf/f;->p(I)V

    .line 199
    .line 200
    .line 201
    :cond_5
    move-object/from16 v26, v7

    .line 202
    .line 203
    goto/16 :goto_19

    .line 204
    .line 205
    :pswitch_6
    const/4 v13, 0x0

    .line 206
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 207
    .line 208
    .line 209
    move-result v5

    .line 210
    if-eqz v5, :cond_5

    .line 211
    .line 212
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v10, Lcom/google/protobuf/f;

    .line 219
    .line 220
    invoke-virtual {v10, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v10, v5}, Lcom/google/protobuf/f;->s(I)V

    .line 224
    .line 225
    .line 226
    goto/16 :goto_3

    .line 227
    .line 228
    :pswitch_7
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 229
    .line 230
    .line 231
    move-result v13

    .line 232
    if-eqz v13, :cond_3

    .line 233
    .line 234
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v10

    .line 238
    check-cast v10, Lcom/google/protobuf/e;

    .line 239
    .line 240
    iget-object v11, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast v11, Lcom/google/protobuf/f;

    .line 243
    .line 244
    invoke-virtual {v11, v12, v5}, Lcom/google/protobuf/f;->r(II)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v11, v10}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 248
    .line 249
    .line 250
    goto/16 :goto_3

    .line 251
    .line 252
    :pswitch_8
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 253
    .line 254
    .line 255
    move-result v5

    .line 256
    if-eqz v5, :cond_3

    .line 257
    .line 258
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v5

    .line 262
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 263
    .line 264
    .line 265
    move-result-object v10

    .line 266
    invoke-virtual {v6, v12, v5, v10}, Lcom/google/protobuf/f0;->b(ILjava/lang/Object;Lcom/google/protobuf/w0;)V

    .line 267
    .line 268
    .line 269
    goto/16 :goto_3

    .line 270
    .line 271
    :pswitch_9
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 272
    .line 273
    .line 274
    move-result v13

    .line 275
    if-eqz v13, :cond_3

    .line 276
    .line 277
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v10

    .line 281
    instance-of v11, v10, Ljava/lang/String;

    .line 282
    .line 283
    if-eqz v11, :cond_6

    .line 284
    .line 285
    check-cast v10, Ljava/lang/String;

    .line 286
    .line 287
    iget-object v11, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 288
    .line 289
    check-cast v11, Lcom/google/protobuf/f;

    .line 290
    .line 291
    invoke-virtual {v11, v12, v5}, Lcom/google/protobuf/f;->r(II)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v11, v10}, Lcom/google/protobuf/f;->q(Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    goto/16 :goto_3

    .line 298
    .line 299
    :cond_6
    check-cast v10, Lcom/google/protobuf/e;

    .line 300
    .line 301
    iget-object v11, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast v11, Lcom/google/protobuf/f;

    .line 304
    .line 305
    invoke-virtual {v11, v12, v5}, Lcom/google/protobuf/f;->r(II)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v11, v10}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 309
    .line 310
    .line 311
    goto/16 :goto_3

    .line 312
    .line 313
    :pswitch_a
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 314
    .line 315
    .line 316
    move-result v5

    .line 317
    if-eqz v5, :cond_3

    .line 318
    .line 319
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 320
    .line 321
    invoke-virtual {v5, v1, v10, v11}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v5

    .line 325
    check-cast v5, Ljava/lang/Boolean;

    .line 326
    .line 327
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 328
    .line 329
    .line 330
    move-result v5

    .line 331
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 332
    .line 333
    check-cast v10, Lcom/google/protobuf/f;

    .line 334
    .line 335
    const/4 v13, 0x0

    .line 336
    invoke-virtual {v10, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 337
    .line 338
    .line 339
    int-to-byte v5, v5

    .line 340
    invoke-virtual {v10, v5}, Lcom/google/protobuf/f;->i(B)V

    .line 341
    .line 342
    .line 343
    goto/16 :goto_3

    .line 344
    .line 345
    :pswitch_b
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 346
    .line 347
    .line 348
    move-result v5

    .line 349
    if-eqz v5, :cond_3

    .line 350
    .line 351
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 352
    .line 353
    .line 354
    move-result v5

    .line 355
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v10, Lcom/google/protobuf/f;

    .line 358
    .line 359
    invoke-virtual {v10, v12, v5}, Lcom/google/protobuf/f;->l(II)V

    .line 360
    .line 361
    .line 362
    goto/16 :goto_3

    .line 363
    .line 364
    :pswitch_c
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 365
    .line 366
    .line 367
    move-result v5

    .line 368
    if-eqz v5, :cond_3

    .line 369
    .line 370
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 371
    .line 372
    .line 373
    move-result-wide v10

    .line 374
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 375
    .line 376
    check-cast v5, Lcom/google/protobuf/f;

    .line 377
    .line 378
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->n(IJ)V

    .line 379
    .line 380
    .line 381
    goto/16 :goto_3

    .line 382
    .line 383
    :pswitch_d
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 384
    .line 385
    .line 386
    move-result v5

    .line 387
    if-eqz v5, :cond_3

    .line 388
    .line 389
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->s(JLjava/lang/Object;)I

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 394
    .line 395
    check-cast v10, Lcom/google/protobuf/f;

    .line 396
    .line 397
    const/4 v13, 0x0

    .line 398
    invoke-virtual {v10, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 399
    .line 400
    .line 401
    invoke-virtual {v10, v5}, Lcom/google/protobuf/f;->p(I)V

    .line 402
    .line 403
    .line 404
    goto/16 :goto_3

    .line 405
    .line 406
    :pswitch_e
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 407
    .line 408
    .line 409
    move-result v5

    .line 410
    if-eqz v5, :cond_3

    .line 411
    .line 412
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 413
    .line 414
    .line 415
    move-result-wide v10

    .line 416
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 417
    .line 418
    check-cast v5, Lcom/google/protobuf/f;

    .line 419
    .line 420
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->t(IJ)V

    .line 421
    .line 422
    .line 423
    goto/16 :goto_3

    .line 424
    .line 425
    :pswitch_f
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 426
    .line 427
    .line 428
    move-result v5

    .line 429
    if-eqz v5, :cond_3

    .line 430
    .line 431
    invoke-static {v10, v11, v1}, Lcom/google/protobuf/n0;->t(JLjava/lang/Object;)J

    .line 432
    .line 433
    .line 434
    move-result-wide v10

    .line 435
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast v5, Lcom/google/protobuf/f;

    .line 438
    .line 439
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->t(IJ)V

    .line 440
    .line 441
    .line 442
    goto/16 :goto_3

    .line 443
    .line 444
    :pswitch_10
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 445
    .line 446
    .line 447
    move-result v5

    .line 448
    if-eqz v5, :cond_3

    .line 449
    .line 450
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 451
    .line 452
    invoke-virtual {v5, v1, v10, v11}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    move-result-object v5

    .line 456
    check-cast v5, Ljava/lang/Float;

    .line 457
    .line 458
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 459
    .line 460
    .line 461
    move-result v5

    .line 462
    iget-object v10, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v10, Lcom/google/protobuf/f;

    .line 465
    .line 466
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 467
    .line 468
    .line 469
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 470
    .line 471
    .line 472
    move-result v5

    .line 473
    invoke-virtual {v10, v12, v5}, Lcom/google/protobuf/f;->l(II)V

    .line 474
    .line 475
    .line 476
    goto/16 :goto_3

    .line 477
    .line 478
    :pswitch_11
    invoke-virtual {v0, v12, v1, v2}, Lcom/google/protobuf/n0;->n(ILjava/lang/Object;I)Z

    .line 479
    .line 480
    .line 481
    move-result v5

    .line 482
    if-eqz v5, :cond_3

    .line 483
    .line 484
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 485
    .line 486
    invoke-virtual {v5, v1, v10, v11}, Lcom/google/protobuf/l1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v5

    .line 490
    check-cast v5, Ljava/lang/Double;

    .line 491
    .line 492
    invoke-virtual {v5}, Ljava/lang/Double;->doubleValue()D

    .line 493
    .line 494
    .line 495
    move-result-wide v10

    .line 496
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 497
    .line 498
    check-cast v5, Lcom/google/protobuf/f;

    .line 499
    .line 500
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 501
    .line 502
    .line 503
    invoke-static {v10, v11}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 504
    .line 505
    .line 506
    move-result-wide v10

    .line 507
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->n(IJ)V

    .line 508
    .line 509
    .line 510
    goto/16 :goto_3

    .line 511
    .line 512
    :pswitch_12
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v10

    .line 516
    if-eqz v10, :cond_f

    .line 517
    .line 518
    div-int/lit8 v11, v2, 0x3

    .line 519
    .line 520
    mul-int/2addr v11, v5

    .line 521
    iget-object v13, v0, Lcom/google/protobuf/n0;->b:[Ljava/lang/Object;

    .line 522
    .line 523
    aget-object v11, v13, v11

    .line 524
    .line 525
    iget-object v13, v0, Lcom/google/protobuf/n0;->i:Lcom/google/protobuf/j0;

    .line 526
    .line 527
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 528
    .line 529
    .line 530
    check-cast v11, Lcom/google/protobuf/h0;

    .line 531
    .line 532
    iget-object v11, v11, Lcom/google/protobuf/h0;->a:Lcom/google/protobuf/g0;

    .line 533
    .line 534
    iget-object v13, v11, Lcom/google/protobuf/g0;->b:Lcom/google/protobuf/u1;

    .line 535
    .line 536
    iget-object v11, v11, Lcom/google/protobuf/g0;->a:Lcom/google/protobuf/u1;

    .line 537
    .line 538
    check-cast v10, Lcom/google/protobuf/i0;

    .line 539
    .line 540
    iget-object v14, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 541
    .line 542
    check-cast v14, Lcom/google/protobuf/f;

    .line 543
    .line 544
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 545
    .line 546
    .line 547
    invoke-virtual {v10}, Lcom/google/protobuf/i0;->entrySet()Ljava/util/Set;

    .line 548
    .line 549
    .line 550
    move-result-object v10

    .line 551
    invoke-interface {v10}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 552
    .line 553
    .line 554
    move-result-object v10

    .line 555
    :goto_5
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 556
    .line 557
    .line 558
    move-result v18

    .line 559
    if-eqz v18, :cond_f

    .line 560
    .line 561
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 562
    .line 563
    .line 564
    move-result-object v18

    .line 565
    check-cast v18, Ljava/util/Map$Entry;

    .line 566
    .line 567
    invoke-virtual {v14, v12, v5}, Lcom/google/protobuf/f;->r(II)V

    .line 568
    .line 569
    .line 570
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    move-result-object v15

    .line 574
    move/from16 v19, v5

    .line 575
    .line 576
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v5

    .line 580
    sget v20, Lcom/google/protobuf/k;->c:I

    .line 581
    .line 582
    invoke-static/range {v16 .. v16}, Lcom/google/protobuf/f;->f(I)I

    .line 583
    .line 584
    .line 585
    move-result v20

    .line 586
    move/from16 v21, v3

    .line 587
    .line 588
    sget-object v3, Lcom/google/protobuf/u1;->h:Lcom/google/protobuf/r1;

    .line 589
    .line 590
    if-ne v11, v3, :cond_7

    .line 591
    .line 592
    mul-int/lit8 v20, v20, 0x2

    .line 593
    .line 594
    :cond_7
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 595
    .line 596
    .line 597
    move-result v22

    .line 598
    move/from16 v23, v4

    .line 599
    .line 600
    const-string v4, "There is no way to get here, but the compiler thinks otherwise."

    .line 601
    .line 602
    const/16 v24, 0x8

    .line 603
    .line 604
    const/16 v25, 0x4

    .line 605
    .line 606
    move-object/from16 v26, v7

    .line 607
    .line 608
    packed-switch v22, :pswitch_data_1

    .line 609
    .line 610
    .line 611
    new-instance v0, Ljava/lang/RuntimeException;

    .line 612
    .line 613
    invoke-direct {v0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    throw v0

    .line 617
    :pswitch_13
    check-cast v15, Ljava/lang/Long;

    .line 618
    .line 619
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 620
    .line 621
    .line 622
    move-result-wide v27

    .line 623
    shl-long v29, v27, v16

    .line 624
    .line 625
    shr-long v27, v27, v17

    .line 626
    .line 627
    xor-long v27, v29, v27

    .line 628
    .line 629
    invoke-static/range {v27 .. v28}, Lcom/google/protobuf/f;->h(J)I

    .line 630
    .line 631
    .line 632
    move-result v15

    .line 633
    :goto_6
    move v7, v15

    .line 634
    goto/16 :goto_a

    .line 635
    .line 636
    :pswitch_14
    check-cast v15, Ljava/lang/Integer;

    .line 637
    .line 638
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 639
    .line 640
    .line 641
    move-result v15

    .line 642
    shl-int/lit8 v22, v15, 0x1

    .line 643
    .line 644
    shr-int/lit8 v15, v15, 0x1f

    .line 645
    .line 646
    xor-int v15, v22, v15

    .line 647
    .line 648
    invoke-static {v15}, Lcom/google/protobuf/f;->g(I)I

    .line 649
    .line 650
    .line 651
    move-result v15

    .line 652
    goto :goto_6

    .line 653
    :pswitch_15
    check-cast v15, Ljava/lang/Long;

    .line 654
    .line 655
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 656
    .line 657
    .line 658
    :goto_7
    move/from16 v7, v24

    .line 659
    .line 660
    goto/16 :goto_a

    .line 661
    .line 662
    :pswitch_16
    check-cast v15, Ljava/lang/Integer;

    .line 663
    .line 664
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 665
    .line 666
    .line 667
    :goto_8
    move/from16 v7, v25

    .line 668
    .line 669
    goto/16 :goto_a

    .line 670
    .line 671
    :pswitch_17
    instance-of v7, v15, Lau/i;

    .line 672
    .line 673
    if-eqz v7, :cond_8

    .line 674
    .line 675
    check-cast v15, Lau/i;

    .line 676
    .line 677
    iget v7, v15, Lau/i;->d:I

    .line 678
    .line 679
    invoke-static {v7}, Lcom/google/protobuf/f;->d(I)I

    .line 680
    .line 681
    .line 682
    move-result v7

    .line 683
    goto/16 :goto_a

    .line 684
    .line 685
    :cond_8
    check-cast v15, Ljava/lang/Integer;

    .line 686
    .line 687
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 688
    .line 689
    .line 690
    move-result v7

    .line 691
    invoke-static {v7}, Lcom/google/protobuf/f;->d(I)I

    .line 692
    .line 693
    .line 694
    move-result v7

    .line 695
    goto/16 :goto_a

    .line 696
    .line 697
    :pswitch_18
    check-cast v15, Ljava/lang/Integer;

    .line 698
    .line 699
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 700
    .line 701
    .line 702
    move-result v7

    .line 703
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 704
    .line 705
    .line 706
    move-result v7

    .line 707
    goto/16 :goto_a

    .line 708
    .line 709
    :pswitch_19
    instance-of v7, v15, Lcom/google/protobuf/e;

    .line 710
    .line 711
    if-eqz v7, :cond_9

    .line 712
    .line 713
    check-cast v15, Lcom/google/protobuf/e;

    .line 714
    .line 715
    invoke-virtual {v15}, Lcom/google/protobuf/e;->size()I

    .line 716
    .line 717
    .line 718
    move-result v7

    .line 719
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 720
    .line 721
    .line 722
    move-result v15

    .line 723
    :goto_9
    add-int/2addr v7, v15

    .line 724
    goto/16 :goto_a

    .line 725
    .line 726
    :cond_9
    check-cast v15, [B

    .line 727
    .line 728
    array-length v7, v15

    .line 729
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 730
    .line 731
    .line 732
    move-result v15

    .line 733
    goto :goto_9

    .line 734
    :pswitch_1a
    check-cast v15, Lcom/google/protobuf/a;

    .line 735
    .line 736
    check-cast v15, Lcom/google/protobuf/p;

    .line 737
    .line 738
    const/4 v7, 0x0

    .line 739
    invoke-virtual {v15, v7}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 740
    .line 741
    .line 742
    move-result v15

    .line 743
    invoke-static {v15}, Lcom/google/protobuf/f;->g(I)I

    .line 744
    .line 745
    .line 746
    move-result v22

    .line 747
    add-int v15, v22, v15

    .line 748
    .line 749
    goto :goto_6

    .line 750
    :pswitch_1b
    const/4 v7, 0x0

    .line 751
    check-cast v15, Lcom/google/protobuf/a;

    .line 752
    .line 753
    check-cast v15, Lcom/google/protobuf/p;

    .line 754
    .line 755
    invoke-virtual {v15, v7}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 756
    .line 757
    .line 758
    move-result v15

    .line 759
    goto :goto_6

    .line 760
    :pswitch_1c
    instance-of v7, v15, Lcom/google/protobuf/e;

    .line 761
    .line 762
    if-eqz v7, :cond_a

    .line 763
    .line 764
    check-cast v15, Lcom/google/protobuf/e;

    .line 765
    .line 766
    invoke-virtual {v15}, Lcom/google/protobuf/e;->size()I

    .line 767
    .line 768
    .line 769
    move-result v7

    .line 770
    invoke-static {v7}, Lcom/google/protobuf/f;->g(I)I

    .line 771
    .line 772
    .line 773
    move-result v15

    .line 774
    goto :goto_9

    .line 775
    :cond_a
    check-cast v15, Ljava/lang/String;

    .line 776
    .line 777
    invoke-static {v15}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 778
    .line 779
    .line 780
    move-result v7

    .line 781
    goto :goto_a

    .line 782
    :pswitch_1d
    check-cast v15, Ljava/lang/Boolean;

    .line 783
    .line 784
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 785
    .line 786
    .line 787
    move/from16 v7, v16

    .line 788
    .line 789
    goto :goto_a

    .line 790
    :pswitch_1e
    check-cast v15, Ljava/lang/Integer;

    .line 791
    .line 792
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 793
    .line 794
    .line 795
    goto/16 :goto_8

    .line 796
    .line 797
    :pswitch_1f
    check-cast v15, Ljava/lang/Long;

    .line 798
    .line 799
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 800
    .line 801
    .line 802
    goto/16 :goto_7

    .line 803
    .line 804
    :pswitch_20
    check-cast v15, Ljava/lang/Integer;

    .line 805
    .line 806
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 807
    .line 808
    .line 809
    move-result v7

    .line 810
    invoke-static {v7}, Lcom/google/protobuf/f;->d(I)I

    .line 811
    .line 812
    .line 813
    move-result v7

    .line 814
    goto :goto_a

    .line 815
    :pswitch_21
    check-cast v15, Ljava/lang/Long;

    .line 816
    .line 817
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 818
    .line 819
    .line 820
    move-result-wide v27

    .line 821
    invoke-static/range {v27 .. v28}, Lcom/google/protobuf/f;->h(J)I

    .line 822
    .line 823
    .line 824
    move-result v7

    .line 825
    goto :goto_a

    .line 826
    :pswitch_22
    check-cast v15, Ljava/lang/Long;

    .line 827
    .line 828
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 829
    .line 830
    .line 831
    move-result-wide v27

    .line 832
    invoke-static/range {v27 .. v28}, Lcom/google/protobuf/f;->h(J)I

    .line 833
    .line 834
    .line 835
    move-result v7

    .line 836
    goto :goto_a

    .line 837
    :pswitch_23
    check-cast v15, Ljava/lang/Float;

    .line 838
    .line 839
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 840
    .line 841
    .line 842
    goto/16 :goto_8

    .line 843
    .line 844
    :pswitch_24
    check-cast v15, Ljava/lang/Double;

    .line 845
    .line 846
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 847
    .line 848
    .line 849
    goto/16 :goto_7

    .line 850
    .line 851
    :goto_a
    add-int v7, v7, v20

    .line 852
    .line 853
    invoke-static/range {v19 .. v19}, Lcom/google/protobuf/f;->f(I)I

    .line 854
    .line 855
    .line 856
    move-result v15

    .line 857
    if-ne v13, v3, :cond_b

    .line 858
    .line 859
    mul-int/lit8 v15, v15, 0x2

    .line 860
    .line 861
    :cond_b
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    .line 862
    .line 863
    .line 864
    move-result v3

    .line 865
    packed-switch v3, :pswitch_data_2

    .line 866
    .line 867
    .line 868
    new-instance v0, Ljava/lang/RuntimeException;

    .line 869
    .line 870
    invoke-direct {v0, v4}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 871
    .line 872
    .line 873
    throw v0

    .line 874
    :pswitch_25
    check-cast v5, Ljava/lang/Long;

    .line 875
    .line 876
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 877
    .line 878
    .line 879
    move-result-wide v3

    .line 880
    shl-long v24, v3, v16

    .line 881
    .line 882
    shr-long v3, v3, v17

    .line 883
    .line 884
    xor-long v3, v24, v3

    .line 885
    .line 886
    invoke-static {v3, v4}, Lcom/google/protobuf/f;->h(J)I

    .line 887
    .line 888
    .line 889
    move-result v3

    .line 890
    goto/16 :goto_e

    .line 891
    .line 892
    :pswitch_26
    check-cast v5, Ljava/lang/Integer;

    .line 893
    .line 894
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 895
    .line 896
    .line 897
    move-result v3

    .line 898
    shl-int/lit8 v4, v3, 0x1

    .line 899
    .line 900
    shr-int/lit8 v3, v3, 0x1f

    .line 901
    .line 902
    xor-int/2addr v3, v4

    .line 903
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 904
    .line 905
    .line 906
    move-result v3

    .line 907
    goto/16 :goto_e

    .line 908
    .line 909
    :pswitch_27
    check-cast v5, Ljava/lang/Long;

    .line 910
    .line 911
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 912
    .line 913
    .line 914
    :goto_b
    move/from16 v3, v24

    .line 915
    .line 916
    goto/16 :goto_e

    .line 917
    .line 918
    :pswitch_28
    check-cast v5, Ljava/lang/Integer;

    .line 919
    .line 920
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 921
    .line 922
    .line 923
    :goto_c
    move/from16 v3, v25

    .line 924
    .line 925
    goto/16 :goto_e

    .line 926
    .line 927
    :pswitch_29
    instance-of v3, v5, Lau/i;

    .line 928
    .line 929
    if-eqz v3, :cond_c

    .line 930
    .line 931
    check-cast v5, Lau/i;

    .line 932
    .line 933
    iget v3, v5, Lau/i;->d:I

    .line 934
    .line 935
    invoke-static {v3}, Lcom/google/protobuf/f;->d(I)I

    .line 936
    .line 937
    .line 938
    move-result v3

    .line 939
    goto/16 :goto_e

    .line 940
    .line 941
    :cond_c
    check-cast v5, Ljava/lang/Integer;

    .line 942
    .line 943
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 944
    .line 945
    .line 946
    move-result v3

    .line 947
    invoke-static {v3}, Lcom/google/protobuf/f;->d(I)I

    .line 948
    .line 949
    .line 950
    move-result v3

    .line 951
    goto/16 :goto_e

    .line 952
    .line 953
    :pswitch_2a
    check-cast v5, Ljava/lang/Integer;

    .line 954
    .line 955
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 956
    .line 957
    .line 958
    move-result v3

    .line 959
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 960
    .line 961
    .line 962
    move-result v3

    .line 963
    goto/16 :goto_e

    .line 964
    .line 965
    :pswitch_2b
    instance-of v3, v5, Lcom/google/protobuf/e;

    .line 966
    .line 967
    if-eqz v3, :cond_d

    .line 968
    .line 969
    check-cast v5, Lcom/google/protobuf/e;

    .line 970
    .line 971
    invoke-virtual {v5}, Lcom/google/protobuf/e;->size()I

    .line 972
    .line 973
    .line 974
    move-result v3

    .line 975
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 976
    .line 977
    .line 978
    move-result v4

    .line 979
    :goto_d
    add-int/2addr v3, v4

    .line 980
    goto/16 :goto_e

    .line 981
    .line 982
    :cond_d
    check-cast v5, [B

    .line 983
    .line 984
    array-length v3, v5

    .line 985
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 986
    .line 987
    .line 988
    move-result v4

    .line 989
    goto :goto_d

    .line 990
    :pswitch_2c
    check-cast v5, Lcom/google/protobuf/a;

    .line 991
    .line 992
    check-cast v5, Lcom/google/protobuf/p;

    .line 993
    .line 994
    const/4 v3, 0x0

    .line 995
    invoke-virtual {v5, v3}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 996
    .line 997
    .line 998
    move-result v3

    .line 999
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 1000
    .line 1001
    .line 1002
    move-result v4

    .line 1003
    goto :goto_d

    .line 1004
    :pswitch_2d
    const/4 v3, 0x0

    .line 1005
    check-cast v5, Lcom/google/protobuf/a;

    .line 1006
    .line 1007
    check-cast v5, Lcom/google/protobuf/p;

    .line 1008
    .line 1009
    invoke-virtual {v5, v3}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 1010
    .line 1011
    .line 1012
    move-result v3

    .line 1013
    goto :goto_e

    .line 1014
    :pswitch_2e
    instance-of v3, v5, Lcom/google/protobuf/e;

    .line 1015
    .line 1016
    if-eqz v3, :cond_e

    .line 1017
    .line 1018
    check-cast v5, Lcom/google/protobuf/e;

    .line 1019
    .line 1020
    invoke-virtual {v5}, Lcom/google/protobuf/e;->size()I

    .line 1021
    .line 1022
    .line 1023
    move-result v3

    .line 1024
    invoke-static {v3}, Lcom/google/protobuf/f;->g(I)I

    .line 1025
    .line 1026
    .line 1027
    move-result v4

    .line 1028
    goto :goto_d

    .line 1029
    :cond_e
    check-cast v5, Ljava/lang/String;

    .line 1030
    .line 1031
    invoke-static {v5}, Lcom/google/protobuf/f;->e(Ljava/lang/String;)I

    .line 1032
    .line 1033
    .line 1034
    move-result v3

    .line 1035
    goto :goto_e

    .line 1036
    :pswitch_2f
    check-cast v5, Ljava/lang/Boolean;

    .line 1037
    .line 1038
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1039
    .line 1040
    .line 1041
    move/from16 v3, v16

    .line 1042
    .line 1043
    goto :goto_e

    .line 1044
    :pswitch_30
    check-cast v5, Ljava/lang/Integer;

    .line 1045
    .line 1046
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1047
    .line 1048
    .line 1049
    goto :goto_c

    .line 1050
    :pswitch_31
    check-cast v5, Ljava/lang/Long;

    .line 1051
    .line 1052
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1053
    .line 1054
    .line 1055
    goto/16 :goto_b

    .line 1056
    .line 1057
    :pswitch_32
    check-cast v5, Ljava/lang/Integer;

    .line 1058
    .line 1059
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 1060
    .line 1061
    .line 1062
    move-result v3

    .line 1063
    invoke-static {v3}, Lcom/google/protobuf/f;->d(I)I

    .line 1064
    .line 1065
    .line 1066
    move-result v3

    .line 1067
    goto :goto_e

    .line 1068
    :pswitch_33
    check-cast v5, Ljava/lang/Long;

    .line 1069
    .line 1070
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 1071
    .line 1072
    .line 1073
    move-result-wide v3

    .line 1074
    invoke-static {v3, v4}, Lcom/google/protobuf/f;->h(J)I

    .line 1075
    .line 1076
    .line 1077
    move-result v3

    .line 1078
    goto :goto_e

    .line 1079
    :pswitch_34
    check-cast v5, Ljava/lang/Long;

    .line 1080
    .line 1081
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 1082
    .line 1083
    .line 1084
    move-result-wide v3

    .line 1085
    invoke-static {v3, v4}, Lcom/google/protobuf/f;->h(J)I

    .line 1086
    .line 1087
    .line 1088
    move-result v3

    .line 1089
    goto :goto_e

    .line 1090
    :pswitch_35
    check-cast v5, Ljava/lang/Float;

    .line 1091
    .line 1092
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1093
    .line 1094
    .line 1095
    goto/16 :goto_c

    .line 1096
    .line 1097
    :pswitch_36
    check-cast v5, Ljava/lang/Double;

    .line 1098
    .line 1099
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1100
    .line 1101
    .line 1102
    goto/16 :goto_b

    .line 1103
    .line 1104
    :goto_e
    add-int/2addr v3, v15

    .line 1105
    add-int/2addr v3, v7

    .line 1106
    invoke-virtual {v14, v3}, Lcom/google/protobuf/f;->s(I)V

    .line 1107
    .line 1108
    .line 1109
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v3

    .line 1113
    invoke-interface/range {v18 .. v18}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v4

    .line 1117
    move/from16 v5, v16

    .line 1118
    .line 1119
    invoke-static {v14, v11, v5, v3}, Lcom/google/protobuf/k;->b(Lcom/google/protobuf/f;Lcom/google/protobuf/u1;ILjava/lang/Object;)V

    .line 1120
    .line 1121
    .line 1122
    move/from16 v3, v19

    .line 1123
    .line 1124
    invoke-static {v14, v13, v3, v4}, Lcom/google/protobuf/k;->b(Lcom/google/protobuf/f;Lcom/google/protobuf/u1;ILjava/lang/Object;)V

    .line 1125
    .line 1126
    .line 1127
    move v5, v3

    .line 1128
    move/from16 v3, v21

    .line 1129
    .line 1130
    move/from16 v4, v23

    .line 1131
    .line 1132
    move-object/from16 v7, v26

    .line 1133
    .line 1134
    const/16 v16, 0x1

    .line 1135
    .line 1136
    goto/16 :goto_5

    .line 1137
    .line 1138
    :cond_f
    move/from16 v21, v3

    .line 1139
    .line 1140
    move/from16 v23, v4

    .line 1141
    .line 1142
    move-object/from16 v26, v7

    .line 1143
    .line 1144
    :cond_10
    :goto_f
    move/from16 v3, v21

    .line 1145
    .line 1146
    move/from16 v4, v23

    .line 1147
    .line 1148
    goto/16 :goto_4

    .line 1149
    .line 1150
    :pswitch_37
    move/from16 v21, v3

    .line 1151
    .line 1152
    move/from16 v23, v4

    .line 1153
    .line 1154
    move-object/from16 v26, v7

    .line 1155
    .line 1156
    aget v3, v26, v2

    .line 1157
    .line 1158
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v4

    .line 1162
    check-cast v4, Ljava/util/List;

    .line 1163
    .line 1164
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 1165
    .line 1166
    .line 1167
    move-result-object v5

    .line 1168
    sget-object v7, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1169
    .line 1170
    if-eqz v4, :cond_10

    .line 1171
    .line 1172
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1173
    .line 1174
    .line 1175
    move-result v7

    .line 1176
    if-nez v7, :cond_10

    .line 1177
    .line 1178
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1179
    .line 1180
    .line 1181
    const/4 v7, 0x0

    .line 1182
    :goto_10
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1183
    .line 1184
    .line 1185
    move-result v10

    .line 1186
    if-ge v7, v10, :cond_10

    .line 1187
    .line 1188
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v10

    .line 1192
    invoke-virtual {v6, v3, v10, v5}, Lcom/google/protobuf/f0;->a(ILjava/lang/Object;Lcom/google/protobuf/w0;)V

    .line 1193
    .line 1194
    .line 1195
    add-int/lit8 v7, v7, 0x1

    .line 1196
    .line 1197
    goto :goto_10

    .line 1198
    :pswitch_38
    move/from16 v21, v3

    .line 1199
    .line 1200
    move/from16 v23, v4

    .line 1201
    .line 1202
    move-object/from16 v26, v7

    .line 1203
    .line 1204
    aget v3, v26, v2

    .line 1205
    .line 1206
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1207
    .line 1208
    .line 1209
    move-result-object v4

    .line 1210
    check-cast v4, Ljava/util/List;

    .line 1211
    .line 1212
    const/4 v5, 0x1

    .line 1213
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->w(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1214
    .line 1215
    .line 1216
    goto :goto_f

    .line 1217
    :pswitch_39
    move/from16 v21, v3

    .line 1218
    .line 1219
    move/from16 v23, v4

    .line 1220
    .line 1221
    move-object/from16 v26, v7

    .line 1222
    .line 1223
    move/from16 v5, v16

    .line 1224
    .line 1225
    aget v3, v26, v2

    .line 1226
    .line 1227
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v4

    .line 1231
    check-cast v4, Ljava/util/List;

    .line 1232
    .line 1233
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->v(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1234
    .line 1235
    .line 1236
    goto :goto_f

    .line 1237
    :pswitch_3a
    move/from16 v21, v3

    .line 1238
    .line 1239
    move/from16 v23, v4

    .line 1240
    .line 1241
    move-object/from16 v26, v7

    .line 1242
    .line 1243
    move/from16 v5, v16

    .line 1244
    .line 1245
    aget v3, v26, v2

    .line 1246
    .line 1247
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v4

    .line 1251
    check-cast v4, Ljava/util/List;

    .line 1252
    .line 1253
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->u(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1254
    .line 1255
    .line 1256
    goto :goto_f

    .line 1257
    :pswitch_3b
    move/from16 v21, v3

    .line 1258
    .line 1259
    move/from16 v23, v4

    .line 1260
    .line 1261
    move-object/from16 v26, v7

    .line 1262
    .line 1263
    move/from16 v5, v16

    .line 1264
    .line 1265
    aget v3, v26, v2

    .line 1266
    .line 1267
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v4

    .line 1271
    check-cast v4, Ljava/util/List;

    .line 1272
    .line 1273
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->t(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1274
    .line 1275
    .line 1276
    goto/16 :goto_f

    .line 1277
    .line 1278
    :pswitch_3c
    move/from16 v21, v3

    .line 1279
    .line 1280
    move/from16 v23, v4

    .line 1281
    .line 1282
    move-object/from16 v26, v7

    .line 1283
    .line 1284
    move/from16 v5, v16

    .line 1285
    .line 1286
    aget v3, v26, v2

    .line 1287
    .line 1288
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v4

    .line 1292
    check-cast v4, Ljava/util/List;

    .line 1293
    .line 1294
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->n(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1295
    .line 1296
    .line 1297
    goto/16 :goto_f

    .line 1298
    .line 1299
    :pswitch_3d
    move/from16 v21, v3

    .line 1300
    .line 1301
    move/from16 v23, v4

    .line 1302
    .line 1303
    move-object/from16 v26, v7

    .line 1304
    .line 1305
    move/from16 v5, v16

    .line 1306
    .line 1307
    aget v3, v26, v2

    .line 1308
    .line 1309
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1310
    .line 1311
    .line 1312
    move-result-object v4

    .line 1313
    check-cast v4, Ljava/util/List;

    .line 1314
    .line 1315
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->x(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1316
    .line 1317
    .line 1318
    goto/16 :goto_f

    .line 1319
    .line 1320
    :pswitch_3e
    move/from16 v21, v3

    .line 1321
    .line 1322
    move/from16 v23, v4

    .line 1323
    .line 1324
    move-object/from16 v26, v7

    .line 1325
    .line 1326
    move/from16 v5, v16

    .line 1327
    .line 1328
    aget v3, v26, v2

    .line 1329
    .line 1330
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v4

    .line 1334
    check-cast v4, Ljava/util/List;

    .line 1335
    .line 1336
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->l(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1337
    .line 1338
    .line 1339
    goto/16 :goto_f

    .line 1340
    .line 1341
    :pswitch_3f
    move/from16 v21, v3

    .line 1342
    .line 1343
    move/from16 v23, v4

    .line 1344
    .line 1345
    move-object/from16 v26, v7

    .line 1346
    .line 1347
    move/from16 v5, v16

    .line 1348
    .line 1349
    aget v3, v26, v2

    .line 1350
    .line 1351
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1352
    .line 1353
    .line 1354
    move-result-object v4

    .line 1355
    check-cast v4, Ljava/util/List;

    .line 1356
    .line 1357
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->o(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1358
    .line 1359
    .line 1360
    goto/16 :goto_f

    .line 1361
    .line 1362
    :pswitch_40
    move/from16 v21, v3

    .line 1363
    .line 1364
    move/from16 v23, v4

    .line 1365
    .line 1366
    move-object/from16 v26, v7

    .line 1367
    .line 1368
    move/from16 v5, v16

    .line 1369
    .line 1370
    aget v3, v26, v2

    .line 1371
    .line 1372
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v4

    .line 1376
    check-cast v4, Ljava/util/List;

    .line 1377
    .line 1378
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->p(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1379
    .line 1380
    .line 1381
    goto/16 :goto_f

    .line 1382
    .line 1383
    :pswitch_41
    move/from16 v21, v3

    .line 1384
    .line 1385
    move/from16 v23, v4

    .line 1386
    .line 1387
    move-object/from16 v26, v7

    .line 1388
    .line 1389
    move/from16 v5, v16

    .line 1390
    .line 1391
    aget v3, v26, v2

    .line 1392
    .line 1393
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1394
    .line 1395
    .line 1396
    move-result-object v4

    .line 1397
    check-cast v4, Ljava/util/List;

    .line 1398
    .line 1399
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->r(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1400
    .line 1401
    .line 1402
    goto/16 :goto_f

    .line 1403
    .line 1404
    :pswitch_42
    move/from16 v21, v3

    .line 1405
    .line 1406
    move/from16 v23, v4

    .line 1407
    .line 1408
    move-object/from16 v26, v7

    .line 1409
    .line 1410
    move/from16 v5, v16

    .line 1411
    .line 1412
    aget v3, v26, v2

    .line 1413
    .line 1414
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1415
    .line 1416
    .line 1417
    move-result-object v4

    .line 1418
    check-cast v4, Ljava/util/List;

    .line 1419
    .line 1420
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->y(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1421
    .line 1422
    .line 1423
    goto/16 :goto_f

    .line 1424
    .line 1425
    :pswitch_43
    move/from16 v21, v3

    .line 1426
    .line 1427
    move/from16 v23, v4

    .line 1428
    .line 1429
    move-object/from16 v26, v7

    .line 1430
    .line 1431
    move/from16 v5, v16

    .line 1432
    .line 1433
    aget v3, v26, v2

    .line 1434
    .line 1435
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v4

    .line 1439
    check-cast v4, Ljava/util/List;

    .line 1440
    .line 1441
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->s(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1442
    .line 1443
    .line 1444
    goto/16 :goto_f

    .line 1445
    .line 1446
    :pswitch_44
    move/from16 v21, v3

    .line 1447
    .line 1448
    move/from16 v23, v4

    .line 1449
    .line 1450
    move-object/from16 v26, v7

    .line 1451
    .line 1452
    move/from16 v5, v16

    .line 1453
    .line 1454
    aget v3, v26, v2

    .line 1455
    .line 1456
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1457
    .line 1458
    .line 1459
    move-result-object v4

    .line 1460
    check-cast v4, Ljava/util/List;

    .line 1461
    .line 1462
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->q(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1463
    .line 1464
    .line 1465
    goto/16 :goto_f

    .line 1466
    .line 1467
    :pswitch_45
    move/from16 v21, v3

    .line 1468
    .line 1469
    move/from16 v23, v4

    .line 1470
    .line 1471
    move-object/from16 v26, v7

    .line 1472
    .line 1473
    move/from16 v5, v16

    .line 1474
    .line 1475
    aget v3, v26, v2

    .line 1476
    .line 1477
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1478
    .line 1479
    .line 1480
    move-result-object v4

    .line 1481
    check-cast v4, Ljava/util/List;

    .line 1482
    .line 1483
    invoke-static {v3, v4, v6, v5}, Lcom/google/protobuf/x0;->m(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1484
    .line 1485
    .line 1486
    goto/16 :goto_f

    .line 1487
    .line 1488
    :pswitch_46
    move/from16 v21, v3

    .line 1489
    .line 1490
    move/from16 v23, v4

    .line 1491
    .line 1492
    move-object/from16 v26, v7

    .line 1493
    .line 1494
    aget v3, v26, v2

    .line 1495
    .line 1496
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1497
    .line 1498
    .line 1499
    move-result-object v4

    .line 1500
    check-cast v4, Ljava/util/List;

    .line 1501
    .line 1502
    const/4 v13, 0x0

    .line 1503
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->w(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1504
    .line 1505
    .line 1506
    :goto_11
    move/from16 v3, v21

    .line 1507
    .line 1508
    move/from16 v4, v23

    .line 1509
    .line 1510
    goto/16 :goto_19

    .line 1511
    .line 1512
    :pswitch_47
    move/from16 v21, v3

    .line 1513
    .line 1514
    move/from16 v23, v4

    .line 1515
    .line 1516
    move-object/from16 v26, v7

    .line 1517
    .line 1518
    const/4 v13, 0x0

    .line 1519
    aget v3, v26, v2

    .line 1520
    .line 1521
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v4

    .line 1525
    check-cast v4, Ljava/util/List;

    .line 1526
    .line 1527
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->v(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1528
    .line 1529
    .line 1530
    goto :goto_11

    .line 1531
    :pswitch_48
    move/from16 v21, v3

    .line 1532
    .line 1533
    move/from16 v23, v4

    .line 1534
    .line 1535
    move-object/from16 v26, v7

    .line 1536
    .line 1537
    const/4 v13, 0x0

    .line 1538
    aget v3, v26, v2

    .line 1539
    .line 1540
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1541
    .line 1542
    .line 1543
    move-result-object v4

    .line 1544
    check-cast v4, Ljava/util/List;

    .line 1545
    .line 1546
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->u(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1547
    .line 1548
    .line 1549
    goto :goto_11

    .line 1550
    :pswitch_49
    move/from16 v21, v3

    .line 1551
    .line 1552
    move/from16 v23, v4

    .line 1553
    .line 1554
    move-object/from16 v26, v7

    .line 1555
    .line 1556
    const/4 v13, 0x0

    .line 1557
    aget v3, v26, v2

    .line 1558
    .line 1559
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1560
    .line 1561
    .line 1562
    move-result-object v4

    .line 1563
    check-cast v4, Ljava/util/List;

    .line 1564
    .line 1565
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->t(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1566
    .line 1567
    .line 1568
    goto :goto_11

    .line 1569
    :pswitch_4a
    move/from16 v21, v3

    .line 1570
    .line 1571
    move/from16 v23, v4

    .line 1572
    .line 1573
    move-object/from16 v26, v7

    .line 1574
    .line 1575
    const/4 v13, 0x0

    .line 1576
    aget v3, v26, v2

    .line 1577
    .line 1578
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1579
    .line 1580
    .line 1581
    move-result-object v4

    .line 1582
    check-cast v4, Ljava/util/List;

    .line 1583
    .line 1584
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->n(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1585
    .line 1586
    .line 1587
    goto :goto_11

    .line 1588
    :pswitch_4b
    move/from16 v21, v3

    .line 1589
    .line 1590
    move/from16 v23, v4

    .line 1591
    .line 1592
    move-object/from16 v26, v7

    .line 1593
    .line 1594
    const/4 v13, 0x0

    .line 1595
    aget v3, v26, v2

    .line 1596
    .line 1597
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1598
    .line 1599
    .line 1600
    move-result-object v4

    .line 1601
    check-cast v4, Ljava/util/List;

    .line 1602
    .line 1603
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->x(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1604
    .line 1605
    .line 1606
    goto :goto_11

    .line 1607
    :pswitch_4c
    move/from16 v21, v3

    .line 1608
    .line 1609
    move/from16 v23, v4

    .line 1610
    .line 1611
    move-object/from16 v26, v7

    .line 1612
    .line 1613
    aget v3, v26, v2

    .line 1614
    .line 1615
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1616
    .line 1617
    .line 1618
    move-result-object v4

    .line 1619
    check-cast v4, Ljava/util/List;

    .line 1620
    .line 1621
    sget-object v5, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1622
    .line 1623
    if-eqz v4, :cond_10

    .line 1624
    .line 1625
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1626
    .line 1627
    .line 1628
    move-result v5

    .line 1629
    if-nez v5, :cond_10

    .line 1630
    .line 1631
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1632
    .line 1633
    .line 1634
    const/4 v5, 0x0

    .line 1635
    :goto_12
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1636
    .line 1637
    .line 1638
    move-result v7

    .line 1639
    if-ge v5, v7, :cond_10

    .line 1640
    .line 1641
    iget-object v7, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 1642
    .line 1643
    check-cast v7, Lcom/google/protobuf/f;

    .line 1644
    .line 1645
    invoke-interface {v4, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1646
    .line 1647
    .line 1648
    move-result-object v10

    .line 1649
    check-cast v10, Lcom/google/protobuf/e;

    .line 1650
    .line 1651
    const/4 v11, 0x2

    .line 1652
    invoke-virtual {v7, v3, v11}, Lcom/google/protobuf/f;->r(II)V

    .line 1653
    .line 1654
    .line 1655
    invoke-virtual {v7, v10}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 1656
    .line 1657
    .line 1658
    add-int/lit8 v5, v5, 0x1

    .line 1659
    .line 1660
    goto :goto_12

    .line 1661
    :pswitch_4d
    move/from16 v21, v3

    .line 1662
    .line 1663
    move/from16 v23, v4

    .line 1664
    .line 1665
    move-object/from16 v26, v7

    .line 1666
    .line 1667
    aget v3, v26, v2

    .line 1668
    .line 1669
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1670
    .line 1671
    .line 1672
    move-result-object v4

    .line 1673
    check-cast v4, Ljava/util/List;

    .line 1674
    .line 1675
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 1676
    .line 1677
    .line 1678
    move-result-object v5

    .line 1679
    sget-object v7, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1680
    .line 1681
    if-eqz v4, :cond_10

    .line 1682
    .line 1683
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1684
    .line 1685
    .line 1686
    move-result v7

    .line 1687
    if-nez v7, :cond_10

    .line 1688
    .line 1689
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1690
    .line 1691
    .line 1692
    const/4 v7, 0x0

    .line 1693
    :goto_13
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1694
    .line 1695
    .line 1696
    move-result v10

    .line 1697
    if-ge v7, v10, :cond_10

    .line 1698
    .line 1699
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1700
    .line 1701
    .line 1702
    move-result-object v10

    .line 1703
    invoke-virtual {v6, v3, v10, v5}, Lcom/google/protobuf/f0;->b(ILjava/lang/Object;Lcom/google/protobuf/w0;)V

    .line 1704
    .line 1705
    .line 1706
    add-int/lit8 v7, v7, 0x1

    .line 1707
    .line 1708
    goto :goto_13

    .line 1709
    :pswitch_4e
    move/from16 v21, v3

    .line 1710
    .line 1711
    move/from16 v23, v4

    .line 1712
    .line 1713
    move-object/from16 v26, v7

    .line 1714
    .line 1715
    aget v3, v26, v2

    .line 1716
    .line 1717
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1718
    .line 1719
    .line 1720
    move-result-object v4

    .line 1721
    check-cast v4, Ljava/util/List;

    .line 1722
    .line 1723
    sget-object v5, Lcom/google/protobuf/x0;->a:Ljava/lang/Class;

    .line 1724
    .line 1725
    if-eqz v4, :cond_10

    .line 1726
    .line 1727
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 1728
    .line 1729
    .line 1730
    move-result v5

    .line 1731
    if-nez v5, :cond_10

    .line 1732
    .line 1733
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 1734
    .line 1735
    check-cast v5, Lcom/google/protobuf/f;

    .line 1736
    .line 1737
    instance-of v7, v4, Lcom/google/protobuf/z;

    .line 1738
    .line 1739
    if-eqz v7, :cond_12

    .line 1740
    .line 1741
    move-object v7, v4

    .line 1742
    check-cast v7, Lcom/google/protobuf/z;

    .line 1743
    .line 1744
    const/4 v10, 0x0

    .line 1745
    :goto_14
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1746
    .line 1747
    .line 1748
    move-result v11

    .line 1749
    if-ge v10, v11, :cond_10

    .line 1750
    .line 1751
    invoke-interface {v7, v10}, Lcom/google/protobuf/z;->b(I)Ljava/lang/Object;

    .line 1752
    .line 1753
    .line 1754
    move-result-object v11

    .line 1755
    instance-of v12, v11, Ljava/lang/String;

    .line 1756
    .line 1757
    if-eqz v12, :cond_11

    .line 1758
    .line 1759
    check-cast v11, Ljava/lang/String;

    .line 1760
    .line 1761
    const/4 v12, 0x2

    .line 1762
    invoke-virtual {v5, v3, v12}, Lcom/google/protobuf/f;->r(II)V

    .line 1763
    .line 1764
    .line 1765
    invoke-virtual {v5, v11}, Lcom/google/protobuf/f;->q(Ljava/lang/String;)V

    .line 1766
    .line 1767
    .line 1768
    goto :goto_15

    .line 1769
    :cond_11
    const/4 v12, 0x2

    .line 1770
    check-cast v11, Lcom/google/protobuf/e;

    .line 1771
    .line 1772
    invoke-virtual {v5, v3, v12}, Lcom/google/protobuf/f;->r(II)V

    .line 1773
    .line 1774
    .line 1775
    invoke-virtual {v5, v11}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 1776
    .line 1777
    .line 1778
    :goto_15
    add-int/lit8 v10, v10, 0x1

    .line 1779
    .line 1780
    goto :goto_14

    .line 1781
    :cond_12
    const/4 v7, 0x0

    .line 1782
    :goto_16
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1783
    .line 1784
    .line 1785
    move-result v10

    .line 1786
    if-ge v7, v10, :cond_10

    .line 1787
    .line 1788
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1789
    .line 1790
    .line 1791
    move-result-object v10

    .line 1792
    check-cast v10, Ljava/lang/String;

    .line 1793
    .line 1794
    const/4 v11, 0x2

    .line 1795
    invoke-virtual {v5, v3, v11}, Lcom/google/protobuf/f;->r(II)V

    .line 1796
    .line 1797
    .line 1798
    invoke-virtual {v5, v10}, Lcom/google/protobuf/f;->q(Ljava/lang/String;)V

    .line 1799
    .line 1800
    .line 1801
    add-int/lit8 v7, v7, 0x1

    .line 1802
    .line 1803
    goto :goto_16

    .line 1804
    :pswitch_4f
    move/from16 v21, v3

    .line 1805
    .line 1806
    move/from16 v23, v4

    .line 1807
    .line 1808
    move-object/from16 v26, v7

    .line 1809
    .line 1810
    aget v3, v26, v2

    .line 1811
    .line 1812
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1813
    .line 1814
    .line 1815
    move-result-object v4

    .line 1816
    check-cast v4, Ljava/util/List;

    .line 1817
    .line 1818
    const/4 v13, 0x0

    .line 1819
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->l(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1820
    .line 1821
    .line 1822
    goto/16 :goto_11

    .line 1823
    .line 1824
    :pswitch_50
    move/from16 v21, v3

    .line 1825
    .line 1826
    move/from16 v23, v4

    .line 1827
    .line 1828
    move-object/from16 v26, v7

    .line 1829
    .line 1830
    const/4 v13, 0x0

    .line 1831
    aget v3, v26, v2

    .line 1832
    .line 1833
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1834
    .line 1835
    .line 1836
    move-result-object v4

    .line 1837
    check-cast v4, Ljava/util/List;

    .line 1838
    .line 1839
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->o(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1840
    .line 1841
    .line 1842
    goto/16 :goto_11

    .line 1843
    .line 1844
    :pswitch_51
    move/from16 v21, v3

    .line 1845
    .line 1846
    move/from16 v23, v4

    .line 1847
    .line 1848
    move-object/from16 v26, v7

    .line 1849
    .line 1850
    const/4 v13, 0x0

    .line 1851
    aget v3, v26, v2

    .line 1852
    .line 1853
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1854
    .line 1855
    .line 1856
    move-result-object v4

    .line 1857
    check-cast v4, Ljava/util/List;

    .line 1858
    .line 1859
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->p(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1860
    .line 1861
    .line 1862
    goto/16 :goto_11

    .line 1863
    .line 1864
    :pswitch_52
    move/from16 v21, v3

    .line 1865
    .line 1866
    move/from16 v23, v4

    .line 1867
    .line 1868
    move-object/from16 v26, v7

    .line 1869
    .line 1870
    const/4 v13, 0x0

    .line 1871
    aget v3, v26, v2

    .line 1872
    .line 1873
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v4

    .line 1877
    check-cast v4, Ljava/util/List;

    .line 1878
    .line 1879
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->r(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1880
    .line 1881
    .line 1882
    goto/16 :goto_11

    .line 1883
    .line 1884
    :pswitch_53
    move/from16 v21, v3

    .line 1885
    .line 1886
    move/from16 v23, v4

    .line 1887
    .line 1888
    move-object/from16 v26, v7

    .line 1889
    .line 1890
    const/4 v13, 0x0

    .line 1891
    aget v3, v26, v2

    .line 1892
    .line 1893
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1894
    .line 1895
    .line 1896
    move-result-object v4

    .line 1897
    check-cast v4, Ljava/util/List;

    .line 1898
    .line 1899
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->y(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1900
    .line 1901
    .line 1902
    goto/16 :goto_11

    .line 1903
    .line 1904
    :pswitch_54
    move/from16 v21, v3

    .line 1905
    .line 1906
    move/from16 v23, v4

    .line 1907
    .line 1908
    move-object/from16 v26, v7

    .line 1909
    .line 1910
    const/4 v13, 0x0

    .line 1911
    aget v3, v26, v2

    .line 1912
    .line 1913
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1914
    .line 1915
    .line 1916
    move-result-object v4

    .line 1917
    check-cast v4, Ljava/util/List;

    .line 1918
    .line 1919
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->s(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1920
    .line 1921
    .line 1922
    goto/16 :goto_11

    .line 1923
    .line 1924
    :pswitch_55
    move/from16 v21, v3

    .line 1925
    .line 1926
    move/from16 v23, v4

    .line 1927
    .line 1928
    move-object/from16 v26, v7

    .line 1929
    .line 1930
    const/4 v13, 0x0

    .line 1931
    aget v3, v26, v2

    .line 1932
    .line 1933
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1934
    .line 1935
    .line 1936
    move-result-object v4

    .line 1937
    check-cast v4, Ljava/util/List;

    .line 1938
    .line 1939
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->q(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1940
    .line 1941
    .line 1942
    goto/16 :goto_11

    .line 1943
    .line 1944
    :pswitch_56
    move/from16 v21, v3

    .line 1945
    .line 1946
    move/from16 v23, v4

    .line 1947
    .line 1948
    move-object/from16 v26, v7

    .line 1949
    .line 1950
    const/4 v13, 0x0

    .line 1951
    aget v3, v26, v2

    .line 1952
    .line 1953
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1954
    .line 1955
    .line 1956
    move-result-object v4

    .line 1957
    check-cast v4, Ljava/util/List;

    .line 1958
    .line 1959
    invoke-static {v3, v4, v6, v13}, Lcom/google/protobuf/x0;->m(ILjava/util/List;Lcom/google/protobuf/f0;Z)V

    .line 1960
    .line 1961
    .line 1962
    goto/16 :goto_11

    .line 1963
    .line 1964
    :pswitch_57
    move-object/from16 v26, v7

    .line 1965
    .line 1966
    move v5, v14

    .line 1967
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 1968
    .line 1969
    .line 1970
    move-result v5

    .line 1971
    if-eqz v5, :cond_4

    .line 1972
    .line 1973
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1974
    .line 1975
    .line 1976
    move-result-object v5

    .line 1977
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 1978
    .line 1979
    .line 1980
    move-result-object v7

    .line 1981
    invoke-virtual {v6, v12, v5, v7}, Lcom/google/protobuf/f0;->a(ILjava/lang/Object;Lcom/google/protobuf/w0;)V

    .line 1982
    .line 1983
    .line 1984
    goto/16 :goto_4

    .line 1985
    .line 1986
    :pswitch_58
    move-object/from16 v26, v7

    .line 1987
    .line 1988
    move v5, v14

    .line 1989
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 1990
    .line 1991
    .line 1992
    move-result v5

    .line 1993
    if-eqz v5, :cond_13

    .line 1994
    .line 1995
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1996
    .line 1997
    .line 1998
    move-result-wide v10

    .line 1999
    iget-object v0, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2000
    .line 2001
    check-cast v0, Lcom/google/protobuf/f;

    .line 2002
    .line 2003
    const/16 v16, 0x1

    .line 2004
    .line 2005
    shl-long v13, v10, v16

    .line 2006
    .line 2007
    shr-long v10, v10, v17

    .line 2008
    .line 2009
    xor-long/2addr v10, v13

    .line 2010
    invoke-virtual {v0, v12, v10, v11}, Lcom/google/protobuf/f;->t(IJ)V

    .line 2011
    .line 2012
    .line 2013
    :cond_13
    :goto_17
    const/4 v13, 0x0

    .line 2014
    :cond_14
    :goto_18
    move-object/from16 v0, p0

    .line 2015
    .line 2016
    goto/16 :goto_19

    .line 2017
    .line 2018
    :pswitch_59
    move-object/from16 v26, v7

    .line 2019
    .line 2020
    move v5, v14

    .line 2021
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2022
    .line 2023
    .line 2024
    move-result v5

    .line 2025
    if-eqz v5, :cond_13

    .line 2026
    .line 2027
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2028
    .line 2029
    .line 2030
    move-result v0

    .line 2031
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2032
    .line 2033
    check-cast v5, Lcom/google/protobuf/f;

    .line 2034
    .line 2035
    shl-int/lit8 v7, v0, 0x1

    .line 2036
    .line 2037
    shr-int/lit8 v0, v0, 0x1f

    .line 2038
    .line 2039
    xor-int/2addr v0, v7

    .line 2040
    const/4 v13, 0x0

    .line 2041
    invoke-virtual {v5, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 2042
    .line 2043
    .line 2044
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->s(I)V

    .line 2045
    .line 2046
    .line 2047
    goto :goto_17

    .line 2048
    :pswitch_5a
    move-object/from16 v26, v7

    .line 2049
    .line 2050
    move v5, v14

    .line 2051
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2052
    .line 2053
    .line 2054
    move-result v5

    .line 2055
    if-eqz v5, :cond_13

    .line 2056
    .line 2057
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2058
    .line 2059
    .line 2060
    move-result-wide v10

    .line 2061
    iget-object v0, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2062
    .line 2063
    check-cast v0, Lcom/google/protobuf/f;

    .line 2064
    .line 2065
    invoke-virtual {v0, v12, v10, v11}, Lcom/google/protobuf/f;->n(IJ)V

    .line 2066
    .line 2067
    .line 2068
    goto :goto_17

    .line 2069
    :pswitch_5b
    move-object/from16 v26, v7

    .line 2070
    .line 2071
    move v5, v14

    .line 2072
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2073
    .line 2074
    .line 2075
    move-result v5

    .line 2076
    if-eqz v5, :cond_13

    .line 2077
    .line 2078
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2079
    .line 2080
    .line 2081
    move-result v0

    .line 2082
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2083
    .line 2084
    check-cast v5, Lcom/google/protobuf/f;

    .line 2085
    .line 2086
    invoke-virtual {v5, v12, v0}, Lcom/google/protobuf/f;->l(II)V

    .line 2087
    .line 2088
    .line 2089
    goto :goto_17

    .line 2090
    :pswitch_5c
    move-object/from16 v26, v7

    .line 2091
    .line 2092
    move v5, v14

    .line 2093
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2094
    .line 2095
    .line 2096
    move-result v5

    .line 2097
    if-eqz v5, :cond_13

    .line 2098
    .line 2099
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2100
    .line 2101
    .line 2102
    move-result v0

    .line 2103
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2104
    .line 2105
    check-cast v5, Lcom/google/protobuf/f;

    .line 2106
    .line 2107
    const/4 v13, 0x0

    .line 2108
    invoke-virtual {v5, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 2109
    .line 2110
    .line 2111
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->p(I)V

    .line 2112
    .line 2113
    .line 2114
    goto :goto_18

    .line 2115
    :pswitch_5d
    move-object/from16 v26, v7

    .line 2116
    .line 2117
    move v5, v14

    .line 2118
    const/4 v13, 0x0

    .line 2119
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2120
    .line 2121
    .line 2122
    move-result v5

    .line 2123
    if-eqz v5, :cond_14

    .line 2124
    .line 2125
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2126
    .line 2127
    .line 2128
    move-result v0

    .line 2129
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2130
    .line 2131
    check-cast v5, Lcom/google/protobuf/f;

    .line 2132
    .line 2133
    invoke-virtual {v5, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 2134
    .line 2135
    .line 2136
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->s(I)V

    .line 2137
    .line 2138
    .line 2139
    goto :goto_17

    .line 2140
    :pswitch_5e
    move-object/from16 v26, v7

    .line 2141
    .line 2142
    move v7, v5

    .line 2143
    move v5, v14

    .line 2144
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2145
    .line 2146
    .line 2147
    move-result v5

    .line 2148
    if-eqz v5, :cond_13

    .line 2149
    .line 2150
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2151
    .line 2152
    .line 2153
    move-result-object v0

    .line 2154
    check-cast v0, Lcom/google/protobuf/e;

    .line 2155
    .line 2156
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2157
    .line 2158
    check-cast v5, Lcom/google/protobuf/f;

    .line 2159
    .line 2160
    invoke-virtual {v5, v12, v7}, Lcom/google/protobuf/f;->r(II)V

    .line 2161
    .line 2162
    .line 2163
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 2164
    .line 2165
    .line 2166
    goto/16 :goto_17

    .line 2167
    .line 2168
    :pswitch_5f
    move-object/from16 v26, v7

    .line 2169
    .line 2170
    move v5, v14

    .line 2171
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2172
    .line 2173
    .line 2174
    move-result v5

    .line 2175
    if-eqz v5, :cond_4

    .line 2176
    .line 2177
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2178
    .line 2179
    .line 2180
    move-result-object v5

    .line 2181
    invoke-virtual {v0, v2}, Lcom/google/protobuf/n0;->j(I)Lcom/google/protobuf/w0;

    .line 2182
    .line 2183
    .line 2184
    move-result-object v7

    .line 2185
    invoke-virtual {v6, v12, v5, v7}, Lcom/google/protobuf/f0;->b(ILjava/lang/Object;Lcom/google/protobuf/w0;)V

    .line 2186
    .line 2187
    .line 2188
    goto/16 :goto_4

    .line 2189
    .line 2190
    :pswitch_60
    move-object/from16 v26, v7

    .line 2191
    .line 2192
    move v7, v5

    .line 2193
    move v5, v14

    .line 2194
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2195
    .line 2196
    .line 2197
    move-result v5

    .line 2198
    if-eqz v5, :cond_13

    .line 2199
    .line 2200
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 2201
    .line 2202
    .line 2203
    move-result-object v0

    .line 2204
    instance-of v5, v0, Ljava/lang/String;

    .line 2205
    .line 2206
    if-eqz v5, :cond_15

    .line 2207
    .line 2208
    check-cast v0, Ljava/lang/String;

    .line 2209
    .line 2210
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2211
    .line 2212
    check-cast v5, Lcom/google/protobuf/f;

    .line 2213
    .line 2214
    invoke-virtual {v5, v12, v7}, Lcom/google/protobuf/f;->r(II)V

    .line 2215
    .line 2216
    .line 2217
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->q(Ljava/lang/String;)V

    .line 2218
    .line 2219
    .line 2220
    goto/16 :goto_17

    .line 2221
    .line 2222
    :cond_15
    check-cast v0, Lcom/google/protobuf/e;

    .line 2223
    .line 2224
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2225
    .line 2226
    check-cast v5, Lcom/google/protobuf/f;

    .line 2227
    .line 2228
    invoke-virtual {v5, v12, v7}, Lcom/google/protobuf/f;->r(II)V

    .line 2229
    .line 2230
    .line 2231
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->k(Lcom/google/protobuf/e;)V

    .line 2232
    .line 2233
    .line 2234
    goto/16 :goto_17

    .line 2235
    .line 2236
    :pswitch_61
    move-object/from16 v26, v7

    .line 2237
    .line 2238
    move v5, v14

    .line 2239
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2240
    .line 2241
    .line 2242
    move-result v5

    .line 2243
    if-eqz v5, :cond_13

    .line 2244
    .line 2245
    sget-object v0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2246
    .line 2247
    invoke-virtual {v0, v10, v11, v1}, Lcom/google/protobuf/l1;->c(JLjava/lang/Object;)Z

    .line 2248
    .line 2249
    .line 2250
    move-result v0

    .line 2251
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2252
    .line 2253
    check-cast v5, Lcom/google/protobuf/f;

    .line 2254
    .line 2255
    const/4 v13, 0x0

    .line 2256
    invoke-virtual {v5, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 2257
    .line 2258
    .line 2259
    int-to-byte v0, v0

    .line 2260
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->i(B)V

    .line 2261
    .line 2262
    .line 2263
    goto/16 :goto_17

    .line 2264
    .line 2265
    :pswitch_62
    move-object/from16 v26, v7

    .line 2266
    .line 2267
    move v5, v14

    .line 2268
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2269
    .line 2270
    .line 2271
    move-result v5

    .line 2272
    if-eqz v5, :cond_13

    .line 2273
    .line 2274
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2275
    .line 2276
    .line 2277
    move-result v0

    .line 2278
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2279
    .line 2280
    check-cast v5, Lcom/google/protobuf/f;

    .line 2281
    .line 2282
    invoke-virtual {v5, v12, v0}, Lcom/google/protobuf/f;->l(II)V

    .line 2283
    .line 2284
    .line 2285
    goto/16 :goto_17

    .line 2286
    .line 2287
    :pswitch_63
    move-object/from16 v26, v7

    .line 2288
    .line 2289
    move v5, v14

    .line 2290
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2291
    .line 2292
    .line 2293
    move-result v5

    .line 2294
    if-eqz v5, :cond_13

    .line 2295
    .line 2296
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2297
    .line 2298
    .line 2299
    move-result-wide v10

    .line 2300
    iget-object v0, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2301
    .line 2302
    check-cast v0, Lcom/google/protobuf/f;

    .line 2303
    .line 2304
    invoke-virtual {v0, v12, v10, v11}, Lcom/google/protobuf/f;->n(IJ)V

    .line 2305
    .line 2306
    .line 2307
    goto/16 :goto_17

    .line 2308
    .line 2309
    :pswitch_64
    move-object/from16 v26, v7

    .line 2310
    .line 2311
    move v5, v14

    .line 2312
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2313
    .line 2314
    .line 2315
    move-result v5

    .line 2316
    if-eqz v5, :cond_13

    .line 2317
    .line 2318
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 2319
    .line 2320
    .line 2321
    move-result v0

    .line 2322
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2323
    .line 2324
    check-cast v5, Lcom/google/protobuf/f;

    .line 2325
    .line 2326
    const/4 v13, 0x0

    .line 2327
    invoke-virtual {v5, v12, v13}, Lcom/google/protobuf/f;->r(II)V

    .line 2328
    .line 2329
    .line 2330
    invoke-virtual {v5, v0}, Lcom/google/protobuf/f;->p(I)V

    .line 2331
    .line 2332
    .line 2333
    goto/16 :goto_18

    .line 2334
    .line 2335
    :pswitch_65
    move-object/from16 v26, v7

    .line 2336
    .line 2337
    move v5, v14

    .line 2338
    const/4 v13, 0x0

    .line 2339
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2340
    .line 2341
    .line 2342
    move-result v5

    .line 2343
    if-eqz v5, :cond_14

    .line 2344
    .line 2345
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2346
    .line 2347
    .line 2348
    move-result-wide v10

    .line 2349
    iget-object v0, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2350
    .line 2351
    check-cast v0, Lcom/google/protobuf/f;

    .line 2352
    .line 2353
    invoke-virtual {v0, v12, v10, v11}, Lcom/google/protobuf/f;->t(IJ)V

    .line 2354
    .line 2355
    .line 2356
    goto/16 :goto_18

    .line 2357
    .line 2358
    :pswitch_66
    move-object/from16 v26, v7

    .line 2359
    .line 2360
    move v5, v14

    .line 2361
    const/4 v13, 0x0

    .line 2362
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2363
    .line 2364
    .line 2365
    move-result v5

    .line 2366
    if-eqz v5, :cond_14

    .line 2367
    .line 2368
    invoke-virtual {v9, v1, v10, v11}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 2369
    .line 2370
    .line 2371
    move-result-wide v10

    .line 2372
    iget-object v0, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2373
    .line 2374
    check-cast v0, Lcom/google/protobuf/f;

    .line 2375
    .line 2376
    invoke-virtual {v0, v12, v10, v11}, Lcom/google/protobuf/f;->t(IJ)V

    .line 2377
    .line 2378
    .line 2379
    goto/16 :goto_18

    .line 2380
    .line 2381
    :pswitch_67
    move-object/from16 v26, v7

    .line 2382
    .line 2383
    move v5, v14

    .line 2384
    const/4 v13, 0x0

    .line 2385
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2386
    .line 2387
    .line 2388
    move-result v5

    .line 2389
    if-eqz v5, :cond_14

    .line 2390
    .line 2391
    sget-object v0, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2392
    .line 2393
    invoke-virtual {v0, v10, v11, v1}, Lcom/google/protobuf/l1;->f(JLjava/lang/Object;)F

    .line 2394
    .line 2395
    .line 2396
    move-result v0

    .line 2397
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2398
    .line 2399
    check-cast v5, Lcom/google/protobuf/f;

    .line 2400
    .line 2401
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2402
    .line 2403
    .line 2404
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 2405
    .line 2406
    .line 2407
    move-result v0

    .line 2408
    invoke-virtual {v5, v12, v0}, Lcom/google/protobuf/f;->l(II)V

    .line 2409
    .line 2410
    .line 2411
    goto/16 :goto_18

    .line 2412
    .line 2413
    :pswitch_68
    move-object/from16 v26, v7

    .line 2414
    .line 2415
    move v5, v14

    .line 2416
    const/4 v13, 0x0

    .line 2417
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/n0;->l(Ljava/lang/Object;IIII)Z

    .line 2418
    .line 2419
    .line 2420
    move-result v5

    .line 2421
    if-eqz v5, :cond_16

    .line 2422
    .line 2423
    sget-object v5, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 2424
    .line 2425
    invoke-virtual {v5, v10, v11, v1}, Lcom/google/protobuf/l1;->e(JLjava/lang/Object;)D

    .line 2426
    .line 2427
    .line 2428
    move-result-wide v10

    .line 2429
    iget-object v5, v6, Lcom/google/protobuf/f0;->a:Ljava/lang/Object;

    .line 2430
    .line 2431
    check-cast v5, Lcom/google/protobuf/f;

    .line 2432
    .line 2433
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2434
    .line 2435
    .line 2436
    invoke-static {v10, v11}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 2437
    .line 2438
    .line 2439
    move-result-wide v10

    .line 2440
    invoke-virtual {v5, v12, v10, v11}, Lcom/google/protobuf/f;->n(IJ)V

    .line 2441
    .line 2442
    .line 2443
    :cond_16
    :goto_19
    add-int/lit8 v2, v2, 0x3

    .line 2444
    .line 2445
    move-object/from16 v7, v26

    .line 2446
    .line 2447
    const v10, 0xfffff

    .line 2448
    .line 2449
    .line 2450
    goto/16 :goto_0

    .line 2451
    .line 2452
    :cond_17
    iget-object v0, v0, Lcom/google/protobuf/n0;->h:Lcom/google/protobuf/e1;

    .line 2453
    .line 2454
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2455
    .line 2456
    .line 2457
    move-object v0, v1

    .line 2458
    check-cast v0, Lcom/google/protobuf/p;

    .line 2459
    .line 2460
    iget-object v0, v0, Lcom/google/protobuf/p;->unknownFields:Lcom/google/protobuf/d1;

    .line 2461
    .line 2462
    invoke-virtual {v0, v6}, Lcom/google/protobuf/d1;->b(Lcom/google/protobuf/f0;)V

    .line 2463
    .line 2464
    .line 2465
    return-void

    .line 2466
    nop

    .line 2467
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_68
        :pswitch_67
        :pswitch_66
        :pswitch_65
        :pswitch_64
        :pswitch_63
        :pswitch_62
        :pswitch_61
        :pswitch_60
        :pswitch_5f
        :pswitch_5e
        :pswitch_5d
        :pswitch_5c
        :pswitch_5b
        :pswitch_5a
        :pswitch_59
        :pswitch_58
        :pswitch_57
        :pswitch_56
        :pswitch_55
        :pswitch_54
        :pswitch_53
        :pswitch_52
        :pswitch_51
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2468
    .line 2469
    .line 2470
    .line 2471
    .line 2472
    .line 2473
    .line 2474
    .line 2475
    .line 2476
    .line 2477
    .line 2478
    .line 2479
    .line 2480
    .line 2481
    .line 2482
    .line 2483
    .line 2484
    .line 2485
    .line 2486
    .line 2487
    .line 2488
    .line 2489
    .line 2490
    .line 2491
    .line 2492
    .line 2493
    .line 2494
    .line 2495
    .line 2496
    .line 2497
    .line 2498
    .line 2499
    .line 2500
    .line 2501
    .line 2502
    .line 2503
    .line 2504
    .line 2505
    .line 2506
    .line 2507
    .line 2508
    .line 2509
    .line 2510
    .line 2511
    .line 2512
    .line 2513
    .line 2514
    .line 2515
    .line 2516
    .line 2517
    .line 2518
    .line 2519
    .line 2520
    .line 2521
    .line 2522
    .line 2523
    .line 2524
    .line 2525
    .line 2526
    .line 2527
    .line 2528
    .line 2529
    .line 2530
    .line 2531
    .line 2532
    .line 2533
    .line 2534
    .line 2535
    .line 2536
    .line 2537
    .line 2538
    .line 2539
    .line 2540
    .line 2541
    .line 2542
    .line 2543
    .line 2544
    .line 2545
    .line 2546
    .line 2547
    .line 2548
    .line 2549
    .line 2550
    .line 2551
    .line 2552
    .line 2553
    .line 2554
    .line 2555
    .line 2556
    .line 2557
    .line 2558
    .line 2559
    .line 2560
    .line 2561
    .line 2562
    .line 2563
    .line 2564
    .line 2565
    .line 2566
    .line 2567
    .line 2568
    .line 2569
    .line 2570
    .line 2571
    .line 2572
    .line 2573
    .line 2574
    .line 2575
    .line 2576
    .line 2577
    .line 2578
    .line 2579
    .line 2580
    .line 2581
    .line 2582
    .line 2583
    .line 2584
    .line 2585
    .line 2586
    .line 2587
    .line 2588
    .line 2589
    .line 2590
    .line 2591
    .line 2592
    .line 2593
    .line 2594
    .line 2595
    .line 2596
    .line 2597
    .line 2598
    .line 2599
    .line 2600
    .line 2601
    .line 2602
    .line 2603
    .line 2604
    .line 2605
    .line 2606
    .line 2607
    .line 2608
    .line 2609
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
    .end packed-switch

    .line 2610
    .line 2611
    .line 2612
    .line 2613
    .line 2614
    .line 2615
    .line 2616
    .line 2617
    .line 2618
    .line 2619
    .line 2620
    .line 2621
    .line 2622
    .line 2623
    .line 2624
    .line 2625
    .line 2626
    .line 2627
    .line 2628
    .line 2629
    .line 2630
    .line 2631
    .line 2632
    .line 2633
    .line 2634
    .line 2635
    .line 2636
    .line 2637
    .line 2638
    .line 2639
    .line 2640
    .line 2641
    .line 2642
    .line 2643
    .line 2644
    .line 2645
    .line 2646
    .line 2647
    .line 2648
    .line 2649
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
    .end packed-switch
.end method
