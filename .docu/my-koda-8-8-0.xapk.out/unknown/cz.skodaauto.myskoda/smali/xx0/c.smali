.class public Lxx0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lxx0/a;

.field public static final f:[B


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:I

.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lxx0/a;

    .line 2
    .line 3
    sget-object v1, Lxx0/b;->d:[Lxx0/b;

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-direct {v0, v1, v2, v2}, Lxx0/c;-><init>(IZZ)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lxx0/c;->e:Lxx0/a;

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    new-array v0, v0, [B

    .line 14
    .line 15
    fill-array-data v0, :array_0

    .line 16
    .line 17
    .line 18
    sput-object v0, Lxx0/c;->f:[B

    .line 19
    .line 20
    new-instance v0, Lxx0/c;

    .line 21
    .line 22
    const/4 v3, 0x1

    .line 23
    invoke-direct {v0, v1, v3, v2}, Lxx0/c;-><init>(IZZ)V

    .line 24
    .line 25
    .line 26
    new-instance v0, Lxx0/c;

    .line 27
    .line 28
    const/16 v1, 0x4c

    .line 29
    .line 30
    invoke-direct {v0, v1, v2, v3}, Lxx0/c;-><init>(IZZ)V

    .line 31
    .line 32
    .line 33
    new-instance v0, Lxx0/c;

    .line 34
    .line 35
    const/16 v1, 0x40

    .line 36
    .line 37
    invoke-direct {v0, v1, v2, v3}, Lxx0/c;-><init>(IZZ)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :array_0
    .array-data 1
        0xdt
        0xat
    .end array-data
.end method

.method public constructor <init>(IZZ)V
    .locals 1

    .line 1
    sget-object v0, Lxx0/b;->d:[Lxx0/b;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-boolean p2, p0, Lxx0/c;->a:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lxx0/c;->b:Z

    .line 9
    .line 10
    iput p1, p0, Lxx0/c;->c:I

    .line 11
    .line 12
    if-eqz p2, :cond_1

    .line 13
    .line 14
    if-nez p3, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string p1, "Failed requirement."

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    div-int/lit8 p1, p1, 0x4

    .line 26
    .line 27
    iput p1, p0, Lxx0/c;->d:I

    .line 28
    .line 29
    return-void
.end method

.method public static a(Lxx0/c;Ljava/lang/CharSequence;II)[B
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    and-int/lit8 v2, p3, 0x2

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    move v2, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move/from16 v2, p2

    .line 13
    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    iget-boolean v5, v0, Lxx0/c;->b:Z

    .line 22
    .line 23
    const-string v6, "source"

    .line 24
    .line 25
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    instance-of v6, v1, Ljava/lang/String;

    .line 29
    .line 30
    const/16 v7, 0xff

    .line 31
    .line 32
    if-eqz v6, :cond_1

    .line 33
    .line 34
    check-cast v1, Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    invoke-static {v2, v4, v6}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v2, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    const-string v2, "substring(...)"

    .line 48
    .line 49
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    sget-object v2, Lly0/a;->d:Ljava/nio/charset/Charset;

    .line 53
    .line 54
    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    const-string v2, "getBytes(...)"

    .line 59
    .line 60
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_1
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    invoke-static {v2, v4, v6}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 69
    .line 70
    .line 71
    sub-int v6, v4, v2

    .line 72
    .line 73
    new-array v6, v6, [B

    .line 74
    .line 75
    move v8, v3

    .line 76
    :goto_1
    if-ge v2, v4, :cond_3

    .line 77
    .line 78
    invoke-interface {v1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 79
    .line 80
    .line 81
    move-result v9

    .line 82
    if-gt v9, v7, :cond_2

    .line 83
    .line 84
    add-int/lit8 v10, v8, 0x1

    .line 85
    .line 86
    int-to-byte v9, v9

    .line 87
    aput-byte v9, v6, v8

    .line 88
    .line 89
    move v8, v10

    .line 90
    goto :goto_2

    .line 91
    :cond_2
    add-int/lit8 v9, v8, 0x1

    .line 92
    .line 93
    const/16 v10, 0x3f

    .line 94
    .line 95
    aput-byte v10, v6, v8

    .line 96
    .line 97
    move v8, v9

    .line 98
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_3
    move-object v1, v6

    .line 102
    :goto_3
    array-length v2, v1

    .line 103
    array-length v4, v1

    .line 104
    invoke-static {v3, v2, v4}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 105
    .line 106
    .line 107
    const/4 v4, 0x1

    .line 108
    const/16 v6, 0x8

    .line 109
    .line 110
    const/4 v8, 0x6

    .line 111
    const/16 v9, 0x3d

    .line 112
    .line 113
    const/4 v10, -0x2

    .line 114
    if-nez v2, :cond_4

    .line 115
    .line 116
    move v11, v3

    .line 117
    goto :goto_6

    .line 118
    :cond_4
    if-eq v2, v4, :cond_23

    .line 119
    .line 120
    if-eqz v5, :cond_7

    .line 121
    .line 122
    move v12, v2

    .line 123
    move v11, v3

    .line 124
    :goto_4
    if-ge v11, v2, :cond_9

    .line 125
    .line 126
    aget-byte v13, v1, v11

    .line 127
    .line 128
    and-int/2addr v13, v7

    .line 129
    sget-object v14, Lxx0/d;->b:[I

    .line 130
    .line 131
    aget v13, v14, v13

    .line 132
    .line 133
    if-gez v13, :cond_6

    .line 134
    .line 135
    if-ne v13, v10, :cond_5

    .line 136
    .line 137
    sub-int v11, v2, v11

    .line 138
    .line 139
    sub-int/2addr v12, v11

    .line 140
    goto :goto_5

    .line 141
    :cond_5
    add-int/lit8 v12, v12, -0x1

    .line 142
    .line 143
    :cond_6
    add-int/lit8 v11, v11, 0x1

    .line 144
    .line 145
    goto :goto_4

    .line 146
    :cond_7
    add-int/lit8 v11, v2, -0x1

    .line 147
    .line 148
    aget-byte v11, v1, v11

    .line 149
    .line 150
    if-ne v11, v9, :cond_8

    .line 151
    .line 152
    add-int/lit8 v12, v2, -0x1

    .line 153
    .line 154
    add-int/lit8 v11, v2, -0x2

    .line 155
    .line 156
    aget-byte v11, v1, v11

    .line 157
    .line 158
    if-ne v11, v9, :cond_9

    .line 159
    .line 160
    add-int/lit8 v12, v2, -0x2

    .line 161
    .line 162
    goto :goto_5

    .line 163
    :cond_8
    move v12, v2

    .line 164
    :cond_9
    :goto_5
    int-to-long v11, v12

    .line 165
    int-to-long v13, v8

    .line 166
    mul-long/2addr v11, v13

    .line 167
    int-to-long v13, v6

    .line 168
    div-long/2addr v11, v13

    .line 169
    long-to-int v11, v11

    .line 170
    :goto_6
    new-array v12, v11, [B

    .line 171
    .line 172
    iget-boolean v0, v0, Lxx0/c;->a:Z

    .line 173
    .line 174
    if-eqz v0, :cond_a

    .line 175
    .line 176
    sget-object v0, Lxx0/d;->d:[I

    .line 177
    .line 178
    goto :goto_7

    .line 179
    :cond_a
    sget-object v0, Lxx0/d;->b:[I

    .line 180
    .line 181
    :goto_7
    const/4 v13, -0x8

    .line 182
    move v14, v3

    .line 183
    move/from16 v16, v14

    .line 184
    .line 185
    move/from16 p1, v4

    .line 186
    .line 187
    move v15, v13

    .line 188
    :goto_8
    move/from16 p2, v8

    .line 189
    .line 190
    const-string v8, ") at index "

    .line 191
    .line 192
    move/from16 v17, v6

    .line 193
    .line 194
    const-string v6, "toString(...)"

    .line 195
    .line 196
    const-string v9, "\'("

    .line 197
    .line 198
    if-ge v14, v2, :cond_19

    .line 199
    .line 200
    if-ne v15, v13, :cond_b

    .line 201
    .line 202
    add-int/lit8 v4, v14, 0x3

    .line 203
    .line 204
    if-ge v4, v2, :cond_b

    .line 205
    .line 206
    add-int/lit8 v18, v14, 0x1

    .line 207
    .line 208
    aget-byte v13, v1, v14

    .line 209
    .line 210
    and-int/2addr v13, v7

    .line 211
    aget v13, v0, v13

    .line 212
    .line 213
    add-int/lit8 v19, v14, 0x2

    .line 214
    .line 215
    aget-byte v10, v1, v18

    .line 216
    .line 217
    and-int/2addr v10, v7

    .line 218
    aget v10, v0, v10

    .line 219
    .line 220
    move-object/from16 v18, v0

    .line 221
    .line 222
    aget-byte v0, v1, v19

    .line 223
    .line 224
    and-int/2addr v0, v7

    .line 225
    aget v0, v18, v0

    .line 226
    .line 227
    add-int/lit8 v19, v14, 0x4

    .line 228
    .line 229
    aget-byte v4, v1, v4

    .line 230
    .line 231
    and-int/2addr v4, v7

    .line 232
    aget v4, v18, v4

    .line 233
    .line 234
    shl-int/lit8 v13, v13, 0x12

    .line 235
    .line 236
    shl-int/lit8 v10, v10, 0xc

    .line 237
    .line 238
    or-int/2addr v10, v13

    .line 239
    shl-int/lit8 v0, v0, 0x6

    .line 240
    .line 241
    or-int/2addr v0, v10

    .line 242
    or-int/2addr v0, v4

    .line 243
    if-ltz v0, :cond_c

    .line 244
    .line 245
    add-int/lit8 v4, v3, 0x1

    .line 246
    .line 247
    shr-int/lit8 v6, v0, 0x10

    .line 248
    .line 249
    int-to-byte v6, v6

    .line 250
    aput-byte v6, v12, v3

    .line 251
    .line 252
    add-int/lit8 v6, v3, 0x2

    .line 253
    .line 254
    shr-int/lit8 v8, v0, 0x8

    .line 255
    .line 256
    int-to-byte v8, v8

    .line 257
    aput-byte v8, v12, v4

    .line 258
    .line 259
    add-int/lit8 v3, v3, 0x3

    .line 260
    .line 261
    int-to-byte v0, v0

    .line 262
    aput-byte v0, v12, v6

    .line 263
    .line 264
    move/from16 v8, p2

    .line 265
    .line 266
    move/from16 v6, v17

    .line 267
    .line 268
    move-object/from16 v0, v18

    .line 269
    .line 270
    move/from16 v14, v19

    .line 271
    .line 272
    const/16 v9, 0x3d

    .line 273
    .line 274
    :goto_9
    const/4 v10, -0x2

    .line 275
    const/4 v13, -0x8

    .line 276
    goto :goto_8

    .line 277
    :cond_b
    move-object/from16 v18, v0

    .line 278
    .line 279
    :cond_c
    aget-byte v0, v1, v14

    .line 280
    .line 281
    and-int/2addr v0, v7

    .line 282
    aget v4, v18, v0

    .line 283
    .line 284
    if-gez v4, :cond_17

    .line 285
    .line 286
    const/4 v10, -0x2

    .line 287
    if-ne v4, v10, :cond_15

    .line 288
    .line 289
    const/4 v4, -0x8

    .line 290
    if-eq v15, v4, :cond_14

    .line 291
    .line 292
    const/4 v0, -0x6

    .line 293
    if-eq v15, v0, :cond_13

    .line 294
    .line 295
    const/4 v0, -0x4

    .line 296
    if-eq v15, v0, :cond_e

    .line 297
    .line 298
    if-ne v15, v10, :cond_d

    .line 299
    .line 300
    :goto_a
    add-int/lit8 v14, v14, 0x1

    .line 301
    .line 302
    goto :goto_d

    .line 303
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 304
    .line 305
    const-string v1, "Unreachable"

    .line 306
    .line 307
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw v0

    .line 311
    :cond_e
    sget-object v0, Lxx0/b;->d:[Lxx0/b;

    .line 312
    .line 313
    add-int/lit8 v14, v14, 0x1

    .line 314
    .line 315
    if-nez v5, :cond_f

    .line 316
    .line 317
    goto :goto_c

    .line 318
    :cond_f
    :goto_b
    if-ge v14, v2, :cond_11

    .line 319
    .line 320
    aget-byte v0, v1, v14

    .line 321
    .line 322
    and-int/2addr v0, v7

    .line 323
    sget-object v4, Lxx0/d;->b:[I

    .line 324
    .line 325
    aget v0, v4, v0

    .line 326
    .line 327
    const/4 v4, -0x1

    .line 328
    if-eq v0, v4, :cond_10

    .line 329
    .line 330
    goto :goto_c

    .line 331
    :cond_10
    add-int/lit8 v14, v14, 0x1

    .line 332
    .line 333
    goto :goto_b

    .line 334
    :cond_11
    :goto_c
    if-eq v14, v2, :cond_12

    .line 335
    .line 336
    aget-byte v0, v1, v14

    .line 337
    .line 338
    const/16 v10, 0x3d

    .line 339
    .line 340
    if-ne v0, v10, :cond_12

    .line 341
    .line 342
    add-int/lit8 v14, v14, 0x1

    .line 343
    .line 344
    goto :goto_d

    .line 345
    :cond_12
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 346
    .line 347
    const-string v1, "Missing one pad character at index "

    .line 348
    .line 349
    invoke-static {v14, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v1

    .line 353
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    throw v0

    .line 357
    :cond_13
    sget-object v0, Lxx0/b;->d:[Lxx0/b;

    .line 358
    .line 359
    goto :goto_a

    .line 360
    :goto_d
    move/from16 v0, p1

    .line 361
    .line 362
    const/4 v10, -0x2

    .line 363
    goto/16 :goto_f

    .line 364
    .line 365
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 366
    .line 367
    const-string v1, "Redundant pad character at index "

    .line 368
    .line 369
    invoke-static {v14, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    throw v0

    .line 377
    :cond_15
    const/16 v10, 0x3d

    .line 378
    .line 379
    if-eqz v5, :cond_16

    .line 380
    .line 381
    add-int/lit8 v14, v14, 0x1

    .line 382
    .line 383
    move/from16 v8, p2

    .line 384
    .line 385
    move v9, v10

    .line 386
    move/from16 v6, v17

    .line 387
    .line 388
    move-object/from16 v0, v18

    .line 389
    .line 390
    goto :goto_9

    .line 391
    :cond_16
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 392
    .line 393
    new-instance v2, Ljava/lang/StringBuilder;

    .line 394
    .line 395
    const-string v3, "Invalid symbol \'"

    .line 396
    .line 397
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 398
    .line 399
    .line 400
    int-to-char v3, v0

    .line 401
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 402
    .line 403
    .line 404
    invoke-virtual {v2, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 405
    .line 406
    .line 407
    invoke-static/range {v17 .. v17}, Lry/a;->a(I)V

    .line 408
    .line 409
    .line 410
    move/from16 v3, v17

    .line 411
    .line 412
    invoke-static {v0, v3}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 420
    .line 421
    .line 422
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 423
    .line 424
    .line 425
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 426
    .line 427
    .line 428
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    throw v1

    .line 436
    :cond_17
    const/16 v10, 0x3d

    .line 437
    .line 438
    add-int/lit8 v14, v14, 0x1

    .line 439
    .line 440
    shl-int/lit8 v0, v16, 0x6

    .line 441
    .line 442
    or-int v16, v0, v4

    .line 443
    .line 444
    add-int/lit8 v4, v15, 0x6

    .line 445
    .line 446
    if-ltz v4, :cond_18

    .line 447
    .line 448
    add-int/lit8 v0, v3, 0x1

    .line 449
    .line 450
    ushr-int v6, v16, v4

    .line 451
    .line 452
    int-to-byte v6, v6

    .line 453
    aput-byte v6, v12, v3

    .line 454
    .line 455
    shl-int v3, p1, v4

    .line 456
    .line 457
    add-int/lit8 v3, v3, -0x1

    .line 458
    .line 459
    and-int v16, v16, v3

    .line 460
    .line 461
    add-int/lit8 v15, v15, -0x2

    .line 462
    .line 463
    move/from16 v8, p2

    .line 464
    .line 465
    move v3, v0

    .line 466
    :goto_e
    move v9, v10

    .line 467
    move-object/from16 v0, v18

    .line 468
    .line 469
    const/16 v6, 0x8

    .line 470
    .line 471
    goto/16 :goto_9

    .line 472
    .line 473
    :cond_18
    move/from16 v8, p2

    .line 474
    .line 475
    move v15, v4

    .line 476
    goto :goto_e

    .line 477
    :cond_19
    const/4 v0, 0x0

    .line 478
    :goto_f
    if-eq v15, v10, :cond_22

    .line 479
    .line 480
    const/4 v4, -0x8

    .line 481
    if-eq v15, v4, :cond_1b

    .line 482
    .line 483
    if-eqz v0, :cond_1a

    .line 484
    .line 485
    goto :goto_10

    .line 486
    :cond_1a
    sget-object v0, Lxx0/b;->d:[Lxx0/b;

    .line 487
    .line 488
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 489
    .line 490
    const-string v1, "The padding option is set to PRESENT, but the input is not properly padded"

    .line 491
    .line 492
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 493
    .line 494
    .line 495
    throw v0

    .line 496
    :cond_1b
    :goto_10
    if-nez v16, :cond_21

    .line 497
    .line 498
    if-nez v5, :cond_1c

    .line 499
    .line 500
    goto :goto_12

    .line 501
    :cond_1c
    :goto_11
    if-ge v14, v2, :cond_1e

    .line 502
    .line 503
    aget-byte v0, v1, v14

    .line 504
    .line 505
    and-int/2addr v0, v7

    .line 506
    sget-object v4, Lxx0/d;->b:[I

    .line 507
    .line 508
    aget v0, v4, v0

    .line 509
    .line 510
    const/4 v4, -0x1

    .line 511
    if-eq v0, v4, :cond_1d

    .line 512
    .line 513
    goto :goto_12

    .line 514
    :cond_1d
    add-int/lit8 v14, v14, 0x1

    .line 515
    .line 516
    goto :goto_11

    .line 517
    :cond_1e
    :goto_12
    if-lt v14, v2, :cond_20

    .line 518
    .line 519
    if-ne v3, v11, :cond_1f

    .line 520
    .line 521
    return-object v12

    .line 522
    :cond_1f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 523
    .line 524
    const-string v1, "Check failed."

    .line 525
    .line 526
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    throw v0

    .line 530
    :cond_20
    aget-byte v0, v1, v14

    .line 531
    .line 532
    and-int/2addr v0, v7

    .line 533
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 534
    .line 535
    new-instance v2, Ljava/lang/StringBuilder;

    .line 536
    .line 537
    const-string v3, "Symbol \'"

    .line 538
    .line 539
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    int-to-char v3, v0

    .line 543
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 544
    .line 545
    .line 546
    invoke-virtual {v2, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 547
    .line 548
    .line 549
    const/16 v3, 0x8

    .line 550
    .line 551
    invoke-static {v3}, Lry/a;->a(I)V

    .line 552
    .line 553
    .line 554
    invoke-static {v0, v3}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 555
    .line 556
    .line 557
    move-result-object v0

    .line 558
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 559
    .line 560
    .line 561
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 562
    .line 563
    .line 564
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 565
    .line 566
    .line 567
    add-int/lit8 v14, v14, -0x1

    .line 568
    .line 569
    const-string v0, " is prohibited after the pad character"

    .line 570
    .line 571
    invoke-static {v14, v0, v2}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 572
    .line 573
    .line 574
    move-result-object v0

    .line 575
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    throw v1

    .line 579
    :cond_21
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 580
    .line 581
    const-string v1, "The pad bits must be zeros"

    .line 582
    .line 583
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 584
    .line 585
    .line 586
    throw v0

    .line 587
    :cond_22
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 588
    .line 589
    const-string v1, "The last unit of input does not have enough bits"

    .line 590
    .line 591
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    throw v0

    .line 595
    :cond_23
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 596
    .line 597
    const-string v1, "Input should have at least 2 symbols for Base64 decoding, startIndex: 0, endIndex: "

    .line 598
    .line 599
    invoke-static {v2, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 600
    .line 601
    .line 602
    move-result-object v1

    .line 603
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    throw v0
.end method

.method public static b(Lxx0/c;[B)Ljava/lang/String;
    .locals 13

    .line 1
    array-length v0, p1

    .line 2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3
    .line 4
    .line 5
    array-length v1, p1

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v2, v0, v1}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lxx0/c;->c(I)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    new-array v3, v1, [B

    .line 15
    .line 16
    array-length v4, p1

    .line 17
    invoke-static {v2, v0, v4}, Landroidx/glance/appwidget/protobuf/f1;->a(III)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, v0}, Lxx0/c;->c(I)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-ltz v1, :cond_9

    .line 25
    .line 26
    if-ltz v4, :cond_8

    .line 27
    .line 28
    if-gt v4, v1, :cond_8

    .line 29
    .line 30
    iget-boolean v1, p0, Lxx0/c;->a:Z

    .line 31
    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    sget-object v1, Lxx0/d;->c:[B

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    sget-object v1, Lxx0/d;->a:[B

    .line 38
    .line 39
    :goto_0
    iget-boolean v4, p0, Lxx0/c;->b:Z

    .line 40
    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    iget p0, p0, Lxx0/c;->d:I

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const p0, 0x7fffffff

    .line 47
    .line 48
    .line 49
    :goto_1
    move v4, v2

    .line 50
    move v5, v4

    .line 51
    :cond_2
    :goto_2
    add-int/lit8 v6, v4, 0x2

    .line 52
    .line 53
    const/4 v7, 0x1

    .line 54
    if-ge v6, v0, :cond_4

    .line 55
    .line 56
    sub-int v6, v0, v4

    .line 57
    .line 58
    div-int/lit8 v6, v6, 0x3

    .line 59
    .line 60
    invoke-static {v6, p0}, Ljava/lang/Math;->min(II)I

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    move v8, v2

    .line 65
    :goto_3
    if-ge v8, v6, :cond_3

    .line 66
    .line 67
    add-int/lit8 v9, v4, 0x1

    .line 68
    .line 69
    aget-byte v10, p1, v4

    .line 70
    .line 71
    and-int/lit16 v10, v10, 0xff

    .line 72
    .line 73
    add-int/lit8 v11, v4, 0x2

    .line 74
    .line 75
    aget-byte v9, p1, v9

    .line 76
    .line 77
    and-int/lit16 v9, v9, 0xff

    .line 78
    .line 79
    add-int/lit8 v4, v4, 0x3

    .line 80
    .line 81
    aget-byte v11, p1, v11

    .line 82
    .line 83
    and-int/lit16 v11, v11, 0xff

    .line 84
    .line 85
    shl-int/lit8 v10, v10, 0x10

    .line 86
    .line 87
    shl-int/lit8 v9, v9, 0x8

    .line 88
    .line 89
    or-int/2addr v9, v10

    .line 90
    or-int/2addr v9, v11

    .line 91
    add-int/lit8 v10, v5, 0x1

    .line 92
    .line 93
    ushr-int/lit8 v11, v9, 0x12

    .line 94
    .line 95
    aget-byte v11, v1, v11

    .line 96
    .line 97
    aput-byte v11, v3, v5

    .line 98
    .line 99
    add-int/lit8 v11, v5, 0x2

    .line 100
    .line 101
    ushr-int/lit8 v12, v9, 0xc

    .line 102
    .line 103
    and-int/lit8 v12, v12, 0x3f

    .line 104
    .line 105
    aget-byte v12, v1, v12

    .line 106
    .line 107
    aput-byte v12, v3, v10

    .line 108
    .line 109
    add-int/lit8 v10, v5, 0x3

    .line 110
    .line 111
    ushr-int/lit8 v12, v9, 0x6

    .line 112
    .line 113
    and-int/lit8 v12, v12, 0x3f

    .line 114
    .line 115
    aget-byte v12, v1, v12

    .line 116
    .line 117
    aput-byte v12, v3, v11

    .line 118
    .line 119
    add-int/lit8 v5, v5, 0x4

    .line 120
    .line 121
    and-int/lit8 v9, v9, 0x3f

    .line 122
    .line 123
    aget-byte v9, v1, v9

    .line 124
    .line 125
    aput-byte v9, v3, v10

    .line 126
    .line 127
    add-int/lit8 v8, v8, 0x1

    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_3
    if-ne v6, p0, :cond_2

    .line 131
    .line 132
    if-eq v4, v0, :cond_2

    .line 133
    .line 134
    add-int/lit8 v6, v5, 0x1

    .line 135
    .line 136
    sget-object v8, Lxx0/c;->f:[B

    .line 137
    .line 138
    aget-byte v9, v8, v2

    .line 139
    .line 140
    aput-byte v9, v3, v5

    .line 141
    .line 142
    add-int/lit8 v5, v5, 0x2

    .line 143
    .line 144
    aget-byte v7, v8, v7

    .line 145
    .line 146
    aput-byte v7, v3, v6

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_4
    sub-int p0, v0, v4

    .line 150
    .line 151
    const/16 v2, 0x3d

    .line 152
    .line 153
    if-eq p0, v7, :cond_6

    .line 154
    .line 155
    const/4 v7, 0x2

    .line 156
    if-eq p0, v7, :cond_5

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_5
    add-int/lit8 p0, v4, 0x1

    .line 160
    .line 161
    aget-byte v4, p1, v4

    .line 162
    .line 163
    and-int/lit16 v4, v4, 0xff

    .line 164
    .line 165
    aget-byte p0, p1, p0

    .line 166
    .line 167
    and-int/lit16 p0, p0, 0xff

    .line 168
    .line 169
    shl-int/lit8 p1, v4, 0xa

    .line 170
    .line 171
    shl-int/2addr p0, v7

    .line 172
    or-int/2addr p0, p1

    .line 173
    add-int/lit8 p1, v5, 0x1

    .line 174
    .line 175
    ushr-int/lit8 v4, p0, 0xc

    .line 176
    .line 177
    aget-byte v4, v1, v4

    .line 178
    .line 179
    aput-byte v4, v3, v5

    .line 180
    .line 181
    add-int/lit8 v4, v5, 0x2

    .line 182
    .line 183
    ushr-int/lit8 v7, p0, 0x6

    .line 184
    .line 185
    and-int/lit8 v7, v7, 0x3f

    .line 186
    .line 187
    aget-byte v7, v1, v7

    .line 188
    .line 189
    aput-byte v7, v3, p1

    .line 190
    .line 191
    add-int/lit8 v5, v5, 0x3

    .line 192
    .line 193
    and-int/lit8 p0, p0, 0x3f

    .line 194
    .line 195
    aget-byte p0, v1, p0

    .line 196
    .line 197
    aput-byte p0, v3, v4

    .line 198
    .line 199
    sget-object p0, Lxx0/b;->d:[Lxx0/b;

    .line 200
    .line 201
    aput-byte v2, v3, v5

    .line 202
    .line 203
    move v4, v6

    .line 204
    goto :goto_4

    .line 205
    :cond_6
    add-int/lit8 p0, v4, 0x1

    .line 206
    .line 207
    aget-byte p1, p1, v4

    .line 208
    .line 209
    and-int/lit16 p1, p1, 0xff

    .line 210
    .line 211
    shl-int/lit8 p1, p1, 0x4

    .line 212
    .line 213
    add-int/lit8 v4, v5, 0x1

    .line 214
    .line 215
    ushr-int/lit8 v6, p1, 0x6

    .line 216
    .line 217
    aget-byte v6, v1, v6

    .line 218
    .line 219
    aput-byte v6, v3, v5

    .line 220
    .line 221
    add-int/lit8 v6, v5, 0x2

    .line 222
    .line 223
    and-int/lit8 p1, p1, 0x3f

    .line 224
    .line 225
    aget-byte p1, v1, p1

    .line 226
    .line 227
    aput-byte p1, v3, v4

    .line 228
    .line 229
    sget-object p1, Lxx0/b;->d:[Lxx0/b;

    .line 230
    .line 231
    add-int/lit8 v5, v5, 0x3

    .line 232
    .line 233
    aput-byte v2, v3, v6

    .line 234
    .line 235
    aput-byte v2, v3, v5

    .line 236
    .line 237
    move v4, p0

    .line 238
    :goto_4
    if-ne v4, v0, :cond_7

    .line 239
    .line 240
    new-instance p0, Ljava/lang/String;

    .line 241
    .line 242
    sget-object p1, Lly0/a;->d:Ljava/nio/charset/Charset;

    .line 243
    .line 244
    invoke-direct {p0, v3, p1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 245
    .line 246
    .line 247
    return-object p0

    .line 248
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 249
    .line 250
    const-string p1, "Check failed."

    .line 251
    .line 252
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw p0

    .line 256
    :cond_8
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 257
    .line 258
    const-string p1, "The destination array does not have enough capacity, destination offset: 0, destination size: "

    .line 259
    .line 260
    const-string v0, ", capacity needed: "

    .line 261
    .line 262
    invoke-static {p1, v0, v1, v4}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p1

    .line 266
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    throw p0

    .line 270
    :cond_9
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 271
    .line 272
    const-string p1, "destination offset: 0, destination size: "

    .line 273
    .line 274
    invoke-static {v1, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object p1

    .line 278
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    throw p0
.end method


# virtual methods
.method public final c(I)I
    .locals 3

    .line 1
    div-int/lit8 v0, p1, 0x3

    .line 2
    .line 3
    rem-int/lit8 p1, p1, 0x3

    .line 4
    .line 5
    mul-int/lit8 v0, v0, 0x4

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    sget-object p1, Lxx0/b;->d:[Lxx0/b;

    .line 10
    .line 11
    add-int/lit8 v0, v0, 0x4

    .line 12
    .line 13
    :cond_0
    const-string p1, "Input is too big"

    .line 14
    .line 15
    if-ltz v0, :cond_3

    .line 16
    .line 17
    iget-boolean v1, p0, Lxx0/c;->b:Z

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    add-int/lit8 v1, v0, -0x1

    .line 22
    .line 23
    iget p0, p0, Lxx0/c;->c:I

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-static {v1, p0, v2, v0}, La7/g0;->d(IIII)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    :cond_1
    if-ltz v0, :cond_2

    .line 31
    .line 32
    return v0

    .line 33
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method
