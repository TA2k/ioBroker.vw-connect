.class public final Lcom/google/protobuf/n1;
.super Lcom/google/protobuf/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/protobuf/n1;->c:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static d(J[BII)I
    .locals 2

    .line 1
    if-eqz p4, :cond_2

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p4, v0, :cond_1

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-ne p4, v0, :cond_0

    .line 8
    .line 9
    invoke-static {p2, p0, p1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    const-wide/16 v0, 0x1

    .line 14
    .line 15
    add-long/2addr p0, v0

    .line 16
    invoke-static {p2, p0, p1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p3, p4, p0}, Lcom/google/protobuf/p1;->d(III)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/AssertionError;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p2, p0, p1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p3, p0}, Lcom/google/protobuf/p1;->c(II)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    return p0

    .line 40
    :cond_2
    sget-object p0, Lcom/google/protobuf/p1;->a:Lcom/google/protobuf/b1;

    .line 41
    .line 42
    const/16 p0, -0xc

    .line 43
    .line 44
    if-le p3, p0, :cond_3

    .line 45
    .line 46
    const/4 p0, -0x1

    .line 47
    return p0

    .line 48
    :cond_3
    return p3
.end method


# virtual methods
.method public final a(IILjava/lang/String;[B)I
    .locals 23

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p0

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    iget v3, v3, Lcom/google/protobuf/n1;->c:I

    .line 12
    .line 13
    packed-switch v3, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    int-to-long v5, v0

    .line 17
    int-to-long v7, v1

    .line 18
    add-long/2addr v7, v5

    .line 19
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const-string v9, " at index "

    .line 24
    .line 25
    const-string v10, "Failed writing "

    .line 26
    .line 27
    if-gt v3, v1, :cond_c

    .line 28
    .line 29
    array-length v11, v4

    .line 30
    sub-int/2addr v11, v1

    .line 31
    if-lt v11, v0, :cond_c

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    :goto_0
    const-wide/16 v11, 0x1

    .line 35
    .line 36
    const/16 v1, 0x80

    .line 37
    .line 38
    if-ge v0, v3, :cond_0

    .line 39
    .line 40
    invoke-virtual {v2, v0}, Ljava/lang/String;->charAt(I)C

    .line 41
    .line 42
    .line 43
    move-result v13

    .line 44
    if-ge v13, v1, :cond_0

    .line 45
    .line 46
    add-long/2addr v11, v5

    .line 47
    int-to-byte v1, v13

    .line 48
    invoke-static {v4, v5, v6, v1}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 49
    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    move-wide v5, v11

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    if-ne v0, v3, :cond_2

    .line 56
    .line 57
    :cond_1
    long-to-int v0, v5

    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :cond_2
    :goto_1
    if-ge v0, v3, :cond_1

    .line 61
    .line 62
    invoke-virtual {v2, v0}, Ljava/lang/String;->charAt(I)C

    .line 63
    .line 64
    .line 65
    move-result v13

    .line 66
    if-ge v13, v1, :cond_3

    .line 67
    .line 68
    cmp-long v14, v5, v7

    .line 69
    .line 70
    if-gez v14, :cond_3

    .line 71
    .line 72
    add-long v14, v5, v11

    .line 73
    .line 74
    int-to-byte v13, v13

    .line 75
    invoke-static {v4, v5, v6, v13}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 76
    .line 77
    .line 78
    move-wide/from16 v19, v7

    .line 79
    .line 80
    move-wide/from16 p0, v11

    .line 81
    .line 82
    move-wide v5, v14

    .line 83
    goto/16 :goto_4

    .line 84
    .line 85
    :cond_3
    const/16 v14, 0x800

    .line 86
    .line 87
    const-wide/16 v15, 0x2

    .line 88
    .line 89
    if-ge v13, v14, :cond_4

    .line 90
    .line 91
    sub-long v17, v7, v15

    .line 92
    .line 93
    cmp-long v14, v5, v17

    .line 94
    .line 95
    if-gtz v14, :cond_4

    .line 96
    .line 97
    move-wide/from16 p0, v11

    .line 98
    .line 99
    add-long v11, v5, p0

    .line 100
    .line 101
    ushr-int/lit8 v14, v13, 0x6

    .line 102
    .line 103
    or-int/lit16 v14, v14, 0x3c0

    .line 104
    .line 105
    int-to-byte v14, v14

    .line 106
    invoke-static {v4, v5, v6, v14}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 107
    .line 108
    .line 109
    add-long/2addr v5, v15

    .line 110
    and-int/lit8 v13, v13, 0x3f

    .line 111
    .line 112
    or-int/2addr v13, v1

    .line 113
    int-to-byte v13, v13

    .line 114
    invoke-static {v4, v11, v12, v13}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 115
    .line 116
    .line 117
    move-wide/from16 v19, v7

    .line 118
    .line 119
    goto/16 :goto_4

    .line 120
    .line 121
    :cond_4
    move-wide/from16 p0, v11

    .line 122
    .line 123
    const v11, 0xdfff

    .line 124
    .line 125
    .line 126
    const v12, 0xd800

    .line 127
    .line 128
    .line 129
    const-wide/16 v17, 0x3

    .line 130
    .line 131
    if-lt v13, v12, :cond_6

    .line 132
    .line 133
    if-ge v11, v13, :cond_5

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_5
    move-wide/from16 v19, v7

    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_6
    :goto_2
    sub-long v19, v7, v17

    .line 140
    .line 141
    cmp-long v14, v5, v19

    .line 142
    .line 143
    if-gtz v14, :cond_5

    .line 144
    .line 145
    add-long v11, v5, p0

    .line 146
    .line 147
    ushr-int/lit8 v14, v13, 0xc

    .line 148
    .line 149
    or-int/lit16 v14, v14, 0x1e0

    .line 150
    .line 151
    int-to-byte v14, v14

    .line 152
    invoke-static {v4, v5, v6, v14}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 153
    .line 154
    .line 155
    add-long v14, v5, v15

    .line 156
    .line 157
    ushr-int/lit8 v16, v13, 0x6

    .line 158
    .line 159
    move-wide/from16 v19, v7

    .line 160
    .line 161
    and-int/lit8 v7, v16, 0x3f

    .line 162
    .line 163
    or-int/2addr v7, v1

    .line 164
    int-to-byte v7, v7

    .line 165
    invoke-static {v4, v11, v12, v7}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 166
    .line 167
    .line 168
    add-long v5, v5, v17

    .line 169
    .line 170
    and-int/lit8 v7, v13, 0x3f

    .line 171
    .line 172
    or-int/2addr v7, v1

    .line 173
    int-to-byte v7, v7

    .line 174
    invoke-static {v4, v14, v15, v7}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 175
    .line 176
    .line 177
    goto :goto_4

    .line 178
    :goto_3
    const-wide/16 v7, 0x4

    .line 179
    .line 180
    sub-long v21, v19, v7

    .line 181
    .line 182
    cmp-long v14, v5, v21

    .line 183
    .line 184
    if-gtz v14, :cond_9

    .line 185
    .line 186
    add-int/lit8 v11, v0, 0x1

    .line 187
    .line 188
    if-eq v11, v3, :cond_8

    .line 189
    .line 190
    invoke-virtual {v2, v11}, Ljava/lang/String;->charAt(I)C

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    invoke-static {v13, v0}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 195
    .line 196
    .line 197
    move-result v12

    .line 198
    if-eqz v12, :cond_7

    .line 199
    .line 200
    invoke-static {v13, v0}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 201
    .line 202
    .line 203
    move-result v0

    .line 204
    add-long v12, v5, p0

    .line 205
    .line 206
    ushr-int/lit8 v14, v0, 0x12

    .line 207
    .line 208
    or-int/lit16 v14, v14, 0xf0

    .line 209
    .line 210
    int-to-byte v14, v14

    .line 211
    invoke-static {v4, v5, v6, v14}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 212
    .line 213
    .line 214
    add-long v14, v5, v15

    .line 215
    .line 216
    ushr-int/lit8 v16, v0, 0xc

    .line 217
    .line 218
    move-wide/from16 v21, v7

    .line 219
    .line 220
    and-int/lit8 v7, v16, 0x3f

    .line 221
    .line 222
    or-int/2addr v7, v1

    .line 223
    int-to-byte v7, v7

    .line 224
    invoke-static {v4, v12, v13, v7}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 225
    .line 226
    .line 227
    add-long v7, v5, v17

    .line 228
    .line 229
    ushr-int/lit8 v12, v0, 0x6

    .line 230
    .line 231
    and-int/lit8 v12, v12, 0x3f

    .line 232
    .line 233
    or-int/2addr v12, v1

    .line 234
    int-to-byte v12, v12

    .line 235
    invoke-static {v4, v14, v15, v12}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 236
    .line 237
    .line 238
    add-long v5, v5, v21

    .line 239
    .line 240
    and-int/lit8 v0, v0, 0x3f

    .line 241
    .line 242
    or-int/2addr v0, v1

    .line 243
    int-to-byte v0, v0

    .line 244
    invoke-static {v4, v7, v8, v0}, Lcom/google/protobuf/m1;->k([BJB)V

    .line 245
    .line 246
    .line 247
    move v0, v11

    .line 248
    :goto_4
    add-int/lit8 v0, v0, 0x1

    .line 249
    .line 250
    move-wide/from16 v11, p0

    .line 251
    .line 252
    move-wide/from16 v7, v19

    .line 253
    .line 254
    goto/16 :goto_1

    .line 255
    .line 256
    :cond_7
    move v0, v11

    .line 257
    :cond_8
    new-instance v1, Lcom/google/protobuf/o1;

    .line 258
    .line 259
    add-int/lit8 v0, v0, -0x1

    .line 260
    .line 261
    invoke-direct {v1, v0, v3}, Lcom/google/protobuf/o1;-><init>(II)V

    .line 262
    .line 263
    .line 264
    throw v1

    .line 265
    :cond_9
    if-gt v12, v13, :cond_b

    .line 266
    .line 267
    if-gt v13, v11, :cond_b

    .line 268
    .line 269
    add-int/lit8 v1, v0, 0x1

    .line 270
    .line 271
    if-eq v1, v3, :cond_a

    .line 272
    .line 273
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    invoke-static {v13, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    if-nez v1, :cond_b

    .line 282
    .line 283
    :cond_a
    new-instance v1, Lcom/google/protobuf/o1;

    .line 284
    .line 285
    invoke-direct {v1, v0, v3}, Lcom/google/protobuf/o1;-><init>(II)V

    .line 286
    .line 287
    .line 288
    throw v1

    .line 289
    :cond_b
    new-instance v0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 290
    .line 291
    new-instance v1, Ljava/lang/StringBuilder;

    .line 292
    .line 293
    invoke-direct {v1, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 300
    .line 301
    .line 302
    invoke-virtual {v1, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 303
    .line 304
    .line 305
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-direct {v0, v1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw v0

    .line 313
    :goto_5
    return v0

    .line 314
    :cond_c
    new-instance v4, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 315
    .line 316
    new-instance v5, Ljava/lang/StringBuilder;

    .line 317
    .line 318
    invoke-direct {v5, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    add-int/lit8 v3, v3, -0x1

    .line 322
    .line 323
    invoke-virtual {v2, v3}, Ljava/lang/String;->charAt(I)C

    .line 324
    .line 325
    .line 326
    move-result v2

    .line 327
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 328
    .line 329
    .line 330
    invoke-virtual {v5, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    add-int/2addr v0, v1

    .line 334
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 335
    .line 336
    .line 337
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    invoke-direct {v4, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    throw v4

    .line 345
    :pswitch_0
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 346
    .line 347
    .line 348
    move-result v3

    .line 349
    add-int/2addr v1, v0

    .line 350
    const/4 v5, 0x0

    .line 351
    :goto_6
    const/16 v6, 0x80

    .line 352
    .line 353
    if-ge v5, v3, :cond_d

    .line 354
    .line 355
    add-int v7, v5, v0

    .line 356
    .line 357
    if-ge v7, v1, :cond_d

    .line 358
    .line 359
    invoke-virtual {v2, v5}, Ljava/lang/String;->charAt(I)C

    .line 360
    .line 361
    .line 362
    move-result v8

    .line 363
    if-ge v8, v6, :cond_d

    .line 364
    .line 365
    int-to-byte v6, v8

    .line 366
    aput-byte v6, v4, v7

    .line 367
    .line 368
    add-int/lit8 v5, v5, 0x1

    .line 369
    .line 370
    goto :goto_6

    .line 371
    :cond_d
    if-ne v5, v3, :cond_e

    .line 372
    .line 373
    add-int/2addr v0, v3

    .line 374
    goto/16 :goto_9

    .line 375
    .line 376
    :cond_e
    add-int/2addr v0, v5

    .line 377
    :goto_7
    if-ge v5, v3, :cond_18

    .line 378
    .line 379
    invoke-virtual {v2, v5}, Ljava/lang/String;->charAt(I)C

    .line 380
    .line 381
    .line 382
    move-result v7

    .line 383
    if-ge v7, v6, :cond_f

    .line 384
    .line 385
    if-ge v0, v1, :cond_f

    .line 386
    .line 387
    add-int/lit8 v8, v0, 0x1

    .line 388
    .line 389
    int-to-byte v7, v7

    .line 390
    aput-byte v7, v4, v0

    .line 391
    .line 392
    move v0, v8

    .line 393
    goto/16 :goto_8

    .line 394
    .line 395
    :cond_f
    const/16 v8, 0x800

    .line 396
    .line 397
    if-ge v7, v8, :cond_10

    .line 398
    .line 399
    add-int/lit8 v8, v1, -0x2

    .line 400
    .line 401
    if-gt v0, v8, :cond_10

    .line 402
    .line 403
    add-int/lit8 v8, v0, 0x1

    .line 404
    .line 405
    ushr-int/lit8 v9, v7, 0x6

    .line 406
    .line 407
    or-int/lit16 v9, v9, 0x3c0

    .line 408
    .line 409
    int-to-byte v9, v9

    .line 410
    aput-byte v9, v4, v0

    .line 411
    .line 412
    add-int/lit8 v0, v0, 0x2

    .line 413
    .line 414
    and-int/lit8 v7, v7, 0x3f

    .line 415
    .line 416
    or-int/2addr v7, v6

    .line 417
    int-to-byte v7, v7

    .line 418
    aput-byte v7, v4, v8

    .line 419
    .line 420
    goto :goto_8

    .line 421
    :cond_10
    const v8, 0xdfff

    .line 422
    .line 423
    .line 424
    const v9, 0xd800

    .line 425
    .line 426
    .line 427
    if-lt v7, v9, :cond_11

    .line 428
    .line 429
    if-ge v8, v7, :cond_12

    .line 430
    .line 431
    :cond_11
    add-int/lit8 v10, v1, -0x3

    .line 432
    .line 433
    if-gt v0, v10, :cond_12

    .line 434
    .line 435
    add-int/lit8 v8, v0, 0x1

    .line 436
    .line 437
    ushr-int/lit8 v9, v7, 0xc

    .line 438
    .line 439
    or-int/lit16 v9, v9, 0x1e0

    .line 440
    .line 441
    int-to-byte v9, v9

    .line 442
    aput-byte v9, v4, v0

    .line 443
    .line 444
    add-int/lit8 v9, v0, 0x2

    .line 445
    .line 446
    ushr-int/lit8 v10, v7, 0x6

    .line 447
    .line 448
    and-int/lit8 v10, v10, 0x3f

    .line 449
    .line 450
    or-int/2addr v10, v6

    .line 451
    int-to-byte v10, v10

    .line 452
    aput-byte v10, v4, v8

    .line 453
    .line 454
    add-int/lit8 v0, v0, 0x3

    .line 455
    .line 456
    and-int/lit8 v7, v7, 0x3f

    .line 457
    .line 458
    or-int/2addr v7, v6

    .line 459
    int-to-byte v7, v7

    .line 460
    aput-byte v7, v4, v9

    .line 461
    .line 462
    goto :goto_8

    .line 463
    :cond_12
    add-int/lit8 v10, v1, -0x4

    .line 464
    .line 465
    if-gt v0, v10, :cond_15

    .line 466
    .line 467
    add-int/lit8 v8, v5, 0x1

    .line 468
    .line 469
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 470
    .line 471
    .line 472
    move-result v9

    .line 473
    if-eq v8, v9, :cond_14

    .line 474
    .line 475
    invoke-virtual {v2, v8}, Ljava/lang/String;->charAt(I)C

    .line 476
    .line 477
    .line 478
    move-result v5

    .line 479
    invoke-static {v7, v5}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 480
    .line 481
    .line 482
    move-result v9

    .line 483
    if-eqz v9, :cond_13

    .line 484
    .line 485
    invoke-static {v7, v5}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 486
    .line 487
    .line 488
    move-result v5

    .line 489
    add-int/lit8 v7, v0, 0x1

    .line 490
    .line 491
    ushr-int/lit8 v9, v5, 0x12

    .line 492
    .line 493
    or-int/lit16 v9, v9, 0xf0

    .line 494
    .line 495
    int-to-byte v9, v9

    .line 496
    aput-byte v9, v4, v0

    .line 497
    .line 498
    add-int/lit8 v9, v0, 0x2

    .line 499
    .line 500
    ushr-int/lit8 v10, v5, 0xc

    .line 501
    .line 502
    and-int/lit8 v10, v10, 0x3f

    .line 503
    .line 504
    or-int/2addr v10, v6

    .line 505
    int-to-byte v10, v10

    .line 506
    aput-byte v10, v4, v7

    .line 507
    .line 508
    add-int/lit8 v7, v0, 0x3

    .line 509
    .line 510
    ushr-int/lit8 v10, v5, 0x6

    .line 511
    .line 512
    and-int/lit8 v10, v10, 0x3f

    .line 513
    .line 514
    or-int/2addr v10, v6

    .line 515
    int-to-byte v10, v10

    .line 516
    aput-byte v10, v4, v9

    .line 517
    .line 518
    add-int/lit8 v0, v0, 0x4

    .line 519
    .line 520
    and-int/lit8 v5, v5, 0x3f

    .line 521
    .line 522
    or-int/2addr v5, v6

    .line 523
    int-to-byte v5, v5

    .line 524
    aput-byte v5, v4, v7

    .line 525
    .line 526
    move v5, v8

    .line 527
    :goto_8
    add-int/lit8 v5, v5, 0x1

    .line 528
    .line 529
    goto/16 :goto_7

    .line 530
    .line 531
    :cond_13
    move v5, v8

    .line 532
    :cond_14
    new-instance v0, Lcom/google/protobuf/o1;

    .line 533
    .line 534
    add-int/lit8 v5, v5, -0x1

    .line 535
    .line 536
    invoke-direct {v0, v5, v3}, Lcom/google/protobuf/o1;-><init>(II)V

    .line 537
    .line 538
    .line 539
    throw v0

    .line 540
    :cond_15
    if-gt v9, v7, :cond_17

    .line 541
    .line 542
    if-gt v7, v8, :cond_17

    .line 543
    .line 544
    add-int/lit8 v1, v5, 0x1

    .line 545
    .line 546
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 547
    .line 548
    .line 549
    move-result v4

    .line 550
    if-eq v1, v4, :cond_16

    .line 551
    .line 552
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 553
    .line 554
    .line 555
    move-result v1

    .line 556
    invoke-static {v7, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 557
    .line 558
    .line 559
    move-result v1

    .line 560
    if-nez v1, :cond_17

    .line 561
    .line 562
    :cond_16
    new-instance v0, Lcom/google/protobuf/o1;

    .line 563
    .line 564
    invoke-direct {v0, v5, v3}, Lcom/google/protobuf/o1;-><init>(II)V

    .line 565
    .line 566
    .line 567
    throw v0

    .line 568
    :cond_17
    new-instance v1, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 569
    .line 570
    new-instance v2, Ljava/lang/StringBuilder;

    .line 571
    .line 572
    const-string v3, "Failed writing "

    .line 573
    .line 574
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 575
    .line 576
    .line 577
    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 578
    .line 579
    .line 580
    const-string v3, " at index "

    .line 581
    .line 582
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 583
    .line 584
    .line 585
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 586
    .line 587
    .line 588
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    invoke-direct {v1, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    throw v1

    .line 596
    :cond_18
    :goto_9
    return v0

    .line 597
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c([BII)I
    .locals 12

    .line 1
    iget p0, p0, Lcom/google/protobuf/n1;->c:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    or-int p0, p2, p3

    .line 7
    .line 8
    array-length v0, p1

    .line 9
    sub-int/2addr v0, p3

    .line 10
    or-int/2addr p0, v0

    .line 11
    if-ltz p0, :cond_14

    .line 12
    .line 13
    int-to-long v0, p2

    .line 14
    int-to-long p2, p3

    .line 15
    sub-long/2addr p2, v0

    .line 16
    long-to-int p0, p2

    .line 17
    const/16 p2, 0x10

    .line 18
    .line 19
    const/4 p3, 0x0

    .line 20
    const-wide/16 v2, 0x1

    .line 21
    .line 22
    if-ge p0, p2, :cond_0

    .line 23
    .line 24
    move v4, p3

    .line 25
    goto :goto_3

    .line 26
    :cond_0
    long-to-int p2, v0

    .line 27
    and-int/lit8 p2, p2, 0x7

    .line 28
    .line 29
    rsub-int/lit8 p2, p2, 0x8

    .line 30
    .line 31
    move v4, p3

    .line 32
    move-wide v5, v0

    .line 33
    :goto_0
    if-ge v4, p2, :cond_2

    .line 34
    .line 35
    add-long v7, v5, v2

    .line 36
    .line 37
    invoke-static {p1, v5, v6}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    if-gez v5, :cond_1

    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 45
    .line 46
    move-wide v5, v7

    .line 47
    goto :goto_0

    .line 48
    :cond_2
    :goto_1
    add-int/lit8 p2, v4, 0x8

    .line 49
    .line 50
    if-gt p2, p0, :cond_4

    .line 51
    .line 52
    sget-wide v7, Lcom/google/protobuf/m1;->f:J

    .line 53
    .line 54
    add-long/2addr v7, v5

    .line 55
    sget-object v9, Lcom/google/protobuf/m1;->c:Lcom/google/protobuf/l1;

    .line 56
    .line 57
    invoke-virtual {v9, p1, v7, v8}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 58
    .line 59
    .line 60
    move-result-wide v7

    .line 61
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr v7, v9

    .line 67
    const-wide/16 v9, 0x0

    .line 68
    .line 69
    cmp-long v7, v7, v9

    .line 70
    .line 71
    if-eqz v7, :cond_3

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_3
    const-wide/16 v7, 0x8

    .line 75
    .line 76
    add-long/2addr v5, v7

    .line 77
    move v4, p2

    .line 78
    goto :goto_1

    .line 79
    :cond_4
    :goto_2
    if-ge v4, p0, :cond_6

    .line 80
    .line 81
    add-long v7, v5, v2

    .line 82
    .line 83
    invoke-static {p1, v5, v6}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    if-gez p2, :cond_5

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_5
    add-int/lit8 v4, v4, 0x1

    .line 91
    .line 92
    move-wide v5, v7

    .line 93
    goto :goto_2

    .line 94
    :cond_6
    move v4, p0

    .line 95
    :goto_3
    sub-int/2addr p0, v4

    .line 96
    int-to-long v4, v4

    .line 97
    add-long/2addr v0, v4

    .line 98
    :cond_7
    :goto_4
    move p2, p3

    .line 99
    :goto_5
    if-lez p0, :cond_9

    .line 100
    .line 101
    add-long v4, v0, v2

    .line 102
    .line 103
    invoke-static {p1, v0, v1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    if-ltz p2, :cond_8

    .line 108
    .line 109
    add-int/lit8 p0, p0, -0x1

    .line 110
    .line 111
    move-wide v0, v4

    .line 112
    goto :goto_5

    .line 113
    :cond_8
    move-wide v0, v4

    .line 114
    :cond_9
    if-nez p0, :cond_a

    .line 115
    .line 116
    goto/16 :goto_7

    .line 117
    .line 118
    :cond_a
    add-int/lit8 v4, p0, -0x1

    .line 119
    .line 120
    const/16 v5, -0x20

    .line 121
    .line 122
    const/16 v6, -0x41

    .line 123
    .line 124
    if-ge p2, v5, :cond_d

    .line 125
    .line 126
    if-nez v4, :cond_b

    .line 127
    .line 128
    move p3, p2

    .line 129
    goto/16 :goto_7

    .line 130
    .line 131
    :cond_b
    add-int/lit8 p0, p0, -0x2

    .line 132
    .line 133
    const/16 v4, -0x3e

    .line 134
    .line 135
    if-lt p2, v4, :cond_13

    .line 136
    .line 137
    add-long v4, v0, v2

    .line 138
    .line 139
    invoke-static {p1, v0, v1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 140
    .line 141
    .line 142
    move-result p2

    .line 143
    if-le p2, v6, :cond_c

    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_c
    move-wide v0, v4

    .line 147
    goto :goto_4

    .line 148
    :cond_d
    const/16 v7, -0x10

    .line 149
    .line 150
    const-wide/16 v8, 0x2

    .line 151
    .line 152
    if-ge p2, v7, :cond_11

    .line 153
    .line 154
    const/4 v7, 0x2

    .line 155
    if-ge v4, v7, :cond_e

    .line 156
    .line 157
    invoke-static {v0, v1, p1, p2, v4}, Lcom/google/protobuf/n1;->d(J[BII)I

    .line 158
    .line 159
    .line 160
    move-result p3

    .line 161
    goto :goto_7

    .line 162
    :cond_e
    add-int/lit8 p0, p0, -0x3

    .line 163
    .line 164
    add-long v10, v0, v2

    .line 165
    .line 166
    invoke-static {p1, v0, v1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    if-gt v4, v6, :cond_13

    .line 171
    .line 172
    const/16 v7, -0x60

    .line 173
    .line 174
    if-ne p2, v5, :cond_f

    .line 175
    .line 176
    if-lt v4, v7, :cond_13

    .line 177
    .line 178
    :cond_f
    const/16 v5, -0x13

    .line 179
    .line 180
    if-ne p2, v5, :cond_10

    .line 181
    .line 182
    if-ge v4, v7, :cond_13

    .line 183
    .line 184
    :cond_10
    add-long/2addr v0, v8

    .line 185
    invoke-static {p1, v10, v11}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 186
    .line 187
    .line 188
    move-result p2

    .line 189
    if-le p2, v6, :cond_7

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_11
    const/4 v5, 0x3

    .line 193
    if-ge v4, v5, :cond_12

    .line 194
    .line 195
    invoke-static {v0, v1, p1, p2, v4}, Lcom/google/protobuf/n1;->d(J[BII)I

    .line 196
    .line 197
    .line 198
    move-result p3

    .line 199
    goto :goto_7

    .line 200
    :cond_12
    add-int/lit8 p0, p0, -0x4

    .line 201
    .line 202
    add-long v4, v0, v2

    .line 203
    .line 204
    invoke-static {p1, v0, v1}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 205
    .line 206
    .line 207
    move-result v7

    .line 208
    if-gt v7, v6, :cond_13

    .line 209
    .line 210
    shl-int/lit8 p2, p2, 0x1c

    .line 211
    .line 212
    add-int/lit8 v7, v7, 0x70

    .line 213
    .line 214
    add-int/2addr v7, p2

    .line 215
    shr-int/lit8 p2, v7, 0x1e

    .line 216
    .line 217
    if-nez p2, :cond_13

    .line 218
    .line 219
    add-long/2addr v8, v0

    .line 220
    invoke-static {p1, v4, v5}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 221
    .line 222
    .line 223
    move-result p2

    .line 224
    if-gt p2, v6, :cond_13

    .line 225
    .line 226
    const-wide/16 v4, 0x3

    .line 227
    .line 228
    add-long/2addr v0, v4

    .line 229
    invoke-static {p1, v8, v9}, Lcom/google/protobuf/m1;->g([BJ)B

    .line 230
    .line 231
    .line 232
    move-result p2

    .line 233
    if-le p2, v6, :cond_7

    .line 234
    .line 235
    :cond_13
    :goto_6
    const/4 p3, -0x1

    .line 236
    :goto_7
    return p3

    .line 237
    :cond_14
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 238
    .line 239
    array-length p1, p1

    .line 240
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 245
    .line 246
    .line 247
    move-result-object p2

    .line 248
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 249
    .line 250
    .line 251
    move-result-object p3

    .line 252
    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object p1

    .line 256
    const-string p2, "Array length=%d, index=%d, limit=%d"

    .line 257
    .line 258
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object p1

    .line 262
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    throw p0

    .line 266
    :goto_8
    :pswitch_0
    if-ge p2, p3, :cond_15

    .line 267
    .line 268
    aget-byte p0, p1, p2

    .line 269
    .line 270
    if-ltz p0, :cond_15

    .line 271
    .line 272
    add-int/lit8 p2, p2, 0x1

    .line 273
    .line 274
    goto :goto_8

    .line 275
    :cond_15
    if-lt p2, p3, :cond_16

    .line 276
    .line 277
    goto :goto_a

    .line 278
    :cond_16
    :goto_9
    if-lt p2, p3, :cond_17

    .line 279
    .line 280
    :goto_a
    const/4 p0, 0x0

    .line 281
    goto/16 :goto_c

    .line 282
    .line 283
    :cond_17
    add-int/lit8 p0, p2, 0x1

    .line 284
    .line 285
    aget-byte v0, p1, p2

    .line 286
    .line 287
    if-gez v0, :cond_20

    .line 288
    .line 289
    const/16 v1, -0x20

    .line 290
    .line 291
    const/16 v2, -0x41

    .line 292
    .line 293
    if-ge v0, v1, :cond_19

    .line 294
    .line 295
    if-lt p0, p3, :cond_18

    .line 296
    .line 297
    move p0, v0

    .line 298
    goto :goto_c

    .line 299
    :cond_18
    const/16 v1, -0x3e

    .line 300
    .line 301
    if-lt v0, v1, :cond_1f

    .line 302
    .line 303
    add-int/lit8 p2, p2, 0x2

    .line 304
    .line 305
    aget-byte p0, p1, p0

    .line 306
    .line 307
    if-le p0, v2, :cond_16

    .line 308
    .line 309
    goto :goto_b

    .line 310
    :cond_19
    const/16 v3, -0x10

    .line 311
    .line 312
    if-ge v0, v3, :cond_1d

    .line 313
    .line 314
    add-int/lit8 v3, p3, -0x1

    .line 315
    .line 316
    if-lt p0, v3, :cond_1a

    .line 317
    .line 318
    invoke-static {p1, p0, p3}, Lcom/google/protobuf/p1;->a([BII)I

    .line 319
    .line 320
    .line 321
    move-result p0

    .line 322
    goto :goto_c

    .line 323
    :cond_1a
    add-int/lit8 v3, p2, 0x2

    .line 324
    .line 325
    aget-byte p0, p1, p0

    .line 326
    .line 327
    if-gt p0, v2, :cond_1f

    .line 328
    .line 329
    const/16 v4, -0x60

    .line 330
    .line 331
    if-ne v0, v1, :cond_1b

    .line 332
    .line 333
    if-lt p0, v4, :cond_1f

    .line 334
    .line 335
    :cond_1b
    const/16 v1, -0x13

    .line 336
    .line 337
    if-ne v0, v1, :cond_1c

    .line 338
    .line 339
    if-ge p0, v4, :cond_1f

    .line 340
    .line 341
    :cond_1c
    add-int/lit8 p2, p2, 0x3

    .line 342
    .line 343
    aget-byte p0, p1, v3

    .line 344
    .line 345
    if-le p0, v2, :cond_16

    .line 346
    .line 347
    goto :goto_b

    .line 348
    :cond_1d
    add-int/lit8 v1, p3, -0x2

    .line 349
    .line 350
    if-lt p0, v1, :cond_1e

    .line 351
    .line 352
    invoke-static {p1, p0, p3}, Lcom/google/protobuf/p1;->a([BII)I

    .line 353
    .line 354
    .line 355
    move-result p0

    .line 356
    goto :goto_c

    .line 357
    :cond_1e
    add-int/lit8 v1, p2, 0x2

    .line 358
    .line 359
    aget-byte p0, p1, p0

    .line 360
    .line 361
    if-gt p0, v2, :cond_1f

    .line 362
    .line 363
    shl-int/lit8 v0, v0, 0x1c

    .line 364
    .line 365
    add-int/lit8 p0, p0, 0x70

    .line 366
    .line 367
    add-int/2addr p0, v0

    .line 368
    shr-int/lit8 p0, p0, 0x1e

    .line 369
    .line 370
    if-nez p0, :cond_1f

    .line 371
    .line 372
    add-int/lit8 p0, p2, 0x3

    .line 373
    .line 374
    aget-byte v0, p1, v1

    .line 375
    .line 376
    if-gt v0, v2, :cond_1f

    .line 377
    .line 378
    add-int/lit8 p2, p2, 0x4

    .line 379
    .line 380
    aget-byte p0, p1, p0

    .line 381
    .line 382
    if-le p0, v2, :cond_16

    .line 383
    .line 384
    :cond_1f
    :goto_b
    const/4 p0, -0x1

    .line 385
    :goto_c
    return p0

    .line 386
    :cond_20
    move p2, p0

    .line 387
    goto :goto_9

    .line 388
    nop

    .line 389
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
