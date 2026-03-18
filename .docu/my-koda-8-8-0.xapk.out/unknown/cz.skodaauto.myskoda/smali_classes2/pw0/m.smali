.class public abstract Lpw0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Loz0/a;

.field public static final b:Loz0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Loz0/a;

    .line 2
    .line 3
    const-string v1, "\r\n"

    .line 4
    .line 5
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 6
    .line 7
    invoke-static {v1, v2}, Ljp/ib;->c(Ljava/lang/String;Ljava/nio/charset/Charset;)[B

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x0

    .line 12
    array-length v3, v1

    .line 13
    invoke-direct {v0, v1, v2, v3}, Loz0/a;-><init>([BII)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lpw0/m;->a:Loz0/a;

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    new-array v0, v0, [B

    .line 20
    .line 21
    fill-array-data v0, :array_0

    .line 22
    .line 23
    .line 24
    new-instance v1, Loz0/a;

    .line 25
    .line 26
    invoke-direct {v1, v0}, Loz0/a;-><init>([B)V

    .line 27
    .line 28
    .line 29
    sput-object v1, Lpw0/m;->b:Loz0/a;

    .line 30
    .line 31
    return-void

    .line 32
    nop

    .line 33
    :array_0
    .array-data 1
        0x2dt
        0x2dt
    .end array-data
.end method

.method public static final a(Loz0/a;Lio/ktor/utils/io/o0;Lio/ktor/utils/io/m;Lpw0/d;JLrx0/c;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    move-wide/from16 v4, p4

    .line 4
    .line 5
    move-object/from16 v0, p6

    .line 6
    .line 7
    instance-of v1, v0, Lpw0/j;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    move-object v1, v0

    .line 12
    check-cast v1, Lpw0/j;

    .line 13
    .line 14
    iget v2, v1, Lpw0/j;->j:I

    .line 15
    .line 16
    const/high16 v6, -0x80000000

    .line 17
    .line 18
    and-int v7, v2, v6

    .line 19
    .line 20
    if-eqz v7, :cond_0

    .line 21
    .line 22
    sub-int/2addr v2, v6

    .line 23
    iput v2, v1, Lpw0/j;->j:I

    .line 24
    .line 25
    :goto_0
    move-object v6, v1

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    new-instance v1, Lpw0/j;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :goto_1
    iget-object v0, v6, Lpw0/j;->i:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v1, v6, Lpw0/j;->j:I

    .line 38
    .line 39
    const/4 v8, 0x4

    .line 40
    const/4 v2, 0x2

    .line 41
    const/4 v9, 0x3

    .line 42
    const/4 v10, 0x1

    .line 43
    const/4 v11, 0x0

    .line 44
    if-eqz v1, :cond_5

    .line 45
    .line 46
    if-eq v1, v10, :cond_4

    .line 47
    .line 48
    if-eq v1, v2, :cond_3

    .line 49
    .line 50
    if-eq v1, v9, :cond_2

    .line 51
    .line 52
    if-ne v1, v8, :cond_1

    .line 53
    .line 54
    iget-wide v1, v6, Lpw0/j;->h:J

    .line 55
    .line 56
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_b

    .line 60
    .line 61
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_2
    iget-wide v1, v6, Lpw0/j;->h:J

    .line 70
    .line 71
    iget-wide v3, v6, Lpw0/j;->g:J

    .line 72
    .line 73
    iget-object v5, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 74
    .line 75
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto/16 :goto_8

    .line 79
    .line 80
    :cond_3
    iget-wide v1, v6, Lpw0/j;->g:J

    .line 81
    .line 82
    iget-object v3, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 83
    .line 84
    iget-object v4, v6, Lpw0/j;->e:Lio/ktor/utils/io/o0;

    .line 85
    .line 86
    iget-object v5, v6, Lpw0/j;->d:Loz0/a;

    .line 87
    .line 88
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move/from16 v24, v9

    .line 92
    .line 93
    move-wide/from16 v27, v1

    .line 94
    .line 95
    move-object v2, v0

    .line 96
    move-object v1, v4

    .line 97
    move-object v0, v5

    .line 98
    move-wide/from16 v4, v27

    .line 99
    .line 100
    goto/16 :goto_7

    .line 101
    .line 102
    :cond_4
    iget-wide v1, v6, Lpw0/j;->g:J

    .line 103
    .line 104
    iget-object v3, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 105
    .line 106
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto/16 :goto_6

    .line 110
    .line 111
    :cond_5
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    const-string v0, "Content-Length"

    .line 115
    .line 116
    move-object/from16 v1, p3

    .line 117
    .line 118
    invoke-virtual {v1, v0}, Lpw0/d;->a(Ljava/lang/String;)Lqw0/b;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    if-eqz v0, :cond_d

    .line 123
    .line 124
    sget v1, Lqw0/f;->a:I

    .line 125
    .line 126
    invoke-virtual {v0}, Lqw0/b;->length()I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    const-string v14, ": too large for Long type"

    .line 131
    .line 132
    const-string v15, "Invalid number "

    .line 133
    .line 134
    const-wide/16 v16, 0x0

    .line 135
    .line 136
    const/16 v12, 0x13

    .line 137
    .line 138
    if-gt v1, v12, :cond_c

    .line 139
    .line 140
    const-wide/16 v18, 0x9

    .line 141
    .line 142
    const-wide/16 v20, 0x30

    .line 143
    .line 144
    const/4 v13, 0x0

    .line 145
    if-ne v1, v12, :cond_a

    .line 146
    .line 147
    invoke-virtual {v0}, Lqw0/b;->length()I

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    move-wide/from16 v22, v16

    .line 152
    .line 153
    :goto_2
    if-ge v13, v1, :cond_8

    .line 154
    .line 155
    invoke-virtual {v0, v13}, Lqw0/b;->charAt(I)C

    .line 156
    .line 157
    .line 158
    move-result v12

    .line 159
    move/from16 v24, v9

    .line 160
    .line 161
    int-to-long v8, v12

    .line 162
    sub-long v8, v8, v20

    .line 163
    .line 164
    cmp-long v12, v8, v16

    .line 165
    .line 166
    if-ltz v12, :cond_7

    .line 167
    .line 168
    cmp-long v12, v8, v18

    .line 169
    .line 170
    if-gtz v12, :cond_7

    .line 171
    .line 172
    shl-long v25, v22, v24

    .line 173
    .line 174
    shl-long v22, v22, v10

    .line 175
    .line 176
    add-long v25, v25, v22

    .line 177
    .line 178
    add-long v22, v25, v8

    .line 179
    .line 180
    cmp-long v8, v22, v16

    .line 181
    .line 182
    if-ltz v8, :cond_6

    .line 183
    .line 184
    add-int/lit8 v13, v13, 0x1

    .line 185
    .line 186
    move/from16 v9, v24

    .line 187
    .line 188
    const/4 v8, 0x4

    .line 189
    goto :goto_2

    .line 190
    :cond_6
    new-instance v1, Ljava/lang/NumberFormatException;

    .line 191
    .line 192
    new-instance v2, Ljava/lang/StringBuilder;

    .line 193
    .line 194
    invoke-direct {v2, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    invoke-direct {v1, v0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    throw v1

    .line 211
    :cond_7
    invoke-static {v0, v13}, Lqw0/f;->b(Lqw0/b;I)V

    .line 212
    .line 213
    .line 214
    throw v11

    .line 215
    :cond_8
    move/from16 v24, v9

    .line 216
    .line 217
    :cond_9
    move-wide/from16 v0, v22

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_a
    move/from16 v24, v9

    .line 221
    .line 222
    move-wide/from16 v22, v16

    .line 223
    .line 224
    :goto_3
    if-ge v13, v1, :cond_9

    .line 225
    .line 226
    invoke-virtual {v0, v13}, Lqw0/b;->charAt(I)C

    .line 227
    .line 228
    .line 229
    move-result v8

    .line 230
    int-to-long v8, v8

    .line 231
    sub-long v8, v8, v20

    .line 232
    .line 233
    cmp-long v12, v8, v16

    .line 234
    .line 235
    if-ltz v12, :cond_b

    .line 236
    .line 237
    cmp-long v12, v8, v18

    .line 238
    .line 239
    if-gtz v12, :cond_b

    .line 240
    .line 241
    shl-long v14, v22, v24

    .line 242
    .line 243
    shl-long v22, v22, v10

    .line 244
    .line 245
    add-long v14, v14, v22

    .line 246
    .line 247
    add-long v22, v14, v8

    .line 248
    .line 249
    add-int/lit8 v13, v13, 0x1

    .line 250
    .line 251
    goto :goto_3

    .line 252
    :cond_b
    invoke-static {v0, v13}, Lqw0/f;->b(Lqw0/b;I)V

    .line 253
    .line 254
    .line 255
    throw v11

    .line 256
    :goto_4
    new-instance v8, Ljava/lang/Long;

    .line 257
    .line 258
    invoke-direct {v8, v0, v1}, Ljava/lang/Long;-><init>(J)V

    .line 259
    .line 260
    .line 261
    goto :goto_5

    .line 262
    :cond_c
    new-instance v1, Ljava/lang/NumberFormatException;

    .line 263
    .line 264
    new-instance v2, Ljava/lang/StringBuilder;

    .line 265
    .line 266
    invoke-direct {v2, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    invoke-direct {v1, v0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw v1

    .line 283
    :cond_d
    move/from16 v24, v9

    .line 284
    .line 285
    const-wide/16 v16, 0x0

    .line 286
    .line 287
    move-object v8, v11

    .line 288
    :goto_5
    if-nez v8, :cond_f

    .line 289
    .line 290
    iput-object v11, v6, Lpw0/j;->d:Loz0/a;

    .line 291
    .line 292
    iput-object v11, v6, Lpw0/j;->e:Lio/ktor/utils/io/o0;

    .line 293
    .line 294
    iput-object v3, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 295
    .line 296
    iput-wide v4, v6, Lpw0/j;->g:J

    .line 297
    .line 298
    iput v10, v6, Lpw0/j;->j:I

    .line 299
    .line 300
    new-instance v0, Lio/ktor/utils/io/q;

    .line 301
    .line 302
    move-object/from16 v2, p0

    .line 303
    .line 304
    move-object/from16 v1, p1

    .line 305
    .line 306
    invoke-direct/range {v0 .. v5}, Lio/ktor/utils/io/q;-><init>(Lio/ktor/utils/io/t;Loz0/a;Lio/ktor/utils/io/d0;J)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v0, v10, v6}, Lio/ktor/utils/io/q;->d(ZLrx0/c;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    if-ne v0, v7, :cond_e

    .line 314
    .line 315
    goto/16 :goto_a

    .line 316
    .line 317
    :cond_e
    move-wide v1, v4

    .line 318
    :goto_6
    check-cast v0, Ljava/lang/Number;

    .line 319
    .line 320
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 321
    .line 322
    .line 323
    move-result-wide v4

    .line 324
    move-wide/from16 v27, v4

    .line 325
    .line 326
    move-object v5, v3

    .line 327
    move-wide v3, v1

    .line 328
    move-wide/from16 v1, v27

    .line 329
    .line 330
    goto :goto_9

    .line 331
    :cond_f
    move-object/from16 v1, p1

    .line 332
    .line 333
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 334
    .line 335
    .line 336
    move-result-wide v9

    .line 337
    cmp-long v0, v16, v9

    .line 338
    .line 339
    if-gtz v0, :cond_13

    .line 340
    .line 341
    cmp-long v0, v9, v4

    .line 342
    .line 343
    if-gtz v0, :cond_13

    .line 344
    .line 345
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 346
    .line 347
    .line 348
    move-result-wide v8

    .line 349
    move-object/from16 v0, p0

    .line 350
    .line 351
    iput-object v0, v6, Lpw0/j;->d:Loz0/a;

    .line 352
    .line 353
    iput-object v1, v6, Lpw0/j;->e:Lio/ktor/utils/io/o0;

    .line 354
    .line 355
    iput-object v3, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 356
    .line 357
    iput-wide v4, v6, Lpw0/j;->g:J

    .line 358
    .line 359
    iput v2, v6, Lpw0/j;->j:I

    .line 360
    .line 361
    invoke-static {v1, v3, v8, v9, v6}, Lio/ktor/utils/io/h0;->c(Lio/ktor/utils/io/t;Lio/ktor/utils/io/d0;JLrx0/c;)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v2

    .line 365
    if-ne v2, v7, :cond_10

    .line 366
    .line 367
    goto :goto_a

    .line 368
    :cond_10
    :goto_7
    check-cast v2, Ljava/lang/Number;

    .line 369
    .line 370
    invoke-virtual {v2}, Ljava/lang/Number;->longValue()J

    .line 371
    .line 372
    .line 373
    move-result-wide v8

    .line 374
    iput-object v11, v6, Lpw0/j;->d:Loz0/a;

    .line 375
    .line 376
    iput-object v11, v6, Lpw0/j;->e:Lio/ktor/utils/io/o0;

    .line 377
    .line 378
    iput-object v3, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 379
    .line 380
    iput-wide v4, v6, Lpw0/j;->g:J

    .line 381
    .line 382
    iput-wide v8, v6, Lpw0/j;->h:J

    .line 383
    .line 384
    move/from16 v2, v24

    .line 385
    .line 386
    iput v2, v6, Lpw0/j;->j:I

    .line 387
    .line 388
    invoke-static {v1, v0, v6}, Lpw0/m;->d(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v0

    .line 392
    if-ne v0, v7, :cond_11

    .line 393
    .line 394
    goto :goto_a

    .line 395
    :cond_11
    move-wide v1, v4

    .line 396
    move-object v5, v3

    .line 397
    move-wide v3, v1

    .line 398
    move-wide v1, v8

    .line 399
    :goto_8
    check-cast v0, Ljava/lang/Number;

    .line 400
    .line 401
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    .line 402
    .line 403
    .line 404
    move-result-wide v8

    .line 405
    add-long/2addr v8, v1

    .line 406
    move-wide v1, v8

    .line 407
    :goto_9
    iput-object v11, v6, Lpw0/j;->d:Loz0/a;

    .line 408
    .line 409
    iput-object v11, v6, Lpw0/j;->e:Lio/ktor/utils/io/o0;

    .line 410
    .line 411
    iput-object v11, v6, Lpw0/j;->f:Lio/ktor/utils/io/d0;

    .line 412
    .line 413
    iput-wide v3, v6, Lpw0/j;->g:J

    .line 414
    .line 415
    iput-wide v1, v6, Lpw0/j;->h:J

    .line 416
    .line 417
    const/4 v0, 0x4

    .line 418
    iput v0, v6, Lpw0/j;->j:I

    .line 419
    .line 420
    check-cast v5, Lio/ktor/utils/io/m;

    .line 421
    .line 422
    invoke-virtual {v5, v6}, Lio/ktor/utils/io/m;->b(Lrx0/c;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    if-ne v0, v7, :cond_12

    .line 427
    .line 428
    :goto_a
    return-object v7

    .line 429
    :cond_12
    :goto_b
    new-instance v0, Ljava/lang/Long;

    .line 430
    .line 431
    invoke-direct {v0, v1, v2}, Ljava/lang/Long;-><init>(J)V

    .line 432
    .line 433
    .line 434
    return-object v0

    .line 435
    :cond_13
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 436
    .line 437
    .line 438
    move-result-wide v0

    .line 439
    new-instance v2, Ljava/io/IOException;

    .line 440
    .line 441
    const-string v3, "Multipart content length exceeds limit "

    .line 442
    .line 443
    const-string v6, " > "

    .line 444
    .line 445
    invoke-static {v0, v1, v3, v6}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 446
    .line 447
    .line 448
    move-result-object v0

    .line 449
    const-string v1, "; limit is defined using \'formFieldLimit\' argument"

    .line 450
    .line 451
    invoke-static {v4, v5, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v0

    .line 455
    invoke-direct {v2, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 456
    .line 457
    .line 458
    throw v2
.end method

.method public static final b(Lio/ktor/utils/io/o0;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lpw0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lpw0/k;

    .line 7
    .line 8
    iget v1, v0, Lpw0/k;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lpw0/k;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpw0/k;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lpw0/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpw0/k;->f:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget-object p0, v0, Lpw0/k;->d:Lqw0/c;

    .line 38
    .line 39
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    .line 42
    goto :goto_1

    .line 43
    :catchall_0
    move-exception p1

    .line 44
    goto :goto_3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    new-instance p1, Lqw0/c;

    .line 57
    .line 58
    invoke-direct {p1}, Lqw0/c;-><init>()V

    .line 59
    .line 60
    .line 61
    :try_start_1
    iput-object p1, v0, Lpw0/k;->d:Lqw0/c;

    .line 62
    .line 63
    iput v4, v0, Lpw0/k;->f:I

    .line 64
    .line 65
    sget-object v2, Lpw0/g;->a:Ljava/util/Set;

    .line 66
    .line 67
    new-instance v2, Lb8/i;

    .line 68
    .line 69
    const/4 v5, 0x6

    .line 70
    invoke-direct {v2, v5}, Lb8/i;-><init>(I)V

    .line 71
    .line 72
    .line 73
    iput v3, v2, Lb8/i;->b:I

    .line 74
    .line 75
    iput v3, v2, Lb8/i;->c:I

    .line 76
    .line 77
    invoke-static {p0, p1, v2, v0}, Lpw0/g;->c(Lio/ktor/utils/io/t;Lqw0/c;Lb8/i;Lrx0/c;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 81
    if-ne p0, v1, :cond_3

    .line 82
    .line 83
    return-object v1

    .line 84
    :cond_3
    move-object v8, p1

    .line 85
    move-object p1, p0

    .line 86
    move-object p0, v8

    .line 87
    :goto_1
    :try_start_2
    check-cast p1, Lpw0/d;

    .line 88
    .line 89
    if-eqz p1, :cond_4

    .line 90
    .line 91
    return-object p1

    .line 92
    :cond_4
    new-instance p1, Ljava/io/EOFException;

    .line 93
    .line 94
    const-string v0, "Failed to parse multipart headers: unexpected end of stream"

    .line 95
    .line 96
    invoke-direct {p1, v0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 100
    :goto_2
    move-object v8, p1

    .line 101
    move-object p1, p0

    .line 102
    move-object p0, v8

    .line 103
    goto :goto_3

    .line 104
    :catchall_1
    move-exception p0

    .line 105
    goto :goto_2

    .line 106
    :goto_3
    iget-object v0, p0, Lqw0/c;->d:Ldx0/d;

    .line 107
    .line 108
    iget-object v1, p0, Lqw0/c;->e:Ljava/util/ArrayList;

    .line 109
    .line 110
    const/4 v2, 0x0

    .line 111
    if-eqz v1, :cond_5

    .line 112
    .line 113
    iput-object v2, p0, Lqw0/c;->f:[C

    .line 114
    .line 115
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    move v6, v3

    .line 120
    :goto_4
    if-ge v6, v5, :cond_7

    .line 121
    .line 122
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v7

    .line 126
    invoke-interface {v0, v7}, Ldx0/d;->o0(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    add-int/lit8 v6, v6, 0x1

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_5
    iget-object v1, p0, Lqw0/c;->f:[C

    .line 133
    .line 134
    if-eqz v1, :cond_6

    .line 135
    .line 136
    invoke-interface {v0, v1}, Ldx0/d;->o0(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    :cond_6
    iput-object v2, p0, Lqw0/c;->f:[C

    .line 140
    .line 141
    :cond_7
    iput-boolean v4, p0, Lqw0/c;->h:Z

    .line 142
    .line 143
    iput-object v2, p0, Lqw0/c;->e:Ljava/util/ArrayList;

    .line 144
    .line 145
    iput-object v2, p0, Lqw0/c;->g:Ljava/lang/String;

    .line 146
    .line 147
    iput v3, p0, Lqw0/c;->j:I

    .line 148
    .line 149
    iput v3, p0, Lqw0/c;->i:I

    .line 150
    .line 151
    throw p1
.end method

.method public static final c(Lkotlin/jvm/internal/d0;[BB)V
    .locals 2

    .line 1
    iget v0, p0, Lkotlin/jvm/internal/d0;->d:I

    .line 2
    .line 3
    array-length v1, p1

    .line 4
    if-ge v0, v1, :cond_0

    .line 5
    .line 6
    add-int/lit8 v1, v0, 0x1

    .line 7
    .line 8
    iput v1, p0, Lkotlin/jvm/internal/d0;->d:I

    .line 9
    .line 10
    aput-byte p2, p1, v0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 14
    .line 15
    const-string p1, "Failed to parse multipart: boundary shouldn\'t be longer than 70 characters"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public static final d(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lpw0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lpw0/l;

    .line 7
    .line 8
    iget v1, v0, Lpw0/l;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lpw0/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpw0/l;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lpw0/l;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpw0/l;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lpw0/l;->d:Loz0/a;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lpw0/l;->d:Loz0/a;

    .line 54
    .line 55
    iput v3, v0, Lpw0/l;->f:I

    .line 56
    .line 57
    invoke-static {p0, p1, v0}, Lio/ktor/utils/io/h0;->l(Lio/ktor/utils/io/t;Loz0/a;Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    if-ne p2, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 65
    .line 66
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-eqz p0, :cond_4

    .line 71
    .line 72
    iget-object p0, p1, Loz0/a;->d:[B

    .line 73
    .line 74
    array-length p0, p0

    .line 75
    int-to-long p0, p0

    .line 76
    goto :goto_2

    .line 77
    :cond_4
    const-wide/16 p0, 0x0

    .line 78
    .line 79
    :goto_2
    new-instance p2, Ljava/lang/Long;

    .line 80
    .line 81
    invoke-direct {p2, p0, p1}, Ljava/lang/Long;-><init>(J)V

    .line 82
    .line 83
    .line 84
    return-object p2
.end method
