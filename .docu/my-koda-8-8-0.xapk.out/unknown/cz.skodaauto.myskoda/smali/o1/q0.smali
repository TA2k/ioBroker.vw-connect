.class public abstract Lo1/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x9c4

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lo1/q0;->a:F

    .line 5
    .line 6
    const/16 v0, 0x5dc

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Lo1/q0;->b:F

    .line 10
    .line 11
    const/16 v0, 0x32

    .line 12
    .line 13
    int-to-float v0, v0

    .line 14
    sput v0, Lo1/q0;->c:F

    .line 15
    .line 16
    return-void
.end method

.method public static final a(Lm1/p;IIILt4/c;Lrx0/c;)Ljava/lang/Object;
    .locals 28

    .line 1
    move/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v0, p4

    .line 4
    .line 5
    move-object/from16 v2, p5

    .line 6
    .line 7
    instance-of v3, v2, Lo1/p0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lo1/p0;

    .line 13
    .line 14
    iget v4, v3, Lo1/p0;->p:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lo1/p0;->p:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lo1/p0;

    .line 27
    .line 28
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lo1/p0;->o:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lo1/p0;->p:I

    .line 36
    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x2

    .line 39
    const/4 v10, 0x1

    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    if-eq v5, v10, :cond_2

    .line 43
    .line 44
    if-ne v5, v8, :cond_1

    .line 45
    .line 46
    iget v0, v3, Lo1/p0;->i:I

    .line 47
    .line 48
    iget v1, v3, Lo1/p0;->h:I

    .line 49
    .line 50
    iget-object v3, v3, Lo1/p0;->d:Lm1/p;

    .line 51
    .line 52
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto/16 :goto_10

    .line 56
    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    iget v0, v3, Lo1/p0;->k:I

    .line 66
    .line 67
    iget v1, v3, Lo1/p0;->n:F

    .line 68
    .line 69
    iget v5, v3, Lo1/p0;->m:F

    .line 70
    .line 71
    iget v11, v3, Lo1/p0;->l:F

    .line 72
    .line 73
    iget v12, v3, Lo1/p0;->j:I

    .line 74
    .line 75
    iget v13, v3, Lo1/p0;->i:I

    .line 76
    .line 77
    iget v14, v3, Lo1/p0;->h:I

    .line 78
    .line 79
    iget-object v15, v3, Lo1/p0;->g:Lkotlin/jvm/internal/d0;

    .line 80
    .line 81
    iget-object v9, v3, Lo1/p0;->f:Lkotlin/jvm/internal/f0;

    .line 82
    .line 83
    iget-object v8, v3, Lo1/p0;->e:Lkotlin/jvm/internal/b0;

    .line 84
    .line 85
    iget-object v6, v3, Lo1/p0;->d:Lm1/p;

    .line 86
    .line 87
    :try_start_0
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lo1/i; {:try_start_0 .. :try_end_0} :catch_0

    .line 88
    .line 89
    .line 90
    move/from16 v25, v5

    .line 91
    .line 92
    move-object v2, v6

    .line 93
    move/from16 v26, v13

    .line 94
    .line 95
    move-object v5, v3

    .line 96
    move v3, v1

    .line 97
    move v1, v10

    .line 98
    move v10, v12

    .line 99
    :goto_1
    move-object v6, v8

    .line 100
    move-object v8, v9

    .line 101
    goto/16 :goto_a

    .line 102
    .line 103
    :catch_0
    move-exception v0

    .line 104
    move-object v2, v6

    .line 105
    move v7, v13

    .line 106
    move v6, v14

    .line 107
    :goto_2
    move-object v13, v3

    .line 108
    goto/16 :goto_c

    .line 109
    .line 110
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    int-to-float v2, v1

    .line 114
    cmpl-float v2, v2, v7

    .line 115
    .line 116
    if-ltz v2, :cond_4

    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_4
    const-string v2, "Index should be non-negative"

    .line 120
    .line 121
    invoke-static {v2}, Lj1/b;->a(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    :goto_3
    :try_start_1
    sget v2, Lo1/q0;->a:F

    .line 125
    .line 126
    invoke-interface {v0, v2}, Lt4/c;->w0(F)F

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    sget v5, Lo1/q0;->b:F

    .line 131
    .line 132
    invoke-interface {v0, v5}, Lt4/c;->w0(F)F

    .line 133
    .line 134
    .line 135
    move-result v5

    .line 136
    sget v6, Lo1/q0;->c:F

    .line 137
    .line 138
    invoke-interface {v0, v6}, Lt4/c;->w0(F)F

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    new-instance v6, Lkotlin/jvm/internal/b0;

    .line 143
    .line 144
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 145
    .line 146
    .line 147
    iput-boolean v10, v6, Lkotlin/jvm/internal/b0;->d:Z

    .line 148
    .line 149
    new-instance v8, Lkotlin/jvm/internal/f0;

    .line 150
    .line 151
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 152
    .line 153
    .line 154
    const/16 v9, 0x1e

    .line 155
    .line 156
    invoke-static {v7, v7, v9}, Lc1/d;->b(FFI)Lc1/k;

    .line 157
    .line 158
    .line 159
    move-result-object v11

    .line 160
    iput-object v11, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 161
    .line 162
    invoke-static/range {p0 .. p1}, Lo1/q0;->c(Lm1/p;I)Z

    .line 163
    .line 164
    .line 165
    move-result v9

    .line 166
    if-nez v9, :cond_c

    .line 167
    .line 168
    invoke-virtual/range {p0 .. p0}, Lm1/p;->c()I

    .line 169
    .line 170
    .line 171
    move-result v9

    .line 172
    if-le v1, v9, :cond_5

    .line 173
    .line 174
    move v9, v10

    .line 175
    goto :goto_4

    .line 176
    :cond_5
    const/4 v9, 0x0

    .line 177
    :goto_4
    new-instance v11, Lkotlin/jvm/internal/d0;

    .line 178
    .line 179
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 180
    .line 181
    .line 182
    iput v10, v11, Lkotlin/jvm/internal/d0;->d:I
    :try_end_1
    .catch Lo1/i; {:try_start_1 .. :try_end_1} :catch_7

    .line 183
    .line 184
    move/from16 v26, p2

    .line 185
    .line 186
    move/from16 v25, p3

    .line 187
    .line 188
    move/from16 v23, v5

    .line 189
    .line 190
    move-object/from16 v24, v11

    .line 191
    .line 192
    move v11, v2

    .line 193
    move-object v5, v3

    .line 194
    move v3, v0

    .line 195
    move v2, v1

    .line 196
    move v0, v9

    .line 197
    move-object/from16 v1, p0

    .line 198
    .line 199
    :goto_5
    :try_start_2
    iget-boolean v9, v6, Lkotlin/jvm/internal/b0;->d:Z

    .line 200
    .line 201
    if-eqz v9, :cond_f

    .line 202
    .line 203
    iget v9, v1, Lm1/p;->a:I

    .line 204
    .line 205
    packed-switch v9, :pswitch_data_0

    .line 206
    .line 207
    .line 208
    iget-object v9, v1, Lm1/p;->c:Lg1/q2;

    .line 209
    .line 210
    check-cast v9, Lp1/v;

    .line 211
    .line 212
    invoke-virtual {v9}, Lp1/v;->m()I

    .line 213
    .line 214
    .line 215
    move-result v9

    .line 216
    goto :goto_6

    .line 217
    :pswitch_0
    iget-object v9, v1, Lm1/p;->c:Lg1/q2;

    .line 218
    .line 219
    check-cast v9, Lm1/t;

    .line 220
    .line 221
    invoke-virtual {v9}, Lm1/t;->h()Lm1/l;

    .line 222
    .line 223
    .line 224
    move-result-object v9

    .line 225
    iget v9, v9, Lm1/l;->n:I

    .line 226
    .line 227
    :goto_6
    if-lez v9, :cond_f

    .line 228
    .line 229
    invoke-virtual {v1, v2}, Lm1/p;->b(I)I

    .line 230
    .line 231
    .line 232
    move-result v9

    .line 233
    add-int v9, v9, v26

    .line 234
    .line 235
    invoke-static {v9}, Ljava/lang/Math;->abs(I)I

    .line 236
    .line 237
    .line 238
    move-result v12
    :try_end_2
    .catch Lo1/i; {:try_start_2 .. :try_end_2} :catch_6

    .line 239
    int-to-float v12, v12

    .line 240
    cmpg-float v12, v12, v11

    .line 241
    .line 242
    if-gez v12, :cond_7

    .line 243
    .line 244
    int-to-float v9, v9

    .line 245
    :try_start_3
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 246
    .line 247
    .line 248
    move-result v9

    .line 249
    invoke-static {v9, v3}, Ljava/lang/Math;->max(FF)F

    .line 250
    .line 251
    .line 252
    move-result v9
    :try_end_3
    .catch Lo1/i; {:try_start_3 .. :try_end_3} :catch_1

    .line 253
    if-eqz v0, :cond_6

    .line 254
    .line 255
    goto :goto_7

    .line 256
    :cond_6
    neg-float v9, v9

    .line 257
    goto :goto_7

    .line 258
    :catch_1
    move-exception v0

    .line 259
    move v6, v2

    .line 260
    move-object v13, v5

    .line 261
    move/from16 v7, v26

    .line 262
    .line 263
    move-object v2, v1

    .line 264
    goto/16 :goto_c

    .line 265
    .line 266
    :cond_7
    if-eqz v0, :cond_8

    .line 267
    .line 268
    move v9, v11

    .line 269
    goto :goto_7

    .line 270
    :cond_8
    neg-float v9, v11

    .line 271
    :goto_7
    :try_start_4
    iget-object v12, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 272
    .line 273
    check-cast v12, Lc1/k;

    .line 274
    .line 275
    const/16 v13, 0x1e

    .line 276
    .line 277
    invoke-static {v12, v7, v7, v13}, Lc1/d;->m(Lc1/k;FFI)Lc1/k;

    .line 278
    .line 279
    .line 280
    move-result-object v12

    .line 281
    iput-object v12, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 282
    .line 283
    new-instance v20, Lkotlin/jvm/internal/c0;

    .line 284
    .line 285
    invoke-direct/range {v20 .. v20}, Ljava/lang/Object;-><init>()V

    .line 286
    .line 287
    .line 288
    new-instance v13, Ljava/lang/Float;

    .line 289
    .line 290
    invoke-direct {v13, v9}, Ljava/lang/Float;-><init>(F)V

    .line 291
    .line 292
    .line 293
    iget-object v14, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v14, Lc1/k;

    .line 296
    .line 297
    invoke-virtual {v14}, Lc1/k;->a()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v14

    .line 301
    check-cast v14, Ljava/lang/Number;

    .line 302
    .line 303
    invoke-virtual {v14}, Ljava/lang/Number;->floatValue()F

    .line 304
    .line 305
    .line 306
    move-result v14

    .line 307
    cmpg-float v14, v14, v7

    .line 308
    .line 309
    if-nez v14, :cond_9

    .line 310
    .line 311
    move v14, v10

    .line 312
    goto :goto_8

    .line 313
    :cond_9
    const/4 v14, 0x0

    .line 314
    :goto_8
    xor-int/2addr v14, v10

    .line 315
    if-eqz v0, :cond_a

    .line 316
    .line 317
    move/from16 v22, v10

    .line 318
    .line 319
    goto :goto_9

    .line 320
    :cond_a
    const/16 v22, 0x0

    .line 321
    .line 322
    :goto_9
    new-instance v16, Lo1/o0;
    :try_end_4
    .catch Lo1/i; {:try_start_4 .. :try_end_4} :catch_6

    .line 323
    .line 324
    move-object/from16 v17, v1

    .line 325
    .line 326
    move/from16 v18, v2

    .line 327
    .line 328
    move-object/from16 v21, v6

    .line 329
    .line 330
    move-object/from16 v27, v8

    .line 331
    .line 332
    move/from16 v19, v9

    .line 333
    .line 334
    :try_start_5
    invoke-direct/range {v16 .. v27}, Lo1/o0;-><init>(Lm1/p;IFLkotlin/jvm/internal/c0;Lkotlin/jvm/internal/b0;ZFLkotlin/jvm/internal/d0;IILkotlin/jvm/internal/f0;)V
    :try_end_5
    .catch Lo1/i; {:try_start_5 .. :try_end_5} :catch_5

    .line 335
    .line 336
    .line 337
    move-object/from16 v2, v17

    .line 338
    .line 339
    move/from16 v6, v18

    .line 340
    .line 341
    move-object/from16 v8, v21

    .line 342
    .line 343
    move/from16 v1, v23

    .line 344
    .line 345
    move-object/from16 v15, v24

    .line 346
    .line 347
    move/from16 v10, v25

    .line 348
    .line 349
    move/from16 v7, v26

    .line 350
    .line 351
    move-object/from16 v9, v27

    .line 352
    .line 353
    :try_start_6
    iput-object v2, v5, Lo1/p0;->d:Lm1/p;

    .line 354
    .line 355
    iput-object v8, v5, Lo1/p0;->e:Lkotlin/jvm/internal/b0;

    .line 356
    .line 357
    iput-object v9, v5, Lo1/p0;->f:Lkotlin/jvm/internal/f0;

    .line 358
    .line 359
    iput-object v15, v5, Lo1/p0;->g:Lkotlin/jvm/internal/d0;

    .line 360
    .line 361
    iput v6, v5, Lo1/p0;->h:I

    .line 362
    .line 363
    iput v7, v5, Lo1/p0;->i:I

    .line 364
    .line 365
    iput v10, v5, Lo1/p0;->j:I

    .line 366
    .line 367
    iput v11, v5, Lo1/p0;->l:F

    .line 368
    .line 369
    iput v1, v5, Lo1/p0;->m:F

    .line 370
    .line 371
    iput v3, v5, Lo1/p0;->n:F

    .line 372
    .line 373
    iput v0, v5, Lo1/p0;->k:I

    .line 374
    .line 375
    move/from16 v25, v1

    .line 376
    .line 377
    const/4 v1, 0x1

    .line 378
    iput v1, v5, Lo1/p0;->p:I
    :try_end_6
    .catch Lo1/i; {:try_start_6 .. :try_end_6} :catch_4

    .line 379
    .line 380
    const/16 v18, 0x0

    .line 381
    .line 382
    const/16 v22, 0x2

    .line 383
    .line 384
    move-object/from16 v21, v5

    .line 385
    .line 386
    move-object/from16 v17, v13

    .line 387
    .line 388
    move/from16 v19, v14

    .line 389
    .line 390
    move-object/from16 v20, v16

    .line 391
    .line 392
    move-object/from16 v16, v12

    .line 393
    .line 394
    :try_start_7
    invoke-static/range {v16 .. v22}, Lc1/d;->i(Lc1/k;Ljava/lang/Float;Lc1/f1;ZLay0/k;Lrx0/c;I)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v5
    :try_end_7
    .catch Lo1/i; {:try_start_7 .. :try_end_7} :catch_3

    .line 398
    if-ne v5, v4, :cond_b

    .line 399
    .line 400
    goto/16 :goto_f

    .line 401
    .line 402
    :cond_b
    move v14, v6

    .line 403
    move/from16 v26, v7

    .line 404
    .line 405
    move-object/from16 v5, v21

    .line 406
    .line 407
    goto/16 :goto_1

    .line 408
    .line 409
    :goto_a
    :try_start_8
    iget v7, v15, Lkotlin/jvm/internal/d0;->d:I

    .line 410
    .line 411
    add-int/2addr v7, v1

    .line 412
    iput v7, v15, Lkotlin/jvm/internal/d0;->d:I
    :try_end_8
    .catch Lo1/i; {:try_start_8 .. :try_end_8} :catch_2

    .line 413
    .line 414
    move-object v1, v2

    .line 415
    move v2, v14

    .line 416
    move-object/from16 v24, v15

    .line 417
    .line 418
    move/from16 v23, v25

    .line 419
    .line 420
    const/4 v7, 0x0

    .line 421
    move/from16 v25, v10

    .line 422
    .line 423
    const/4 v10, 0x1

    .line 424
    goto/16 :goto_5

    .line 425
    .line 426
    :catch_2
    move-exception v0

    .line 427
    move-object v13, v5

    .line 428
    move v6, v14

    .line 429
    move/from16 v7, v26

    .line 430
    .line 431
    goto :goto_c

    .line 432
    :catch_3
    move-exception v0

    .line 433
    :goto_b
    move-object/from16 v13, v21

    .line 434
    .line 435
    goto :goto_c

    .line 436
    :catch_4
    move-exception v0

    .line 437
    move-object/from16 v21, v5

    .line 438
    .line 439
    goto :goto_b

    .line 440
    :catch_5
    move-exception v0

    .line 441
    move-object/from16 v21, v5

    .line 442
    .line 443
    move-object/from16 v2, v17

    .line 444
    .line 445
    move/from16 v6, v18

    .line 446
    .line 447
    move/from16 v7, v26

    .line 448
    .line 449
    goto :goto_b

    .line 450
    :catch_6
    move-exception v0

    .line 451
    move v6, v2

    .line 452
    move-object/from16 v21, v5

    .line 453
    .line 454
    move/from16 v7, v26

    .line 455
    .line 456
    move-object v2, v1

    .line 457
    goto :goto_b

    .line 458
    :catch_7
    move-exception v0

    .line 459
    move-object/from16 v2, p0

    .line 460
    .line 461
    move/from16 v7, p2

    .line 462
    .line 463
    move v6, v1

    .line 464
    goto/16 :goto_2

    .line 465
    .line 466
    :cond_c
    :try_start_9
    invoke-virtual/range {p0 .. p1}, Lm1/p;->b(I)I

    .line 467
    .line 468
    .line 469
    move-result v0

    .line 470
    new-instance v2, Lo1/i;

    .line 471
    .line 472
    iget-object v5, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 473
    .line 474
    check-cast v5, Lc1/k;

    .line 475
    .line 476
    invoke-direct {v2, v0, v5}, Lo1/i;-><init>(ILc1/k;)V

    .line 477
    .line 478
    .line 479
    throw v2
    :try_end_9
    .catch Lo1/i; {:try_start_9 .. :try_end_9} :catch_7

    .line 480
    :goto_c
    iget-object v1, v0, Lo1/i;->e:Lc1/k;

    .line 481
    .line 482
    const/4 v3, 0x0

    .line 483
    const/16 v9, 0x1e

    .line 484
    .line 485
    invoke-static {v1, v3, v3, v9}, Lc1/d;->m(Lc1/k;FFI)Lc1/k;

    .line 486
    .line 487
    .line 488
    move-result-object v8

    .line 489
    iget v0, v0, Lo1/i;->d:I

    .line 490
    .line 491
    add-int/2addr v0, v7

    .line 492
    int-to-float v0, v0

    .line 493
    new-instance v1, Lkotlin/jvm/internal/c0;

    .line 494
    .line 495
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 496
    .line 497
    .line 498
    new-instance v9, Ljava/lang/Float;

    .line 499
    .line 500
    invoke-direct {v9, v0}, Ljava/lang/Float;-><init>(F)V

    .line 501
    .line 502
    .line 503
    invoke-virtual {v8}, Lc1/k;->a()Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v5

    .line 507
    check-cast v5, Ljava/lang/Number;

    .line 508
    .line 509
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 510
    .line 511
    .line 512
    move-result v5

    .line 513
    cmpg-float v3, v5, v3

    .line 514
    .line 515
    if-nez v3, :cond_d

    .line 516
    .line 517
    const/16 v24, 0x1

    .line 518
    .line 519
    :goto_d
    const/4 v3, 0x1

    .line 520
    goto :goto_e

    .line 521
    :cond_d
    const/16 v24, 0x0

    .line 522
    .line 523
    goto :goto_d

    .line 524
    :goto_e
    xor-int/lit8 v11, v24, 0x1

    .line 525
    .line 526
    new-instance v12, Lg1/j3;

    .line 527
    .line 528
    const/4 v3, 0x2

    .line 529
    invoke-direct {v12, v0, v1, v2, v3}, Lg1/j3;-><init>(FLjava/lang/Object;Ljava/lang/Object;I)V

    .line 530
    .line 531
    .line 532
    iput-object v2, v13, Lo1/p0;->d:Lm1/p;

    .line 533
    .line 534
    const/4 v0, 0x0

    .line 535
    iput-object v0, v13, Lo1/p0;->e:Lkotlin/jvm/internal/b0;

    .line 536
    .line 537
    iput-object v0, v13, Lo1/p0;->f:Lkotlin/jvm/internal/f0;

    .line 538
    .line 539
    iput-object v0, v13, Lo1/p0;->g:Lkotlin/jvm/internal/d0;

    .line 540
    .line 541
    iput v6, v13, Lo1/p0;->h:I

    .line 542
    .line 543
    iput v7, v13, Lo1/p0;->i:I

    .line 544
    .line 545
    const/4 v1, 0x2

    .line 546
    iput v1, v13, Lo1/p0;->p:I

    .line 547
    .line 548
    const/4 v10, 0x0

    .line 549
    const/4 v14, 0x2

    .line 550
    invoke-static/range {v8 .. v14}, Lc1/d;->i(Lc1/k;Ljava/lang/Float;Lc1/f1;ZLay0/k;Lrx0/c;I)Ljava/lang/Object;

    .line 551
    .line 552
    .line 553
    move-result-object v0

    .line 554
    if-ne v0, v4, :cond_e

    .line 555
    .line 556
    :goto_f
    return-object v4

    .line 557
    :cond_e
    move-object v3, v2

    .line 558
    move v1, v6

    .line 559
    move v0, v7

    .line 560
    :goto_10
    invoke-virtual {v3, v1, v0}, Lm1/p;->f(II)V

    .line 561
    .line 562
    .line 563
    :cond_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 564
    .line 565
    return-object v0

    .line 566
    nop

    .line 567
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public static final b(ZLm1/p;II)Z
    .locals 0

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    invoke-virtual {p1}, Lm1/p;->c()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-le p0, p2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p1}, Lm1/p;->c()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-ne p0, p2, :cond_3

    .line 15
    .line 16
    invoke-virtual {p1}, Lm1/p;->d()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-le p0, p3, :cond_3

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    invoke-virtual {p1}, Lm1/p;->c()I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-ge p0, p2, :cond_2

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_2
    invoke-virtual {p1}, Lm1/p;->c()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-ne p0, p2, :cond_3

    .line 35
    .line 36
    invoke-virtual {p1}, Lm1/p;->d()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-ge p0, p3, :cond_3

    .line 41
    .line 42
    :goto_0
    const/4 p0, 0x1

    .line 43
    return p0

    .line 44
    :cond_3
    const/4 p0, 0x0

    .line 45
    return p0
.end method

.method public static final c(Lm1/p;I)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lm1/p;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lm1/p;->e()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-gt p1, p0, :cond_0

    .line 11
    .line 12
    if-gt v0, p1, :cond_0

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    return p0

    .line 16
    :cond_0
    return v1
.end method
