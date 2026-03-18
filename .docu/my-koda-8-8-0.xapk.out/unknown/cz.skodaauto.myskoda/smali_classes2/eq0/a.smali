.class public final synthetic Leq0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(IILjava/util/List;)V
    .locals 0

    .line 1
    iput p2, p0, Leq0/a;->d:I

    iput-object p3, p0, Leq0/a;->e:Ljava/util/List;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;I)V
    .locals 0

    .line 2
    iput p2, p0, Leq0/a;->d:I

    iput-object p1, p0, Leq0/a;->e:Ljava/util/List;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Leq0/a;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x0

    .line 8
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    iget-object v0, v0, Leq0/a;->e:Ljava/util/List;

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    move-object/from16 v1, p1

    .line 17
    .line 18
    check-cast v1, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v2, p2

    .line 21
    .line 22
    check-cast v2, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    invoke-static {v0, v1, v2}, Lzj0/j;->l(Ljava/util/List;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    return-object v5

    .line 35
    :pswitch_0
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Ll2/o;

    .line 38
    .line 39
    move-object/from16 v2, p2

    .line 40
    .line 41
    check-cast v2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    invoke-static {v0, v1, v2}, Lz70/s;->f(Ljava/util/List;Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    return-object v5

    .line 54
    :pswitch_1
    move-object/from16 v1, p1

    .line 55
    .line 56
    check-cast v1, Ll2/o;

    .line 57
    .line 58
    move-object/from16 v7, p2

    .line 59
    .line 60
    check-cast v7, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    and-int/lit8 v8, v7, 0x3

    .line 67
    .line 68
    if-eq v8, v2, :cond_0

    .line 69
    .line 70
    move v2, v6

    .line 71
    goto :goto_0

    .line 72
    :cond_0
    move v2, v4

    .line 73
    :goto_0
    and-int/2addr v6, v7

    .line 74
    check-cast v1, Ll2/t;

    .line 75
    .line 76
    invoke-virtual {v1, v6, v2}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-eqz v2, :cond_4

    .line 81
    .line 82
    check-cast v0, Ljava/lang/Iterable;

    .line 83
    .line 84
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    move v2, v4

    .line 89
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v6

    .line 93
    if-eqz v6, :cond_5

    .line 94
    .line 95
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    add-int/lit8 v7, v2, 0x1

    .line 100
    .line 101
    if-ltz v2, :cond_3

    .line 102
    .line 103
    check-cast v6, Ly70/m0;

    .line 104
    .line 105
    if-lez v2, :cond_1

    .line 106
    .line 107
    const v2, 0x97a7e56

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 114
    .line 115
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    check-cast v2, Lj91/c;

    .line 120
    .line 121
    iget v2, v2, Lj91/c;->c:F

    .line 122
    .line 123
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 124
    .line 125
    invoke-static {v8, v2, v1, v4}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 126
    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_1
    const v2, 0x8ed21b6

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 136
    .line 137
    .line 138
    :goto_2
    iget v2, v6, Ly70/m0;->a:I

    .line 139
    .line 140
    iget-object v8, v6, Ly70/m0;->b:Lcq0/s;

    .line 141
    .line 142
    if-nez v8, :cond_2

    .line 143
    .line 144
    const v8, 0x97d67e8

    .line 145
    .line 146
    .line 147
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 151
    .line 152
    .line 153
    move-object v10, v3

    .line 154
    goto :goto_3

    .line 155
    :cond_2
    const v9, 0x10d27f39

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1, v9}, Ll2/t;->Y(I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v8, v1}, Lz70/l;->g0(Lcq0/s;Ll2/t;)J

    .line 162
    .line 163
    .line 164
    move-result-wide v8

    .line 165
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 166
    .line 167
    .line 168
    new-instance v10, Le3/s;

    .line 169
    .line 170
    invoke-direct {v10, v8, v9}, Le3/s;-><init>(J)V

    .line 171
    .line 172
    .line 173
    :goto_3
    iget-object v6, v6, Ly70/m0;->c:Ljava/lang/String;

    .line 174
    .line 175
    invoke-static {v2, v10, v6, v1, v4}, Lz70/s;->e(ILe3/s;Ljava/lang/String;Ll2/o;I)V

    .line 176
    .line 177
    .line 178
    move v2, v7

    .line 179
    goto :goto_1

    .line 180
    :cond_3
    invoke-static {}, Ljp/k1;->r()V

    .line 181
    .line 182
    .line 183
    throw v3

    .line 184
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 185
    .line 186
    .line 187
    :cond_5
    return-object v5

    .line 188
    :pswitch_2
    move-object/from16 v1, p1

    .line 189
    .line 190
    check-cast v1, Ll2/o;

    .line 191
    .line 192
    move-object/from16 v2, p2

    .line 193
    .line 194
    check-cast v2, Ljava/lang/Integer;

    .line 195
    .line 196
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    invoke-static {v0, v1, v2}, Lxk0/h;->d(Ljava/util/List;Ll2/o;I)V

    .line 204
    .line 205
    .line 206
    return-object v5

    .line 207
    :pswitch_3
    move-object/from16 v1, p1

    .line 208
    .line 209
    check-cast v1, Ll2/o;

    .line 210
    .line 211
    move-object/from16 v2, p2

    .line 212
    .line 213
    check-cast v2, Ljava/lang/Integer;

    .line 214
    .line 215
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 219
    .line 220
    .line 221
    move-result v2

    .line 222
    invoke-static {v0, v1, v2}, Ls60/a;->J(Ljava/util/List;Ll2/o;I)V

    .line 223
    .line 224
    .line 225
    return-object v5

    .line 226
    :pswitch_4
    move-object/from16 v1, p1

    .line 227
    .line 228
    check-cast v1, Ll2/o;

    .line 229
    .line 230
    move-object/from16 v2, p2

    .line 231
    .line 232
    check-cast v2, Ljava/lang/Integer;

    .line 233
    .line 234
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 238
    .line 239
    .line 240
    move-result v2

    .line 241
    invoke-static {v0, v1, v2}, Ljp/yg;->h(Ljava/util/List;Ll2/o;I)V

    .line 242
    .line 243
    .line 244
    return-object v5

    .line 245
    :pswitch_5
    move-object/from16 v1, p1

    .line 246
    .line 247
    check-cast v1, Ll2/o;

    .line 248
    .line 249
    move-object/from16 v2, p2

    .line 250
    .line 251
    check-cast v2, Ljava/lang/Integer;

    .line 252
    .line 253
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 254
    .line 255
    .line 256
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 257
    .line 258
    .line 259
    move-result v2

    .line 260
    invoke-static {v0, v1, v2}, Ljp/wa;->c(Ljava/util/List;Ll2/o;I)V

    .line 261
    .line 262
    .line 263
    return-object v5

    .line 264
    :pswitch_6
    move-object/from16 v1, p1

    .line 265
    .line 266
    check-cast v1, Ll2/o;

    .line 267
    .line 268
    move-object/from16 v7, p2

    .line 269
    .line 270
    check-cast v7, Ljava/lang/Integer;

    .line 271
    .line 272
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 273
    .line 274
    .line 275
    move-result v7

    .line 276
    and-int/lit8 v8, v7, 0x3

    .line 277
    .line 278
    if-eq v8, v2, :cond_6

    .line 279
    .line 280
    move v8, v6

    .line 281
    goto :goto_4

    .line 282
    :cond_6
    move v8, v4

    .line 283
    :goto_4
    and-int/2addr v7, v6

    .line 284
    check-cast v1, Ll2/t;

    .line 285
    .line 286
    invoke-virtual {v1, v7, v8}, Ll2/t;->O(IZ)Z

    .line 287
    .line 288
    .line 289
    move-result v7

    .line 290
    if-eqz v7, :cond_a

    .line 291
    .line 292
    check-cast v0, Ljava/lang/Iterable;

    .line 293
    .line 294
    new-instance v9, Ljava/util/ArrayList;

    .line 295
    .line 296
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 297
    .line 298
    .line 299
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    :cond_7
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 304
    .line 305
    .line 306
    move-result v7

    .line 307
    if-eqz v7, :cond_9

    .line 308
    .line 309
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    check-cast v7, Lm70/r;

    .line 314
    .line 315
    iget-object v7, v7, Lm70/r;->c:Lxj0/f;

    .line 316
    .line 317
    if-eqz v7, :cond_8

    .line 318
    .line 319
    invoke-static {v7}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 320
    .line 321
    .line 322
    move-result-object v7

    .line 323
    goto :goto_6

    .line 324
    :cond_8
    move-object v7, v3

    .line 325
    :goto_6
    if-eqz v7, :cond_7

    .line 326
    .line 327
    invoke-virtual {v9, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    goto :goto_5

    .line 331
    :cond_9
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 332
    .line 333
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    check-cast v0, Lj91/e;

    .line 338
    .line 339
    invoke-virtual {v0}, Lj91/e;->k()J

    .line 340
    .line 341
    .line 342
    move-result-wide v10

    .line 343
    new-instance v0, Lsp/h;

    .line 344
    .line 345
    invoke-direct {v0, v4}, Lsp/h;-><init>(I)V

    .line 346
    .line 347
    .line 348
    new-instance v3, Lsp/h;

    .line 349
    .line 350
    invoke-direct {v3, v6}, Lsp/h;-><init>(I)V

    .line 351
    .line 352
    .line 353
    new-array v2, v2, [Lsp/m;

    .line 354
    .line 355
    aput-object v0, v2, v4

    .line 356
    .line 357
    aput-object v3, v2, v6

    .line 358
    .line 359
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 360
    .line 361
    .line 362
    move-result-object v13

    .line 363
    const/16 v20, 0x6

    .line 364
    .line 365
    const/16 v21, 0x1bba

    .line 366
    .line 367
    const/4 v12, 0x0

    .line 368
    const/4 v14, 0x0

    .line 369
    const/4 v15, 0x0

    .line 370
    const/high16 v16, 0x41000000    # 8.0f

    .line 371
    .line 372
    const/16 v17, 0x0

    .line 373
    .line 374
    const/16 v19, 0x0

    .line 375
    .line 376
    move-object/from16 v18, v1

    .line 377
    .line 378
    invoke-static/range {v9 .. v21}, Llp/ka;->a(Ljava/util/ArrayList;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;Ll2/o;III)V

    .line 379
    .line 380
    .line 381
    goto :goto_7

    .line 382
    :cond_a
    move-object/from16 v18, v1

    .line 383
    .line 384
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 385
    .line 386
    .line 387
    :goto_7
    return-object v5

    .line 388
    :pswitch_7
    move-object/from16 v8, p1

    .line 389
    .line 390
    check-cast v8, Ljava/lang/CharSequence;

    .line 391
    .line 392
    move-object/from16 v1, p2

    .line 393
    .line 394
    check-cast v1, Ljava/lang/Integer;

    .line 395
    .line 396
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 397
    .line 398
    .line 399
    move-result v1

    .line 400
    const-string v2, "$this$DelimitedRangesSequence"

    .line 401
    .line 402
    invoke-static {v8, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    check-cast v0, Ljava/util/Collection;

    .line 406
    .line 407
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 408
    .line 409
    .line 410
    move-result v2

    .line 411
    if-ne v2, v6, :cond_d

    .line 412
    .line 413
    check-cast v0, Ljava/lang/Iterable;

    .line 414
    .line 415
    invoke-static {v0}, Lmx0/q;->h0(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v0

    .line 419
    check-cast v0, Ljava/lang/String;

    .line 420
    .line 421
    const/4 v2, 0x4

    .line 422
    invoke-static {v8, v0, v1, v4, v2}, Lly0/p;->K(Ljava/lang/CharSequence;Ljava/lang/String;IZI)I

    .line 423
    .line 424
    .line 425
    move-result v1

    .line 426
    if-gez v1, :cond_c

    .line 427
    .line 428
    :cond_b
    move-object v2, v3

    .line 429
    goto/16 :goto_d

    .line 430
    .line 431
    :cond_c
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 432
    .line 433
    .line 434
    move-result-object v1

    .line 435
    new-instance v2, Llx0/l;

    .line 436
    .line 437
    invoke-direct {v2, v1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 438
    .line 439
    .line 440
    goto/16 :goto_d

    .line 441
    .line 442
    :cond_d
    new-instance v2, Lgy0/j;

    .line 443
    .line 444
    if-gez v1, :cond_e

    .line 445
    .line 446
    goto :goto_8

    .line 447
    :cond_e
    move v4, v1

    .line 448
    :goto_8
    invoke-interface {v8}, Ljava/lang/CharSequence;->length()I

    .line 449
    .line 450
    .line 451
    move-result v1

    .line 452
    invoke-direct {v2, v4, v1, v6}, Lgy0/h;-><init>(III)V

    .line 453
    .line 454
    .line 455
    instance-of v1, v8, Ljava/lang/String;

    .line 456
    .line 457
    const/4 v14, 0x0

    .line 458
    iget v5, v2, Lgy0/h;->f:I

    .line 459
    .line 460
    iget v2, v2, Lgy0/h;->e:I

    .line 461
    .line 462
    if-eqz v1, :cond_14

    .line 463
    .line 464
    if-lez v5, :cond_f

    .line 465
    .line 466
    if-le v4, v2, :cond_10

    .line 467
    .line 468
    :cond_f
    if-gez v5, :cond_b

    .line 469
    .line 470
    if-gt v2, v4, :cond_b

    .line 471
    .line 472
    :cond_10
    move v10, v4

    .line 473
    :goto_9
    move-object v1, v0

    .line 474
    check-cast v1, Ljava/lang/Iterable;

    .line 475
    .line 476
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    :cond_11
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 481
    .line 482
    .line 483
    move-result v4

    .line 484
    if-eqz v4, :cond_12

    .line 485
    .line 486
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v4

    .line 490
    move-object v12, v4

    .line 491
    check-cast v12, Ljava/lang/String;

    .line 492
    .line 493
    move-object v13, v8

    .line 494
    check-cast v13, Ljava/lang/String;

    .line 495
    .line 496
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 497
    .line 498
    .line 499
    move-result v11

    .line 500
    const/4 v9, 0x0

    .line 501
    invoke-static/range {v9 .. v14}, Lly0/w;->r(IIILjava/lang/String;Ljava/lang/String;Z)Z

    .line 502
    .line 503
    .line 504
    move-result v6

    .line 505
    if-eqz v6, :cond_11

    .line 506
    .line 507
    goto :goto_a

    .line 508
    :cond_12
    move-object v4, v3

    .line 509
    :goto_a
    check-cast v4, Ljava/lang/String;

    .line 510
    .line 511
    if-eqz v4, :cond_13

    .line 512
    .line 513
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    new-instance v2, Llx0/l;

    .line 518
    .line 519
    invoke-direct {v2, v0, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 520
    .line 521
    .line 522
    goto :goto_d

    .line 523
    :cond_13
    if-eq v10, v2, :cond_b

    .line 524
    .line 525
    add-int/2addr v10, v5

    .line 526
    goto :goto_9

    .line 527
    :cond_14
    if-lez v5, :cond_15

    .line 528
    .line 529
    if-le v4, v2, :cond_16

    .line 530
    .line 531
    :cond_15
    if-gez v5, :cond_b

    .line 532
    .line 533
    if-gt v2, v4, :cond_b

    .line 534
    .line 535
    :cond_16
    move v9, v4

    .line 536
    :goto_b
    move-object v1, v0

    .line 537
    check-cast v1, Ljava/lang/Iterable;

    .line 538
    .line 539
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 540
    .line 541
    .line 542
    move-result-object v1

    .line 543
    :cond_17
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 544
    .line 545
    .line 546
    move-result v4

    .line 547
    if-eqz v4, :cond_18

    .line 548
    .line 549
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 550
    .line 551
    .line 552
    move-result-object v4

    .line 553
    move-object v6, v4

    .line 554
    check-cast v6, Ljava/lang/String;

    .line 555
    .line 556
    const/4 v7, 0x0

    .line 557
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 558
    .line 559
    .line 560
    move-result v10

    .line 561
    move v11, v14

    .line 562
    invoke-static/range {v6 .. v11}, Lly0/p;->R(Ljava/lang/CharSequence;ILjava/lang/CharSequence;IIZ)Z

    .line 563
    .line 564
    .line 565
    move-result v6

    .line 566
    if-eqz v6, :cond_17

    .line 567
    .line 568
    goto :goto_c

    .line 569
    :cond_18
    move-object v4, v3

    .line 570
    :goto_c
    check-cast v4, Ljava/lang/String;

    .line 571
    .line 572
    if-eqz v4, :cond_19

    .line 573
    .line 574
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 575
    .line 576
    .line 577
    move-result-object v0

    .line 578
    new-instance v2, Llx0/l;

    .line 579
    .line 580
    invoke-direct {v2, v0, v4}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 581
    .line 582
    .line 583
    goto :goto_d

    .line 584
    :cond_19
    if-eq v9, v2, :cond_b

    .line 585
    .line 586
    add-int/2addr v9, v5

    .line 587
    goto :goto_b

    .line 588
    :goto_d
    if-eqz v2, :cond_1a

    .line 589
    .line 590
    iget-object v0, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 591
    .line 592
    iget-object v1, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 593
    .line 594
    check-cast v1, Ljava/lang/String;

    .line 595
    .line 596
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 597
    .line 598
    .line 599
    move-result v1

    .line 600
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 601
    .line 602
    .line 603
    move-result-object v1

    .line 604
    new-instance v3, Llx0/l;

    .line 605
    .line 606
    invoke-direct {v3, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 607
    .line 608
    .line 609
    :cond_1a
    return-object v3

    .line 610
    :pswitch_8
    move-object/from16 v1, p1

    .line 611
    .line 612
    check-cast v1, Ll2/o;

    .line 613
    .line 614
    move-object/from16 v2, p2

    .line 615
    .line 616
    check-cast v2, Ljava/lang/Integer;

    .line 617
    .line 618
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 619
    .line 620
    .line 621
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 622
    .line 623
    .line 624
    move-result v2

    .line 625
    invoke-static {v0, v1, v2}, Li91/o4;->a(Ljava/util/List;Ll2/o;I)V

    .line 626
    .line 627
    .line 628
    return-object v5

    .line 629
    :pswitch_9
    move-object/from16 v1, p1

    .line 630
    .line 631
    check-cast v1, Ll2/o;

    .line 632
    .line 633
    move-object/from16 v2, p2

    .line 634
    .line 635
    check-cast v2, Ljava/lang/Integer;

    .line 636
    .line 637
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 638
    .line 639
    .line 640
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 641
    .line 642
    .line 643
    move-result v2

    .line 644
    invoke-static {v0, v1, v2}, Lha0/b;->e(Ljava/util/List;Ll2/o;I)V

    .line 645
    .line 646
    .line 647
    return-object v5

    .line 648
    :pswitch_a
    move-object/from16 v1, p1

    .line 649
    .line 650
    check-cast v1, Ll2/o;

    .line 651
    .line 652
    move-object/from16 v2, p2

    .line 653
    .line 654
    check-cast v2, Ljava/lang/Integer;

    .line 655
    .line 656
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 657
    .line 658
    .line 659
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 660
    .line 661
    .line 662
    move-result v2

    .line 663
    invoke-static {v0, v1, v2}, Lkp/r6;->a(Ljava/util/List;Ll2/o;I)V

    .line 664
    .line 665
    .line 666
    return-object v5

    .line 667
    :pswitch_data_0
    .packed-switch 0x0
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
