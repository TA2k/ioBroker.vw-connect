.class public final Lb1/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lb1/h;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/h;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lb1/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lb1/h;->i:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lb1/h;->j:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 p1, 0x3

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb1/h;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/layout/c;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    iget-object v4, v0, Lb1/h;->j:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v4, Lxv/o;

    .line 27
    .line 28
    iget-object v5, v0, Lb1/h;->i:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v5, Lg4/g;

    .line 31
    .line 32
    const-string v6, "$this$BoxWithConstraints"

    .line 33
    .line 34
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    and-int/lit8 v6, v3, 0xe

    .line 38
    .line 39
    if-nez v6, :cond_1

    .line 40
    .line 41
    move-object v6, v2

    .line 42
    check-cast v6, Ll2/t;

    .line 43
    .line 44
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    if-eqz v6, :cond_0

    .line 49
    .line 50
    const/4 v6, 0x4

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const/4 v6, 0x2

    .line 53
    :goto_0
    or-int/2addr v3, v6

    .line 54
    :cond_1
    and-int/lit8 v3, v3, 0x5b

    .line 55
    .line 56
    const/16 v6, 0x12

    .line 57
    .line 58
    if-ne v3, v6, :cond_3

    .line 59
    .line 60
    move-object v3, v2

    .line 61
    check-cast v3, Ll2/t;

    .line 62
    .line 63
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    if-nez v6, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 71
    .line 72
    .line 73
    goto/16 :goto_6

    .line 74
    .line 75
    :cond_3
    :goto_1
    iget-object v3, v0, Lb1/h;->g:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v3, Ljava/util/Map;

    .line 78
    .line 79
    iget-wide v6, v1, Landroidx/compose/foundation/layout/c;->b:J

    .line 80
    .line 81
    move-object v15, v2

    .line 82
    check-cast v15, Ll2/t;

    .line 83
    .line 84
    const v1, 0x526ee014

    .line 85
    .line 86
    .line 87
    invoke-virtual {v15, v1}, Ll2/t;->Z(I)V

    .line 88
    .line 89
    .line 90
    sget-object v1, Lw3/h1;->h:Ll2/u2;

    .line 91
    .line 92
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    move-object v13, v1

    .line 97
    check-cast v13, Lt4/c;

    .line 98
    .line 99
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 100
    .line 101
    invoke-interface {v3}, Ljava/util/Map;->size()I

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    invoke-static {v2}, Lmx0/x;->k(I)I

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    invoke-direct {v1, v2}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    check-cast v2, Ljava/lang/Iterable;

    .line 117
    .line 118
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 127
    .line 128
    if-eqz v3, :cond_8

    .line 129
    .line 130
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    check-cast v3, Ljava/util/Map$Entry;

    .line 135
    .line 136
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v9

    .line 140
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    move-object v12, v3

    .line 145
    check-cast v12, Lxv/a;

    .line 146
    .line 147
    invoke-static {v6, v7}, Lt4/a;->h(J)I

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    invoke-static {v6, v7}, Lt4/a;->g(J)I

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    const/4 v11, 0x5

    .line 156
    invoke-static {v3, v10, v11}, Lt4/b;->b(III)J

    .line 157
    .line 158
    .line 159
    move-result-wide v10

    .line 160
    const v3, -0x769f14e3

    .line 161
    .line 162
    .line 163
    invoke-virtual {v15, v3}, Ll2/t;->Z(I)V

    .line 164
    .line 165
    .line 166
    const v3, -0x1d58f75c

    .line 167
    .line 168
    .line 169
    invoke-virtual {v15, v3}, Ll2/t;->Z(I)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    if-ne v3, v8, :cond_5

    .line 177
    .line 178
    iget-object v3, v12, Lxv/a;->a:Lay0/k;

    .line 179
    .line 180
    if-eqz v3, :cond_4

    .line 181
    .line 182
    invoke-interface {v3, v13}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    check-cast v3, Lt4/l;

    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_4
    const/4 v3, 0x0

    .line 190
    :goto_3
    sget-object v8, Ll2/x0;->i:Ll2/x0;

    .line 191
    .line 192
    new-instance v14, Ll2/j1;

    .line 193
    .line 194
    invoke-direct {v14, v3, v8}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v15, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    move-object v3, v14

    .line 201
    :cond_5
    const/4 v8, 0x0

    .line 202
    invoke-virtual {v15, v8}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    check-cast v3, Ll2/b1;

    .line 206
    .line 207
    new-instance v14, Lg4/v;

    .line 208
    .line 209
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v8

    .line 213
    check-cast v8, Lt4/l;

    .line 214
    .line 215
    move-object/from16 p2, v2

    .line 216
    .line 217
    move-object/from16 p3, v3

    .line 218
    .line 219
    if-eqz v8, :cond_6

    .line 220
    .line 221
    iget-wide v2, v8, Lt4/l;->a:J

    .line 222
    .line 223
    const/16 v8, 0x20

    .line 224
    .line 225
    shr-long/2addr v2, v8

    .line 226
    long-to-int v2, v2

    .line 227
    invoke-interface {v13, v2}, Lt4/c;->x(I)J

    .line 228
    .line 229
    .line 230
    move-result-wide v2

    .line 231
    goto :goto_4

    .line 232
    :cond_6
    const/4 v8, 0x0

    .line 233
    invoke-static {v8}, Lgq/b;->c(I)J

    .line 234
    .line 235
    .line 236
    move-result-wide v2

    .line 237
    :goto_4
    invoke-interface/range {p3 .. p3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    check-cast v8, Lt4/l;

    .line 242
    .line 243
    move-wide/from16 v16, v6

    .line 244
    .line 245
    if-eqz v8, :cond_7

    .line 246
    .line 247
    iget-wide v6, v8, Lt4/l;->a:J

    .line 248
    .line 249
    const-wide v18, 0xffffffffL

    .line 250
    .line 251
    .line 252
    .line 253
    .line 254
    and-long v6, v6, v18

    .line 255
    .line 256
    long-to-int v6, v6

    .line 257
    invoke-interface {v13, v6}, Lt4/c;->x(I)J

    .line 258
    .line 259
    .line 260
    move-result-wide v6

    .line 261
    goto :goto_5

    .line 262
    :cond_7
    const/4 v6, 0x1

    .line 263
    invoke-static {v6}, Lgq/b;->c(I)J

    .line 264
    .line 265
    .line 266
    move-result-wide v6

    .line 267
    :goto_5
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 268
    .line 269
    .line 270
    invoke-direct {v14, v2, v3, v6, v7}, Lg4/v;-><init>(JJ)V

    .line 271
    .line 272
    .line 273
    new-instance v2, Lt1/f0;

    .line 274
    .line 275
    new-instance v8, Lxv/d;

    .line 276
    .line 277
    move-object v3, v9

    .line 278
    move-wide v9, v10

    .line 279
    move-object/from16 v11, p3

    .line 280
    .line 281
    invoke-direct/range {v8 .. v13}, Lxv/d;-><init>(JLl2/b1;Lxv/a;Lt4/c;)V

    .line 282
    .line 283
    .line 284
    const v6, -0x344e44bd    # -2.3295622E7f

    .line 285
    .line 286
    .line 287
    invoke-static {v6, v15, v8}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 288
    .line 289
    .line 290
    move-result-object v6

    .line 291
    invoke-direct {v2, v14, v6}, Lt1/f0;-><init>(Lg4/v;Lt2/b;)V

    .line 292
    .line 293
    .line 294
    const/4 v6, 0x0

    .line 295
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 296
    .line 297
    .line 298
    invoke-interface {v1, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-object/from16 v2, p2

    .line 302
    .line 303
    move-wide/from16 v6, v16

    .line 304
    .line 305
    goto/16 :goto_2

    .line 306
    .line 307
    :cond_8
    const/4 v6, 0x0

    .line 308
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 309
    .line 310
    .line 311
    sget-object v2, Lvv/e0;->a:Ll2/e0;

    .line 312
    .line 313
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v2

    .line 317
    check-cast v2, Lxf0/b2;

    .line 318
    .line 319
    const v3, 0x37615927

    .line 320
    .line 321
    .line 322
    invoke-virtual {v15, v3}, Ll2/t;->Z(I)V

    .line 323
    .line 324
    .line 325
    if-nez v2, :cond_9

    .line 326
    .line 327
    sget-object v2, Lw3/h1;->r:Ll2/u2;

    .line 328
    .line 329
    invoke-virtual {v15, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    move-result-object v2

    .line 333
    :cond_9
    invoke-virtual {v15, v6}, Ll2/t;->q(Z)V

    .line 334
    .line 335
    .line 336
    iget-object v3, v0, Lb1/h;->h:Ljava/lang/Object;

    .line 337
    .line 338
    check-cast v3, Lvv/m0;

    .line 339
    .line 340
    iget-object v0, v0, Lb1/h;->i:Ljava/lang/Object;

    .line 341
    .line 342
    move-object v9, v0

    .line 343
    check-cast v9, Lg4/g;

    .line 344
    .line 345
    sget-object v11, Lxv/b;->i:Lxv/b;

    .line 346
    .line 347
    const v0, 0x7cbdd48

    .line 348
    .line 349
    .line 350
    invoke-virtual {v15, v0}, Ll2/t;->Z(I)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v15, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    move-result v0

    .line 357
    invoke-virtual {v15, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 358
    .line 359
    .line 360
    move-result v6

    .line 361
    or-int/2addr v0, v6

    .line 362
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v6

    .line 366
    if-nez v0, :cond_a

    .line 367
    .line 368
    if-ne v6, v8, :cond_b

    .line 369
    .line 370
    :cond_a
    new-instance v6, Lxv/q;

    .line 371
    .line 372
    const/4 v0, 0x1

    .line 373
    invoke-direct {v6, v5, v4, v0}, Lxv/q;-><init>(Lg4/g;Lxv/o;I)V

    .line 374
    .line 375
    .line 376
    invoke-virtual {v15, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    :cond_b
    move-object v13, v6

    .line 380
    check-cast v13, Lay0/k;

    .line 381
    .line 382
    const/4 v8, 0x0

    .line 383
    invoke-virtual {v15, v8}, Ll2/t;->q(Z)V

    .line 384
    .line 385
    .line 386
    new-instance v14, Lxv/r;

    .line 387
    .line 388
    const/4 v0, 0x1

    .line 389
    invoke-direct {v14, v5, v4, v2, v0}, Lxv/r;-><init>(Lg4/g;Lxv/o;Ljava/lang/Object;I)V

    .line 390
    .line 391
    .line 392
    const/high16 v16, 0x1000000

    .line 393
    .line 394
    const/16 v17, 0x2

    .line 395
    .line 396
    const/4 v10, 0x0

    .line 397
    move-object v12, v1

    .line 398
    move-object v8, v3

    .line 399
    invoke-static/range {v8 .. v17}, Lvv/l0;->a(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 400
    .line 401
    .line 402
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 403
    .line 404
    return-object v0

    .line 405
    :pswitch_0
    iget-object v1, v0, Lb1/h;->i:Ljava/lang/Object;

    .line 406
    .line 407
    move-object v4, v1

    .line 408
    check-cast v4, Lay0/k;

    .line 409
    .line 410
    move-object/from16 v1, p1

    .line 411
    .line 412
    check-cast v1, Lx2/s;

    .line 413
    .line 414
    move-object/from16 v2, p2

    .line 415
    .line 416
    check-cast v2, Ll2/o;

    .line 417
    .line 418
    move-object/from16 v3, p3

    .line 419
    .line 420
    check-cast v3, Ljava/lang/Number;

    .line 421
    .line 422
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 423
    .line 424
    .line 425
    iget-object v3, v0, Lb1/h;->j:Ljava/lang/Object;

    .line 426
    .line 427
    move-object v8, v3

    .line 428
    check-cast v8, Lay0/a;

    .line 429
    .line 430
    iget-object v3, v0, Lb1/h;->g:Ljava/lang/Object;

    .line 431
    .line 432
    move-object v9, v3

    .line 433
    check-cast v9, Lx21/k;

    .line 434
    .line 435
    const-string v3, "$this$composed"

    .line 436
    .line 437
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    move-object v10, v2

    .line 441
    check-cast v10, Ll2/t;

    .line 442
    .line 443
    const v2, 0xdcb1d68

    .line 444
    .line 445
    .line 446
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 447
    .line 448
    .line 449
    const v2, -0x3ccd56e3

    .line 450
    .line 451
    .line 452
    invoke-virtual {v10, v2}, Ll2/t;->Y(I)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    const-wide/16 v5, 0x0

    .line 460
    .line 461
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 462
    .line 463
    if-ne v2, v11, :cond_c

    .line 464
    .line 465
    new-instance v2, Ld3/b;

    .line 466
    .line 467
    invoke-direct {v2, v5, v6}, Ld3/b;-><init>(J)V

    .line 468
    .line 469
    .line 470
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 471
    .line 472
    .line 473
    move-result-object v2

    .line 474
    invoke-virtual {v10, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 475
    .line 476
    .line 477
    :cond_c
    check-cast v2, Ll2/b1;

    .line 478
    .line 479
    const v3, -0x3ccd4e82

    .line 480
    .line 481
    .line 482
    const/4 v12, 0x0

    .line 483
    invoke-static {v3, v10, v12}, Lvj/b;->d(ILl2/t;Z)Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object v3

    .line 487
    if-ne v3, v11, :cond_d

    .line 488
    .line 489
    new-instance v3, Lt4/l;

    .line 490
    .line 491
    invoke-direct {v3, v5, v6}, Lt4/l;-><init>(J)V

    .line 492
    .line 493
    .line 494
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 495
    .line 496
    .line 497
    move-result-object v3

    .line 498
    invoke-virtual {v10, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 499
    .line 500
    .line 501
    :cond_d
    move-object v7, v3

    .line 502
    check-cast v7, Ll2/b1;

    .line 503
    .line 504
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 505
    .line 506
    .line 507
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v3

    .line 511
    if-ne v3, v11, :cond_e

    .line 512
    .line 513
    invoke-static {v10}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 514
    .line 515
    .line 516
    move-result-object v3

    .line 517
    new-instance v5, Ll2/d0;

    .line 518
    .line 519
    invoke-direct {v5, v3}, Ll2/d0;-><init>(Lvy0/b0;)V

    .line 520
    .line 521
    .line 522
    invoke-virtual {v10, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 523
    .line 524
    .line 525
    move-object v3, v5

    .line 526
    :cond_e
    check-cast v3, Ll2/d0;

    .line 527
    .line 528
    iget-object v3, v3, Ll2/d0;->d:Lvy0/b0;

    .line 529
    .line 530
    const v5, -0x3ccd3e70

    .line 531
    .line 532
    .line 533
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object v5

    .line 540
    if-ne v5, v11, :cond_f

    .line 541
    .line 542
    new-instance v5, Lb1/e;

    .line 543
    .line 544
    const/16 v6, 0x16

    .line 545
    .line 546
    invoke-direct {v5, v6, v2, v7}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 547
    .line 548
    .line 549
    invoke-virtual {v10, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 550
    .line 551
    .line 552
    :cond_f
    check-cast v5, Lay0/k;

    .line 553
    .line 554
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 555
    .line 556
    .line 557
    invoke-static {v1, v5}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 558
    .line 559
    .line 560
    move-result-object v1

    .line 561
    iget-object v14, v9, Lx21/k;->a:Lx21/y;

    .line 562
    .line 563
    iget-object v5, v9, Lx21/k;->b:Ljava/lang/Integer;

    .line 564
    .line 565
    new-instance v6, La4/b;

    .line 566
    .line 567
    const/16 v13, 0xe

    .line 568
    .line 569
    invoke-direct {v6, v13, v5, v14}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 570
    .line 571
    .line 572
    invoke-static {v6}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 573
    .line 574
    .line 575
    move-result-object v5

    .line 576
    invoke-virtual {v5}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v5

    .line 580
    check-cast v5, Ljava/lang/Boolean;

    .line 581
    .line 582
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 583
    .line 584
    .line 585
    move-result v5

    .line 586
    if-nez v5, :cond_11

    .line 587
    .line 588
    iget-object v5, v9, Lx21/k;->a:Lx21/y;

    .line 589
    .line 590
    invoke-virtual {v5}, Lx21/y;->g()Z

    .line 591
    .line 592
    .line 593
    move-result v5

    .line 594
    if-nez v5, :cond_10

    .line 595
    .line 596
    goto :goto_7

    .line 597
    :cond_10
    move/from16 v16, v12

    .line 598
    .line 599
    goto :goto_8

    .line 600
    :cond_11
    :goto_7
    const/4 v5, 0x1

    .line 601
    move/from16 v16, v5

    .line 602
    .line 603
    :goto_8
    iget-object v5, v0, Lb1/h;->h:Ljava/lang/Object;

    .line 604
    .line 605
    move-object/from16 v17, v5

    .line 606
    .line 607
    check-cast v17, Lx21/c;

    .line 608
    .line 609
    const v5, -0x3ccd0691

    .line 610
    .line 611
    .line 612
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 613
    .line 614
    .line 615
    invoke-virtual {v10, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 616
    .line 617
    .line 618
    move-result v5

    .line 619
    invoke-virtual {v10, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 620
    .line 621
    .line 622
    move-result v6

    .line 623
    or-int/2addr v5, v6

    .line 624
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 625
    .line 626
    .line 627
    move-result v6

    .line 628
    or-int/2addr v5, v6

    .line 629
    iget-object v0, v0, Lb1/h;->g:Ljava/lang/Object;

    .line 630
    .line 631
    check-cast v0, Lx21/k;

    .line 632
    .line 633
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    move-result-object v6

    .line 637
    if-nez v5, :cond_12

    .line 638
    .line 639
    if-ne v6, v11, :cond_13

    .line 640
    .line 641
    :cond_12
    move-object v6, v2

    .line 642
    new-instance v2, Lnn/m;

    .line 643
    .line 644
    move-object v5, v0

    .line 645
    invoke-direct/range {v2 .. v7}, Lnn/m;-><init>(Lvy0/b0;Lay0/k;Lx21/k;Ll2/b1;Ll2/b1;)V

    .line 646
    .line 647
    .line 648
    invoke-virtual {v10, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 649
    .line 650
    .line 651
    move-object v6, v2

    .line 652
    :cond_13
    check-cast v6, Lay0/k;

    .line 653
    .line 654
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 655
    .line 656
    .line 657
    const v0, -0x3cccc520

    .line 658
    .line 659
    .line 660
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 661
    .line 662
    .line 663
    invoke-virtual {v10, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 664
    .line 665
    .line 666
    move-result v0

    .line 667
    invoke-virtual {v10, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 668
    .line 669
    .line 670
    move-result v2

    .line 671
    or-int/2addr v0, v2

    .line 672
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 673
    .line 674
    .line 675
    move-result-object v2

    .line 676
    if-nez v0, :cond_14

    .line 677
    .line 678
    if-ne v2, v11, :cond_15

    .line 679
    .line 680
    :cond_14
    new-instance v2, La4/b;

    .line 681
    .line 682
    invoke-direct {v2, v9, v8}, La4/b;-><init>(Lx21/k;Lay0/a;)V

    .line 683
    .line 684
    .line 685
    invoke-virtual {v10, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 686
    .line 687
    .line 688
    :cond_15
    move-object v15, v2

    .line 689
    check-cast v15, Lay0/a;

    .line 690
    .line 691
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 692
    .line 693
    .line 694
    const v0, -0x3cccb4c3

    .line 695
    .line 696
    .line 697
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 698
    .line 699
    .line 700
    invoke-virtual {v10, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 701
    .line 702
    .line 703
    move-result v0

    .line 704
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 705
    .line 706
    .line 707
    move-result-object v2

    .line 708
    if-nez v0, :cond_16

    .line 709
    .line 710
    if-ne v2, v11, :cond_17

    .line 711
    .line 712
    :cond_16
    new-instance v2, Lb1/g;

    .line 713
    .line 714
    const/4 v0, 0x6

    .line 715
    invoke-direct {v2, v9, v0}, Lb1/g;-><init>(Ljava/lang/Object;I)V

    .line 716
    .line 717
    .line 718
    invoke-virtual {v10, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 719
    .line 720
    .line 721
    :cond_17
    check-cast v2, Lay0/n;

    .line 722
    .line 723
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 724
    .line 725
    .line 726
    const-string v0, "<this>"

    .line 727
    .line 728
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 729
    .line 730
    .line 731
    const-string v0, "onDragStarted"

    .line 732
    .line 733
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 734
    .line 735
    .line 736
    const-string v0, "onDragStopped"

    .line 737
    .line 738
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 739
    .line 740
    .line 741
    const-string v0, "onDrag"

    .line 742
    .line 743
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 744
    .line 745
    .line 746
    new-instance v13, Lx21/h;

    .line 747
    .line 748
    move-object/from16 v19, v2

    .line 749
    .line 750
    move-object/from16 v18, v6

    .line 751
    .line 752
    invoke-direct/range {v13 .. v19}, Lx21/h;-><init>(Lx21/y;Lay0/a;ZLx21/c;Lay0/k;Lay0/n;)V

    .line 753
    .line 754
    .line 755
    invoke-static {v1, v13}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 756
    .line 757
    .line 758
    move-result-object v0

    .line 759
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 760
    .line 761
    .line 762
    return-object v0

    .line 763
    :pswitch_1
    move-object/from16 v1, p1

    .line 764
    .line 765
    check-cast v1, Lb1/a0;

    .line 766
    .line 767
    move-object/from16 v2, p2

    .line 768
    .line 769
    check-cast v2, Ll2/o;

    .line 770
    .line 771
    move-object/from16 v3, p3

    .line 772
    .line 773
    check-cast v3, Ljava/lang/Number;

    .line 774
    .line 775
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 776
    .line 777
    .line 778
    move-result v3

    .line 779
    iget-object v4, v0, Lb1/h;->g:Ljava/lang/Object;

    .line 780
    .line 781
    check-cast v4, Lv2/o;

    .line 782
    .line 783
    iget-object v5, v0, Lb1/h;->i:Ljava/lang/Object;

    .line 784
    .line 785
    check-cast v5, Lb1/t;

    .line 786
    .line 787
    and-int/lit8 v6, v3, 0x6

    .line 788
    .line 789
    if-nez v6, :cond_1a

    .line 790
    .line 791
    and-int/lit8 v6, v3, 0x8

    .line 792
    .line 793
    if-nez v6, :cond_18

    .line 794
    .line 795
    move-object v6, v2

    .line 796
    check-cast v6, Ll2/t;

    .line 797
    .line 798
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 799
    .line 800
    .line 801
    move-result v6

    .line 802
    goto :goto_9

    .line 803
    :cond_18
    move-object v6, v2

    .line 804
    check-cast v6, Ll2/t;

    .line 805
    .line 806
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 807
    .line 808
    .line 809
    move-result v6

    .line 810
    :goto_9
    if-eqz v6, :cond_19

    .line 811
    .line 812
    const/4 v6, 0x4

    .line 813
    goto :goto_a

    .line 814
    :cond_19
    const/4 v6, 0x2

    .line 815
    :goto_a
    or-int/2addr v3, v6

    .line 816
    :cond_1a
    and-int/lit8 v6, v3, 0x13

    .line 817
    .line 818
    const/16 v7, 0x12

    .line 819
    .line 820
    const/4 v8, 0x0

    .line 821
    const/4 v9, 0x1

    .line 822
    if-eq v6, v7, :cond_1b

    .line 823
    .line 824
    move v6, v9

    .line 825
    goto :goto_b

    .line 826
    :cond_1b
    move v6, v8

    .line 827
    :goto_b
    and-int/2addr v3, v9

    .line 828
    check-cast v2, Ll2/t;

    .line 829
    .line 830
    invoke-virtual {v2, v3, v6}, Ll2/t;->O(IZ)Z

    .line 831
    .line 832
    .line 833
    move-result v3

    .line 834
    if-eqz v3, :cond_1f

    .line 835
    .line 836
    invoke-virtual {v2, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 837
    .line 838
    .line 839
    move-result v3

    .line 840
    iget-object v6, v0, Lb1/h;->h:Ljava/lang/Object;

    .line 841
    .line 842
    invoke-virtual {v2, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 843
    .line 844
    .line 845
    move-result v7

    .line 846
    or-int/2addr v3, v7

    .line 847
    invoke-virtual {v2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 848
    .line 849
    .line 850
    move-result v7

    .line 851
    or-int/2addr v3, v7

    .line 852
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v7

    .line 856
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 857
    .line 858
    if-nez v3, :cond_1c

    .line 859
    .line 860
    if-ne v7, v9, :cond_1d

    .line 861
    .line 862
    :cond_1c
    new-instance v7, La3/g;

    .line 863
    .line 864
    const/4 v3, 0x1

    .line 865
    invoke-direct {v7, v4, v6, v5, v3}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 866
    .line 867
    .line 868
    invoke-virtual {v2, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 869
    .line 870
    .line 871
    :cond_1d
    check-cast v7, Lay0/k;

    .line 872
    .line 873
    invoke-static {v1, v7, v2}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 874
    .line 875
    .line 876
    iget-object v3, v5, Lb1/t;->e:Landroidx/collection/q0;

    .line 877
    .line 878
    const-string v4, "null cannot be cast to non-null type androidx.compose.animation.AnimatedVisibilityScopeImpl"

    .line 879
    .line 880
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 881
    .line 882
    .line 883
    check-cast v1, Lb1/b0;

    .line 884
    .line 885
    iget-object v1, v1, Lb1/b0;->a:Ll2/j1;

    .line 886
    .line 887
    invoke-virtual {v3, v6, v1}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 888
    .line 889
    .line 890
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 891
    .line 892
    .line 893
    move-result-object v1

    .line 894
    if-ne v1, v9, :cond_1e

    .line 895
    .line 896
    new-instance v1, Lb1/n;

    .line 897
    .line 898
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 899
    .line 900
    .line 901
    invoke-virtual {v2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 902
    .line 903
    .line 904
    :cond_1e
    check-cast v1, Lb1/n;

    .line 905
    .line 906
    iget-object v0, v0, Lb1/h;->j:Ljava/lang/Object;

    .line 907
    .line 908
    check-cast v0, Lt2/b;

    .line 909
    .line 910
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 911
    .line 912
    .line 913
    move-result-object v3

    .line 914
    invoke-virtual {v0, v1, v6, v2, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 915
    .line 916
    .line 917
    goto :goto_c

    .line 918
    :cond_1f
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 919
    .line 920
    .line 921
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 922
    .line 923
    return-object v0

    .line 924
    nop

    .line 925
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
