.class public final Lel/i;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Llx0/e;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/n;Lay0/p;Lay0/n;Lay0/p;Lt2/b;I)V
    .locals 0

    const/4 p6, 0x1

    iput p6, p0, Lel/i;->f:I

    .line 1
    iput-object p1, p0, Lel/i;->g:Ljava/lang/Object;

    iput-object p2, p0, Lel/i;->h:Ljava/lang/Object;

    iput-object p3, p0, Lel/i;->i:Llx0/e;

    iput-object p4, p0, Lel/i;->j:Ljava/lang/Object;

    iput-object p5, p0, Lel/i;->k:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Lz4/k;Lay0/a;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p6, p0, Lel/i;->f:I

    iput-object p1, p0, Lel/i;->g:Ljava/lang/Object;

    iput-object p2, p0, Lel/i;->h:Ljava/lang/Object;

    iput-object p3, p0, Lel/i;->i:Llx0/e;

    iput-object p4, p0, Lel/i;->j:Ljava/lang/Object;

    iput-object p5, p0, Lel/i;->k:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 42

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lel/i;->f:I

    .line 4
    .line 5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 6
    .line 7
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 8
    .line 9
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 10
    .line 11
    iget-object v6, v0, Lel/i;->i:Llx0/e;

    .line 12
    .line 13
    iget-object v7, v0, Lel/i;->k:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v8, v0, Lel/i;->j:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v9, v0, Lel/i;->g:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v0, v0, Lel/i;->h:Ljava/lang/Object;

    .line 20
    .line 21
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    const/4 v11, 0x2

    .line 24
    const/4 v13, 0x3

    .line 25
    packed-switch v1, :pswitch_data_0

    .line 26
    .line 27
    .line 28
    move-object/from16 v1, p1

    .line 29
    .line 30
    check-cast v1, Ll2/o;

    .line 31
    .line 32
    move-object/from16 v2, p2

    .line 33
    .line 34
    check-cast v2, Ljava/lang/Number;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    check-cast v0, Lz4/k;

    .line 41
    .line 42
    and-int/2addr v2, v13

    .line 43
    if-ne v2, v11, :cond_1

    .line 44
    .line 45
    move-object v2, v1

    .line 46
    check-cast v2, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 49
    .line 50
    .line 51
    move-result v11

    .line 52
    if-nez v11, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_2

    .line 59
    .line 60
    :cond_1
    :goto_0
    check-cast v9, Ll2/b1;

    .line 61
    .line 62
    invoke-interface {v9, v10}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget v2, v0, Lz4/k;->b:I

    .line 66
    .line 67
    invoke-virtual {v0}, Lz4/k;->e()V

    .line 68
    .line 69
    .line 70
    check-cast v1, Ll2/t;

    .line 71
    .line 72
    const v9, -0x5a0dbf1b

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1, v9}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0}, Lz4/k;->d()Lt1/j0;

    .line 79
    .line 80
    .line 81
    move-result-object v9

    .line 82
    iget-object v9, v9, Lt1/j0;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v9, Lz4/k;

    .line 85
    .line 86
    invoke-virtual {v9}, Lz4/k;->c()Lz4/f;

    .line 87
    .line 88
    .line 89
    move-result-object v11

    .line 90
    invoke-virtual {v9}, Lz4/k;->c()Lz4/f;

    .line 91
    .line 92
    .line 93
    move-result-object v13

    .line 94
    invoke-virtual {v9}, Lz4/k;->c()Lz4/f;

    .line 95
    .line 96
    .line 97
    move-result-object v15

    .line 98
    invoke-virtual {v9}, Lz4/k;->c()Lz4/f;

    .line 99
    .line 100
    .line 101
    move-result-object v14

    .line 102
    invoke-virtual {v9}, Lz4/k;->c()Lz4/f;

    .line 103
    .line 104
    .line 105
    move-result-object v9

    .line 106
    filled-new-array {v11, v13, v15, v14, v9}, [Lz4/f;

    .line 107
    .line 108
    .line 109
    move-result-object v9

    .line 110
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 111
    .line 112
    .line 113
    move-result-object v9

    .line 114
    const v11, 0x603126db

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1, v11}, Ll2/t;->Y(I)V

    .line 118
    .line 119
    .line 120
    check-cast v9, Ljava/lang/Iterable;

    .line 121
    .line 122
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v9

    .line 126
    const/4 v11, 0x0

    .line 127
    :goto_1
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 128
    .line 129
    .line 130
    move-result v13

    .line 131
    if-eqz v13, :cond_8

    .line 132
    .line 133
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v13

    .line 137
    add-int/lit8 v14, v11, 0x1

    .line 138
    .line 139
    if-ltz v11, :cond_7

    .line 140
    .line 141
    check-cast v13, Lz4/f;

    .line 142
    .line 143
    move-object v15, v8

    .line 144
    check-cast v15, Lv2/o;

    .line 145
    .line 146
    invoke-static {v15}, Lmx0/q;->H(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 147
    .line 148
    .line 149
    move-result-object v15

    .line 150
    invoke-static {v11, v15}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v15

    .line 154
    check-cast v15, Ld3/b;

    .line 155
    .line 156
    invoke-virtual {v1, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v16

    .line 160
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    if-nez v16, :cond_2

    .line 165
    .line 166
    if-ne v3, v5, :cond_3

    .line 167
    .line 168
    :cond_2
    new-instance v3, Lag/t;

    .line 169
    .line 170
    const/16 v12, 0x13

    .line 171
    .line 172
    invoke-direct {v3, v15, v12}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :cond_3
    check-cast v3, Lay0/k;

    .line 179
    .line 180
    invoke-static {v4, v13, v3}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    const/4 v12, 0x1

    .line 185
    int-to-float v15, v12

    .line 186
    move-object/from16 v38, v6

    .line 187
    .line 188
    const/4 v12, 0x4

    .line 189
    int-to-float v6, v12

    .line 190
    invoke-static {v3, v15, v6}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 195
    .line 196
    invoke-virtual {v1, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v12

    .line 200
    check-cast v12, Lj91/e;

    .line 201
    .line 202
    move-object/from16 v39, v7

    .line 203
    .line 204
    move-object/from16 v40, v8

    .line 205
    .line 206
    invoke-virtual {v12}, Lj91/e;->t()J

    .line 207
    .line 208
    .line 209
    move-result-wide v7

    .line 210
    sget-object v12, Le3/j0;->a:Le3/i0;

    .line 211
    .line 212
    invoke-static {v3, v7, v8, v12}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 213
    .line 214
    .line 215
    move-result-object v3

    .line 216
    const/4 v7, 0x0

    .line 217
    invoke-static {v3, v1, v7}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 218
    .line 219
    .line 220
    move-object/from16 v7, v39

    .line 221
    .line 222
    check-cast v7, Ljava/util/List;

    .line 223
    .line 224
    invoke-static {v11, v7}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v3

    .line 228
    check-cast v3, Ljava/lang/String;

    .line 229
    .line 230
    if-nez v3, :cond_4

    .line 231
    .line 232
    const-string v3, ""

    .line 233
    .line 234
    :cond_4
    move-object v15, v3

    .line 235
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 236
    .line 237
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    check-cast v3, Lj91/f;

    .line 242
    .line 243
    invoke-virtual {v3}, Lj91/f;->e()Lg4/p0;

    .line 244
    .line 245
    .line 246
    move-result-object v16

    .line 247
    invoke-virtual {v1, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    check-cast v3, Lj91/e;

    .line 252
    .line 253
    invoke-virtual {v3}, Lj91/e;->t()J

    .line 254
    .line 255
    .line 256
    move-result-wide v18

    .line 257
    invoke-virtual {v0}, Lz4/k;->c()Lz4/f;

    .line 258
    .line 259
    .line 260
    move-result-object v3

    .line 261
    invoke-virtual {v1, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v6

    .line 265
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v7

    .line 269
    if-nez v6, :cond_5

    .line 270
    .line 271
    if-ne v7, v5, :cond_6

    .line 272
    .line 273
    :cond_5
    new-instance v7, Lc40/g;

    .line 274
    .line 275
    const/16 v6, 0x12

    .line 276
    .line 277
    invoke-direct {v7, v13, v6}, Lc40/g;-><init>(Lz4/f;I)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v1, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 281
    .line 282
    .line 283
    :cond_6
    check-cast v7, Lay0/k;

    .line 284
    .line 285
    invoke-static {v4, v3, v7}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 286
    .line 287
    .line 288
    move-result-object v17

    .line 289
    const/16 v35, 0x0

    .line 290
    .line 291
    const v36, 0xfff0

    .line 292
    .line 293
    .line 294
    const-wide/16 v20, 0x0

    .line 295
    .line 296
    const/16 v22, 0x0

    .line 297
    .line 298
    const-wide/16 v23, 0x0

    .line 299
    .line 300
    const/16 v25, 0x0

    .line 301
    .line 302
    const/16 v26, 0x0

    .line 303
    .line 304
    const-wide/16 v27, 0x0

    .line 305
    .line 306
    const/16 v29, 0x0

    .line 307
    .line 308
    const/16 v30, 0x0

    .line 309
    .line 310
    const/16 v31, 0x0

    .line 311
    .line 312
    const/16 v32, 0x0

    .line 313
    .line 314
    const/16 v34, 0x0

    .line 315
    .line 316
    move-object/from16 v33, v1

    .line 317
    .line 318
    invoke-static/range {v15 .. v36}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 319
    .line 320
    .line 321
    move v11, v14

    .line 322
    move-object/from16 v6, v38

    .line 323
    .line 324
    move-object/from16 v7, v39

    .line 325
    .line 326
    move-object/from16 v8, v40

    .line 327
    .line 328
    goto/16 :goto_1

    .line 329
    .line 330
    :cond_7
    invoke-static {}, Ljp/k1;->r()V

    .line 331
    .line 332
    .line 333
    const/4 v0, 0x0

    .line 334
    throw v0

    .line 335
    :cond_8
    move-object/from16 v38, v6

    .line 336
    .line 337
    const/4 v7, 0x0

    .line 338
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    .line 339
    .line 340
    .line 341
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    iget v0, v0, Lz4/k;->b:I

    .line 345
    .line 346
    if-eq v0, v2, :cond_9

    .line 347
    .line 348
    move-object/from16 v6, v38

    .line 349
    .line 350
    check-cast v6, Lay0/a;

    .line 351
    .line 352
    invoke-static {v6, v1}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 353
    .line 354
    .line 355
    :cond_9
    :goto_2
    return-object v10

    .line 356
    :pswitch_0
    move-object/from16 v38, v6

    .line 357
    .line 358
    move-object/from16 v39, v7

    .line 359
    .line 360
    move-object/from16 v40, v8

    .line 361
    .line 362
    move-object/from16 v1, p1

    .line 363
    .line 364
    check-cast v1, Ll2/o;

    .line 365
    .line 366
    move-object/from16 v3, p2

    .line 367
    .line 368
    check-cast v3, Ljava/lang/Number;

    .line 369
    .line 370
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 371
    .line 372
    .line 373
    move-result v3

    .line 374
    check-cast v0, Lz4/k;

    .line 375
    .line 376
    move-object/from16 v8, v40

    .line 377
    .line 378
    check-cast v8, Lfh/f;

    .line 379
    .line 380
    move-object/from16 v7, v39

    .line 381
    .line 382
    check-cast v7, Lay0/k;

    .line 383
    .line 384
    and-int/2addr v3, v13

    .line 385
    if-ne v3, v11, :cond_b

    .line 386
    .line 387
    move-object v3, v1

    .line 388
    check-cast v3, Ll2/t;

    .line 389
    .line 390
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 391
    .line 392
    .line 393
    move-result v4

    .line 394
    if-nez v4, :cond_a

    .line 395
    .line 396
    goto :goto_3

    .line 397
    :cond_a
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 398
    .line 399
    .line 400
    move-object/from16 v34, v10

    .line 401
    .line 402
    goto/16 :goto_a

    .line 403
    .line 404
    :cond_b
    :goto_3
    check-cast v9, Ll2/b1;

    .line 405
    .line 406
    invoke-interface {v9, v10}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 407
    .line 408
    .line 409
    iget v3, v0, Lz4/k;->b:I

    .line 410
    .line 411
    invoke-virtual {v0}, Lz4/k;->e()V

    .line 412
    .line 413
    .line 414
    check-cast v1, Ll2/t;

    .line 415
    .line 416
    const v4, -0x6f526986

    .line 417
    .line 418
    .line 419
    invoke-virtual {v1, v4}, Ll2/t;->Y(I)V

    .line 420
    .line 421
    .line 422
    invoke-virtual {v0}, Lz4/k;->d()Lt1/j0;

    .line 423
    .line 424
    .line 425
    move-result-object v4

    .line 426
    iget-object v4, v4, Lt1/j0;->e:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v4, Lz4/k;

    .line 429
    .line 430
    invoke-virtual {v4}, Lz4/k;->c()Lz4/f;

    .line 431
    .line 432
    .line 433
    move-result-object v6

    .line 434
    invoke-virtual {v4}, Lz4/k;->c()Lz4/f;

    .line 435
    .line 436
    .line 437
    move-result-object v4

    .line 438
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 439
    .line 440
    invoke-static {v9, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 441
    .line 442
    .line 443
    move-result-object v11

    .line 444
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v12

    .line 448
    if-ne v12, v5, :cond_c

    .line 449
    .line 450
    sget-object v12, Lwk/d;->g:Lwk/d;

    .line 451
    .line 452
    invoke-virtual {v1, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 453
    .line 454
    .line 455
    :cond_c
    check-cast v12, Lay0/k;

    .line 456
    .line 457
    invoke-static {v11, v6, v12}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 458
    .line 459
    .line 460
    move-result-object v6

    .line 461
    sget-object v11, Lk1/j;->c:Lk1/e;

    .line 462
    .line 463
    sget-object v12, Lx2/c;->p:Lx2/h;

    .line 464
    .line 465
    const/4 v13, 0x0

    .line 466
    invoke-static {v11, v12, v1, v13}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 467
    .line 468
    .line 469
    move-result-object v11

    .line 470
    iget-wide v12, v1, Ll2/t;->T:J

    .line 471
    .line 472
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 473
    .line 474
    .line 475
    move-result v12

    .line 476
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 477
    .line 478
    .line 479
    move-result-object v13

    .line 480
    invoke-static {v1, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 481
    .line 482
    .line 483
    move-result-object v6

    .line 484
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 485
    .line 486
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 487
    .line 488
    .line 489
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 490
    .line 491
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 492
    .line 493
    .line 494
    iget-boolean v15, v1, Ll2/t;->S:Z

    .line 495
    .line 496
    if-eqz v15, :cond_d

    .line 497
    .line 498
    invoke-virtual {v1, v14}, Ll2/t;->l(Lay0/a;)V

    .line 499
    .line 500
    .line 501
    goto :goto_4

    .line 502
    :cond_d
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 503
    .line 504
    .line 505
    :goto_4
    sget-object v15, Lv3/j;->g:Lv3/h;

    .line 506
    .line 507
    invoke-static {v15, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 508
    .line 509
    .line 510
    sget-object v11, Lv3/j;->f:Lv3/h;

    .line 511
    .line 512
    invoke-static {v11, v13, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 513
    .line 514
    .line 515
    sget-object v13, Lv3/j;->j:Lv3/h;

    .line 516
    .line 517
    iget-boolean v2, v1, Ll2/t;->S:Z

    .line 518
    .line 519
    if-nez v2, :cond_e

    .line 520
    .line 521
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object v2

    .line 525
    move-object/from16 p1, v11

    .line 526
    .line 527
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 528
    .line 529
    .line 530
    move-result-object v11

    .line 531
    invoke-static {v2, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 532
    .line 533
    .line 534
    move-result v2

    .line 535
    if-nez v2, :cond_f

    .line 536
    .line 537
    goto :goto_5

    .line 538
    :cond_e
    move-object/from16 p1, v11

    .line 539
    .line 540
    :goto_5
    invoke-static {v12, v1, v12, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 541
    .line 542
    .line 543
    :cond_f
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 544
    .line 545
    invoke-static {v2, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 546
    .line 547
    .line 548
    const/16 v6, 0x18

    .line 549
    .line 550
    int-to-float v6, v6

    .line 551
    const-string v11, "wallbox_auth_mode_title"

    .line 552
    .line 553
    invoke-static {v9, v6, v1, v9, v11}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 554
    .line 555
    .line 556
    move-result-object v6

    .line 557
    const v11, 0x7f120bda

    .line 558
    .line 559
    .line 560
    invoke-static {v1, v11}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 561
    .line 562
    .line 563
    move-result-object v11

    .line 564
    sget-object v12, Lj91/j;->a:Ll2/u2;

    .line 565
    .line 566
    invoke-virtual {v1, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    move-result-object v16

    .line 570
    check-cast v16, Lj91/f;

    .line 571
    .line 572
    invoke-virtual/range {v16 .. v16}, Lj91/f;->i()Lg4/p0;

    .line 573
    .line 574
    .line 575
    move-result-object v16

    .line 576
    move-object/from16 p2, v6

    .line 577
    .line 578
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 579
    .line 580
    invoke-virtual {v1, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    move-result-object v17

    .line 584
    check-cast v17, Lj91/e;

    .line 585
    .line 586
    invoke-virtual/range {v17 .. v17}, Lj91/e;->q()J

    .line 587
    .line 588
    .line 589
    move-result-wide v17

    .line 590
    const/16 v31, 0x0

    .line 591
    .line 592
    const v32, 0xfff0

    .line 593
    .line 594
    .line 595
    move-object/from16 v19, v14

    .line 596
    .line 597
    move-object/from16 v20, v15

    .line 598
    .line 599
    move-wide/from16 v14, v17

    .line 600
    .line 601
    move-object/from16 v18, v12

    .line 602
    .line 603
    move-object/from16 v12, v16

    .line 604
    .line 605
    const-wide/16 v16, 0x0

    .line 606
    .line 607
    move-object/from16 v21, v18

    .line 608
    .line 609
    const/16 v18, 0x0

    .line 610
    .line 611
    move-object/from16 v22, v19

    .line 612
    .line 613
    move-object/from16 v23, v20

    .line 614
    .line 615
    const-wide/16 v19, 0x0

    .line 616
    .line 617
    move-object/from16 v24, v21

    .line 618
    .line 619
    const/16 v21, 0x0

    .line 620
    .line 621
    move-object/from16 v25, v22

    .line 622
    .line 623
    const/16 v22, 0x0

    .line 624
    .line 625
    move-object/from16 v26, v23

    .line 626
    .line 627
    move-object/from16 v27, v24

    .line 628
    .line 629
    const-wide/16 v23, 0x0

    .line 630
    .line 631
    move-object/from16 v28, v25

    .line 632
    .line 633
    const/16 v25, 0x0

    .line 634
    .line 635
    move-object/from16 v29, v26

    .line 636
    .line 637
    const/16 v26, 0x0

    .line 638
    .line 639
    move-object/from16 v30, v27

    .line 640
    .line 641
    const/16 v27, 0x0

    .line 642
    .line 643
    move-object/from16 v34, v28

    .line 644
    .line 645
    const/16 v28, 0x0

    .line 646
    .line 647
    move-object/from16 v35, v30

    .line 648
    .line 649
    const/16 v30, 0x180

    .line 650
    .line 651
    move/from16 v41, v3

    .line 652
    .line 653
    move-object/from16 v3, p1

    .line 654
    .line 655
    move-object/from16 p1, v0

    .line 656
    .line 657
    move-object v0, v13

    .line 658
    move-object/from16 v13, p2

    .line 659
    .line 660
    move-object/from16 p2, v4

    .line 661
    .line 662
    move-object/from16 v4, v35

    .line 663
    .line 664
    move/from16 v35, v41

    .line 665
    .line 666
    move-object/from16 v41, v29

    .line 667
    .line 668
    move-object/from16 v29, v1

    .line 669
    .line 670
    move-object/from16 v1, v34

    .line 671
    .line 672
    move-object/from16 v34, v10

    .line 673
    .line 674
    move-object/from16 v10, v41

    .line 675
    .line 676
    invoke-static/range {v11 .. v32}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 677
    .line 678
    .line 679
    move-object/from16 v11, v29

    .line 680
    .line 681
    const/16 v12, 0x16

    .line 682
    .line 683
    int-to-float v12, v12

    .line 684
    const-string v13, "wallbox_change_auth_mode_desc"

    .line 685
    .line 686
    invoke-static {v9, v12, v11, v9, v13}, Lvj/b;->q(Lx2/p;FLl2/t;Lx2/p;Ljava/lang/String;)Lx2/s;

    .line 687
    .line 688
    .line 689
    move-result-object v13

    .line 690
    const v12, 0x7f120bd8

    .line 691
    .line 692
    .line 693
    invoke-static {v11, v12}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 694
    .line 695
    .line 696
    move-result-object v12

    .line 697
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 698
    .line 699
    .line 700
    move-result-object v4

    .line 701
    check-cast v4, Lj91/f;

    .line 702
    .line 703
    invoke-virtual {v4}, Lj91/f;->b()Lg4/p0;

    .line 704
    .line 705
    .line 706
    move-result-object v4

    .line 707
    invoke-virtual {v11, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v6

    .line 711
    check-cast v6, Lj91/e;

    .line 712
    .line 713
    invoke-virtual {v6}, Lj91/e;->s()J

    .line 714
    .line 715
    .line 716
    move-result-wide v14

    .line 717
    move-object v11, v12

    .line 718
    move-object v12, v4

    .line 719
    invoke-static/range {v11 .. v32}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 720
    .line 721
    .line 722
    move-object/from16 v11, v29

    .line 723
    .line 724
    const/16 v4, 0x10

    .line 725
    .line 726
    int-to-float v4, v4

    .line 727
    const/high16 v6, 0x3f800000    # 1.0f

    .line 728
    .line 729
    invoke-static {v9, v4, v11, v9, v6}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 730
    .line 731
    .line 732
    move-result-object v4

    .line 733
    sget-object v6, Lk1/j;->g:Lk1/f;

    .line 734
    .line 735
    sget-object v12, Lx2/c;->n:Lx2/i;

    .line 736
    .line 737
    const/16 v13, 0x36

    .line 738
    .line 739
    invoke-static {v6, v12, v11, v13}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 740
    .line 741
    .line 742
    move-result-object v6

    .line 743
    iget-wide v12, v11, Ll2/t;->T:J

    .line 744
    .line 745
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 746
    .line 747
    .line 748
    move-result v12

    .line 749
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 750
    .line 751
    .line 752
    move-result-object v13

    .line 753
    invoke-static {v11, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 754
    .line 755
    .line 756
    move-result-object v4

    .line 757
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 758
    .line 759
    .line 760
    iget-boolean v14, v11, Ll2/t;->S:Z

    .line 761
    .line 762
    if-eqz v14, :cond_10

    .line 763
    .line 764
    invoke-virtual {v11, v1}, Ll2/t;->l(Lay0/a;)V

    .line 765
    .line 766
    .line 767
    goto :goto_6

    .line 768
    :cond_10
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 769
    .line 770
    .line 771
    :goto_6
    invoke-static {v10, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 772
    .line 773
    .line 774
    invoke-static {v3, v13, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 775
    .line 776
    .line 777
    iget-boolean v1, v11, Ll2/t;->S:Z

    .line 778
    .line 779
    if-nez v1, :cond_11

    .line 780
    .line 781
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 782
    .line 783
    .line 784
    move-result-object v1

    .line 785
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 786
    .line 787
    .line 788
    move-result-object v3

    .line 789
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 790
    .line 791
    .line 792
    move-result v1

    .line 793
    if-nez v1, :cond_12

    .line 794
    .line 795
    :cond_11
    invoke-static {v12, v11, v12, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 796
    .line 797
    .line 798
    :cond_12
    invoke-static {v2, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 799
    .line 800
    .line 801
    const v0, 0x7f120bdb

    .line 802
    .line 803
    .line 804
    invoke-static {v11, v0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 805
    .line 806
    .line 807
    move-result-object v15

    .line 808
    const-string v0, "wallbox_change_auth_mode_switch"

    .line 809
    .line 810
    invoke-static {v9, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 811
    .line 812
    .line 813
    move-result-object v17

    .line 814
    iget-boolean v0, v8, Lfh/f;->a:Z

    .line 815
    .line 816
    iget-boolean v1, v8, Lfh/f;->b:Z

    .line 817
    .line 818
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 819
    .line 820
    .line 821
    move-result v2

    .line 822
    invoke-virtual {v11, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 823
    .line 824
    .line 825
    move-result v3

    .line 826
    or-int/2addr v2, v3

    .line 827
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 828
    .line 829
    .line 830
    move-result-object v3

    .line 831
    if-nez v2, :cond_13

    .line 832
    .line 833
    if-ne v3, v5, :cond_14

    .line 834
    .line 835
    :cond_13
    new-instance v3, Lc41/f;

    .line 836
    .line 837
    const/16 v2, 0xf

    .line 838
    .line 839
    invoke-direct {v3, v2, v7, v8}, Lc41/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 840
    .line 841
    .line 842
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 843
    .line 844
    .line 845
    :cond_14
    move-object v13, v3

    .line 846
    check-cast v13, Lay0/a;

    .line 847
    .line 848
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 849
    .line 850
    .line 851
    move-result v2

    .line 852
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v3

    .line 856
    if-nez v2, :cond_15

    .line 857
    .line 858
    if-ne v3, v5, :cond_16

    .line 859
    .line 860
    :cond_15
    new-instance v3, Lfk/b;

    .line 861
    .line 862
    const/4 v2, 0x6

    .line 863
    invoke-direct {v3, v2, v7}, Lfk/b;-><init>(ILay0/k;)V

    .line 864
    .line 865
    .line 866
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 867
    .line 868
    .line 869
    :cond_16
    move-object v14, v3

    .line 870
    check-cast v14, Lay0/k;

    .line 871
    .line 872
    move-object/from16 v29, v11

    .line 873
    .line 874
    const/16 v11, 0x6000

    .line 875
    .line 876
    const/4 v12, 0x0

    .line 877
    move/from16 v18, v0

    .line 878
    .line 879
    move/from16 v19, v1

    .line 880
    .line 881
    move-object/from16 v16, v29

    .line 882
    .line 883
    invoke-static/range {v11 .. v19}, Li91/y3;->a(IILay0/a;Lay0/k;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 884
    .line 885
    .line 886
    move-object/from16 v1, v16

    .line 887
    .line 888
    const/4 v12, 0x1

    .line 889
    invoke-virtual {v1, v12}, Ll2/t;->q(Z)V

    .line 890
    .line 891
    .line 892
    iget-boolean v0, v8, Lfh/f;->e:Z

    .line 893
    .line 894
    if-eqz v0, :cond_17

    .line 895
    .line 896
    const v0, -0x5a1cdbb7

    .line 897
    .line 898
    .line 899
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 900
    .line 901
    .line 902
    const/4 v13, 0x0

    .line 903
    invoke-static {v1, v13}, Lwk/a;->r(Ll2/o;I)V

    .line 904
    .line 905
    .line 906
    invoke-virtual {v1, v13}, Ll2/t;->q(Z)V

    .line 907
    .line 908
    .line 909
    :goto_7
    const/4 v12, 0x1

    .line 910
    goto :goto_9

    .line 911
    :cond_17
    const/4 v13, 0x0

    .line 912
    iget-boolean v0, v8, Lfh/f;->d:Z

    .line 913
    .line 914
    if-eqz v0, :cond_18

    .line 915
    .line 916
    const v0, -0x5a1badb5

    .line 917
    .line 918
    .line 919
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 920
    .line 921
    .line 922
    invoke-static {v1, v13}, Llp/re;->a(Ll2/o;I)V

    .line 923
    .line 924
    .line 925
    :goto_8
    invoke-virtual {v1, v13}, Ll2/t;->q(Z)V

    .line 926
    .line 927
    .line 928
    goto :goto_7

    .line 929
    :cond_18
    const v0, -0x5a7f1dcb

    .line 930
    .line 931
    .line 932
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 933
    .line 934
    .line 935
    goto :goto_8

    .line 936
    :goto_9
    invoke-virtual {v1, v12}, Ll2/t;->q(Z)V

    .line 937
    .line 938
    .line 939
    const/16 v0, 0x28

    .line 940
    .line 941
    int-to-float v15, v0

    .line 942
    const/16 v16, 0x7

    .line 943
    .line 944
    const/4 v12, 0x0

    .line 945
    const/4 v13, 0x0

    .line 946
    const/4 v14, 0x0

    .line 947
    move-object v11, v9

    .line 948
    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 949
    .line 950
    .line 951
    move-result-object v0

    .line 952
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 953
    .line 954
    .line 955
    move-result-object v2

    .line 956
    if-ne v2, v5, :cond_19

    .line 957
    .line 958
    sget-object v2, Lwk/d;->h:Lwk/d;

    .line 959
    .line 960
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 961
    .line 962
    .line 963
    :cond_19
    check-cast v2, Lay0/k;

    .line 964
    .line 965
    move-object/from16 v3, p2

    .line 966
    .line 967
    invoke-static {v0, v3, v2}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 968
    .line 969
    .line 970
    move-result-object v0

    .line 971
    const-string v2, "wallbox_change_auth_mode_save_cta"

    .line 972
    .line 973
    invoke-static {v0, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 974
    .line 975
    .line 976
    move-result-object v17

    .line 977
    const v0, 0x7f120951

    .line 978
    .line 979
    .line 980
    invoke-static {v1, v0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 981
    .line 982
    .line 983
    move-result-object v15

    .line 984
    iget-boolean v0, v8, Lfh/f;->c:Z

    .line 985
    .line 986
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 987
    .line 988
    .line 989
    move-result v2

    .line 990
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 991
    .line 992
    .line 993
    move-result-object v3

    .line 994
    if-nez v2, :cond_1a

    .line 995
    .line 996
    if-ne v3, v5, :cond_1b

    .line 997
    .line 998
    :cond_1a
    new-instance v3, Lep0/f;

    .line 999
    .line 1000
    const/16 v2, 0x14

    .line 1001
    .line 1002
    invoke-direct {v3, v7, v2}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 1003
    .line 1004
    .line 1005
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1006
    .line 1007
    .line 1008
    :cond_1b
    move-object v13, v3

    .line 1009
    check-cast v13, Lay0/a;

    .line 1010
    .line 1011
    const/4 v11, 0x0

    .line 1012
    const/16 v12, 0x28

    .line 1013
    .line 1014
    const/4 v14, 0x0

    .line 1015
    const/16 v19, 0x0

    .line 1016
    .line 1017
    move/from16 v18, v0

    .line 1018
    .line 1019
    move-object/from16 v16, v1

    .line 1020
    .line 1021
    invoke-static/range {v11 .. v19}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 1022
    .line 1023
    .line 1024
    move-object/from16 v11, v16

    .line 1025
    .line 1026
    const/4 v13, 0x0

    .line 1027
    invoke-virtual {v11, v13}, Ll2/t;->q(Z)V

    .line 1028
    .line 1029
    .line 1030
    move-object/from16 v0, p1

    .line 1031
    .line 1032
    iget v0, v0, Lz4/k;->b:I

    .line 1033
    .line 1034
    move/from16 v1, v35

    .line 1035
    .line 1036
    if-eq v0, v1, :cond_1c

    .line 1037
    .line 1038
    move-object/from16 v6, v38

    .line 1039
    .line 1040
    check-cast v6, Lay0/a;

    .line 1041
    .line 1042
    invoke-static {v6, v11}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 1043
    .line 1044
    .line 1045
    :cond_1c
    :goto_a
    return-object v34

    .line 1046
    :pswitch_1
    move-object/from16 v38, v6

    .line 1047
    .line 1048
    move-object/from16 v39, v7

    .line 1049
    .line 1050
    move-object/from16 v40, v8

    .line 1051
    .line 1052
    move-object/from16 v34, v10

    .line 1053
    .line 1054
    move-object/from16 v17, p1

    .line 1055
    .line 1056
    check-cast v17, Ll2/o;

    .line 1057
    .line 1058
    move-object/from16 v1, p2

    .line 1059
    .line 1060
    check-cast v1, Ljava/lang/Number;

    .line 1061
    .line 1062
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 1063
    .line 1064
    .line 1065
    move-object v12, v9

    .line 1066
    check-cast v12, Lay0/n;

    .line 1067
    .line 1068
    move-object v13, v0

    .line 1069
    check-cast v13, Lay0/p;

    .line 1070
    .line 1071
    move-object/from16 v14, v38

    .line 1072
    .line 1073
    check-cast v14, Lay0/n;

    .line 1074
    .line 1075
    move-object/from16 v15, v40

    .line 1076
    .line 1077
    check-cast v15, Lay0/p;

    .line 1078
    .line 1079
    move-object/from16 v16, v39

    .line 1080
    .line 1081
    check-cast v16, Lt2/b;

    .line 1082
    .line 1083
    const/16 v0, 0x6c31

    .line 1084
    .line 1085
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 1086
    .line 1087
    .line 1088
    move-result v18

    .line 1089
    invoke-static/range {v12 .. v18}, Llp/hc;->a(Lay0/n;Lay0/p;Lay0/n;Lay0/p;Lt2/b;Ll2/o;I)V

    .line 1090
    .line 1091
    .line 1092
    return-object v34

    .line 1093
    :pswitch_2
    move-object/from16 v38, v6

    .line 1094
    .line 1095
    move-object/from16 v39, v7

    .line 1096
    .line 1097
    move-object/from16 v40, v8

    .line 1098
    .line 1099
    move-object/from16 v34, v10

    .line 1100
    .line 1101
    move-object/from16 v1, p1

    .line 1102
    .line 1103
    check-cast v1, Ll2/o;

    .line 1104
    .line 1105
    move-object/from16 v2, p2

    .line 1106
    .line 1107
    check-cast v2, Ljava/lang/Number;

    .line 1108
    .line 1109
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1110
    .line 1111
    .line 1112
    move-result v2

    .line 1113
    move-object/from16 v7, v39

    .line 1114
    .line 1115
    check-cast v7, Lay0/k;

    .line 1116
    .line 1117
    check-cast v0, Lz4/k;

    .line 1118
    .line 1119
    and-int/2addr v2, v13

    .line 1120
    if-ne v2, v11, :cond_1e

    .line 1121
    .line 1122
    move-object v2, v1

    .line 1123
    check-cast v2, Ll2/t;

    .line 1124
    .line 1125
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 1126
    .line 1127
    .line 1128
    move-result v3

    .line 1129
    if-nez v3, :cond_1d

    .line 1130
    .line 1131
    goto :goto_b

    .line 1132
    :cond_1d
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 1133
    .line 1134
    .line 1135
    move-object/from16 v2, v34

    .line 1136
    .line 1137
    goto/16 :goto_14

    .line 1138
    .line 1139
    :cond_1e
    :goto_b
    check-cast v9, Ll2/b1;

    .line 1140
    .line 1141
    move-object/from16 v2, v34

    .line 1142
    .line 1143
    invoke-interface {v9, v2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1144
    .line 1145
    .line 1146
    iget v3, v0, Lz4/k;->b:I

    .line 1147
    .line 1148
    invoke-virtual {v0}, Lz4/k;->e()V

    .line 1149
    .line 1150
    .line 1151
    check-cast v1, Ll2/t;

    .line 1152
    .line 1153
    const v6, -0x793262fd

    .line 1154
    .line 1155
    .line 1156
    invoke-virtual {v1, v6}, Ll2/t;->Y(I)V

    .line 1157
    .line 1158
    .line 1159
    invoke-virtual {v0}, Lz4/k;->d()Lt1/j0;

    .line 1160
    .line 1161
    .line 1162
    move-result-object v6

    .line 1163
    iget-object v6, v6, Lt1/j0;->e:Ljava/lang/Object;

    .line 1164
    .line 1165
    check-cast v6, Lz4/k;

    .line 1166
    .line 1167
    invoke-virtual {v6}, Lz4/k;->c()Lz4/f;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v8

    .line 1171
    invoke-virtual {v6}, Lz4/k;->c()Lz4/f;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v9

    .line 1175
    invoke-virtual {v6}, Lz4/k;->c()Lz4/f;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v6

    .line 1179
    move-object/from16 v10, v40

    .line 1180
    .line 1181
    check-cast v10, Ldi/l;

    .line 1182
    .line 1183
    const v12, 0x7017c522

    .line 1184
    .line 1185
    .line 1186
    invoke-virtual {v1, v12}, Ll2/t;->Y(I)V

    .line 1187
    .line 1188
    .line 1189
    new-instance v12, Lel/e;

    .line 1190
    .line 1191
    const/4 v14, 0x0

    .line 1192
    invoke-direct {v12, v10, v7, v14}, Lel/e;-><init>(Ldi/l;Lay0/k;I)V

    .line 1193
    .line 1194
    .line 1195
    const v14, -0xa345aa3

    .line 1196
    .line 1197
    .line 1198
    invoke-static {v14, v1, v12}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v12

    .line 1202
    new-instance v14, Lel/e;

    .line 1203
    .line 1204
    const/4 v15, 0x1

    .line 1205
    invoke-direct {v14, v10, v7, v15}, Lel/e;-><init>(Ldi/l;Lay0/k;I)V

    .line 1206
    .line 1207
    .line 1208
    const v15, 0x2e87727c

    .line 1209
    .line 1210
    .line 1211
    invoke-static {v15, v1, v14}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1212
    .line 1213
    .line 1214
    move-result-object v14

    .line 1215
    new-instance v15, Lel/e;

    .line 1216
    .line 1217
    invoke-direct {v15, v10, v7, v11}, Lel/e;-><init>(Ldi/l;Lay0/k;I)V

    .line 1218
    .line 1219
    .line 1220
    move/from16 v16, v11

    .line 1221
    .line 1222
    const v11, 0x67433f9b

    .line 1223
    .line 1224
    .line 1225
    invoke-static {v11, v1, v15}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v11

    .line 1229
    new-instance v15, Lel/e;

    .line 1230
    .line 1231
    invoke-direct {v15, v10, v7, v13}, Lel/e;-><init>(Ldi/l;Lay0/k;I)V

    .line 1232
    .line 1233
    .line 1234
    move/from16 v26, v13

    .line 1235
    .line 1236
    const v13, -0x6000f346

    .line 1237
    .line 1238
    .line 1239
    invoke-static {v13, v1, v15}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1240
    .line 1241
    .line 1242
    move-result-object v13

    .line 1243
    const/4 v15, 0x4

    .line 1244
    new-array v15, v15, [Lay0/n;

    .line 1245
    .line 1246
    const/16 v17, 0x0

    .line 1247
    .line 1248
    aput-object v12, v15, v17

    .line 1249
    .line 1250
    const/16 v37, 0x1

    .line 1251
    .line 1252
    aput-object v14, v15, v37

    .line 1253
    .line 1254
    aput-object v11, v15, v16

    .line 1255
    .line 1256
    aput-object v13, v15, v26

    .line 1257
    .line 1258
    invoke-static {v15}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v11

    .line 1262
    iget-boolean v12, v10, Ldi/l;->j:Z

    .line 1263
    .line 1264
    const/16 v13, 0xa

    .line 1265
    .line 1266
    if-eqz v12, :cond_24

    .line 1267
    .line 1268
    const v12, 0x33a8e5d5

    .line 1269
    .line 1270
    .line 1271
    invoke-virtual {v1, v12}, Ll2/t;->Y(I)V

    .line 1272
    .line 1273
    .line 1274
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v12

    .line 1278
    if-ne v12, v5, :cond_1f

    .line 1279
    .line 1280
    sget-object v12, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 1281
    .line 1282
    invoke-static {v12}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v12

    .line 1286
    invoke-virtual {v1, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1287
    .line 1288
    .line 1289
    :cond_1f
    check-cast v12, Ll2/b1;

    .line 1290
    .line 1291
    new-instance v15, Leh/c;

    .line 1292
    .line 1293
    const/16 v14, 0x9

    .line 1294
    .line 1295
    invoke-direct {v15, v12, v14}, Leh/c;-><init>(Ll2/b1;I)V

    .line 1296
    .line 1297
    .line 1298
    const v14, 0x474b9d79

    .line 1299
    .line 1300
    .line 1301
    invoke-static {v14, v1, v15}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1302
    .line 1303
    .line 1304
    move-result-object v14

    .line 1305
    invoke-virtual {v11, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1306
    .line 1307
    .line 1308
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v14

    .line 1312
    check-cast v14, Ljava/lang/Boolean;

    .line 1313
    .line 1314
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1315
    .line 1316
    .line 1317
    move-result v14

    .line 1318
    if-eqz v14, :cond_23

    .line 1319
    .line 1320
    const v14, 0x33b0de05

    .line 1321
    .line 1322
    .line 1323
    invoke-virtual {v1, v14}, Ll2/t;->Y(I)V

    .line 1324
    .line 1325
    .line 1326
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v14

    .line 1330
    if-ne v14, v5, :cond_20

    .line 1331
    .line 1332
    new-instance v14, La2/h;

    .line 1333
    .line 1334
    invoke-direct {v14, v12, v13}, La2/h;-><init>(Ll2/b1;I)V

    .line 1335
    .line 1336
    .line 1337
    invoke-virtual {v1, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1338
    .line 1339
    .line 1340
    :cond_20
    move-object/from16 v18, v14

    .line 1341
    .line 1342
    check-cast v18, Lay0/a;

    .line 1343
    .line 1344
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1345
    .line 1346
    .line 1347
    move-result v14

    .line 1348
    invoke-virtual {v1, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1349
    .line 1350
    .line 1351
    move-result v15

    .line 1352
    or-int/2addr v14, v15

    .line 1353
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v15

    .line 1357
    if-nez v14, :cond_22

    .line 1358
    .line 1359
    if-ne v15, v5, :cond_21

    .line 1360
    .line 1361
    goto :goto_c

    .line 1362
    :cond_21
    const/4 v14, 0x0

    .line 1363
    goto :goto_d

    .line 1364
    :cond_22
    :goto_c
    new-instance v15, Lel/f;

    .line 1365
    .line 1366
    const/4 v14, 0x0

    .line 1367
    invoke-direct {v15, v12, v7, v10, v14}, Lel/f;-><init>(Ll2/b1;Lay0/k;Ldi/l;I)V

    .line 1368
    .line 1369
    .line 1370
    invoke-virtual {v1, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1371
    .line 1372
    .line 1373
    :goto_d
    move-object/from16 v19, v15

    .line 1374
    .line 1375
    check-cast v19, Lay0/a;

    .line 1376
    .line 1377
    const/16 v21, 0x6000

    .line 1378
    .line 1379
    move/from16 v17, v14

    .line 1380
    .line 1381
    const v14, 0x7f120bf3

    .line 1382
    .line 1383
    .line 1384
    const v15, 0x7f120bf1

    .line 1385
    .line 1386
    .line 1387
    const v16, 0x7f120bf0

    .line 1388
    .line 1389
    .line 1390
    move/from16 v12, v17

    .line 1391
    .line 1392
    const v17, 0x7f120bf2

    .line 1393
    .line 1394
    .line 1395
    move-object/from16 v20, v1

    .line 1396
    .line 1397
    const v1, 0x332f22ba

    .line 1398
    .line 1399
    .line 1400
    invoke-static/range {v14 .. v21}, Lel/b;->f(IIIILay0/a;Lay0/a;Ll2/o;I)V

    .line 1401
    .line 1402
    .line 1403
    move-object/from16 v14, v20

    .line 1404
    .line 1405
    :goto_e
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 1406
    .line 1407
    .line 1408
    goto :goto_f

    .line 1409
    :cond_23
    move-object v14, v1

    .line 1410
    const v1, 0x332f22ba

    .line 1411
    .line 1412
    .line 1413
    const/4 v12, 0x0

    .line 1414
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 1415
    .line 1416
    .line 1417
    goto :goto_e

    .line 1418
    :goto_f
    invoke-virtual {v14, v12}, Ll2/t;->q(Z)V

    .line 1419
    .line 1420
    .line 1421
    goto :goto_10

    .line 1422
    :cond_24
    move-object v14, v1

    .line 1423
    const v1, 0x332f22ba

    .line 1424
    .line 1425
    .line 1426
    const/4 v12, 0x0

    .line 1427
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 1428
    .line 1429
    .line 1430
    goto :goto_f

    .line 1431
    :goto_10
    iget-boolean v12, v10, Ldi/l;->j:Z

    .line 1432
    .line 1433
    const/16 v15, 0xc

    .line 1434
    .line 1435
    if-eqz v12, :cond_2a

    .line 1436
    .line 1437
    const v12, 0x33bce3bd

    .line 1438
    .line 1439
    .line 1440
    invoke-virtual {v14, v12}, Ll2/t;->Y(I)V

    .line 1441
    .line 1442
    .line 1443
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1444
    .line 1445
    .line 1446
    move-result-object v12

    .line 1447
    if-ne v12, v5, :cond_25

    .line 1448
    .line 1449
    sget-object v12, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 1450
    .line 1451
    invoke-static {v12}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 1452
    .line 1453
    .line 1454
    move-result-object v12

    .line 1455
    invoke-virtual {v14, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1456
    .line 1457
    .line 1458
    :cond_25
    check-cast v12, Ll2/b1;

    .line 1459
    .line 1460
    new-instance v1, Leh/c;

    .line 1461
    .line 1462
    invoke-direct {v1, v12, v13}, Leh/c;-><init>(Ll2/b1;I)V

    .line 1463
    .line 1464
    .line 1465
    const v13, -0x320b2810

    .line 1466
    .line 1467
    .line 1468
    invoke-static {v13, v14, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1469
    .line 1470
    .line 1471
    move-result-object v1

    .line 1472
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1473
    .line 1474
    .line 1475
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1476
    .line 1477
    .line 1478
    move-result-object v1

    .line 1479
    check-cast v1, Ljava/lang/Boolean;

    .line 1480
    .line 1481
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1482
    .line 1483
    .line 1484
    move-result v1

    .line 1485
    if-eqz v1, :cond_29

    .line 1486
    .line 1487
    const v1, 0x33c4c567

    .line 1488
    .line 1489
    .line 1490
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 1491
    .line 1492
    .line 1493
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1494
    .line 1495
    .line 1496
    move-result-object v1

    .line 1497
    if-ne v1, v5, :cond_26

    .line 1498
    .line 1499
    new-instance v1, La2/h;

    .line 1500
    .line 1501
    invoke-direct {v1, v12, v15}, La2/h;-><init>(Ll2/b1;I)V

    .line 1502
    .line 1503
    .line 1504
    invoke-virtual {v14, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1505
    .line 1506
    .line 1507
    :cond_26
    move-object/from16 v18, v1

    .line 1508
    .line 1509
    check-cast v18, Lay0/a;

    .line 1510
    .line 1511
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1512
    .line 1513
    .line 1514
    move-result v1

    .line 1515
    invoke-virtual {v14, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1516
    .line 1517
    .line 1518
    move-result v13

    .line 1519
    or-int/2addr v1, v13

    .line 1520
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1521
    .line 1522
    .line 1523
    move-result-object v13

    .line 1524
    if-nez v1, :cond_27

    .line 1525
    .line 1526
    if-ne v13, v5, :cond_28

    .line 1527
    .line 1528
    :cond_27
    new-instance v13, Lel/f;

    .line 1529
    .line 1530
    const/4 v1, 0x1

    .line 1531
    invoke-direct {v13, v12, v7, v10, v1}, Lel/f;-><init>(Ll2/b1;Lay0/k;Ldi/l;I)V

    .line 1532
    .line 1533
    .line 1534
    invoke-virtual {v14, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1535
    .line 1536
    .line 1537
    :cond_28
    move-object/from16 v19, v13

    .line 1538
    .line 1539
    check-cast v19, Lay0/a;

    .line 1540
    .line 1541
    const/16 v21, 0x6000

    .line 1542
    .line 1543
    move-object/from16 v20, v14

    .line 1544
    .line 1545
    const v14, 0x7f120c15

    .line 1546
    .line 1547
    .line 1548
    move v1, v15

    .line 1549
    const v15, 0x7f120c13

    .line 1550
    .line 1551
    .line 1552
    const v16, 0x7f120c12

    .line 1553
    .line 1554
    .line 1555
    const v17, 0x7f120c14

    .line 1556
    .line 1557
    .line 1558
    invoke-static/range {v14 .. v21}, Lel/b;->f(IIIILay0/a;Lay0/a;Ll2/o;I)V

    .line 1559
    .line 1560
    .line 1561
    move-object/from16 v14, v20

    .line 1562
    .line 1563
    const/4 v13, 0x0

    .line 1564
    :goto_11
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 1565
    .line 1566
    .line 1567
    goto :goto_12

    .line 1568
    :cond_29
    move v1, v15

    .line 1569
    const v10, 0x332f22ba

    .line 1570
    .line 1571
    .line 1572
    const/4 v13, 0x0

    .line 1573
    invoke-virtual {v14, v10}, Ll2/t;->Y(I)V

    .line 1574
    .line 1575
    .line 1576
    goto :goto_11

    .line 1577
    :goto_12
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 1578
    .line 1579
    .line 1580
    goto :goto_13

    .line 1581
    :cond_2a
    move v10, v1

    .line 1582
    move v1, v15

    .line 1583
    const/4 v13, 0x0

    .line 1584
    invoke-virtual {v14, v10}, Ll2/t;->Y(I)V

    .line 1585
    .line 1586
    .line 1587
    goto :goto_12

    .line 1588
    :goto_13
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 1589
    .line 1590
    .line 1591
    invoke-static {v11}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 1592
    .line 1593
    .line 1594
    move-result-object v10

    .line 1595
    const/high16 v11, 0x3f800000    # 1.0f

    .line 1596
    .line 1597
    invoke-static {v4, v11}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 1598
    .line 1599
    .line 1600
    move-result-object v11

    .line 1601
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v12

    .line 1605
    if-ne v12, v5, :cond_2b

    .line 1606
    .line 1607
    sget-object v12, Lel/d;->g:Lel/d;

    .line 1608
    .line 1609
    invoke-virtual {v14, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1610
    .line 1611
    .line 1612
    :cond_2b
    check-cast v12, Lay0/k;

    .line 1613
    .line 1614
    invoke-static {v11, v8, v12}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 1615
    .line 1616
    .line 1617
    move-result-object v8

    .line 1618
    invoke-virtual {v14, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1619
    .line 1620
    .line 1621
    move-result v11

    .line 1622
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1623
    .line 1624
    .line 1625
    move-result-object v12

    .line 1626
    if-nez v11, :cond_2c

    .line 1627
    .line 1628
    if-ne v12, v5, :cond_2d

    .line 1629
    .line 1630
    :cond_2c
    new-instance v12, Lak/p;

    .line 1631
    .line 1632
    invoke-direct {v12, v10, v1}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 1633
    .line 1634
    .line 1635
    invoke-virtual {v14, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1636
    .line 1637
    .line 1638
    :cond_2d
    move-object/from16 v22, v12

    .line 1639
    .line 1640
    check-cast v22, Lay0/k;

    .line 1641
    .line 1642
    const/16 v24, 0x0

    .line 1643
    .line 1644
    const/16 v25, 0x1fe

    .line 1645
    .line 1646
    const/4 v15, 0x0

    .line 1647
    const/16 v16, 0x0

    .line 1648
    .line 1649
    const/16 v17, 0x0

    .line 1650
    .line 1651
    const/16 v18, 0x0

    .line 1652
    .line 1653
    const/16 v19, 0x0

    .line 1654
    .line 1655
    const/16 v20, 0x0

    .line 1656
    .line 1657
    const/16 v21, 0x0

    .line 1658
    .line 1659
    move-object/from16 v23, v14

    .line 1660
    .line 1661
    move-object v14, v8

    .line 1662
    invoke-static/range {v14 .. v25}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 1663
    .line 1664
    .line 1665
    move-object/from16 v14, v23

    .line 1666
    .line 1667
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1668
    .line 1669
    .line 1670
    move-result v1

    .line 1671
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1672
    .line 1673
    .line 1674
    move-result-object v8

    .line 1675
    if-nez v1, :cond_2e

    .line 1676
    .line 1677
    if-ne v8, v5, :cond_2f

    .line 1678
    .line 1679
    :cond_2e
    new-instance v8, Lc40/g;

    .line 1680
    .line 1681
    move/from16 v1, v26

    .line 1682
    .line 1683
    invoke-direct {v8, v6, v1}, Lc40/g;-><init>(Lz4/f;I)V

    .line 1684
    .line 1685
    .line 1686
    invoke-virtual {v14, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1687
    .line 1688
    .line 1689
    :cond_2f
    check-cast v8, Lay0/k;

    .line 1690
    .line 1691
    invoke-static {v4, v9, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 1692
    .line 1693
    .line 1694
    move-result-object v15

    .line 1695
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 1696
    .line 1697
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1698
    .line 1699
    .line 1700
    move-result-object v8

    .line 1701
    check-cast v8, Lj91/c;

    .line 1702
    .line 1703
    iget v8, v8, Lj91/c;->e:F

    .line 1704
    .line 1705
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1706
    .line 1707
    .line 1708
    move-result-object v9

    .line 1709
    check-cast v9, Lj91/c;

    .line 1710
    .line 1711
    iget v9, v9, Lj91/c;->d:F

    .line 1712
    .line 1713
    const/16 v20, 0x5

    .line 1714
    .line 1715
    const/16 v16, 0x0

    .line 1716
    .line 1717
    const/16 v18, 0x0

    .line 1718
    .line 1719
    move/from16 v17, v8

    .line 1720
    .line 1721
    move/from16 v19, v9

    .line 1722
    .line 1723
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 1724
    .line 1725
    .line 1726
    move-result-object v8

    .line 1727
    const/4 v13, 0x0

    .line 1728
    invoke-static {v8, v7, v14, v13}, Lel/b;->b(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 1729
    .line 1730
    .line 1731
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 1732
    .line 1733
    .line 1734
    move-result-object v8

    .line 1735
    if-ne v8, v5, :cond_30

    .line 1736
    .line 1737
    sget-object v8, Lel/d;->h:Lel/d;

    .line 1738
    .line 1739
    invoke-virtual {v14, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1740
    .line 1741
    .line 1742
    :cond_30
    check-cast v8, Lay0/k;

    .line 1743
    .line 1744
    invoke-static {v4, v6, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 1745
    .line 1746
    .line 1747
    move-result-object v15

    .line 1748
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1749
    .line 1750
    .line 1751
    move-result-object v1

    .line 1752
    check-cast v1, Lj91/c;

    .line 1753
    .line 1754
    iget v1, v1, Lj91/c;->c:F

    .line 1755
    .line 1756
    const/16 v20, 0x7

    .line 1757
    .line 1758
    const/16 v16, 0x0

    .line 1759
    .line 1760
    const/16 v17, 0x0

    .line 1761
    .line 1762
    const/16 v18, 0x0

    .line 1763
    .line 1764
    move/from16 v19, v1

    .line 1765
    .line 1766
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 1767
    .line 1768
    .line 1769
    move-result-object v1

    .line 1770
    const/4 v13, 0x0

    .line 1771
    invoke-static {v1, v7, v14, v13}, Lel/b;->e(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 1772
    .line 1773
    .line 1774
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 1775
    .line 1776
    .line 1777
    iget v0, v0, Lz4/k;->b:I

    .line 1778
    .line 1779
    if-eq v0, v3, :cond_31

    .line 1780
    .line 1781
    move-object/from16 v6, v38

    .line 1782
    .line 1783
    check-cast v6, Lay0/a;

    .line 1784
    .line 1785
    invoke-static {v6, v14}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 1786
    .line 1787
    .line 1788
    :cond_31
    :goto_14
    return-object v2

    .line 1789
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
