.class public final Lca0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lca0/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lca0/g;->e:Ljava/util/ArrayList;

    .line 4
    .line 5
    iput-object p2, p0, Lca0/g;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lca0/g;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move-object/from16 v3, p3

    .line 21
    .line 22
    check-cast v3, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v4, p4

    .line 25
    .line 26
    check-cast v4, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    and-int/lit8 v5, v4, 0x6

    .line 33
    .line 34
    if-nez v5, :cond_1

    .line 35
    .line 36
    move-object v5, v3

    .line 37
    check-cast v5, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    const/4 v1, 0x4

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v1, 0x2

    .line 48
    :goto_0
    or-int/2addr v1, v4

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move v1, v4

    .line 51
    :goto_1
    and-int/lit8 v4, v4, 0x30

    .line 52
    .line 53
    if-nez v4, :cond_3

    .line 54
    .line 55
    move-object v4, v3

    .line 56
    check-cast v4, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_2

    .line 63
    .line 64
    const/16 v4, 0x20

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_2
    const/16 v4, 0x10

    .line 68
    .line 69
    :goto_2
    or-int/2addr v1, v4

    .line 70
    :cond_3
    and-int/lit16 v4, v1, 0x93

    .line 71
    .line 72
    const/16 v5, 0x92

    .line 73
    .line 74
    const/4 v6, 0x1

    .line 75
    const/4 v7, 0x0

    .line 76
    if-eq v4, v5, :cond_4

    .line 77
    .line 78
    move v4, v6

    .line 79
    goto :goto_3

    .line 80
    :cond_4
    move v4, v7

    .line 81
    :goto_3
    and-int/2addr v1, v6

    .line 82
    check-cast v3, Ll2/t;

    .line 83
    .line 84
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_5

    .line 89
    .line 90
    iget-object v1, v0, Lca0/g;->e:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    check-cast v1, Lzc/a;

    .line 97
    .line 98
    const v2, 0x21d83189

    .line 99
    .line 100
    .line 101
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 102
    .line 103
    .line 104
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 105
    .line 106
    invoke-virtual {v3, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    check-cast v4, Lj91/c;

    .line 111
    .line 112
    iget v4, v4, Lj91/c;->e:F

    .line 113
    .line 114
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 115
    .line 116
    invoke-static {v5, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    invoke-static {v3, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 121
    .line 122
    .line 123
    new-instance v4, Le1/u;

    .line 124
    .line 125
    const/16 v6, 0xa

    .line 126
    .line 127
    invoke-direct {v4, v1, v6}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 128
    .line 129
    .line 130
    const v6, -0x1c5daf53

    .line 131
    .line 132
    .line 133
    invoke-static {v6, v3, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    const/16 v6, 0x188

    .line 138
    .line 139
    iget-object v0, v0, Lca0/g;->f:Lay0/k;

    .line 140
    .line 141
    invoke-static {v1, v0, v4, v3, v6}, Lxj/k;->f(Lzc/a;Lay0/k;Lt2/b;Ll2/o;I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v3, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    check-cast v0, Lj91/c;

    .line 149
    .line 150
    iget v0, v0, Lj91/c;->d:F

    .line 151
    .line 152
    invoke-static {v5, v0, v3, v7}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 153
    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_5
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 157
    .line 158
    .line 159
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    return-object v0

    .line 162
    :pswitch_0
    move-object/from16 v1, p1

    .line 163
    .line 164
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 165
    .line 166
    move-object/from16 v2, p2

    .line 167
    .line 168
    check-cast v2, Ljava/lang/Number;

    .line 169
    .line 170
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 171
    .line 172
    .line 173
    move-result v2

    .line 174
    move-object/from16 v3, p3

    .line 175
    .line 176
    check-cast v3, Ll2/o;

    .line 177
    .line 178
    move-object/from16 v4, p4

    .line 179
    .line 180
    check-cast v4, Ljava/lang/Number;

    .line 181
    .line 182
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    and-int/lit8 v5, v4, 0x6

    .line 187
    .line 188
    const/4 v6, 0x4

    .line 189
    const/4 v7, 0x2

    .line 190
    if-nez v5, :cond_7

    .line 191
    .line 192
    move-object v5, v3

    .line 193
    check-cast v5, Ll2/t;

    .line 194
    .line 195
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v1

    .line 199
    if-eqz v1, :cond_6

    .line 200
    .line 201
    move v1, v6

    .line 202
    goto :goto_5

    .line 203
    :cond_6
    move v1, v7

    .line 204
    :goto_5
    or-int/2addr v1, v4

    .line 205
    goto :goto_6

    .line 206
    :cond_7
    move v1, v4

    .line 207
    :goto_6
    and-int/lit8 v4, v4, 0x30

    .line 208
    .line 209
    const/16 v5, 0x10

    .line 210
    .line 211
    if-nez v4, :cond_9

    .line 212
    .line 213
    move-object v4, v3

    .line 214
    check-cast v4, Ll2/t;

    .line 215
    .line 216
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 217
    .line 218
    .line 219
    move-result v4

    .line 220
    if-eqz v4, :cond_8

    .line 221
    .line 222
    const/16 v4, 0x20

    .line 223
    .line 224
    goto :goto_7

    .line 225
    :cond_8
    move v4, v5

    .line 226
    :goto_7
    or-int/2addr v1, v4

    .line 227
    :cond_9
    and-int/lit16 v4, v1, 0x93

    .line 228
    .line 229
    const/16 v8, 0x92

    .line 230
    .line 231
    const/4 v9, 0x1

    .line 232
    const/4 v10, 0x0

    .line 233
    if-eq v4, v8, :cond_a

    .line 234
    .line 235
    move v4, v9

    .line 236
    goto :goto_8

    .line 237
    :cond_a
    move v4, v10

    .line 238
    :goto_8
    and-int/2addr v1, v9

    .line 239
    check-cast v3, Ll2/t;

    .line 240
    .line 241
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 242
    .line 243
    .line 244
    move-result v1

    .line 245
    if-eqz v1, :cond_15

    .line 246
    .line 247
    iget-object v1, v0, Lca0/g;->e:Ljava/util/ArrayList;

    .line 248
    .line 249
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    check-cast v1, Lhc/c;

    .line 254
    .line 255
    const v4, 0xa51ef82

    .line 256
    .line 257
    .line 258
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v4

    .line 265
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 266
    .line 267
    if-ne v4, v8, :cond_b

    .line 268
    .line 269
    const/4 v4, 0x0

    .line 270
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    invoke-virtual {v3, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    :cond_b
    check-cast v4, Ll2/b1;

    .line 278
    .line 279
    iget-object v11, v1, Lhc/c;->d:Lgl/h;

    .line 280
    .line 281
    iget-object v1, v1, Lhc/c;->e:Lhc/b;

    .line 282
    .line 283
    invoke-static {v3}, Ldk/b;->o(Ll2/o;)Lg4/g0;

    .line 284
    .line 285
    .line 286
    move-result-object v12

    .line 287
    invoke-static {v11, v12, v3}, Lhl/a;->b(Lgl/h;Lg4/g0;Ll2/o;)Lg4/g;

    .line 288
    .line 289
    .line 290
    move-result-object v11

    .line 291
    sget-object v12, Lfk/c;->a:[I

    .line 292
    .line 293
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 294
    .line 295
    .line 296
    move-result v13

    .line 297
    aget v12, v12, v13

    .line 298
    .line 299
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 300
    .line 301
    if-ne v12, v9, :cond_c

    .line 302
    .line 303
    const/16 v5, 0x18

    .line 304
    .line 305
    int-to-float v5, v5

    .line 306
    const/4 v12, 0x0

    .line 307
    invoke-static {v13, v12, v5, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 308
    .line 309
    .line 310
    move-result-object v5

    .line 311
    goto :goto_9

    .line 312
    :cond_c
    int-to-float v15, v5

    .line 313
    const/16 v5, 0x8

    .line 314
    .line 315
    int-to-float v5, v5

    .line 316
    const/16 v18, 0x5

    .line 317
    .line 318
    const/4 v14, 0x0

    .line 319
    const/16 v16, 0x0

    .line 320
    .line 321
    move/from16 v17, v5

    .line 322
    .line 323
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    :goto_9
    sget-object v12, Lfk/d;->a:Lzb/u;

    .line 328
    .line 329
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 330
    .line 331
    .line 332
    new-instance v12, Ljava/lang/StringBuilder;

    .line 333
    .line 334
    const-string v13, "consents_document_item_"

    .line 335
    .line 336
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v12, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 340
    .line 341
    .line 342
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    invoke-static {v5, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 347
    .line 348
    .line 349
    move-result-object v2

    .line 350
    iget-object v0, v0, Lca0/g;->f:Lay0/k;

    .line 351
    .line 352
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 353
    .line 354
    .line 355
    move-result v5

    .line 356
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v12

    .line 360
    if-nez v5, :cond_d

    .line 361
    .line 362
    if-ne v12, v8, :cond_e

    .line 363
    .line 364
    :cond_d
    new-instance v12, Lfk/b;

    .line 365
    .line 366
    const/4 v5, 0x0

    .line 367
    invoke-direct {v12, v5, v0}, Lfk/b;-><init>(ILay0/k;)V

    .line 368
    .line 369
    .line 370
    invoke-virtual {v3, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 371
    .line 372
    .line 373
    :cond_e
    check-cast v12, Lay0/k;

    .line 374
    .line 375
    invoke-static {v2, v4, v12}, Lhl/a;->a(Lx2/s;Ll2/b1;Lay0/k;)Lx2/s;

    .line 376
    .line 377
    .line 378
    move-result-object v12

    .line 379
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 380
    .line 381
    .line 382
    move-result v0

    .line 383
    if-eqz v0, :cond_13

    .line 384
    .line 385
    if-eq v0, v9, :cond_12

    .line 386
    .line 387
    if-eq v0, v7, :cond_11

    .line 388
    .line 389
    const/4 v1, 0x3

    .line 390
    if-eq v0, v1, :cond_10

    .line 391
    .line 392
    if-ne v0, v6, :cond_f

    .line 393
    .line 394
    const v0, 0x56db878c

    .line 395
    .line 396
    .line 397
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 398
    .line 399
    .line 400
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 401
    .line 402
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    check-cast v0, Lj91/f;

    .line 407
    .line 408
    invoke-virtual {v0}, Lj91/f;->e()Lg4/p0;

    .line 409
    .line 410
    .line 411
    move-result-object v0

    .line 412
    invoke-virtual {v3, v10}, Ll2/t;->q(Z)V

    .line 413
    .line 414
    .line 415
    :goto_a
    move-object v13, v0

    .line 416
    goto :goto_b

    .line 417
    :cond_f
    const v0, 0x56db5877    # 1.205865E14f

    .line 418
    .line 419
    .line 420
    invoke-static {v0, v3, v10}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 421
    .line 422
    .line 423
    move-result-object v0

    .line 424
    throw v0

    .line 425
    :cond_10
    const v0, 0x56db7de7

    .line 426
    .line 427
    .line 428
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 429
    .line 430
    .line 431
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 432
    .line 433
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object v0

    .line 437
    check-cast v0, Lj91/f;

    .line 438
    .line 439
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 440
    .line 441
    .line 442
    move-result-object v0

    .line 443
    invoke-virtual {v3, v10}, Ll2/t;->q(Z)V

    .line 444
    .line 445
    .line 446
    goto :goto_a

    .line 447
    :cond_11
    const v0, 0x56db74c9

    .line 448
    .line 449
    .line 450
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 451
    .line 452
    .line 453
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 454
    .line 455
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v0

    .line 459
    check-cast v0, Lj91/f;

    .line 460
    .line 461
    invoke-virtual {v0}, Lj91/f;->j()Lg4/p0;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    invoke-virtual {v3, v10}, Ll2/t;->q(Z)V

    .line 466
    .line 467
    .line 468
    goto :goto_a

    .line 469
    :cond_12
    const v0, 0x56db6b49

    .line 470
    .line 471
    .line 472
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 473
    .line 474
    .line 475
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 476
    .line 477
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v0

    .line 481
    check-cast v0, Lj91/f;

    .line 482
    .line 483
    invoke-virtual {v0}, Lj91/f;->i()Lg4/p0;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    invoke-virtual {v3, v10}, Ll2/t;->q(Z)V

    .line 488
    .line 489
    .line 490
    goto :goto_a

    .line 491
    :cond_13
    const v0, 0x56db61c9

    .line 492
    .line 493
    .line 494
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 495
    .line 496
    .line 497
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 498
    .line 499
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    check-cast v0, Lj91/f;

    .line 504
    .line 505
    invoke-virtual {v0}, Lj91/f;->i()Lg4/p0;

    .line 506
    .line 507
    .line 508
    move-result-object v0

    .line 509
    invoke-virtual {v3, v10}, Ll2/t;->q(Z)V

    .line 510
    .line 511
    .line 512
    goto :goto_a

    .line 513
    :goto_b
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    if-ne v0, v8, :cond_14

    .line 518
    .line 519
    new-instance v0, Lag/t;

    .line 520
    .line 521
    const/4 v1, 0x5

    .line 522
    invoke-direct {v0, v4, v1}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 523
    .line 524
    .line 525
    invoke-virtual {v3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 526
    .line 527
    .line 528
    :cond_14
    move-object/from16 v26, v0

    .line 529
    .line 530
    check-cast v26, Lay0/k;

    .line 531
    .line 532
    const/high16 v29, 0x30000

    .line 533
    .line 534
    const/16 v30, 0x7ff8

    .line 535
    .line 536
    const-wide/16 v14, 0x0

    .line 537
    .line 538
    const-wide/16 v16, 0x0

    .line 539
    .line 540
    const-wide/16 v18, 0x0

    .line 541
    .line 542
    const/16 v20, 0x0

    .line 543
    .line 544
    const-wide/16 v21, 0x0

    .line 545
    .line 546
    const/16 v23, 0x0

    .line 547
    .line 548
    const/16 v24, 0x0

    .line 549
    .line 550
    const/16 v25, 0x0

    .line 551
    .line 552
    const/16 v28, 0x0

    .line 553
    .line 554
    move-object/from16 v27, v3

    .line 555
    .line 556
    invoke-static/range {v11 .. v30}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 557
    .line 558
    .line 559
    invoke-virtual {v3, v10}, Ll2/t;->q(Z)V

    .line 560
    .line 561
    .line 562
    goto :goto_c

    .line 563
    :cond_15
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 564
    .line 565
    .line 566
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 567
    .line 568
    return-object v0

    .line 569
    :pswitch_1
    move-object/from16 v1, p1

    .line 570
    .line 571
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 572
    .line 573
    move-object/from16 v2, p2

    .line 574
    .line 575
    check-cast v2, Ljava/lang/Number;

    .line 576
    .line 577
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 578
    .line 579
    .line 580
    move-result v2

    .line 581
    move-object/from16 v3, p3

    .line 582
    .line 583
    check-cast v3, Ll2/o;

    .line 584
    .line 585
    move-object/from16 v4, p4

    .line 586
    .line 587
    check-cast v4, Ljava/lang/Number;

    .line 588
    .line 589
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 590
    .line 591
    .line 592
    move-result v4

    .line 593
    and-int/lit8 v5, v4, 0x6

    .line 594
    .line 595
    const/4 v6, 0x2

    .line 596
    if-nez v5, :cond_17

    .line 597
    .line 598
    move-object v5, v3

    .line 599
    check-cast v5, Ll2/t;

    .line 600
    .line 601
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 602
    .line 603
    .line 604
    move-result v1

    .line 605
    if-eqz v1, :cond_16

    .line 606
    .line 607
    const/4 v1, 0x4

    .line 608
    goto :goto_d

    .line 609
    :cond_16
    move v1, v6

    .line 610
    :goto_d
    or-int/2addr v1, v4

    .line 611
    goto :goto_e

    .line 612
    :cond_17
    move v1, v4

    .line 613
    :goto_e
    and-int/lit8 v4, v4, 0x30

    .line 614
    .line 615
    if-nez v4, :cond_19

    .line 616
    .line 617
    move-object v4, v3

    .line 618
    check-cast v4, Ll2/t;

    .line 619
    .line 620
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 621
    .line 622
    .line 623
    move-result v4

    .line 624
    if-eqz v4, :cond_18

    .line 625
    .line 626
    const/16 v4, 0x20

    .line 627
    .line 628
    goto :goto_f

    .line 629
    :cond_18
    const/16 v4, 0x10

    .line 630
    .line 631
    :goto_f
    or-int/2addr v1, v4

    .line 632
    :cond_19
    and-int/lit16 v4, v1, 0x93

    .line 633
    .line 634
    const/16 v5, 0x92

    .line 635
    .line 636
    const/4 v7, 0x1

    .line 637
    const/4 v8, 0x0

    .line 638
    if-eq v4, v5, :cond_1a

    .line 639
    .line 640
    move v4, v7

    .line 641
    goto :goto_10

    .line 642
    :cond_1a
    move v4, v8

    .line 643
    :goto_10
    and-int/2addr v1, v7

    .line 644
    move-object v12, v3

    .line 645
    check-cast v12, Ll2/t;

    .line 646
    .line 647
    invoke-virtual {v12, v1, v4}, Ll2/t;->O(IZ)Z

    .line 648
    .line 649
    .line 650
    move-result v1

    .line 651
    if-eqz v1, :cond_1e

    .line 652
    .line 653
    iget-object v1, v0, Lca0/g;->e:Ljava/util/ArrayList;

    .line 654
    .line 655
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 656
    .line 657
    .line 658
    move-result-object v1

    .line 659
    check-cast v1, Lba0/j;

    .line 660
    .line 661
    const v3, -0x6d455d38

    .line 662
    .line 663
    .line 664
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 665
    .line 666
    .line 667
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 668
    .line 669
    if-lez v2, :cond_1b

    .line 670
    .line 671
    const v2, -0x6d4578f4

    .line 672
    .line 673
    .line 674
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 675
    .line 676
    .line 677
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 678
    .line 679
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 680
    .line 681
    .line 682
    move-result-object v2

    .line 683
    check-cast v2, Lj91/c;

    .line 684
    .line 685
    iget v2, v2, Lj91/c;->k:F

    .line 686
    .line 687
    const/4 v4, 0x0

    .line 688
    invoke-static {v3, v2, v4, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 689
    .line 690
    .line 691
    move-result-object v2

    .line 692
    invoke-static {v8, v8, v12, v2}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 693
    .line 694
    .line 695
    :goto_11
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    .line 696
    .line 697
    .line 698
    goto :goto_12

    .line 699
    :cond_1b
    const v2, -0x6d9e1553

    .line 700
    .line 701
    .line 702
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 703
    .line 704
    .line 705
    goto :goto_11

    .line 706
    :goto_12
    iget v2, v1, Lba0/j;->a:I

    .line 707
    .line 708
    invoke-static {v12, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 709
    .line 710
    .line 711
    move-result-object v14

    .line 712
    new-instance v2, Li91/q1;

    .line 713
    .line 714
    iget v4, v1, Lba0/j;->b:I

    .line 715
    .line 716
    const/4 v5, 0x0

    .line 717
    const/4 v6, 0x6

    .line 718
    invoke-direct {v2, v4, v5, v6}, Li91/q1;-><init>(ILe3/s;I)V

    .line 719
    .line 720
    .line 721
    new-instance v4, Li91/p1;

    .line 722
    .line 723
    const v5, 0x7f08033b

    .line 724
    .line 725
    .line 726
    invoke-direct {v4, v5}, Li91/p1;-><init>(I)V

    .line 727
    .line 728
    .line 729
    iget-object v0, v0, Lca0/g;->f:Lay0/k;

    .line 730
    .line 731
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 732
    .line 733
    .line 734
    move-result v5

    .line 735
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 736
    .line 737
    .line 738
    move-result v6

    .line 739
    or-int/2addr v5, v6

    .line 740
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 741
    .line 742
    .line 743
    move-result-object v6

    .line 744
    if-nez v5, :cond_1c

    .line 745
    .line 746
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 747
    .line 748
    if-ne v6, v5, :cond_1d

    .line 749
    .line 750
    :cond_1c
    new-instance v6, Lc41/f;

    .line 751
    .line 752
    const/4 v5, 0x1

    .line 753
    invoke-direct {v6, v5, v0, v1}, Lc41/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 754
    .line 755
    .line 756
    invoke-virtual {v12, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 757
    .line 758
    .line 759
    :cond_1d
    move-object/from16 v22, v6

    .line 760
    .line 761
    check-cast v22, Lay0/a;

    .line 762
    .line 763
    new-instance v13, Li91/c2;

    .line 764
    .line 765
    const/4 v15, 0x0

    .line 766
    const/16 v18, 0x0

    .line 767
    .line 768
    const/16 v19, 0x0

    .line 769
    .line 770
    const/16 v20, 0x0

    .line 771
    .line 772
    const/16 v21, 0x0

    .line 773
    .line 774
    const/16 v23, 0x7f2

    .line 775
    .line 776
    move-object/from16 v16, v2

    .line 777
    .line 778
    move-object/from16 v17, v4

    .line 779
    .line 780
    invoke-direct/range {v13 .. v23}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 781
    .line 782
    .line 783
    iget v0, v1, Lba0/j;->a:I

    .line 784
    .line 785
    invoke-static {v3, v0}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 786
    .line 787
    .line 788
    move-result-object v10

    .line 789
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 790
    .line 791
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 792
    .line 793
    .line 794
    move-result-object v0

    .line 795
    check-cast v0, Lj91/c;

    .line 796
    .line 797
    iget v11, v0, Lj91/c;->k:F

    .line 798
    .line 799
    move-object v9, v13

    .line 800
    const/4 v13, 0x0

    .line 801
    const/4 v14, 0x0

    .line 802
    invoke-static/range {v9 .. v14}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 803
    .line 804
    .line 805
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    .line 806
    .line 807
    .line 808
    goto :goto_13

    .line 809
    :cond_1e
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 810
    .line 811
    .line 812
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 813
    .line 814
    return-object v0

    .line 815
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
