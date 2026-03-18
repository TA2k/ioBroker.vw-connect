.class public final Li40/h2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(IILay0/k;Ljava/util/List;)V
    .locals 0

    .line 1
    iput p2, p0, Li40/h2;->d:I

    .line 2
    .line 3
    iput-object p4, p0, Li40/h2;->g:Ljava/util/List;

    .line 4
    .line 5
    iput p1, p0, Li40/h2;->e:I

    .line 6
    .line 7
    iput-object p3, p0, Li40/h2;->f:Lay0/k;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/h2;->d:I

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
    const/4 v6, 0x2

    .line 35
    if-nez v5, :cond_1

    .line 36
    .line 37
    move-object v5, v3

    .line 38
    check-cast v5, Ll2/t;

    .line 39
    .line 40
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_0

    .line 45
    .line 46
    const/4 v1, 0x4

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move v1, v6

    .line 49
    :goto_0
    or-int/2addr v1, v4

    .line 50
    goto :goto_1

    .line 51
    :cond_1
    move v1, v4

    .line 52
    :goto_1
    and-int/lit8 v4, v4, 0x30

    .line 53
    .line 54
    const/16 v5, 0x20

    .line 55
    .line 56
    if-nez v4, :cond_3

    .line 57
    .line 58
    move-object v4, v3

    .line 59
    check-cast v4, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_2

    .line 66
    .line 67
    move v4, v5

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    const/16 v4, 0x10

    .line 70
    .line 71
    :goto_2
    or-int/2addr v1, v4

    .line 72
    :cond_3
    and-int/lit16 v4, v1, 0x93

    .line 73
    .line 74
    const/16 v7, 0x92

    .line 75
    .line 76
    const/4 v8, 0x1

    .line 77
    const/4 v9, 0x0

    .line 78
    if-eq v4, v7, :cond_4

    .line 79
    .line 80
    move v4, v8

    .line 81
    goto :goto_3

    .line 82
    :cond_4
    move v4, v9

    .line 83
    :goto_3
    and-int/lit8 v7, v1, 0x1

    .line 84
    .line 85
    check-cast v3, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {v3, v7, v4}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-eqz v4, :cond_c

    .line 92
    .line 93
    iget-object v4, v0, Li40/h2;->g:Ljava/util/List;

    .line 94
    .line 95
    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    move-object v10, v4

    .line 100
    check-cast v10, Ljava/lang/String;

    .line 101
    .line 102
    const v4, -0x17fa95cb

    .line 103
    .line 104
    .line 105
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 106
    .line 107
    .line 108
    if-lez v2, :cond_5

    .line 109
    .line 110
    const v4, -0x17fa96c4

    .line 111
    .line 112
    .line 113
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 114
    .line 115
    .line 116
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 117
    .line 118
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    check-cast v4, Lj91/c;

    .line 123
    .line 124
    iget v4, v4, Lj91/c;->k:F

    .line 125
    .line 126
    const/4 v7, 0x0

    .line 127
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 128
    .line 129
    invoke-static {v11, v4, v7, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    invoke-static {v9, v9, v3, v4}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 134
    .line 135
    .line 136
    :goto_4
    invoke-virtual {v3, v9}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_5
    const v4, -0x181fbe13

    .line 141
    .line 142
    .line 143
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    goto :goto_4

    .line 147
    :goto_5
    iget v4, v0, Li40/h2;->e:I

    .line 148
    .line 149
    if-ne v2, v4, :cond_6

    .line 150
    .line 151
    new-instance v4, Li91/p1;

    .line 152
    .line 153
    const v6, 0x7f080321

    .line 154
    .line 155
    .line 156
    invoke-direct {v4, v6}, Li91/p1;-><init>(I)V

    .line 157
    .line 158
    .line 159
    :goto_6
    move-object v14, v4

    .line 160
    goto :goto_7

    .line 161
    :cond_6
    const/4 v4, 0x0

    .line 162
    goto :goto_6

    .line 163
    :goto_7
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 164
    .line 165
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    check-cast v4, Lj91/c;

    .line 170
    .line 171
    iget v4, v4, Lj91/c;->k:F

    .line 172
    .line 173
    iget-object v0, v0, Li40/h2;->f:Lay0/k;

    .line 174
    .line 175
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v6

    .line 179
    and-int/lit8 v7, v1, 0x70

    .line 180
    .line 181
    xor-int/lit8 v7, v7, 0x30

    .line 182
    .line 183
    if-le v7, v5, :cond_7

    .line 184
    .line 185
    invoke-virtual {v3, v2}, Ll2/t;->e(I)Z

    .line 186
    .line 187
    .line 188
    move-result v7

    .line 189
    if-nez v7, :cond_9

    .line 190
    .line 191
    :cond_7
    and-int/lit8 v1, v1, 0x30

    .line 192
    .line 193
    if-ne v1, v5, :cond_8

    .line 194
    .line 195
    goto :goto_8

    .line 196
    :cond_8
    move v8, v9

    .line 197
    :cond_9
    :goto_8
    or-int v1, v6, v8

    .line 198
    .line 199
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v5

    .line 203
    if-nez v1, :cond_a

    .line 204
    .line 205
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 206
    .line 207
    if-ne v5, v1, :cond_b

    .line 208
    .line 209
    :cond_a
    new-instance v5, Lal/p;

    .line 210
    .line 211
    const/4 v1, 0x2

    .line 212
    invoke-direct {v5, v2, v1, v0}, Lal/p;-><init>(IILay0/k;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    :cond_b
    move-object/from16 v17, v5

    .line 219
    .line 220
    check-cast v17, Lay0/a;

    .line 221
    .line 222
    const/16 v22, 0x0

    .line 223
    .line 224
    const/16 v23, 0xe6e

    .line 225
    .line 226
    const/4 v11, 0x0

    .line 227
    const/4 v12, 0x0

    .line 228
    const/4 v13, 0x0

    .line 229
    const/4 v15, 0x0

    .line 230
    const/16 v16, 0x0

    .line 231
    .line 232
    const/16 v19, 0x0

    .line 233
    .line 234
    const/16 v21, 0x0

    .line 235
    .line 236
    move-object/from16 v20, v3

    .line 237
    .line 238
    move/from16 v18, v4

    .line 239
    .line 240
    invoke-static/range {v10 .. v23}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v3, v9}, Ll2/t;->q(Z)V

    .line 244
    .line 245
    .line 246
    goto :goto_9

    .line 247
    :cond_c
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 248
    .line 249
    .line 250
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 251
    .line 252
    return-object v0

    .line 253
    :pswitch_0
    move-object/from16 v1, p1

    .line 254
    .line 255
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 256
    .line 257
    move-object/from16 v2, p2

    .line 258
    .line 259
    check-cast v2, Ljava/lang/Number;

    .line 260
    .line 261
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 262
    .line 263
    .line 264
    move-result v2

    .line 265
    move-object/from16 v3, p3

    .line 266
    .line 267
    check-cast v3, Ll2/o;

    .line 268
    .line 269
    move-object/from16 v4, p4

    .line 270
    .line 271
    check-cast v4, Ljava/lang/Number;

    .line 272
    .line 273
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 274
    .line 275
    .line 276
    move-result v4

    .line 277
    and-int/lit8 v5, v4, 0x6

    .line 278
    .line 279
    const/4 v6, 0x2

    .line 280
    if-nez v5, :cond_e

    .line 281
    .line 282
    move-object v5, v3

    .line 283
    check-cast v5, Ll2/t;

    .line 284
    .line 285
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v1

    .line 289
    if-eqz v1, :cond_d

    .line 290
    .line 291
    const/4 v1, 0x4

    .line 292
    goto :goto_a

    .line 293
    :cond_d
    move v1, v6

    .line 294
    :goto_a
    or-int/2addr v1, v4

    .line 295
    goto :goto_b

    .line 296
    :cond_e
    move v1, v4

    .line 297
    :goto_b
    and-int/lit8 v4, v4, 0x30

    .line 298
    .line 299
    const/16 v5, 0x20

    .line 300
    .line 301
    if-nez v4, :cond_10

    .line 302
    .line 303
    move-object v4, v3

    .line 304
    check-cast v4, Ll2/t;

    .line 305
    .line 306
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 307
    .line 308
    .line 309
    move-result v4

    .line 310
    if-eqz v4, :cond_f

    .line 311
    .line 312
    move v4, v5

    .line 313
    goto :goto_c

    .line 314
    :cond_f
    const/16 v4, 0x10

    .line 315
    .line 316
    :goto_c
    or-int/2addr v1, v4

    .line 317
    :cond_10
    and-int/lit16 v4, v1, 0x93

    .line 318
    .line 319
    const/16 v7, 0x92

    .line 320
    .line 321
    const/4 v8, 0x1

    .line 322
    const/4 v9, 0x0

    .line 323
    if-eq v4, v7, :cond_11

    .line 324
    .line 325
    move v4, v8

    .line 326
    goto :goto_d

    .line 327
    :cond_11
    move v4, v9

    .line 328
    :goto_d
    and-int/lit8 v7, v1, 0x1

    .line 329
    .line 330
    check-cast v3, Ll2/t;

    .line 331
    .line 332
    invoke-virtual {v3, v7, v4}, Ll2/t;->O(IZ)Z

    .line 333
    .line 334
    .line 335
    move-result v4

    .line 336
    if-eqz v4, :cond_19

    .line 337
    .line 338
    iget-object v4, v0, Li40/h2;->g:Ljava/util/List;

    .line 339
    .line 340
    check-cast v4, Ljava/util/ArrayList;

    .line 341
    .line 342
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v4

    .line 346
    move-object v10, v4

    .line 347
    check-cast v10, Ljava/lang/String;

    .line 348
    .line 349
    const v4, 0x3f2ac89b

    .line 350
    .line 351
    .line 352
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 353
    .line 354
    .line 355
    if-lez v2, :cond_12

    .line 356
    .line 357
    const v4, 0x3f2ac8b9

    .line 358
    .line 359
    .line 360
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 361
    .line 362
    .line 363
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 364
    .line 365
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v4

    .line 369
    check-cast v4, Lj91/c;

    .line 370
    .line 371
    iget v4, v4, Lj91/c;->k:F

    .line 372
    .line 373
    const/4 v7, 0x0

    .line 374
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 375
    .line 376
    invoke-static {v11, v4, v7, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 377
    .line 378
    .line 379
    move-result-object v4

    .line 380
    invoke-static {v9, v9, v3, v4}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 381
    .line 382
    .line 383
    :goto_e
    invoke-virtual {v3, v9}, Ll2/t;->q(Z)V

    .line 384
    .line 385
    .line 386
    goto :goto_f

    .line 387
    :cond_12
    const v4, 0x3f07bc0a

    .line 388
    .line 389
    .line 390
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 391
    .line 392
    .line 393
    goto :goto_e

    .line 394
    :goto_f
    iget v4, v0, Li40/h2;->e:I

    .line 395
    .line 396
    if-ne v2, v4, :cond_13

    .line 397
    .line 398
    new-instance v4, Li91/p1;

    .line 399
    .line 400
    const v6, 0x7f080321

    .line 401
    .line 402
    .line 403
    invoke-direct {v4, v6}, Li91/p1;-><init>(I)V

    .line 404
    .line 405
    .line 406
    :goto_10
    move-object v14, v4

    .line 407
    goto :goto_11

    .line 408
    :cond_13
    const/4 v4, 0x0

    .line 409
    goto :goto_10

    .line 410
    :goto_11
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 411
    .line 412
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v4

    .line 416
    check-cast v4, Lj91/c;

    .line 417
    .line 418
    iget v4, v4, Lj91/c;->k:F

    .line 419
    .line 420
    iget-object v0, v0, Li40/h2;->f:Lay0/k;

    .line 421
    .line 422
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 423
    .line 424
    .line 425
    move-result v6

    .line 426
    and-int/lit8 v7, v1, 0x70

    .line 427
    .line 428
    xor-int/lit8 v7, v7, 0x30

    .line 429
    .line 430
    if-le v7, v5, :cond_14

    .line 431
    .line 432
    invoke-virtual {v3, v2}, Ll2/t;->e(I)Z

    .line 433
    .line 434
    .line 435
    move-result v7

    .line 436
    if-nez v7, :cond_16

    .line 437
    .line 438
    :cond_14
    and-int/lit8 v1, v1, 0x30

    .line 439
    .line 440
    if-ne v1, v5, :cond_15

    .line 441
    .line 442
    goto :goto_12

    .line 443
    :cond_15
    move v8, v9

    .line 444
    :cond_16
    :goto_12
    or-int v1, v6, v8

    .line 445
    .line 446
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v5

    .line 450
    if-nez v1, :cond_17

    .line 451
    .line 452
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 453
    .line 454
    if-ne v5, v1, :cond_18

    .line 455
    .line 456
    :cond_17
    new-instance v5, Lal/p;

    .line 457
    .line 458
    const/4 v1, 0x1

    .line 459
    invoke-direct {v5, v2, v1, v0}, Lal/p;-><init>(IILay0/k;)V

    .line 460
    .line 461
    .line 462
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 463
    .line 464
    .line 465
    :cond_18
    move-object/from16 v17, v5

    .line 466
    .line 467
    check-cast v17, Lay0/a;

    .line 468
    .line 469
    const/16 v22, 0x0

    .line 470
    .line 471
    const/16 v23, 0xe6e

    .line 472
    .line 473
    const/4 v11, 0x0

    .line 474
    const/4 v12, 0x0

    .line 475
    const/4 v13, 0x0

    .line 476
    const/4 v15, 0x0

    .line 477
    const/16 v16, 0x0

    .line 478
    .line 479
    const/16 v19, 0x0

    .line 480
    .line 481
    const/16 v21, 0x0

    .line 482
    .line 483
    move-object/from16 v20, v3

    .line 484
    .line 485
    move/from16 v18, v4

    .line 486
    .line 487
    invoke-static/range {v10 .. v23}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 488
    .line 489
    .line 490
    invoke-virtual {v3, v9}, Ll2/t;->q(Z)V

    .line 491
    .line 492
    .line 493
    goto :goto_13

    .line 494
    :cond_19
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 495
    .line 496
    .line 497
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 498
    .line 499
    return-object v0

    .line 500
    nop

    .line 501
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
