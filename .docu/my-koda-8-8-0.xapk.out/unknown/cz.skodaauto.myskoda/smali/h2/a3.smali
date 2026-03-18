.class public final Lh2/a3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(ILay0/k;Lx2/s;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh2/a3;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lh2/a3;->e:I

    iput-object p2, p0, Lh2/a3;->f:Ljava/lang/Object;

    iput-object p3, p0, Lh2/a3;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(ILjava/lang/Object;Lo1/b0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh2/a3;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Lh2/a3;->f:Ljava/lang/Object;

    iput p1, p0, Lh2/a3;->e:I

    iput-object p2, p0, Lh2/a3;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/a3;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget v3, v0, Lh2/a3;->e:I

    .line 8
    .line 9
    iget-object v4, v0, Lh2/a3;->f:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v5, 0x2

    .line 12
    const/4 v6, 0x1

    .line 13
    iget-object v0, v0, Lh2/a3;->g:Ljava/lang/Object;

    .line 14
    .line 15
    const/4 v7, 0x0

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    move-object/from16 v1, p1

    .line 20
    .line 21
    check-cast v1, Ll2/o;

    .line 22
    .line 23
    move-object/from16 v8, p2

    .line 24
    .line 25
    check-cast v8, Ljava/lang/Number;

    .line 26
    .line 27
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result v8

    .line 31
    and-int/lit8 v9, v8, 0x3

    .line 32
    .line 33
    if-eq v9, v5, :cond_0

    .line 34
    .line 35
    move v5, v6

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v5, v7

    .line 38
    :goto_0
    and-int/2addr v6, v8

    .line 39
    check-cast v1, Ll2/t;

    .line 40
    .line 41
    invoke-virtual {v1, v6, v5}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    if-eqz v5, :cond_1

    .line 46
    .line 47
    check-cast v4, Lo1/b0;

    .line 48
    .line 49
    invoke-interface {v4, v3, v0, v1, v7}, Lo1/b0;->e(ILjava/lang/Object;Ll2/o;I)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 54
    .line 55
    .line 56
    :goto_1
    return-object v2

    .line 57
    :pswitch_0
    move-object/from16 v1, p1

    .line 58
    .line 59
    check-cast v1, Ll2/o;

    .line 60
    .line 61
    move-object/from16 v8, p2

    .line 62
    .line 63
    check-cast v8, Ljava/lang/Number;

    .line 64
    .line 65
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    check-cast v4, Lay0/k;

    .line 70
    .line 71
    and-int/lit8 v9, v8, 0x3

    .line 72
    .line 73
    if-eq v9, v5, :cond_2

    .line 74
    .line 75
    move v5, v6

    .line 76
    goto :goto_2

    .line 77
    :cond_2
    move v5, v7

    .line 78
    :goto_2
    and-int/2addr v6, v8

    .line 79
    move-object v13, v1

    .line 80
    check-cast v13, Ll2/t;

    .line 81
    .line 82
    invoke-virtual {v13, v6, v5}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-eqz v1, :cond_a

    .line 87
    .line 88
    const/4 v1, 0x6

    .line 89
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 90
    .line 91
    const/high16 v6, 0x41a80000    # 21.0f

    .line 92
    .line 93
    const/high16 v8, 0x40400000    # 3.0f

    .line 94
    .line 95
    if-nez v3, :cond_6

    .line 96
    .line 97
    const v3, -0x6092e1f

    .line 98
    .line 99
    .line 100
    invoke-virtual {v13, v3}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    sget-object v3, Li2/a1;->e:Lj3/f;

    .line 104
    .line 105
    if-eqz v3, :cond_3

    .line 106
    .line 107
    :goto_3
    move-object v9, v3

    .line 108
    goto/16 :goto_4

    .line 109
    .line 110
    :cond_3
    new-instance v14, Lj3/e;

    .line 111
    .line 112
    const/16 v23, 0x0

    .line 113
    .line 114
    const/16 v24, 0xe0

    .line 115
    .line 116
    const-string v15, "Filled.Edit"

    .line 117
    .line 118
    const/high16 v16, 0x41c00000    # 24.0f

    .line 119
    .line 120
    const/high16 v17, 0x41c00000    # 24.0f

    .line 121
    .line 122
    const/high16 v18, 0x41c00000    # 24.0f

    .line 123
    .line 124
    const/high16 v19, 0x41c00000    # 24.0f

    .line 125
    .line 126
    const-wide/16 v20, 0x0

    .line 127
    .line 128
    const/16 v22, 0x0

    .line 129
    .line 130
    invoke-direct/range {v14 .. v24}, Lj3/e;-><init>(Ljava/lang/String;FFFFJIZI)V

    .line 131
    .line 132
    .line 133
    sget v3, Lj3/h0;->a:I

    .line 134
    .line 135
    new-instance v3, Le3/p0;

    .line 136
    .line 137
    sget-wide v9, Le3/s;->b:J

    .line 138
    .line 139
    invoke-direct {v3, v9, v10}, Le3/p0;-><init>(J)V

    .line 140
    .line 141
    .line 142
    new-instance v15, Lhu/q;

    .line 143
    .line 144
    invoke-direct {v15, v7, v1}, Lhu/q;-><init>(BI)V

    .line 145
    .line 146
    .line 147
    iget-object v1, v15, Lhu/q;->e:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v1, Ljava/util/ArrayList;

    .line 150
    .line 151
    const/high16 v9, 0x418a0000    # 17.25f

    .line 152
    .line 153
    invoke-virtual {v15, v8, v9}, Lhu/q;->I(FF)V

    .line 154
    .line 155
    .line 156
    new-instance v10, Lj3/a0;

    .line 157
    .line 158
    invoke-direct {v10, v6}, Lj3/a0;-><init>(F)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    const/high16 v6, 0x40700000    # 3.75f

    .line 165
    .line 166
    invoke-virtual {v15, v6}, Lhu/q;->D(F)V

    .line 167
    .line 168
    .line 169
    const v10, 0x418e7ae1    # 17.81f

    .line 170
    .line 171
    .line 172
    const v11, 0x411f0a3d    # 9.94f

    .line 173
    .line 174
    .line 175
    invoke-virtual {v15, v10, v11}, Lhu/q;->F(FF)V

    .line 176
    .line 177
    .line 178
    const/high16 v10, -0x3f900000    # -3.75f

    .line 179
    .line 180
    invoke-virtual {v15, v10, v10}, Lhu/q;->G(FF)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v15, v8, v9}, Lhu/q;->F(FF)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 187
    .line 188
    .line 189
    const v8, 0x41a5ae14    # 20.71f

    .line 190
    .line 191
    .line 192
    const v9, 0x40e147ae    # 7.04f

    .line 193
    .line 194
    .line 195
    invoke-virtual {v15, v8, v9}, Lhu/q;->I(FF)V

    .line 196
    .line 197
    .line 198
    const/16 v20, 0x0

    .line 199
    .line 200
    const v21, -0x404b851f    # -1.41f

    .line 201
    .line 202
    .line 203
    const v16, 0x3ec7ae14    # 0.39f

    .line 204
    .line 205
    .line 206
    const v17, -0x413851ec    # -0.39f

    .line 207
    .line 208
    .line 209
    const v18, 0x3ec7ae14    # 0.39f

    .line 210
    .line 211
    .line 212
    const v19, -0x407d70a4    # -1.02f

    .line 213
    .line 214
    .line 215
    invoke-virtual/range {v15 .. v21}, Lhu/q;->t(FFFFFF)V

    .line 216
    .line 217
    .line 218
    const v8, -0x3fea3d71    # -2.34f

    .line 219
    .line 220
    .line 221
    invoke-virtual {v15, v8, v8}, Lhu/q;->G(FF)V

    .line 222
    .line 223
    .line 224
    const v20, -0x404b851f    # -1.41f

    .line 225
    .line 226
    .line 227
    const/16 v21, 0x0

    .line 228
    .line 229
    const v16, -0x413851ec    # -0.39f

    .line 230
    .line 231
    .line 232
    const v18, -0x407d70a4    # -1.02f

    .line 233
    .line 234
    .line 235
    const v19, -0x413851ec    # -0.39f

    .line 236
    .line 237
    .line 238
    invoke-virtual/range {v15 .. v21}, Lhu/q;->t(FFFFFF)V

    .line 239
    .line 240
    .line 241
    const v8, -0x4015c28f    # -1.83f

    .line 242
    .line 243
    .line 244
    const v9, 0x3fea3d71    # 1.83f

    .line 245
    .line 246
    .line 247
    invoke-virtual {v15, v8, v9}, Lhu/q;->G(FF)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v15, v6, v6}, Lhu/q;->G(FF)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v15, v9, v8}, Lhu/q;->G(FF)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 257
    .line 258
    .line 259
    invoke-static {v14, v1, v3}, Lj3/e;->a(Lj3/e;Ljava/util/ArrayList;Le3/p0;)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v14}, Lj3/e;->b()Lj3/f;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    sput-object v3, Li2/a1;->e:Lj3/f;

    .line 267
    .line 268
    goto/16 :goto_3

    .line 269
    .line 270
    :goto_4
    const v1, 0x7f1205a3

    .line 271
    .line 272
    .line 273
    invoke-static {v13, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v10

    .line 277
    invoke-virtual {v13, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v3

    .line 285
    if-nez v1, :cond_4

    .line 286
    .line 287
    if-ne v3, v5, :cond_5

    .line 288
    .line 289
    :cond_4
    new-instance v3, Le41/b;

    .line 290
    .line 291
    const/16 v1, 0x14

    .line 292
    .line 293
    invoke-direct {v3, v1, v4}, Le41/b;-><init>(ILay0/k;)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v13, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    :cond_5
    move-object v8, v3

    .line 300
    check-cast v8, Lay0/a;

    .line 301
    .line 302
    move-object v11, v0

    .line 303
    check-cast v11, Lx2/s;

    .line 304
    .line 305
    const/4 v14, 0x0

    .line 306
    const/16 v15, 0x10

    .line 307
    .line 308
    const/4 v12, 0x0

    .line 309
    invoke-static/range {v8 .. v15}, Lh2/m3;->h(Lay0/a;Lj3/f;Ljava/lang/String;Lx2/s;ZLl2/o;II)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 313
    .line 314
    .line 315
    goto/16 :goto_7

    .line 316
    .line 317
    :cond_6
    const v3, -0x604a288

    .line 318
    .line 319
    .line 320
    invoke-virtual {v13, v3}, Ll2/t;->Y(I)V

    .line 321
    .line 322
    .line 323
    sget-object v3, Li2/a1;->f:Lj3/f;

    .line 324
    .line 325
    if-eqz v3, :cond_7

    .line 326
    .line 327
    :goto_5
    move-object v9, v3

    .line 328
    goto/16 :goto_6

    .line 329
    .line 330
    :cond_7
    new-instance v14, Lj3/e;

    .line 331
    .line 332
    const/16 v23, 0x0

    .line 333
    .line 334
    const/16 v24, 0xe0

    .line 335
    .line 336
    const-string v15, "Filled.DateRange"

    .line 337
    .line 338
    const/high16 v16, 0x41c00000    # 24.0f

    .line 339
    .line 340
    const/high16 v17, 0x41c00000    # 24.0f

    .line 341
    .line 342
    const/high16 v18, 0x41c00000    # 24.0f

    .line 343
    .line 344
    const/high16 v19, 0x41c00000    # 24.0f

    .line 345
    .line 346
    const-wide/16 v20, 0x0

    .line 347
    .line 348
    const/16 v22, 0x0

    .line 349
    .line 350
    invoke-direct/range {v14 .. v24}, Lj3/e;-><init>(Ljava/lang/String;FFFFJIZI)V

    .line 351
    .line 352
    .line 353
    sget v3, Lj3/h0;->a:I

    .line 354
    .line 355
    new-instance v3, Le3/p0;

    .line 356
    .line 357
    sget-wide v9, Le3/s;->b:J

    .line 358
    .line 359
    invoke-direct {v3, v9, v10}, Le3/p0;-><init>(J)V

    .line 360
    .line 361
    .line 362
    new-instance v15, Lhu/q;

    .line 363
    .line 364
    invoke-direct {v15, v7, v1}, Lhu/q;-><init>(BI)V

    .line 365
    .line 366
    .line 367
    const/high16 v1, 0x41100000    # 9.0f

    .line 368
    .line 369
    const/high16 v9, 0x41300000    # 11.0f

    .line 370
    .line 371
    invoke-virtual {v15, v1, v9}, Lhu/q;->I(FF)V

    .line 372
    .line 373
    .line 374
    const/high16 v10, 0x40e00000    # 7.0f

    .line 375
    .line 376
    invoke-virtual {v15, v10, v9}, Lhu/q;->F(FF)V

    .line 377
    .line 378
    .line 379
    const/high16 v10, 0x40000000    # 2.0f

    .line 380
    .line 381
    invoke-virtual {v15, v10}, Lhu/q;->O(F)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v15, v10}, Lhu/q;->D(F)V

    .line 385
    .line 386
    .line 387
    const/high16 v11, -0x40000000    # -2.0f

    .line 388
    .line 389
    invoke-virtual {v15, v11}, Lhu/q;->O(F)V

    .line 390
    .line 391
    .line 392
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 393
    .line 394
    .line 395
    const/high16 v12, 0x41500000    # 13.0f

    .line 396
    .line 397
    invoke-virtual {v15, v12, v9}, Lhu/q;->I(FF)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v15, v11}, Lhu/q;->D(F)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v15, v10}, Lhu/q;->O(F)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v15, v10}, Lhu/q;->D(F)V

    .line 407
    .line 408
    .line 409
    invoke-virtual {v15, v11}, Lhu/q;->O(F)V

    .line 410
    .line 411
    .line 412
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 413
    .line 414
    .line 415
    const/high16 v12, 0x41880000    # 17.0f

    .line 416
    .line 417
    invoke-virtual {v15, v12, v9}, Lhu/q;->I(FF)V

    .line 418
    .line 419
    .line 420
    invoke-virtual {v15, v11}, Lhu/q;->D(F)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v15, v10}, Lhu/q;->O(F)V

    .line 424
    .line 425
    .line 426
    invoke-virtual {v15, v10}, Lhu/q;->D(F)V

    .line 427
    .line 428
    .line 429
    invoke-virtual {v15, v11}, Lhu/q;->O(F)V

    .line 430
    .line 431
    .line 432
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 433
    .line 434
    .line 435
    const/high16 v12, 0x41980000    # 19.0f

    .line 436
    .line 437
    const/high16 v7, 0x40800000    # 4.0f

    .line 438
    .line 439
    invoke-virtual {v15, v12, v7}, Lhu/q;->I(FF)V

    .line 440
    .line 441
    .line 442
    const/high16 v9, -0x40800000    # -1.0f

    .line 443
    .line 444
    invoke-virtual {v15, v9}, Lhu/q;->D(F)V

    .line 445
    .line 446
    .line 447
    const/high16 v9, 0x41900000    # 18.0f

    .line 448
    .line 449
    invoke-virtual {v15, v9, v10}, Lhu/q;->F(FF)V

    .line 450
    .line 451
    .line 452
    invoke-virtual {v15, v11}, Lhu/q;->D(F)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v15, v10}, Lhu/q;->O(F)V

    .line 456
    .line 457
    .line 458
    const/high16 v9, 0x41000000    # 8.0f

    .line 459
    .line 460
    invoke-virtual {v15, v9, v7}, Lhu/q;->F(FF)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v15, v9, v10}, Lhu/q;->F(FF)V

    .line 464
    .line 465
    .line 466
    const/high16 v9, 0x40c00000    # 6.0f

    .line 467
    .line 468
    invoke-virtual {v15, v9, v10}, Lhu/q;->F(FF)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {v15, v10}, Lhu/q;->O(F)V

    .line 472
    .line 473
    .line 474
    const/high16 v10, 0x40a00000    # 5.0f

    .line 475
    .line 476
    invoke-virtual {v15, v10, v7}, Lhu/q;->F(FF)V

    .line 477
    .line 478
    .line 479
    const v20, -0x400147ae    # -1.99f

    .line 480
    .line 481
    .line 482
    const/high16 v21, 0x40000000    # 2.0f

    .line 483
    .line 484
    const v16, -0x4071eb85    # -1.11f

    .line 485
    .line 486
    .line 487
    const/16 v17, 0x0

    .line 488
    .line 489
    const v18, -0x400147ae    # -1.99f

    .line 490
    .line 491
    .line 492
    const v19, 0x3f666666    # 0.9f

    .line 493
    .line 494
    .line 495
    invoke-virtual/range {v15 .. v21}, Lhu/q;->t(FFFFFF)V

    .line 496
    .line 497
    .line 498
    const/high16 v7, 0x41a00000    # 20.0f

    .line 499
    .line 500
    invoke-virtual {v15, v8, v7}, Lhu/q;->F(FF)V

    .line 501
    .line 502
    .line 503
    const/high16 v20, 0x40000000    # 2.0f

    .line 504
    .line 505
    const/16 v16, 0x0

    .line 506
    .line 507
    const v17, 0x3f8ccccd    # 1.1f

    .line 508
    .line 509
    .line 510
    const v18, 0x3f63d70a    # 0.89f

    .line 511
    .line 512
    .line 513
    const/high16 v19, 0x40000000    # 2.0f

    .line 514
    .line 515
    invoke-virtual/range {v15 .. v21}, Lhu/q;->t(FFFFFF)V

    .line 516
    .line 517
    .line 518
    const/high16 v8, 0x41600000    # 14.0f

    .line 519
    .line 520
    invoke-virtual {v15, v8}, Lhu/q;->D(F)V

    .line 521
    .line 522
    .line 523
    const/high16 v21, -0x40000000    # -2.0f

    .line 524
    .line 525
    const v16, 0x3f8ccccd    # 1.1f

    .line 526
    .line 527
    .line 528
    const/16 v17, 0x0

    .line 529
    .line 530
    const/high16 v18, 0x40000000    # 2.0f

    .line 531
    .line 532
    const v19, -0x4099999a    # -0.9f

    .line 533
    .line 534
    .line 535
    invoke-virtual/range {v15 .. v21}, Lhu/q;->t(FFFFFF)V

    .line 536
    .line 537
    .line 538
    invoke-virtual {v15, v6, v9}, Lhu/q;->F(FF)V

    .line 539
    .line 540
    .line 541
    const/high16 v20, -0x40000000    # -2.0f

    .line 542
    .line 543
    const/16 v16, 0x0

    .line 544
    .line 545
    const v17, -0x40733333    # -1.1f

    .line 546
    .line 547
    .line 548
    const v18, -0x4099999a    # -0.9f

    .line 549
    .line 550
    .line 551
    const/high16 v19, -0x40000000    # -2.0f

    .line 552
    .line 553
    invoke-virtual/range {v15 .. v21}, Lhu/q;->t(FFFFFF)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 557
    .line 558
    .line 559
    invoke-virtual {v15, v12, v7}, Lhu/q;->I(FF)V

    .line 560
    .line 561
    .line 562
    invoke-virtual {v15, v10, v7}, Lhu/q;->F(FF)V

    .line 563
    .line 564
    .line 565
    invoke-virtual {v15, v10, v1}, Lhu/q;->F(FF)V

    .line 566
    .line 567
    .line 568
    invoke-virtual {v15, v8}, Lhu/q;->D(F)V

    .line 569
    .line 570
    .line 571
    const/high16 v1, 0x41300000    # 11.0f

    .line 572
    .line 573
    invoke-virtual {v15, v1}, Lhu/q;->O(F)V

    .line 574
    .line 575
    .line 576
    invoke-virtual {v15}, Lhu/q;->l()V

    .line 577
    .line 578
    .line 579
    iget-object v1, v15, Lhu/q;->e:Ljava/lang/Object;

    .line 580
    .line 581
    check-cast v1, Ljava/util/ArrayList;

    .line 582
    .line 583
    invoke-static {v14, v1, v3}, Lj3/e;->a(Lj3/e;Ljava/util/ArrayList;Le3/p0;)V

    .line 584
    .line 585
    .line 586
    invoke-virtual {v14}, Lj3/e;->b()Lj3/f;

    .line 587
    .line 588
    .line 589
    move-result-object v3

    .line 590
    sput-object v3, Li2/a1;->f:Lj3/f;

    .line 591
    .line 592
    goto/16 :goto_5

    .line 593
    .line 594
    :goto_6
    const v1, 0x7f1205a1

    .line 595
    .line 596
    .line 597
    invoke-static {v13, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 598
    .line 599
    .line 600
    move-result-object v10

    .line 601
    invoke-virtual {v13, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 602
    .line 603
    .line 604
    move-result v1

    .line 605
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    move-result-object v3

    .line 609
    if-nez v1, :cond_8

    .line 610
    .line 611
    if-ne v3, v5, :cond_9

    .line 612
    .line 613
    :cond_8
    new-instance v3, Le41/b;

    .line 614
    .line 615
    const/16 v1, 0x15

    .line 616
    .line 617
    invoke-direct {v3, v1, v4}, Le41/b;-><init>(ILay0/k;)V

    .line 618
    .line 619
    .line 620
    invoke-virtual {v13, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 621
    .line 622
    .line 623
    :cond_9
    move-object v8, v3

    .line 624
    check-cast v8, Lay0/a;

    .line 625
    .line 626
    move-object v11, v0

    .line 627
    check-cast v11, Lx2/s;

    .line 628
    .line 629
    const/4 v14, 0x0

    .line 630
    const/16 v15, 0x10

    .line 631
    .line 632
    const/4 v12, 0x0

    .line 633
    invoke-static/range {v8 .. v15}, Lh2/m3;->h(Lay0/a;Lj3/f;Ljava/lang/String;Lx2/s;ZLl2/o;II)V

    .line 634
    .line 635
    .line 636
    const/4 v0, 0x0

    .line 637
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 638
    .line 639
    .line 640
    goto :goto_7

    .line 641
    :cond_a
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 642
    .line 643
    .line 644
    :goto_7
    return-object v2

    .line 645
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
