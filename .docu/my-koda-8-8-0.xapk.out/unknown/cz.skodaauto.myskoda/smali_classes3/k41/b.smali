.class public final synthetic Lk41/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/b;


# direct methods
.method public synthetic constructor <init>(Lz70/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lk41/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk41/b;->e:Lz70/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lk41/b;->d:I

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
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$item"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v1, v3, 0x11

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    const/4 v5, 0x0

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v6

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v5

    .line 40
    :goto_0
    and-int/2addr v3, v6

    .line 41
    check-cast v2, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_1

    .line 48
    .line 49
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 50
    .line 51
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Lj91/c;

    .line 56
    .line 57
    iget v10, v1, Lj91/c;->c:F

    .line 58
    .line 59
    const/4 v11, 0x7

    .line 60
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 61
    .line 62
    const/4 v7, 0x0

    .line 63
    const/4 v8, 0x0

    .line 64
    const/4 v9, 0x0

    .line 65
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    iget-object v0, v0, Lk41/b;->e:Lz70/b;

    .line 70
    .line 71
    iget-object v0, v0, Lz70/b;->a:Lij0/a;

    .line 72
    .line 73
    new-array v1, v5, [Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v0, Ljj0/f;

    .line 76
    .line 77
    const v3, 0x7f12113f

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 85
    .line 86
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    check-cast v0, Lj91/f;

    .line 91
    .line 92
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    new-instance v0, Lr4/k;

    .line 97
    .line 98
    const/4 v1, 0x5

    .line 99
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 100
    .line 101
    .line 102
    const/16 v26, 0x0

    .line 103
    .line 104
    const v27, 0xfbf8

    .line 105
    .line 106
    .line 107
    const-wide/16 v9, 0x0

    .line 108
    .line 109
    const-wide/16 v11, 0x0

    .line 110
    .line 111
    const/4 v13, 0x0

    .line 112
    const-wide/16 v14, 0x0

    .line 113
    .line 114
    const/16 v16, 0x0

    .line 115
    .line 116
    const-wide/16 v18, 0x0

    .line 117
    .line 118
    const/16 v20, 0x0

    .line 119
    .line 120
    const/16 v21, 0x0

    .line 121
    .line 122
    const/16 v22, 0x0

    .line 123
    .line 124
    const/16 v23, 0x0

    .line 125
    .line 126
    const/16 v25, 0x0

    .line 127
    .line 128
    move-object/from16 v17, v0

    .line 129
    .line 130
    move-object/from16 v24, v2

    .line 131
    .line 132
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 133
    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_1
    move-object/from16 v24, v2

    .line 137
    .line 138
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 139
    .line 140
    .line 141
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    return-object v0

    .line 144
    :pswitch_0
    move-object/from16 v1, p1

    .line 145
    .line 146
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 147
    .line 148
    move-object/from16 v2, p2

    .line 149
    .line 150
    check-cast v2, Ll2/o;

    .line 151
    .line 152
    move-object/from16 v3, p3

    .line 153
    .line 154
    check-cast v3, Ljava/lang/Integer;

    .line 155
    .line 156
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    const-string v4, "$this$item"

    .line 161
    .line 162
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    and-int/lit8 v1, v3, 0x11

    .line 166
    .line 167
    const/16 v4, 0x10

    .line 168
    .line 169
    const/4 v5, 0x0

    .line 170
    const/4 v6, 0x1

    .line 171
    if-eq v1, v4, :cond_2

    .line 172
    .line 173
    move v1, v6

    .line 174
    goto :goto_2

    .line 175
    :cond_2
    move v1, v5

    .line 176
    :goto_2
    and-int/2addr v3, v6

    .line 177
    check-cast v2, Ll2/t;

    .line 178
    .line 179
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 180
    .line 181
    .line 182
    move-result v1

    .line 183
    if-eqz v1, :cond_3

    .line 184
    .line 185
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 186
    .line 187
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v1

    .line 191
    check-cast v1, Lj91/c;

    .line 192
    .line 193
    iget v10, v1, Lj91/c;->c:F

    .line 194
    .line 195
    const/4 v11, 0x7

    .line 196
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 197
    .line 198
    const/4 v7, 0x0

    .line 199
    const/4 v8, 0x0

    .line 200
    const/4 v9, 0x0

    .line 201
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v8

    .line 205
    iget-object v0, v0, Lk41/b;->e:Lz70/b;

    .line 206
    .line 207
    iget-object v0, v0, Lz70/b;->a:Lij0/a;

    .line 208
    .line 209
    new-array v1, v5, [Ljava/lang/Object;

    .line 210
    .line 211
    check-cast v0, Ljj0/f;

    .line 212
    .line 213
    const v3, 0x7f121143

    .line 214
    .line 215
    .line 216
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v6

    .line 220
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 221
    .line 222
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    check-cast v0, Lj91/f;

    .line 227
    .line 228
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 229
    .line 230
    .line 231
    move-result-object v7

    .line 232
    new-instance v0, Lr4/k;

    .line 233
    .line 234
    const/4 v1, 0x5

    .line 235
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 236
    .line 237
    .line 238
    const/16 v26, 0x0

    .line 239
    .line 240
    const v27, 0xfbf8

    .line 241
    .line 242
    .line 243
    const-wide/16 v9, 0x0

    .line 244
    .line 245
    const-wide/16 v11, 0x0

    .line 246
    .line 247
    const/4 v13, 0x0

    .line 248
    const-wide/16 v14, 0x0

    .line 249
    .line 250
    const/16 v16, 0x0

    .line 251
    .line 252
    const-wide/16 v18, 0x0

    .line 253
    .line 254
    const/16 v20, 0x0

    .line 255
    .line 256
    const/16 v21, 0x0

    .line 257
    .line 258
    const/16 v22, 0x0

    .line 259
    .line 260
    const/16 v23, 0x0

    .line 261
    .line 262
    const/16 v25, 0x0

    .line 263
    .line 264
    move-object/from16 v17, v0

    .line 265
    .line 266
    move-object/from16 v24, v2

    .line 267
    .line 268
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 269
    .line 270
    .line 271
    goto :goto_3

    .line 272
    :cond_3
    move-object/from16 v24, v2

    .line 273
    .line 274
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 275
    .line 276
    .line 277
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 278
    .line 279
    return-object v0

    .line 280
    :pswitch_1
    move-object/from16 v1, p1

    .line 281
    .line 282
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 283
    .line 284
    move-object/from16 v2, p2

    .line 285
    .line 286
    check-cast v2, Ll2/o;

    .line 287
    .line 288
    move-object/from16 v3, p3

    .line 289
    .line 290
    check-cast v3, Ljava/lang/Integer;

    .line 291
    .line 292
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 293
    .line 294
    .line 295
    move-result v3

    .line 296
    const-string v4, "$this$item"

    .line 297
    .line 298
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    and-int/lit8 v1, v3, 0x11

    .line 302
    .line 303
    const/16 v4, 0x10

    .line 304
    .line 305
    const/4 v5, 0x1

    .line 306
    const/4 v6, 0x0

    .line 307
    if-eq v1, v4, :cond_4

    .line 308
    .line 309
    move v1, v5

    .line 310
    goto :goto_4

    .line 311
    :cond_4
    move v1, v6

    .line 312
    :goto_4
    and-int/2addr v3, v5

    .line 313
    check-cast v2, Ll2/t;

    .line 314
    .line 315
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 316
    .line 317
    .line 318
    move-result v1

    .line 319
    if-eqz v1, :cond_5

    .line 320
    .line 321
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 322
    .line 323
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v3

    .line 327
    check-cast v3, Lj91/c;

    .line 328
    .line 329
    iget v9, v3, Lj91/c;->e:F

    .line 330
    .line 331
    const/4 v11, 0x0

    .line 332
    const/16 v12, 0xd

    .line 333
    .line 334
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 335
    .line 336
    const/4 v8, 0x0

    .line 337
    const/4 v10, 0x0

    .line 338
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 339
    .line 340
    .line 341
    move-result-object v9

    .line 342
    move-object v3, v7

    .line 343
    iget-object v0, v0, Lk41/b;->e:Lz70/b;

    .line 344
    .line 345
    iget-object v0, v0, Lz70/b;->a:Lij0/a;

    .line 346
    .line 347
    new-array v4, v6, [Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v0, Ljj0/f;

    .line 350
    .line 351
    const v5, 0x7f12113a

    .line 352
    .line 353
    .line 354
    invoke-virtual {v0, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 355
    .line 356
    .line 357
    move-result-object v7

    .line 358
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 359
    .line 360
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    move-result-object v0

    .line 364
    check-cast v0, Lj91/f;

    .line 365
    .line 366
    invoke-virtual {v0}, Lj91/f;->e()Lg4/p0;

    .line 367
    .line 368
    .line 369
    move-result-object v8

    .line 370
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 371
    .line 372
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    check-cast v0, Lj91/e;

    .line 377
    .line 378
    invoke-virtual {v0}, Lj91/e;->t()J

    .line 379
    .line 380
    .line 381
    move-result-wide v10

    .line 382
    new-instance v0, Lr4/k;

    .line 383
    .line 384
    const/4 v4, 0x5

    .line 385
    invoke-direct {v0, v4}, Lr4/k;-><init>(I)V

    .line 386
    .line 387
    .line 388
    const/16 v27, 0x0

    .line 389
    .line 390
    const v28, 0xfbf0

    .line 391
    .line 392
    .line 393
    const-wide/16 v12, 0x0

    .line 394
    .line 395
    const/4 v14, 0x0

    .line 396
    const-wide/16 v15, 0x0

    .line 397
    .line 398
    const/16 v17, 0x0

    .line 399
    .line 400
    const-wide/16 v19, 0x0

    .line 401
    .line 402
    const/16 v21, 0x0

    .line 403
    .line 404
    const/16 v22, 0x0

    .line 405
    .line 406
    const/16 v23, 0x0

    .line 407
    .line 408
    const/16 v24, 0x0

    .line 409
    .line 410
    const/16 v26, 0x0

    .line 411
    .line 412
    move-object/from16 v18, v0

    .line 413
    .line 414
    move-object/from16 v25, v2

    .line 415
    .line 416
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    move-result-object v0

    .line 423
    check-cast v0, Lj91/c;

    .line 424
    .line 425
    iget v0, v0, Lj91/c;->f:F

    .line 426
    .line 427
    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    invoke-static {v2, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 432
    .line 433
    .line 434
    goto :goto_5

    .line 435
    :cond_5
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 436
    .line 437
    .line 438
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 439
    .line 440
    return-object v0

    .line 441
    :pswitch_2
    move-object/from16 v1, p1

    .line 442
    .line 443
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 444
    .line 445
    move-object/from16 v2, p2

    .line 446
    .line 447
    check-cast v2, Ll2/o;

    .line 448
    .line 449
    move-object/from16 v3, p3

    .line 450
    .line 451
    check-cast v3, Ljava/lang/Integer;

    .line 452
    .line 453
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 454
    .line 455
    .line 456
    move-result v3

    .line 457
    const-string v4, "$this$item"

    .line 458
    .line 459
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    and-int/lit8 v1, v3, 0x11

    .line 463
    .line 464
    const/16 v4, 0x10

    .line 465
    .line 466
    const/4 v5, 0x0

    .line 467
    const/4 v6, 0x1

    .line 468
    if-eq v1, v4, :cond_6

    .line 469
    .line 470
    move v1, v6

    .line 471
    goto :goto_6

    .line 472
    :cond_6
    move v1, v5

    .line 473
    :goto_6
    and-int/2addr v3, v6

    .line 474
    check-cast v2, Ll2/t;

    .line 475
    .line 476
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 477
    .line 478
    .line 479
    move-result v1

    .line 480
    if-eqz v1, :cond_7

    .line 481
    .line 482
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 483
    .line 484
    const/high16 v3, 0x3f800000    # 1.0f

    .line 485
    .line 486
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 487
    .line 488
    .line 489
    move-result-object v6

    .line 490
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 491
    .line 492
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v3

    .line 496
    check-cast v3, Lj91/c;

    .line 497
    .line 498
    iget v8, v3, Lj91/c;->e:F

    .line 499
    .line 500
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v1

    .line 504
    check-cast v1, Lj91/c;

    .line 505
    .line 506
    iget v10, v1, Lj91/c;->f:F

    .line 507
    .line 508
    const/4 v11, 0x5

    .line 509
    const/4 v7, 0x0

    .line 510
    const/4 v9, 0x0

    .line 511
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 512
    .line 513
    .line 514
    move-result-object v8

    .line 515
    iget-object v0, v0, Lk41/b;->e:Lz70/b;

    .line 516
    .line 517
    iget-object v0, v0, Lz70/b;->a:Lij0/a;

    .line 518
    .line 519
    new-array v1, v5, [Ljava/lang/Object;

    .line 520
    .line 521
    check-cast v0, Ljj0/f;

    .line 522
    .line 523
    const v3, 0x7f121138

    .line 524
    .line 525
    .line 526
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 527
    .line 528
    .line 529
    move-result-object v6

    .line 530
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 531
    .line 532
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object v0

    .line 536
    check-cast v0, Lj91/f;

    .line 537
    .line 538
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 539
    .line 540
    .line 541
    move-result-object v7

    .line 542
    new-instance v0, Lr4/k;

    .line 543
    .line 544
    const/4 v1, 0x5

    .line 545
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 546
    .line 547
    .line 548
    const/16 v26, 0x0

    .line 549
    .line 550
    const v27, 0xfbf8

    .line 551
    .line 552
    .line 553
    const-wide/16 v9, 0x0

    .line 554
    .line 555
    const-wide/16 v11, 0x0

    .line 556
    .line 557
    const/4 v13, 0x0

    .line 558
    const-wide/16 v14, 0x0

    .line 559
    .line 560
    const/16 v16, 0x0

    .line 561
    .line 562
    const-wide/16 v18, 0x0

    .line 563
    .line 564
    const/16 v20, 0x0

    .line 565
    .line 566
    const/16 v21, 0x0

    .line 567
    .line 568
    const/16 v22, 0x0

    .line 569
    .line 570
    const/16 v23, 0x0

    .line 571
    .line 572
    const/16 v25, 0x0

    .line 573
    .line 574
    move-object/from16 v17, v0

    .line 575
    .line 576
    move-object/from16 v24, v2

    .line 577
    .line 578
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 579
    .line 580
    .line 581
    goto :goto_7

    .line 582
    :cond_7
    move-object/from16 v24, v2

    .line 583
    .line 584
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 585
    .line 586
    .line 587
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 588
    .line 589
    return-object v0

    .line 590
    nop

    .line 591
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
