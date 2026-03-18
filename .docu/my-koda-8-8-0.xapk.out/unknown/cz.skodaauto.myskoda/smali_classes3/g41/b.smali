.class public final synthetic Lg41/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/d;


# direct methods
.method public synthetic constructor <init>(Lz70/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg41/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg41/b;->e:Lz70/d;

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
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lg41/b;->d:I

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
    move-result-object v3

    .line 55
    check-cast v3, Lj91/c;

    .line 56
    .line 57
    iget v8, v3, Lj91/c;->e:F

    .line 58
    .line 59
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    check-cast v1, Lj91/c;

    .line 64
    .line 65
    iget v10, v1, Lj91/c;->f:F

    .line 66
    .line 67
    const/4 v11, 0x5

    .line 68
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 69
    .line 70
    const/4 v7, 0x0

    .line 71
    const/4 v9, 0x0

    .line 72
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 73
    .line 74
    .line 75
    move-result-object v8

    .line 76
    iget-object v0, v0, Lg41/b;->e:Lz70/d;

    .line 77
    .line 78
    iget-object v0, v0, Lz70/d;->b:Lij0/a;

    .line 79
    .line 80
    new-array v1, v5, [Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Ljj0/f;

    .line 83
    .line 84
    const v3, 0x7f1207a4

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 92
    .line 93
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    check-cast v0, Lj91/f;

    .line 98
    .line 99
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    new-instance v0, Lr4/k;

    .line 104
    .line 105
    const/4 v1, 0x5

    .line 106
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 107
    .line 108
    .line 109
    const/16 v26, 0x0

    .line 110
    .line 111
    const v27, 0xfbf8

    .line 112
    .line 113
    .line 114
    const-wide/16 v9, 0x0

    .line 115
    .line 116
    const-wide/16 v11, 0x0

    .line 117
    .line 118
    const/4 v13, 0x0

    .line 119
    const-wide/16 v14, 0x0

    .line 120
    .line 121
    const/16 v16, 0x0

    .line 122
    .line 123
    const-wide/16 v18, 0x0

    .line 124
    .line 125
    const/16 v20, 0x0

    .line 126
    .line 127
    const/16 v21, 0x0

    .line 128
    .line 129
    const/16 v22, 0x0

    .line 130
    .line 131
    const/16 v23, 0x0

    .line 132
    .line 133
    const/16 v25, 0x0

    .line 134
    .line 135
    move-object/from16 v17, v0

    .line 136
    .line 137
    move-object/from16 v24, v2

    .line 138
    .line 139
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 140
    .line 141
    .line 142
    goto :goto_1

    .line 143
    :cond_1
    move-object/from16 v24, v2

    .line 144
    .line 145
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 146
    .line 147
    .line 148
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    return-object v0

    .line 151
    :pswitch_0
    move-object/from16 v1, p1

    .line 152
    .line 153
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 154
    .line 155
    move-object/from16 v2, p2

    .line 156
    .line 157
    check-cast v2, Ll2/o;

    .line 158
    .line 159
    move-object/from16 v3, p3

    .line 160
    .line 161
    check-cast v3, Ljava/lang/Integer;

    .line 162
    .line 163
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 164
    .line 165
    .line 166
    move-result v3

    .line 167
    const-string v4, "$this$item"

    .line 168
    .line 169
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    and-int/lit8 v1, v3, 0x11

    .line 173
    .line 174
    const/16 v4, 0x10

    .line 175
    .line 176
    const/4 v5, 0x0

    .line 177
    const/4 v6, 0x1

    .line 178
    if-eq v1, v4, :cond_2

    .line 179
    .line 180
    move v1, v6

    .line 181
    goto :goto_2

    .line 182
    :cond_2
    move v1, v5

    .line 183
    :goto_2
    and-int/2addr v3, v6

    .line 184
    check-cast v2, Ll2/t;

    .line 185
    .line 186
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    if-eqz v1, :cond_3

    .line 191
    .line 192
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 193
    .line 194
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    check-cast v1, Lj91/c;

    .line 199
    .line 200
    iget v10, v1, Lj91/c;->c:F

    .line 201
    .line 202
    const/4 v11, 0x7

    .line 203
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 204
    .line 205
    const/4 v7, 0x0

    .line 206
    const/4 v8, 0x0

    .line 207
    const/4 v9, 0x0

    .line 208
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 209
    .line 210
    .line 211
    move-result-object v8

    .line 212
    iget-object v0, v0, Lg41/b;->e:Lz70/d;

    .line 213
    .line 214
    iget-object v0, v0, Lz70/d;->b:Lij0/a;

    .line 215
    .line 216
    new-array v1, v5, [Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v0, Ljj0/f;

    .line 219
    .line 220
    const v3, 0x7f1207ac

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v6

    .line 227
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 228
    .line 229
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    check-cast v0, Lj91/f;

    .line 234
    .line 235
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 236
    .line 237
    .line 238
    move-result-object v7

    .line 239
    new-instance v0, Lr4/k;

    .line 240
    .line 241
    const/4 v1, 0x5

    .line 242
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 243
    .line 244
    .line 245
    const/16 v26, 0x0

    .line 246
    .line 247
    const v27, 0xfbf8

    .line 248
    .line 249
    .line 250
    const-wide/16 v9, 0x0

    .line 251
    .line 252
    const-wide/16 v11, 0x0

    .line 253
    .line 254
    const/4 v13, 0x0

    .line 255
    const-wide/16 v14, 0x0

    .line 256
    .line 257
    const/16 v16, 0x0

    .line 258
    .line 259
    const-wide/16 v18, 0x0

    .line 260
    .line 261
    const/16 v20, 0x0

    .line 262
    .line 263
    const/16 v21, 0x0

    .line 264
    .line 265
    const/16 v22, 0x0

    .line 266
    .line 267
    const/16 v23, 0x0

    .line 268
    .line 269
    const/16 v25, 0x0

    .line 270
    .line 271
    move-object/from16 v17, v0

    .line 272
    .line 273
    move-object/from16 v24, v2

    .line 274
    .line 275
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 276
    .line 277
    .line 278
    goto :goto_3

    .line 279
    :cond_3
    move-object/from16 v24, v2

    .line 280
    .line 281
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 282
    .line 283
    .line 284
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    return-object v0

    .line 287
    :pswitch_1
    move-object/from16 v1, p1

    .line 288
    .line 289
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 290
    .line 291
    move-object/from16 v2, p2

    .line 292
    .line 293
    check-cast v2, Ll2/o;

    .line 294
    .line 295
    move-object/from16 v3, p3

    .line 296
    .line 297
    check-cast v3, Ljava/lang/Integer;

    .line 298
    .line 299
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 300
    .line 301
    .line 302
    move-result v3

    .line 303
    const-string v4, "$this$item"

    .line 304
    .line 305
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    and-int/lit8 v1, v3, 0x11

    .line 309
    .line 310
    const/16 v4, 0x10

    .line 311
    .line 312
    const/4 v5, 0x0

    .line 313
    const/4 v6, 0x1

    .line 314
    if-eq v1, v4, :cond_4

    .line 315
    .line 316
    move v1, v6

    .line 317
    goto :goto_4

    .line 318
    :cond_4
    move v1, v5

    .line 319
    :goto_4
    and-int/2addr v3, v6

    .line 320
    check-cast v2, Ll2/t;

    .line 321
    .line 322
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 323
    .line 324
    .line 325
    move-result v1

    .line 326
    if-eqz v1, :cond_5

    .line 327
    .line 328
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 329
    .line 330
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    check-cast v1, Lj91/c;

    .line 335
    .line 336
    iget v10, v1, Lj91/c;->c:F

    .line 337
    .line 338
    const/4 v11, 0x7

    .line 339
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 340
    .line 341
    const/4 v7, 0x0

    .line 342
    const/4 v8, 0x0

    .line 343
    const/4 v9, 0x0

    .line 344
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 345
    .line 346
    .line 347
    move-result-object v8

    .line 348
    iget-object v0, v0, Lg41/b;->e:Lz70/d;

    .line 349
    .line 350
    iget-object v0, v0, Lz70/d;->b:Lij0/a;

    .line 351
    .line 352
    new-array v1, v5, [Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v0, Ljj0/f;

    .line 355
    .line 356
    const v3, 0x7f1207a8

    .line 357
    .line 358
    .line 359
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object v6

    .line 363
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 364
    .line 365
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    check-cast v0, Lj91/f;

    .line 370
    .line 371
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 372
    .line 373
    .line 374
    move-result-object v7

    .line 375
    new-instance v0, Lr4/k;

    .line 376
    .line 377
    const/4 v1, 0x5

    .line 378
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 379
    .line 380
    .line 381
    const/16 v26, 0x0

    .line 382
    .line 383
    const v27, 0xfbf8

    .line 384
    .line 385
    .line 386
    const-wide/16 v9, 0x0

    .line 387
    .line 388
    const-wide/16 v11, 0x0

    .line 389
    .line 390
    const/4 v13, 0x0

    .line 391
    const-wide/16 v14, 0x0

    .line 392
    .line 393
    const/16 v16, 0x0

    .line 394
    .line 395
    const-wide/16 v18, 0x0

    .line 396
    .line 397
    const/16 v20, 0x0

    .line 398
    .line 399
    const/16 v21, 0x0

    .line 400
    .line 401
    const/16 v22, 0x0

    .line 402
    .line 403
    const/16 v23, 0x0

    .line 404
    .line 405
    const/16 v25, 0x0

    .line 406
    .line 407
    move-object/from16 v17, v0

    .line 408
    .line 409
    move-object/from16 v24, v2

    .line 410
    .line 411
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 412
    .line 413
    .line 414
    goto :goto_5

    .line 415
    :cond_5
    move-object/from16 v24, v2

    .line 416
    .line 417
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 418
    .line 419
    .line 420
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 421
    .line 422
    return-object v0

    .line 423
    :pswitch_2
    move-object/from16 v1, p1

    .line 424
    .line 425
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 426
    .line 427
    move-object/from16 v2, p2

    .line 428
    .line 429
    check-cast v2, Ll2/o;

    .line 430
    .line 431
    move-object/from16 v3, p3

    .line 432
    .line 433
    check-cast v3, Ljava/lang/Integer;

    .line 434
    .line 435
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 436
    .line 437
    .line 438
    move-result v3

    .line 439
    const-string v4, "$this$item"

    .line 440
    .line 441
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    and-int/lit8 v1, v3, 0x11

    .line 445
    .line 446
    const/16 v4, 0x10

    .line 447
    .line 448
    const/4 v5, 0x0

    .line 449
    const/4 v6, 0x1

    .line 450
    if-eq v1, v4, :cond_6

    .line 451
    .line 452
    move v1, v6

    .line 453
    goto :goto_6

    .line 454
    :cond_6
    move v1, v5

    .line 455
    :goto_6
    and-int/2addr v3, v6

    .line 456
    check-cast v2, Ll2/t;

    .line 457
    .line 458
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 459
    .line 460
    .line 461
    move-result v1

    .line 462
    if-eqz v1, :cond_7

    .line 463
    .line 464
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 465
    .line 466
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 467
    .line 468
    .line 469
    move-result-object v1

    .line 470
    check-cast v1, Lj91/c;

    .line 471
    .line 472
    iget v10, v1, Lj91/c;->l:F

    .line 473
    .line 474
    const/4 v11, 0x7

    .line 475
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 476
    .line 477
    const/4 v7, 0x0

    .line 478
    const/4 v8, 0x0

    .line 479
    const/4 v9, 0x0

    .line 480
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 481
    .line 482
    .line 483
    move-result-object v8

    .line 484
    iget-object v0, v0, Lg41/b;->e:Lz70/d;

    .line 485
    .line 486
    iget-object v0, v0, Lz70/d;->b:Lij0/a;

    .line 487
    .line 488
    new-array v1, v5, [Ljava/lang/Object;

    .line 489
    .line 490
    check-cast v0, Ljj0/f;

    .line 491
    .line 492
    const v3, 0x7f1207ab

    .line 493
    .line 494
    .line 495
    invoke-virtual {v0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 496
    .line 497
    .line 498
    move-result-object v6

    .line 499
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 500
    .line 501
    invoke-virtual {v2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v0

    .line 505
    check-cast v0, Lj91/f;

    .line 506
    .line 507
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 508
    .line 509
    .line 510
    move-result-object v7

    .line 511
    new-instance v0, Lr4/k;

    .line 512
    .line 513
    const/4 v1, 0x5

    .line 514
    invoke-direct {v0, v1}, Lr4/k;-><init>(I)V

    .line 515
    .line 516
    .line 517
    const/16 v26, 0x0

    .line 518
    .line 519
    const v27, 0xfbf8

    .line 520
    .line 521
    .line 522
    const-wide/16 v9, 0x0

    .line 523
    .line 524
    const-wide/16 v11, 0x0

    .line 525
    .line 526
    const/4 v13, 0x0

    .line 527
    const-wide/16 v14, 0x0

    .line 528
    .line 529
    const/16 v16, 0x0

    .line 530
    .line 531
    const-wide/16 v18, 0x0

    .line 532
    .line 533
    const/16 v20, 0x0

    .line 534
    .line 535
    const/16 v21, 0x0

    .line 536
    .line 537
    const/16 v22, 0x0

    .line 538
    .line 539
    const/16 v23, 0x0

    .line 540
    .line 541
    const/16 v25, 0x0

    .line 542
    .line 543
    move-object/from16 v17, v0

    .line 544
    .line 545
    move-object/from16 v24, v2

    .line 546
    .line 547
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 548
    .line 549
    .line 550
    goto :goto_7

    .line 551
    :cond_7
    move-object/from16 v24, v2

    .line 552
    .line 553
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 554
    .line 555
    .line 556
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 557
    .line 558
    return-object v0

    .line 559
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
