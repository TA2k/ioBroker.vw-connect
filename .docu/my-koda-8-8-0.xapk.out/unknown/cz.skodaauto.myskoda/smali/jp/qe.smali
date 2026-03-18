.class public abstract Ljp/qe;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;Lx61/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v8, p3

    .line 6
    .line 7
    const-string v1, "rpaViewModel"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v5, p2

    .line 13
    .line 14
    check-cast v5, Ll2/t;

    .line 15
    .line 16
    const v1, 0x4293e64

    .line 17
    .line 18
    .line 19
    invoke-virtual {v5, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    const/4 v1, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v1, 0x2

    .line 31
    :goto_0
    or-int/2addr v1, v8

    .line 32
    invoke-virtual {v5, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    const/16 v3, 0x20

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v3, 0x10

    .line 42
    .line 43
    :goto_1
    or-int v10, v1, v3

    .line 44
    .line 45
    and-int/lit8 v1, v10, 0x13

    .line 46
    .line 47
    const/16 v3, 0x12

    .line 48
    .line 49
    const/4 v12, 0x0

    .line 50
    if-eq v1, v3, :cond_2

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    move v1, v12

    .line 55
    :goto_2
    and-int/lit8 v3, v10, 0x1

    .line 56
    .line 57
    invoke-virtual {v5, v3, v1}, Ll2/t;->O(IZ)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-eqz v1, :cond_14

    .line 62
    .line 63
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->getShowTouchPositionGrid()Lyy0/a2;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-static {v1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 68
    .line 69
    .line 70
    move-result-object v13

    .line 71
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 72
    .line 73
    const-string v3, "RPA_CONTENT_SCREEN"

    .line 74
    .line 75
    invoke-static {v1, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 84
    .line 85
    if-ne v3, v14, :cond_3

    .line 86
    .line 87
    new-instance v3, Lp81/c;

    .line 88
    .line 89
    const/16 v4, 0x18

    .line 90
    .line 91
    invoke-direct {v3, v4}, Lp81/c;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v5, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_3
    check-cast v3, Lay0/k;

    .line 98
    .line 99
    invoke-static {v1, v12, v3}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    const/high16 v3, 0x3f800000    # 1.0f

    .line 104
    .line 105
    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    const-string v3, "<this>"

    .line 110
    .line 111
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    sget-object v3, Lq61/o;->d:Lq61/o;

    .line 115
    .line 116
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    invoke-static {v1, v4, v3}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 123
    .line 124
    invoke-static {v3, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    iget-wide v6, v5, Ll2/t;->T:J

    .line 129
    .line 130
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 135
    .line 136
    .line 137
    move-result-object v7

    .line 138
    invoke-static {v5, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 143
    .line 144
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 148
    .line 149
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 150
    .line 151
    .line 152
    iget-boolean v11, v5, Ll2/t;->S:Z

    .line 153
    .line 154
    if-eqz v11, :cond_4

    .line 155
    .line 156
    invoke-virtual {v5, v15}, Ll2/t;->l(Lay0/a;)V

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_4
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 161
    .line 162
    .line 163
    :goto_3
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 164
    .line 165
    invoke-static {v11, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 169
    .line 170
    invoke-static {v3, v7, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 174
    .line 175
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 176
    .line 177
    if-nez v7, :cond_5

    .line 178
    .line 179
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v7

    .line 183
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 184
    .line 185
    .line 186
    move-result-object v11

    .line 187
    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v7

    .line 191
    if-nez v7, :cond_6

    .line 192
    .line 193
    :cond_5
    invoke-static {v6, v5, v6, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 194
    .line 195
    .line 196
    :cond_6
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 197
    .line 198
    invoke-static {v3, v1, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 199
    .line 200
    .line 201
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->isRPADisplayedPartially()Lyy0/a2;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    invoke-static {v1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->getCustomScreenCreator()Lyy0/a2;

    .line 210
    .line 211
    .line 212
    move-result-object v3

    .line 213
    invoke-static {v3, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 214
    .line 215
    .line 216
    move-result-object v3

    .line 217
    invoke-interface {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAViewModel;->getBackgroundSceneConfig()Lyy0/a2;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    invoke-static {v6, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 222
    .line 223
    .line 224
    move-result-object v6

    .line 225
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v7

    .line 229
    if-ne v7, v14, :cond_7

    .line 230
    .line 231
    sget-object v7, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 232
    .line 233
    invoke-static {v7}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 234
    .line 235
    .line 236
    move-result-object v7

    .line 237
    invoke-virtual {v5, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    :cond_7
    check-cast v7, Ll2/b1;

    .line 241
    .line 242
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v11

    .line 246
    if-ne v11, v14, :cond_8

    .line 247
    .line 248
    sget-object v11, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 249
    .line 250
    invoke-static {v11}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 251
    .line 252
    .line 253
    move-result-object v11

    .line 254
    invoke-virtual {v5, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    :cond_8
    move-object/from16 v19, v11

    .line 258
    .line 259
    check-cast v19, Ll2/b1;

    .line 260
    .line 261
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v11

    .line 265
    const/4 v15, 0x0

    .line 266
    if-ne v11, v14, :cond_9

    .line 267
    .line 268
    new-instance v11, Lq61/k;

    .line 269
    .line 270
    const/4 v9, 0x0

    .line 271
    invoke-direct {v11, v7, v15, v9}, Lq61/k;-><init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v5, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    :cond_9
    check-cast v11, Lay0/n;

    .line 278
    .line 279
    invoke-static {v11, v4, v5}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 280
    .line 281
    .line 282
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    check-cast v4, Ljava/lang/Boolean;

    .line 287
    .line 288
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 289
    .line 290
    .line 291
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v9

    .line 295
    check-cast v9, Ljava/lang/Boolean;

    .line 296
    .line 297
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 298
    .line 299
    .line 300
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v11

    .line 304
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v15

    .line 308
    if-nez v11, :cond_a

    .line 309
    .line 310
    if-ne v15, v14, :cond_b

    .line 311
    .line 312
    :cond_a
    new-instance v15, Laa/s;

    .line 313
    .line 314
    const/16 v16, 0x1d

    .line 315
    .line 316
    move-object/from16 v17, v1

    .line 317
    .line 318
    move-object/from16 v18, v7

    .line 319
    .line 320
    const/16 v20, 0x0

    .line 321
    .line 322
    invoke-direct/range {v15 .. v20}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v5, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    :cond_b
    check-cast v15, Lay0/n;

    .line 329
    .line 330
    invoke-static {v4, v9, v15, v5}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 331
    .line 332
    .line 333
    if-nez v2, :cond_c

    .line 334
    .line 335
    const v1, -0x7a222cce

    .line 336
    .line 337
    .line 338
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 339
    .line 340
    .line 341
    :goto_4
    invoke-virtual {v5, v12}, Ll2/t;->q(Z)V

    .line 342
    .line 343
    .line 344
    goto :goto_6

    .line 345
    :cond_c
    const v1, -0x7a222ccd

    .line 346
    .line 347
    .line 348
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 349
    .line 350
    .line 351
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v1

    .line 355
    move-object v3, v1

    .line 356
    check-cast v3, Lg61/g;

    .line 357
    .line 358
    if-nez v3, :cond_d

    .line 359
    .line 360
    const v1, -0x56fd4b01

    .line 361
    .line 362
    .line 363
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 364
    .line 365
    .line 366
    :goto_5
    invoke-virtual {v5, v12}, Ll2/t;->q(Z)V

    .line 367
    .line 368
    .line 369
    goto :goto_4

    .line 370
    :cond_d
    const v1, -0x56fd4b00

    .line 371
    .line 372
    .line 373
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 374
    .line 375
    .line 376
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 377
    .line 378
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v4

    .line 382
    if-nez v4, :cond_13

    .line 383
    .line 384
    const/4 v6, 0x6

    .line 385
    const/4 v7, 0x0

    .line 386
    const/4 v4, 0x0

    .line 387
    invoke-static/range {v1 .. v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->RPAScreen(Lx2/s;Lx61/a;Lg61/g;Lg61/a;Ll2/o;II)V

    .line 388
    .line 389
    .line 390
    goto :goto_5

    .line 391
    :goto_6
    invoke-interface/range {v19 .. v19}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v1

    .line 395
    check-cast v1, Ljava/lang/Boolean;

    .line 396
    .line 397
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 398
    .line 399
    .line 400
    move-result v1

    .line 401
    if-eqz v1, :cond_11

    .line 402
    .line 403
    const v1, -0x7a1b514e

    .line 404
    .line 405
    .line 406
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 407
    .line 408
    .line 409
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 410
    .line 411
    and-int/lit8 v3, v10, 0x70

    .line 412
    .line 413
    const/16 v4, 0x20

    .line 414
    .line 415
    if-eq v3, v4, :cond_e

    .line 416
    .line 417
    move v3, v12

    .line 418
    goto :goto_7

    .line 419
    :cond_e
    const/4 v3, 0x1

    .line 420
    :goto_7
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v4

    .line 424
    if-nez v3, :cond_f

    .line 425
    .line 426
    if-ne v4, v14, :cond_10

    .line 427
    .line 428
    :cond_f
    new-instance v4, Lp61/e;

    .line 429
    .line 430
    const/4 v3, 0x1

    .line 431
    invoke-direct {v4, v2, v3}, Lp61/e;-><init>(Lx61/a;I)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 435
    .line 436
    .line 437
    :cond_10
    check-cast v4, Lay0/a;

    .line 438
    .line 439
    const/4 v3, 0x6

    .line 440
    invoke-static {v3, v4, v5, v1}, Lp61/a;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 441
    .line 442
    .line 443
    :goto_8
    invoke-virtual {v5, v12}, Ll2/t;->q(Z)V

    .line 444
    .line 445
    .line 446
    const/4 v1, 0x1

    .line 447
    goto :goto_9

    .line 448
    :cond_11
    const v1, -0x7a63b5bc

    .line 449
    .line 450
    .line 451
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 452
    .line 453
    .line 454
    goto :goto_8

    .line 455
    :goto_9
    invoke-virtual {v5, v1}, Ll2/t;->q(Z)V

    .line 456
    .line 457
    .line 458
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v1

    .line 462
    check-cast v1, Ljava/lang/Boolean;

    .line 463
    .line 464
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 465
    .line 466
    .line 467
    move-result v1

    .line 468
    if-eqz v1, :cond_12

    .line 469
    .line 470
    const v1, 0x3bb73cf4

    .line 471
    .line 472
    .line 473
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 474
    .line 475
    .line 476
    invoke-static {v5, v12}, Lr61/c;->a(Ll2/o;I)V

    .line 477
    .line 478
    .line 479
    :goto_a
    invoke-virtual {v5, v12}, Ll2/t;->q(Z)V

    .line 480
    .line 481
    .line 482
    goto :goto_b

    .line 483
    :cond_12
    const v1, 0x3b6ba01e

    .line 484
    .line 485
    .line 486
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 487
    .line 488
    .line 489
    goto :goto_a

    .line 490
    :cond_13
    new-instance v0, Ljava/lang/ClassCastException;

    .line 491
    .line 492
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 493
    .line 494
    .line 495
    throw v0

    .line 496
    :cond_14
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 497
    .line 498
    .line 499
    :goto_b
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    if-eqz v1, :cond_15

    .line 504
    .line 505
    new-instance v3, Lo50/b;

    .line 506
    .line 507
    const/4 v4, 0x6

    .line 508
    invoke-direct {v3, v8, v4, v0, v2}, Lo50/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 509
    .line 510
    .line 511
    iput-object v3, v1, Ll2/u1;->d:Lay0/n;

    .line 512
    .line 513
    :cond_15
    return-void
.end method

.method public static b(Ld01/y;)Ld01/h;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "headers"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Ld01/y;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x1

    .line 14
    const/4 v8, 0x0

    .line 15
    const/4 v9, 0x0

    .line 16
    const/4 v10, 0x0

    .line 17
    const/4 v11, -0x1

    .line 18
    const/4 v12, -0x1

    .line 19
    const/4 v13, 0x0

    .line 20
    const/4 v14, 0x0

    .line 21
    const/4 v15, 0x0

    .line 22
    const/16 v16, -0x1

    .line 23
    .line 24
    const/16 v17, -0x1

    .line 25
    .line 26
    const/16 v18, 0x0

    .line 27
    .line 28
    const/16 v19, 0x0

    .line 29
    .line 30
    const/16 v20, 0x0

    .line 31
    .line 32
    :goto_0
    if-ge v6, v1, :cond_18

    .line 33
    .line 34
    invoke-virtual {v0, v6}, Ld01/y;->e(I)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const/16 v22, 0x1

    .line 39
    .line 40
    invoke-virtual {v0, v6}, Ld01/y;->k(I)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    const-string v5, "Cache-Control"

    .line 45
    .line 46
    invoke-virtual {v2, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    if-eqz v5, :cond_1

    .line 51
    .line 52
    if-eqz v8, :cond_0

    .line 53
    .line 54
    :goto_1
    const/4 v7, 0x0

    .line 55
    goto :goto_2

    .line 56
    :cond_0
    move-object v8, v4

    .line 57
    goto :goto_2

    .line 58
    :cond_1
    const-string v5, "Pragma"

    .line 59
    .line 60
    invoke-virtual {v2, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v2, :cond_17

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :goto_2
    const/4 v2, 0x0

    .line 68
    :goto_3
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-ge v2, v5, :cond_17

    .line 73
    .line 74
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    move v3, v2

    .line 79
    :goto_4
    if-ge v3, v5, :cond_3

    .line 80
    .line 81
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    move/from16 v23, v1

    .line 86
    .line 87
    const-string v1, "=,;"

    .line 88
    .line 89
    invoke-static {v1, v0}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_2

    .line 94
    .line 95
    goto :goto_5

    .line 96
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 97
    .line 98
    move-object/from16 v0, p0

    .line 99
    .line 100
    move/from16 v1, v23

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_3
    move/from16 v23, v1

    .line 104
    .line 105
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    :goto_5
    invoke-virtual {v4, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    const-string v1, "substring(...)"

    .line 114
    .line 115
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-static {v0}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    if-eq v3, v2, :cond_a

    .line 131
    .line 132
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    const/16 v5, 0x2c

    .line 137
    .line 138
    if-eq v2, v5, :cond_a

    .line 139
    .line 140
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    const/16 v5, 0x3b

    .line 145
    .line 146
    if-ne v2, v5, :cond_4

    .line 147
    .line 148
    goto/16 :goto_a

    .line 149
    .line 150
    :cond_4
    add-int/lit8 v3, v3, 0x1

    .line 151
    .line 152
    sget-object v2, Le01/e;->a:[B

    .line 153
    .line 154
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    :goto_6
    if-ge v3, v2, :cond_6

    .line 159
    .line 160
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 161
    .line 162
    .line 163
    move-result v5

    .line 164
    move/from16 v24, v2

    .line 165
    .line 166
    const/16 v2, 0x20

    .line 167
    .line 168
    if-eq v5, v2, :cond_5

    .line 169
    .line 170
    const/16 v2, 0x9

    .line 171
    .line 172
    if-eq v5, v2, :cond_5

    .line 173
    .line 174
    goto :goto_7

    .line 175
    :cond_5
    add-int/lit8 v3, v3, 0x1

    .line 176
    .line 177
    move/from16 v2, v24

    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_6
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 181
    .line 182
    .line 183
    move-result v3

    .line 184
    :goto_7
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    if-ge v3, v2, :cond_7

    .line 189
    .line 190
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 191
    .line 192
    .line 193
    move-result v2

    .line 194
    const/16 v5, 0x22

    .line 195
    .line 196
    if-ne v2, v5, :cond_7

    .line 197
    .line 198
    add-int/lit8 v3, v3, 0x1

    .line 199
    .line 200
    const/4 v2, 0x4

    .line 201
    invoke-static {v4, v5, v3, v2}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    invoke-virtual {v4, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    add-int/lit8 v2, v2, 0x1

    .line 213
    .line 214
    goto :goto_b

    .line 215
    :cond_7
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    move v5, v3

    .line 220
    :goto_8
    if-ge v5, v2, :cond_9

    .line 221
    .line 222
    move/from16 v24, v2

    .line 223
    .line 224
    invoke-virtual {v4, v5}, Ljava/lang/String;->charAt(I)C

    .line 225
    .line 226
    .line 227
    move-result v2

    .line 228
    move/from16 v25, v5

    .line 229
    .line 230
    const-string v5, ",;"

    .line 231
    .line 232
    invoke-static {v5, v2}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 233
    .line 234
    .line 235
    move-result v2

    .line 236
    if-eqz v2, :cond_8

    .line 237
    .line 238
    move/from16 v5, v25

    .line 239
    .line 240
    goto :goto_9

    .line 241
    :cond_8
    add-int/lit8 v5, v25, 0x1

    .line 242
    .line 243
    move/from16 v2, v24

    .line 244
    .line 245
    goto :goto_8

    .line 246
    :cond_9
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 247
    .line 248
    .line 249
    move-result v5

    .line 250
    :goto_9
    invoke-virtual {v4, v3, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v2

    .line 254
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    invoke-static {v2}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object v3

    .line 265
    move v2, v5

    .line 266
    goto :goto_b

    .line 267
    :cond_a
    :goto_a
    add-int/lit8 v3, v3, 0x1

    .line 268
    .line 269
    move v2, v3

    .line 270
    const/4 v3, 0x0

    .line 271
    :goto_b
    const-string v1, "no-cache"

    .line 272
    .line 273
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    if-eqz v1, :cond_b

    .line 278
    .line 279
    move-object/from16 v0, p0

    .line 280
    .line 281
    move/from16 v9, v22

    .line 282
    .line 283
    :goto_c
    move/from16 v1, v23

    .line 284
    .line 285
    goto/16 :goto_3

    .line 286
    .line 287
    :cond_b
    const-string v1, "no-store"

    .line 288
    .line 289
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 290
    .line 291
    .line 292
    move-result v1

    .line 293
    if-eqz v1, :cond_c

    .line 294
    .line 295
    move-object/from16 v0, p0

    .line 296
    .line 297
    move/from16 v10, v22

    .line 298
    .line 299
    goto :goto_c

    .line 300
    :cond_c
    const-string v1, "max-age"

    .line 301
    .line 302
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 303
    .line 304
    .line 305
    move-result v1

    .line 306
    if-eqz v1, :cond_e

    .line 307
    .line 308
    const/4 v1, -0x1

    .line 309
    invoke-static {v1, v3}, Le01/e;->p(ILjava/lang/String;)I

    .line 310
    .line 311
    .line 312
    move-result v11

    .line 313
    :cond_d
    :goto_d
    move-object/from16 v0, p0

    .line 314
    .line 315
    goto :goto_c

    .line 316
    :cond_e
    const/4 v1, -0x1

    .line 317
    const-string v5, "s-maxage"

    .line 318
    .line 319
    invoke-virtual {v5, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 320
    .line 321
    .line 322
    move-result v5

    .line 323
    if-eqz v5, :cond_f

    .line 324
    .line 325
    invoke-static {v1, v3}, Le01/e;->p(ILjava/lang/String;)I

    .line 326
    .line 327
    .line 328
    move-result v12

    .line 329
    goto :goto_d

    .line 330
    :cond_f
    const-string v1, "private"

    .line 331
    .line 332
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 333
    .line 334
    .line 335
    move-result v1

    .line 336
    if-eqz v1, :cond_10

    .line 337
    .line 338
    move-object/from16 v0, p0

    .line 339
    .line 340
    move/from16 v13, v22

    .line 341
    .line 342
    goto :goto_c

    .line 343
    :cond_10
    const-string v1, "public"

    .line 344
    .line 345
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 346
    .line 347
    .line 348
    move-result v1

    .line 349
    if-eqz v1, :cond_11

    .line 350
    .line 351
    move-object/from16 v0, p0

    .line 352
    .line 353
    move/from16 v14, v22

    .line 354
    .line 355
    goto :goto_c

    .line 356
    :cond_11
    const-string v1, "must-revalidate"

    .line 357
    .line 358
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 359
    .line 360
    .line 361
    move-result v1

    .line 362
    if-eqz v1, :cond_12

    .line 363
    .line 364
    move-object/from16 v0, p0

    .line 365
    .line 366
    move/from16 v15, v22

    .line 367
    .line 368
    goto :goto_c

    .line 369
    :cond_12
    const-string v1, "max-stale"

    .line 370
    .line 371
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 372
    .line 373
    .line 374
    move-result v1

    .line 375
    if-eqz v1, :cond_13

    .line 376
    .line 377
    const v0, 0x7fffffff

    .line 378
    .line 379
    .line 380
    invoke-static {v0, v3}, Le01/e;->p(ILjava/lang/String;)I

    .line 381
    .line 382
    .line 383
    move-result v16

    .line 384
    goto :goto_d

    .line 385
    :cond_13
    const-string v1, "min-fresh"

    .line 386
    .line 387
    invoke-virtual {v1, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 388
    .line 389
    .line 390
    move-result v1

    .line 391
    if-eqz v1, :cond_14

    .line 392
    .line 393
    const/4 v1, -0x1

    .line 394
    invoke-static {v1, v3}, Le01/e;->p(ILjava/lang/String;)I

    .line 395
    .line 396
    .line 397
    move-result v17

    .line 398
    goto :goto_d

    .line 399
    :cond_14
    const/4 v1, -0x1

    .line 400
    const-string v3, "only-if-cached"

    .line 401
    .line 402
    invoke-virtual {v3, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 403
    .line 404
    .line 405
    move-result v3

    .line 406
    if-eqz v3, :cond_15

    .line 407
    .line 408
    move-object/from16 v0, p0

    .line 409
    .line 410
    move/from16 v18, v22

    .line 411
    .line 412
    goto/16 :goto_c

    .line 413
    .line 414
    :cond_15
    const-string v3, "no-transform"

    .line 415
    .line 416
    invoke-virtual {v3, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 417
    .line 418
    .line 419
    move-result v3

    .line 420
    if-eqz v3, :cond_16

    .line 421
    .line 422
    move-object/from16 v0, p0

    .line 423
    .line 424
    move/from16 v19, v22

    .line 425
    .line 426
    goto/16 :goto_c

    .line 427
    .line 428
    :cond_16
    const-string v3, "immutable"

    .line 429
    .line 430
    invoke-virtual {v3, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 431
    .line 432
    .line 433
    move-result v0

    .line 434
    if-eqz v0, :cond_d

    .line 435
    .line 436
    move-object/from16 v0, p0

    .line 437
    .line 438
    move/from16 v20, v22

    .line 439
    .line 440
    goto/16 :goto_c

    .line 441
    .line 442
    :cond_17
    move/from16 v23, v1

    .line 443
    .line 444
    const/4 v1, -0x1

    .line 445
    add-int/lit8 v6, v6, 0x1

    .line 446
    .line 447
    move-object/from16 v0, p0

    .line 448
    .line 449
    move/from16 v1, v23

    .line 450
    .line 451
    goto/16 :goto_0

    .line 452
    .line 453
    :cond_18
    if-nez v7, :cond_19

    .line 454
    .line 455
    const/16 v21, 0x0

    .line 456
    .line 457
    goto :goto_e

    .line 458
    :cond_19
    move-object/from16 v21, v8

    .line 459
    .line 460
    :goto_e
    new-instance v8, Ld01/h;

    .line 461
    .line 462
    invoke-direct/range {v8 .. v21}, Ld01/h;-><init>(ZZIIZZZIIZZZLjava/lang/String;)V

    .line 463
    .line 464
    .line 465
    return-object v8
.end method
