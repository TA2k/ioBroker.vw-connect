.class public abstract Lkp/z8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/content/Context;)Lt4/e;
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget v0, v0, Landroid/content/res/Configuration;->fontScale:F

    .line 10
    .line 11
    new-instance v1, Lt4/e;

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    iget p0, p0, Landroid/util/DisplayMetrics;->density:F

    .line 22
    .line 23
    invoke-static {v0}, Lu4/b;->a(F)Lu4/a;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-nez v2, :cond_0

    .line 28
    .line 29
    new-instance v2, Lt4/n;

    .line 30
    .line 31
    invoke-direct {v2, v0}, Lt4/n;-><init>(F)V

    .line 32
    .line 33
    .line 34
    :cond_0
    invoke-direct {v1, p0, v0, v2}, Lt4/e;-><init>(FFLu4/a;)V

    .line 35
    .line 36
    .line 37
    return-object v1
.end method

.method public static final b(Lay0/a;Lay0/n;Ljd/k;Lh2/e8;Ll2/o;II)V
    .locals 72

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move/from16 v5, p5

    .line 8
    .line 9
    const-string v3, "onDismiss"

    .line 10
    .line 11
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v3, "onDateSelected"

    .line 15
    .line 16
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v10, p4

    .line 20
    .line 21
    check-cast v10, Ll2/t;

    .line 22
    .line 23
    const v3, 0x5aa575db

    .line 24
    .line 25
    .line 26
    invoke-virtual {v10, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v3, v5, 0x6

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_0

    .line 38
    .line 39
    const/4 v3, 0x4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v3, 0x2

    .line 42
    :goto_0
    or-int/2addr v3, v5

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v3, v5

    .line 45
    :goto_1
    and-int/lit8 v6, v5, 0x30

    .line 46
    .line 47
    if-nez v6, :cond_3

    .line 48
    .line 49
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-eqz v6, :cond_2

    .line 54
    .line 55
    const/16 v6, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v6, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr v3, v6

    .line 61
    :cond_3
    and-int/lit8 v6, p6, 0x4

    .line 62
    .line 63
    if-eqz v6, :cond_4

    .line 64
    .line 65
    or-int/lit16 v3, v3, 0x180

    .line 66
    .line 67
    goto :goto_5

    .line 68
    :cond_4
    and-int/lit16 v7, v5, 0x180

    .line 69
    .line 70
    if-nez v7, :cond_7

    .line 71
    .line 72
    and-int/lit16 v7, v5, 0x200

    .line 73
    .line 74
    if-nez v7, :cond_5

    .line 75
    .line 76
    invoke-virtual {v10, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    goto :goto_3

    .line 81
    :cond_5
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    :goto_3
    if-eqz v7, :cond_6

    .line 86
    .line 87
    const/16 v7, 0x100

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_6
    const/16 v7, 0x80

    .line 91
    .line 92
    :goto_4
    or-int/2addr v3, v7

    .line 93
    :cond_7
    :goto_5
    and-int/lit16 v7, v5, 0xc00

    .line 94
    .line 95
    if-nez v7, :cond_8

    .line 96
    .line 97
    or-int/lit16 v3, v3, 0x400

    .line 98
    .line 99
    :cond_8
    and-int/lit16 v7, v3, 0x493

    .line 100
    .line 101
    const/16 v8, 0x492

    .line 102
    .line 103
    const/4 v14, 0x0

    .line 104
    const/4 v15, 0x1

    .line 105
    if-eq v7, v8, :cond_9

    .line 106
    .line 107
    move v7, v15

    .line 108
    goto :goto_6

    .line 109
    :cond_9
    move v7, v14

    .line 110
    :goto_6
    and-int/lit8 v8, v3, 0x1

    .line 111
    .line 112
    invoke-virtual {v10, v8, v7}, Ll2/t;->O(IZ)Z

    .line 113
    .line 114
    .line 115
    move-result v7

    .line 116
    if-eqz v7, :cond_20

    .line 117
    .line 118
    invoke-virtual {v10}, Ll2/t;->T()V

    .line 119
    .line 120
    .line 121
    and-int/lit8 v7, v5, 0x1

    .line 122
    .line 123
    if-eqz v7, :cond_b

    .line 124
    .line 125
    invoke-virtual {v10}, Ll2/t;->y()Z

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    if-eqz v7, :cond_a

    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_a
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 133
    .line 134
    .line 135
    and-int/lit16 v3, v3, -0x1c01

    .line 136
    .line 137
    move-object/from16 v6, p3

    .line 138
    .line 139
    goto :goto_8

    .line 140
    :cond_b
    :goto_7
    if-eqz v6, :cond_c

    .line 141
    .line 142
    const/4 v0, 0x0

    .line 143
    :cond_c
    and-int/lit16 v3, v3, -0x1c01

    .line 144
    .line 145
    sget-object v6, Lgd/b;->a:Lgd/a;

    .line 146
    .line 147
    :goto_8
    invoke-virtual {v10}, Ll2/t;->r()V

    .line 148
    .line 149
    .line 150
    if-eqz v0, :cond_d

    .line 151
    .line 152
    iget-wide v8, v0, Ljd/k;->a:J

    .line 153
    .line 154
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    goto :goto_9

    .line 159
    :cond_d
    const/4 v7, 0x0

    .line 160
    :goto_9
    if-eqz v0, :cond_e

    .line 161
    .line 162
    iget-wide v8, v0, Ljd/k;->b:J

    .line 163
    .line 164
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    goto :goto_a

    .line 169
    :cond_e
    const/4 v8, 0x0

    .line 170
    :goto_a
    sget-object v9, Lh2/f4;->a:Lk1/a1;

    .line 171
    .line 172
    sget-object v9, Lh2/c2;->b:Lgy0/j;

    .line 173
    .line 174
    invoke-static {v10}, Lh2/r;->y(Ll2/o;)Ljava/util/Locale;

    .line 175
    .line 176
    .line 177
    move-result-object v11

    .line 178
    new-array v13, v14, [Ljava/lang/Object;

    .line 179
    .line 180
    new-instance v12, Lgv0/a;

    .line 181
    .line 182
    const/4 v4, 0x7

    .line 183
    invoke-direct {v12, v14, v4}, Lgv0/a;-><init>(BI)V

    .line 184
    .line 185
    .line 186
    new-instance v4, Lh2/n3;

    .line 187
    .line 188
    invoke-direct {v4, v6, v11, v15}, Lh2/n3;-><init>(Lh2/e8;Ljava/util/Locale;I)V

    .line 189
    .line 190
    .line 191
    invoke-static {v12, v4}, Lu2/m;->b(Lay0/n;Lay0/k;)Lu2/l;

    .line 192
    .line 193
    .line 194
    move-result-object v4

    .line 195
    invoke-virtual {v10, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v12

    .line 199
    invoke-virtual {v10, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v16

    .line 203
    or-int v12, v12, v16

    .line 204
    .line 205
    invoke-virtual {v10, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v16

    .line 209
    or-int v12, v12, v16

    .line 210
    .line 211
    invoke-virtual {v10, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v16

    .line 215
    or-int v12, v12, v16

    .line 216
    .line 217
    invoke-virtual {v10, v14}, Ll2/t;->e(I)Z

    .line 218
    .line 219
    .line 220
    move-result v16

    .line 221
    or-int v12, v12, v16

    .line 222
    .line 223
    invoke-virtual {v10, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v16

    .line 227
    or-int v12, v12, v16

    .line 228
    .line 229
    invoke-virtual {v10, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v16

    .line 233
    or-int v12, v12, v16

    .line 234
    .line 235
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v15

    .line 239
    move-object/from16 v22, v11

    .line 240
    .line 241
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 242
    .line 243
    if-nez v12, :cond_10

    .line 244
    .line 245
    if-ne v15, v11, :cond_f

    .line 246
    .line 247
    goto :goto_b

    .line 248
    :cond_f
    move-object v12, v6

    .line 249
    goto :goto_c

    .line 250
    :cond_10
    :goto_b
    new-instance v16, Lh2/w3;

    .line 251
    .line 252
    const/16 v23, 0x0

    .line 253
    .line 254
    move-object/from16 v19, v7

    .line 255
    .line 256
    move-object/from16 v21, v6

    .line 257
    .line 258
    move-object/from16 v17, v7

    .line 259
    .line 260
    move-object/from16 v18, v8

    .line 261
    .line 262
    move-object/from16 v20, v9

    .line 263
    .line 264
    invoke-direct/range {v16 .. v23}, Lh2/w3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 265
    .line 266
    .line 267
    move-object/from16 v15, v16

    .line 268
    .line 269
    move-object/from16 v12, v21

    .line 270
    .line 271
    invoke-virtual {v10, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 272
    .line 273
    .line 274
    :goto_c
    check-cast v15, Lay0/a;

    .line 275
    .line 276
    invoke-static {v13, v4, v15, v10, v14}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v4

    .line 280
    check-cast v4, Lh2/g4;

    .line 281
    .line 282
    iget-object v6, v4, Lh2/s;->d:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v6, Ll2/j1;

    .line 285
    .line 286
    invoke-virtual {v6, v12}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    sget-object v6, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 290
    .line 291
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 292
    .line 293
    .line 294
    move-result-object v7

    .line 295
    invoke-virtual {v7}, Lj91/e;->b()J

    .line 296
    .line 297
    .line 298
    move-result-wide v7

    .line 299
    sget-object v9, Le3/j0;->a:Le3/i0;

    .line 300
    .line 301
    invoke-static {v6, v7, v8, v9}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 306
    .line 307
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 308
    .line 309
    const/4 v9, 0x6

    .line 310
    invoke-static {v7, v8, v10, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 311
    .line 312
    .line 313
    move-result-object v7

    .line 314
    iget-wide v14, v10, Ll2/t;->T:J

    .line 315
    .line 316
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 317
    .line 318
    .line 319
    move-result v8

    .line 320
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 321
    .line 322
    .line 323
    move-result-object v13

    .line 324
    invoke-static {v10, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 325
    .line 326
    .line 327
    move-result-object v6

    .line 328
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 329
    .line 330
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 331
    .line 332
    .line 333
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 334
    .line 335
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 336
    .line 337
    .line 338
    iget-boolean v15, v10, Ll2/t;->S:Z

    .line 339
    .line 340
    if-eqz v15, :cond_11

    .line 341
    .line 342
    invoke-virtual {v10, v14}, Ll2/t;->l(Lay0/a;)V

    .line 343
    .line 344
    .line 345
    goto :goto_d

    .line 346
    :cond_11
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 347
    .line 348
    .line 349
    :goto_d
    sget-object v15, Lv3/j;->g:Lv3/h;

    .line 350
    .line 351
    invoke-static {v15, v7, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 352
    .line 353
    .line 354
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 355
    .line 356
    invoke-static {v7, v13, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 357
    .line 358
    .line 359
    sget-object v13, Lv3/j;->j:Lv3/h;

    .line 360
    .line 361
    iget-boolean v9, v10, Ll2/t;->S:Z

    .line 362
    .line 363
    if-nez v9, :cond_12

    .line 364
    .line 365
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v9

    .line 369
    move-object/from16 p3, v0

    .line 370
    .line 371
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 376
    .line 377
    .line 378
    move-result v0

    .line 379
    if-nez v0, :cond_13

    .line 380
    .line 381
    goto :goto_e

    .line 382
    :cond_12
    move-object/from16 p3, v0

    .line 383
    .line 384
    :goto_e
    invoke-static {v8, v10, v8, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 385
    .line 386
    .line 387
    :cond_13
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 388
    .line 389
    invoke-static {v0, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 390
    .line 391
    .line 392
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 393
    .line 394
    const/high16 v8, 0x3f800000    # 1.0f

    .line 395
    .line 396
    invoke-static {v6, v8}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 397
    .line 398
    .line 399
    move-result-object v17

    .line 400
    const/16 v9, 0xc

    .line 401
    .line 402
    int-to-float v9, v9

    .line 403
    const/16 v21, 0x0

    .line 404
    .line 405
    const/16 v22, 0xa

    .line 406
    .line 407
    const/16 v19, 0x0

    .line 408
    .line 409
    move/from16 v20, v9

    .line 410
    .line 411
    move/from16 v18, v9

    .line 412
    .line 413
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 414
    .line 415
    .line 416
    move-result-object v9

    .line 417
    sget-object v8, Lx2/c;->n:Lx2/i;

    .line 418
    .line 419
    move/from16 v26, v3

    .line 420
    .line 421
    sget-object v3, Lk1/j;->g:Lk1/f;

    .line 422
    .line 423
    const/16 v5, 0x36

    .line 424
    .line 425
    invoke-static {v3, v8, v10, v5}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 426
    .line 427
    .line 428
    move-result-object v3

    .line 429
    move-object/from16 v17, v6

    .line 430
    .line 431
    iget-wide v5, v10, Ll2/t;->T:J

    .line 432
    .line 433
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 434
    .line 435
    .line 436
    move-result v5

    .line 437
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 438
    .line 439
    .line 440
    move-result-object v6

    .line 441
    invoke-static {v10, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 442
    .line 443
    .line 444
    move-result-object v8

    .line 445
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 446
    .line 447
    .line 448
    iget-boolean v9, v10, Ll2/t;->S:Z

    .line 449
    .line 450
    if-eqz v9, :cond_14

    .line 451
    .line 452
    invoke-virtual {v10, v14}, Ll2/t;->l(Lay0/a;)V

    .line 453
    .line 454
    .line 455
    goto :goto_f

    .line 456
    :cond_14
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 457
    .line 458
    .line 459
    :goto_f
    invoke-static {v15, v3, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 460
    .line 461
    .line 462
    invoke-static {v7, v6, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 463
    .line 464
    .line 465
    iget-boolean v3, v10, Ll2/t;->S:Z

    .line 466
    .line 467
    if-nez v3, :cond_15

    .line 468
    .line 469
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v3

    .line 473
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 474
    .line 475
    .line 476
    move-result-object v6

    .line 477
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    move-result v3

    .line 481
    if-nez v3, :cond_16

    .line 482
    .line 483
    :cond_15
    invoke-static {v5, v10, v5, v13}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 484
    .line 485
    .line 486
    :cond_16
    invoke-static {v0, v8, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 487
    .line 488
    .line 489
    and-int/lit8 v0, v26, 0xe

    .line 490
    .line 491
    const/4 v3, 0x4

    .line 492
    if-ne v0, v3, :cond_17

    .line 493
    .line 494
    const/4 v0, 0x1

    .line 495
    goto :goto_10

    .line 496
    :cond_17
    const/4 v0, 0x0

    .line 497
    :goto_10
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    move-result-object v3

    .line 501
    const/16 v5, 0x15

    .line 502
    .line 503
    if-nez v0, :cond_18

    .line 504
    .line 505
    if-ne v3, v11, :cond_19

    .line 506
    .line 507
    :cond_18
    new-instance v3, Lb71/i;

    .line 508
    .line 509
    invoke-direct {v3, v1, v5}, Lb71/i;-><init>(Lay0/a;I)V

    .line 510
    .line 511
    .line 512
    invoke-virtual {v10, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 513
    .line 514
    .line 515
    :cond_19
    move-object/from16 v21, v3

    .line 516
    .line 517
    check-cast v21, Lay0/a;

    .line 518
    .line 519
    const/16 v22, 0xf

    .line 520
    .line 521
    const/16 v18, 0x0

    .line 522
    .line 523
    const/16 v19, 0x0

    .line 524
    .line 525
    const/16 v20, 0x0

    .line 526
    .line 527
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 528
    .line 529
    .line 530
    move-result-object v8

    .line 531
    const v0, 0x7f080359

    .line 532
    .line 533
    .line 534
    const/4 v3, 0x6

    .line 535
    invoke-static {v0, v3, v10}, Ljp/ha;->c(IILl2/o;)Lj3/f;

    .line 536
    .line 537
    .line 538
    move-result-object v6

    .line 539
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 540
    .line 541
    .line 542
    move-result-object v0

    .line 543
    invoke-virtual {v0}, Lj91/e;->e()J

    .line 544
    .line 545
    .line 546
    move-result-wide v13

    .line 547
    new-instance v9, Le3/m;

    .line 548
    .line 549
    const/4 v0, 0x5

    .line 550
    invoke-direct {v9, v13, v14, v0}, Le3/m;-><init>(JI)V

    .line 551
    .line 552
    .line 553
    const-string v7, "Close"

    .line 554
    .line 555
    move-object v0, v11

    .line 556
    const/16 v11, 0x38

    .line 557
    .line 558
    move-object v3, v0

    .line 559
    const/high16 v0, 0x3f800000    # 1.0f

    .line 560
    .line 561
    invoke-static/range {v6 .. v11}, Lkp/m;->b(Lj3/f;Ljava/lang/String;Lx2/s;Le3/m;Ll2/o;I)V

    .line 562
    .line 563
    .line 564
    const v6, 0x7f120a22

    .line 565
    .line 566
    .line 567
    invoke-static {v10, v6}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 568
    .line 569
    .line 570
    move-result-object v6

    .line 571
    and-int/lit8 v7, v26, 0x70

    .line 572
    .line 573
    const/16 v8, 0x20

    .line 574
    .line 575
    if-ne v7, v8, :cond_1a

    .line 576
    .line 577
    const/4 v7, 0x1

    .line 578
    goto :goto_11

    .line 579
    :cond_1a
    const/4 v7, 0x0

    .line 580
    :goto_11
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 581
    .line 582
    .line 583
    move-result v8

    .line 584
    or-int/2addr v7, v8

    .line 585
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 586
    .line 587
    .line 588
    move-result-object v8

    .line 589
    if-nez v7, :cond_1b

    .line 590
    .line 591
    if-ne v8, v3, :cond_1c

    .line 592
    .line 593
    :cond_1b
    new-instance v8, Ld90/w;

    .line 594
    .line 595
    invoke-direct {v8, v5, v2, v4}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 596
    .line 597
    .line 598
    invoke-virtual {v10, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 599
    .line 600
    .line 601
    :cond_1c
    check-cast v8, Lay0/a;

    .line 602
    .line 603
    invoke-virtual {v4}, Lh2/g4;->h()Ljava/lang/Long;

    .line 604
    .line 605
    .line 606
    move-result-object v3

    .line 607
    if-eqz v3, :cond_1d

    .line 608
    .line 609
    invoke-virtual {v4}, Lh2/g4;->g()Ljava/lang/Long;

    .line 610
    .line 611
    .line 612
    move-result-object v3

    .line 613
    if-eqz v3, :cond_1d

    .line 614
    .line 615
    const/4 v13, 0x1

    .line 616
    :goto_12
    move-object v11, v10

    .line 617
    move-object v10, v6

    .line 618
    goto :goto_13

    .line 619
    :cond_1d
    const/4 v13, 0x0

    .line 620
    goto :goto_12

    .line 621
    :goto_13
    const/4 v6, 0x0

    .line 622
    const/16 v7, 0x14

    .line 623
    .line 624
    const/4 v9, 0x0

    .line 625
    move-object/from16 v21, v12

    .line 626
    .line 627
    const/4 v12, 0x0

    .line 628
    invoke-static/range {v6 .. v13}, Li91/j0;->w0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 629
    .line 630
    .line 631
    move-object v10, v11

    .line 632
    const/4 v3, 0x1

    .line 633
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 634
    .line 635
    .line 636
    float-to-double v5, v0

    .line 637
    const-wide/16 v7, 0x0

    .line 638
    .line 639
    cmpl-double v3, v5, v7

    .line 640
    .line 641
    if-lez v3, :cond_1e

    .line 642
    .line 643
    const/4 v14, 0x1

    .line 644
    goto :goto_14

    .line 645
    :cond_1e
    const/4 v14, 0x0

    .line 646
    :goto_14
    if-nez v14, :cond_1f

    .line 647
    .line 648
    const-string v3, "invalid weight; must be greater than zero"

    .line 649
    .line 650
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 651
    .line 652
    .line 653
    :cond_1f
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 654
    .line 655
    const/4 v3, 0x1

    .line 656
    invoke-direct {v7, v0, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 657
    .line 658
    .line 659
    sget-object v0, Lh2/c2;->a:Lh2/c2;

    .line 660
    .line 661
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 662
    .line 663
    .line 664
    move-result-object v0

    .line 665
    invoke-virtual {v0}, Lj91/e;->b()J

    .line 666
    .line 667
    .line 668
    move-result-wide v23

    .line 669
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 670
    .line 671
    .line 672
    move-result-object v0

    .line 673
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 674
    .line 675
    .line 676
    move-result-wide v25

    .line 677
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 678
    .line 679
    .line 680
    move-result-object v0

    .line 681
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 682
    .line 683
    .line 684
    move-result-wide v27

    .line 685
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 686
    .line 687
    .line 688
    move-result-object v0

    .line 689
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 690
    .line 691
    .line 692
    move-result-wide v29

    .line 693
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 694
    .line 695
    .line 696
    move-result-object v0

    .line 697
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 698
    .line 699
    .line 700
    move-result-wide v31

    .line 701
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 702
    .line 703
    .line 704
    move-result-object v0

    .line 705
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 706
    .line 707
    .line 708
    move-result-wide v35

    .line 709
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 710
    .line 711
    .line 712
    move-result-object v0

    .line 713
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 714
    .line 715
    .line 716
    move-result-wide v39

    .line 717
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 718
    .line 719
    .line 720
    move-result-object v0

    .line 721
    invoke-virtual {v0}, Lj91/e;->b()J

    .line 722
    .line 723
    .line 724
    move-result-wide v41

    .line 725
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 726
    .line 727
    .line 728
    move-result-object v0

    .line 729
    invoke-virtual {v0}, Lj91/e;->e()J

    .line 730
    .line 731
    .line 732
    move-result-wide v45

    .line 733
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 734
    .line 735
    .line 736
    move-result-object v0

    .line 737
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 738
    .line 739
    .line 740
    move-result-wide v49

    .line 741
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 742
    .line 743
    .line 744
    move-result-object v0

    .line 745
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 746
    .line 747
    .line 748
    move-result-wide v51

    .line 749
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 750
    .line 751
    .line 752
    move-result-object v0

    .line 753
    invoke-virtual {v0}, Lj91/e;->b()J

    .line 754
    .line 755
    .line 756
    move-result-wide v53

    .line 757
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 758
    .line 759
    .line 760
    move-result-object v0

    .line 761
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 762
    .line 763
    .line 764
    move-result-wide v55

    .line 765
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 766
    .line 767
    .line 768
    move-result-object v0

    .line 769
    invoke-virtual {v0}, Lj91/e;->e()J

    .line 770
    .line 771
    .line 772
    move-result-wide v57

    .line 773
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 774
    .line 775
    .line 776
    move-result-object v0

    .line 777
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 778
    .line 779
    .line 780
    move-result-wide v59

    .line 781
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 782
    .line 783
    .line 784
    move-result-object v0

    .line 785
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 786
    .line 787
    .line 788
    move-result-wide v61

    .line 789
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 790
    .line 791
    .line 792
    move-result-object v0

    .line 793
    invoke-virtual {v0}, Lj91/e;->e()J

    .line 794
    .line 795
    .line 796
    move-result-wide v63

    .line 797
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 798
    .line 799
    .line 800
    move-result-object v0

    .line 801
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 802
    .line 803
    .line 804
    move-result-wide v67

    .line 805
    invoke-static {v10}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 806
    .line 807
    .line 808
    move-result-object v0

    .line 809
    invoke-virtual {v0}, Lj91/e;->c()J

    .line 810
    .line 811
    .line 812
    move-result-wide v65

    .line 813
    sget-wide v33, Le3/s;->i:J

    .line 814
    .line 815
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 816
    .line 817
    invoke-virtual {v10, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 818
    .line 819
    .line 820
    move-result-object v0

    .line 821
    check-cast v0, Lh2/f1;

    .line 822
    .line 823
    const/16 v5, 0x30

    .line 824
    .line 825
    invoke-static {v0, v10, v5}, Lh2/c2;->c(Lh2/f1;Ll2/o;I)Lh2/z1;

    .line 826
    .line 827
    .line 828
    move-result-object v22

    .line 829
    const/16 v71, 0x0

    .line 830
    .line 831
    move-wide/from16 v37, v33

    .line 832
    .line 833
    move-wide/from16 v43, v33

    .line 834
    .line 835
    move-wide/from16 v47, v33

    .line 836
    .line 837
    move-wide/from16 v69, v33

    .line 838
    .line 839
    invoke-virtual/range {v22 .. v71}, Lh2/z1;->a(JJJJJJJJJJJJJJJJJJJJJJJJLh2/eb;)Lh2/z1;

    .line 840
    .line 841
    .line 842
    move-result-object v9

    .line 843
    const/4 v13, 0x0

    .line 844
    const/high16 v15, 0x180000

    .line 845
    .line 846
    const/4 v8, 0x0

    .line 847
    move-object v11, v10

    .line 848
    const/4 v10, 0x0

    .line 849
    move-object v14, v11

    .line 850
    const/4 v11, 0x0

    .line 851
    const/4 v12, 0x0

    .line 852
    move-object v6, v4

    .line 853
    invoke-static/range {v6 .. v15}, Lh2/f4;->a(Lh2/g4;Lx2/s;Lh2/g2;Lh2/z1;Lay0/n;Lay0/n;ZLc3/q;Ll2/o;I)V

    .line 854
    .line 855
    .line 856
    move-object v10, v14

    .line 857
    invoke-virtual {v10, v3}, Ll2/t;->q(Z)V

    .line 858
    .line 859
    .line 860
    move-object/from16 v3, p3

    .line 861
    .line 862
    move-object/from16 v4, v21

    .line 863
    .line 864
    goto :goto_15

    .line 865
    :cond_20
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 866
    .line 867
    .line 868
    move-object/from16 v4, p3

    .line 869
    .line 870
    move-object v3, v0

    .line 871
    :goto_15
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 872
    .line 873
    .line 874
    move-result-object v8

    .line 875
    if-eqz v8, :cond_21

    .line 876
    .line 877
    new-instance v0, Ldk/j;

    .line 878
    .line 879
    const/4 v7, 0x2

    .line 880
    move/from16 v5, p5

    .line 881
    .line 882
    move/from16 v6, p6

    .line 883
    .line 884
    invoke-direct/range {v0 .. v7}, Ldk/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 885
    .line 886
    .line 887
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 888
    .line 889
    :cond_21
    return-void
.end method
