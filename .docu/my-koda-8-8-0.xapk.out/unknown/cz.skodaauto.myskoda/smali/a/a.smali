.class public abstract La/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V
    .locals 27

    .line 1
    move/from16 v10, p10

    .line 2
    .line 3
    move-object/from16 v0, p9

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, 0x3335543

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, p11, 0x1

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    or-int/lit8 v2, v10, 0x6

    .line 18
    .line 19
    move v3, v2

    .line 20
    move-object/from16 v2, p0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    and-int/lit8 v2, v10, 0x6

    .line 24
    .line 25
    if-nez v2, :cond_2

    .line 26
    .line 27
    move-object/from16 v2, p0

    .line 28
    .line 29
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    const/4 v3, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/4 v3, 0x2

    .line 38
    :goto_0
    or-int/2addr v3, v10

    .line 39
    goto :goto_1

    .line 40
    :cond_2
    move-object/from16 v2, p0

    .line 41
    .line 42
    move v3, v10

    .line 43
    :goto_1
    and-int/lit8 v4, v10, 0x30

    .line 44
    .line 45
    if-nez v4, :cond_5

    .line 46
    .line 47
    and-int/lit8 v4, p11, 0x2

    .line 48
    .line 49
    if-nez v4, :cond_3

    .line 50
    .line 51
    move-object/from16 v4, p1

    .line 52
    .line 53
    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    if-eqz v5, :cond_4

    .line 58
    .line 59
    const/16 v5, 0x20

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    move-object/from16 v4, p1

    .line 63
    .line 64
    :cond_4
    const/16 v5, 0x10

    .line 65
    .line 66
    :goto_2
    or-int/2addr v3, v5

    .line 67
    goto :goto_3

    .line 68
    :cond_5
    move-object/from16 v4, p1

    .line 69
    .line 70
    :goto_3
    and-int/lit8 v5, p11, 0x4

    .line 71
    .line 72
    if-eqz v5, :cond_7

    .line 73
    .line 74
    or-int/lit16 v3, v3, 0x180

    .line 75
    .line 76
    :cond_6
    move-object/from16 v6, p2

    .line 77
    .line 78
    goto :goto_5

    .line 79
    :cond_7
    and-int/lit16 v6, v10, 0x180

    .line 80
    .line 81
    if-nez v6, :cond_6

    .line 82
    .line 83
    move-object/from16 v6, p2

    .line 84
    .line 85
    invoke-virtual {v0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v7

    .line 89
    if-eqz v7, :cond_8

    .line 90
    .line 91
    const/16 v7, 0x100

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_8
    const/16 v7, 0x80

    .line 95
    .line 96
    :goto_4
    or-int/2addr v3, v7

    .line 97
    :goto_5
    or-int/lit16 v3, v3, 0xc00

    .line 98
    .line 99
    and-int/lit16 v7, v10, 0x6000

    .line 100
    .line 101
    if-nez v7, :cond_b

    .line 102
    .line 103
    and-int/lit8 v7, p11, 0x10

    .line 104
    .line 105
    if-nez v7, :cond_9

    .line 106
    .line 107
    move-object/from16 v7, p3

    .line 108
    .line 109
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    if-eqz v8, :cond_a

    .line 114
    .line 115
    const/16 v8, 0x4000

    .line 116
    .line 117
    goto :goto_6

    .line 118
    :cond_9
    move-object/from16 v7, p3

    .line 119
    .line 120
    :cond_a
    const/16 v8, 0x2000

    .line 121
    .line 122
    :goto_6
    or-int/2addr v3, v8

    .line 123
    goto :goto_7

    .line 124
    :cond_b
    move-object/from16 v7, p3

    .line 125
    .line 126
    :goto_7
    and-int/lit8 v8, p11, 0x20

    .line 127
    .line 128
    const/high16 v9, 0x30000

    .line 129
    .line 130
    if-eqz v8, :cond_d

    .line 131
    .line 132
    or-int/2addr v3, v9

    .line 133
    :cond_c
    move-object/from16 v9, p4

    .line 134
    .line 135
    goto :goto_9

    .line 136
    :cond_d
    and-int/2addr v9, v10

    .line 137
    if-nez v9, :cond_c

    .line 138
    .line 139
    move-object/from16 v9, p4

    .line 140
    .line 141
    invoke-virtual {v0, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v11

    .line 145
    if-eqz v11, :cond_e

    .line 146
    .line 147
    const/high16 v11, 0x20000

    .line 148
    .line 149
    goto :goto_8

    .line 150
    :cond_e
    const/high16 v11, 0x10000

    .line 151
    .line 152
    :goto_8
    or-int/2addr v3, v11

    .line 153
    :goto_9
    const/high16 v11, 0x180000

    .line 154
    .line 155
    and-int/2addr v11, v10

    .line 156
    if-nez v11, :cond_f

    .line 157
    .line 158
    const/high16 v11, 0x80000

    .line 159
    .line 160
    or-int/2addr v3, v11

    .line 161
    :cond_f
    const/high16 v11, 0xc00000

    .line 162
    .line 163
    or-int/2addr v11, v3

    .line 164
    const/high16 v12, 0x6000000

    .line 165
    .line 166
    and-int/2addr v12, v10

    .line 167
    if-nez v12, :cond_10

    .line 168
    .line 169
    const/high16 v11, 0x2c00000

    .line 170
    .line 171
    or-int/2addr v11, v3

    .line 172
    :cond_10
    const/high16 v3, 0x30000000

    .line 173
    .line 174
    and-int/2addr v3, v10

    .line 175
    if-nez v3, :cond_12

    .line 176
    .line 177
    move-object/from16 v3, p8

    .line 178
    .line 179
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v12

    .line 183
    if-eqz v12, :cond_11

    .line 184
    .line 185
    const/high16 v12, 0x20000000

    .line 186
    .line 187
    goto :goto_a

    .line 188
    :cond_11
    const/high16 v12, 0x10000000

    .line 189
    .line 190
    :goto_a
    or-int/2addr v11, v12

    .line 191
    goto :goto_b

    .line 192
    :cond_12
    move-object/from16 v3, p8

    .line 193
    .line 194
    :goto_b
    const v12, 0x12492493

    .line 195
    .line 196
    .line 197
    and-int/2addr v12, v11

    .line 198
    const v13, 0x12492492

    .line 199
    .line 200
    .line 201
    const/4 v14, 0x0

    .line 202
    const/4 v15, 0x1

    .line 203
    if-eq v12, v13, :cond_13

    .line 204
    .line 205
    move v12, v15

    .line 206
    goto :goto_c

    .line 207
    :cond_13
    move v12, v14

    .line 208
    :goto_c
    and-int/lit8 v13, v11, 0x1

    .line 209
    .line 210
    invoke-virtual {v0, v13, v12}, Ll2/t;->O(IZ)Z

    .line 211
    .line 212
    .line 213
    move-result v12

    .line 214
    if-eqz v12, :cond_1f

    .line 215
    .line 216
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 217
    .line 218
    .line 219
    and-int/lit8 v12, v10, 0x1

    .line 220
    .line 221
    const v13, -0xe380001

    .line 222
    .line 223
    .line 224
    const v16, -0xe001

    .line 225
    .line 226
    .line 227
    if-eqz v12, :cond_17

    .line 228
    .line 229
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 230
    .line 231
    .line 232
    move-result v12

    .line 233
    if-eqz v12, :cond_14

    .line 234
    .line 235
    goto :goto_e

    .line 236
    :cond_14
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 237
    .line 238
    .line 239
    and-int/lit8 v1, p11, 0x2

    .line 240
    .line 241
    if-eqz v1, :cond_15

    .line 242
    .line 243
    and-int/lit8 v11, v11, -0x71

    .line 244
    .line 245
    :cond_15
    and-int/lit8 v1, p11, 0x10

    .line 246
    .line 247
    if-eqz v1, :cond_16

    .line 248
    .line 249
    and-int v11, v11, v16

    .line 250
    .line 251
    :cond_16
    and-int v1, v11, v13

    .line 252
    .line 253
    move-object/from16 v15, p5

    .line 254
    .line 255
    move/from16 v16, p6

    .line 256
    .line 257
    move-object/from16 v17, p7

    .line 258
    .line 259
    move-object v11, v2

    .line 260
    move-object v13, v6

    .line 261
    :goto_d
    move-object v12, v4

    .line 262
    move-object/from16 v19, v7

    .line 263
    .line 264
    move-object/from16 v18, v9

    .line 265
    .line 266
    goto :goto_11

    .line 267
    :cond_17
    :goto_e
    if-eqz v1, :cond_18

    .line 268
    .line 269
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 270
    .line 271
    goto :goto_f

    .line 272
    :cond_18
    move-object v1, v2

    .line 273
    :goto_f
    and-int/lit8 v2, p11, 0x2

    .line 274
    .line 275
    if-eqz v2, :cond_19

    .line 276
    .line 277
    const/4 v2, 0x3

    .line 278
    invoke-static {v14, v2, v0}, Lm1/v;->a(IILl2/o;)Lm1/t;

    .line 279
    .line 280
    .line 281
    move-result-object v2

    .line 282
    and-int/lit8 v11, v11, -0x71

    .line 283
    .line 284
    move-object v4, v2

    .line 285
    :cond_19
    if-eqz v5, :cond_1a

    .line 286
    .line 287
    int-to-float v2, v14

    .line 288
    new-instance v5, Lk1/a1;

    .line 289
    .line 290
    invoke-direct {v5, v2, v2, v2, v2}, Lk1/a1;-><init>(FFFF)V

    .line 291
    .line 292
    .line 293
    goto :goto_10

    .line 294
    :cond_1a
    move-object v5, v6

    .line 295
    :goto_10
    and-int/lit8 v2, p11, 0x10

    .line 296
    .line 297
    if-eqz v2, :cond_1b

    .line 298
    .line 299
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 300
    .line 301
    and-int v11, v11, v16

    .line 302
    .line 303
    move-object v7, v2

    .line 304
    :cond_1b
    if-eqz v8, :cond_1c

    .line 305
    .line 306
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 307
    .line 308
    move-object v9, v2

    .line 309
    :cond_1c
    invoke-static {v0}, Lb1/h1;->a(Ll2/o;)Lc1/u;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    move-result v6

    .line 317
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v8

    .line 321
    if-nez v6, :cond_1d

    .line 322
    .line 323
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 324
    .line 325
    if-ne v8, v6, :cond_1e

    .line 326
    .line 327
    :cond_1d
    new-instance v8, Lg1/d0;

    .line 328
    .line 329
    invoke-direct {v8, v2}, Lg1/d0;-><init>(Lc1/u;)V

    .line 330
    .line 331
    .line 332
    invoke-virtual {v0, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    :cond_1e
    move-object v2, v8

    .line 336
    check-cast v2, Lg1/d0;

    .line 337
    .line 338
    invoke-static {v0}, Le1/e1;->a(Ll2/o;)Le1/j;

    .line 339
    .line 340
    .line 341
    move-result-object v6

    .line 342
    and-int v8, v11, v13

    .line 343
    .line 344
    move-object v11, v1

    .line 345
    move-object v13, v5

    .line 346
    move-object/from16 v17, v6

    .line 347
    .line 348
    move v1, v8

    .line 349
    move/from16 v16, v15

    .line 350
    .line 351
    move-object v15, v2

    .line 352
    goto :goto_d

    .line 353
    :goto_11
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 354
    .line 355
    .line 356
    and-int/lit8 v2, v1, 0xe

    .line 357
    .line 358
    or-int/lit16 v2, v2, 0x6000

    .line 359
    .line 360
    and-int/lit8 v4, v1, 0x70

    .line 361
    .line 362
    or-int/2addr v2, v4

    .line 363
    and-int/lit16 v4, v1, 0x380

    .line 364
    .line 365
    or-int/2addr v2, v4

    .line 366
    and-int/lit16 v4, v1, 0x1c00

    .line 367
    .line 368
    or-int/2addr v2, v4

    .line 369
    shr-int/lit8 v4, v1, 0x3

    .line 370
    .line 371
    const/high16 v5, 0x380000

    .line 372
    .line 373
    and-int/2addr v4, v5

    .line 374
    or-int/2addr v2, v4

    .line 375
    shl-int/lit8 v4, v1, 0xc

    .line 376
    .line 377
    const/high16 v5, 0x70000000

    .line 378
    .line 379
    and-int/2addr v4, v5

    .line 380
    or-int v24, v2, v4

    .line 381
    .line 382
    shr-int/lit8 v2, v1, 0xc

    .line 383
    .line 384
    and-int/lit8 v2, v2, 0xe

    .line 385
    .line 386
    shr-int/lit8 v1, v1, 0x12

    .line 387
    .line 388
    and-int/lit16 v1, v1, 0x1c00

    .line 389
    .line 390
    or-int v25, v2, v1

    .line 391
    .line 392
    const/16 v26, 0x1900

    .line 393
    .line 394
    const/4 v14, 0x1

    .line 395
    const/16 v20, 0x0

    .line 396
    .line 397
    const/16 v21, 0x0

    .line 398
    .line 399
    move-object/from16 v23, v0

    .line 400
    .line 401
    move-object/from16 v22, v3

    .line 402
    .line 403
    invoke-static/range {v11 .. v26}, Lb0/c;->a(Lx2/s;Lm1/t;Lk1/z0;ZLg1/j1;ZLe1/j;Lx2/d;Lk1/i;Lx2/i;Lk1/g;Lay0/k;Ll2/o;III)V

    .line 404
    .line 405
    .line 406
    move-object v1, v11

    .line 407
    move-object v2, v12

    .line 408
    move-object v3, v13

    .line 409
    move-object v6, v15

    .line 410
    move/from16 v7, v16

    .line 411
    .line 412
    move-object/from16 v8, v17

    .line 413
    .line 414
    move-object/from16 v5, v18

    .line 415
    .line 416
    move-object/from16 v4, v19

    .line 417
    .line 418
    goto :goto_12

    .line 419
    :cond_1f
    move-object/from16 v23, v0

    .line 420
    .line 421
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 422
    .line 423
    .line 424
    move-object/from16 v8, p7

    .line 425
    .line 426
    move-object v1, v2

    .line 427
    move-object v2, v4

    .line 428
    move-object v3, v6

    .line 429
    move-object v4, v7

    .line 430
    move-object v5, v9

    .line 431
    move-object/from16 v6, p5

    .line 432
    .line 433
    move/from16 v7, p6

    .line 434
    .line 435
    :goto_12
    invoke-virtual/range {v23 .. v23}, Ll2/t;->s()Ll2/u1;

    .line 436
    .line 437
    .line 438
    move-result-object v13

    .line 439
    if-eqz v13, :cond_20

    .line 440
    .line 441
    new-instance v0, Lh2/r0;

    .line 442
    .line 443
    const/4 v12, 0x2

    .line 444
    move-object/from16 v9, p8

    .line 445
    .line 446
    move/from16 v11, p11

    .line 447
    .line 448
    invoke-direct/range {v0 .. v12}, Lh2/r0;-><init>(Lx2/s;Lm1/t;Lk1/z0;Ljava/lang/Object;Ljava/lang/Object;Lg1/j1;ZLe1/j;Lay0/k;III)V

    .line 449
    .line 450
    .line 451
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 452
    .line 453
    :cond_20
    return-void
.end method

.method public static final b(Lx2/s;Lm1/t;Lk1/z0;Lk1/g;Lx2/i;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V
    .locals 27

    .line 1
    move-object/from16 v12, p9

    .line 2
    .line 3
    check-cast v12, Ll2/t;

    .line 4
    .line 5
    const v0, -0x705086e1

    .line 6
    .line 7
    .line 8
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    and-int/lit8 v0, p10, 0x6

    .line 12
    .line 13
    move-object/from16 v14, p0

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {v12, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x2

    .line 26
    :goto_0
    or-int v0, p10, v0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move/from16 v0, p10

    .line 30
    .line 31
    :goto_1
    and-int/lit8 v1, p11, 0x2

    .line 32
    .line 33
    if-nez v1, :cond_2

    .line 34
    .line 35
    move-object/from16 v1, p1

    .line 36
    .line 37
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_3

    .line 42
    .line 43
    const/16 v2, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    move-object/from16 v1, p1

    .line 47
    .line 48
    :cond_3
    const/16 v2, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v2

    .line 51
    and-int/lit8 v2, p11, 0x4

    .line 52
    .line 53
    if-eqz v2, :cond_4

    .line 54
    .line 55
    or-int/lit16 v0, v0, 0x180

    .line 56
    .line 57
    move-object/from16 v3, p2

    .line 58
    .line 59
    goto :goto_4

    .line 60
    :cond_4
    move-object/from16 v3, p2

    .line 61
    .line 62
    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_5

    .line 67
    .line 68
    const/16 v4, 0x100

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_5
    const/16 v4, 0x80

    .line 72
    .line 73
    :goto_3
    or-int/2addr v0, v4

    .line 74
    :goto_4
    or-int/lit16 v0, v0, 0xc00

    .line 75
    .line 76
    and-int/lit8 v4, p11, 0x10

    .line 77
    .line 78
    if-nez v4, :cond_6

    .line 79
    .line 80
    move-object/from16 v4, p3

    .line 81
    .line 82
    invoke-virtual {v12, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    if-eqz v5, :cond_7

    .line 87
    .line 88
    const/16 v5, 0x4000

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_6
    move-object/from16 v4, p3

    .line 92
    .line 93
    :cond_7
    const/16 v5, 0x2000

    .line 94
    .line 95
    :goto_5
    or-int/2addr v0, v5

    .line 96
    const/high16 v5, 0x30000

    .line 97
    .line 98
    or-int/2addr v0, v5

    .line 99
    and-int/lit8 v5, p11, 0x40

    .line 100
    .line 101
    if-nez v5, :cond_8

    .line 102
    .line 103
    move-object/from16 v5, p5

    .line 104
    .line 105
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v6

    .line 109
    if-eqz v6, :cond_9

    .line 110
    .line 111
    const/high16 v6, 0x100000

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_8
    move-object/from16 v5, p5

    .line 115
    .line 116
    :cond_9
    const/high16 v6, 0x80000

    .line 117
    .line 118
    :goto_6
    or-int/2addr v0, v6

    .line 119
    const/high16 v6, 0x2c00000

    .line 120
    .line 121
    or-int/2addr v0, v6

    .line 122
    move-object/from16 v11, p8

    .line 123
    .line 124
    invoke-virtual {v12, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v6

    .line 128
    if-eqz v6, :cond_a

    .line 129
    .line 130
    const/high16 v6, 0x20000000

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_a
    const/high16 v6, 0x10000000

    .line 134
    .line 135
    :goto_7
    or-int/2addr v0, v6

    .line 136
    const v6, 0x12492493

    .line 137
    .line 138
    .line 139
    and-int/2addr v6, v0

    .line 140
    const v7, 0x12492492

    .line 141
    .line 142
    .line 143
    const/4 v8, 0x0

    .line 144
    const/4 v9, 0x1

    .line 145
    if-eq v6, v7, :cond_b

    .line 146
    .line 147
    move v6, v9

    .line 148
    goto :goto_8

    .line 149
    :cond_b
    move v6, v8

    .line 150
    :goto_8
    and-int/lit8 v7, v0, 0x1

    .line 151
    .line 152
    invoke-virtual {v12, v7, v6}, Ll2/t;->O(IZ)Z

    .line 153
    .line 154
    .line 155
    move-result v6

    .line 156
    if-eqz v6, :cond_17

    .line 157
    .line 158
    invoke-virtual {v12}, Ll2/t;->T()V

    .line 159
    .line 160
    .line 161
    and-int/lit8 v6, p10, 0x1

    .line 162
    .line 163
    const v7, -0xe000001

    .line 164
    .line 165
    .line 166
    const v10, -0x380001

    .line 167
    .line 168
    .line 169
    const v13, -0xe001

    .line 170
    .line 171
    .line 172
    if-eqz v6, :cond_10

    .line 173
    .line 174
    invoke-virtual {v12}, Ll2/t;->y()Z

    .line 175
    .line 176
    .line 177
    move-result v6

    .line 178
    if-eqz v6, :cond_c

    .line 179
    .line 180
    goto :goto_a

    .line 181
    :cond_c
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 182
    .line 183
    .line 184
    and-int/lit8 v2, p11, 0x2

    .line 185
    .line 186
    if-eqz v2, :cond_d

    .line 187
    .line 188
    and-int/lit8 v0, v0, -0x71

    .line 189
    .line 190
    :cond_d
    and-int/lit8 v2, p11, 0x10

    .line 191
    .line 192
    if-eqz v2, :cond_e

    .line 193
    .line 194
    and-int/2addr v0, v13

    .line 195
    :cond_e
    and-int/lit8 v2, p11, 0x40

    .line 196
    .line 197
    if-eqz v2, :cond_f

    .line 198
    .line 199
    and-int/2addr v0, v10

    .line 200
    :cond_f
    and-int/2addr v0, v7

    .line 201
    move-object/from16 v9, p4

    .line 202
    .line 203
    move-object/from16 v6, p7

    .line 204
    .line 205
    move-object v10, v4

    .line 206
    move-object v4, v5

    .line 207
    move/from16 v5, p6

    .line 208
    .line 209
    :goto_9
    move-object v2, v3

    .line 210
    goto :goto_b

    .line 211
    :cond_10
    :goto_a
    and-int/lit8 v6, p11, 0x2

    .line 212
    .line 213
    if-eqz v6, :cond_11

    .line 214
    .line 215
    const/4 v1, 0x3

    .line 216
    invoke-static {v8, v1, v12}, Lm1/v;->a(IILl2/o;)Lm1/t;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    and-int/lit8 v0, v0, -0x71

    .line 221
    .line 222
    :cond_11
    if-eqz v2, :cond_12

    .line 223
    .line 224
    int-to-float v2, v8

    .line 225
    new-instance v3, Lk1/a1;

    .line 226
    .line 227
    invoke-direct {v3, v2, v2, v2, v2}, Lk1/a1;-><init>(FFFF)V

    .line 228
    .line 229
    .line 230
    :cond_12
    and-int/lit8 v2, p11, 0x10

    .line 231
    .line 232
    if-eqz v2, :cond_13

    .line 233
    .line 234
    sget-object v2, Lk1/j;->a:Lk1/c;

    .line 235
    .line 236
    and-int/2addr v0, v13

    .line 237
    move-object v4, v2

    .line 238
    :cond_13
    sget-object v2, Lx2/c;->m:Lx2/i;

    .line 239
    .line 240
    and-int/lit8 v6, p11, 0x40

    .line 241
    .line 242
    if-eqz v6, :cond_16

    .line 243
    .line 244
    invoke-static {v12}, Lb1/h1;->a(Ll2/o;)Lc1/u;

    .line 245
    .line 246
    .line 247
    move-result-object v5

    .line 248
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result v6

    .line 252
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v8

    .line 256
    if-nez v6, :cond_14

    .line 257
    .line 258
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 259
    .line 260
    if-ne v8, v6, :cond_15

    .line 261
    .line 262
    :cond_14
    new-instance v8, Lg1/d0;

    .line 263
    .line 264
    invoke-direct {v8, v5}, Lg1/d0;-><init>(Lc1/u;)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    :cond_15
    move-object v5, v8

    .line 271
    check-cast v5, Lg1/d0;

    .line 272
    .line 273
    and-int/2addr v0, v10

    .line 274
    :cond_16
    invoke-static {v12}, Le1/e1;->a(Ll2/o;)Le1/j;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    and-int/2addr v0, v7

    .line 279
    move-object v10, v4

    .line 280
    move-object v4, v5

    .line 281
    move v5, v9

    .line 282
    move-object v9, v2

    .line 283
    goto :goto_9

    .line 284
    :goto_b
    invoke-virtual {v12}, Ll2/t;->r()V

    .line 285
    .line 286
    .line 287
    and-int/lit8 v3, v0, 0xe

    .line 288
    .line 289
    or-int/lit16 v3, v3, 0x6000

    .line 290
    .line 291
    and-int/lit8 v7, v0, 0x70

    .line 292
    .line 293
    or-int/2addr v3, v7

    .line 294
    and-int/lit16 v7, v0, 0x380

    .line 295
    .line 296
    or-int/2addr v3, v7

    .line 297
    or-int/lit16 v3, v3, 0xc00

    .line 298
    .line 299
    shr-int/lit8 v7, v0, 0x3

    .line 300
    .line 301
    const/high16 v8, 0x70000

    .line 302
    .line 303
    and-int/2addr v7, v8

    .line 304
    or-int/2addr v3, v7

    .line 305
    const/high16 v7, 0x180000

    .line 306
    .line 307
    or-int v13, v3, v7

    .line 308
    .line 309
    shr-int/lit8 v3, v0, 0x6

    .line 310
    .line 311
    and-int/lit16 v3, v3, 0x380

    .line 312
    .line 313
    const/16 v7, 0x30

    .line 314
    .line 315
    or-int/2addr v3, v7

    .line 316
    shr-int/lit8 v0, v0, 0x12

    .line 317
    .line 318
    and-int/lit16 v0, v0, 0x1c00

    .line 319
    .line 320
    or-int/2addr v0, v3

    .line 321
    const/16 v15, 0x700

    .line 322
    .line 323
    const/4 v3, 0x0

    .line 324
    const/4 v7, 0x0

    .line 325
    const/4 v8, 0x0

    .line 326
    move-object/from16 v26, v14

    .line 327
    .line 328
    move v14, v0

    .line 329
    move-object/from16 v0, v26

    .line 330
    .line 331
    invoke-static/range {v0 .. v15}, Lb0/c;->a(Lx2/s;Lm1/t;Lk1/z0;ZLg1/j1;ZLe1/j;Lx2/d;Lk1/i;Lx2/i;Lk1/g;Lay0/k;Ll2/o;III)V

    .line 332
    .line 333
    .line 334
    move-object/from16 v16, v2

    .line 335
    .line 336
    move-object/from16 v19, v4

    .line 337
    .line 338
    move/from16 v20, v5

    .line 339
    .line 340
    move-object/from16 v21, v6

    .line 341
    .line 342
    move-object/from16 v18, v9

    .line 343
    .line 344
    move-object/from16 v17, v10

    .line 345
    .line 346
    :goto_c
    move-object v15, v1

    .line 347
    goto :goto_d

    .line 348
    :cond_17
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 349
    .line 350
    .line 351
    move-object/from16 v18, p4

    .line 352
    .line 353
    move/from16 v20, p6

    .line 354
    .line 355
    move-object/from16 v21, p7

    .line 356
    .line 357
    move-object/from16 v16, v3

    .line 358
    .line 359
    move-object/from16 v17, v4

    .line 360
    .line 361
    move-object/from16 v19, v5

    .line 362
    .line 363
    goto :goto_c

    .line 364
    :goto_d
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    if-eqz v0, :cond_18

    .line 369
    .line 370
    new-instance v13, Lh2/r0;

    .line 371
    .line 372
    const/16 v25, 0x1

    .line 373
    .line 374
    move-object/from16 v14, p0

    .line 375
    .line 376
    move-object/from16 v22, p8

    .line 377
    .line 378
    move/from16 v23, p10

    .line 379
    .line 380
    move/from16 v24, p11

    .line 381
    .line 382
    invoke-direct/range {v13 .. v25}, Lh2/r0;-><init>(Lx2/s;Lm1/t;Lk1/z0;Ljava/lang/Object;Ljava/lang/Object;Lg1/j1;ZLe1/j;Lay0/k;III)V

    .line 383
    .line 384
    .line 385
    iput-object v13, v0, Ll2/u1;->d:Lay0/n;

    .line 386
    .line 387
    :cond_18
    return-void
.end method

.method public static final c(Ljava/lang/Integer;Lay0/k;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "event"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v9, p2

    .line 13
    .line 14
    check-cast v9, Ll2/t;

    .line 15
    .line 16
    const v3, 0x53b4a700

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/4 v4, 0x4

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    move v3, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v3, 0x2

    .line 32
    :goto_0
    or-int/2addr v3, v2

    .line 33
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    const/16 v6, 0x20

    .line 38
    .line 39
    if-eqz v5, :cond_1

    .line 40
    .line 41
    move v5, v6

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/16 v5, 0x10

    .line 44
    .line 45
    :goto_1
    or-int/2addr v3, v5

    .line 46
    and-int/lit8 v5, v3, 0x13

    .line 47
    .line 48
    const/16 v7, 0x12

    .line 49
    .line 50
    const/4 v10, 0x0

    .line 51
    const/4 v8, 0x1

    .line 52
    if-eq v5, v7, :cond_2

    .line 53
    .line 54
    move v5, v8

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    move v5, v10

    .line 57
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 58
    .line 59
    invoke-virtual {v9, v7, v5}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result v5

    .line 63
    if-eqz v5, :cond_c

    .line 64
    .line 65
    and-int/lit8 v5, v3, 0xe

    .line 66
    .line 67
    if-ne v5, v4, :cond_3

    .line 68
    .line 69
    move v4, v8

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    move v4, v10

    .line 72
    :goto_3
    and-int/lit8 v3, v3, 0x70

    .line 73
    .line 74
    if-ne v3, v6, :cond_4

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    move v8, v10

    .line 78
    :goto_4
    or-int v3, v4, v8

    .line 79
    .line 80
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-nez v3, :cond_5

    .line 87
    .line 88
    if-ne v4, v11, :cond_6

    .line 89
    .line 90
    :cond_5
    new-instance v4, Lwh/g;

    .line 91
    .line 92
    const/4 v3, 0x1

    .line 93
    invoke-direct {v4, v0, v1, v3}, Lwh/g;-><init>(Ljava/lang/Integer;Lay0/k;I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_6
    check-cast v4, Lay0/k;

    .line 100
    .line 101
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 102
    .line 103
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    check-cast v3, Ljava/lang/Boolean;

    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    if-eqz v3, :cond_7

    .line 114
    .line 115
    const v3, -0x105bcaaa

    .line 116
    .line 117
    .line 118
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 122
    .line 123
    .line 124
    const/4 v3, 0x0

    .line 125
    goto :goto_5

    .line 126
    :cond_7
    const v3, 0x31054eee

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 130
    .line 131
    .line 132
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 133
    .line 134
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v3

    .line 138
    check-cast v3, Lhi/a;

    .line 139
    .line 140
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    :goto_5
    new-instance v7, Lvh/i;

    .line 144
    .line 145
    const/16 v5, 0x8

    .line 146
    .line 147
    invoke-direct {v7, v5, v3, v4}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    if-eqz v5, :cond_b

    .line 155
    .line 156
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 157
    .line 158
    if-eqz v3, :cond_8

    .line 159
    .line 160
    move-object v3, v5

    .line 161
    check-cast v3, Landroidx/lifecycle/k;

    .line 162
    .line 163
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    :goto_6
    move-object v8, v3

    .line 168
    goto :goto_7

    .line 169
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 170
    .line 171
    goto :goto_6

    .line 172
    :goto_7
    const-class v3, Lyh/e;

    .line 173
    .line 174
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 175
    .line 176
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    const/4 v6, 0x0

    .line 181
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    move-object v14, v3

    .line 186
    check-cast v14, Lyh/e;

    .line 187
    .line 188
    iget-object v3, v14, Lyh/e;->e:Lyy0/l1;

    .line 189
    .line 190
    invoke-static {v3, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v3

    .line 202
    check-cast v3, Lyh/d;

    .line 203
    .line 204
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    if-nez v5, :cond_9

    .line 213
    .line 214
    if-ne v6, v11, :cond_a

    .line 215
    .line 216
    :cond_9
    new-instance v12, Ly21/d;

    .line 217
    .line 218
    const/16 v18, 0x0

    .line 219
    .line 220
    const/16 v19, 0x8

    .line 221
    .line 222
    const/4 v13, 0x1

    .line 223
    const-class v15, Lyh/e;

    .line 224
    .line 225
    const-string v16, "onUiEvent"

    .line 226
    .line 227
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding2/solar/capacity/EnterCapacityScreenUiEvent;)V"

    .line 228
    .line 229
    invoke-direct/range {v12 .. v19}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    move-object v6, v12

    .line 236
    :cond_a
    check-cast v6, Lhy0/g;

    .line 237
    .line 238
    check-cast v6, Lay0/k;

    .line 239
    .line 240
    invoke-interface {v4, v3, v6, v9, v10}, Leh/n;->Q(Lyh/d;Lay0/k;Ll2/o;I)V

    .line 241
    .line 242
    .line 243
    goto :goto_8

    .line 244
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 245
    .line 246
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 247
    .line 248
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw v0

    .line 252
    :cond_c
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 253
    .line 254
    .line 255
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 256
    .line 257
    .line 258
    move-result-object v3

    .line 259
    if-eqz v3, :cond_d

    .line 260
    .line 261
    new-instance v4, Lx40/n;

    .line 262
    .line 263
    const/16 v5, 0xf

    .line 264
    .line 265
    invoke-direct {v4, v2, v5, v0, v1}, Lx40/n;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 269
    .line 270
    :cond_d
    return-void
.end method

.method public static d(I)Ljava/lang/String;
    .locals 2

    .line 1
    if-eqz p0, :cond_a

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p0, v0, :cond_9

    .line 5
    .line 6
    const/16 v0, 0x8

    .line 7
    .line 8
    if-eq p0, v0, :cond_8

    .line 9
    .line 10
    const/16 v0, 0x13

    .line 11
    .line 12
    if-eq p0, v0, :cond_7

    .line 13
    .line 14
    const/16 v0, 0x16

    .line 15
    .line 16
    if-eq p0, v0, :cond_6

    .line 17
    .line 18
    const/16 v0, 0x22

    .line 19
    .line 20
    if-eq p0, v0, :cond_5

    .line 21
    .line 22
    const/16 v0, 0x29

    .line 23
    .line 24
    if-eq p0, v0, :cond_4

    .line 25
    .line 26
    const/16 v0, 0x3e

    .line 27
    .line 28
    if-eq p0, v0, :cond_3

    .line 29
    .line 30
    const/16 v0, 0x85

    .line 31
    .line 32
    if-eq p0, v0, :cond_2

    .line 33
    .line 34
    const/16 v0, 0x93

    .line 35
    .line 36
    if-eq p0, v0, :cond_1

    .line 37
    .line 38
    const/16 v0, 0x100

    .line 39
    .line 40
    if-eq p0, v0, :cond_0

    .line 41
    .line 42
    const-string v0, "UNKNOWN ("

    .line 43
    .line 44
    const-string v1, ")"

    .line 45
    .line 46
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :cond_0
    const-string p0, "GATT CONN CANCEL "

    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_1
    const-string p0, "GATT TIMEOUT"

    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_2
    const-string p0, "GATT ERROR"

    .line 58
    .line 59
    return-object p0

    .line 60
    :cond_3
    const-string p0, "GATT CONN FAIL ESTABLISH"

    .line 61
    .line 62
    return-object p0

    .line 63
    :cond_4
    const-string p0, "GATT PAIRING WITH UNIT KEY NOT SUPPORTED"

    .line 64
    .line 65
    return-object p0

    .line 66
    :cond_5
    const-string p0, "GATT CONN LMP TIMEOUT"

    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_6
    const-string p0, "GATT CONN TERMINATE LOCAL HOST"

    .line 70
    .line 71
    return-object p0

    .line 72
    :cond_7
    const-string p0, "GATT CONN TERMINATE PEER USER"

    .line 73
    .line 74
    return-object p0

    .line 75
    :cond_8
    const-string p0, "GATT CONN TIMEOUT"

    .line 76
    .line 77
    return-object p0

    .line 78
    :cond_9
    const-string p0, "GATT CONN L2C FAILURE"

    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_a
    const-string p0, "SUCCESS"

    .line 82
    .line 83
    return-object p0
.end method
