.class public abstract Lkp/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V
    .locals 19

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move/from16 v8, p8

    .line 4
    .line 5
    move-object/from16 v0, p7

    .line 6
    .line 7
    check-cast v0, Ll2/t;

    .line 8
    .line 9
    const v1, 0x441d0e20

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v1, v8, 0x6

    .line 16
    .line 17
    move-object/from16 v10, p0

    .line 18
    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v1, 0x2

    .line 30
    :goto_0
    or-int/2addr v1, v8

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v1, v8

    .line 33
    :goto_1
    and-int/lit8 v3, v8, 0x30

    .line 34
    .line 35
    if-nez v3, :cond_3

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_2

    .line 42
    .line 43
    const/16 v3, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/16 v3, 0x10

    .line 47
    .line 48
    :goto_2
    or-int/2addr v1, v3

    .line 49
    :cond_3
    and-int/lit8 v3, p9, 0x4

    .line 50
    .line 51
    if-eqz v3, :cond_5

    .line 52
    .line 53
    or-int/lit16 v1, v1, 0x180

    .line 54
    .line 55
    :cond_4
    move-object/from16 v5, p2

    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_5
    and-int/lit16 v5, v8, 0x180

    .line 59
    .line 60
    if-nez v5, :cond_4

    .line 61
    .line 62
    move-object/from16 v5, p2

    .line 63
    .line 64
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    if-eqz v6, :cond_6

    .line 69
    .line 70
    const/16 v6, 0x100

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_6
    const/16 v6, 0x80

    .line 74
    .line 75
    :goto_3
    or-int/2addr v1, v6

    .line 76
    :goto_4
    and-int/lit8 v6, p9, 0x8

    .line 77
    .line 78
    if-eqz v6, :cond_8

    .line 79
    .line 80
    or-int/lit16 v1, v1, 0xc00

    .line 81
    .line 82
    :cond_7
    move-object/from16 v7, p3

    .line 83
    .line 84
    goto :goto_6

    .line 85
    :cond_8
    and-int/lit16 v7, v8, 0xc00

    .line 86
    .line 87
    if-nez v7, :cond_7

    .line 88
    .line 89
    move-object/from16 v7, p3

    .line 90
    .line 91
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    if-eqz v9, :cond_9

    .line 96
    .line 97
    const/16 v9, 0x800

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_9
    const/16 v9, 0x400

    .line 101
    .line 102
    :goto_5
    or-int/2addr v1, v9

    .line 103
    :goto_6
    and-int/lit8 v9, p9, 0x10

    .line 104
    .line 105
    if-eqz v9, :cond_b

    .line 106
    .line 107
    or-int/lit16 v1, v1, 0x6000

    .line 108
    .line 109
    :cond_a
    move-object/from16 v11, p4

    .line 110
    .line 111
    goto :goto_8

    .line 112
    :cond_b
    and-int/lit16 v11, v8, 0x6000

    .line 113
    .line 114
    if-nez v11, :cond_a

    .line 115
    .line 116
    move-object/from16 v11, p4

    .line 117
    .line 118
    invoke-virtual {v0, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v12

    .line 122
    if-eqz v12, :cond_c

    .line 123
    .line 124
    const/16 v12, 0x4000

    .line 125
    .line 126
    goto :goto_7

    .line 127
    :cond_c
    const/16 v12, 0x2000

    .line 128
    .line 129
    :goto_7
    or-int/2addr v1, v12

    .line 130
    :goto_8
    and-int/lit8 v12, p9, 0x20

    .line 131
    .line 132
    const/high16 v13, 0x30000

    .line 133
    .line 134
    if-eqz v12, :cond_e

    .line 135
    .line 136
    or-int/2addr v1, v13

    .line 137
    :cond_d
    move/from16 v13, p5

    .line 138
    .line 139
    goto :goto_a

    .line 140
    :cond_e
    and-int/2addr v13, v8

    .line 141
    if-nez v13, :cond_d

    .line 142
    .line 143
    move/from16 v13, p5

    .line 144
    .line 145
    invoke-virtual {v0, v13}, Ll2/t;->d(F)Z

    .line 146
    .line 147
    .line 148
    move-result v14

    .line 149
    if-eqz v14, :cond_f

    .line 150
    .line 151
    const/high16 v14, 0x20000

    .line 152
    .line 153
    goto :goto_9

    .line 154
    :cond_f
    const/high16 v14, 0x10000

    .line 155
    .line 156
    :goto_9
    or-int/2addr v1, v14

    .line 157
    :goto_a
    and-int/lit8 v14, p9, 0x40

    .line 158
    .line 159
    const/high16 v15, 0x180000

    .line 160
    .line 161
    if-eqz v14, :cond_11

    .line 162
    .line 163
    or-int/2addr v1, v15

    .line 164
    :cond_10
    move-object/from16 v15, p6

    .line 165
    .line 166
    goto :goto_c

    .line 167
    :cond_11
    and-int/2addr v15, v8

    .line 168
    if-nez v15, :cond_10

    .line 169
    .line 170
    move-object/from16 v15, p6

    .line 171
    .line 172
    invoke-virtual {v0, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v16

    .line 176
    if-eqz v16, :cond_12

    .line 177
    .line 178
    const/high16 v16, 0x100000

    .line 179
    .line 180
    goto :goto_b

    .line 181
    :cond_12
    const/high16 v16, 0x80000

    .line 182
    .line 183
    :goto_b
    or-int v1, v1, v16

    .line 184
    .line 185
    :goto_c
    const v16, 0x92493

    .line 186
    .line 187
    .line 188
    and-int v4, v1, v16

    .line 189
    .line 190
    move/from16 v16, v1

    .line 191
    .line 192
    const v1, 0x92492

    .line 193
    .line 194
    .line 195
    move/from16 v17, v3

    .line 196
    .line 197
    const/4 v3, 0x0

    .line 198
    const/4 v15, 0x1

    .line 199
    if-eq v4, v1, :cond_13

    .line 200
    .line 201
    move v1, v15

    .line 202
    goto :goto_d

    .line 203
    :cond_13
    move v1, v3

    .line 204
    :goto_d
    and-int/lit8 v4, v16, 0x1

    .line 205
    .line 206
    invoke-virtual {v0, v4, v1}, Ll2/t;->O(IZ)Z

    .line 207
    .line 208
    .line 209
    move-result v1

    .line 210
    if-eqz v1, :cond_21

    .line 211
    .line 212
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 213
    .line 214
    if-eqz v17, :cond_14

    .line 215
    .line 216
    move-object v5, v1

    .line 217
    :cond_14
    if-eqz v6, :cond_15

    .line 218
    .line 219
    sget-object v4, Lx2/c;->h:Lx2/j;

    .line 220
    .line 221
    move-object v11, v4

    .line 222
    goto :goto_e

    .line 223
    :cond_15
    move-object v11, v7

    .line 224
    :goto_e
    if-eqz v9, :cond_16

    .line 225
    .line 226
    sget-object v4, Lt3/j;->b:Lt3/x0;

    .line 227
    .line 228
    move/from16 v18, v12

    .line 229
    .line 230
    move-object v12, v4

    .line 231
    move/from16 v4, v18

    .line 232
    .line 233
    goto :goto_f

    .line 234
    :cond_16
    move v4, v12

    .line 235
    move-object/from16 v12, p4

    .line 236
    .line 237
    :goto_f
    if-eqz v4, :cond_17

    .line 238
    .line 239
    const/high16 v4, 0x3f800000    # 1.0f

    .line 240
    .line 241
    move v13, v4

    .line 242
    :cond_17
    if-eqz v14, :cond_18

    .line 243
    .line 244
    const/4 v4, 0x0

    .line 245
    move-object v14, v4

    .line 246
    goto :goto_10

    .line 247
    :cond_18
    move-object/from16 v14, p6

    .line 248
    .line 249
    :goto_10
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 250
    .line 251
    if-eqz v2, :cond_1c

    .line 252
    .line 253
    const v6, 0x71340604

    .line 254
    .line 255
    .line 256
    invoke-virtual {v0, v6}, Ll2/t;->Y(I)V

    .line 257
    .line 258
    .line 259
    and-int/lit8 v6, v16, 0x70

    .line 260
    .line 261
    const/16 v7, 0x20

    .line 262
    .line 263
    if-ne v6, v7, :cond_19

    .line 264
    .line 265
    move v6, v15

    .line 266
    goto :goto_11

    .line 267
    :cond_19
    move v6, v3

    .line 268
    :goto_11
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v7

    .line 272
    if-nez v6, :cond_1a

    .line 273
    .line 274
    if-ne v7, v4, :cond_1b

    .line 275
    .line 276
    :cond_1a
    new-instance v7, Lac0/r;

    .line 277
    .line 278
    const/4 v6, 0x4

    .line 279
    invoke-direct {v7, v2, v6}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    :cond_1b
    check-cast v7, Lay0/k;

    .line 286
    .line 287
    invoke-static {v1, v3, v7}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 292
    .line 293
    .line 294
    goto :goto_12

    .line 295
    :cond_1c
    const v6, 0x71367242

    .line 296
    .line 297
    .line 298
    invoke-virtual {v0, v6}, Ll2/t;->Y(I)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 302
    .line 303
    .line 304
    :goto_12
    invoke-interface {v5, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    invoke-static {v1}, Ljp/ba;->d(Lx2/s;)Lx2/s;

    .line 309
    .line 310
    .line 311
    move-result-object v9

    .line 312
    move v1, v15

    .line 313
    const/4 v15, 0x2

    .line 314
    invoke-static/range {v9 .. v15}, Landroidx/compose/ui/draw/a;->d(Lx2/s;Li3/c;Lx2/e;Lt3/k;FLe3/m;I)Lx2/s;

    .line 315
    .line 316
    .line 317
    move-result-object v3

    .line 318
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v6

    .line 322
    if-ne v6, v4, :cond_1d

    .line 323
    .line 324
    sget-object v6, Le1/q0;->a:Le1/q0;

    .line 325
    .line 326
    invoke-virtual {v0, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    :cond_1d
    check-cast v6, Lt3/q0;

    .line 330
    .line 331
    iget-wide v9, v0, Ll2/t;->T:J

    .line 332
    .line 333
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 334
    .line 335
    .line 336
    move-result v4

    .line 337
    invoke-static {v0, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 338
    .line 339
    .line 340
    move-result-object v3

    .line 341
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 342
    .line 343
    .line 344
    move-result-object v7

    .line 345
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 346
    .line 347
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 348
    .line 349
    .line 350
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 351
    .line 352
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 353
    .line 354
    .line 355
    iget-boolean v10, v0, Ll2/t;->S:Z

    .line 356
    .line 357
    if-eqz v10, :cond_1e

    .line 358
    .line 359
    invoke-virtual {v0, v9}, Ll2/t;->l(Lay0/a;)V

    .line 360
    .line 361
    .line 362
    goto :goto_13

    .line 363
    :cond_1e
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 364
    .line 365
    .line 366
    :goto_13
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 367
    .line 368
    invoke-static {v9, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 369
    .line 370
    .line 371
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 372
    .line 373
    invoke-static {v6, v7, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 374
    .line 375
    .line 376
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 377
    .line 378
    invoke-static {v6, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 379
    .line 380
    .line 381
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 382
    .line 383
    iget-boolean v6, v0, Ll2/t;->S:Z

    .line 384
    .line 385
    if-nez v6, :cond_1f

    .line 386
    .line 387
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v6

    .line 391
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 392
    .line 393
    .line 394
    move-result-object v7

    .line 395
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 396
    .line 397
    .line 398
    move-result v6

    .line 399
    if-nez v6, :cond_20

    .line 400
    .line 401
    :cond_1f
    invoke-static {v4, v0, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 402
    .line 403
    .line 404
    :cond_20
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 405
    .line 406
    .line 407
    move-object v3, v5

    .line 408
    move-object v4, v11

    .line 409
    move-object v5, v12

    .line 410
    move-object v7, v14

    .line 411
    :goto_14
    move v6, v13

    .line 412
    goto :goto_15

    .line 413
    :cond_21
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 414
    .line 415
    .line 416
    move-object v3, v5

    .line 417
    move-object v4, v7

    .line 418
    move-object/from16 v5, p4

    .line 419
    .line 420
    move-object/from16 v7, p6

    .line 421
    .line 422
    goto :goto_14

    .line 423
    :goto_15
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 424
    .line 425
    .line 426
    move-result-object v10

    .line 427
    if-eqz v10, :cond_22

    .line 428
    .line 429
    new-instance v0, Le1/p0;

    .line 430
    .line 431
    move-object/from16 v1, p0

    .line 432
    .line 433
    move/from16 v9, p9

    .line 434
    .line 435
    invoke-direct/range {v0 .. v9}, Le1/p0;-><init>(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;II)V

    .line 436
    .line 437
    .line 438
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 439
    .line 440
    :cond_22
    return-void
.end method

.method public static final b(Lj3/f;Ljava/lang/String;Lx2/s;Le3/m;Ll2/o;I)V
    .locals 10

    .line 1
    and-int/lit8 p5, p5, 0x4

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 6
    .line 7
    :cond_0
    move-object v2, p2

    .line 8
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 9
    .line 10
    invoke-static {p0, p4}, Lj3/b;->c(Lj3/f;Ll2/o;)Lj3/j0;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const/16 v8, 0x38

    .line 15
    .line 16
    const/4 v9, 0x0

    .line 17
    sget-object v4, Lt3/j;->b:Lt3/x0;

    .line 18
    .line 19
    const/high16 v5, 0x3f800000    # 1.0f

    .line 20
    .line 21
    move-object v1, p1

    .line 22
    move-object v6, p3

    .line 23
    move-object v7, p4

    .line 24
    invoke-static/range {v0 .. v9}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public static final c(Le3/f;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;Ll2/o;II)V
    .locals 10

    .line 1
    and-int/lit8 v0, p7, 0x4

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 6
    .line 7
    :cond_0
    move-object v2, p2

    .line 8
    and-int/lit8 p2, p7, 0x8

    .line 9
    .line 10
    if-eqz p2, :cond_1

    .line 11
    .line 12
    sget-object p3, Lx2/c;->h:Lx2/j;

    .line 13
    .line 14
    :cond_1
    move-object v3, p3

    .line 15
    and-int/lit8 p2, p7, 0x10

    .line 16
    .line 17
    if-eqz p2, :cond_2

    .line 18
    .line 19
    sget-object p2, Lt3/j;->b:Lt3/x0;

    .line 20
    .line 21
    move-object v4, p2

    .line 22
    goto :goto_0

    .line 23
    :cond_2
    move-object v4, p4

    .line 24
    :goto_0
    move-object v7, p5

    .line 25
    check-cast v7, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p3

    .line 35
    if-nez p2, :cond_3

    .line 36
    .line 37
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 38
    .line 39
    if-ne p3, p2, :cond_4

    .line 40
    .line 41
    :cond_3
    const/4 p2, 0x1

    .line 42
    invoke-static {p0, p2}, Llp/t1;->a(Le3/f;I)Li3/a;

    .line 43
    .line 44
    .line 45
    move-result-object p3

    .line 46
    invoke-virtual {v7, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    :cond_4
    move-object v0, p3

    .line 50
    check-cast v0, Li3/a;

    .line 51
    .line 52
    const p0, 0x3ffff0

    .line 53
    .line 54
    .line 55
    and-int v8, p6, p0

    .line 56
    .line 57
    const/4 v9, 0x0

    .line 58
    const/high16 v5, 0x3f800000    # 1.0f

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    move-object v1, p1

    .line 62
    invoke-static/range {v0 .. v9}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 63
    .line 64
    .line 65
    return-void
.end method

.method public static final d(Lij0/a;Lss0/b;II)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/pe;->a(Lss0/b;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move p2, p3

    .line 14
    :goto_0
    const/4 p1, 0x0

    .line 15
    new-array p1, p1, [Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Ljj0/f;

    .line 18
    .line 19
    invoke-virtual {p0, p2, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
