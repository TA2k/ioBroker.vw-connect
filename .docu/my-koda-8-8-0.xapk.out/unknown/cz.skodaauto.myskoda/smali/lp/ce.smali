.class public abstract Llp/ce;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx21/y;Ljava/lang/Integer;Lx2/s;ZZLt2/b;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v6, p2

    .line 6
    .line 7
    move-object/from16 v7, p5

    .line 8
    .line 9
    move/from16 v8, p7

    .line 10
    .line 11
    move-object/from16 v9, p6

    .line 12
    .line 13
    check-cast v9, Ll2/t;

    .line 14
    .line 15
    const v0, 0x4350632d

    .line 16
    .line 17
    .line 18
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, v8, 0x6

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    const/4 v0, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v0, 0x2

    .line 34
    :goto_0
    or-int/2addr v0, v8

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v0, v8

    .line 37
    :goto_1
    and-int/lit8 v4, v8, 0x30

    .line 38
    .line 39
    if-nez v4, :cond_3

    .line 40
    .line 41
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_2

    .line 46
    .line 47
    const/16 v4, 0x20

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v4, 0x10

    .line 51
    .line 52
    :goto_2
    or-int/2addr v0, v4

    .line 53
    :cond_3
    and-int/lit16 v4, v8, 0x180

    .line 54
    .line 55
    if-nez v4, :cond_5

    .line 56
    .line 57
    invoke-virtual {v9, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-eqz v4, :cond_4

    .line 62
    .line 63
    const/16 v4, 0x100

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    const/16 v4, 0x80

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v4

    .line 69
    :cond_5
    and-int/lit16 v4, v8, 0xc00

    .line 70
    .line 71
    if-nez v4, :cond_7

    .line 72
    .line 73
    move/from16 v4, p3

    .line 74
    .line 75
    invoke-virtual {v9, v4}, Ll2/t;->h(Z)Z

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    if-eqz v10, :cond_6

    .line 80
    .line 81
    const/16 v10, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v10, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v0, v10

    .line 87
    goto :goto_5

    .line 88
    :cond_7
    move/from16 v4, p3

    .line 89
    .line 90
    :goto_5
    and-int/lit16 v10, v8, 0x6000

    .line 91
    .line 92
    if-nez v10, :cond_9

    .line 93
    .line 94
    move/from16 v10, p4

    .line 95
    .line 96
    invoke-virtual {v9, v10}, Ll2/t;->h(Z)Z

    .line 97
    .line 98
    .line 99
    move-result v11

    .line 100
    if-eqz v11, :cond_8

    .line 101
    .line 102
    const/16 v11, 0x4000

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_8
    const/16 v11, 0x2000

    .line 106
    .line 107
    :goto_6
    or-int/2addr v0, v11

    .line 108
    goto :goto_7

    .line 109
    :cond_9
    move/from16 v10, p4

    .line 110
    .line 111
    :goto_7
    const/high16 v11, 0x30000

    .line 112
    .line 113
    and-int/2addr v11, v8

    .line 114
    if-nez v11, :cond_b

    .line 115
    .line 116
    invoke-virtual {v9, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v11

    .line 120
    if-eqz v11, :cond_a

    .line 121
    .line 122
    const/high16 v11, 0x20000

    .line 123
    .line 124
    goto :goto_8

    .line 125
    :cond_a
    const/high16 v11, 0x10000

    .line 126
    .line 127
    :goto_8
    or-int/2addr v0, v11

    .line 128
    :cond_b
    const v11, 0x12493

    .line 129
    .line 130
    .line 131
    and-int/2addr v11, v0

    .line 132
    const v12, 0x12492

    .line 133
    .line 134
    .line 135
    if-ne v11, v12, :cond_d

    .line 136
    .line 137
    invoke-virtual {v9}, Ll2/t;->A()Z

    .line 138
    .line 139
    .line 140
    move-result v11

    .line 141
    if-nez v11, :cond_c

    .line 142
    .line 143
    goto :goto_9

    .line 144
    :cond_c
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 145
    .line 146
    .line 147
    goto/16 :goto_f

    .line 148
    .line 149
    :cond_d
    :goto_9
    const v11, -0x7321ecb3

    .line 150
    .line 151
    .line 152
    invoke-virtual {v9, v11}, Ll2/t;->Y(I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v11

    .line 159
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 160
    .line 161
    if-ne v11, v12, :cond_e

    .line 162
    .line 163
    new-instance v11, Ld3/b;

    .line 164
    .line 165
    const-wide/16 v13, 0x0

    .line 166
    .line 167
    invoke-direct {v11, v13, v14}, Ld3/b;-><init>(J)V

    .line 168
    .line 169
    .line 170
    invoke-static {v11}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 171
    .line 172
    .line 173
    move-result-object v11

    .line 174
    invoke-virtual {v9, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    :cond_e
    check-cast v11, Ll2/b1;

    .line 178
    .line 179
    const v13, -0x7321e181

    .line 180
    .line 181
    .line 182
    const/4 v14, 0x0

    .line 183
    invoke-static {v13, v9, v14}, Lvj/b;->d(ILl2/t;Z)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v13

    .line 187
    if-ne v13, v12, :cond_f

    .line 188
    .line 189
    new-instance v13, Lkn/m;

    .line 190
    .line 191
    const/4 v15, 0x3

    .line 192
    invoke-direct {v13, v11, v15}, Lkn/m;-><init>(Ll2/b1;I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v9, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    :cond_f
    check-cast v13, Lay0/k;

    .line 199
    .line 200
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    invoke-static {v6, v13}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 204
    .line 205
    .line 206
    move-result-object v13

    .line 207
    sget-object v15, Lx2/c;->d:Lx2/j;

    .line 208
    .line 209
    invoke-static {v15, v14}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 210
    .line 211
    .line 212
    move-result-object v15

    .line 213
    iget-wide v5, v9, Ll2/t;->T:J

    .line 214
    .line 215
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 216
    .line 217
    .line 218
    move-result v5

    .line 219
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 220
    .line 221
    .line 222
    move-result-object v6

    .line 223
    invoke-static {v9, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v13

    .line 227
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 228
    .line 229
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 230
    .line 231
    .line 232
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 233
    .line 234
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 235
    .line 236
    .line 237
    iget-boolean v3, v9, Ll2/t;->S:Z

    .line 238
    .line 239
    if-eqz v3, :cond_10

    .line 240
    .line 241
    invoke-virtual {v9, v14}, Ll2/t;->l(Lay0/a;)V

    .line 242
    .line 243
    .line 244
    goto :goto_a

    .line 245
    :cond_10
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 246
    .line 247
    .line 248
    :goto_a
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 249
    .line 250
    invoke-static {v3, v15, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 251
    .line 252
    .line 253
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 254
    .line 255
    invoke-static {v3, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 256
    .line 257
    .line 258
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 259
    .line 260
    iget-boolean v6, v9, Ll2/t;->S:Z

    .line 261
    .line 262
    if-nez v6, :cond_11

    .line 263
    .line 264
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v6

    .line 268
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 269
    .line 270
    .line 271
    move-result-object v14

    .line 272
    invoke-static {v6, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-result v6

    .line 276
    if-nez v6, :cond_12

    .line 277
    .line 278
    :cond_11
    invoke-static {v5, v9, v5, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 279
    .line 280
    .line 281
    :cond_12
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 282
    .line 283
    invoke-static {v3, v13, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 284
    .line 285
    .line 286
    const v3, 0x33f9dd0e

    .line 287
    .line 288
    .line 289
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 290
    .line 291
    .line 292
    and-int/lit8 v3, v0, 0xe

    .line 293
    .line 294
    const/4 v5, 0x1

    .line 295
    const/4 v6, 0x4

    .line 296
    if-ne v3, v6, :cond_13

    .line 297
    .line 298
    move v6, v5

    .line 299
    goto :goto_b

    .line 300
    :cond_13
    const/4 v6, 0x0

    .line 301
    :goto_b
    invoke-virtual {v9, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result v13

    .line 305
    or-int/2addr v6, v13

    .line 306
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v13

    .line 310
    if-nez v6, :cond_14

    .line 311
    .line 312
    if-ne v13, v12, :cond_15

    .line 313
    .line 314
    :cond_14
    new-instance v13, Lx21/k;

    .line 315
    .line 316
    new-instance v6, Lkn/e0;

    .line 317
    .line 318
    const/4 v14, 0x1

    .line 319
    invoke-direct {v6, v11, v14}, Lkn/e0;-><init>(Ll2/b1;I)V

    .line 320
    .line 321
    .line 322
    invoke-direct {v13, v1, v2, v6}, Lx21/k;-><init>(Lx21/y;Ljava/lang/Integer;Lkn/e0;)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v9, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    :cond_15
    check-cast v13, Lx21/k;

    .line 329
    .line 330
    const/4 v6, 0x0

    .line 331
    invoke-virtual {v9, v6}, Ll2/t;->q(Z)V

    .line 332
    .line 333
    .line 334
    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 335
    .line 336
    .line 337
    move-result-object v6

    .line 338
    shr-int/lit8 v11, v0, 0x9

    .line 339
    .line 340
    and-int/lit16 v11, v11, 0x3f0

    .line 341
    .line 342
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 343
    .line 344
    .line 345
    move-result-object v11

    .line 346
    invoke-virtual {v7, v13, v6, v9, v11}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    invoke-virtual {v9, v5}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    iget-object v6, v1, Lx21/y;->r:Ljava/util/HashSet;

    .line 353
    .line 354
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 355
    .line 356
    .line 357
    move-result-object v11

    .line 358
    const v13, -0x7321aca9

    .line 359
    .line 360
    .line 361
    invoke-virtual {v9, v13}, Ll2/t;->Y(I)V

    .line 362
    .line 363
    .line 364
    and-int/lit16 v0, v0, 0x1c00

    .line 365
    .line 366
    const/16 v13, 0x800

    .line 367
    .line 368
    if-ne v0, v13, :cond_16

    .line 369
    .line 370
    move v0, v5

    .line 371
    :goto_c
    const/4 v13, 0x4

    .line 372
    goto :goto_d

    .line 373
    :cond_16
    const/4 v0, 0x0

    .line 374
    goto :goto_c

    .line 375
    :goto_d
    if-ne v3, v13, :cond_17

    .line 376
    .line 377
    goto :goto_e

    .line 378
    :cond_17
    const/4 v5, 0x0

    .line 379
    :goto_e
    or-int/2addr v0, v5

    .line 380
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 381
    .line 382
    .line 383
    move-result v3

    .line 384
    or-int/2addr v0, v3

    .line 385
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v3

    .line 389
    if-nez v0, :cond_18

    .line 390
    .line 391
    if-ne v3, v12, :cond_19

    .line 392
    .line 393
    :cond_18
    new-instance v0, Lbc/g;

    .line 394
    .line 395
    const/4 v5, 0x6

    .line 396
    const/4 v4, 0x0

    .line 397
    move/from16 v3, p3

    .line 398
    .line 399
    invoke-direct/range {v0 .. v5}, Lbc/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 403
    .line 404
    .line 405
    move-object v3, v0

    .line 406
    :cond_19
    check-cast v3, Lay0/n;

    .line 407
    .line 408
    const/4 v0, 0x0

    .line 409
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 410
    .line 411
    .line 412
    invoke-static {v6, v11, v3, v9}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 413
    .line 414
    .line 415
    :goto_f
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 416
    .line 417
    .line 418
    move-result-object v9

    .line 419
    if-eqz v9, :cond_1a

    .line 420
    .line 421
    new-instance v0, Lx21/m;

    .line 422
    .line 423
    move-object/from16 v1, p0

    .line 424
    .line 425
    move-object/from16 v2, p1

    .line 426
    .line 427
    move-object/from16 v3, p2

    .line 428
    .line 429
    move/from16 v4, p3

    .line 430
    .line 431
    move-object v6, v7

    .line 432
    move v7, v8

    .line 433
    move v5, v10

    .line 434
    invoke-direct/range {v0 .. v7}, Lx21/m;-><init>(Lx21/y;Ljava/lang/Integer;Lx2/s;ZZLt2/b;I)V

    .line 435
    .line 436
    .line 437
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 438
    .line 439
    :cond_1a
    return-void
.end method

.method public static varargs b(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 10

    .line 1
    const/4 v1, 0x0

    .line 2
    move v2, v1

    .line 3
    :goto_0
    array-length v0, p1

    .line 4
    if-ge v2, v0, :cond_1

    .line 5
    .line 6
    aget-object v3, p1, v2

    .line 7
    .line 8
    if-nez v3, :cond_0

    .line 9
    .line 10
    const-string v0, "null"

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    :try_start_0
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    goto :goto_1

    .line 18
    :catch_0
    move-exception v0

    .line 19
    move-object v8, v0

    .line 20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const/16 v4, 0x40

    .line 37
    .line 38
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-static {v3}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    invoke-static {v3}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    const-string v3, "com.google.common.base.Strings"

    .line 57
    .line 58
    invoke-static {v3}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    sget-object v4, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 63
    .line 64
    const-string v6, "lenientToString"

    .line 65
    .line 66
    const-string v5, "Exception during lenientFormat for "

    .line 67
    .line 68
    invoke-virtual {v5, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    const-string v5, "com.google.common.base.Strings"

    .line 73
    .line 74
    invoke-virtual/range {v3 .. v8}, Ljava/util/logging/Logger;->logp(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 75
    .line 76
    .line 77
    const-string v3, "<"

    .line 78
    .line 79
    const-string v4, " threw "

    .line 80
    .line 81
    invoke-static {v3, v0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v3, ">"

    .line 97
    .line 98
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    :goto_1
    aput-object v0, p1, v2

    .line 106
    .line 107
    add-int/lit8 v2, v2, 0x1

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    mul-int/lit8 v0, v0, 0x10

    .line 115
    .line 116
    new-instance v3, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    add-int/2addr v2, v0

    .line 119
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 120
    .line 121
    .line 122
    move v0, v1

    .line 123
    :goto_2
    array-length v2, p1

    .line 124
    if-ge v1, v2, :cond_3

    .line 125
    .line 126
    const-string v4, "%s"

    .line 127
    .line 128
    invoke-virtual {p0, v4, v0}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    const/4 v5, -0x1

    .line 133
    if-ne v4, v5, :cond_2

    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_2
    invoke-virtual {v3, p0, v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    add-int/lit8 v0, v1, 0x1

    .line 140
    .line 141
    aget-object v1, p1, v1

    .line 142
    .line 143
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    add-int/lit8 v1, v4, 0x2

    .line 147
    .line 148
    move v9, v1

    .line 149
    move v1, v0

    .line 150
    move v0, v9

    .line 151
    goto :goto_2

    .line 152
    :cond_3
    :goto_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    invoke-virtual {v3, p0, v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    if-ge v1, v2, :cond_5

    .line 160
    .line 161
    const-string p0, " ["

    .line 162
    .line 163
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    add-int/lit8 p0, v1, 0x1

    .line 167
    .line 168
    aget-object v0, p1, v1

    .line 169
    .line 170
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    :goto_4
    array-length v0, p1

    .line 174
    if-ge p0, v0, :cond_4

    .line 175
    .line 176
    const-string v0, ", "

    .line 177
    .line 178
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    add-int/lit8 v0, p0, 0x1

    .line 182
    .line 183
    aget-object p0, p1, p0

    .line 184
    .line 185
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    move p0, v0

    .line 189
    goto :goto_4

    .line 190
    :cond_4
    const/16 p0, 0x5d

    .line 191
    .line 192
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    :cond_5
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    return-object p0
.end method
