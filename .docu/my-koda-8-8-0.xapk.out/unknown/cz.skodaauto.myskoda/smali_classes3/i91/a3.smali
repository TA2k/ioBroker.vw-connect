.class public abstract Li91/a3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    int-to-float v0, v0

    .line 3
    sput v0, Li91/a3;->a:F

    .line 4
    .line 5
    const/16 v0, 0x8

    .line 6
    .line 7
    int-to-float v0, v0

    .line 8
    sput v0, Li91/a3;->b:F

    .line 9
    .line 10
    return-void
.end method

.method public static final a(IIIILl2/o;Lx2/s;)V
    .locals 17

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v6, p4

    .line 6
    .line 7
    check-cast v6, Ll2/t;

    .line 8
    .line 9
    const v0, -0x45843f8a

    .line 10
    .line 11
    .line 12
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, p2, 0x6

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {v6, v1}, Ll2/t;->e(I)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int v0, p2, v0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move/from16 v0, p2

    .line 32
    .line 33
    :goto_1
    and-int/lit8 v3, p2, 0x30

    .line 34
    .line 35
    if-nez v3, :cond_3

    .line 36
    .line 37
    invoke-virtual {v6, v2}, Ll2/t;->e(I)Z

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
    or-int/2addr v0, v3

    .line 49
    :cond_3
    and-int/lit8 v3, p3, 0x4

    .line 50
    .line 51
    if-eqz v3, :cond_4

    .line 52
    .line 53
    or-int/lit16 v0, v0, 0x180

    .line 54
    .line 55
    move-object/from16 v4, p5

    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_4
    move-object/from16 v4, p5

    .line 59
    .line 60
    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_5

    .line 65
    .line 66
    const/16 v5, 0x100

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_5
    const/16 v5, 0x80

    .line 70
    .line 71
    :goto_3
    or-int/2addr v0, v5

    .line 72
    :goto_4
    and-int/lit16 v5, v0, 0x93

    .line 73
    .line 74
    const/16 v7, 0x92

    .line 75
    .line 76
    const/4 v10, 0x1

    .line 77
    const/4 v11, 0x0

    .line 78
    if-eq v5, v7, :cond_6

    .line 79
    .line 80
    move v5, v10

    .line 81
    goto :goto_5

    .line 82
    :cond_6
    move v5, v11

    .line 83
    :goto_5
    and-int/2addr v0, v10

    .line 84
    invoke-virtual {v6, v0, v5}, Ll2/t;->O(IZ)Z

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    if-eqz v0, :cond_13

    .line 89
    .line 90
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 91
    .line 92
    if-eqz v3, :cond_7

    .line 93
    .line 94
    move-object v12, v0

    .line 95
    goto :goto_6

    .line 96
    :cond_7
    move-object v12, v4

    .line 97
    :goto_6
    const/4 v3, 0x6

    .line 98
    int-to-float v3, v3

    .line 99
    invoke-static {v3}, Lk1/j;->g(F)Lk1/h;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    sget-object v4, Lx2/c;->n:Lx2/i;

    .line 104
    .line 105
    sget v13, Li91/a3;->b:F

    .line 106
    .line 107
    invoke-static {v12, v13}, Landroidx/compose/foundation/layout/d;->h(Lx2/s;F)Lx2/s;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    const/16 v7, 0x36

    .line 112
    .line 113
    invoke-static {v3, v4, v6, v7}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    iget-wide v7, v6, Ll2/t;->T:J

    .line 118
    .line 119
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    invoke-static {v6, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 128
    .line 129
    .line 130
    move-result-object v5

    .line 131
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 132
    .line 133
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 134
    .line 135
    .line 136
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 137
    .line 138
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 139
    .line 140
    .line 141
    iget-boolean v9, v6, Ll2/t;->S:Z

    .line 142
    .line 143
    if-eqz v9, :cond_8

    .line 144
    .line 145
    invoke-virtual {v6, v8}, Ll2/t;->l(Lay0/a;)V

    .line 146
    .line 147
    .line 148
    goto :goto_7

    .line 149
    :cond_8
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 150
    .line 151
    .line 152
    :goto_7
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 153
    .line 154
    invoke-static {v8, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 155
    .line 156
    .line 157
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 158
    .line 159
    invoke-static {v3, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 160
    .line 161
    .line 162
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 163
    .line 164
    iget-boolean v7, v6, Ll2/t;->S:Z

    .line 165
    .line 166
    if-nez v7, :cond_9

    .line 167
    .line 168
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v7

    .line 172
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 173
    .line 174
    .line 175
    move-result-object v8

    .line 176
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    if-nez v7, :cond_a

    .line 181
    .line 182
    :cond_9
    invoke-static {v4, v6, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 183
    .line 184
    .line 185
    :cond_a
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 186
    .line 187
    invoke-static {v3, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 188
    .line 189
    .line 190
    const v3, 0x12de341b

    .line 191
    .line 192
    .line 193
    invoke-virtual {v6, v3}, Ll2/t;->Y(I)V

    .line 194
    .line 195
    .line 196
    if-gez v1, :cond_b

    .line 197
    .line 198
    move v14, v11

    .line 199
    goto :goto_8

    .line 200
    :cond_b
    move v14, v1

    .line 201
    :goto_8
    move v15, v11

    .line 202
    :goto_9
    if-ge v15, v14, :cond_12

    .line 203
    .line 204
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 205
    .line 206
    invoke-static {v0, v13}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    .line 207
    .line 208
    .line 209
    move-result-object v4

    .line 210
    invoke-static {v3, v11}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 211
    .line 212
    .line 213
    move-result-object v3

    .line 214
    iget-wide v7, v6, Ll2/t;->T:J

    .line 215
    .line 216
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 217
    .line 218
    .line 219
    move-result v5

    .line 220
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 221
    .line 222
    .line 223
    move-result-object v7

    .line 224
    invoke-static {v6, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 225
    .line 226
    .line 227
    move-result-object v4

    .line 228
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 229
    .line 230
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 231
    .line 232
    .line 233
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 234
    .line 235
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 236
    .line 237
    .line 238
    iget-boolean v9, v6, Ll2/t;->S:Z

    .line 239
    .line 240
    if-eqz v9, :cond_c

    .line 241
    .line 242
    invoke-virtual {v6, v8}, Ll2/t;->l(Lay0/a;)V

    .line 243
    .line 244
    .line 245
    goto :goto_a

    .line 246
    :cond_c
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 247
    .line 248
    .line 249
    :goto_a
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 250
    .line 251
    invoke-static {v8, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 252
    .line 253
    .line 254
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 255
    .line 256
    invoke-static {v3, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 257
    .line 258
    .line 259
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 260
    .line 261
    iget-boolean v7, v6, Ll2/t;->S:Z

    .line 262
    .line 263
    if-nez v7, :cond_d

    .line 264
    .line 265
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v7

    .line 269
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 270
    .line 271
    .line 272
    move-result-object v8

    .line 273
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 274
    .line 275
    .line 276
    move-result v7

    .line 277
    if-nez v7, :cond_e

    .line 278
    .line 279
    :cond_d
    invoke-static {v5, v6, v5, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 280
    .line 281
    .line 282
    :cond_e
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 283
    .line 284
    invoke-static {v3, v4, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 285
    .line 286
    .line 287
    if-ne v15, v2, :cond_f

    .line 288
    .line 289
    move v9, v10

    .line 290
    goto :goto_b

    .line 291
    :cond_f
    move v9, v11

    .line 292
    :goto_b
    if-eqz v9, :cond_10

    .line 293
    .line 294
    move v3, v13

    .line 295
    goto :goto_c

    .line 296
    :cond_10
    sget v3, Li91/a3;->a:F

    .line 297
    .line 298
    :goto_c
    const/4 v7, 0x0

    .line 299
    const/16 v8, 0xe

    .line 300
    .line 301
    const/4 v4, 0x0

    .line 302
    const/4 v5, 0x0

    .line 303
    invoke-static/range {v3 .. v8}, Lc1/e;->a(FLc1/a0;Lay0/k;Ll2/o;II)Ll2/t2;

    .line 304
    .line 305
    .line 306
    move-result-object v16

    .line 307
    if-eqz v9, :cond_11

    .line 308
    .line 309
    const v3, 0x23ae5499

    .line 310
    .line 311
    .line 312
    invoke-virtual {v6, v3}, Ll2/t;->Y(I)V

    .line 313
    .line 314
    .line 315
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 316
    .line 317
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v3

    .line 321
    check-cast v3, Lj91/e;

    .line 322
    .line 323
    invoke-virtual {v3}, Lj91/e;->k()J

    .line 324
    .line 325
    .line 326
    move-result-wide v3

    .line 327
    :goto_d
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 328
    .line 329
    .line 330
    goto :goto_e

    .line 331
    :cond_11
    const v3, 0x23ae5997

    .line 332
    .line 333
    .line 334
    invoke-virtual {v6, v3}, Ll2/t;->Y(I)V

    .line 335
    .line 336
    .line 337
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 338
    .line 339
    invoke-virtual {v6, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object v3

    .line 343
    check-cast v3, Lj91/e;

    .line 344
    .line 345
    invoke-virtual {v3}, Lj91/e;->m()J

    .line 346
    .line 347
    .line 348
    move-result-wide v3

    .line 349
    goto :goto_d

    .line 350
    :goto_e
    const/4 v8, 0x0

    .line 351
    const/16 v9, 0xe

    .line 352
    .line 353
    const/4 v5, 0x0

    .line 354
    move-object v7, v6

    .line 355
    const/4 v6, 0x0

    .line 356
    invoke-static/range {v3 .. v9}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 357
    .line 358
    .line 359
    move-result-object v3

    .line 360
    move-object v6, v7

    .line 361
    invoke-interface/range {v16 .. v16}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v4

    .line 365
    check-cast v4, Lt4/f;

    .line 366
    .line 367
    iget v4, v4, Lt4/f;->d:F

    .line 368
    .line 369
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    .line 370
    .line 371
    .line 372
    move-result-object v4

    .line 373
    invoke-static {}, Ls1/f;->a()Ls1/e;

    .line 374
    .line 375
    .line 376
    move-result-object v5

    .line 377
    invoke-static {v4, v5}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 378
    .line 379
    .line 380
    move-result-object v4

    .line 381
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v3

    .line 385
    check-cast v3, Le3/s;

    .line 386
    .line 387
    iget-wide v7, v3, Le3/s;->a:J

    .line 388
    .line 389
    sget-object v3, Le3/j0;->a:Le3/i0;

    .line 390
    .line 391
    invoke-static {v4, v7, v8, v3}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 392
    .line 393
    .line 394
    move-result-object v3

    .line 395
    invoke-static {v3, v6, v11}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 396
    .line 397
    .line 398
    invoke-virtual {v6, v10}, Ll2/t;->q(Z)V

    .line 399
    .line 400
    .line 401
    add-int/lit8 v15, v15, 0x1

    .line 402
    .line 403
    goto/16 :goto_9

    .line 404
    .line 405
    :cond_12
    invoke-virtual {v6, v11}, Ll2/t;->q(Z)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {v6, v10}, Ll2/t;->q(Z)V

    .line 409
    .line 410
    .line 411
    move-object v5, v12

    .line 412
    goto :goto_f

    .line 413
    :cond_13
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 414
    .line 415
    .line 416
    move-object v5, v4

    .line 417
    :goto_f
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 418
    .line 419
    .line 420
    move-result-object v6

    .line 421
    if-eqz v6, :cond_14

    .line 422
    .line 423
    new-instance v0, Li91/z2;

    .line 424
    .line 425
    move/from16 v3, p2

    .line 426
    .line 427
    move/from16 v4, p3

    .line 428
    .line 429
    invoke-direct/range {v0 .. v5}, Li91/z2;-><init>(IIIILx2/s;)V

    .line 430
    .line 431
    .line 432
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 433
    .line 434
    :cond_14
    return-void
.end method
