.class public abstract Lna0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ln70/c0;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ln70/c0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x64018e77

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lna0/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Ln70/c0;

    .line 20
    .line 21
    const/16 v1, 0x14

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ln70/c0;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, -0x2c30f114

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Lna0/a;->b:Lt2/b;

    .line 35
    .line 36
    return-void
.end method

.method public static final a(Lma0/f;Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 30

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v9, p3

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v0, -0x231ce89

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p4, v0

    .line 23
    .line 24
    move-object/from16 v1, p1

    .line 25
    .line 26
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v2, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v2

    .line 38
    move-object/from16 v2, p2

    .line 39
    .line 40
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-eqz v4, :cond_2

    .line 45
    .line 46
    const/16 v4, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v4, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v4

    .line 52
    and-int/lit16 v4, v0, 0x93

    .line 53
    .line 54
    const/16 v5, 0x92

    .line 55
    .line 56
    const/4 v6, 0x1

    .line 57
    const/4 v7, 0x0

    .line 58
    if-eq v4, v5, :cond_3

    .line 59
    .line 60
    move v4, v6

    .line 61
    goto :goto_3

    .line 62
    :cond_3
    move v4, v7

    .line 63
    :goto_3
    and-int/lit8 v5, v0, 0x1

    .line 64
    .line 65
    invoke-virtual {v9, v5, v4}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-eqz v4, :cond_8

    .line 70
    .line 71
    sget-object v10, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 72
    .line 73
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    iget v11, v4, Lj91/c;->j:F

    .line 78
    .line 79
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    iget v13, v4, Lj91/c;->j:F

    .line 84
    .line 85
    const/4 v14, 0x0

    .line 86
    const/16 v15, 0xa

    .line 87
    .line 88
    const/4 v12, 0x0

    .line 89
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    invoke-static {v7, v6, v9}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    const/16 v8, 0xe

    .line 98
    .line 99
    invoke-static {v4, v5, v8}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 104
    .line 105
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 106
    .line 107
    invoke-static {v5, v8, v9, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    iget-wide v10, v9, Ll2/t;->T:J

    .line 112
    .line 113
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 114
    .line 115
    .line 116
    move-result v8

    .line 117
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 118
    .line 119
    .line 120
    move-result-object v10

    .line 121
    invoke-static {v9, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 126
    .line 127
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 131
    .line 132
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 133
    .line 134
    .line 135
    iget-boolean v12, v9, Ll2/t;->S:Z

    .line 136
    .line 137
    if-eqz v12, :cond_4

    .line 138
    .line 139
    invoke-virtual {v9, v11}, Ll2/t;->l(Lay0/a;)V

    .line 140
    .line 141
    .line 142
    goto :goto_4

    .line 143
    :cond_4
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 144
    .line 145
    .line 146
    :goto_4
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 147
    .line 148
    invoke-static {v11, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 152
    .line 153
    invoke-static {v5, v10, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 157
    .line 158
    iget-boolean v10, v9, Ll2/t;->S:Z

    .line 159
    .line 160
    if-nez v10, :cond_5

    .line 161
    .line 162
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v10

    .line 166
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object v11

    .line 170
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v10

    .line 174
    if-nez v10, :cond_6

    .line 175
    .line 176
    :cond_5
    invoke-static {v8, v9, v8, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 177
    .line 178
    .line 179
    :cond_6
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 180
    .line 181
    invoke-static {v5, v4, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 182
    .line 183
    .line 184
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 185
    .line 186
    .line 187
    move-result-object v4

    .line 188
    iget v4, v4, Lj91/c;->e:F

    .line 189
    .line 190
    const v5, 0x7f1213d9

    .line 191
    .line 192
    .line 193
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 194
    .line 195
    invoke-static {v8, v4, v9, v5, v9}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    const/high16 v5, 0x3f800000    # 1.0f

    .line 200
    .line 201
    invoke-static {v8, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v10

    .line 205
    const-string v11, "todo_detail_header"

    .line 206
    .line 207
    invoke-static {v10, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 208
    .line 209
    .line 210
    move-result-object v10

    .line 211
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 212
    .line 213
    .line 214
    move-result-object v11

    .line 215
    invoke-virtual {v11}, Lj91/f;->j()Lg4/p0;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    const/16 v24, 0x0

    .line 220
    .line 221
    const v25, 0xfff8

    .line 222
    .line 223
    .line 224
    move v13, v7

    .line 225
    move-object v12, v8

    .line 226
    const-wide/16 v7, 0x0

    .line 227
    .line 228
    move v14, v6

    .line 229
    move-object/from16 v22, v9

    .line 230
    .line 231
    move-object v6, v10

    .line 232
    const-wide/16 v9, 0x0

    .line 233
    .line 234
    move v15, v5

    .line 235
    move-object v5, v11

    .line 236
    const/4 v11, 0x0

    .line 237
    move-object/from16 v16, v12

    .line 238
    .line 239
    move/from16 v17, v13

    .line 240
    .line 241
    const-wide/16 v12, 0x0

    .line 242
    .line 243
    move/from16 v18, v14

    .line 244
    .line 245
    const/4 v14, 0x0

    .line 246
    move/from16 v19, v15

    .line 247
    .line 248
    const/4 v15, 0x0

    .line 249
    move-object/from16 v20, v16

    .line 250
    .line 251
    move/from16 v21, v17

    .line 252
    .line 253
    const-wide/16 v16, 0x0

    .line 254
    .line 255
    move/from16 v23, v18

    .line 256
    .line 257
    const/16 v18, 0x0

    .line 258
    .line 259
    move/from16 v26, v19

    .line 260
    .line 261
    const/16 v19, 0x0

    .line 262
    .line 263
    move-object/from16 v27, v20

    .line 264
    .line 265
    const/16 v20, 0x0

    .line 266
    .line 267
    move/from16 v28, v21

    .line 268
    .line 269
    const/16 v21, 0x0

    .line 270
    .line 271
    move/from16 v29, v23

    .line 272
    .line 273
    const/16 v23, 0x180

    .line 274
    .line 275
    move/from16 p3, v0

    .line 276
    .line 277
    move-object/from16 v0, v27

    .line 278
    .line 279
    move/from16 v1, v28

    .line 280
    .line 281
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 282
    .line 283
    .line 284
    move-object/from16 v9, v22

    .line 285
    .line 286
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 287
    .line 288
    .line 289
    move-result-object v4

    .line 290
    iget v4, v4, Lj91/c;->d:F

    .line 291
    .line 292
    const v5, 0x7f121333

    .line 293
    .line 294
    .line 295
    invoke-static {v0, v4, v9, v5, v9}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v4

    .line 299
    const/high16 v15, 0x3f800000    # 1.0f

    .line 300
    .line 301
    invoke-static {v0, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 302
    .line 303
    .line 304
    move-result-object v5

    .line 305
    const-string v6, "todo_detail_body"

    .line 306
    .line 307
    invoke-static {v5, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 308
    .line 309
    .line 310
    move-result-object v6

    .line 311
    invoke-static {v9}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 312
    .line 313
    .line 314
    move-result-object v5

    .line 315
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 316
    .line 317
    .line 318
    move-result-object v5

    .line 319
    invoke-static {v9}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 320
    .line 321
    .line 322
    move-result-object v7

    .line 323
    invoke-virtual {v7}, Lj91/e;->s()J

    .line 324
    .line 325
    .line 326
    move-result-wide v7

    .line 327
    const v25, 0xfff0

    .line 328
    .line 329
    .line 330
    const-wide/16 v9, 0x0

    .line 331
    .line 332
    const/4 v15, 0x0

    .line 333
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 334
    .line 335
    .line 336
    move-object/from16 v9, v22

    .line 337
    .line 338
    invoke-static {v9}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 339
    .line 340
    .line 341
    move-result-object v4

    .line 342
    iget v4, v4, Lj91/c;->e:F

    .line 343
    .line 344
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 345
    .line 346
    .line 347
    move-result-object v4

    .line 348
    invoke-static {v9, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 349
    .line 350
    .line 351
    and-int/lit8 v4, p3, 0xe

    .line 352
    .line 353
    invoke-static {v3, v9, v4}, Lna0/a;->b(Lma0/f;Ll2/o;I)V

    .line 354
    .line 355
    .line 356
    const v4, -0x3ddc9549

    .line 357
    .line 358
    .line 359
    invoke-virtual {v9, v4}, Ll2/t;->Y(I)V

    .line 360
    .line 361
    .line 362
    iget-object v4, v3, Lma0/f;->e:Ljava/util/List;

    .line 363
    .line 364
    check-cast v4, Ljava/lang/Iterable;

    .line 365
    .line 366
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 367
    .line 368
    .line 369
    move-result-object v12

    .line 370
    :goto_5
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 371
    .line 372
    .line 373
    move-result v4

    .line 374
    if-eqz v4, :cond_7

    .line 375
    .line 376
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v4

    .line 380
    move-object v5, v4

    .line 381
    check-cast v5, Lma0/e;

    .line 382
    .line 383
    const-string v4, "todoItem"

    .line 384
    .line 385
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    iget-object v4, v3, Lma0/f;->f:Ljava/util/List;

    .line 389
    .line 390
    invoke-interface {v4, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 391
    .line 392
    .line 393
    move-result v6

    .line 394
    shl-int/lit8 v4, p3, 0x6

    .line 395
    .line 396
    const v7, 0xfc00

    .line 397
    .line 398
    .line 399
    and-int v10, v4, v7

    .line 400
    .line 401
    const/4 v11, 0x1

    .line 402
    const/4 v4, 0x0

    .line 403
    move-object/from16 v7, p1

    .line 404
    .line 405
    move-object v8, v2

    .line 406
    invoke-static/range {v4 .. v11}, Lna0/a;->d(Lx2/s;Lma0/e;ZLay0/k;Lay0/k;Ll2/o;II)V

    .line 407
    .line 408
    .line 409
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 410
    .line 411
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v2

    .line 415
    check-cast v2, Lj91/c;

    .line 416
    .line 417
    iget v2, v2, Lj91/c;->c:F

    .line 418
    .line 419
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 420
    .line 421
    .line 422
    move-result-object v2

    .line 423
    invoke-static {v9, v2}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 424
    .line 425
    .line 426
    move-object/from16 v2, p2

    .line 427
    .line 428
    goto :goto_5

    .line 429
    :cond_7
    invoke-virtual {v9, v1}, Ll2/t;->q(Z)V

    .line 430
    .line 431
    .line 432
    const/4 v14, 0x1

    .line 433
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 434
    .line 435
    .line 436
    goto :goto_6

    .line 437
    :cond_8
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 438
    .line 439
    .line 440
    :goto_6
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 441
    .line 442
    .line 443
    move-result-object v6

    .line 444
    if-eqz v6, :cond_9

    .line 445
    .line 446
    new-instance v0, Li91/k3;

    .line 447
    .line 448
    const/16 v2, 0x14

    .line 449
    .line 450
    move-object/from16 v4, p1

    .line 451
    .line 452
    move-object/from16 v5, p2

    .line 453
    .line 454
    move/from16 v1, p4

    .line 455
    .line 456
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 457
    .line 458
    .line 459
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 460
    .line 461
    :cond_9
    return-void
.end method

.method public static final b(Lma0/f;Ll2/o;I)V
    .locals 9

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p1, 0x421a16f4

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    const/4 v0, 0x2

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const/4 p1, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move p1, v0

    .line 20
    :goto_0
    or-int/2addr p1, p2

    .line 21
    and-int/lit8 v1, p1, 0x3

    .line 22
    .line 23
    const/4 v8, 0x0

    .line 24
    const/4 v2, 0x1

    .line 25
    if-eq v1, v0, :cond_1

    .line 26
    .line 27
    move v0, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move v0, v8

    .line 30
    :goto_1
    and-int/2addr p1, v2

    .line 31
    invoke-virtual {v5, p1, v0}, Ll2/t;->O(IZ)Z

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    if-eqz p1, :cond_5

    .line 36
    .line 37
    iget-boolean p1, p0, Lma0/f;->b:Z

    .line 38
    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    iget-boolean p1, p0, Lma0/f;->c:Z

    .line 42
    .line 43
    if-nez p1, :cond_4

    .line 44
    .line 45
    const p1, 0x5a16ea09

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5, p1}, Ll2/t;->Y(I)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 52
    .line 53
    invoke-static {p1, v2}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    new-instance v1, Lma0/e;

    .line 58
    .line 59
    const-string p1, ""

    .line 60
    .line 61
    invoke-direct {v1, p1, p1, p1, p1}, Lma0/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 69
    .line 70
    if-ne p1, v2, :cond_2

    .line 71
    .line 72
    new-instance p1, Lmj/g;

    .line 73
    .line 74
    const/16 v3, 0x1b

    .line 75
    .line 76
    invoke-direct {p1, v3}, Lmj/g;-><init>(I)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v5, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_2
    move-object v3, p1

    .line 83
    check-cast v3, Lay0/k;

    .line 84
    .line 85
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-ne p1, v2, :cond_3

    .line 90
    .line 91
    new-instance p1, Lmj/g;

    .line 92
    .line 93
    const/16 v2, 0x1c

    .line 94
    .line 95
    invoke-direct {p1, v2}, Lmj/g;-><init>(I)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v5, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    :cond_3
    move-object v4, p1

    .line 102
    check-cast v4, Lay0/k;

    .line 103
    .line 104
    const/16 v6, 0x6d80

    .line 105
    .line 106
    const/4 v7, 0x0

    .line 107
    const/4 v2, 0x0

    .line 108
    invoke-static/range {v0 .. v7}, Lna0/a;->d(Lx2/s;Lma0/e;ZLay0/k;Lay0/k;Ll2/o;II)V

    .line 109
    .line 110
    .line 111
    :goto_2
    invoke-virtual {v5, v8}, Ll2/t;->q(Z)V

    .line 112
    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_4
    const p1, 0x59d75a4e

    .line 116
    .line 117
    .line 118
    invoke-virtual {v5, p1}, Ll2/t;->Y(I)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_5
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    :goto_3
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    if-eqz p1, :cond_6

    .line 130
    .line 131
    new-instance v0, Llk/c;

    .line 132
    .line 133
    const/16 v1, 0x9

    .line 134
    .line 135
    invoke-direct {v0, p0, p2, v1}, Llk/c;-><init>(Ljava/lang/Object;II)V

    .line 136
    .line 137
    .line 138
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_6
    return-void
.end method

.method public static final c(Lx2/s;Ll2/o;I)V
    .locals 13

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const v0, -0x2b4cd5ee

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v1, 0x2

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v1

    .line 24
    :goto_0
    or-int/2addr v0, p2

    .line 25
    and-int/lit8 v2, v0, 0x3

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    const/4 v4, 0x0

    .line 29
    if-eq v2, v1, :cond_1

    .line 30
    .line 31
    move v1, v3

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v1, v4

    .line 34
    :goto_1
    and-int/lit8 v2, v0, 0x1

    .line 35
    .line 36
    invoke-virtual {p1, v2, v1}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_6

    .line 41
    .line 42
    invoke-static {p1}, Lxf0/y1;->F(Ll2/o;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    const v0, 0x1d8dbac0

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 52
    .line 53
    .line 54
    invoke-static {p1, v4}, Lna0/a;->f(Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-eqz p1, :cond_7

    .line 65
    .line 66
    new-instance v0, Ll30/a;

    .line 67
    .line 68
    const/4 v1, 0x5

    .line 69
    invoke-direct {v0, p0, p2, v1}, Ll30/a;-><init>(Lx2/s;II)V

    .line 70
    .line 71
    .line 72
    :goto_2
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 73
    .line 74
    return-void

    .line 75
    :cond_2
    const v1, 0x1d754a90

    .line 76
    .line 77
    .line 78
    const v2, -0x6040e0aa

    .line 79
    .line 80
    .line 81
    invoke-static {v1, v2, p1, p1, v4}, Lvj/b;->c(IILl2/t;Ll2/t;Z)Landroidx/lifecycle/i1;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    if-eqz v1, :cond_5

    .line 86
    .line 87
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    invoke-static {p1}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 92
    .line 93
    .line 94
    move-result-object v10

    .line 95
    const-class v2, Lma0/b;

    .line 96
    .line 97
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 98
    .line 99
    invoke-virtual {v5, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    const/4 v7, 0x0

    .line 108
    const/4 v9, 0x0

    .line 109
    const/4 v11, 0x0

    .line 110
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 115
    .line 116
    .line 117
    check-cast v1, Lql0/j;

    .line 118
    .line 119
    invoke-static {v1, p1, v4, v3}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 120
    .line 121
    .line 122
    move-object v7, v1

    .line 123
    check-cast v7, Lma0/b;

    .line 124
    .line 125
    invoke-virtual {p1, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    if-nez v1, :cond_3

    .line 134
    .line 135
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 136
    .line 137
    if-ne v2, v1, :cond_4

    .line 138
    .line 139
    :cond_3
    new-instance v5, Ln80/d;

    .line 140
    .line 141
    const/4 v11, 0x0

    .line 142
    const/16 v12, 0x9

    .line 143
    .line 144
    const/4 v6, 0x0

    .line 145
    const-class v8, Lma0/b;

    .line 146
    .line 147
    const-string v9, "onOpenTodoDetail"

    .line 148
    .line 149
    const-string v10, "onOpenTodoDetail()V"

    .line 150
    .line 151
    invoke-direct/range {v5 .. v12}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {p1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    move-object v2, v5

    .line 158
    :cond_4
    check-cast v2, Lhy0/g;

    .line 159
    .line 160
    check-cast v2, Lay0/a;

    .line 161
    .line 162
    and-int/lit8 v0, v0, 0xe

    .line 163
    .line 164
    invoke-static {p0, v2, p1, v0, v4}, Lna0/a;->e(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 165
    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 169
    .line 170
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 171
    .line 172
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 177
    .line 178
    .line 179
    :goto_3
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    if-eqz p1, :cond_7

    .line 184
    .line 185
    new-instance v0, Ll30/a;

    .line 186
    .line 187
    const/4 v1, 0x6

    .line 188
    invoke-direct {v0, p0, p2, v1}, Ll30/a;-><init>(Lx2/s;II)V

    .line 189
    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_7
    return-void
.end method

.method public static final d(Lx2/s;Lma0/e;ZLay0/k;Lay0/k;Ll2/o;II)V
    .locals 16

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move-object/from16 v5, p4

    .line 6
    .line 7
    move/from16 v6, p6

    .line 8
    .line 9
    move-object/from16 v14, p5

    .line 10
    .line 11
    check-cast v14, Ll2/t;

    .line 12
    .line 13
    const v0, 0x3c45700a

    .line 14
    .line 15
    .line 16
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, p7, 0x1

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    or-int/lit8 v1, v6, 0x6

    .line 24
    .line 25
    move v3, v1

    .line 26
    move-object/from16 v1, p0

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_0
    and-int/lit8 v1, v6, 0x6

    .line 30
    .line 31
    if-nez v1, :cond_2

    .line 32
    .line 33
    move-object/from16 v1, p0

    .line 34
    .line 35
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_1

    .line 40
    .line 41
    const/4 v3, 0x4

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    const/4 v3, 0x2

    .line 44
    :goto_0
    or-int/2addr v3, v6

    .line 45
    goto :goto_1

    .line 46
    :cond_2
    move-object/from16 v1, p0

    .line 47
    .line 48
    move v3, v6

    .line 49
    :goto_1
    and-int/lit8 v7, v6, 0x30

    .line 50
    .line 51
    const/16 v8, 0x20

    .line 52
    .line 53
    if-nez v7, :cond_4

    .line 54
    .line 55
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    if-eqz v7, :cond_3

    .line 60
    .line 61
    move v7, v8

    .line 62
    goto :goto_2

    .line 63
    :cond_3
    const/16 v7, 0x10

    .line 64
    .line 65
    :goto_2
    or-int/2addr v3, v7

    .line 66
    :cond_4
    and-int/lit16 v7, v6, 0x180

    .line 67
    .line 68
    move/from16 v9, p2

    .line 69
    .line 70
    if-nez v7, :cond_6

    .line 71
    .line 72
    invoke-virtual {v14, v9}, Ll2/t;->h(Z)Z

    .line 73
    .line 74
    .line 75
    move-result v7

    .line 76
    if-eqz v7, :cond_5

    .line 77
    .line 78
    const/16 v7, 0x100

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_5
    const/16 v7, 0x80

    .line 82
    .line 83
    :goto_3
    or-int/2addr v3, v7

    .line 84
    :cond_6
    and-int/lit16 v7, v6, 0xc00

    .line 85
    .line 86
    const/16 v10, 0x800

    .line 87
    .line 88
    if-nez v7, :cond_8

    .line 89
    .line 90
    invoke-virtual {v14, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v7

    .line 94
    if-eqz v7, :cond_7

    .line 95
    .line 96
    move v7, v10

    .line 97
    goto :goto_4

    .line 98
    :cond_7
    const/16 v7, 0x400

    .line 99
    .line 100
    :goto_4
    or-int/2addr v3, v7

    .line 101
    :cond_8
    and-int/lit16 v7, v6, 0x6000

    .line 102
    .line 103
    if-nez v7, :cond_a

    .line 104
    .line 105
    invoke-virtual {v14, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v7

    .line 109
    if-eqz v7, :cond_9

    .line 110
    .line 111
    const/16 v7, 0x4000

    .line 112
    .line 113
    goto :goto_5

    .line 114
    :cond_9
    const/16 v7, 0x2000

    .line 115
    .line 116
    :goto_5
    or-int/2addr v3, v7

    .line 117
    :cond_a
    and-int/lit16 v7, v3, 0x2493

    .line 118
    .line 119
    const/16 v11, 0x2492

    .line 120
    .line 121
    const/4 v12, 0x0

    .line 122
    const/4 v13, 0x1

    .line 123
    if-eq v7, v11, :cond_b

    .line 124
    .line 125
    move v7, v13

    .line 126
    goto :goto_6

    .line 127
    :cond_b
    move v7, v12

    .line 128
    :goto_6
    and-int/lit8 v11, v3, 0x1

    .line 129
    .line 130
    invoke-virtual {v14, v11, v7}, Ll2/t;->O(IZ)Z

    .line 131
    .line 132
    .line 133
    move-result v7

    .line 134
    if-eqz v7, :cond_11

    .line 135
    .line 136
    if-eqz v0, :cond_c

    .line 137
    .line 138
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 139
    .line 140
    move-object v7, v0

    .line 141
    goto :goto_7

    .line 142
    :cond_c
    move-object v7, v1

    .line 143
    :goto_7
    and-int/lit16 v0, v3, 0x1c00

    .line 144
    .line 145
    if-ne v0, v10, :cond_d

    .line 146
    .line 147
    move v0, v13

    .line 148
    goto :goto_8

    .line 149
    :cond_d
    move v0, v12

    .line 150
    :goto_8
    and-int/lit8 v1, v3, 0x70

    .line 151
    .line 152
    if-ne v1, v8, :cond_e

    .line 153
    .line 154
    move v12, v13

    .line 155
    :cond_e
    or-int/2addr v0, v12

    .line 156
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    if-nez v0, :cond_f

    .line 161
    .line 162
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 163
    .line 164
    if-ne v1, v0, :cond_10

    .line 165
    .line 166
    :cond_f
    new-instance v1, Llk/j;

    .line 167
    .line 168
    const/16 v0, 0x11

    .line 169
    .line 170
    invoke-direct {v1, v0, v4, v2}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v14, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    :cond_10
    move-object v10, v1

    .line 177
    check-cast v10, Lay0/a;

    .line 178
    .line 179
    iget-object v8, v2, Lma0/e;->a:Ljava/lang/String;

    .line 180
    .line 181
    iget-object v12, v2, Lma0/e;->c:Ljava/lang/String;

    .line 182
    .line 183
    const-string v0, "_icon"

    .line 184
    .line 185
    invoke-static {v12, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v13

    .line 189
    new-instance v0, Ll2/u;

    .line 190
    .line 191
    const/16 v1, 0x15

    .line 192
    .line 193
    invoke-direct {v0, v1, v2, v5}, Ll2/u;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    const v1, 0x164862e1

    .line 197
    .line 198
    .line 199
    invoke-static {v1, v14, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 200
    .line 201
    .line 202
    move-result-object v11

    .line 203
    and-int/lit8 v0, v3, 0xe

    .line 204
    .line 205
    or-int/lit16 v0, v0, 0x6000

    .line 206
    .line 207
    and-int/lit16 v1, v3, 0x380

    .line 208
    .line 209
    or-int v15, v0, v1

    .line 210
    .line 211
    invoke-static/range {v7 .. v15}, Lxf0/i0;->b(Lx2/s;Ljava/lang/String;ZLay0/a;Lt2/b;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 212
    .line 213
    .line 214
    move-object v1, v7

    .line 215
    goto :goto_9

    .line 216
    :cond_11
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 217
    .line 218
    .line 219
    :goto_9
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 220
    .line 221
    .line 222
    move-result-object v8

    .line 223
    if-eqz v8, :cond_12

    .line 224
    .line 225
    new-instance v0, Leq0/d;

    .line 226
    .line 227
    move/from16 v3, p2

    .line 228
    .line 229
    move/from16 v7, p7

    .line 230
    .line 231
    invoke-direct/range {v0 .. v7}, Leq0/d;-><init>(Lx2/s;Lma0/e;ZLay0/k;Lay0/k;II)V

    .line 232
    .line 233
    .line 234
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 235
    .line 236
    :cond_12
    return-void
.end method

.method public static final e(Lx2/s;Lay0/a;Ll2/o;II)V
    .locals 11

    .line 1
    move-object v4, p2

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const v0, 0x296a799e

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 v0, p4, 0x1

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    or-int/lit8 v1, p3, 0x6

    .line 15
    .line 16
    move v2, v1

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    const/4 v2, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const/4 v2, 0x2

    .line 27
    :goto_0
    or-int/2addr v2, p3

    .line 28
    :goto_1
    and-int/lit8 v3, p3, 0x30

    .line 29
    .line 30
    if-nez v3, :cond_3

    .line 31
    .line 32
    invoke-virtual {v4, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_2

    .line 37
    .line 38
    const/16 v3, 0x20

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/16 v3, 0x10

    .line 42
    .line 43
    :goto_2
    or-int/2addr v2, v3

    .line 44
    :cond_3
    and-int/lit8 v3, v2, 0x13

    .line 45
    .line 46
    const/16 v5, 0x12

    .line 47
    .line 48
    if-eq v3, v5, :cond_4

    .line 49
    .line 50
    const/4 v3, 0x1

    .line 51
    goto :goto_3

    .line 52
    :cond_4
    const/4 v3, 0x0

    .line 53
    :goto_3
    and-int/lit8 v5, v2, 0x1

    .line 54
    .line 55
    invoke-virtual {v4, v5, v3}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_6

    .line 60
    .line 61
    if-eqz v0, :cond_5

    .line 62
    .line 63
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 64
    .line 65
    goto :goto_4

    .line 66
    :cond_5
    move-object v0, p0

    .line 67
    :goto_4
    and-int/lit8 v1, v2, 0xe

    .line 68
    .line 69
    or-int/lit16 v1, v1, 0xc00

    .line 70
    .line 71
    and-int/lit8 v2, v2, 0x70

    .line 72
    .line 73
    or-int v5, v1, v2

    .line 74
    .line 75
    const/4 v6, 0x4

    .line 76
    const/4 v2, 0x0

    .line 77
    sget-object v3, Lna0/a;->a:Lt2/b;

    .line 78
    .line 79
    move-object v1, p1

    .line 80
    invoke-static/range {v0 .. v6}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 81
    .line 82
    .line 83
    move-object v6, v0

    .line 84
    goto :goto_5

    .line 85
    :cond_6
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    move-object v6, p0

    .line 89
    :goto_5
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    if-eqz v0, :cond_7

    .line 94
    .line 95
    new-instance v5, Lf20/b;

    .line 96
    .line 97
    const/4 v10, 0x2

    .line 98
    move-object v7, p1

    .line 99
    move v8, p3

    .line 100
    move v9, p4

    .line 101
    invoke-direct/range {v5 .. v10}, Lf20/b;-><init>(Lx2/s;Lay0/a;III)V

    .line 102
    .line 103
    .line 104
    iput-object v5, v0, Ll2/u1;->d:Lay0/n;

    .line 105
    .line 106
    :cond_7
    return-void
.end method

.method public static final f(Ll2/o;I)V
    .locals 4

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x6a53f505

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v1

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v0

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    sget-object v2, Lna0/a;->b:Lt2/b;

    .line 25
    .line 26
    const/16 v3, 0x30

    .line 27
    .line 28
    invoke-static {v0, v2, p0, v3, v1}, Lxf0/y1;->i(ZLay0/n;Ll2/o;II)V

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_2

    .line 40
    .line 41
    new-instance v0, Ln70/c0;

    .line 42
    .line 43
    const/16 v1, 0x15

    .line 44
    .line 45
    invoke-direct {v0, p1, v1}, Ln70/c0;-><init>(II)V

    .line 46
    .line 47
    .line 48
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 49
    .line 50
    :cond_2
    return-void
.end method

.method public static final g(Ll2/o;I)V
    .locals 16

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v7, p0

    .line 4
    .line 5
    check-cast v7, Ll2/t;

    .line 6
    .line 7
    const v1, -0x629a167f

    .line 8
    .line 9
    .line 10
    invoke-virtual {v7, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move v3, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v3, v2

    .line 20
    :goto_0
    and-int/lit8 v4, v0, 0x1

    .line 21
    .line 22
    invoke-virtual {v7, v4, v3}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_c

    .line 27
    .line 28
    const v3, -0x6040e0aa

    .line 29
    .line 30
    .line 31
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v7}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    if-eqz v3, :cond_b

    .line 39
    .line 40
    invoke-static {v3}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 41
    .line 42
    .line 43
    move-result-object v11

    .line 44
    invoke-static {v7}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 45
    .line 46
    .line 47
    move-result-object v13

    .line 48
    const-class v4, Lma0/g;

    .line 49
    .line 50
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 51
    .line 52
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    invoke-interface {v3}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 57
    .line 58
    .line 59
    move-result-object v9

    .line 60
    const/4 v10, 0x0

    .line 61
    const/4 v12, 0x0

    .line 62
    const/4 v14, 0x0

    .line 63
    invoke-static/range {v8 .. v14}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 68
    .line 69
    .line 70
    check-cast v3, Lql0/j;

    .line 71
    .line 72
    invoke-static {v3, v7, v2, v1}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 73
    .line 74
    .line 75
    move-object v10, v3

    .line 76
    check-cast v10, Lma0/g;

    .line 77
    .line 78
    iget-object v2, v10, Lql0/j;->g:Lyy0/l1;

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    invoke-static {v2, v3, v7, v1}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    check-cast v1, Lma0/f;

    .line 90
    .line 91
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-nez v2, :cond_1

    .line 102
    .line 103
    if-ne v3, v4, :cond_2

    .line 104
    .line 105
    :cond_1
    new-instance v8, Ln80/d;

    .line 106
    .line 107
    const/4 v14, 0x0

    .line 108
    const/16 v15, 0xa

    .line 109
    .line 110
    const/4 v9, 0x0

    .line 111
    const-class v11, Lma0/g;

    .line 112
    .line 113
    const-string v12, "onGoBack"

    .line 114
    .line 115
    const-string v13, "onGoBack()V"

    .line 116
    .line 117
    invoke-direct/range {v8 .. v15}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    move-object v3, v8

    .line 124
    :cond_2
    check-cast v3, Lhy0/g;

    .line 125
    .line 126
    move-object v2, v3

    .line 127
    check-cast v2, Lay0/a;

    .line 128
    .line 129
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    if-nez v3, :cond_3

    .line 138
    .line 139
    if-ne v5, v4, :cond_4

    .line 140
    .line 141
    :cond_3
    new-instance v8, Ln70/x;

    .line 142
    .line 143
    const/4 v14, 0x0

    .line 144
    const/4 v15, 0x7

    .line 145
    const/4 v9, 0x1

    .line 146
    const-class v11, Lma0/g;

    .line 147
    .line 148
    const-string v12, "onTodoSelected"

    .line 149
    .line 150
    const-string v13, "onTodoSelected(Lcz/skodaauto/myskoda/feature/vehicletodo/presentation/TodoDetailViewModel$State$TodoItem;)V"

    .line 151
    .line 152
    invoke-direct/range {v8 .. v15}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    move-object v5, v8

    .line 159
    :cond_4
    check-cast v5, Lhy0/g;

    .line 160
    .line 161
    move-object v3, v5

    .line 162
    check-cast v3, Lay0/k;

    .line 163
    .line 164
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v5

    .line 168
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v6

    .line 172
    if-nez v5, :cond_5

    .line 173
    .line 174
    if-ne v6, v4, :cond_6

    .line 175
    .line 176
    :cond_5
    new-instance v8, Ln70/x;

    .line 177
    .line 178
    const/4 v14, 0x0

    .line 179
    const/16 v15, 0x8

    .line 180
    .line 181
    const/4 v9, 0x1

    .line 182
    const-class v11, Lma0/g;

    .line 183
    .line 184
    const-string v12, "onOpenLink"

    .line 185
    .line 186
    const-string v13, "onOpenLink(Ljava/lang/String;)V"

    .line 187
    .line 188
    invoke-direct/range {v8 .. v15}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    move-object v6, v8

    .line 195
    :cond_6
    check-cast v6, Lhy0/g;

    .line 196
    .line 197
    check-cast v6, Lay0/k;

    .line 198
    .line 199
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    if-nez v5, :cond_7

    .line 208
    .line 209
    if-ne v8, v4, :cond_8

    .line 210
    .line 211
    :cond_7
    new-instance v8, Ln80/d;

    .line 212
    .line 213
    const/4 v14, 0x0

    .line 214
    const/16 v15, 0xb

    .line 215
    .line 216
    const/4 v9, 0x0

    .line 217
    const-class v11, Lma0/g;

    .line 218
    .line 219
    const-string v12, "onRefresh"

    .line 220
    .line 221
    const-string v13, "onRefresh()V"

    .line 222
    .line 223
    invoke-direct/range {v8 .. v15}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    :cond_8
    check-cast v8, Lhy0/g;

    .line 230
    .line 231
    move-object v5, v8

    .line 232
    check-cast v5, Lay0/a;

    .line 233
    .line 234
    invoke-virtual {v7, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v8

    .line 238
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v9

    .line 242
    if-nez v8, :cond_9

    .line 243
    .line 244
    if-ne v9, v4, :cond_a

    .line 245
    .line 246
    :cond_9
    new-instance v8, Ln80/d;

    .line 247
    .line 248
    const/4 v14, 0x0

    .line 249
    const/16 v15, 0xc

    .line 250
    .line 251
    const/4 v9, 0x0

    .line 252
    const-class v11, Lma0/g;

    .line 253
    .line 254
    const-string v12, "onCloseError"

    .line 255
    .line 256
    const-string v13, "onCloseError()V"

    .line 257
    .line 258
    invoke-direct/range {v8 .. v15}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 262
    .line 263
    .line 264
    move-object v9, v8

    .line 265
    :cond_a
    check-cast v9, Lhy0/g;

    .line 266
    .line 267
    check-cast v9, Lay0/a;

    .line 268
    .line 269
    const/4 v8, 0x0

    .line 270
    move-object v4, v6

    .line 271
    move-object v6, v9

    .line 272
    invoke-static/range {v1 .. v8}, Lna0/a;->h(Lma0/f;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    goto :goto_1

    .line 276
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 277
    .line 278
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 279
    .line 280
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    throw v0

    .line 284
    :cond_c
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_1
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    if-eqz v1, :cond_d

    .line 292
    .line 293
    new-instance v2, Ln70/c0;

    .line 294
    .line 295
    const/16 v3, 0x16

    .line 296
    .line 297
    invoke-direct {v2, v0, v3}, Ln70/c0;-><init>(II)V

    .line 298
    .line 299
    .line 300
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 301
    .line 302
    :cond_d
    return-void
.end method

.method public static final h(Lma0/f;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 23

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    move-object/from16 v7, p5

    .line 6
    .line 7
    move-object/from16 v8, p6

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v0, 0x2205c3a2

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

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
    or-int v0, p7, v0

    .line 27
    .line 28
    invoke-virtual {v8, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    const/16 v2, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v2, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v2

    .line 40
    move-object/from16 v3, p2

    .line 41
    .line 42
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_2

    .line 47
    .line 48
    const/16 v2, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v2, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v2

    .line 54
    move-object/from16 v4, p3

    .line 55
    .line 56
    invoke-virtual {v8, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_3

    .line 61
    .line 62
    const/16 v2, 0x800

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v2, 0x400

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v2

    .line 68
    move-object/from16 v5, p4

    .line 69
    .line 70
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    if-eqz v2, :cond_4

    .line 75
    .line 76
    const/16 v2, 0x4000

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/16 v2, 0x2000

    .line 80
    .line 81
    :goto_4
    or-int/2addr v0, v2

    .line 82
    invoke-virtual {v8, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    const/high16 v9, 0x20000

    .line 87
    .line 88
    if-eqz v2, :cond_5

    .line 89
    .line 90
    move v2, v9

    .line 91
    goto :goto_5

    .line 92
    :cond_5
    const/high16 v2, 0x10000

    .line 93
    .line 94
    :goto_5
    or-int/2addr v0, v2

    .line 95
    const v2, 0x12493

    .line 96
    .line 97
    .line 98
    and-int/2addr v2, v0

    .line 99
    const v10, 0x12492

    .line 100
    .line 101
    .line 102
    const/4 v11, 0x0

    .line 103
    const/4 v12, 0x1

    .line 104
    if-eq v2, v10, :cond_6

    .line 105
    .line 106
    move v2, v12

    .line 107
    goto :goto_6

    .line 108
    :cond_6
    move v2, v11

    .line 109
    :goto_6
    and-int/lit8 v10, v0, 0x1

    .line 110
    .line 111
    invoke-virtual {v8, v10, v2}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    if-eqz v2, :cond_b

    .line 116
    .line 117
    move v2, v0

    .line 118
    iget-object v0, v1, Lma0/f;->a:Lql0/g;

    .line 119
    .line 120
    if-nez v0, :cond_7

    .line 121
    .line 122
    const v0, 0x3ccd726f

    .line 123
    .line 124
    .line 125
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 129
    .line 130
    .line 131
    new-instance v0, Ln70/v;

    .line 132
    .line 133
    const/16 v2, 0x8

    .line 134
    .line 135
    invoke-direct {v0, v6, v2}, Ln70/v;-><init>(Lay0/a;I)V

    .line 136
    .line 137
    .line 138
    const v2, 0x68c8175e

    .line 139
    .line 140
    .line 141
    invoke-static {v2, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 142
    .line 143
    .line 144
    move-result-object v9

    .line 145
    new-instance v0, La71/u0;

    .line 146
    .line 147
    const/16 v1, 0x18

    .line 148
    .line 149
    move-object v2, v5

    .line 150
    move-object v5, v4

    .line 151
    move-object v4, v3

    .line 152
    move-object/from16 v3, p0

    .line 153
    .line 154
    invoke-direct/range {v0 .. v5}, La71/u0;-><init>(ILay0/a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    const v1, -0x5e3e820d

    .line 158
    .line 159
    .line 160
    invoke-static {v1, v8, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 161
    .line 162
    .line 163
    move-result-object v19

    .line 164
    const v21, 0x30000030

    .line 165
    .line 166
    .line 167
    const/16 v22, 0x1fd

    .line 168
    .line 169
    move-object v3, v8

    .line 170
    const/4 v8, 0x0

    .line 171
    const/4 v10, 0x0

    .line 172
    const/4 v11, 0x0

    .line 173
    const/4 v12, 0x0

    .line 174
    const/4 v13, 0x0

    .line 175
    const-wide/16 v14, 0x0

    .line 176
    .line 177
    const-wide/16 v16, 0x0

    .line 178
    .line 179
    const/16 v18, 0x0

    .line 180
    .line 181
    move-object/from16 v20, v3

    .line 182
    .line 183
    invoke-static/range {v8 .. v22}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 184
    .line 185
    .line 186
    goto :goto_9

    .line 187
    :cond_7
    move-object v3, v8

    .line 188
    const v1, 0x3ccd7270

    .line 189
    .line 190
    .line 191
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    const/high16 v1, 0x70000

    .line 195
    .line 196
    and-int/2addr v1, v2

    .line 197
    if-ne v1, v9, :cond_8

    .line 198
    .line 199
    goto :goto_7

    .line 200
    :cond_8
    move v12, v11

    .line 201
    :goto_7
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    if-nez v12, :cond_9

    .line 206
    .line 207
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 208
    .line 209
    if-ne v1, v2, :cond_a

    .line 210
    .line 211
    :cond_9
    new-instance v1, Li50/c0;

    .line 212
    .line 213
    const/16 v2, 0x13

    .line 214
    .line 215
    invoke-direct {v1, v7, v2}, Li50/c0;-><init>(Lay0/a;I)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    :cond_a
    check-cast v1, Lay0/k;

    .line 222
    .line 223
    const/4 v4, 0x0

    .line 224
    const/4 v5, 0x4

    .line 225
    const/4 v2, 0x0

    .line 226
    invoke-static/range {v0 .. v5}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 233
    .line 234
    .line 235
    move-result-object v9

    .line 236
    if-eqz v9, :cond_c

    .line 237
    .line 238
    new-instance v0, Lna0/b;

    .line 239
    .line 240
    const/4 v8, 0x0

    .line 241
    move-object/from16 v1, p0

    .line 242
    .line 243
    move-object/from16 v3, p2

    .line 244
    .line 245
    move-object/from16 v4, p3

    .line 246
    .line 247
    move-object/from16 v5, p4

    .line 248
    .line 249
    move-object v2, v6

    .line 250
    move-object v6, v7

    .line 251
    move/from16 v7, p7

    .line 252
    .line 253
    invoke-direct/range {v0 .. v8}, Lna0/b;-><init>(Lma0/f;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;II)V

    .line 254
    .line 255
    .line 256
    :goto_8
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 257
    .line 258
    return-void

    .line 259
    :cond_b
    move-object v3, v8

    .line 260
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 261
    .line 262
    .line 263
    :goto_9
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 264
    .line 265
    .line 266
    move-result-object v9

    .line 267
    if-eqz v9, :cond_c

    .line 268
    .line 269
    new-instance v0, Lna0/b;

    .line 270
    .line 271
    const/4 v8, 0x1

    .line 272
    move-object/from16 v1, p0

    .line 273
    .line 274
    move-object/from16 v2, p1

    .line 275
    .line 276
    move-object/from16 v3, p2

    .line 277
    .line 278
    move-object/from16 v4, p3

    .line 279
    .line 280
    move-object/from16 v5, p4

    .line 281
    .line 282
    move-object/from16 v6, p5

    .line 283
    .line 284
    move/from16 v7, p7

    .line 285
    .line 286
    invoke-direct/range {v0 .. v8}, Lna0/b;-><init>(Lma0/f;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;II)V

    .line 287
    .line 288
    .line 289
    goto :goto_8

    .line 290
    :cond_c
    return-void
.end method

.method public static final i(Ll2/o;I)V
    .locals 32

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    check-cast v1, Ll2/t;

    .line 4
    .line 5
    const v2, 0x3bdcdf41

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    move v4, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v4, v2

    .line 18
    :goto_0
    and-int/lit8 v5, p1, 0x1

    .line 19
    .line 20
    invoke-virtual {v1, v5, v4}, Ll2/t;->O(IZ)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_4

    .line 25
    .line 26
    sget-object v4, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 27
    .line 28
    sget-object v5, Lj91/a;->a:Ll2/u2;

    .line 29
    .line 30
    invoke-virtual {v1, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    check-cast v6, Lj91/c;

    .line 35
    .line 36
    iget v6, v6, Lj91/c;->j:F

    .line 37
    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x0

    .line 40
    invoke-static {v4, v6, v8, v7}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-static {v2, v3, v1}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    const/16 v6, 0xe

    .line 49
    .line 50
    invoke-static {v4, v2, v6}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    sget-object v4, Lk1/j;->e:Lk1/f;

    .line 55
    .line 56
    sget-object v6, Lx2/c;->q:Lx2/h;

    .line 57
    .line 58
    const/16 v7, 0x36

    .line 59
    .line 60
    invoke-static {v4, v6, v1, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    iget-wide v6, v1, Ll2/t;->T:J

    .line 65
    .line 66
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 79
    .line 80
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 84
    .line 85
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 86
    .line 87
    .line 88
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 89
    .line 90
    if-eqz v9, :cond_1

    .line 91
    .line 92
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 97
    .line 98
    .line 99
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 100
    .line 101
    invoke-static {v8, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 102
    .line 103
    .line 104
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 105
    .line 106
    invoke-static {v4, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 107
    .line 108
    .line 109
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 110
    .line 111
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 112
    .line 113
    if-nez v7, :cond_2

    .line 114
    .line 115
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 120
    .line 121
    .line 122
    move-result-object v8

    .line 123
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v7

    .line 127
    if-nez v7, :cond_3

    .line 128
    .line 129
    :cond_2
    invoke-static {v6, v1, v6, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 130
    .line 131
    .line 132
    :cond_3
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 133
    .line 134
    invoke-static {v4, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 135
    .line 136
    .line 137
    const v2, 0x7f12019a

    .line 138
    .line 139
    .line 140
    invoke-static {v1, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 145
    .line 146
    invoke-virtual {v1, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    check-cast v6, Lj91/f;

    .line 151
    .line 152
    invoke-virtual {v6}, Lj91/f;->l()Lg4/p0;

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 157
    .line 158
    invoke-virtual {v1, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    check-cast v8, Lj91/e;

    .line 163
    .line 164
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 165
    .line 166
    .line 167
    move-result-wide v8

    .line 168
    new-instance v12, Lr4/k;

    .line 169
    .line 170
    const/4 v10, 0x3

    .line 171
    invoke-direct {v12, v10}, Lr4/k;-><init>(I)V

    .line 172
    .line 173
    .line 174
    const/16 v21, 0x0

    .line 175
    .line 176
    const v22, 0xfbf4

    .line 177
    .line 178
    .line 179
    move v11, v3

    .line 180
    const/4 v3, 0x0

    .line 181
    move-object/from16 v19, v1

    .line 182
    .line 183
    move-object v1, v2

    .line 184
    move-object v2, v6

    .line 185
    move-object v13, v7

    .line 186
    const-wide/16 v6, 0x0

    .line 187
    .line 188
    move-object v14, v4

    .line 189
    move-wide/from16 v30, v8

    .line 190
    .line 191
    move-object v9, v5

    .line 192
    move-wide/from16 v4, v30

    .line 193
    .line 194
    const/4 v8, 0x0

    .line 195
    move-object v15, v9

    .line 196
    move/from16 v16, v10

    .line 197
    .line 198
    const-wide/16 v9, 0x0

    .line 199
    .line 200
    move/from16 v17, v11

    .line 201
    .line 202
    const/4 v11, 0x0

    .line 203
    move-object/from16 v20, v13

    .line 204
    .line 205
    move-object/from16 v18, v14

    .line 206
    .line 207
    const-wide/16 v13, 0x0

    .line 208
    .line 209
    move-object/from16 v23, v15

    .line 210
    .line 211
    const/4 v15, 0x0

    .line 212
    move/from16 v24, v16

    .line 213
    .line 214
    const/16 v16, 0x0

    .line 215
    .line 216
    move/from16 v25, v17

    .line 217
    .line 218
    const/16 v17, 0x0

    .line 219
    .line 220
    move-object/from16 v26, v18

    .line 221
    .line 222
    const/16 v18, 0x0

    .line 223
    .line 224
    move-object/from16 v27, v20

    .line 225
    .line 226
    const/16 v20, 0x0

    .line 227
    .line 228
    move-object/from16 v0, v23

    .line 229
    .line 230
    move-object/from16 v28, v26

    .line 231
    .line 232
    move-object/from16 v29, v27

    .line 233
    .line 234
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 235
    .line 236
    .line 237
    move-object/from16 v1, v19

    .line 238
    .line 239
    const/high16 v2, 0x3f800000    # 1.0f

    .line 240
    .line 241
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 242
    .line 243
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v0

    .line 251
    check-cast v0, Lj91/c;

    .line 252
    .line 253
    iget v0, v0, Lj91/c;->c:F

    .line 254
    .line 255
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    invoke-static {v1, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 260
    .line 261
    .line 262
    const v0, 0x7f12019c

    .line 263
    .line 264
    .line 265
    invoke-static {v1, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    move-object/from16 v14, v28

    .line 270
    .line 271
    invoke-virtual {v1, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    check-cast v2, Lj91/f;

    .line 276
    .line 277
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 278
    .line 279
    .line 280
    move-result-object v2

    .line 281
    move-object/from16 v13, v29

    .line 282
    .line 283
    invoke-virtual {v1, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    check-cast v3, Lj91/e;

    .line 288
    .line 289
    invoke-virtual {v3}, Lj91/e;->s()J

    .line 290
    .line 291
    .line 292
    move-result-wide v4

    .line 293
    new-instance v12, Lr4/k;

    .line 294
    .line 295
    const/4 v3, 0x3

    .line 296
    invoke-direct {v12, v3}, Lr4/k;-><init>(I)V

    .line 297
    .line 298
    .line 299
    const/4 v3, 0x0

    .line 300
    const-wide/16 v13, 0x0

    .line 301
    .line 302
    move-object v1, v0

    .line 303
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 304
    .line 305
    .line 306
    move-object/from16 v1, v19

    .line 307
    .line 308
    const/4 v11, 0x1

    .line 309
    invoke-virtual {v1, v11}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    goto :goto_2

    .line 313
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 314
    .line 315
    .line 316
    :goto_2
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    if-eqz v0, :cond_5

    .line 321
    .line 322
    new-instance v1, Ln70/c0;

    .line 323
    .line 324
    const/16 v2, 0x17

    .line 325
    .line 326
    move/from16 v3, p1

    .line 327
    .line 328
    invoke-direct {v1, v3, v2}, Ln70/c0;-><init>(II)V

    .line 329
    .line 330
    .line 331
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 332
    .line 333
    :cond_5
    return-void
.end method
