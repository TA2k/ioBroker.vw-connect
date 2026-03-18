.class public final synthetic Li40/m3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Landroid/net/Uri;

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Lg4/p0;


# direct methods
.method public synthetic constructor <init>(Landroid/net/Uri;FFFLjava/lang/String;Lg4/p0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li40/m3;->d:Landroid/net/Uri;

    .line 5
    .line 6
    iput p2, p0, Li40/m3;->e:F

    .line 7
    .line 8
    iput p3, p0, Li40/m3;->f:F

    .line 9
    .line 10
    iput p4, p0, Li40/m3;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Li40/m3;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Li40/m3;->i:Lg4/p0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x1

    .line 19
    const/4 v6, 0x0

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v5

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v6

    .line 25
    :goto_0
    and-int/2addr v2, v5

    .line 26
    move-object v14, v1

    .line 27
    check-cast v14, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_f

    .line 34
    .line 35
    sget-object v8, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 36
    .line 37
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 38
    .line 39
    invoke-static {v1, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iget-wide v2, v14, Ll2/t;->T:J

    .line 44
    .line 45
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-static {v14, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 58
    .line 59
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 63
    .line 64
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 65
    .line 66
    .line 67
    iget-boolean v9, v14, Ll2/t;->S:Z

    .line 68
    .line 69
    if-eqz v9, :cond_1

    .line 70
    .line 71
    invoke-virtual {v14, v7}, Ll2/t;->l(Lay0/a;)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 76
    .line 77
    .line 78
    :goto_1
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 79
    .line 80
    invoke-static {v9, v1, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 81
    .line 82
    .line 83
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 84
    .line 85
    invoke-static {v1, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 86
    .line 87
    .line 88
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 89
    .line 90
    iget-boolean v10, v14, Ll2/t;->S:Z

    .line 91
    .line 92
    if-nez v10, :cond_2

    .line 93
    .line 94
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v10

    .line 98
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object v11

    .line 102
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v10

    .line 106
    if-nez v10, :cond_3

    .line 107
    .line 108
    :cond_2
    invoke-static {v2, v14, v2, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 109
    .line 110
    .line 111
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 112
    .line 113
    invoke-static {v2, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 121
    .line 122
    if-ne v4, v10, :cond_4

    .line 123
    .line 124
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    invoke-virtual {v14, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_4
    check-cast v4, Ll2/b1;

    .line 134
    .line 135
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v11

    .line 139
    check-cast v11, Ljava/lang/Boolean;

    .line 140
    .line 141
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 142
    .line 143
    .line 144
    move-result v11

    .line 145
    if-eqz v11, :cond_6

    .line 146
    .line 147
    const v11, -0x8381719

    .line 148
    .line 149
    .line 150
    invoke-virtual {v14, v11}, Ll2/t;->Y(I)V

    .line 151
    .line 152
    .line 153
    const/high16 p1, 0x3f800000    # 1.0f

    .line 154
    .line 155
    sget-wide v12, Le3/s;->b:J

    .line 156
    .line 157
    invoke-static {v14}, Lkp/k;->c(Ll2/o;)Z

    .line 158
    .line 159
    .line 160
    move-result v11

    .line 161
    if-eqz v11, :cond_5

    .line 162
    .line 163
    const v11, 0x3ecccccd    # 0.4f

    .line 164
    .line 165
    .line 166
    goto :goto_2

    .line 167
    :cond_5
    const v11, 0x3f19999a    # 0.6f

    .line 168
    .line 169
    .line 170
    :goto_2
    sub-float v11, p1, v11

    .line 171
    .line 172
    invoke-static {v12, v13, v11}, Le3/s;->b(JF)J

    .line 173
    .line 174
    .line 175
    move-result-wide v11

    .line 176
    new-instance v13, Le3/m;

    .line 177
    .line 178
    const/16 v15, 0x10

    .line 179
    .line 180
    invoke-direct {v13, v11, v12, v15}, Le3/m;-><init>(JI)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    :goto_3
    move-object/from16 v21, v13

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_6
    const/high16 p1, 0x3f800000    # 1.0f

    .line 190
    .line 191
    const v11, -0x835233b

    .line 192
    .line 193
    .line 194
    invoke-virtual {v14, v11}, Ll2/t;->Y(I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 198
    .line 199
    .line 200
    const/4 v13, 0x0

    .line 201
    goto :goto_3

    .line 202
    :goto_4
    const v11, 0x7f080247

    .line 203
    .line 204
    .line 205
    invoke-static {v11, v6, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 206
    .line 207
    .line 208
    move-result-object v16

    .line 209
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v11

    .line 213
    if-ne v11, v10, :cond_7

    .line 214
    .line 215
    new-instance v11, La2/h;

    .line 216
    .line 217
    const/16 v12, 0x1c

    .line 218
    .line 219
    invoke-direct {v11, v4, v12}, La2/h;-><init>(Ll2/b1;I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v14, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    :cond_7
    check-cast v11, Lay0/a;

    .line 226
    .line 227
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v12

    .line 231
    if-ne v12, v10, :cond_8

    .line 232
    .line 233
    new-instance v12, La2/h;

    .line 234
    .line 235
    const/16 v10, 0x1d

    .line 236
    .line 237
    invoke-direct {v12, v4, v10}, La2/h;-><init>(Ll2/b1;I)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {v14, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    :cond_8
    check-cast v12, Lay0/a;

    .line 244
    .line 245
    const/16 v24, 0x0

    .line 246
    .line 247
    const v25, 0xf5e4

    .line 248
    .line 249
    .line 250
    move-object v10, v7

    .line 251
    iget-object v7, v0, Li40/m3;->d:Landroid/net/Uri;

    .line 252
    .line 253
    move-object v13, v9

    .line 254
    const/4 v9, 0x0

    .line 255
    move-object v15, v10

    .line 256
    move-object v10, v11

    .line 257
    move-object v11, v12

    .line 258
    const/4 v12, 0x0

    .line 259
    move-object/from16 v17, v13

    .line 260
    .line 261
    const/4 v13, 0x0

    .line 262
    move-object/from16 v22, v14

    .line 263
    .line 264
    sget-object v14, Lt3/j;->a:Lt3/x0;

    .line 265
    .line 266
    move-object/from16 v18, v15

    .line 267
    .line 268
    const/4 v15, 0x0

    .line 269
    move-object/from16 v19, v17

    .line 270
    .line 271
    const/16 v17, 0x0

    .line 272
    .line 273
    move-object/from16 v20, v18

    .line 274
    .line 275
    const/16 v18, 0x0

    .line 276
    .line 277
    move-object/from16 v23, v19

    .line 278
    .line 279
    const/16 v19, 0x0

    .line 280
    .line 281
    move-object/from16 v26, v20

    .line 282
    .line 283
    const/16 v20, 0x0

    .line 284
    .line 285
    move-object/from16 v27, v23

    .line 286
    .line 287
    const v23, 0x30006c30

    .line 288
    .line 289
    .line 290
    move-object/from16 v5, v26

    .line 291
    .line 292
    move-object/from16 v29, v27

    .line 293
    .line 294
    invoke-static/range {v7 .. v25}, Lxf0/i0;->c(Landroid/net/Uri;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ld01/h0;Lx2/e;Lt3/k;Ljava/util/List;Li3/c;Li3/c;Li3/c;ZZLe3/m;Ll2/o;III)V

    .line 295
    .line 296
    .line 297
    move-object/from16 v14, v22

    .line 298
    .line 299
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v4

    .line 303
    check-cast v4, Ljava/lang/Boolean;

    .line 304
    .line 305
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 306
    .line 307
    .line 308
    move-result v4

    .line 309
    if-eqz v4, :cond_e

    .line 310
    .line 311
    const v4, -0x82d7945

    .line 312
    .line 313
    .line 314
    invoke-virtual {v14, v4}, Ll2/t;->Y(I)V

    .line 315
    .line 316
    .line 317
    iget v4, v0, Li40/m3;->e:F

    .line 318
    .line 319
    invoke-static {v8, v4}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 320
    .line 321
    .line 322
    move-result-object v4

    .line 323
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 324
    .line 325
    sget-object v8, Lx2/c;->p:Lx2/h;

    .line 326
    .line 327
    invoke-static {v7, v8, v14, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 328
    .line 329
    .line 330
    move-result-object v7

    .line 331
    iget-wide v8, v14, Ll2/t;->T:J

    .line 332
    .line 333
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 334
    .line 335
    .line 336
    move-result v8

    .line 337
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 338
    .line 339
    .line 340
    move-result-object v9

    .line 341
    invoke-static {v14, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 342
    .line 343
    .line 344
    move-result-object v4

    .line 345
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 346
    .line 347
    .line 348
    iget-boolean v10, v14, Ll2/t;->S:Z

    .line 349
    .line 350
    if-eqz v10, :cond_9

    .line 351
    .line 352
    invoke-virtual {v14, v5}, Ll2/t;->l(Lay0/a;)V

    .line 353
    .line 354
    .line 355
    :goto_5
    move-object/from16 v13, v29

    .line 356
    .line 357
    goto :goto_6

    .line 358
    :cond_9
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 359
    .line 360
    .line 361
    goto :goto_5

    .line 362
    :goto_6
    invoke-static {v13, v7, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 363
    .line 364
    .line 365
    invoke-static {v1, v9, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 366
    .line 367
    .line 368
    iget-boolean v1, v14, Ll2/t;->S:Z

    .line 369
    .line 370
    if-nez v1, :cond_a

    .line 371
    .line 372
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v1

    .line 376
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 377
    .line 378
    .line 379
    move-result-object v5

    .line 380
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 381
    .line 382
    .line 383
    move-result v1

    .line 384
    if-nez v1, :cond_b

    .line 385
    .line 386
    :cond_a
    invoke-static {v8, v14, v8, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 387
    .line 388
    .line 389
    :cond_b
    invoke-static {v2, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 390
    .line 391
    .line 392
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 393
    .line 394
    iget v2, v0, Li40/m3;->f:F

    .line 395
    .line 396
    iget v3, v0, Li40/m3;->g:F

    .line 397
    .line 398
    invoke-static {v1, v2, v3}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 399
    .line 400
    .line 401
    move-result-object v9

    .line 402
    const v1, 0x7f080238

    .line 403
    .line 404
    .line 405
    invoke-static {v1, v6, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 406
    .line 407
    .line 408
    move-result-object v7

    .line 409
    const/16 v15, 0x30

    .line 410
    .line 411
    const/16 v16, 0x78

    .line 412
    .line 413
    const/4 v8, 0x0

    .line 414
    const/4 v10, 0x0

    .line 415
    const/4 v11, 0x0

    .line 416
    const/4 v12, 0x0

    .line 417
    const/4 v13, 0x0

    .line 418
    invoke-static/range {v7 .. v16}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 419
    .line 420
    .line 421
    iget-object v7, v0, Li40/m3;->h:Ljava/lang/String;

    .line 422
    .line 423
    if-nez v7, :cond_c

    .line 424
    .line 425
    const v0, 0x4e995cca

    .line 426
    .line 427
    .line 428
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 429
    .line 430
    .line 431
    :goto_7
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 432
    .line 433
    .line 434
    const/4 v2, 0x1

    .line 435
    goto :goto_a

    .line 436
    :cond_c
    const v1, 0x4e995ccb

    .line 437
    .line 438
    .line 439
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 440
    .line 441
    .line 442
    const/high16 v1, 0x3f800000    # 1.0f

    .line 443
    .line 444
    float-to-double v2, v1

    .line 445
    const-wide/16 v4, 0x0

    .line 446
    .line 447
    cmpl-double v2, v2, v4

    .line 448
    .line 449
    if-lez v2, :cond_d

    .line 450
    .line 451
    :goto_8
    const/4 v2, 0x1

    .line 452
    goto :goto_9

    .line 453
    :cond_d
    const-string v2, "invalid weight; must be greater than zero"

    .line 454
    .line 455
    invoke-static {v2}, Ll1/a;->a(Ljava/lang/String;)V

    .line 456
    .line 457
    .line 458
    goto :goto_8

    .line 459
    :goto_9
    invoke-static {v1, v2, v14}, Lvj/b;->u(FZLl2/t;)V

    .line 460
    .line 461
    .line 462
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 463
    .line 464
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v1

    .line 468
    check-cast v1, Lj91/e;

    .line 469
    .line 470
    invoke-virtual {v1}, Lj91/e;->g()J

    .line 471
    .line 472
    .line 473
    move-result-wide v10

    .line 474
    const/16 v27, 0x0

    .line 475
    .line 476
    const v28, 0xfff4

    .line 477
    .line 478
    .line 479
    iget-object v8, v0, Li40/m3;->i:Lg4/p0;

    .line 480
    .line 481
    const/4 v9, 0x0

    .line 482
    const-wide/16 v12, 0x0

    .line 483
    .line 484
    move-object/from16 v22, v14

    .line 485
    .line 486
    const/4 v14, 0x0

    .line 487
    const-wide/16 v15, 0x0

    .line 488
    .line 489
    const/16 v17, 0x0

    .line 490
    .line 491
    const/16 v18, 0x0

    .line 492
    .line 493
    const-wide/16 v19, 0x0

    .line 494
    .line 495
    const/16 v21, 0x0

    .line 496
    .line 497
    move-object/from16 v25, v22

    .line 498
    .line 499
    const/16 v22, 0x0

    .line 500
    .line 501
    const/16 v23, 0x0

    .line 502
    .line 503
    const/16 v24, 0x0

    .line 504
    .line 505
    const/16 v26, 0x0

    .line 506
    .line 507
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 508
    .line 509
    .line 510
    move-object/from16 v14, v25

    .line 511
    .line 512
    goto :goto_7

    .line 513
    :goto_a
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 514
    .line 515
    .line 516
    :goto_b
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 517
    .line 518
    .line 519
    goto :goto_c

    .line 520
    :cond_e
    const/4 v2, 0x1

    .line 521
    const v0, -0x879b197

    .line 522
    .line 523
    .line 524
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 525
    .line 526
    .line 527
    goto :goto_b

    .line 528
    :goto_c
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 529
    .line 530
    .line 531
    goto :goto_d

    .line 532
    :cond_f
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 533
    .line 534
    .line 535
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 536
    .line 537
    return-object v0
.end method
