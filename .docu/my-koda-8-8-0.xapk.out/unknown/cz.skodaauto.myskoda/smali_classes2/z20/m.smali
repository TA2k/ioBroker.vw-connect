.class public final Lz20/m;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Lz4/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Ly20/g;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lvy0/b0;

.field public final synthetic l:Lh2/r8;

.field public final synthetic m:Lay0/k;


# direct methods
.method public constructor <init>(Ll2/b1;Lz4/k;Lay0/a;Ly20/g;Lay0/a;Lvy0/b0;Lh2/r8;Lay0/k;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lz20/m;->f:Ll2/b1;

    .line 2
    .line 3
    iput-object p2, p0, Lz20/m;->g:Lz4/k;

    .line 4
    .line 5
    iput-object p3, p0, Lz20/m;->h:Lay0/a;

    .line 6
    .line 7
    iput-object p4, p0, Lz20/m;->i:Ly20/g;

    .line 8
    .line 9
    iput-object p5, p0, Lz20/m;->j:Lay0/a;

    .line 10
    .line 11
    iput-object p6, p0, Lz20/m;->k:Lvy0/b0;

    .line 12
    .line 13
    iput-object p7, p0, Lz20/m;->l:Lh2/r8;

    .line 14
    .line 15
    iput-object p8, p0, Lz20/m;->m:Lay0/k;

    .line 16
    .line 17
    const/4 p1, 0x2

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 38

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
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v2, v2, 0x3

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    if-ne v2, v3, :cond_1

    .line 21
    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Ll2/t;

    .line 24
    .line 25
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-nez v3, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 33
    .line 34
    .line 35
    return-object v4

    .line 36
    :cond_1
    :goto_0
    iget-object v2, v0, Lz20/m;->f:Ll2/b1;

    .line 37
    .line 38
    invoke-interface {v2, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v0, Lz20/m;->g:Lz4/k;

    .line 42
    .line 43
    iget v3, v2, Lz4/k;->b:I

    .line 44
    .line 45
    invoke-virtual {v2}, Lz4/k;->e()V

    .line 46
    .line 47
    .line 48
    move-object v10, v1

    .line 49
    check-cast v10, Ll2/t;

    .line 50
    .line 51
    const v1, 0x65660868

    .line 52
    .line 53
    .line 54
    invoke-virtual {v10, v1}, Ll2/t;->Y(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2}, Lz4/k;->d()Lt1/j0;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    iget-object v1, v1, Lt1/j0;->e:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v1, Lz4/k;

    .line 64
    .line 65
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 66
    .line 67
    .line 68
    move-result-object v14

    .line 69
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 70
    .line 71
    .line 72
    move-result-object v15

    .line 73
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    sget-object v7, Lx2/c;->n:Lx2/i;

    .line 86
    .line 87
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 88
    .line 89
    const/high16 v9, 0x3f800000    # 1.0f

    .line 90
    .line 91
    invoke-static {v8, v9}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v11

    .line 95
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v12

    .line 99
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-ne v12, v13, :cond_2

    .line 102
    .line 103
    sget-object v12, Lz20/l;->e:Lz20/l;

    .line 104
    .line 105
    invoke-virtual {v10, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_2
    check-cast v12, Lay0/k;

    .line 109
    .line 110
    invoke-static {v11, v14, v12}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v11

    .line 114
    sget-object v12, Lk1/j;->a:Lk1/c;

    .line 115
    .line 116
    const/16 v9, 0x30

    .line 117
    .line 118
    invoke-static {v12, v7, v10, v9}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 119
    .line 120
    .line 121
    move-result-object v7

    .line 122
    move-object/from16 p2, v4

    .line 123
    .line 124
    move-object v9, v5

    .line 125
    iget-wide v4, v10, Ll2/t;->T:J

    .line 126
    .line 127
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 128
    .line 129
    .line 130
    move-result v4

    .line 131
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 132
    .line 133
    .line 134
    move-result-object v5

    .line 135
    invoke-static {v10, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 136
    .line 137
    .line 138
    move-result-object v11

    .line 139
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 140
    .line 141
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 145
    .line 146
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 147
    .line 148
    .line 149
    move-object/from16 v16, v6

    .line 150
    .line 151
    iget-boolean v6, v10, Ll2/t;->S:Z

    .line 152
    .line 153
    if-eqz v6, :cond_3

    .line 154
    .line 155
    invoke-virtual {v10, v12}, Ll2/t;->l(Lay0/a;)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_3
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 160
    .line 161
    .line 162
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 163
    .line 164
    invoke-static {v6, v7, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 165
    .line 166
    .line 167
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 168
    .line 169
    invoke-static {v6, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 170
    .line 171
    .line 172
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 173
    .line 174
    iget-boolean v6, v10, Ll2/t;->S:Z

    .line 175
    .line 176
    if-nez v6, :cond_4

    .line 177
    .line 178
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v6

    .line 182
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 183
    .line 184
    .line 185
    move-result-object v7

    .line 186
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    move-result v6

    .line 190
    if-nez v6, :cond_5

    .line 191
    .line 192
    :cond_4
    invoke-static {v4, v10, v4, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 193
    .line 194
    .line 195
    :cond_5
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 196
    .line 197
    invoke-static {v4, v11, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    const/high16 v4, 0x3f800000    # 1.0f

    .line 201
    .line 202
    float-to-double v5, v4

    .line 203
    const-wide/16 v11, 0x0

    .line 204
    .line 205
    cmpl-double v5, v5, v11

    .line 206
    .line 207
    if-lez v5, :cond_6

    .line 208
    .line 209
    goto :goto_2

    .line 210
    :cond_6
    const-string v5, "invalid weight; must be greater than zero"

    .line 211
    .line 212
    invoke-static {v5}, Ll1/a;->a(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    :goto_2
    new-instance v5, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 216
    .line 217
    const/4 v6, 0x1

    .line 218
    invoke-direct {v5, v4, v6}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 219
    .line 220
    .line 221
    iget-object v4, v0, Lz20/m;->i:Ly20/g;

    .line 222
    .line 223
    const/4 v7, 0x0

    .line 224
    invoke-static {v5, v4, v10, v7}, Lz20/a;->j(Lx2/s;Ly20/g;Ll2/o;I)V

    .line 225
    .line 226
    .line 227
    iget-object v5, v4, Ly20/g;->a:Lss0/d0;

    .line 228
    .line 229
    iget-object v11, v4, Ly20/g;->c:Ljava/lang/String;

    .line 230
    .line 231
    iget-object v12, v4, Ly20/g;->d:Ly20/f;

    .line 232
    .line 233
    instance-of v5, v5, Lss0/j0;

    .line 234
    .line 235
    if-eqz v5, :cond_9

    .line 236
    .line 237
    const v5, -0x253e38eb

    .line 238
    .line 239
    .line 240
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 241
    .line 242
    .line 243
    iget-object v5, v0, Lz20/m;->k:Lvy0/b0;

    .line 244
    .line 245
    invoke-virtual {v10, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v17

    .line 249
    iget-object v6, v0, Lz20/m;->l:Lh2/r8;

    .line 250
    .line 251
    invoke-virtual {v10, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v18

    .line 255
    or-int v17, v17, v18

    .line 256
    .line 257
    iget-object v7, v0, Lz20/m;->m:Lay0/k;

    .line 258
    .line 259
    invoke-virtual {v10, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v18

    .line 263
    or-int v17, v17, v18

    .line 264
    .line 265
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    move-result v18

    .line 269
    or-int v17, v17, v18

    .line 270
    .line 271
    move-object/from16 v20, v4

    .line 272
    .line 273
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    if-nez v17, :cond_7

    .line 278
    .line 279
    if-ne v4, v13, :cond_8

    .line 280
    .line 281
    :cond_7
    new-instance v17, Luu/b1;

    .line 282
    .line 283
    const/16 v22, 0x1

    .line 284
    .line 285
    move-object/from16 v18, v5

    .line 286
    .line 287
    move-object/from16 v21, v6

    .line 288
    .line 289
    move-object/from16 v19, v7

    .line 290
    .line 291
    invoke-direct/range {v17 .. v22}, Luu/b1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 292
    .line 293
    .line 294
    move-object/from16 v4, v17

    .line 295
    .line 296
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    :cond_8
    move-object v5, v4

    .line 300
    check-cast v5, Lay0/a;

    .line 301
    .line 302
    const/16 v4, 0x14

    .line 303
    .line 304
    int-to-float v4, v4

    .line 305
    invoke-static {v8, v4}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 306
    .line 307
    .line 308
    move-result-object v4

    .line 309
    const-string v6, "vehicle_card_more_button"

    .line 310
    .line 311
    invoke-static {v4, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 312
    .line 313
    .line 314
    move-result-object v6

    .line 315
    move-object v4, v11

    .line 316
    move-object v11, v10

    .line 317
    sget-object v10, Lz20/a;->g:Lt2/b;

    .line 318
    .line 319
    move-object v7, v12

    .line 320
    const v12, 0x180030

    .line 321
    .line 322
    .line 323
    move-object/from16 v17, v13

    .line 324
    .line 325
    const/16 v13, 0x3c

    .line 326
    .line 327
    move-object/from16 v18, v7

    .line 328
    .line 329
    const/4 v7, 0x0

    .line 330
    move-object/from16 v19, v8

    .line 331
    .line 332
    const/4 v8, 0x0

    .line 333
    move-object/from16 v21, v9

    .line 334
    .line 335
    const/4 v9, 0x0

    .line 336
    move-object/from16 v30, v1

    .line 337
    .line 338
    move-object/from16 v28, v2

    .line 339
    .line 340
    move/from16 p1, v3

    .line 341
    .line 342
    move-object/from16 v27, v4

    .line 343
    .line 344
    move-object/from16 v3, v16

    .line 345
    .line 346
    move-object/from16 v2, v17

    .line 347
    .line 348
    move-object/from16 v31, v18

    .line 349
    .line 350
    move-object/from16 v1, v19

    .line 351
    .line 352
    move-object/from16 v29, v20

    .line 353
    .line 354
    move-object/from16 v4, v21

    .line 355
    .line 356
    const/4 v0, 0x0

    .line 357
    invoke-static/range {v5 .. v13}, Lh2/r;->l(Lay0/a;Lx2/s;ZLh2/d5;Le3/n0;Lay0/n;Ll2/o;II)V

    .line 358
    .line 359
    .line 360
    move-object v10, v11

    .line 361
    :goto_3
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 362
    .line 363
    .line 364
    const/4 v5, 0x1

    .line 365
    goto :goto_4

    .line 366
    :cond_9
    move-object/from16 v30, v1

    .line 367
    .line 368
    move-object/from16 v28, v2

    .line 369
    .line 370
    move/from16 p1, v3

    .line 371
    .line 372
    move-object/from16 v29, v4

    .line 373
    .line 374
    move v0, v7

    .line 375
    move-object v1, v8

    .line 376
    move-object v4, v9

    .line 377
    move-object/from16 v27, v11

    .line 378
    .line 379
    move-object/from16 v31, v12

    .line 380
    .line 381
    move-object v2, v13

    .line 382
    move-object/from16 v3, v16

    .line 383
    .line 384
    const v5, -0x2626d5bd

    .line 385
    .line 386
    .line 387
    invoke-virtual {v10, v5}, Ll2/t;->Y(I)V

    .line 388
    .line 389
    .line 390
    goto :goto_3

    .line 391
    :goto_4
    invoke-virtual {v10, v5}, Ll2/t;->q(Z)V

    .line 392
    .line 393
    .line 394
    move-object/from16 v5, v29

    .line 395
    .line 396
    iget-boolean v6, v5, Ly20/g;->g:Z

    .line 397
    .line 398
    const v7, 0x64851dc7

    .line 399
    .line 400
    .line 401
    if-eqz v6, :cond_c

    .line 402
    .line 403
    const v6, 0x657a8fc0

    .line 404
    .line 405
    .line 406
    invoke-virtual {v10, v6}, Ll2/t;->Y(I)V

    .line 407
    .line 408
    .line 409
    const v6, 0x7f120354

    .line 410
    .line 411
    .line 412
    invoke-static {v10, v6}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 413
    .line 414
    .line 415
    move-result-object v6

    .line 416
    sget-object v8, Lj91/j;->a:Ll2/u2;

    .line 417
    .line 418
    invoke-virtual {v10, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v8

    .line 422
    check-cast v8, Lj91/f;

    .line 423
    .line 424
    invoke-virtual {v8}, Lj91/f;->e()Lg4/p0;

    .line 425
    .line 426
    .line 427
    move-result-object v8

    .line 428
    sget-object v9, Lj91/h;->a:Ll2/u2;

    .line 429
    .line 430
    invoke-virtual {v10, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v9

    .line 434
    check-cast v9, Lj91/e;

    .line 435
    .line 436
    invoke-virtual {v9}, Lj91/e;->s()J

    .line 437
    .line 438
    .line 439
    move-result-wide v11

    .line 440
    invoke-virtual {v10, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 441
    .line 442
    .line 443
    move-result v9

    .line 444
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v13

    .line 448
    if-nez v9, :cond_a

    .line 449
    .line 450
    if-ne v13, v2, :cond_b

    .line 451
    .line 452
    :cond_a
    new-instance v13, Lc40/g;

    .line 453
    .line 454
    const/16 v9, 0x16

    .line 455
    .line 456
    invoke-direct {v13, v14, v9}, Lc40/g;-><init>(Lz4/f;I)V

    .line 457
    .line 458
    .line 459
    invoke-virtual {v10, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 460
    .line 461
    .line 462
    :cond_b
    check-cast v13, Lay0/k;

    .line 463
    .line 464
    invoke-static {v1, v15, v13}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 465
    .line 466
    .line 467
    move-result-object v9

    .line 468
    const-string v13, "vehicle_card_guest_user"

    .line 469
    .line 470
    invoke-static {v9, v13}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 471
    .line 472
    .line 473
    move-result-object v9

    .line 474
    const/16 v25, 0x0

    .line 475
    .line 476
    const v26, 0xfff0

    .line 477
    .line 478
    .line 479
    move-object/from16 v20, v5

    .line 480
    .line 481
    move-object v5, v6

    .line 482
    move-object v6, v8

    .line 483
    move-object/from16 v23, v10

    .line 484
    .line 485
    move-wide/from16 v36, v11

    .line 486
    .line 487
    move v12, v7

    .line 488
    move-object v7, v9

    .line 489
    move-wide/from16 v8, v36

    .line 490
    .line 491
    const-wide/16 v10, 0x0

    .line 492
    .line 493
    move v13, v12

    .line 494
    const/4 v12, 0x0

    .line 495
    move/from16 v16, v13

    .line 496
    .line 497
    move-object v15, v14

    .line 498
    const-wide/16 v13, 0x0

    .line 499
    .line 500
    move-object/from16 v17, v15

    .line 501
    .line 502
    const/4 v15, 0x0

    .line 503
    move/from16 v18, v16

    .line 504
    .line 505
    const/16 v16, 0x0

    .line 506
    .line 507
    move-object/from16 v19, v17

    .line 508
    .line 509
    move/from16 v21, v18

    .line 510
    .line 511
    const-wide/16 v17, 0x0

    .line 512
    .line 513
    move-object/from16 v22, v19

    .line 514
    .line 515
    const/16 v19, 0x0

    .line 516
    .line 517
    move-object/from16 v29, v20

    .line 518
    .line 519
    const/16 v20, 0x0

    .line 520
    .line 521
    move/from16 v24, v21

    .line 522
    .line 523
    const/16 v21, 0x0

    .line 524
    .line 525
    move-object/from16 v32, v22

    .line 526
    .line 527
    const/16 v22, 0x0

    .line 528
    .line 529
    move/from16 v33, v24

    .line 530
    .line 531
    const/16 v24, 0x0

    .line 532
    .line 533
    move-object/from16 v34, v3

    .line 534
    .line 535
    move-object/from16 v35, v29

    .line 536
    .line 537
    move-object/from16 v3, v32

    .line 538
    .line 539
    move-object/from16 v29, v4

    .line 540
    .line 541
    move/from16 v4, v33

    .line 542
    .line 543
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 544
    .line 545
    .line 546
    move-object/from16 v10, v23

    .line 547
    .line 548
    :goto_5
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 549
    .line 550
    .line 551
    move-object/from16 v13, v35

    .line 552
    .line 553
    goto :goto_6

    .line 554
    :cond_c
    move-object/from16 v34, v3

    .line 555
    .line 556
    move-object/from16 v29, v4

    .line 557
    .line 558
    move-object/from16 v35, v5

    .line 559
    .line 560
    move v4, v7

    .line 561
    move-object v3, v14

    .line 562
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 563
    .line 564
    .line 565
    goto :goto_5

    .line 566
    :goto_6
    iget-object v6, v13, Ly20/g;->i:Lhp0/e;

    .line 567
    .line 568
    sget v5, Lz20/e;->a:F

    .line 569
    .line 570
    invoke-static {v1, v5}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 571
    .line 572
    .line 573
    move-result-object v5

    .line 574
    sget v7, Lz20/e;->b:F

    .line 575
    .line 576
    invoke-static {v5, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 577
    .line 578
    .line 579
    move-result-object v5

    .line 580
    iget v7, v13, Ly20/g;->h:F

    .line 581
    .line 582
    invoke-static {v5, v7}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 583
    .line 584
    .line 585
    move-result-object v5

    .line 586
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 587
    .line 588
    .line 589
    move-result v7

    .line 590
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 591
    .line 592
    .line 593
    move-result-object v8

    .line 594
    if-nez v7, :cond_d

    .line 595
    .line 596
    if-ne v8, v2, :cond_e

    .line 597
    .line 598
    :cond_d
    new-instance v8, Lc40/g;

    .line 599
    .line 600
    const/16 v7, 0x17

    .line 601
    .line 602
    invoke-direct {v8, v3, v7}, Lc40/g;-><init>(Lz4/f;I)V

    .line 603
    .line 604
    .line 605
    invoke-virtual {v10, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 606
    .line 607
    .line 608
    :cond_e
    check-cast v8, Lay0/k;

    .line 609
    .line 610
    move-object/from16 v3, v29

    .line 611
    .line 612
    invoke-static {v5, v3, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 613
    .line 614
    .line 615
    move-result-object v5

    .line 616
    const/16 v11, 0xc40

    .line 617
    .line 618
    const/16 v12, 0x14

    .line 619
    .line 620
    const/4 v7, 0x0

    .line 621
    sget-object v8, Lt3/j;->d:Lt3/x0;

    .line 622
    .line 623
    const/4 v9, 0x0

    .line 624
    invoke-static/range {v5 .. v12}, Llp/xa;->c(Lx2/s;Lhp0/e;ILt3/k;Lay0/a;Ll2/o;II)V

    .line 625
    .line 626
    .line 627
    iget-object v5, v13, Ly20/g;->e:Ljava/lang/String;

    .line 628
    .line 629
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 630
    .line 631
    invoke-virtual {v10, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 632
    .line 633
    .line 634
    move-result-object v6

    .line 635
    check-cast v6, Lj91/f;

    .line 636
    .line 637
    invoke-virtual {v6}, Lj91/f;->j()Lg4/p0;

    .line 638
    .line 639
    .line 640
    move-result-object v6

    .line 641
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 642
    .line 643
    .line 644
    move-result v7

    .line 645
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 646
    .line 647
    .line 648
    move-result-object v8

    .line 649
    if-nez v7, :cond_f

    .line 650
    .line 651
    if-ne v8, v2, :cond_10

    .line 652
    .line 653
    :cond_f
    new-instance v8, Lc40/g;

    .line 654
    .line 655
    const/16 v7, 0x18

    .line 656
    .line 657
    invoke-direct {v8, v3, v7}, Lc40/g;-><init>(Lz4/f;I)V

    .line 658
    .line 659
    .line 660
    invoke-virtual {v10, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 661
    .line 662
    .line 663
    :cond_10
    check-cast v8, Lay0/k;

    .line 664
    .line 665
    move-object/from16 v3, v34

    .line 666
    .line 667
    invoke-static {v1, v3, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 668
    .line 669
    .line 670
    move-result-object v3

    .line 671
    const-string v7, "vehicle_card_name"

    .line 672
    .line 673
    invoke-static {v3, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 674
    .line 675
    .line 676
    move-result-object v7

    .line 677
    const/16 v25, 0x0

    .line 678
    .line 679
    const v26, 0xfff8

    .line 680
    .line 681
    .line 682
    const-wide/16 v8, 0x0

    .line 683
    .line 684
    move-object/from16 v23, v10

    .line 685
    .line 686
    const-wide/16 v10, 0x0

    .line 687
    .line 688
    const/4 v12, 0x0

    .line 689
    const-wide/16 v13, 0x0

    .line 690
    .line 691
    const/4 v15, 0x0

    .line 692
    const/16 v16, 0x0

    .line 693
    .line 694
    const-wide/16 v17, 0x0

    .line 695
    .line 696
    const/16 v19, 0x0

    .line 697
    .line 698
    const/16 v20, 0x0

    .line 699
    .line 700
    const/16 v21, 0x0

    .line 701
    .line 702
    const/16 v22, 0x0

    .line 703
    .line 704
    const/16 v24, 0x0

    .line 705
    .line 706
    invoke-static/range {v5 .. v26}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 707
    .line 708
    .line 709
    move-object/from16 v10, v23

    .line 710
    .line 711
    sget-object v3, Ly20/f;->e:Ly20/f;

    .line 712
    .line 713
    move-object/from16 v13, v31

    .line 714
    .line 715
    if-ne v13, v3, :cond_12

    .line 716
    .line 717
    const v3, 0x65910830

    .line 718
    .line 719
    .line 720
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 721
    .line 722
    .line 723
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 724
    .line 725
    .line 726
    move-result-object v3

    .line 727
    if-ne v3, v2, :cond_11

    .line 728
    .line 729
    sget-object v3, Lz20/l;->f:Lz20/l;

    .line 730
    .line 731
    invoke-virtual {v10, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 732
    .line 733
    .line 734
    :cond_11
    check-cast v3, Lay0/k;

    .line 735
    .line 736
    move-object/from16 v14, v30

    .line 737
    .line 738
    invoke-static {v1, v14, v3}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 739
    .line 740
    .line 741
    move-result-object v3

    .line 742
    const v5, 0x7f12033e

    .line 743
    .line 744
    .line 745
    invoke-static {v3, v5}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 746
    .line 747
    .line 748
    move-result-object v11

    .line 749
    const/4 v5, 0x0

    .line 750
    const/16 v6, 0x18

    .line 751
    .line 752
    move-object/from16 v3, p0

    .line 753
    .line 754
    iget-object v7, v3, Lz20/m;->j:Lay0/a;

    .line 755
    .line 756
    const/4 v8, 0x0

    .line 757
    const/4 v12, 0x0

    .line 758
    move-object/from16 v9, v27

    .line 759
    .line 760
    invoke-static/range {v5 .. v12}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 761
    .line 762
    .line 763
    :goto_7
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 764
    .line 765
    .line 766
    goto :goto_8

    .line 767
    :cond_12
    move-object/from16 v3, p0

    .line 768
    .line 769
    move-object/from16 v9, v27

    .line 770
    .line 771
    move-object/from16 v14, v30

    .line 772
    .line 773
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 774
    .line 775
    .line 776
    goto :goto_7

    .line 777
    :goto_8
    sget-object v5, Ly20/f;->g:Ly20/f;

    .line 778
    .line 779
    if-ne v13, v5, :cond_14

    .line 780
    .line 781
    const v4, 0x65986712

    .line 782
    .line 783
    .line 784
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 785
    .line 786
    .line 787
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 788
    .line 789
    .line 790
    move-result-object v4

    .line 791
    if-ne v4, v2, :cond_13

    .line 792
    .line 793
    sget-object v4, Lz20/l;->g:Lz20/l;

    .line 794
    .line 795
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 796
    .line 797
    .line 798
    :cond_13
    check-cast v4, Lay0/k;

    .line 799
    .line 800
    invoke-static {v1, v14, v4}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 801
    .line 802
    .line 803
    move-result-object v1

    .line 804
    const v2, 0x7f12159c

    .line 805
    .line 806
    .line 807
    invoke-static {v1, v2}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 808
    .line 809
    .line 810
    move-result-object v11

    .line 811
    const/4 v5, 0x0

    .line 812
    const/16 v6, 0x18

    .line 813
    .line 814
    iget-object v7, v3, Lz20/m;->j:Lay0/a;

    .line 815
    .line 816
    const/4 v8, 0x0

    .line 817
    const/4 v12, 0x0

    .line 818
    invoke-static/range {v5 .. v12}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 819
    .line 820
    .line 821
    :goto_9
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 822
    .line 823
    .line 824
    goto :goto_a

    .line 825
    :cond_14
    invoke-virtual {v10, v4}, Ll2/t;->Y(I)V

    .line 826
    .line 827
    .line 828
    goto :goto_9

    .line 829
    :goto_a
    invoke-virtual {v10, v0}, Ll2/t;->q(Z)V

    .line 830
    .line 831
    .line 832
    move-object/from16 v0, v28

    .line 833
    .line 834
    iget v0, v0, Lz4/k;->b:I

    .line 835
    .line 836
    move/from16 v1, p1

    .line 837
    .line 838
    if-eq v0, v1, :cond_15

    .line 839
    .line 840
    iget-object v0, v3, Lz20/m;->h:Lay0/a;

    .line 841
    .line 842
    invoke-static {v0, v10}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 843
    .line 844
    .line 845
    :cond_15
    return-object p2
.end method
