.class public final synthetic Lxf0/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Z

.field public final synthetic h:J

.field public final synthetic i:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(IZLjava/lang/String;ZJLjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/p0;->d:I

    .line 5
    .line 6
    iput-boolean p2, p0, Lxf0/p0;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, Lxf0/p0;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-boolean p4, p0, Lxf0/p0;->g:Z

    .line 11
    .line 12
    iput-wide p5, p0, Lxf0/p0;->h:J

    .line 13
    .line 14
    iput-object p7, p0, Lxf0/p0;->i:Ljava/lang/String;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

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
    const/4 v4, 0x1

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x2

    .line 20
    if-eq v3, v6, :cond_0

    .line 21
    .line 22
    move v3, v4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v4

    .line 26
    move-object v12, v1

    .line 27
    check-cast v12, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_b

    .line 34
    .line 35
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 36
    .line 37
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 38
    .line 39
    const/high16 v3, 0x3f800000    # 1.0f

    .line 40
    .line 41
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 46
    .line 47
    .line 48
    move-result-object v8

    .line 49
    iget v8, v8, Lj91/c;->j:F

    .line 50
    .line 51
    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    sget-object v8, Lk1/j;->a:Lk1/c;

    .line 56
    .line 57
    const/16 v9, 0x30

    .line 58
    .line 59
    invoke-static {v8, v1, v12, v9}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    iget-wide v8, v12, Ll2/t;->T:J

    .line 64
    .line 65
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 70
    .line 71
    .line 72
    move-result-object v9

    .line 73
    invoke-static {v12, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 78
    .line 79
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 83
    .line 84
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 85
    .line 86
    .line 87
    iget-boolean v11, v12, Ll2/t;->S:Z

    .line 88
    .line 89
    if-eqz v11, :cond_1

    .line 90
    .line 91
    invoke-virtual {v12, v10}, Ll2/t;->l(Lay0/a;)V

    .line 92
    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_1
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 96
    .line 97
    .line 98
    :goto_1
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 99
    .line 100
    invoke-static {v11, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 101
    .line 102
    .line 103
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 104
    .line 105
    invoke-static {v1, v9, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 106
    .line 107
    .line 108
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 109
    .line 110
    iget-boolean v13, v12, Ll2/t;->S:Z

    .line 111
    .line 112
    if-nez v13, :cond_2

    .line 113
    .line 114
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v13

    .line 118
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 119
    .line 120
    .line 121
    move-result-object v14

    .line 122
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v13

    .line 126
    if-nez v13, :cond_3

    .line 127
    .line 128
    :cond_2
    invoke-static {v8, v12, v8, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 129
    .line 130
    .line 131
    :cond_3
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 132
    .line 133
    invoke-static {v8, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    .line 135
    .line 136
    float-to-double v13, v3

    .line 137
    const-wide/16 v15, 0x0

    .line 138
    .line 139
    cmpl-double v7, v13, v15

    .line 140
    .line 141
    if-lez v7, :cond_4

    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_4
    const-string v7, "invalid weight; must be greater than zero"

    .line 145
    .line 146
    invoke-static {v7}, Ll1/a;->a(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    :goto_2
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 150
    .line 151
    invoke-direct {v7, v3, v4}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 152
    .line 153
    .line 154
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 155
    .line 156
    sget-object v13, Lx2/c;->p:Lx2/h;

    .line 157
    .line 158
    invoke-static {v3, v13, v12, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    iget-wide v13, v12, Ll2/t;->T:J

    .line 163
    .line 164
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 165
    .line 166
    .line 167
    move-result v13

    .line 168
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 169
    .line 170
    .line 171
    move-result-object v14

    .line 172
    invoke-static {v12, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 173
    .line 174
    .line 175
    move-result-object v7

    .line 176
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 177
    .line 178
    .line 179
    iget-boolean v15, v12, Ll2/t;->S:Z

    .line 180
    .line 181
    if-eqz v15, :cond_5

    .line 182
    .line 183
    invoke-virtual {v12, v10}, Ll2/t;->l(Lay0/a;)V

    .line 184
    .line 185
    .line 186
    goto :goto_3

    .line 187
    :cond_5
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 188
    .line 189
    .line 190
    :goto_3
    invoke-static {v11, v3, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 191
    .line 192
    .line 193
    invoke-static {v1, v14, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 194
    .line 195
    .line 196
    iget-boolean v1, v12, Ll2/t;->S:Z

    .line 197
    .line 198
    if-nez v1, :cond_6

    .line 199
    .line 200
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    if-nez v1, :cond_7

    .line 213
    .line 214
    :cond_6
    invoke-static {v13, v12, v13, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 215
    .line 216
    .line 217
    :cond_7
    invoke-static {v8, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 218
    .line 219
    .line 220
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 221
    .line 222
    .line 223
    move-result-object v1

    .line 224
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 225
    .line 226
    .line 227
    move-result-object v8

    .line 228
    iget-boolean v1, v0, Lxf0/p0;->e:Z

    .line 229
    .line 230
    if-eqz v1, :cond_8

    .line 231
    .line 232
    const v3, -0x5a728113

    .line 233
    .line 234
    .line 235
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 236
    .line 237
    .line 238
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 239
    .line 240
    .line 241
    move-result-object v3

    .line 242
    invoke-virtual {v3}, Lj91/e;->q()J

    .line 243
    .line 244
    .line 245
    move-result-wide v9

    .line 246
    :goto_4
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 247
    .line 248
    .line 249
    move-wide v10, v9

    .line 250
    goto :goto_5

    .line 251
    :cond_8
    const v3, -0x5a727cd0

    .line 252
    .line 253
    .line 254
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 255
    .line 256
    .line 257
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 258
    .line 259
    .line 260
    move-result-object v3

    .line 261
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 262
    .line 263
    .line 264
    move-result-wide v9

    .line 265
    goto :goto_4

    .line 266
    :goto_5
    const/16 v27, 0x0

    .line 267
    .line 268
    const v28, 0xfff4

    .line 269
    .line 270
    .line 271
    iget-object v7, v0, Lxf0/p0;->f:Ljava/lang/String;

    .line 272
    .line 273
    const/4 v9, 0x0

    .line 274
    move-object/from16 v25, v12

    .line 275
    .line 276
    const-wide/16 v12, 0x0

    .line 277
    .line 278
    const/4 v14, 0x0

    .line 279
    const-wide/16 v15, 0x0

    .line 280
    .line 281
    const/16 v17, 0x0

    .line 282
    .line 283
    const/16 v18, 0x0

    .line 284
    .line 285
    const-wide/16 v19, 0x0

    .line 286
    .line 287
    const/16 v21, 0x0

    .line 288
    .line 289
    const/16 v22, 0x0

    .line 290
    .line 291
    const/16 v23, 0x0

    .line 292
    .line 293
    const/16 v24, 0x0

    .line 294
    .line 295
    const/16 v26, 0x0

    .line 296
    .line 297
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 298
    .line 299
    .line 300
    move-object/from16 v12, v25

    .line 301
    .line 302
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 303
    .line 304
    .line 305
    move-result-object v3

    .line 306
    iget v3, v3, Lj91/c;->b:F

    .line 307
    .line 308
    invoke-static {v2, v3, v12, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->h(Lx2/p;FLl2/t;Ll2/t;)Lj91/c;

    .line 309
    .line 310
    .line 311
    move-result-object v3

    .line 312
    iget v3, v3, Lj91/c;->i:F

    .line 313
    .line 314
    const/4 v7, 0x0

    .line 315
    invoke-static {v2, v3, v7, v6}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 316
    .line 317
    .line 318
    move-result-object v3

    .line 319
    iget-boolean v6, v0, Lxf0/p0;->g:Z

    .line 320
    .line 321
    invoke-static {v3, v6}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 322
    .line 323
    .line 324
    move-result-object v9

    .line 325
    if-eqz v1, :cond_9

    .line 326
    .line 327
    const v3, -0x5a72490e

    .line 328
    .line 329
    .line 330
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 334
    .line 335
    .line 336
    iget-wide v6, v0, Lxf0/p0;->h:J

    .line 337
    .line 338
    :goto_6
    move-wide v10, v6

    .line 339
    goto :goto_7

    .line 340
    :cond_9
    const v3, -0x5a724430

    .line 341
    .line 342
    .line 343
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 344
    .line 345
    .line 346
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    invoke-virtual {v3}, Lj91/e;->r()J

    .line 351
    .line 352
    .line 353
    move-result-wide v6

    .line 354
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 355
    .line 356
    .line 357
    goto :goto_6

    .line 358
    :goto_7
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 359
    .line 360
    .line 361
    move-result-object v3

    .line 362
    invoke-virtual {v3}, Lj91/f;->a()Lg4/p0;

    .line 363
    .line 364
    .line 365
    move-result-object v8

    .line 366
    const/16 v27, 0x0

    .line 367
    .line 368
    const v28, 0xfff0

    .line 369
    .line 370
    .line 371
    iget-object v7, v0, Lxf0/p0;->i:Ljava/lang/String;

    .line 372
    .line 373
    move-object/from16 v25, v12

    .line 374
    .line 375
    const-wide/16 v12, 0x0

    .line 376
    .line 377
    const/4 v14, 0x0

    .line 378
    const-wide/16 v15, 0x0

    .line 379
    .line 380
    const/16 v17, 0x0

    .line 381
    .line 382
    const/16 v18, 0x0

    .line 383
    .line 384
    const-wide/16 v19, 0x0

    .line 385
    .line 386
    const/16 v21, 0x0

    .line 387
    .line 388
    const/16 v22, 0x0

    .line 389
    .line 390
    const/16 v23, 0x0

    .line 391
    .line 392
    const/16 v24, 0x0

    .line 393
    .line 394
    const/16 v26, 0x0

    .line 395
    .line 396
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 397
    .line 398
    .line 399
    move-object/from16 v12, v25

    .line 400
    .line 401
    invoke-virtual {v12, v4}, Ll2/t;->q(Z)V

    .line 402
    .line 403
    .line 404
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 405
    .line 406
    .line 407
    move-result-object v3

    .line 408
    iget v3, v3, Lj91/c;->d:F

    .line 409
    .line 410
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 411
    .line 412
    .line 413
    move-result-object v3

    .line 414
    invoke-static {v12, v3}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 415
    .line 416
    .line 417
    iget v0, v0, Lxf0/p0;->d:I

    .line 418
    .line 419
    invoke-static {v0, v5, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 420
    .line 421
    .line 422
    move-result-object v7

    .line 423
    if-eqz v1, :cond_a

    .line 424
    .line 425
    const v0, 0x66664b65

    .line 426
    .line 427
    .line 428
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 429
    .line 430
    .line 431
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 436
    .line 437
    .line 438
    move-result-wide v0

    .line 439
    :goto_8
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 440
    .line 441
    .line 442
    move-wide v10, v0

    .line 443
    goto :goto_9

    .line 444
    :cond_a
    const v0, 0x66664fe6

    .line 445
    .line 446
    .line 447
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 448
    .line 449
    .line 450
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 451
    .line 452
    .line 453
    move-result-object v0

    .line 454
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 455
    .line 456
    .line 457
    move-result-wide v0

    .line 458
    goto :goto_8

    .line 459
    :goto_9
    sget v0, Lxf0/r0;->b:F

    .line 460
    .line 461
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 462
    .line 463
    .line 464
    move-result-object v9

    .line 465
    const/16 v13, 0x1b0

    .line 466
    .line 467
    const/4 v14, 0x0

    .line 468
    const/4 v8, 0x0

    .line 469
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 470
    .line 471
    .line 472
    invoke-virtual {v12, v4}, Ll2/t;->q(Z)V

    .line 473
    .line 474
    .line 475
    goto :goto_a

    .line 476
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 477
    .line 478
    .line 479
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 480
    .line 481
    return-object v0
.end method
