.class public final synthetic Lbk/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(IILay0/a;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    iput p2, p0, Lbk/g;->d:I

    iput-object p4, p0, Lbk/g;->e:Ljava/lang/String;

    iput-boolean p5, p0, Lbk/g;->f:Z

    iput-object p3, p0, Lbk/g;->g:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILay0/a;Ljava/lang/String;Z)V
    .locals 0

    .line 2
    const/4 p1, 0x2

    iput p1, p0, Lbk/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lbk/g;->g:Lay0/a;

    iput-object p3, p0, Lbk/g;->e:Ljava/lang/String;

    iput-boolean p4, p0, Lbk/g;->f:Z

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Ljava/lang/String;Z)V
    .locals 1

    .line 3
    const/4 v0, 0x3

    iput v0, p0, Lbk/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbk/g;->g:Lay0/a;

    iput-boolean p3, p0, Lbk/g;->f:Z

    iput-object p2, p0, Lbk/g;->e:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lbk/g;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x1

    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x2

    .line 25
    if-eq v3, v6, :cond_0

    .line 26
    .line 27
    move v3, v4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    and-int/2addr v2, v4

    .line 31
    move-object v12, v1

    .line 32
    check-cast v12, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_c

    .line 39
    .line 40
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 41
    .line 42
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 43
    .line 44
    const/high16 v3, 0x3f800000    # 1.0f

    .line 45
    .line 46
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    sget v8, Luz/f0;->b:F

    .line 51
    .line 52
    const/4 v9, 0x0

    .line 53
    invoke-static {v7, v8, v9, v6}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object v13

    .line 57
    iget-object v6, v0, Lbk/g;->g:Lay0/a;

    .line 58
    .line 59
    invoke-virtual {v12, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v7

    .line 63
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v8

    .line 67
    if-nez v7, :cond_1

    .line 68
    .line 69
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 70
    .line 71
    if-ne v8, v7, :cond_2

    .line 72
    .line 73
    :cond_1
    new-instance v8, Lp61/b;

    .line 74
    .line 75
    const/16 v7, 0x10

    .line 76
    .line 77
    invoke-direct {v8, v6, v7}, Lp61/b;-><init>(Lay0/a;I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_2
    move-object/from16 v17, v8

    .line 84
    .line 85
    check-cast v17, Lay0/a;

    .line 86
    .line 87
    const/16 v18, 0xf

    .line 88
    .line 89
    const/4 v14, 0x0

    .line 90
    const/4 v15, 0x0

    .line 91
    const/16 v16, 0x0

    .line 92
    .line 93
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    sget-object v7, Lk1/j;->a:Lk1/c;

    .line 98
    .line 99
    const/16 v8, 0x30

    .line 100
    .line 101
    invoke-static {v7, v1, v12, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    iget-wide v7, v12, Ll2/t;->T:J

    .line 106
    .line 107
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 108
    .line 109
    .line 110
    move-result v7

    .line 111
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    invoke-static {v12, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 120
    .line 121
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 125
    .line 126
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 127
    .line 128
    .line 129
    iget-boolean v10, v12, Ll2/t;->S:Z

    .line 130
    .line 131
    if-eqz v10, :cond_3

    .line 132
    .line 133
    invoke-virtual {v12, v9}, Ll2/t;->l(Lay0/a;)V

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_3
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 138
    .line 139
    .line 140
    :goto_1
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 141
    .line 142
    invoke-static {v9, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 146
    .line 147
    invoke-static {v1, v8, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 148
    .line 149
    .line 150
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 151
    .line 152
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 153
    .line 154
    if-nez v8, :cond_4

    .line 155
    .line 156
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v8

    .line 160
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 161
    .line 162
    .line 163
    move-result-object v9

    .line 164
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    if-nez v8, :cond_5

    .line 169
    .line 170
    :cond_4
    invoke-static {v7, v12, v7, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 171
    .line 172
    .line 173
    :cond_5
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 174
    .line 175
    invoke-static {v1, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 176
    .line 177
    .line 178
    iget-boolean v1, v0, Lbk/g;->f:Z

    .line 179
    .line 180
    iget-object v0, v0, Lbk/g;->e:Ljava/lang/String;

    .line 181
    .line 182
    const/16 v6, 0xa

    .line 183
    .line 184
    if-eqz v1, :cond_6

    .line 185
    .line 186
    const v7, 0x394b526a

    .line 187
    .line 188
    .line 189
    invoke-virtual {v12, v7}, Ll2/t;->Y(I)V

    .line 190
    .line 191
    .line 192
    sget-object v7, Lj91/a;->a:Ll2/u2;

    .line 193
    .line 194
    invoke-virtual {v12, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v8

    .line 198
    check-cast v8, Lj91/c;

    .line 199
    .line 200
    iget v8, v8, Lj91/c;->d:F

    .line 201
    .line 202
    int-to-float v6, v6

    .line 203
    invoke-virtual {v12, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v7

    .line 207
    check-cast v7, Lj91/c;

    .line 208
    .line 209
    iget v7, v7, Lj91/c;->c:F

    .line 210
    .line 211
    invoke-static {v2, v8, v6, v7, v6}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    invoke-static {v5, v5, v12, v2}, Li91/j0;->m0(IILl2/o;Lx2/s;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 219
    .line 220
    .line 221
    goto :goto_3

    .line 222
    :cond_6
    if-nez v1, :cond_7

    .line 223
    .line 224
    if-nez v0, :cond_7

    .line 225
    .line 226
    const v7, -0xfdaa8ee

    .line 227
    .line 228
    .line 229
    invoke-virtual {v12, v7}, Ll2/t;->Y(I)V

    .line 230
    .line 231
    .line 232
    const v7, 0x7f080492

    .line 233
    .line 234
    .line 235
    invoke-static {v7, v5, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 236
    .line 237
    .line 238
    move-result-object v7

    .line 239
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 240
    .line 241
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v8

    .line 245
    check-cast v8, Lj91/e;

    .line 246
    .line 247
    invoke-virtual {v8}, Lj91/e;->s()J

    .line 248
    .line 249
    .line 250
    move-result-wide v10

    .line 251
    sget-object v8, Lj91/a;->a:Ll2/u2;

    .line 252
    .line 253
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v9

    .line 257
    check-cast v9, Lj91/c;

    .line 258
    .line 259
    iget v9, v9, Lj91/c;->d:F

    .line 260
    .line 261
    int-to-float v6, v6

    .line 262
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v8

    .line 266
    check-cast v8, Lj91/c;

    .line 267
    .line 268
    iget v8, v8, Lj91/c;->c:F

    .line 269
    .line 270
    invoke-static {v2, v9, v6, v8, v6}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    const/16 v6, 0x18

    .line 275
    .line 276
    int-to-float v6, v6

    .line 277
    invoke-static {v2, v6}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 278
    .line 279
    .line 280
    move-result-object v9

    .line 281
    const/16 v13, 0x30

    .line 282
    .line 283
    const/4 v14, 0x0

    .line 284
    const/4 v8, 0x0

    .line 285
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 286
    .line 287
    .line 288
    :goto_2
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 289
    .line 290
    .line 291
    goto :goto_3

    .line 292
    :cond_7
    const v2, -0x10446a39

    .line 293
    .line 294
    .line 295
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 296
    .line 297
    .line 298
    goto :goto_2

    .line 299
    :goto_3
    if-nez v0, :cond_8

    .line 300
    .line 301
    const v0, -0xfd186db

    .line 302
    .line 303
    .line 304
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 305
    .line 306
    .line 307
    :goto_4
    invoke-virtual {v12, v5}, Ll2/t;->q(Z)V

    .line 308
    .line 309
    .line 310
    goto/16 :goto_8

    .line 311
    .line 312
    :cond_8
    const v2, -0xfd186da

    .line 313
    .line 314
    .line 315
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 316
    .line 317
    .line 318
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 319
    .line 320
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v2

    .line 324
    check-cast v2, Lj91/f;

    .line 325
    .line 326
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 327
    .line 328
    .line 329
    move-result-object v13

    .line 330
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 331
    .line 332
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    check-cast v2, Lj91/e;

    .line 337
    .line 338
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 339
    .line 340
    .line 341
    move-result-wide v14

    .line 342
    const/16 v26, 0x0

    .line 343
    .line 344
    const v27, 0xfffffe

    .line 345
    .line 346
    .line 347
    const-wide/16 v16, 0x0

    .line 348
    .line 349
    const/16 v18, 0x0

    .line 350
    .line 351
    const/16 v19, 0x0

    .line 352
    .line 353
    const-wide/16 v20, 0x0

    .line 354
    .line 355
    const/16 v22, 0x0

    .line 356
    .line 357
    const-wide/16 v23, 0x0

    .line 358
    .line 359
    const/16 v25, 0x0

    .line 360
    .line 361
    invoke-static/range {v13 .. v27}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 362
    .line 363
    .line 364
    move-result-object v25

    .line 365
    float-to-double v6, v3

    .line 366
    const-wide/16 v8, 0x0

    .line 367
    .line 368
    cmpl-double v2, v6, v8

    .line 369
    .line 370
    if-lez v2, :cond_9

    .line 371
    .line 372
    goto :goto_5

    .line 373
    :cond_9
    const-string v2, "invalid weight; must be greater than zero"

    .line 374
    .line 375
    invoke-static {v2}, Ll1/a;->a(Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    :goto_5
    new-instance v2, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 379
    .line 380
    invoke-direct {v2, v3, v4}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 381
    .line 382
    .line 383
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 384
    .line 385
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v6

    .line 389
    check-cast v6, Lj91/c;

    .line 390
    .line 391
    iget v6, v6, Lj91/c;->d:F

    .line 392
    .line 393
    new-instance v7, Lt4/f;

    .line 394
    .line 395
    invoke-direct {v7, v6}, Lt4/f;-><init>(F)V

    .line 396
    .line 397
    .line 398
    if-nez v1, :cond_a

    .line 399
    .line 400
    goto :goto_6

    .line 401
    :cond_a
    const/4 v7, 0x0

    .line 402
    :goto_6
    if-eqz v7, :cond_b

    .line 403
    .line 404
    iget v1, v7, Lt4/f;->d:F

    .line 405
    .line 406
    goto :goto_7

    .line 407
    :cond_b
    int-to-float v1, v5

    .line 408
    :goto_7
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v6

    .line 412
    check-cast v6, Lj91/c;

    .line 413
    .line 414
    iget v6, v6, Lj91/c;->c:F

    .line 415
    .line 416
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    move-result-object v7

    .line 420
    check-cast v7, Lj91/c;

    .line 421
    .line 422
    iget v7, v7, Lj91/c;->c:F

    .line 423
    .line 424
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    move-result-object v3

    .line 428
    check-cast v3, Lj91/c;

    .line 429
    .line 430
    iget v3, v3, Lj91/c;->d:F

    .line 431
    .line 432
    invoke-static {v2, v1, v6, v3, v7}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 433
    .line 434
    .line 435
    move-result-object v8

    .line 436
    const/16 v28, 0x6180

    .line 437
    .line 438
    const v29, 0x1affc

    .line 439
    .line 440
    .line 441
    const-wide/16 v9, 0x0

    .line 442
    .line 443
    move-object/from16 v26, v12

    .line 444
    .line 445
    const-wide/16 v11, 0x0

    .line 446
    .line 447
    const/4 v13, 0x0

    .line 448
    const-wide/16 v14, 0x0

    .line 449
    .line 450
    const/16 v16, 0x0

    .line 451
    .line 452
    const/16 v17, 0x0

    .line 453
    .line 454
    const-wide/16 v18, 0x0

    .line 455
    .line 456
    const/16 v20, 0x2

    .line 457
    .line 458
    const/16 v21, 0x0

    .line 459
    .line 460
    const/16 v22, 0x1

    .line 461
    .line 462
    const/16 v23, 0x0

    .line 463
    .line 464
    const/16 v24, 0x0

    .line 465
    .line 466
    const/16 v27, 0x0

    .line 467
    .line 468
    move-object v7, v0

    .line 469
    invoke-static/range {v7 .. v29}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 470
    .line 471
    .line 472
    move-object/from16 v12, v26

    .line 473
    .line 474
    goto/16 :goto_4

    .line 475
    .line 476
    :goto_8
    invoke-virtual {v12, v4}, Ll2/t;->q(Z)V

    .line 477
    .line 478
    .line 479
    goto :goto_9

    .line 480
    :cond_c
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 481
    .line 482
    .line 483
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 484
    .line 485
    return-object v0

    .line 486
    :pswitch_0
    move-object/from16 v1, p1

    .line 487
    .line 488
    check-cast v1, Ll2/o;

    .line 489
    .line 490
    move-object/from16 v2, p2

    .line 491
    .line 492
    check-cast v2, Ljava/lang/Integer;

    .line 493
    .line 494
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 495
    .line 496
    .line 497
    const/4 v2, 0x1

    .line 498
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 499
    .line 500
    .line 501
    move-result v2

    .line 502
    iget-object v3, v0, Lbk/g;->g:Lay0/a;

    .line 503
    .line 504
    iget-object v4, v0, Lbk/g;->e:Ljava/lang/String;

    .line 505
    .line 506
    iget-boolean v0, v0, Lbk/g;->f:Z

    .line 507
    .line 508
    invoke-static {v2, v3, v4, v1, v0}, Ls60/j;->a(ILay0/a;Ljava/lang/String;Ll2/o;Z)V

    .line 509
    .line 510
    .line 511
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 512
    .line 513
    return-object v0

    .line 514
    :pswitch_1
    move-object/from16 v1, p1

    .line 515
    .line 516
    check-cast v1, Ll2/o;

    .line 517
    .line 518
    move-object/from16 v2, p2

    .line 519
    .line 520
    check-cast v2, Ljava/lang/Integer;

    .line 521
    .line 522
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 523
    .line 524
    .line 525
    const/4 v2, 0x1

    .line 526
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 527
    .line 528
    .line 529
    move-result v2

    .line 530
    iget-object v3, v0, Lbk/g;->g:Lay0/a;

    .line 531
    .line 532
    iget-object v4, v0, Lbk/g;->e:Ljava/lang/String;

    .line 533
    .line 534
    iget-boolean v0, v0, Lbk/g;->f:Z

    .line 535
    .line 536
    invoke-static {v2, v3, v4, v1, v0}, Li40/l1;->e(ILay0/a;Ljava/lang/String;Ll2/o;Z)V

    .line 537
    .line 538
    .line 539
    goto :goto_a

    .line 540
    :pswitch_2
    move-object/from16 v1, p1

    .line 541
    .line 542
    check-cast v1, Ll2/o;

    .line 543
    .line 544
    move-object/from16 v2, p2

    .line 545
    .line 546
    check-cast v2, Ljava/lang/Integer;

    .line 547
    .line 548
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 549
    .line 550
    .line 551
    const/16 v2, 0x37

    .line 552
    .line 553
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 554
    .line 555
    .line 556
    move-result v2

    .line 557
    iget-object v3, v0, Lbk/g;->g:Lay0/a;

    .line 558
    .line 559
    iget-object v4, v0, Lbk/g;->e:Ljava/lang/String;

    .line 560
    .line 561
    iget-boolean v0, v0, Lbk/g;->f:Z

    .line 562
    .line 563
    invoke-static {v2, v3, v4, v1, v0}, Lbk/a;->c(ILay0/a;Ljava/lang/String;Ll2/o;Z)V

    .line 564
    .line 565
    .line 566
    goto :goto_a

    .line 567
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
