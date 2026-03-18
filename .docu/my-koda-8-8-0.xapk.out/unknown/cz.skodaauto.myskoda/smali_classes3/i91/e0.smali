.class public final synthetic Li91/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/Integer;

.field public final synthetic e:Ljava/lang/Integer;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:J

.field public final synthetic l:Z


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Lay0/a;ZLjava/lang/String;Ljava/lang/String;JZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/e0;->d:Ljava/lang/Integer;

    .line 5
    .line 6
    iput-object p2, p0, Li91/e0;->e:Ljava/lang/Integer;

    .line 7
    .line 8
    iput-object p3, p0, Li91/e0;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Li91/e0;->g:Lay0/a;

    .line 11
    .line 12
    iput-boolean p5, p0, Li91/e0;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Li91/e0;->i:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Li91/e0;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput-wide p8, p0, Li91/e0;->k:J

    .line 19
    .line 20
    iput-boolean p10, p0, Li91/e0;->l:Z

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

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
    if-eqz v1, :cond_d

    .line 34
    .line 35
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 36
    .line 37
    const/4 v2, 0x4

    .line 38
    int-to-float v2, v2

    .line 39
    invoke-static {v2}, Lk1/j;->g(F)Lk1/h;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    iget-object v4, v0, Li91/e0;->g:Lay0/a;

    .line 44
    .line 45
    iget-boolean v14, v0, Li91/e0;->h:Z

    .line 46
    .line 47
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 48
    .line 49
    if-eqz v4, :cond_1

    .line 50
    .line 51
    const/16 v16, 0x0

    .line 52
    .line 53
    const/16 v18, 0xe

    .line 54
    .line 55
    const/4 v15, 0x0

    .line 56
    move-object/from16 v17, v4

    .line 57
    .line 58
    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    move-object v15, v13

    .line 63
    move-object v13, v4

    .line 64
    :goto_1
    move/from16 v29, v14

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_1
    move-object v15, v13

    .line 68
    goto :goto_1

    .line 69
    :goto_2
    iget-object v4, v0, Li91/e0;->d:Ljava/lang/Integer;

    .line 70
    .line 71
    const/16 v7, 0xc

    .line 72
    .line 73
    const/16 v8, 0x10

    .line 74
    .line 75
    if-nez v4, :cond_2

    .line 76
    .line 77
    int-to-float v9, v8

    .line 78
    goto :goto_3

    .line 79
    :cond_2
    int-to-float v9, v7

    .line 80
    :goto_3
    iget-object v10, v0, Li91/e0;->e:Ljava/lang/Integer;

    .line 81
    .line 82
    iget-object v11, v0, Li91/e0;->f:Ljava/lang/String;

    .line 83
    .line 84
    if-nez v10, :cond_3

    .line 85
    .line 86
    if-nez v11, :cond_3

    .line 87
    .line 88
    int-to-float v7, v8

    .line 89
    goto :goto_4

    .line 90
    :cond_3
    int-to-float v7, v7

    .line 91
    :goto_4
    invoke-static {v13, v9, v2, v7, v2}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    const/16 v8, 0x36

    .line 96
    .line 97
    invoke-static {v3, v1, v12, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    iget-wide v8, v12, Ll2/t;->T:J

    .line 102
    .line 103
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    invoke-static {v12, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 116
    .line 117
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 121
    .line 122
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 123
    .line 124
    .line 125
    iget-boolean v13, v12, Ll2/t;->S:Z

    .line 126
    .line 127
    if-eqz v13, :cond_4

    .line 128
    .line 129
    invoke-virtual {v12, v9}, Ll2/t;->l(Lay0/a;)V

    .line 130
    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_4
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 134
    .line 135
    .line 136
    :goto_5
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 137
    .line 138
    invoke-static {v9, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 139
    .line 140
    .line 141
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 142
    .line 143
    invoke-static {v1, v8, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 147
    .line 148
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 149
    .line 150
    if-nez v8, :cond_5

    .line 151
    .line 152
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v9

    .line 160
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    if-nez v8, :cond_6

    .line 165
    .line 166
    :cond_5
    invoke-static {v3, v12, v3, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 167
    .line 168
    .line 169
    :cond_6
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 170
    .line 171
    invoke-static {v1, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 172
    .line 173
    .line 174
    const/4 v1, 0x0

    .line 175
    iget-object v3, v0, Li91/e0;->i:Ljava/lang/String;

    .line 176
    .line 177
    move-object v7, v10

    .line 178
    move-object v8, v11

    .line 179
    iget-wide v10, v0, Li91/e0;->k:J

    .line 180
    .line 181
    const/16 v9, 0x14

    .line 182
    .line 183
    if-nez v4, :cond_7

    .line 184
    .line 185
    const v4, 0x11f5600b

    .line 186
    .line 187
    .line 188
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 192
    .line 193
    .line 194
    move-object v4, v7

    .line 195
    move-object/from16 v30, v8

    .line 196
    .line 197
    move v5, v9

    .line 198
    goto :goto_6

    .line 199
    :cond_7
    const v13, 0x11f5600c

    .line 200
    .line 201
    .line 202
    invoke-virtual {v12, v13}, Ll2/t;->Y(I)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 206
    .line 207
    .line 208
    move-result v4

    .line 209
    const-string v13, "chip_leading_icon"

    .line 210
    .line 211
    invoke-static {v1, v3, v13}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v13

    .line 215
    invoke-static {v4, v6, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 216
    .line 217
    .line 218
    move-result-object v4

    .line 219
    int-to-float v14, v9

    .line 220
    invoke-static {v15, v14}, Landroidx/compose/foundation/layout/d;->h(Lx2/s;F)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v14

    .line 224
    invoke-static {v14, v13}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 225
    .line 226
    .line 227
    move-result-object v13

    .line 228
    move v14, v9

    .line 229
    move-object v9, v13

    .line 230
    const/16 v13, 0x30

    .line 231
    .line 232
    move/from16 v16, v14

    .line 233
    .line 234
    const/4 v14, 0x0

    .line 235
    move-object/from16 v17, v8

    .line 236
    .line 237
    const/4 v8, 0x0

    .line 238
    move-object v5, v7

    .line 239
    move-object v7, v4

    .line 240
    move-object v4, v5

    .line 241
    move/from16 v5, v16

    .line 242
    .line 243
    move-object/from16 v30, v17

    .line 244
    .line 245
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 249
    .line 250
    .line 251
    :goto_6
    const-string v7, "chip_text"

    .line 252
    .line 253
    invoke-static {v1, v3, v7}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v7

    .line 257
    sget-object v8, Lj91/j;->a:Ll2/u2;

    .line 258
    .line 259
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v8

    .line 263
    check-cast v8, Lj91/f;

    .line 264
    .line 265
    invoke-virtual {v8}, Lj91/f;->b()Lg4/p0;

    .line 266
    .line 267
    .line 268
    move-result-object v8

    .line 269
    if-eqz v30, :cond_8

    .line 270
    .line 271
    :goto_7
    move/from16 v18, v2

    .line 272
    .line 273
    goto :goto_8

    .line 274
    :cond_8
    int-to-float v2, v6

    .line 275
    goto :goto_7

    .line 276
    :goto_8
    const/16 v19, 0x0

    .line 277
    .line 278
    const/16 v20, 0xb

    .line 279
    .line 280
    const/16 v16, 0x0

    .line 281
    .line 282
    const/16 v17, 0x0

    .line 283
    .line 284
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 285
    .line 286
    .line 287
    move-result-object v2

    .line 288
    invoke-static {v2, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 289
    .line 290
    .line 291
    move-result-object v9

    .line 292
    const/16 v27, 0x6180

    .line 293
    .line 294
    const v28, 0xaff0

    .line 295
    .line 296
    .line 297
    iget-object v7, v0, Li91/e0;->j:Ljava/lang/String;

    .line 298
    .line 299
    move-object/from16 v25, v12

    .line 300
    .line 301
    const-wide/16 v12, 0x0

    .line 302
    .line 303
    const/4 v14, 0x0

    .line 304
    move-object v2, v15

    .line 305
    const-wide/16 v15, 0x0

    .line 306
    .line 307
    const/16 v17, 0x0

    .line 308
    .line 309
    const/16 v18, 0x0

    .line 310
    .line 311
    const-wide/16 v19, 0x0

    .line 312
    .line 313
    const/16 v21, 0x2

    .line 314
    .line 315
    const/16 v22, 0x0

    .line 316
    .line 317
    const/16 v23, 0x1

    .line 318
    .line 319
    const/16 v24, 0x0

    .line 320
    .line 321
    const/16 v26, 0x0

    .line 322
    .line 323
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 324
    .line 325
    .line 326
    move-wide v13, v10

    .line 327
    move-object/from16 v12, v25

    .line 328
    .line 329
    if-nez v30, :cond_9

    .line 330
    .line 331
    const v0, 0x1206a35c

    .line 332
    .line 333
    .line 334
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 335
    .line 336
    .line 337
    :goto_9
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 338
    .line 339
    .line 340
    goto :goto_d

    .line 341
    :cond_9
    const v7, 0x1206a35d

    .line 342
    .line 343
    .line 344
    invoke-virtual {v12, v7}, Ll2/t;->Y(I)V

    .line 345
    .line 346
    .line 347
    iget-boolean v0, v0, Li91/e0;->l:Z

    .line 348
    .line 349
    if-eqz v0, :cond_b

    .line 350
    .line 351
    const v0, 0x5d4a0da8

    .line 352
    .line 353
    .line 354
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 355
    .line 356
    .line 357
    const-string v0, "chip_badge"

    .line 358
    .line 359
    invoke-static {v1, v3, v0}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object v10

    .line 363
    if-eqz v29, :cond_a

    .line 364
    .line 365
    sget-object v0, Li91/f1;->d:Li91/f1;

    .line 366
    .line 367
    :goto_a
    move-object v8, v0

    .line 368
    goto :goto_b

    .line 369
    :cond_a
    sget-object v0, Li91/f1;->e:Li91/f1;

    .line 370
    .line 371
    goto :goto_a

    .line 372
    :goto_b
    const/4 v9, 0x0

    .line 373
    move-object/from16 v25, v12

    .line 374
    .line 375
    const/4 v12, 0x0

    .line 376
    move-object/from16 v11, v25

    .line 377
    .line 378
    move-object/from16 v7, v30

    .line 379
    .line 380
    invoke-static/range {v7 .. v12}, Li91/j0;->g(Ljava/lang/String;Li91/f1;Lx2/s;Ljava/lang/String;Ll2/o;I)V

    .line 381
    .line 382
    .line 383
    move-object v12, v11

    .line 384
    :goto_c
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 385
    .line 386
    .line 387
    goto :goto_9

    .line 388
    :cond_b
    const v0, 0x5ce0ba8f

    .line 389
    .line 390
    .line 391
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 392
    .line 393
    .line 394
    goto :goto_c

    .line 395
    :goto_d
    if-nez v4, :cond_c

    .line 396
    .line 397
    const v0, 0x120f42c7

    .line 398
    .line 399
    .line 400
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 401
    .line 402
    .line 403
    :goto_e
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 404
    .line 405
    .line 406
    const/4 v0, 0x1

    .line 407
    goto :goto_f

    .line 408
    :cond_c
    const v0, 0x120f42c8

    .line 409
    .line 410
    .line 411
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 415
    .line 416
    .line 417
    move-result v0

    .line 418
    const-string v4, "chip_trailing_icon"

    .line 419
    .line 420
    invoke-static {v1, v3, v4}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object v1

    .line 424
    invoke-static {v0, v6, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 425
    .line 426
    .line 427
    move-result-object v7

    .line 428
    int-to-float v0, v5

    .line 429
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->h(Lx2/s;F)Lx2/s;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 434
    .line 435
    .line 436
    move-result-object v9

    .line 437
    move-wide v10, v13

    .line 438
    const/16 v13, 0x30

    .line 439
    .line 440
    const/4 v14, 0x0

    .line 441
    const/4 v8, 0x0

    .line 442
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 443
    .line 444
    .line 445
    goto :goto_e

    .line 446
    :goto_f
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 447
    .line 448
    .line 449
    goto :goto_10

    .line 450
    :cond_d
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 451
    .line 452
    .line 453
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 454
    .line 455
    return-object v0
.end method
