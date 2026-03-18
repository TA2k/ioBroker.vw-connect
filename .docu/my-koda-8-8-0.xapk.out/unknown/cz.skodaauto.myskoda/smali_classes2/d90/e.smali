.class public final synthetic Ld90/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lc90/h;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lc90/h;I)V
    .locals 0

    .line 1
    iput p3, p0, Ld90/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld90/e;->e:Lay0/a;

    .line 4
    .line 5
    iput-object p2, p0, Ld90/e;->f:Lc90/h;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld90/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/q;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$GradientBox"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v1, v3, 0x11

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    const/4 v5, 0x0

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v6

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v5

    .line 40
    :goto_0
    and-int/2addr v3, v6

    .line 41
    move-object v12, v2

    .line 42
    check-cast v12, Ll2/t;

    .line 43
    .line 44
    invoke-virtual {v12, v3, v1}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_4

    .line 49
    .line 50
    const v1, 0x7f1212bb

    .line 51
    .line 52
    .line 53
    invoke-static {v12, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v11

    .line 57
    iget-object v1, v0, Ld90/e;->f:Lc90/h;

    .line 58
    .line 59
    iget-boolean v2, v1, Lc90/h;->b:Z

    .line 60
    .line 61
    if-eqz v2, :cond_1

    .line 62
    .line 63
    iget-object v2, v1, Lc90/h;->f:Ljava/time/LocalTime;

    .line 64
    .line 65
    if-eqz v2, :cond_2

    .line 66
    .line 67
    :cond_1
    iget-boolean v2, v1, Lc90/h;->a:Z

    .line 68
    .line 69
    if-eqz v2, :cond_3

    .line 70
    .line 71
    iget-object v1, v1, Lc90/h;->e:Ljava/time/LocalDate;

    .line 72
    .line 73
    if-eqz v1, :cond_2

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    move v14, v5

    .line 77
    goto :goto_2

    .line 78
    :cond_3
    :goto_1
    move v14, v6

    .line 79
    :goto_2
    const/4 v7, 0x0

    .line 80
    const/16 v8, 0x2c

    .line 81
    .line 82
    iget-object v9, v0, Ld90/e;->e:Lay0/a;

    .line 83
    .line 84
    const/4 v10, 0x0

    .line 85
    const/4 v13, 0x0

    .line 86
    const/4 v15, 0x0

    .line 87
    invoke-static/range {v7 .. v15}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 88
    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_4
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 92
    .line 93
    .line 94
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object v0

    .line 97
    :pswitch_0
    move-object/from16 v1, p1

    .line 98
    .line 99
    check-cast v1, Lk1/z0;

    .line 100
    .line 101
    move-object/from16 v2, p2

    .line 102
    .line 103
    check-cast v2, Ll2/o;

    .line 104
    .line 105
    move-object/from16 v3, p3

    .line 106
    .line 107
    check-cast v3, Ljava/lang/Integer;

    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    const-string v4, "paddingValues"

    .line 114
    .line 115
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    and-int/lit8 v4, v3, 0x6

    .line 119
    .line 120
    if-nez v4, :cond_6

    .line 121
    .line 122
    move-object v4, v2

    .line 123
    check-cast v4, Ll2/t;

    .line 124
    .line 125
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v4

    .line 129
    if-eqz v4, :cond_5

    .line 130
    .line 131
    const/4 v4, 0x4

    .line 132
    goto :goto_4

    .line 133
    :cond_5
    const/4 v4, 0x2

    .line 134
    :goto_4
    or-int/2addr v3, v4

    .line 135
    :cond_6
    and-int/lit8 v4, v3, 0x13

    .line 136
    .line 137
    const/16 v5, 0x12

    .line 138
    .line 139
    const/4 v6, 0x1

    .line 140
    const/4 v7, 0x0

    .line 141
    if-eq v4, v5, :cond_7

    .line 142
    .line 143
    move v4, v6

    .line 144
    goto :goto_5

    .line 145
    :cond_7
    move v4, v7

    .line 146
    :goto_5
    and-int/2addr v3, v6

    .line 147
    move-object v12, v2

    .line 148
    check-cast v12, Ll2/t;

    .line 149
    .line 150
    invoke-virtual {v12, v3, v4}, Ll2/t;->O(IZ)Z

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    if-eqz v2, :cond_b

    .line 155
    .line 156
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 157
    .line 158
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 159
    .line 160
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    check-cast v3, Lj91/e;

    .line 165
    .line 166
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 167
    .line 168
    .line 169
    move-result-wide v3

    .line 170
    sget-object v5, Le3/j0;->a:Le3/i0;

    .line 171
    .line 172
    invoke-static {v2, v3, v4, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    invoke-static {v7, v6, v12}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 177
    .line 178
    .line 179
    move-result-object v3

    .line 180
    const/16 v4, 0xe

    .line 181
    .line 182
    invoke-static {v2, v3, v4}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 187
    .line 188
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    check-cast v4, Lj91/c;

    .line 193
    .line 194
    iget v4, v4, Lj91/c;->d:F

    .line 195
    .line 196
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    check-cast v5, Lj91/c;

    .line 201
    .line 202
    iget v5, v5, Lj91/c;->d:F

    .line 203
    .line 204
    invoke-interface {v1}, Lk1/z0;->d()F

    .line 205
    .line 206
    .line 207
    move-result v8

    .line 208
    invoke-interface {v1}, Lk1/z0;->c()F

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v9

    .line 216
    check-cast v9, Lj91/c;

    .line 217
    .line 218
    iget v9, v9, Lj91/c;->e:F

    .line 219
    .line 220
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v10

    .line 224
    check-cast v10, Lj91/c;

    .line 225
    .line 226
    iget v10, v10, Lj91/c;->e:F

    .line 227
    .line 228
    sub-float/2addr v9, v10

    .line 229
    sub-float/2addr v1, v9

    .line 230
    invoke-static {v2, v4, v8, v5, v1}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 235
    .line 236
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 237
    .line 238
    invoke-static {v2, v4, v12, v7}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 239
    .line 240
    .line 241
    move-result-object v2

    .line 242
    iget-wide v4, v12, Ll2/t;->T:J

    .line 243
    .line 244
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 249
    .line 250
    .line 251
    move-result-object v5

    .line 252
    invoke-static {v12, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 257
    .line 258
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 259
    .line 260
    .line 261
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 262
    .line 263
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 264
    .line 265
    .line 266
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 267
    .line 268
    if-eqz v8, :cond_8

    .line 269
    .line 270
    invoke-virtual {v12, v7}, Ll2/t;->l(Lay0/a;)V

    .line 271
    .line 272
    .line 273
    goto :goto_6

    .line 274
    :cond_8
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 275
    .line 276
    .line 277
    :goto_6
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 278
    .line 279
    invoke-static {v7, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 280
    .line 281
    .line 282
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 283
    .line 284
    invoke-static {v2, v5, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 285
    .line 286
    .line 287
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 288
    .line 289
    iget-boolean v5, v12, Ll2/t;->S:Z

    .line 290
    .line 291
    if-nez v5, :cond_9

    .line 292
    .line 293
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v5

    .line 297
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 298
    .line 299
    .line 300
    move-result-object v7

    .line 301
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result v5

    .line 305
    if-nez v5, :cond_a

    .line 306
    .line 307
    :cond_9
    invoke-static {v4, v12, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 308
    .line 309
    .line 310
    :cond_a
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 311
    .line 312
    invoke-static {v2, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    check-cast v1, Lj91/c;

    .line 320
    .line 321
    iget v1, v1, Lj91/c;->e:F

    .line 322
    .line 323
    const v2, 0x7f1212b8

    .line 324
    .line 325
    .line 326
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 327
    .line 328
    invoke-static {v4, v1, v12, v2, v12}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 329
    .line 330
    .line 331
    move-result-object v8

    .line 332
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 333
    .line 334
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    check-cast v1, Lj91/f;

    .line 339
    .line 340
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 341
    .line 342
    .line 343
    move-result-object v9

    .line 344
    new-instance v1, Lr4/k;

    .line 345
    .line 346
    const/4 v2, 0x5

    .line 347
    invoke-direct {v1, v2}, Lr4/k;-><init>(I)V

    .line 348
    .line 349
    .line 350
    const/16 v28, 0x0

    .line 351
    .line 352
    const v29, 0xfbfc

    .line 353
    .line 354
    .line 355
    const/4 v10, 0x0

    .line 356
    move-object/from16 v26, v12

    .line 357
    .line 358
    const-wide/16 v11, 0x0

    .line 359
    .line 360
    const-wide/16 v13, 0x0

    .line 361
    .line 362
    const/4 v15, 0x0

    .line 363
    const-wide/16 v16, 0x0

    .line 364
    .line 365
    const/16 v18, 0x0

    .line 366
    .line 367
    const-wide/16 v20, 0x0

    .line 368
    .line 369
    const/16 v22, 0x0

    .line 370
    .line 371
    const/16 v23, 0x0

    .line 372
    .line 373
    const/16 v24, 0x0

    .line 374
    .line 375
    const/16 v25, 0x0

    .line 376
    .line 377
    const/16 v27, 0x0

    .line 378
    .line 379
    move-object/from16 v19, v1

    .line 380
    .line 381
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 382
    .line 383
    .line 384
    move-object/from16 v12, v26

    .line 385
    .line 386
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v1

    .line 390
    check-cast v1, Lj91/c;

    .line 391
    .line 392
    iget v1, v1, Lj91/c;->e:F

    .line 393
    .line 394
    const/high16 v2, 0x3f800000    # 1.0f

    .line 395
    .line 396
    invoke-static {v4, v1, v12, v4, v2}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 397
    .line 398
    .line 399
    move-result-object v8

    .line 400
    new-instance v1, La71/a0;

    .line 401
    .line 402
    const/16 v2, 0x10

    .line 403
    .line 404
    iget-object v3, v0, Ld90/e;->f:Lc90/h;

    .line 405
    .line 406
    invoke-direct {v1, v3, v2}, La71/a0;-><init>(Ljava/lang/Object;I)V

    .line 407
    .line 408
    .line 409
    const v2, 0x504dff3c

    .line 410
    .line 411
    .line 412
    invoke-static {v2, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 413
    .line 414
    .line 415
    move-result-object v11

    .line 416
    const/16 v13, 0xc06

    .line 417
    .line 418
    const/4 v14, 0x4

    .line 419
    iget-object v9, v0, Ld90/e;->e:Lay0/a;

    .line 420
    .line 421
    const/4 v10, 0x0

    .line 422
    invoke-static/range {v8 .. v14}, Li91/d0;->a(Lx2/s;Lay0/a;ZLay0/n;Ll2/o;II)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 426
    .line 427
    .line 428
    goto :goto_7

    .line 429
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 430
    .line 431
    .line 432
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 433
    .line 434
    return-object v0

    .line 435
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
