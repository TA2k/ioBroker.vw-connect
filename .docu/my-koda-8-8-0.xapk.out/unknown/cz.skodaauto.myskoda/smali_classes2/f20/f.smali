.class public final synthetic Lf20/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lf20/f;->d:I

    iput-object p3, p0, Lf20/f;->e:Ljava/lang/Object;

    iput-object p4, p0, Lf20/f;->f:Ljava/lang/Object;

    iput-object p5, p0, Lf20/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lt2/b;Ljava/lang/String;)V
    .locals 1

    .line 2
    const/4 v0, 0x5

    iput v0, p0, Lf20/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf20/f;->f:Ljava/lang/Object;

    iput-object p2, p0, Lf20/f;->e:Ljava/lang/Object;

    iput-object p3, p0, Lf20/f;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Lay0/a;II)V
    .locals 0

    .line 3
    iput p5, p0, Lf20/f;->d:I

    iput-object p1, p0, Lf20/f;->e:Ljava/lang/Object;

    iput-object p2, p0, Lf20/f;->g:Ljava/lang/Object;

    iput-object p3, p0, Lf20/f;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 4
    iput p4, p0, Lf20/f;->d:I

    iput-object p1, p0, Lf20/f;->e:Ljava/lang/Object;

    iput-object p2, p0, Lf20/f;->f:Ljava/lang/Object;

    iput-object p3, p0, Lf20/f;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 59

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf20/f;->d:I

    .line 4
    .line 5
    const/16 v2, 0x30

    .line 6
    .line 7
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 8
    .line 9
    const/4 v5, 0x6

    .line 10
    const/4 v6, 0x2

    .line 11
    const/4 v7, 0x0

    .line 12
    const/4 v8, 0x1

    .line 13
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    iget-object v10, v0, Lf20/f;->g:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v11, v0, Lf20/f;->f:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v0, v0, Lf20/f;->e:Ljava/lang/Object;

    .line 20
    .line 21
    packed-switch v1, :pswitch_data_0

    .line 22
    .line 23
    .line 24
    check-cast v0, Lt2/b;

    .line 25
    .line 26
    check-cast v11, Lay0/o;

    .line 27
    .line 28
    check-cast v10, Li91/k2;

    .line 29
    .line 30
    move-object/from16 v1, p1

    .line 31
    .line 32
    check-cast v1, Ll2/o;

    .line 33
    .line 34
    move-object/from16 v2, p2

    .line 35
    .line 36
    check-cast v2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    and-int/lit8 v3, v2, 0x3

    .line 43
    .line 44
    if-eq v3, v6, :cond_0

    .line 45
    .line 46
    move v3, v8

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move v3, v7

    .line 49
    :goto_0
    and-int/2addr v2, v8

    .line 50
    check-cast v1, Ll2/t;

    .line 51
    .line 52
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_2

    .line 57
    .line 58
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-virtual {v0, v1, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    if-nez v11, :cond_1

    .line 66
    .line 67
    const v0, -0xbb5dcfb

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 71
    .line 72
    .line 73
    :goto_1
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_1
    const v0, 0x10236c7c

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 81
    .line 82
    .line 83
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-interface {v11, v10, v1, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 92
    .line 93
    .line 94
    :goto_2
    return-object v9

    .line 95
    :pswitch_0
    check-cast v0, Ljava/lang/String;

    .line 96
    .line 97
    check-cast v11, Li91/e1;

    .line 98
    .line 99
    check-cast v10, Lx2/s;

    .line 100
    .line 101
    move-object/from16 v1, p1

    .line 102
    .line 103
    check-cast v1, Ll2/o;

    .line 104
    .line 105
    move-object/from16 v2, p2

    .line 106
    .line 107
    check-cast v2, Ljava/lang/Integer;

    .line 108
    .line 109
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    invoke-static {v8}, Ll2/b;->x(I)I

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    invoke-static {v0, v11, v10, v1, v2}, Li91/j0;->f(Ljava/lang/String;Li91/e1;Lx2/s;Ll2/o;I)V

    .line 117
    .line 118
    .line 119
    return-object v9

    .line 120
    :pswitch_1
    check-cast v0, Lay0/k;

    .line 121
    .line 122
    check-cast v11, Lv31/c;

    .line 123
    .line 124
    check-cast v10, Lay0/k;

    .line 125
    .line 126
    move-object/from16 v1, p1

    .line 127
    .line 128
    check-cast v1, Ll2/o;

    .line 129
    .line 130
    move-object/from16 v2, p2

    .line 131
    .line 132
    check-cast v2, Ljava/lang/Integer;

    .line 133
    .line 134
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    invoke-static {v8}, Ll2/b;->x(I)I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    invoke-static {v0, v11, v10, v1, v2}, Llp/v9;->a(Lay0/k;Lv31/c;Lay0/k;Ll2/o;I)V

    .line 142
    .line 143
    .line 144
    return-object v9

    .line 145
    :pswitch_2
    check-cast v0, Lh40/z;

    .line 146
    .line 147
    check-cast v11, Lay0/k;

    .line 148
    .line 149
    check-cast v10, Lay0/k;

    .line 150
    .line 151
    move-object/from16 v1, p1

    .line 152
    .line 153
    check-cast v1, Ll2/o;

    .line 154
    .line 155
    move-object/from16 v5, p2

    .line 156
    .line 157
    check-cast v5, Ljava/lang/Integer;

    .line 158
    .line 159
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    and-int/lit8 v12, v5, 0x3

    .line 164
    .line 165
    if-eq v12, v6, :cond_3

    .line 166
    .line 167
    move v12, v8

    .line 168
    goto :goto_3

    .line 169
    :cond_3
    move v12, v7

    .line 170
    :goto_3
    and-int/2addr v5, v8

    .line 171
    check-cast v1, Ll2/t;

    .line 172
    .line 173
    invoke-virtual {v1, v5, v12}, Ll2/t;->O(IZ)Z

    .line 174
    .line 175
    .line 176
    move-result v5

    .line 177
    if-eqz v5, :cond_14

    .line 178
    .line 179
    invoke-static {v1}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    invoke-virtual {v5}, Lj91/e;->h()J

    .line 184
    .line 185
    .line 186
    move-result-wide v12

    .line 187
    sget-object v5, Le3/j0;->a:Le3/i0;

    .line 188
    .line 189
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 190
    .line 191
    invoke-static {v14, v12, v13, v5}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 192
    .line 193
    .line 194
    move-result-object v5

    .line 195
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 196
    .line 197
    .line 198
    move-result-object v12

    .line 199
    iget v12, v12, Lj91/c;->j:F

    .line 200
    .line 201
    invoke-static {v5, v12}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 202
    .line 203
    .line 204
    move-result-object v5

    .line 205
    sget-object v12, Lx2/c;->n:Lx2/i;

    .line 206
    .line 207
    sget-object v13, Lk1/j;->a:Lk1/c;

    .line 208
    .line 209
    invoke-static {v13, v12, v1, v2}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 210
    .line 211
    .line 212
    move-result-object v2

    .line 213
    iget-wide v6, v1, Ll2/t;->T:J

    .line 214
    .line 215
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 216
    .line 217
    .line 218
    move-result v6

    .line 219
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 220
    .line 221
    .line 222
    move-result-object v7

    .line 223
    invoke-static {v1, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v5

    .line 227
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 228
    .line 229
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 230
    .line 231
    .line 232
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 233
    .line 234
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 235
    .line 236
    .line 237
    iget-boolean v12, v1, Ll2/t;->S:Z

    .line 238
    .line 239
    if-eqz v12, :cond_4

    .line 240
    .line 241
    invoke-virtual {v1, v15}, Ll2/t;->l(Lay0/a;)V

    .line 242
    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_4
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 246
    .line 247
    .line 248
    :goto_4
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 249
    .line 250
    invoke-static {v12, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 251
    .line 252
    .line 253
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 254
    .line 255
    invoke-static {v2, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 256
    .line 257
    .line 258
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 259
    .line 260
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 261
    .line 262
    if-nez v8, :cond_5

    .line 263
    .line 264
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v8

    .line 268
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 269
    .line 270
    .line 271
    move-result-object v4

    .line 272
    invoke-static {v8, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-result v4

    .line 276
    if-nez v4, :cond_6

    .line 277
    .line 278
    :cond_5
    invoke-static {v6, v1, v6, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 279
    .line 280
    .line 281
    :cond_6
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 282
    .line 283
    invoke-static {v4, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 284
    .line 285
    .line 286
    move-object v6, v9

    .line 287
    const/high16 v5, 0x3f800000    # 1.0f

    .line 288
    .line 289
    float-to-double v8, v5

    .line 290
    const-wide/16 v16, 0x0

    .line 291
    .line 292
    cmpl-double v8, v8, v16

    .line 293
    .line 294
    if-lez v8, :cond_7

    .line 295
    .line 296
    goto :goto_5

    .line 297
    :cond_7
    const-string v8, "invalid weight; must be greater than zero"

    .line 298
    .line 299
    invoke-static {v8}, Ll1/a;->a(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    :goto_5
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 303
    .line 304
    const/4 v9, 0x1

    .line 305
    invoke-direct {v8, v5, v9}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 306
    .line 307
    .line 308
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 309
    .line 310
    sget-object v9, Lx2/c;->p:Lx2/h;

    .line 311
    .line 312
    move-object/from16 v36, v6

    .line 313
    .line 314
    const/4 v6, 0x0

    .line 315
    invoke-static {v5, v9, v1, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 316
    .line 317
    .line 318
    move-result-object v5

    .line 319
    move-object/from16 p2, v13

    .line 320
    .line 321
    move-object/from16 p1, v14

    .line 322
    .line 323
    iget-wide v13, v1, Ll2/t;->T:J

    .line 324
    .line 325
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 330
    .line 331
    .line 332
    move-result-object v9

    .line 333
    invoke-static {v1, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 334
    .line 335
    .line 336
    move-result-object v8

    .line 337
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 338
    .line 339
    .line 340
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 341
    .line 342
    if-eqz v13, :cond_8

    .line 343
    .line 344
    invoke-virtual {v1, v15}, Ll2/t;->l(Lay0/a;)V

    .line 345
    .line 346
    .line 347
    goto :goto_6

    .line 348
    :cond_8
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 349
    .line 350
    .line 351
    :goto_6
    invoke-static {v12, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 352
    .line 353
    .line 354
    invoke-static {v2, v9, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 355
    .line 356
    .line 357
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 358
    .line 359
    if-nez v5, :cond_9

    .line 360
    .line 361
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v5

    .line 365
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 366
    .line 367
    .line 368
    move-result-object v9

    .line 369
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result v5

    .line 373
    if-nez v5, :cond_a

    .line 374
    .line 375
    :cond_9
    invoke-static {v6, v1, v6, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 376
    .line 377
    .line 378
    :cond_a
    invoke-static {v4, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 379
    .line 380
    .line 381
    iget-object v13, v0, Lh40/z;->d:Ljava/lang/String;

    .line 382
    .line 383
    iget-object v5, v0, Lh40/z;->n:Ljava/lang/String;

    .line 384
    .line 385
    iget-object v6, v0, Lh40/z;->m:Ljava/lang/Double;

    .line 386
    .line 387
    invoke-static {v1}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 388
    .line 389
    .line 390
    move-result-object v8

    .line 391
    invoke-virtual {v8}, Lj91/f;->l()Lg4/p0;

    .line 392
    .line 393
    .line 394
    move-result-object v14

    .line 395
    const/16 v33, 0x0

    .line 396
    .line 397
    const v34, 0xfffc

    .line 398
    .line 399
    .line 400
    move-object v8, v15

    .line 401
    const/4 v15, 0x0

    .line 402
    const-wide/16 v16, 0x0

    .line 403
    .line 404
    const-wide/16 v18, 0x0

    .line 405
    .line 406
    const/16 v20, 0x0

    .line 407
    .line 408
    const-wide/16 v21, 0x0

    .line 409
    .line 410
    const/16 v23, 0x0

    .line 411
    .line 412
    const/16 v24, 0x0

    .line 413
    .line 414
    const-wide/16 v25, 0x0

    .line 415
    .line 416
    const/16 v27, 0x0

    .line 417
    .line 418
    const/16 v28, 0x0

    .line 419
    .line 420
    const/16 v29, 0x0

    .line 421
    .line 422
    const/16 v30, 0x0

    .line 423
    .line 424
    const/16 v32, 0x0

    .line 425
    .line 426
    move-object/from16 v9, p1

    .line 427
    .line 428
    move-object/from16 v31, v1

    .line 429
    .line 430
    move-object/from16 v1, p2

    .line 431
    .line 432
    invoke-static/range {v13 .. v34}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 433
    .line 434
    .line 435
    move-object/from16 v13, v31

    .line 436
    .line 437
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 438
    .line 439
    .line 440
    move-result-object v14

    .line 441
    iget v14, v14, Lj91/c;->c:F

    .line 442
    .line 443
    invoke-static {v9, v14}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 444
    .line 445
    .line 446
    move-result-object v14

    .line 447
    invoke-static {v13, v14}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 448
    .line 449
    .line 450
    iget-object v14, v0, Lh40/z;->k:Ljava/time/LocalDate;

    .line 451
    .line 452
    invoke-static {v14}, Lu7/b;->d(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object v14

    .line 456
    filled-new-array {v14}, [Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v14

    .line 460
    const v15, 0x7f120cec

    .line 461
    .line 462
    .line 463
    invoke-static {v15, v14, v13}, Ljp/ga;->c(I[Ljava/lang/Object;Ll2/o;)Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object v14

    .line 467
    invoke-static {v13}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 468
    .line 469
    .line 470
    move-result-object v15

    .line 471
    invoke-virtual {v15}, Lj91/f;->a()Lg4/p0;

    .line 472
    .line 473
    .line 474
    move-result-object v16

    .line 475
    invoke-static {v13}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 476
    .line 477
    .line 478
    move-result-object v15

    .line 479
    invoke-virtual {v15}, Lj91/e;->s()J

    .line 480
    .line 481
    .line 482
    move-result-wide v17

    .line 483
    const/16 v29, 0x0

    .line 484
    .line 485
    const v30, 0xfffffe

    .line 486
    .line 487
    .line 488
    const-wide/16 v19, 0x0

    .line 489
    .line 490
    const/16 v21, 0x0

    .line 491
    .line 492
    const/16 v22, 0x0

    .line 493
    .line 494
    const-wide/16 v23, 0x0

    .line 495
    .line 496
    const/16 v25, 0x0

    .line 497
    .line 498
    const-wide/16 v26, 0x0

    .line 499
    .line 500
    const/16 v28, 0x0

    .line 501
    .line 502
    invoke-static/range {v16 .. v30}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 503
    .line 504
    .line 505
    move-result-object v15

    .line 506
    move-object v13, v14

    .line 507
    move-object v14, v15

    .line 508
    const/4 v15, 0x0

    .line 509
    const-wide/16 v16, 0x0

    .line 510
    .line 511
    const-wide/16 v18, 0x0

    .line 512
    .line 513
    const/16 v20, 0x0

    .line 514
    .line 515
    const-wide/16 v21, 0x0

    .line 516
    .line 517
    const/16 v23, 0x0

    .line 518
    .line 519
    const/16 v24, 0x0

    .line 520
    .line 521
    const-wide/16 v25, 0x0

    .line 522
    .line 523
    const/16 v27, 0x0

    .line 524
    .line 525
    const/16 v28, 0x0

    .line 526
    .line 527
    const/16 v29, 0x0

    .line 528
    .line 529
    const/16 v30, 0x0

    .line 530
    .line 531
    invoke-static/range {v13 .. v34}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 532
    .line 533
    .line 534
    move-object/from16 v13, v31

    .line 535
    .line 536
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 537
    .line 538
    .line 539
    move-result-object v14

    .line 540
    iget v14, v14, Lj91/c;->d:F

    .line 541
    .line 542
    invoke-static {v9, v14}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 543
    .line 544
    .line 545
    move-result-object v14

    .line 546
    invoke-static {v13, v14}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 547
    .line 548
    .line 549
    sget-object v14, Lx2/c;->m:Lx2/i;

    .line 550
    .line 551
    const/4 v15, 0x0

    .line 552
    invoke-static {v1, v14, v13, v15}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 553
    .line 554
    .line 555
    move-result-object v1

    .line 556
    iget-wide v14, v13, Ll2/t;->T:J

    .line 557
    .line 558
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 559
    .line 560
    .line 561
    move-result v14

    .line 562
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 563
    .line 564
    .line 565
    move-result-object v15

    .line 566
    move-object/from16 v21, v6

    .line 567
    .line 568
    invoke-static {v13, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 569
    .line 570
    .line 571
    move-result-object v6

    .line 572
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 573
    .line 574
    .line 575
    move-object/from16 v22, v5

    .line 576
    .line 577
    iget-boolean v5, v13, Ll2/t;->S:Z

    .line 578
    .line 579
    if-eqz v5, :cond_b

    .line 580
    .line 581
    invoke-virtual {v13, v8}, Ll2/t;->l(Lay0/a;)V

    .line 582
    .line 583
    .line 584
    goto :goto_7

    .line 585
    :cond_b
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 586
    .line 587
    .line 588
    :goto_7
    invoke-static {v12, v1, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 589
    .line 590
    .line 591
    invoke-static {v2, v15, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 592
    .line 593
    .line 594
    iget-boolean v1, v13, Ll2/t;->S:Z

    .line 595
    .line 596
    if-nez v1, :cond_c

    .line 597
    .line 598
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 599
    .line 600
    .line 601
    move-result-object v1

    .line 602
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 603
    .line 604
    .line 605
    move-result-object v2

    .line 606
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 607
    .line 608
    .line 609
    move-result v1

    .line 610
    if-nez v1, :cond_d

    .line 611
    .line 612
    :cond_c
    invoke-static {v14, v13, v14, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 613
    .line 614
    .line 615
    :cond_d
    invoke-static {v4, v6, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 616
    .line 617
    .line 618
    const v1, 0x7f120372

    .line 619
    .line 620
    .line 621
    invoke-static {v13, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 622
    .line 623
    .line 624
    move-result-object v17

    .line 625
    invoke-virtual {v13, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 626
    .line 627
    .line 628
    move-result v2

    .line 629
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 630
    .line 631
    .line 632
    move-result v4

    .line 633
    or-int/2addr v2, v4

    .line 634
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 635
    .line 636
    .line 637
    move-result-object v4

    .line 638
    if-nez v2, :cond_e

    .line 639
    .line 640
    if-ne v4, v3, :cond_f

    .line 641
    .line 642
    :cond_e
    new-instance v4, Li40/d3;

    .line 643
    .line 644
    const/4 v15, 0x0

    .line 645
    invoke-direct {v4, v11, v0, v15}, Li40/d3;-><init>(Lay0/k;Lh40/z;I)V

    .line 646
    .line 647
    .line 648
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 649
    .line 650
    .line 651
    :cond_f
    move-object v15, v4

    .line 652
    check-cast v15, Lay0/a;

    .line 653
    .line 654
    invoke-static {v9, v1}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 655
    .line 656
    .line 657
    move-result-object v19

    .line 658
    move-object/from16 v31, v13

    .line 659
    .line 660
    const/4 v13, 0x0

    .line 661
    const/16 v14, 0x18

    .line 662
    .line 663
    const/16 v16, 0x0

    .line 664
    .line 665
    const/16 v20, 0x0

    .line 666
    .line 667
    move-object/from16 v18, v31

    .line 668
    .line 669
    invoke-static/range {v13 .. v20}, Li91/j0;->Z(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 670
    .line 671
    .line 672
    move-object/from16 v13, v18

    .line 673
    .line 674
    iget-object v1, v0, Lh40/z;->f:Lg40/c0;

    .line 675
    .line 676
    sget-object v2, Lg40/c0;->e:Lg40/c0;

    .line 677
    .line 678
    if-ne v1, v2, :cond_12

    .line 679
    .line 680
    const v1, -0x55fe0749

    .line 681
    .line 682
    .line 683
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 684
    .line 685
    .line 686
    invoke-static {v13}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 687
    .line 688
    .line 689
    move-result-object v1

    .line 690
    iget v1, v1, Lj91/c;->d:F

    .line 691
    .line 692
    const v2, 0x7f120ce1

    .line 693
    .line 694
    .line 695
    invoke-static {v9, v1, v13, v2, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->p(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 696
    .line 697
    .line 698
    move-result-object v17

    .line 699
    invoke-virtual {v13, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 700
    .line 701
    .line 702
    move-result v1

    .line 703
    invoke-virtual {v13, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 704
    .line 705
    .line 706
    move-result v4

    .line 707
    or-int/2addr v1, v4

    .line 708
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 709
    .line 710
    .line 711
    move-result-object v4

    .line 712
    if-nez v1, :cond_10

    .line 713
    .line 714
    if-ne v4, v3, :cond_11

    .line 715
    .line 716
    :cond_10
    new-instance v4, Li40/d3;

    .line 717
    .line 718
    const/4 v1, 0x1

    .line 719
    invoke-direct {v4, v10, v0, v1}, Li40/d3;-><init>(Lay0/k;Lh40/z;I)V

    .line 720
    .line 721
    .line 722
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 723
    .line 724
    .line 725
    :cond_11
    move-object v15, v4

    .line 726
    check-cast v15, Lay0/a;

    .line 727
    .line 728
    invoke-static {v9, v2}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 729
    .line 730
    .line 731
    move-result-object v19

    .line 732
    move-object/from16 v31, v13

    .line 733
    .line 734
    const/4 v13, 0x0

    .line 735
    const/16 v14, 0x18

    .line 736
    .line 737
    const/16 v16, 0x0

    .line 738
    .line 739
    const/16 v20, 0x0

    .line 740
    .line 741
    move-object/from16 v18, v31

    .line 742
    .line 743
    invoke-static/range {v13 .. v20}, Li91/j0;->w0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 744
    .line 745
    .line 746
    move-object/from16 v13, v18

    .line 747
    .line 748
    const/4 v15, 0x0

    .line 749
    :goto_8
    invoke-virtual {v13, v15}, Ll2/t;->q(Z)V

    .line 750
    .line 751
    .line 752
    const/4 v1, 0x1

    .line 753
    goto :goto_9

    .line 754
    :cond_12
    const/4 v15, 0x0

    .line 755
    const v1, -0x56770e17

    .line 756
    .line 757
    .line 758
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 759
    .line 760
    .line 761
    goto :goto_8

    .line 762
    :goto_9
    invoke-virtual {v13, v1}, Ll2/t;->q(Z)V

    .line 763
    .line 764
    .line 765
    invoke-virtual {v13, v1}, Ll2/t;->q(Z)V

    .line 766
    .line 767
    .line 768
    iget-object v0, v0, Lh40/z;->e:Ljava/lang/Object;

    .line 769
    .line 770
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 771
    .line 772
    .line 773
    move-result-object v0

    .line 774
    check-cast v0, Landroid/net/Uri;

    .line 775
    .line 776
    const/4 v1, 0x0

    .line 777
    if-eqz v21, :cond_13

    .line 778
    .line 779
    if-eqz v22, :cond_13

    .line 780
    .line 781
    new-instance v2, Lol0/a;

    .line 782
    .line 783
    new-instance v3, Ljava/math/BigDecimal;

    .line 784
    .line 785
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Double;->doubleValue()D

    .line 786
    .line 787
    .line 788
    move-result-wide v4

    .line 789
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 790
    .line 791
    .line 792
    move-result-object v4

    .line 793
    invoke-direct {v3, v4}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 794
    .line 795
    .line 796
    move-object/from16 v4, v22

    .line 797
    .line 798
    invoke-direct {v2, v3, v4}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 799
    .line 800
    .line 801
    const/4 v12, 0x2

    .line 802
    invoke-static {v2, v12}, Ljp/qd;->a(Lol0/a;I)Ljava/lang/String;

    .line 803
    .line 804
    .line 805
    move-result-object v2

    .line 806
    :goto_a
    const/4 v15, 0x0

    .line 807
    goto :goto_b

    .line 808
    :cond_13
    move-object v2, v1

    .line 809
    goto :goto_a

    .line 810
    :goto_b
    invoke-static {v1, v0, v2, v13, v15}, Li40/o3;->d(Lx2/s;Landroid/net/Uri;Ljava/lang/String;Ll2/o;I)V

    .line 811
    .line 812
    .line 813
    const/4 v1, 0x1

    .line 814
    invoke-virtual {v13, v1}, Ll2/t;->q(Z)V

    .line 815
    .line 816
    .line 817
    goto :goto_c

    .line 818
    :cond_14
    move-object v13, v1

    .line 819
    move-object/from16 v36, v9

    .line 820
    .line 821
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 822
    .line 823
    .line 824
    :goto_c
    return-object v36

    .line 825
    :pswitch_3
    move v1, v8

    .line 826
    move-object/from16 v36, v9

    .line 827
    .line 828
    check-cast v0, Lh40/w;

    .line 829
    .line 830
    check-cast v10, Lx2/s;

    .line 831
    .line 832
    check-cast v11, Lay0/a;

    .line 833
    .line 834
    move-object/from16 v2, p1

    .line 835
    .line 836
    check-cast v2, Ll2/o;

    .line 837
    .line 838
    move-object/from16 v3, p2

    .line 839
    .line 840
    check-cast v3, Ljava/lang/Integer;

    .line 841
    .line 842
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 843
    .line 844
    .line 845
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 846
    .line 847
    .line 848
    move-result v1

    .line 849
    invoke-static {v0, v10, v11, v2, v1}, Li40/a3;->a(Lh40/w;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 850
    .line 851
    .line 852
    return-object v36

    .line 853
    :pswitch_4
    move v1, v8

    .line 854
    move-object/from16 v36, v9

    .line 855
    .line 856
    check-cast v0, Lh40/i3;

    .line 857
    .line 858
    check-cast v11, Lay0/a;

    .line 859
    .line 860
    check-cast v10, Lay0/a;

    .line 861
    .line 862
    move-object/from16 v2, p1

    .line 863
    .line 864
    check-cast v2, Ll2/o;

    .line 865
    .line 866
    move-object/from16 v3, p2

    .line 867
    .line 868
    check-cast v3, Ljava/lang/Integer;

    .line 869
    .line 870
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 871
    .line 872
    .line 873
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 874
    .line 875
    .line 876
    move-result v1

    .line 877
    invoke-static {v0, v11, v10, v2, v1}, Li40/y1;->c(Lh40/i3;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 878
    .line 879
    .line 880
    return-object v36

    .line 881
    :pswitch_5
    move v1, v8

    .line 882
    move-object/from16 v36, v9

    .line 883
    .line 884
    check-cast v0, Lh40/f3;

    .line 885
    .line 886
    check-cast v11, Lay0/a;

    .line 887
    .line 888
    check-cast v10, Lay0/a;

    .line 889
    .line 890
    move-object/from16 v2, p1

    .line 891
    .line 892
    check-cast v2, Ll2/o;

    .line 893
    .line 894
    move-object/from16 v3, p2

    .line 895
    .line 896
    check-cast v3, Ljava/lang/Integer;

    .line 897
    .line 898
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 899
    .line 900
    .line 901
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 902
    .line 903
    .line 904
    move-result v1

    .line 905
    invoke-static {v0, v11, v10, v2, v1}, Li40/l1;->K(Lh40/f3;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 906
    .line 907
    .line 908
    return-object v36

    .line 909
    :pswitch_6
    move v1, v8

    .line 910
    move-object/from16 v36, v9

    .line 911
    .line 912
    check-cast v0, Lh40/p2;

    .line 913
    .line 914
    check-cast v11, Lay0/a;

    .line 915
    .line 916
    check-cast v10, Lay0/a;

    .line 917
    .line 918
    move-object/from16 v2, p1

    .line 919
    .line 920
    check-cast v2, Ll2/o;

    .line 921
    .line 922
    move-object/from16 v3, p2

    .line 923
    .line 924
    check-cast v3, Ljava/lang/Integer;

    .line 925
    .line 926
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 927
    .line 928
    .line 929
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 930
    .line 931
    .line 932
    move-result v1

    .line 933
    invoke-static {v0, v11, v10, v2, v1}, Li40/l1;->A(Lh40/p2;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 934
    .line 935
    .line 936
    return-object v36

    .line 937
    :pswitch_7
    move v1, v8

    .line 938
    move-object/from16 v36, v9

    .line 939
    .line 940
    check-cast v0, Lh40/j2;

    .line 941
    .line 942
    check-cast v11, Lay0/k;

    .line 943
    .line 944
    check-cast v10, Lay0/k;

    .line 945
    .line 946
    move-object/from16 v2, p1

    .line 947
    .line 948
    check-cast v2, Ll2/o;

    .line 949
    .line 950
    move-object/from16 v3, p2

    .line 951
    .line 952
    check-cast v3, Ljava/lang/Integer;

    .line 953
    .line 954
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 955
    .line 956
    .line 957
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 958
    .line 959
    .line 960
    move-result v1

    .line 961
    invoke-static {v0, v11, v10, v2, v1}, Li40/l1;->c(Lh40/j2;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 962
    .line 963
    .line 964
    return-object v36

    .line 965
    :pswitch_8
    move-object/from16 v36, v9

    .line 966
    .line 967
    check-cast v0, Lh40/i1;

    .line 968
    .line 969
    check-cast v11, Lay0/a;

    .line 970
    .line 971
    check-cast v10, Lay0/a;

    .line 972
    .line 973
    move-object/from16 v1, p1

    .line 974
    .line 975
    check-cast v1, Ll2/o;

    .line 976
    .line 977
    move-object/from16 v2, p2

    .line 978
    .line 979
    check-cast v2, Ljava/lang/Integer;

    .line 980
    .line 981
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 982
    .line 983
    .line 984
    move-result v2

    .line 985
    and-int/lit8 v3, v2, 0x3

    .line 986
    .line 987
    const/4 v12, 0x2

    .line 988
    if-eq v3, v12, :cond_15

    .line 989
    .line 990
    const/4 v3, 0x1

    .line 991
    :goto_d
    const/16 v35, 0x1

    .line 992
    .line 993
    goto :goto_e

    .line 994
    :cond_15
    const/4 v3, 0x0

    .line 995
    goto :goto_d

    .line 996
    :goto_e
    and-int/lit8 v2, v2, 0x1

    .line 997
    .line 998
    check-cast v1, Ll2/t;

    .line 999
    .line 1000
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1001
    .line 1002
    .line 1003
    move-result v2

    .line 1004
    if-eqz v2, :cond_17

    .line 1005
    .line 1006
    iget-boolean v2, v0, Lh40/i1;->a:Z

    .line 1007
    .line 1008
    if-nez v2, :cond_16

    .line 1009
    .line 1010
    const v2, 0x6b733a1b

    .line 1011
    .line 1012
    .line 1013
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 1014
    .line 1015
    .line 1016
    new-instance v2, La71/a1;

    .line 1017
    .line 1018
    const/16 v3, 0x17

    .line 1019
    .line 1020
    invoke-direct {v2, v3, v11, v10, v0}, La71/a1;-><init>(ILay0/a;Lay0/a;Lql0/h;)V

    .line 1021
    .line 1022
    .line 1023
    const v0, 0x2e297f2b

    .line 1024
    .line 1025
    .line 1026
    invoke-static {v0, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v15

    .line 1030
    const/16 v17, 0x180

    .line 1031
    .line 1032
    const/16 v18, 0x3

    .line 1033
    .line 1034
    const/4 v12, 0x0

    .line 1035
    const-wide/16 v13, 0x0

    .line 1036
    .line 1037
    move-object/from16 v16, v1

    .line 1038
    .line 1039
    invoke-static/range {v12 .. v18}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 1040
    .line 1041
    .line 1042
    const/4 v15, 0x0

    .line 1043
    :goto_f
    invoke-virtual {v1, v15}, Ll2/t;->q(Z)V

    .line 1044
    .line 1045
    .line 1046
    goto :goto_10

    .line 1047
    :cond_16
    const/4 v15, 0x0

    .line 1048
    const v0, 0x6b396209

    .line 1049
    .line 1050
    .line 1051
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 1052
    .line 1053
    .line 1054
    goto :goto_f

    .line 1055
    :cond_17
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1056
    .line 1057
    .line 1058
    :goto_10
    return-object v36

    .line 1059
    :pswitch_9
    move-object/from16 v36, v9

    .line 1060
    .line 1061
    check-cast v0, Lh40/v0;

    .line 1062
    .line 1063
    check-cast v11, Lay0/a;

    .line 1064
    .line 1065
    check-cast v10, Lay0/a;

    .line 1066
    .line 1067
    move-object/from16 v1, p1

    .line 1068
    .line 1069
    check-cast v1, Ll2/o;

    .line 1070
    .line 1071
    move-object/from16 v2, p2

    .line 1072
    .line 1073
    check-cast v2, Ljava/lang/Integer;

    .line 1074
    .line 1075
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1076
    .line 1077
    .line 1078
    const/16 v35, 0x1

    .line 1079
    .line 1080
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1081
    .line 1082
    .line 1083
    move-result v2

    .line 1084
    invoke-static {v0, v11, v10, v1, v2}, Li40/q;->x(Lh40/v0;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 1085
    .line 1086
    .line 1087
    return-object v36

    .line 1088
    :pswitch_a
    move-object/from16 v36, v9

    .line 1089
    .line 1090
    check-cast v0, Lh40/t0;

    .line 1091
    .line 1092
    check-cast v11, Lay0/a;

    .line 1093
    .line 1094
    check-cast v10, Lay0/a;

    .line 1095
    .line 1096
    move-object/from16 v1, p1

    .line 1097
    .line 1098
    check-cast v1, Ll2/o;

    .line 1099
    .line 1100
    move-object/from16 v2, p2

    .line 1101
    .line 1102
    check-cast v2, Ljava/lang/Integer;

    .line 1103
    .line 1104
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1105
    .line 1106
    .line 1107
    move-result v2

    .line 1108
    and-int/lit8 v3, v2, 0x3

    .line 1109
    .line 1110
    const/4 v12, 0x2

    .line 1111
    if-eq v3, v12, :cond_18

    .line 1112
    .line 1113
    const/4 v3, 0x1

    .line 1114
    :goto_11
    const/16 v35, 0x1

    .line 1115
    .line 1116
    goto :goto_12

    .line 1117
    :cond_18
    const/4 v3, 0x0

    .line 1118
    goto :goto_11

    .line 1119
    :goto_12
    and-int/lit8 v2, v2, 0x1

    .line 1120
    .line 1121
    check-cast v1, Ll2/t;

    .line 1122
    .line 1123
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1124
    .line 1125
    .line 1126
    move-result v2

    .line 1127
    if-eqz v2, :cond_1a

    .line 1128
    .line 1129
    iget-boolean v2, v0, Lh40/t0;->a:Z

    .line 1130
    .line 1131
    if-nez v2, :cond_19

    .line 1132
    .line 1133
    const v2, -0x6807f6c2

    .line 1134
    .line 1135
    .line 1136
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 1137
    .line 1138
    .line 1139
    new-instance v2, La71/a1;

    .line 1140
    .line 1141
    const/16 v3, 0x15

    .line 1142
    .line 1143
    invoke-direct {v2, v3, v11, v10, v0}, La71/a1;-><init>(ILay0/a;Lay0/a;Lql0/h;)V

    .line 1144
    .line 1145
    .line 1146
    const v0, -0x502394f

    .line 1147
    .line 1148
    .line 1149
    invoke-static {v0, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1150
    .line 1151
    .line 1152
    move-result-object v15

    .line 1153
    const/16 v17, 0x180

    .line 1154
    .line 1155
    const/16 v18, 0x3

    .line 1156
    .line 1157
    const/4 v12, 0x0

    .line 1158
    const-wide/16 v13, 0x0

    .line 1159
    .line 1160
    move-object/from16 v16, v1

    .line 1161
    .line 1162
    invoke-static/range {v12 .. v18}, Lxf0/i0;->t(Lx2/s;JLt2/b;Ll2/o;II)V

    .line 1163
    .line 1164
    .line 1165
    const/4 v15, 0x0

    .line 1166
    :goto_13
    invoke-virtual {v1, v15}, Ll2/t;->q(Z)V

    .line 1167
    .line 1168
    .line 1169
    goto :goto_14

    .line 1170
    :cond_19
    const/4 v15, 0x0

    .line 1171
    const v0, -0x68314a1d

    .line 1172
    .line 1173
    .line 1174
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 1175
    .line 1176
    .line 1177
    goto :goto_13

    .line 1178
    :cond_1a
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1179
    .line 1180
    .line 1181
    :goto_14
    return-object v36

    .line 1182
    :pswitch_b
    move-object/from16 v36, v9

    .line 1183
    .line 1184
    check-cast v0, Lh40/m;

    .line 1185
    .line 1186
    check-cast v10, Lay0/k;

    .line 1187
    .line 1188
    check-cast v11, Lay0/a;

    .line 1189
    .line 1190
    move-object/from16 v1, p1

    .line 1191
    .line 1192
    check-cast v1, Ll2/o;

    .line 1193
    .line 1194
    move-object/from16 v2, p2

    .line 1195
    .line 1196
    check-cast v2, Ljava/lang/Integer;

    .line 1197
    .line 1198
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1199
    .line 1200
    .line 1201
    const/16 v35, 0x1

    .line 1202
    .line 1203
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1204
    .line 1205
    .line 1206
    move-result v2

    .line 1207
    invoke-static {v0, v10, v11, v1, v2}, Li40/o0;->g(Lh40/m;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 1208
    .line 1209
    .line 1210
    return-object v36

    .line 1211
    :pswitch_c
    move/from16 v35, v8

    .line 1212
    .line 1213
    move-object/from16 v36, v9

    .line 1214
    .line 1215
    check-cast v0, Lx2/s;

    .line 1216
    .line 1217
    check-cast v11, Lg40/o;

    .line 1218
    .line 1219
    check-cast v10, Lay0/k;

    .line 1220
    .line 1221
    move-object/from16 v1, p1

    .line 1222
    .line 1223
    check-cast v1, Ll2/o;

    .line 1224
    .line 1225
    move-object/from16 v2, p2

    .line 1226
    .line 1227
    check-cast v2, Ljava/lang/Integer;

    .line 1228
    .line 1229
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1230
    .line 1231
    .line 1232
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1233
    .line 1234
    .line 1235
    move-result v2

    .line 1236
    invoke-static {v0, v11, v10, v1, v2}, Li40/l0;->a(Lx2/s;Lg40/o;Lay0/k;Ll2/o;I)V

    .line 1237
    .line 1238
    .line 1239
    return-object v36

    .line 1240
    :pswitch_d
    move/from16 v35, v8

    .line 1241
    .line 1242
    move-object/from16 v36, v9

    .line 1243
    .line 1244
    check-cast v0, Lx2/s;

    .line 1245
    .line 1246
    check-cast v11, Lh40/i0;

    .line 1247
    .line 1248
    check-cast v10, Lay0/k;

    .line 1249
    .line 1250
    move-object/from16 v1, p1

    .line 1251
    .line 1252
    check-cast v1, Ll2/o;

    .line 1253
    .line 1254
    move-object/from16 v2, p2

    .line 1255
    .line 1256
    check-cast v2, Ljava/lang/Integer;

    .line 1257
    .line 1258
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1259
    .line 1260
    .line 1261
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1262
    .line 1263
    .line 1264
    move-result v2

    .line 1265
    invoke-static {v0, v11, v10, v1, v2}, Li40/v;->a(Lx2/s;Lh40/i0;Lay0/k;Ll2/o;I)V

    .line 1266
    .line 1267
    .line 1268
    return-object v36

    .line 1269
    :pswitch_e
    move-object/from16 v36, v9

    .line 1270
    .line 1271
    check-cast v0, Lh40/i0;

    .line 1272
    .line 1273
    move-object v4, v11

    .line 1274
    check-cast v4, Lay0/a;

    .line 1275
    .line 1276
    check-cast v10, Lay0/a;

    .line 1277
    .line 1278
    move-object/from16 v1, p1

    .line 1279
    .line 1280
    check-cast v1, Ll2/o;

    .line 1281
    .line 1282
    move-object/from16 v2, p2

    .line 1283
    .line 1284
    check-cast v2, Ljava/lang/Integer;

    .line 1285
    .line 1286
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1287
    .line 1288
    .line 1289
    move-result v2

    .line 1290
    and-int/lit8 v3, v2, 0x3

    .line 1291
    .line 1292
    const/4 v12, 0x2

    .line 1293
    if-eq v3, v12, :cond_1b

    .line 1294
    .line 1295
    const/4 v7, 0x1

    .line 1296
    :goto_15
    const/16 v35, 0x1

    .line 1297
    .line 1298
    goto :goto_16

    .line 1299
    :cond_1b
    const/4 v7, 0x0

    .line 1300
    goto :goto_15

    .line 1301
    :goto_16
    and-int/lit8 v2, v2, 0x1

    .line 1302
    .line 1303
    move-object v8, v1

    .line 1304
    check-cast v8, Ll2/t;

    .line 1305
    .line 1306
    invoke-virtual {v8, v2, v7}, Ll2/t;->O(IZ)Z

    .line 1307
    .line 1308
    .line 1309
    move-result v1

    .line 1310
    if-eqz v1, :cond_1d

    .line 1311
    .line 1312
    new-instance v15, Ljava/util/ArrayList;

    .line 1313
    .line 1314
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 1315
    .line 1316
    .line 1317
    iget-boolean v0, v0, Lh40/i0;->q:Z

    .line 1318
    .line 1319
    if-eqz v0, :cond_1c

    .line 1320
    .line 1321
    new-instance v1, Li91/v2;

    .line 1322
    .line 1323
    const/4 v5, 0x0

    .line 1324
    const/4 v3, 0x6

    .line 1325
    const v2, 0x7f0804b6

    .line 1326
    .line 1327
    .line 1328
    const/4 v6, 0x0

    .line 1329
    invoke-direct/range {v1 .. v6}, Li91/v2;-><init>(IILay0/a;Ljava/lang/String;Z)V

    .line 1330
    .line 1331
    .line 1332
    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1333
    .line 1334
    .line 1335
    :cond_1c
    new-instance v14, Li91/w2;

    .line 1336
    .line 1337
    const/4 v0, 0x3

    .line 1338
    invoke-direct {v14, v10, v0}, Li91/w2;-><init>(Lay0/a;I)V

    .line 1339
    .line 1340
    .line 1341
    const/16 v19, 0x0

    .line 1342
    .line 1343
    const/16 v20, 0x33f

    .line 1344
    .line 1345
    const/4 v11, 0x0

    .line 1346
    const/4 v12, 0x0

    .line 1347
    const/4 v13, 0x0

    .line 1348
    const/16 v16, 0x0

    .line 1349
    .line 1350
    const/16 v17, 0x0

    .line 1351
    .line 1352
    move-object/from16 v18, v8

    .line 1353
    .line 1354
    invoke-static/range {v11 .. v20}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 1355
    .line 1356
    .line 1357
    goto :goto_17

    .line 1358
    :cond_1d
    move-object/from16 v18, v8

    .line 1359
    .line 1360
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 1361
    .line 1362
    .line 1363
    :goto_17
    return-object v36

    .line 1364
    :pswitch_f
    move-object/from16 v36, v9

    .line 1365
    .line 1366
    check-cast v0, Lh40/m;

    .line 1367
    .line 1368
    check-cast v11, Lay0/k;

    .line 1369
    .line 1370
    check-cast v10, Lay0/k;

    .line 1371
    .line 1372
    move-object/from16 v1, p1

    .line 1373
    .line 1374
    check-cast v1, Ll2/o;

    .line 1375
    .line 1376
    move-object/from16 v2, p2

    .line 1377
    .line 1378
    check-cast v2, Ljava/lang/Integer;

    .line 1379
    .line 1380
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1381
    .line 1382
    .line 1383
    const/16 v35, 0x1

    .line 1384
    .line 1385
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1386
    .line 1387
    .line 1388
    move-result v2

    .line 1389
    invoke-static {v0, v11, v10, v1, v2}, Li40/i;->d(Lh40/m;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 1390
    .line 1391
    .line 1392
    return-object v36

    .line 1393
    :pswitch_10
    move/from16 v35, v8

    .line 1394
    .line 1395
    move-object/from16 v36, v9

    .line 1396
    .line 1397
    check-cast v0, Lg40/h;

    .line 1398
    .line 1399
    check-cast v11, Lay0/a;

    .line 1400
    .line 1401
    check-cast v10, Lx2/s;

    .line 1402
    .line 1403
    move-object/from16 v1, p1

    .line 1404
    .line 1405
    check-cast v1, Ll2/o;

    .line 1406
    .line 1407
    move-object/from16 v2, p2

    .line 1408
    .line 1409
    check-cast v2, Ljava/lang/Integer;

    .line 1410
    .line 1411
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1412
    .line 1413
    .line 1414
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1415
    .line 1416
    .line 1417
    move-result v2

    .line 1418
    invoke-static {v0, v11, v10, v1, v2}, Li40/c;->a(Lg40/h;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 1419
    .line 1420
    .line 1421
    return-object v36

    .line 1422
    :pswitch_11
    move/from16 v35, v8

    .line 1423
    .line 1424
    move-object/from16 v36, v9

    .line 1425
    .line 1426
    check-cast v0, Landroidx/lifecycle/x;

    .line 1427
    .line 1428
    check-cast v10, Lay0/k;

    .line 1429
    .line 1430
    check-cast v11, Lay0/a;

    .line 1431
    .line 1432
    move-object/from16 v1, p1

    .line 1433
    .line 1434
    check-cast v1, Ll2/o;

    .line 1435
    .line 1436
    move-object/from16 v2, p2

    .line 1437
    .line 1438
    check-cast v2, Ljava/lang/Integer;

    .line 1439
    .line 1440
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1441
    .line 1442
    .line 1443
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1444
    .line 1445
    .line 1446
    move-result v2

    .line 1447
    invoke-static {v0, v10, v11, v1, v2}, Li2/a1;->c(Landroidx/lifecycle/x;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 1448
    .line 1449
    .line 1450
    return-object v36

    .line 1451
    :pswitch_12
    move-object/from16 v36, v9

    .line 1452
    .line 1453
    check-cast v0, Lh00/b;

    .line 1454
    .line 1455
    check-cast v11, Lay0/a;

    .line 1456
    .line 1457
    check-cast v10, Lx2/s;

    .line 1458
    .line 1459
    move-object/from16 v1, p1

    .line 1460
    .line 1461
    check-cast v1, Ll2/o;

    .line 1462
    .line 1463
    move-object/from16 v2, p2

    .line 1464
    .line 1465
    check-cast v2, Ljava/lang/Integer;

    .line 1466
    .line 1467
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1468
    .line 1469
    .line 1470
    const/16 v2, 0x9

    .line 1471
    .line 1472
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 1473
    .line 1474
    .line 1475
    move-result v2

    .line 1476
    invoke-static {v0, v11, v10, v1, v2}, Li00/c;->a(Lh00/b;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 1477
    .line 1478
    .line 1479
    return-object v36

    .line 1480
    :pswitch_13
    move-object/from16 v36, v9

    .line 1481
    .line 1482
    check-cast v0, Lga0/v;

    .line 1483
    .line 1484
    check-cast v11, Lay0/a;

    .line 1485
    .line 1486
    check-cast v10, Lay0/a;

    .line 1487
    .line 1488
    move-object/from16 v1, p1

    .line 1489
    .line 1490
    check-cast v1, Ll2/o;

    .line 1491
    .line 1492
    move-object/from16 v2, p2

    .line 1493
    .line 1494
    check-cast v2, Ljava/lang/Integer;

    .line 1495
    .line 1496
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1497
    .line 1498
    .line 1499
    const/16 v35, 0x1

    .line 1500
    .line 1501
    invoke-static/range {v35 .. v35}, Ll2/b;->x(I)I

    .line 1502
    .line 1503
    .line 1504
    move-result v2

    .line 1505
    invoke-static {v0, v11, v10, v1, v2}, Llp/r0;->c(Lga0/v;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 1506
    .line 1507
    .line 1508
    return-object v36

    .line 1509
    :pswitch_14
    move-object/from16 v36, v9

    .line 1510
    .line 1511
    check-cast v0, Lfr0/g;

    .line 1512
    .line 1513
    check-cast v11, Lay0/a;

    .line 1514
    .line 1515
    check-cast v10, Lay0/a;

    .line 1516
    .line 1517
    move-object/from16 v1, p1

    .line 1518
    .line 1519
    check-cast v1, Ll2/o;

    .line 1520
    .line 1521
    move-object/from16 v2, p2

    .line 1522
    .line 1523
    check-cast v2, Ljava/lang/Integer;

    .line 1524
    .line 1525
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1526
    .line 1527
    .line 1528
    move-result v2

    .line 1529
    and-int/lit8 v3, v2, 0x3

    .line 1530
    .line 1531
    const/4 v12, 0x2

    .line 1532
    if-eq v3, v12, :cond_1e

    .line 1533
    .line 1534
    const/4 v3, 0x1

    .line 1535
    :goto_18
    const/16 v35, 0x1

    .line 1536
    .line 1537
    goto :goto_19

    .line 1538
    :cond_1e
    const/4 v3, 0x0

    .line 1539
    goto :goto_18

    .line 1540
    :goto_19
    and-int/lit8 v2, v2, 0x1

    .line 1541
    .line 1542
    check-cast v1, Ll2/t;

    .line 1543
    .line 1544
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1545
    .line 1546
    .line 1547
    move-result v2

    .line 1548
    if-eqz v2, :cond_1f

    .line 1549
    .line 1550
    const/4 v15, 0x0

    .line 1551
    invoke-static {v0, v11, v10, v1, v15}, Lgr0/a;->h(Lfr0/g;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 1552
    .line 1553
    .line 1554
    goto :goto_1a

    .line 1555
    :cond_1f
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1556
    .line 1557
    .line 1558
    :goto_1a
    return-object v36

    .line 1559
    :pswitch_15
    move-object/from16 v36, v9

    .line 1560
    .line 1561
    check-cast v0, Lkotlin/jvm/internal/c0;

    .line 1562
    .line 1563
    check-cast v11, Lg1/u2;

    .line 1564
    .line 1565
    check-cast v10, Lg1/t2;

    .line 1566
    .line 1567
    move-object/from16 v1, p1

    .line 1568
    .line 1569
    check-cast v1, Ljava/lang/Float;

    .line 1570
    .line 1571
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1572
    .line 1573
    .line 1574
    move-result v1

    .line 1575
    move-object/from16 v2, p2

    .line 1576
    .line 1577
    check-cast v2, Ljava/lang/Float;

    .line 1578
    .line 1579
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1580
    .line 1581
    .line 1582
    iget v2, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 1583
    .line 1584
    sub-float/2addr v1, v2

    .line 1585
    invoke-virtual {v11, v1}, Lg1/u2;->d(F)F

    .line 1586
    .line 1587
    .line 1588
    move-result v1

    .line 1589
    invoke-virtual {v11, v1}, Lg1/u2;->h(F)J

    .line 1590
    .line 1591
    .line 1592
    move-result-wide v1

    .line 1593
    iget-object v3, v10, Lg1/t2;->a:Lg1/u2;

    .line 1594
    .line 1595
    iget-object v4, v3, Lg1/u2;->k:Lg1/e2;

    .line 1596
    .line 1597
    const/4 v9, 0x1

    .line 1598
    invoke-virtual {v3, v4, v1, v2, v9}, Lg1/u2;->c(Lg1/e2;JI)J

    .line 1599
    .line 1600
    .line 1601
    move-result-wide v1

    .line 1602
    invoke-virtual {v11, v1, v2}, Lg1/u2;->g(J)F

    .line 1603
    .line 1604
    .line 1605
    move-result v1

    .line 1606
    invoke-virtual {v11, v1}, Lg1/u2;->d(F)F

    .line 1607
    .line 1608
    .line 1609
    move-result v1

    .line 1610
    iget v2, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 1611
    .line 1612
    add-float/2addr v2, v1

    .line 1613
    iput v2, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 1614
    .line 1615
    return-object v36

    .line 1616
    :pswitch_16
    move-object/from16 v36, v9

    .line 1617
    .line 1618
    check-cast v0, Lg1/d1;

    .line 1619
    .line 1620
    check-cast v11, Lkotlin/jvm/internal/e0;

    .line 1621
    .line 1622
    check-cast v10, Lh6/j;

    .line 1623
    .line 1624
    move-object/from16 v1, p1

    .line 1625
    .line 1626
    check-cast v1, Lp3/t;

    .line 1627
    .line 1628
    move-object/from16 v2, p2

    .line 1629
    .line 1630
    check-cast v2, Ld3/b;

    .line 1631
    .line 1632
    invoke-static {v0}, Lv3/f;->w(Lv3/m;)Lv3/f1;

    .line 1633
    .line 1634
    .line 1635
    move-result-object v3

    .line 1636
    const-wide/16 v4, 0x0

    .line 1637
    .line 1638
    invoke-virtual {v3, v4, v5}, Lv3/f1;->K(J)J

    .line 1639
    .line 1640
    .line 1641
    move-result-wide v3

    .line 1642
    iget-wide v5, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 1643
    .line 1644
    invoke-static {v3, v4, v5, v6}, Ld3/b;->c(JJ)Z

    .line 1645
    .line 1646
    .line 1647
    move-result v5

    .line 1648
    if-nez v5, :cond_20

    .line 1649
    .line 1650
    iget-wide v5, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 1651
    .line 1652
    invoke-static {v3, v4, v5, v6}, Ld3/b;->g(JJ)J

    .line 1653
    .line 1654
    .line 1655
    move-result-wide v5

    .line 1656
    iget-wide v7, v0, Lg1/d1;->A:J

    .line 1657
    .line 1658
    invoke-static {v7, v8, v5, v6}, Ld3/b;->h(JJ)J

    .line 1659
    .line 1660
    .line 1661
    move-result-wide v5

    .line 1662
    iput-wide v5, v0, Lg1/d1;->A:J

    .line 1663
    .line 1664
    :cond_20
    iput-wide v3, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 1665
    .line 1666
    iget-wide v3, v0, Lg1/d1;->A:J

    .line 1667
    .line 1668
    invoke-static {v10, v1, v3, v4}, Ljp/le;->a(Lh6/j;Lp3/t;J)V

    .line 1669
    .line 1670
    .line 1671
    iget-object v0, v0, Lg1/d1;->x:Lxy0/j;

    .line 1672
    .line 1673
    if-eqz v0, :cond_21

    .line 1674
    .line 1675
    new-instance v1, Lg1/h0;

    .line 1676
    .line 1677
    iget-wide v2, v2, Ld3/b;->a:J

    .line 1678
    .line 1679
    invoke-direct {v1, v2, v3}, Lg1/h0;-><init>(J)V

    .line 1680
    .line 1681
    .line 1682
    invoke-interface {v0, v1}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1683
    .line 1684
    .line 1685
    :cond_21
    return-object v36

    .line 1686
    :pswitch_17
    move-object/from16 v36, v9

    .line 1687
    .line 1688
    check-cast v11, Lay0/a;

    .line 1689
    .line 1690
    check-cast v0, Lt2/b;

    .line 1691
    .line 1692
    move-object/from16 v37, v10

    .line 1693
    .line 1694
    check-cast v37, Ljava/lang/String;

    .line 1695
    .line 1696
    move-object/from16 v1, p1

    .line 1697
    .line 1698
    check-cast v1, Ll2/o;

    .line 1699
    .line 1700
    move-object/from16 v2, p2

    .line 1701
    .line 1702
    check-cast v2, Ljava/lang/Integer;

    .line 1703
    .line 1704
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1705
    .line 1706
    .line 1707
    move-result v2

    .line 1708
    and-int/lit8 v4, v2, 0x3

    .line 1709
    .line 1710
    const/4 v12, 0x2

    .line 1711
    if-eq v4, v12, :cond_22

    .line 1712
    .line 1713
    const/4 v4, 0x1

    .line 1714
    :goto_1b
    const/16 v35, 0x1

    .line 1715
    .line 1716
    goto :goto_1c

    .line 1717
    :cond_22
    const/4 v4, 0x0

    .line 1718
    goto :goto_1b

    .line 1719
    :goto_1c
    and-int/lit8 v2, v2, 0x1

    .line 1720
    .line 1721
    check-cast v1, Ll2/t;

    .line 1722
    .line 1723
    invoke-virtual {v1, v2, v4}, Ll2/t;->O(IZ)Z

    .line 1724
    .line 1725
    .line 1726
    move-result v2

    .line 1727
    if-eqz v2, :cond_2d

    .line 1728
    .line 1729
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 1730
    .line 1731
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1732
    .line 1733
    .line 1734
    move-result-object v4

    .line 1735
    check-cast v4, Lj91/c;

    .line 1736
    .line 1737
    iget v4, v4, Lj91/c;->d:F

    .line 1738
    .line 1739
    const/16 v22, 0x7

    .line 1740
    .line 1741
    sget-object v23, Lx2/p;->b:Lx2/p;

    .line 1742
    .line 1743
    const/16 v18, 0x0

    .line 1744
    .line 1745
    const/16 v19, 0x0

    .line 1746
    .line 1747
    const/16 v20, 0x0

    .line 1748
    .line 1749
    move/from16 v21, v4

    .line 1750
    .line 1751
    move-object/from16 v17, v23

    .line 1752
    .line 1753
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 1754
    .line 1755
    .line 1756
    move-result-object v4

    .line 1757
    const/high16 v6, 0x3f800000    # 1.0f

    .line 1758
    .line 1759
    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 1760
    .line 1761
    .line 1762
    move-result-object v4

    .line 1763
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 1764
    .line 1765
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 1766
    .line 1767
    const/4 v15, 0x0

    .line 1768
    invoke-static {v6, v7, v1, v15}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1769
    .line 1770
    .line 1771
    move-result-object v6

    .line 1772
    iget-wide v7, v1, Ll2/t;->T:J

    .line 1773
    .line 1774
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 1775
    .line 1776
    .line 1777
    move-result v7

    .line 1778
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 1779
    .line 1780
    .line 1781
    move-result-object v8

    .line 1782
    invoke-static {v1, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1783
    .line 1784
    .line 1785
    move-result-object v4

    .line 1786
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 1787
    .line 1788
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1789
    .line 1790
    .line 1791
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 1792
    .line 1793
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 1794
    .line 1795
    .line 1796
    iget-boolean v10, v1, Ll2/t;->S:Z

    .line 1797
    .line 1798
    if-eqz v10, :cond_23

    .line 1799
    .line 1800
    invoke-virtual {v1, v9}, Ll2/t;->l(Lay0/a;)V

    .line 1801
    .line 1802
    .line 1803
    goto :goto_1d

    .line 1804
    :cond_23
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 1805
    .line 1806
    .line 1807
    :goto_1d
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 1808
    .line 1809
    invoke-static {v10, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1810
    .line 1811
    .line 1812
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 1813
    .line 1814
    invoke-static {v6, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1815
    .line 1816
    .line 1817
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 1818
    .line 1819
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 1820
    .line 1821
    if-nez v13, :cond_24

    .line 1822
    .line 1823
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1824
    .line 1825
    .line 1826
    move-result-object v13

    .line 1827
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1828
    .line 1829
    .line 1830
    move-result-object v14

    .line 1831
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1832
    .line 1833
    .line 1834
    move-result v13

    .line 1835
    if-nez v13, :cond_25

    .line 1836
    .line 1837
    :cond_24
    invoke-static {v7, v1, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1838
    .line 1839
    .line 1840
    :cond_25
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 1841
    .line 1842
    invoke-static {v7, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1843
    .line 1844
    .line 1845
    sget-object v4, Lk1/j;->g:Lk1/f;

    .line 1846
    .line 1847
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1848
    .line 1849
    .line 1850
    move-result-object v13

    .line 1851
    check-cast v13, Lj91/c;

    .line 1852
    .line 1853
    iget v13, v13, Lj91/c;->c:F

    .line 1854
    .line 1855
    const/16 v27, 0x0

    .line 1856
    .line 1857
    const/16 v28, 0xd

    .line 1858
    .line 1859
    const/16 v24, 0x0

    .line 1860
    .line 1861
    const/16 v26, 0x0

    .line 1862
    .line 1863
    move/from16 v25, v13

    .line 1864
    .line 1865
    invoke-static/range {v23 .. v28}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 1866
    .line 1867
    .line 1868
    move-result-object v17

    .line 1869
    if-eqz v11, :cond_26

    .line 1870
    .line 1871
    const/16 v18, 0x1

    .line 1872
    .line 1873
    goto :goto_1e

    .line 1874
    :cond_26
    const/16 v18, 0x0

    .line 1875
    .line 1876
    :goto_1e
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1877
    .line 1878
    .line 1879
    move-result v13

    .line 1880
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1881
    .line 1882
    .line 1883
    move-result-object v14

    .line 1884
    if-nez v13, :cond_27

    .line 1885
    .line 1886
    if-ne v14, v3, :cond_28

    .line 1887
    .line 1888
    :cond_27
    new-instance v14, Lb71/i;

    .line 1889
    .line 1890
    const/16 v3, 0x13

    .line 1891
    .line 1892
    invoke-direct {v14, v11, v3}, Lb71/i;-><init>(Lay0/a;I)V

    .line 1893
    .line 1894
    .line 1895
    invoke-virtual {v1, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1896
    .line 1897
    .line 1898
    :cond_28
    move-object/from16 v21, v14

    .line 1899
    .line 1900
    check-cast v21, Lay0/a;

    .line 1901
    .line 1902
    const/16 v22, 0xe

    .line 1903
    .line 1904
    const/16 v19, 0x0

    .line 1905
    .line 1906
    const/16 v20, 0x0

    .line 1907
    .line 1908
    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 1909
    .line 1910
    .line 1911
    move-result-object v3

    .line 1912
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1913
    .line 1914
    .line 1915
    move-result-object v13

    .line 1916
    check-cast v13, Lj91/c;

    .line 1917
    .line 1918
    iget v13, v13, Lj91/c;->c:F

    .line 1919
    .line 1920
    const/4 v14, 0x0

    .line 1921
    const/4 v15, 0x1

    .line 1922
    invoke-static {v3, v14, v13, v15}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 1923
    .line 1924
    .line 1925
    move-result-object v3

    .line 1926
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 1927
    .line 1928
    .line 1929
    move-result-object v13

    .line 1930
    check-cast v13, Lj91/c;

    .line 1931
    .line 1932
    iget v13, v13, Lj91/c;->d:F

    .line 1933
    .line 1934
    const/4 v12, 0x2

    .line 1935
    invoke-static {v3, v13, v14, v12}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 1936
    .line 1937
    .line 1938
    move-result-object v3

    .line 1939
    const/high16 v12, 0x3f800000    # 1.0f

    .line 1940
    .line 1941
    invoke-static {v3, v12}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 1942
    .line 1943
    .line 1944
    move-result-object v3

    .line 1945
    sget-object v12, Lx2/c;->m:Lx2/i;

    .line 1946
    .line 1947
    invoke-static {v4, v12, v1, v5}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 1948
    .line 1949
    .line 1950
    move-result-object v4

    .line 1951
    iget-wide v12, v1, Ll2/t;->T:J

    .line 1952
    .line 1953
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 1954
    .line 1955
    .line 1956
    move-result v5

    .line 1957
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 1958
    .line 1959
    .line 1960
    move-result-object v12

    .line 1961
    invoke-static {v1, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1962
    .line 1963
    .line 1964
    move-result-object v3

    .line 1965
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 1966
    .line 1967
    .line 1968
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 1969
    .line 1970
    if-eqz v13, :cond_29

    .line 1971
    .line 1972
    invoke-virtual {v1, v9}, Ll2/t;->l(Lay0/a;)V

    .line 1973
    .line 1974
    .line 1975
    goto :goto_1f

    .line 1976
    :cond_29
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 1977
    .line 1978
    .line 1979
    :goto_1f
    invoke-static {v10, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1980
    .line 1981
    .line 1982
    invoke-static {v6, v12, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1983
    .line 1984
    .line 1985
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 1986
    .line 1987
    if-nez v4, :cond_2a

    .line 1988
    .line 1989
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1990
    .line 1991
    .line 1992
    move-result-object v4

    .line 1993
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1994
    .line 1995
    .line 1996
    move-result-object v6

    .line 1997
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1998
    .line 1999
    .line 2000
    move-result v4

    .line 2001
    if-nez v4, :cond_2b

    .line 2002
    .line 2003
    :cond_2a
    invoke-static {v5, v1, v5, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 2004
    .line 2005
    .line 2006
    :cond_2b
    invoke-static {v7, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 2007
    .line 2008
    .line 2009
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 2010
    .line 2011
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2012
    .line 2013
    .line 2014
    move-result-object v3

    .line 2015
    check-cast v3, Lj91/f;

    .line 2016
    .line 2017
    invoke-virtual {v3}, Lj91/f;->k()Lg4/p0;

    .line 2018
    .line 2019
    .line 2020
    move-result-object v38

    .line 2021
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 2022
    .line 2023
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2024
    .line 2025
    .line 2026
    move-result-object v3

    .line 2027
    check-cast v3, Lj91/e;

    .line 2028
    .line 2029
    invoke-virtual {v3}, Lj91/e;->q()J

    .line 2030
    .line 2031
    .line 2032
    move-result-wide v40

    .line 2033
    const/16 v57, 0x0

    .line 2034
    .line 2035
    const v58, 0xfff4

    .line 2036
    .line 2037
    .line 2038
    const/16 v39, 0x0

    .line 2039
    .line 2040
    const-wide/16 v42, 0x0

    .line 2041
    .line 2042
    const/16 v44, 0x0

    .line 2043
    .line 2044
    const-wide/16 v45, 0x0

    .line 2045
    .line 2046
    const/16 v47, 0x0

    .line 2047
    .line 2048
    const/16 v48, 0x0

    .line 2049
    .line 2050
    const-wide/16 v49, 0x0

    .line 2051
    .line 2052
    const/16 v51, 0x0

    .line 2053
    .line 2054
    const/16 v52, 0x0

    .line 2055
    .line 2056
    const/16 v53, 0x0

    .line 2057
    .line 2058
    const/16 v54, 0x0

    .line 2059
    .line 2060
    const/16 v56, 0x0

    .line 2061
    .line 2062
    move-object/from16 v55, v1

    .line 2063
    .line 2064
    invoke-static/range {v37 .. v58}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 2065
    .line 2066
    .line 2067
    if-eqz v11, :cond_2c

    .line 2068
    .line 2069
    const v3, -0x72c8fc8a

    .line 2070
    .line 2071
    .line 2072
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 2073
    .line 2074
    .line 2075
    const v3, 0x7f08033b

    .line 2076
    .line 2077
    .line 2078
    const/4 v15, 0x0

    .line 2079
    invoke-static {v3, v15, v1}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 2080
    .line 2081
    .line 2082
    move-result-object v17

    .line 2083
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2084
    .line 2085
    .line 2086
    move-result-object v2

    .line 2087
    check-cast v2, Lj91/c;

    .line 2088
    .line 2089
    iget v2, v2, Lj91/c;->d:F

    .line 2090
    .line 2091
    const/16 v27, 0x0

    .line 2092
    .line 2093
    const/16 v28, 0xe

    .line 2094
    .line 2095
    const/16 v25, 0x0

    .line 2096
    .line 2097
    const/16 v26, 0x0

    .line 2098
    .line 2099
    move/from16 v24, v2

    .line 2100
    .line 2101
    invoke-static/range {v23 .. v28}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 2102
    .line 2103
    .line 2104
    move-result-object v2

    .line 2105
    sget-object v3, Lx2/c;->n:Lx2/i;

    .line 2106
    .line 2107
    new-instance v4, Landroidx/compose/foundation/layout/VerticalAlignElement;

    .line 2108
    .line 2109
    invoke-direct {v4, v3}, Landroidx/compose/foundation/layout/VerticalAlignElement;-><init>(Lx2/i;)V

    .line 2110
    .line 2111
    .line 2112
    invoke-interface {v2, v4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 2113
    .line 2114
    .line 2115
    move-result-object v19

    .line 2116
    const/16 v23, 0x30

    .line 2117
    .line 2118
    const/16 v24, 0x8

    .line 2119
    .line 2120
    const/16 v18, 0x0

    .line 2121
    .line 2122
    const-wide/16 v20, 0x0

    .line 2123
    .line 2124
    move-object/from16 v22, v1

    .line 2125
    .line 2126
    invoke-static/range {v17 .. v24}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 2127
    .line 2128
    .line 2129
    const/4 v15, 0x0

    .line 2130
    :goto_20
    invoke-virtual {v1, v15}, Ll2/t;->q(Z)V

    .line 2131
    .line 2132
    .line 2133
    const/4 v9, 0x1

    .line 2134
    goto :goto_21

    .line 2135
    :cond_2c
    const/4 v15, 0x0

    .line 2136
    const v2, -0x736dd423

    .line 2137
    .line 2138
    .line 2139
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 2140
    .line 2141
    .line 2142
    goto :goto_20

    .line 2143
    :goto_21
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 2144
    .line 2145
    .line 2146
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2147
    .line 2148
    .line 2149
    move-result-object v2

    .line 2150
    invoke-virtual {v0, v1, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2151
    .line 2152
    .line 2153
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 2154
    .line 2155
    .line 2156
    goto :goto_22

    .line 2157
    :cond_2d
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 2158
    .line 2159
    .line 2160
    :goto_22
    return-object v36

    .line 2161
    :pswitch_18
    move-object/from16 v36, v9

    .line 2162
    .line 2163
    move v9, v8

    .line 2164
    check-cast v0, Le30/o;

    .line 2165
    .line 2166
    check-cast v11, Ld01/h0;

    .line 2167
    .line 2168
    check-cast v10, Lay0/k;

    .line 2169
    .line 2170
    move-object/from16 v1, p1

    .line 2171
    .line 2172
    check-cast v1, Ll2/o;

    .line 2173
    .line 2174
    move-object/from16 v2, p2

    .line 2175
    .line 2176
    check-cast v2, Ljava/lang/Integer;

    .line 2177
    .line 2178
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2179
    .line 2180
    .line 2181
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 2182
    .line 2183
    .line 2184
    move-result v2

    .line 2185
    invoke-static {v0, v11, v10, v1, v2}, Lf30/a;->i(Le30/o;Ld01/h0;Lay0/k;Ll2/o;I)V

    .line 2186
    .line 2187
    .line 2188
    return-object v36

    .line 2189
    :pswitch_19
    move-object/from16 v36, v9

    .line 2190
    .line 2191
    move v9, v8

    .line 2192
    check-cast v0, Ljava/util/List;

    .line 2193
    .line 2194
    check-cast v11, Lay0/a;

    .line 2195
    .line 2196
    check-cast v10, Lay0/k;

    .line 2197
    .line 2198
    move-object/from16 v1, p1

    .line 2199
    .line 2200
    check-cast v1, Ll2/o;

    .line 2201
    .line 2202
    move-object/from16 v2, p2

    .line 2203
    .line 2204
    check-cast v2, Ljava/lang/Integer;

    .line 2205
    .line 2206
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2207
    .line 2208
    .line 2209
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 2210
    .line 2211
    .line 2212
    move-result v2

    .line 2213
    invoke-static {v2, v11, v10, v0, v1}, Lf20/a;->g(ILay0/a;Lay0/k;Ljava/util/List;Ll2/o;)V

    .line 2214
    .line 2215
    .line 2216
    return-object v36

    .line 2217
    :pswitch_1a
    move-object/from16 v36, v9

    .line 2218
    .line 2219
    move v9, v8

    .line 2220
    check-cast v0, Le20/c;

    .line 2221
    .line 2222
    check-cast v11, Lay0/a;

    .line 2223
    .line 2224
    check-cast v10, Lay0/a;

    .line 2225
    .line 2226
    move-object/from16 v1, p1

    .line 2227
    .line 2228
    check-cast v1, Ll2/o;

    .line 2229
    .line 2230
    move-object/from16 v2, p2

    .line 2231
    .line 2232
    check-cast v2, Ljava/lang/Integer;

    .line 2233
    .line 2234
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2235
    .line 2236
    .line 2237
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 2238
    .line 2239
    .line 2240
    move-result v2

    .line 2241
    invoke-static {v0, v11, v10, v1, v2}, Lf20/a;->f(Le20/c;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 2242
    .line 2243
    .line 2244
    return-object v36

    .line 2245
    :pswitch_1b
    move v15, v7

    .line 2246
    move-object/from16 v36, v9

    .line 2247
    .line 2248
    check-cast v0, Lx2/s;

    .line 2249
    .line 2250
    move-object/from16 v37, v11

    .line 2251
    .line 2252
    check-cast v37, Ljava/lang/String;

    .line 2253
    .line 2254
    check-cast v10, Ll2/t2;

    .line 2255
    .line 2256
    move-object/from16 v1, p1

    .line 2257
    .line 2258
    check-cast v1, Ll2/o;

    .line 2259
    .line 2260
    move-object/from16 v3, p2

    .line 2261
    .line 2262
    check-cast v3, Ljava/lang/Integer;

    .line 2263
    .line 2264
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 2265
    .line 2266
    .line 2267
    move-result v3

    .line 2268
    and-int/lit8 v4, v3, 0x3

    .line 2269
    .line 2270
    const/4 v12, 0x2

    .line 2271
    if-eq v4, v12, :cond_2e

    .line 2272
    .line 2273
    const/4 v7, 0x1

    .line 2274
    :goto_23
    const/16 v35, 0x1

    .line 2275
    .line 2276
    goto :goto_24

    .line 2277
    :cond_2e
    move v7, v15

    .line 2278
    goto :goto_23

    .line 2279
    :goto_24
    and-int/lit8 v3, v3, 0x1

    .line 2280
    .line 2281
    check-cast v1, Ll2/t;

    .line 2282
    .line 2283
    invoke-virtual {v1, v3, v7}, Ll2/t;->O(IZ)Z

    .line 2284
    .line 2285
    .line 2286
    move-result v3

    .line 2287
    if-eqz v3, :cond_32

    .line 2288
    .line 2289
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 2290
    .line 2291
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2292
    .line 2293
    .line 2294
    move-result-object v4

    .line 2295
    check-cast v4, Lj91/c;

    .line 2296
    .line 2297
    iget v4, v4, Lj91/c;->e:F

    .line 2298
    .line 2299
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2300
    .line 2301
    .line 2302
    move-result-object v5

    .line 2303
    check-cast v5, Lj91/c;

    .line 2304
    .line 2305
    iget v5, v5, Lj91/c;->e:F

    .line 2306
    .line 2307
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2308
    .line 2309
    .line 2310
    move-result-object v6

    .line 2311
    check-cast v6, Lj91/c;

    .line 2312
    .line 2313
    iget v6, v6, Lj91/c;->b:F

    .line 2314
    .line 2315
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2316
    .line 2317
    .line 2318
    move-result-object v7

    .line 2319
    check-cast v7, Lj91/c;

    .line 2320
    .line 2321
    iget v7, v7, Lj91/c;->b:F

    .line 2322
    .line 2323
    invoke-static {v0, v4, v6, v5, v7}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 2324
    .line 2325
    .line 2326
    move-result-object v0

    .line 2327
    sget-object v4, Lx2/c;->n:Lx2/i;

    .line 2328
    .line 2329
    sget-object v5, Lk1/j;->a:Lk1/c;

    .line 2330
    .line 2331
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2332
    .line 2333
    .line 2334
    move-result-object v3

    .line 2335
    check-cast v3, Lj91/c;

    .line 2336
    .line 2337
    iget v3, v3, Lj91/c;->b:F

    .line 2338
    .line 2339
    invoke-static {v3}, Lk1/j;->g(F)Lk1/h;

    .line 2340
    .line 2341
    .line 2342
    move-result-object v3

    .line 2343
    invoke-static {v3, v4, v1, v2}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 2344
    .line 2345
    .line 2346
    move-result-object v2

    .line 2347
    iget-wide v3, v1, Ll2/t;->T:J

    .line 2348
    .line 2349
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 2350
    .line 2351
    .line 2352
    move-result v3

    .line 2353
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 2354
    .line 2355
    .line 2356
    move-result-object v4

    .line 2357
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 2358
    .line 2359
    .line 2360
    move-result-object v0

    .line 2361
    sget-object v5, Lv3/k;->m1:Lv3/j;

    .line 2362
    .line 2363
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2364
    .line 2365
    .line 2366
    sget-object v5, Lv3/j;->b:Lv3/i;

    .line 2367
    .line 2368
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 2369
    .line 2370
    .line 2371
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 2372
    .line 2373
    if-eqz v6, :cond_2f

    .line 2374
    .line 2375
    invoke-virtual {v1, v5}, Ll2/t;->l(Lay0/a;)V

    .line 2376
    .line 2377
    .line 2378
    goto :goto_25

    .line 2379
    :cond_2f
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 2380
    .line 2381
    .line 2382
    :goto_25
    sget-object v5, Lv3/j;->g:Lv3/h;

    .line 2383
    .line 2384
    invoke-static {v5, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 2385
    .line 2386
    .line 2387
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 2388
    .line 2389
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 2390
    .line 2391
    .line 2392
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 2393
    .line 2394
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 2395
    .line 2396
    if-nez v4, :cond_30

    .line 2397
    .line 2398
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 2399
    .line 2400
    .line 2401
    move-result-object v4

    .line 2402
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2403
    .line 2404
    .line 2405
    move-result-object v5

    .line 2406
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2407
    .line 2408
    .line 2409
    move-result v4

    .line 2410
    if-nez v4, :cond_31

    .line 2411
    .line 2412
    :cond_30
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 2413
    .line 2414
    .line 2415
    :cond_31
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 2416
    .line 2417
    invoke-static {v2, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 2418
    .line 2419
    .line 2420
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 2421
    .line 2422
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 2423
    .line 2424
    .line 2425
    move-result-object v0

    .line 2426
    check-cast v0, Lj91/f;

    .line 2427
    .line 2428
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 2429
    .line 2430
    .line 2431
    move-result-object v38

    .line 2432
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 2433
    .line 2434
    .line 2435
    move-result-object v0

    .line 2436
    check-cast v0, Le3/s;

    .line 2437
    .line 2438
    iget-wide v2, v0, Le3/s;->a:J

    .line 2439
    .line 2440
    const/16 v57, 0x6180

    .line 2441
    .line 2442
    const v58, 0xaff4

    .line 2443
    .line 2444
    .line 2445
    const/16 v39, 0x0

    .line 2446
    .line 2447
    const-wide/16 v42, 0x0

    .line 2448
    .line 2449
    const/16 v44, 0x0

    .line 2450
    .line 2451
    const-wide/16 v45, 0x0

    .line 2452
    .line 2453
    const/16 v47, 0x0

    .line 2454
    .line 2455
    const/16 v48, 0x0

    .line 2456
    .line 2457
    const-wide/16 v49, 0x0

    .line 2458
    .line 2459
    const/16 v51, 0x2

    .line 2460
    .line 2461
    const/16 v52, 0x0

    .line 2462
    .line 2463
    const/16 v53, 0x1

    .line 2464
    .line 2465
    const/16 v54, 0x0

    .line 2466
    .line 2467
    const/16 v56, 0x0

    .line 2468
    .line 2469
    move-object/from16 v55, v1

    .line 2470
    .line 2471
    move-wide/from16 v40, v2

    .line 2472
    .line 2473
    invoke-static/range {v37 .. v58}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 2474
    .line 2475
    .line 2476
    const/4 v9, 0x1

    .line 2477
    invoke-virtual {v1, v9}, Ll2/t;->q(Z)V

    .line 2478
    .line 2479
    .line 2480
    goto :goto_26

    .line 2481
    :cond_32
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 2482
    .line 2483
    .line 2484
    :goto_26
    return-object v36

    .line 2485
    :pswitch_1c
    move-object/from16 v36, v9

    .line 2486
    .line 2487
    move v9, v8

    .line 2488
    check-cast v0, Le20/f;

    .line 2489
    .line 2490
    check-cast v11, Lay0/a;

    .line 2491
    .line 2492
    check-cast v10, Lay0/a;

    .line 2493
    .line 2494
    move-object/from16 v1, p1

    .line 2495
    .line 2496
    check-cast v1, Ll2/o;

    .line 2497
    .line 2498
    move-object/from16 v2, p2

    .line 2499
    .line 2500
    check-cast v2, Ljava/lang/Integer;

    .line 2501
    .line 2502
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2503
    .line 2504
    .line 2505
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 2506
    .line 2507
    .line 2508
    move-result v2

    .line 2509
    invoke-static {v0, v11, v10, v1, v2}, Lf20/j;->h(Le20/f;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 2510
    .line 2511
    .line 2512
    return-object v36

    .line 2513
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
