.class public final synthetic Lh70/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Llx0/e;

.field public final synthetic g:Lql0/h;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lg70/i;Lg61/p;ZLay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lh70/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh70/l;->g:Lql0/h;

    iput-object p2, p0, Lh70/l;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Lh70/l;->e:Z

    iput-object p4, p0, Lh70/l;->f:Llx0/e;

    return-void
.end method

.method public synthetic constructor <init>(Lm70/l;Lm70/j;Lay0/k;Z)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Lh70/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh70/l;->g:Lql0/h;

    iput-object p2, p0, Lh70/l;->h:Ljava/lang/Object;

    iput-object p3, p0, Lh70/l;->f:Llx0/e;

    iput-boolean p4, p0, Lh70/l;->e:Z

    return-void
.end method

.method public synthetic constructor <init>(Lnt0/e;ZLay0/n;Lay0/a;)V
    .locals 1

    .line 3
    const/4 v0, 0x3

    iput v0, p0, Lh70/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh70/l;->g:Lql0/h;

    iput-boolean p2, p0, Lh70/l;->e:Z

    iput-object p3, p0, Lh70/l;->h:Ljava/lang/Object;

    iput-object p4, p0, Lh70/l;->f:Llx0/e;

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/a;Lh40/s3;Lay0/a;)V
    .locals 1

    .line 4
    const/4 v0, 0x1

    iput v0, p0, Lh70/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lh70/l;->e:Z

    iput-object p2, p0, Lh70/l;->f:Llx0/e;

    iput-object p3, p0, Lh70/l;->g:Lql0/h;

    iput-object p4, p0, Lh70/l;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh70/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lh70/l;->g:Lql0/h;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Lnt0/e;

    .line 12
    .line 13
    iget-object v1, v0, Lh70/l;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v1

    .line 16
    check-cast v3, Lay0/n;

    .line 17
    .line 18
    iget-object v1, v0, Lh70/l;->f:Llx0/e;

    .line 19
    .line 20
    move-object v4, v1

    .line 21
    check-cast v4, Lay0/a;

    .line 22
    .line 23
    move-object/from16 v1, p1

    .line 24
    .line 25
    check-cast v1, Lk1/q;

    .line 26
    .line 27
    move-object/from16 v5, p2

    .line 28
    .line 29
    check-cast v5, Ll2/o;

    .line 30
    .line 31
    move-object/from16 v6, p3

    .line 32
    .line 33
    check-cast v6, Ljava/lang/Integer;

    .line 34
    .line 35
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 36
    .line 37
    .line 38
    move-result v6

    .line 39
    const-string v7, "$this$PullToRefreshBox"

    .line 40
    .line 41
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    and-int/lit8 v1, v6, 0x11

    .line 45
    .line 46
    const/16 v7, 0x10

    .line 47
    .line 48
    const/4 v8, 0x1

    .line 49
    const/4 v9, 0x0

    .line 50
    if-eq v1, v7, :cond_0

    .line 51
    .line 52
    move v1, v8

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    move v1, v9

    .line 55
    :goto_0
    and-int/2addr v6, v8

    .line 56
    check-cast v5, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v5, v6, v1}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    iget-boolean v1, v2, Lnt0/e;->d:Z

    .line 65
    .line 66
    if-eqz v1, :cond_1

    .line 67
    .line 68
    const v0, -0x7a648044

    .line 69
    .line 70
    .line 71
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 72
    .line 73
    .line 74
    invoke-static {v5, v9}, Lot0/a;->i(Ll2/o;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_1
    const v1, -0x7a634075

    .line 82
    .line 83
    .line 84
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 85
    .line 86
    .line 87
    iget-boolean v0, v0, Lh70/l;->e:Z

    .line 88
    .line 89
    xor-int/2addr v0, v8

    .line 90
    const/4 v7, 0x0

    .line 91
    move-object v6, v5

    .line 92
    move v5, v0

    .line 93
    invoke-static/range {v2 .. v7}, Lot0/a;->a(Lnt0/e;Lay0/n;Lay0/a;ZLl2/o;I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v6, v9}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_2
    move-object v6, v5

    .line 101
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 102
    .line 103
    .line 104
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object v0

    .line 107
    :pswitch_0
    iget-object v1, v0, Lh70/l;->g:Lql0/h;

    .line 108
    .line 109
    check-cast v1, Lm70/l;

    .line 110
    .line 111
    iget-object v2, v0, Lh70/l;->h:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v2, Lm70/j;

    .line 114
    .line 115
    iget-object v3, v0, Lh70/l;->f:Llx0/e;

    .line 116
    .line 117
    check-cast v3, Lay0/k;

    .line 118
    .line 119
    move-object/from16 v4, p1

    .line 120
    .line 121
    check-cast v4, Lb1/a0;

    .line 122
    .line 123
    move-object/from16 v5, p2

    .line 124
    .line 125
    check-cast v5, Ll2/o;

    .line 126
    .line 127
    move-object/from16 v6, p3

    .line 128
    .line 129
    check-cast v6, Ljava/lang/Integer;

    .line 130
    .line 131
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    const-string v6, "$this$AnimatedVisibility"

    .line 135
    .line 136
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    iget-object v1, v1, Lm70/l;->i:Ljava/util/List;

    .line 140
    .line 141
    invoke-interface {v1, v2}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    const/4 v4, 0x0

    .line 146
    const/4 v6, 0x0

    .line 147
    if-lez v1, :cond_3

    .line 148
    .line 149
    move-object v1, v5

    .line 150
    check-cast v1, Ll2/t;

    .line 151
    .line 152
    const v7, -0x68ef4aa0

    .line 153
    .line 154
    .line 155
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 156
    .line 157
    .line 158
    const/4 v7, 0x1

    .line 159
    invoke-static {v6, v7, v1, v4}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 160
    .line 161
    .line 162
    :goto_2
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 163
    .line 164
    .line 165
    goto :goto_3

    .line 166
    :cond_3
    move-object v1, v5

    .line 167
    check-cast v1, Ll2/t;

    .line 168
    .line 169
    const v7, 0x4a749ff9    # 4007934.2f

    .line 170
    .line 171
    .line 172
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 173
    .line 174
    .line 175
    goto :goto_2

    .line 176
    :goto_3
    iget-boolean v0, v0, Lh70/l;->e:Z

    .line 177
    .line 178
    if-eqz v0, :cond_4

    .line 179
    .line 180
    goto :goto_4

    .line 181
    :cond_4
    move-object v3, v4

    .line 182
    :goto_4
    move-object v0, v5

    .line 183
    check-cast v0, Ll2/t;

    .line 184
    .line 185
    if-nez v3, :cond_6

    .line 186
    .line 187
    const v1, 0x4b079697    # 8885911.0f

    .line 188
    .line 189
    .line 190
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 198
    .line 199
    if-ne v1, v3, :cond_5

    .line 200
    .line 201
    new-instance v1, Lmj/g;

    .line 202
    .line 203
    const/16 v3, 0x16

    .line 204
    .line 205
    invoke-direct {v1, v3}, Lmj/g;-><init>(I)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :cond_5
    move-object v3, v1

    .line 212
    check-cast v3, Lay0/k;

    .line 213
    .line 214
    :goto_5
    invoke-virtual {v0, v6}, Ll2/t;->q(Z)V

    .line 215
    .line 216
    .line 217
    goto :goto_6

    .line 218
    :cond_6
    const v1, -0x68ef42e6

    .line 219
    .line 220
    .line 221
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 222
    .line 223
    .line 224
    goto :goto_5

    .line 225
    :goto_6
    invoke-static {v2, v3, v5, v6}, Ln70/a;->S(Lm70/j;Lay0/k;Ll2/o;I)V

    .line 226
    .line 227
    .line 228
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    return-object v0

    .line 231
    :pswitch_1
    iget-object v1, v0, Lh70/l;->f:Llx0/e;

    .line 232
    .line 233
    move-object v4, v1

    .line 234
    check-cast v4, Lay0/a;

    .line 235
    .line 236
    iget-object v1, v0, Lh70/l;->g:Lql0/h;

    .line 237
    .line 238
    check-cast v1, Lh40/s3;

    .line 239
    .line 240
    iget-object v2, v0, Lh70/l;->h:Ljava/lang/Object;

    .line 241
    .line 242
    move-object v10, v2

    .line 243
    check-cast v10, Lay0/a;

    .line 244
    .line 245
    move-object/from16 v2, p1

    .line 246
    .line 247
    check-cast v2, Landroidx/compose/foundation/lazy/a;

    .line 248
    .line 249
    move-object/from16 v3, p2

    .line 250
    .line 251
    check-cast v3, Ll2/o;

    .line 252
    .line 253
    move-object/from16 v5, p3

    .line 254
    .line 255
    check-cast v5, Ljava/lang/Integer;

    .line 256
    .line 257
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 258
    .line 259
    .line 260
    move-result v5

    .line 261
    const-string v6, "$this$item"

    .line 262
    .line 263
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    and-int/lit8 v2, v5, 0x11

    .line 267
    .line 268
    const/16 v6, 0x10

    .line 269
    .line 270
    const/4 v13, 0x1

    .line 271
    const/4 v14, 0x0

    .line 272
    if-eq v2, v6, :cond_7

    .line 273
    .line 274
    move v2, v13

    .line 275
    goto :goto_7

    .line 276
    :cond_7
    move v2, v14

    .line 277
    :goto_7
    and-int/2addr v5, v13

    .line 278
    move-object v7, v3

    .line 279
    check-cast v7, Ll2/t;

    .line 280
    .line 281
    invoke-virtual {v7, v5, v2}, Ll2/t;->O(IZ)Z

    .line 282
    .line 283
    .line 284
    move-result v2

    .line 285
    if-eqz v2, :cond_d

    .line 286
    .line 287
    sget-object v15, Lj91/a;->a:Ll2/u2;

    .line 288
    .line 289
    invoke-virtual {v7, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v2

    .line 293
    check-cast v2, Lj91/c;

    .line 294
    .line 295
    iget v2, v2, Lj91/c;->k:F

    .line 296
    .line 297
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 298
    .line 299
    const/4 v12, 0x0

    .line 300
    const/4 v3, 0x2

    .line 301
    invoke-static {v11, v2, v12, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 302
    .line 303
    .line 304
    move-result-object v2

    .line 305
    sget-object v5, Lk1/j;->a:Lk1/c;

    .line 306
    .line 307
    sget-object v6, Lx2/c;->m:Lx2/i;

    .line 308
    .line 309
    invoke-static {v5, v6, v7, v14}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 310
    .line 311
    .line 312
    move-result-object v5

    .line 313
    iget-wide v8, v7, Ll2/t;->T:J

    .line 314
    .line 315
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 316
    .line 317
    .line 318
    move-result v6

    .line 319
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 320
    .line 321
    .line 322
    move-result-object v8

    .line 323
    invoke-static {v7, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 324
    .line 325
    .line 326
    move-result-object v2

    .line 327
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 328
    .line 329
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 330
    .line 331
    .line 332
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 333
    .line 334
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 335
    .line 336
    .line 337
    iget-boolean v3, v7, Ll2/t;->S:Z

    .line 338
    .line 339
    if-eqz v3, :cond_8

    .line 340
    .line 341
    invoke-virtual {v7, v9}, Ll2/t;->l(Lay0/a;)V

    .line 342
    .line 343
    .line 344
    goto :goto_8

    .line 345
    :cond_8
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 346
    .line 347
    .line 348
    :goto_8
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 349
    .line 350
    invoke-static {v3, v5, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 351
    .line 352
    .line 353
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 354
    .line 355
    invoke-static {v3, v8, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 356
    .line 357
    .line 358
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 359
    .line 360
    iget-boolean v5, v7, Ll2/t;->S:Z

    .line 361
    .line 362
    if-nez v5, :cond_9

    .line 363
    .line 364
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v5

    .line 368
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 369
    .line 370
    .line 371
    move-result-object v8

    .line 372
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    move-result v5

    .line 376
    if-nez v5, :cond_a

    .line 377
    .line 378
    :cond_9
    invoke-static {v6, v7, v6, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 379
    .line 380
    .line 381
    :cond_a
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 382
    .line 383
    invoke-static {v3, v2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 384
    .line 385
    .line 386
    const v2, 0x7f120eb7

    .line 387
    .line 388
    .line 389
    invoke-static {v7, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 390
    .line 391
    .line 392
    move-result-object v6

    .line 393
    invoke-static {v11, v2}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 394
    .line 395
    .line 396
    move-result-object v8

    .line 397
    const/4 v2, 0x0

    .line 398
    const/16 v3, 0x18

    .line 399
    .line 400
    const/4 v5, 0x0

    .line 401
    const/4 v9, 0x0

    .line 402
    invoke-static/range {v2 .. v9}, Li91/j0;->h0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 403
    .line 404
    .line 405
    iget-boolean v1, v1, Lh40/s3;->q:Z

    .line 406
    .line 407
    if-eqz v1, :cond_b

    .line 408
    .line 409
    const v1, -0x474dec8a

    .line 410
    .line 411
    .line 412
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 413
    .line 414
    .line 415
    invoke-virtual {v7, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v1

    .line 419
    check-cast v1, Lj91/c;

    .line 420
    .line 421
    iget v1, v1, Lj91/c;->d:F

    .line 422
    .line 423
    const v2, 0x7f120eb6

    .line 424
    .line 425
    .line 426
    invoke-static {v11, v1, v7, v2, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->p(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v9

    .line 430
    invoke-static {v11, v2}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 431
    .line 432
    .line 433
    move-result-object v1

    .line 434
    const/4 v5, 0x0

    .line 435
    const/16 v6, 0x18

    .line 436
    .line 437
    const/4 v8, 0x0

    .line 438
    move v2, v12

    .line 439
    const/4 v12, 0x0

    .line 440
    move-object/from16 v33, v11

    .line 441
    .line 442
    move-object v11, v1

    .line 443
    move-object/from16 v1, v33

    .line 444
    .line 445
    move-object/from16 v33, v10

    .line 446
    .line 447
    move-object v10, v7

    .line 448
    move-object/from16 v7, v33

    .line 449
    .line 450
    invoke-static/range {v5 .. v12}, Li91/j0;->w0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 451
    .line 452
    .line 453
    move-object v7, v10

    .line 454
    :goto_9
    invoke-virtual {v7, v14}, Ll2/t;->q(Z)V

    .line 455
    .line 456
    .line 457
    goto :goto_a

    .line 458
    :cond_b
    move-object v1, v11

    .line 459
    move v2, v12

    .line 460
    const v3, -0x480dcb50

    .line 461
    .line 462
    .line 463
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 464
    .line 465
    .line 466
    goto :goto_9

    .line 467
    :goto_a
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 468
    .line 469
    .line 470
    iget-boolean v0, v0, Lh70/l;->e:Z

    .line 471
    .line 472
    if-eqz v0, :cond_c

    .line 473
    .line 474
    const v0, -0x578a06f

    .line 475
    .line 476
    .line 477
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 478
    .line 479
    .line 480
    invoke-virtual {v7, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v0

    .line 484
    check-cast v0, Lj91/c;

    .line 485
    .line 486
    iget v0, v0, Lj91/c;->e:F

    .line 487
    .line 488
    invoke-static {v1, v0, v7, v15}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    check-cast v0, Lj91/c;

    .line 493
    .line 494
    iget v0, v0, Lj91/c;->k:F

    .line 495
    .line 496
    const/4 v3, 0x2

    .line 497
    invoke-static {v1, v0, v2, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 498
    .line 499
    .line 500
    move-result-object v0

    .line 501
    invoke-static {v14, v14, v7, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 502
    .line 503
    .line 504
    invoke-virtual {v7, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v0

    .line 508
    check-cast v0, Lj91/c;

    .line 509
    .line 510
    iget v0, v0, Lj91/c;->e:F

    .line 511
    .line 512
    invoke-static {v1, v0, v7, v14}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 513
    .line 514
    .line 515
    goto :goto_b

    .line 516
    :cond_c
    const v0, -0x63ecf34

    .line 517
    .line 518
    .line 519
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 520
    .line 521
    .line 522
    invoke-virtual {v7, v14}, Ll2/t;->q(Z)V

    .line 523
    .line 524
    .line 525
    goto :goto_b

    .line 526
    :cond_d
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 527
    .line 528
    .line 529
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 530
    .line 531
    return-object v0

    .line 532
    :pswitch_2
    iget-object v1, v0, Lh70/l;->g:Lql0/h;

    .line 533
    .line 534
    check-cast v1, Lg70/i;

    .line 535
    .line 536
    iget-object v2, v0, Lh70/l;->h:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast v2, Lg61/p;

    .line 539
    .line 540
    iget-object v3, v0, Lh70/l;->f:Llx0/e;

    .line 541
    .line 542
    check-cast v3, Lay0/a;

    .line 543
    .line 544
    move-object/from16 v4, p1

    .line 545
    .line 546
    check-cast v4, Lk1/z0;

    .line 547
    .line 548
    move-object/from16 v5, p2

    .line 549
    .line 550
    check-cast v5, Ll2/o;

    .line 551
    .line 552
    move-object/from16 v6, p3

    .line 553
    .line 554
    check-cast v6, Ljava/lang/Integer;

    .line 555
    .line 556
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 557
    .line 558
    .line 559
    move-result v6

    .line 560
    const-string v7, "paddingValues"

    .line 561
    .line 562
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 563
    .line 564
    .line 565
    and-int/lit8 v7, v6, 0x6

    .line 566
    .line 567
    if-nez v7, :cond_f

    .line 568
    .line 569
    move-object v7, v5

    .line 570
    check-cast v7, Ll2/t;

    .line 571
    .line 572
    invoke-virtual {v7, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 573
    .line 574
    .line 575
    move-result v7

    .line 576
    if-eqz v7, :cond_e

    .line 577
    .line 578
    const/4 v7, 0x4

    .line 579
    goto :goto_c

    .line 580
    :cond_e
    const/4 v7, 0x2

    .line 581
    :goto_c
    or-int/2addr v6, v7

    .line 582
    :cond_f
    and-int/lit8 v7, v6, 0x13

    .line 583
    .line 584
    const/16 v8, 0x12

    .line 585
    .line 586
    const/4 v9, 0x1

    .line 587
    const/4 v10, 0x0

    .line 588
    if-eq v7, v8, :cond_10

    .line 589
    .line 590
    move v7, v9

    .line 591
    goto :goto_d

    .line 592
    :cond_10
    move v7, v10

    .line 593
    :goto_d
    and-int/2addr v6, v9

    .line 594
    check-cast v5, Ll2/t;

    .line 595
    .line 596
    invoke-virtual {v5, v6, v7}, Ll2/t;->O(IZ)Z

    .line 597
    .line 598
    .line 599
    move-result v6

    .line 600
    if-eqz v6, :cond_1a

    .line 601
    .line 602
    sget-object v6, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 603
    .line 604
    invoke-static {v5}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 605
    .line 606
    .line 607
    move-result-object v7

    .line 608
    invoke-virtual {v7}, Lj91/e;->b()J

    .line 609
    .line 610
    .line 611
    move-result-wide v7

    .line 612
    sget-object v11, Le3/j0;->a:Le3/i0;

    .line 613
    .line 614
    invoke-static {v6, v7, v8, v11}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 615
    .line 616
    .line 617
    move-result-object v6

    .line 618
    invoke-static {v5}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 619
    .line 620
    .line 621
    move-result-object v7

    .line 622
    iget v7, v7, Lj91/c;->l:F

    .line 623
    .line 624
    invoke-interface {v4}, Lk1/z0;->d()F

    .line 625
    .line 626
    .line 627
    move-result v8

    .line 628
    add-float/2addr v8, v7

    .line 629
    invoke-static {v5}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 630
    .line 631
    .line 632
    move-result-object v7

    .line 633
    iget v7, v7, Lj91/c;->k:F

    .line 634
    .line 635
    invoke-static {v5}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 636
    .line 637
    .line 638
    move-result-object v11

    .line 639
    iget v11, v11, Lj91/c;->k:F

    .line 640
    .line 641
    invoke-interface {v4}, Lk1/z0;->c()F

    .line 642
    .line 643
    .line 644
    move-result v4

    .line 645
    sget-object v12, Lj91/a;->a:Ll2/u2;

    .line 646
    .line 647
    invoke-virtual {v5, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 648
    .line 649
    .line 650
    move-result-object v12

    .line 651
    check-cast v12, Lj91/c;

    .line 652
    .line 653
    iget v12, v12, Lj91/c;->e:F

    .line 654
    .line 655
    sub-float/2addr v4, v12

    .line 656
    new-instance v12, Lt4/f;

    .line 657
    .line 658
    invoke-direct {v12, v4}, Lt4/f;-><init>(F)V

    .line 659
    .line 660
    .line 661
    int-to-float v4, v10

    .line 662
    invoke-static {v4, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->j(FLt4/f;)Ljava/lang/Comparable;

    .line 663
    .line 664
    .line 665
    move-result-object v4

    .line 666
    check-cast v4, Lt4/f;

    .line 667
    .line 668
    iget v4, v4, Lt4/f;->d:F

    .line 669
    .line 670
    invoke-static {v6, v7, v8, v11, v4}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 671
    .line 672
    .line 673
    move-result-object v4

    .line 674
    invoke-static {v10, v9, v5}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 675
    .line 676
    .line 677
    move-result-object v6

    .line 678
    const/16 v7, 0xe

    .line 679
    .line 680
    invoke-static {v4, v6, v7}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 681
    .line 682
    .line 683
    move-result-object v4

    .line 684
    sget-object v6, Lk1/j;->c:Lk1/e;

    .line 685
    .line 686
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 687
    .line 688
    invoke-static {v6, v7, v5, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 689
    .line 690
    .line 691
    move-result-object v6

    .line 692
    iget-wide v7, v5, Ll2/t;->T:J

    .line 693
    .line 694
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 695
    .line 696
    .line 697
    move-result v7

    .line 698
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 699
    .line 700
    .line 701
    move-result-object v8

    .line 702
    invoke-static {v5, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 703
    .line 704
    .line 705
    move-result-object v4

    .line 706
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 707
    .line 708
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 709
    .line 710
    .line 711
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 712
    .line 713
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 714
    .line 715
    .line 716
    iget-boolean v12, v5, Ll2/t;->S:Z

    .line 717
    .line 718
    if-eqz v12, :cond_11

    .line 719
    .line 720
    invoke-virtual {v5, v11}, Ll2/t;->l(Lay0/a;)V

    .line 721
    .line 722
    .line 723
    goto :goto_e

    .line 724
    :cond_11
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 725
    .line 726
    .line 727
    :goto_e
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 728
    .line 729
    invoke-static {v12, v6, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 730
    .line 731
    .line 732
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 733
    .line 734
    invoke-static {v6, v8, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 735
    .line 736
    .line 737
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 738
    .line 739
    iget-boolean v13, v5, Ll2/t;->S:Z

    .line 740
    .line 741
    if-nez v13, :cond_12

    .line 742
    .line 743
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 744
    .line 745
    .line 746
    move-result-object v13

    .line 747
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 748
    .line 749
    .line 750
    move-result-object v14

    .line 751
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 752
    .line 753
    .line 754
    move-result v13

    .line 755
    if-nez v13, :cond_13

    .line 756
    .line 757
    :cond_12
    invoke-static {v7, v5, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 758
    .line 759
    .line 760
    :cond_13
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 761
    .line 762
    invoke-static {v7, v4, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 763
    .line 764
    .line 765
    move-object v4, v11

    .line 766
    iget-object v11, v1, Lg70/i;->a:Ljava/lang/String;

    .line 767
    .line 768
    invoke-static {v5}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 769
    .line 770
    .line 771
    move-result-object v13

    .line 772
    invoke-virtual {v13}, Lj91/f;->j()Lg4/p0;

    .line 773
    .line 774
    .line 775
    move-result-object v13

    .line 776
    const/16 v31, 0x0

    .line 777
    .line 778
    const v32, 0xfffc

    .line 779
    .line 780
    .line 781
    move-object v14, v12

    .line 782
    move-object v12, v13

    .line 783
    const/4 v13, 0x0

    .line 784
    move-object/from16 v16, v14

    .line 785
    .line 786
    const-wide/16 v14, 0x0

    .line 787
    .line 788
    move-object/from16 v18, v16

    .line 789
    .line 790
    const-wide/16 v16, 0x0

    .line 791
    .line 792
    move-object/from16 v19, v18

    .line 793
    .line 794
    const/16 v18, 0x0

    .line 795
    .line 796
    move-object/from16 v21, v19

    .line 797
    .line 798
    const-wide/16 v19, 0x0

    .line 799
    .line 800
    move-object/from16 v22, v21

    .line 801
    .line 802
    const/16 v21, 0x0

    .line 803
    .line 804
    move-object/from16 v23, v22

    .line 805
    .line 806
    const/16 v22, 0x0

    .line 807
    .line 808
    move-object/from16 v25, v23

    .line 809
    .line 810
    const-wide/16 v23, 0x0

    .line 811
    .line 812
    move-object/from16 v26, v25

    .line 813
    .line 814
    const/16 v25, 0x0

    .line 815
    .line 816
    move-object/from16 v27, v26

    .line 817
    .line 818
    const/16 v26, 0x0

    .line 819
    .line 820
    move-object/from16 v28, v27

    .line 821
    .line 822
    const/16 v27, 0x0

    .line 823
    .line 824
    move-object/from16 v29, v28

    .line 825
    .line 826
    const/16 v28, 0x0

    .line 827
    .line 828
    const/16 v30, 0x0

    .line 829
    .line 830
    move-object/from16 v33, v29

    .line 831
    .line 832
    move-object/from16 v29, v5

    .line 833
    .line 834
    move-object/from16 v5, v33

    .line 835
    .line 836
    invoke-static/range {v11 .. v32}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 837
    .line 838
    .line 839
    move-object/from16 v11, v29

    .line 840
    .line 841
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 842
    .line 843
    .line 844
    move-result-object v12

    .line 845
    iget v12, v12, Lj91/c;->b:F

    .line 846
    .line 847
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 848
    .line 849
    invoke-static {v13, v12}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 850
    .line 851
    .line 852
    move-result-object v12

    .line 853
    invoke-static {v11, v12}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 854
    .line 855
    .line 856
    sget-object v12, Lk1/j;->a:Lk1/c;

    .line 857
    .line 858
    sget-object v14, Lx2/c;->m:Lx2/i;

    .line 859
    .line 860
    invoke-static {v12, v14, v11, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 861
    .line 862
    .line 863
    move-result-object v12

    .line 864
    iget-wide v14, v11, Ll2/t;->T:J

    .line 865
    .line 866
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 867
    .line 868
    .line 869
    move-result v14

    .line 870
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 871
    .line 872
    .line 873
    move-result-object v15

    .line 874
    invoke-static {v11, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 875
    .line 876
    .line 877
    move-result-object v10

    .line 878
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 879
    .line 880
    .line 881
    iget-boolean v9, v11, Ll2/t;->S:Z

    .line 882
    .line 883
    if-eqz v9, :cond_14

    .line 884
    .line 885
    invoke-virtual {v11, v4}, Ll2/t;->l(Lay0/a;)V

    .line 886
    .line 887
    .line 888
    goto :goto_f

    .line 889
    :cond_14
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 890
    .line 891
    .line 892
    :goto_f
    invoke-static {v5, v12, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 893
    .line 894
    .line 895
    invoke-static {v6, v15, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 896
    .line 897
    .line 898
    iget-boolean v4, v11, Ll2/t;->S:Z

    .line 899
    .line 900
    if-nez v4, :cond_15

    .line 901
    .line 902
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 903
    .line 904
    .line 905
    move-result-object v4

    .line 906
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 907
    .line 908
    .line 909
    move-result-object v5

    .line 910
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 911
    .line 912
    .line 913
    move-result v4

    .line 914
    if-nez v4, :cond_16

    .line 915
    .line 916
    :cond_15
    invoke-static {v14, v11, v14, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 917
    .line 918
    .line 919
    :cond_16
    invoke-static {v7, v10, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 920
    .line 921
    .line 922
    iget-boolean v0, v0, Lh70/l;->e:Z

    .line 923
    .line 924
    const/4 v4, 0x1

    .line 925
    if-ne v0, v4, :cond_17

    .line 926
    .line 927
    const v4, 0x52a8f76a

    .line 928
    .line 929
    .line 930
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 931
    .line 932
    .line 933
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 934
    .line 935
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move-result-object v4

    .line 939
    check-cast v4, Lj91/e;

    .line 940
    .line 941
    invoke-virtual {v4}, Lj91/e;->n()J

    .line 942
    .line 943
    .line 944
    move-result-wide v4

    .line 945
    const/4 v6, 0x0

    .line 946
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 947
    .line 948
    .line 949
    :goto_10
    move-wide v14, v4

    .line 950
    const/4 v4, 0x1

    .line 951
    goto :goto_11

    .line 952
    :cond_17
    const/4 v6, 0x0

    .line 953
    const v4, 0x52a8fcaf

    .line 954
    .line 955
    .line 956
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 957
    .line 958
    .line 959
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 960
    .line 961
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 962
    .line 963
    .line 964
    move-result-object v4

    .line 965
    check-cast v4, Lj91/e;

    .line 966
    .line 967
    invoke-virtual {v4}, Lj91/e;->s()J

    .line 968
    .line 969
    .line 970
    move-result-wide v4

    .line 971
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 972
    .line 973
    .line 974
    goto :goto_10

    .line 975
    :goto_11
    if-ne v0, v4, :cond_18

    .line 976
    .line 977
    const v4, -0x5d2288da

    .line 978
    .line 979
    .line 980
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 981
    .line 982
    .line 983
    const v4, 0x7f080342

    .line 984
    .line 985
    .line 986
    invoke-static {v4, v6, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 987
    .line 988
    .line 989
    move-result-object v4

    .line 990
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 991
    .line 992
    .line 993
    goto :goto_12

    .line 994
    :cond_18
    const v4, -0x5d227bda

    .line 995
    .line 996
    .line 997
    invoke-virtual {v11, v4}, Ll2/t;->Y(I)V

    .line 998
    .line 999
    .line 1000
    const v4, 0x7f08034c

    .line 1001
    .line 1002
    .line 1003
    invoke-static {v4, v6, v11}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v4

    .line 1007
    invoke-virtual {v11, v6}, Ll2/t;->q(Z)V

    .line 1008
    .line 1009
    .line 1010
    :goto_12
    const/16 v17, 0x30

    .line 1011
    .line 1012
    const/16 v18, 0x4

    .line 1013
    .line 1014
    const/4 v12, 0x0

    .line 1015
    move-object v5, v13

    .line 1016
    const/4 v13, 0x0

    .line 1017
    move-object/from16 v16, v11

    .line 1018
    .line 1019
    move-object v11, v4

    .line 1020
    invoke-static/range {v11 .. v18}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 1021
    .line 1022
    .line 1023
    move-object/from16 v11, v16

    .line 1024
    .line 1025
    const/4 v4, 0x1

    .line 1026
    if-ne v0, v4, :cond_19

    .line 1027
    .line 1028
    const v4, -0x3864009c

    .line 1029
    .line 1030
    .line 1031
    const v7, 0x7f120f5c

    .line 1032
    .line 1033
    .line 1034
    :goto_13
    invoke-static {v4, v7, v11, v11, v6}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v4

    .line 1038
    goto :goto_14

    .line 1039
    :cond_19
    const v4, -0x3863f69a

    .line 1040
    .line 1041
    .line 1042
    const v7, 0x7f120f63

    .line 1043
    .line 1044
    .line 1045
    goto :goto_13

    .line 1046
    :goto_14
    invoke-static {v11}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v6

    .line 1050
    invoke-virtual {v6}, Lj91/f;->b()Lg4/p0;

    .line 1051
    .line 1052
    .line 1053
    move-result-object v12

    .line 1054
    const/16 v31, 0x0

    .line 1055
    .line 1056
    const v32, 0xfffc

    .line 1057
    .line 1058
    .line 1059
    const/4 v13, 0x0

    .line 1060
    const-wide/16 v14, 0x0

    .line 1061
    .line 1062
    const-wide/16 v16, 0x0

    .line 1063
    .line 1064
    const/16 v18, 0x0

    .line 1065
    .line 1066
    const-wide/16 v19, 0x0

    .line 1067
    .line 1068
    const/16 v21, 0x0

    .line 1069
    .line 1070
    const/16 v22, 0x0

    .line 1071
    .line 1072
    const-wide/16 v23, 0x0

    .line 1073
    .line 1074
    const/16 v25, 0x0

    .line 1075
    .line 1076
    const/16 v26, 0x0

    .line 1077
    .line 1078
    const/16 v27, 0x0

    .line 1079
    .line 1080
    const/16 v28, 0x0

    .line 1081
    .line 1082
    const/16 v30, 0x0

    .line 1083
    .line 1084
    move-object/from16 v29, v11

    .line 1085
    .line 1086
    move-object v11, v4

    .line 1087
    invoke-static/range {v11 .. v32}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1088
    .line 1089
    .line 1090
    move-object/from16 v11, v29

    .line 1091
    .line 1092
    const/4 v4, 0x1

    .line 1093
    invoke-virtual {v11, v4}, Ll2/t;->q(Z)V

    .line 1094
    .line 1095
    .line 1096
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v4

    .line 1100
    iget v4, v4, Lj91/c;->d:F

    .line 1101
    .line 1102
    invoke-static {v5, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 1103
    .line 1104
    .line 1105
    move-result-object v4

    .line 1106
    invoke-static {v11, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1107
    .line 1108
    .line 1109
    iget-object v12, v1, Lg70/i;->c:Lhp0/e;

    .line 1110
    .line 1111
    const/high16 v1, 0x3f800000    # 1.0f

    .line 1112
    .line 1113
    invoke-static {v5, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v1

    .line 1117
    sget v4, Lh70/m;->c:F

    .line 1118
    .line 1119
    invoke-static {v1, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v1

    .line 1123
    const/16 v17, 0x46

    .line 1124
    .line 1125
    const/16 v18, 0x1c

    .line 1126
    .line 1127
    const/4 v13, 0x0

    .line 1128
    const/4 v14, 0x0

    .line 1129
    const/4 v15, 0x0

    .line 1130
    move-object/from16 v16, v11

    .line 1131
    .line 1132
    move-object v11, v1

    .line 1133
    invoke-static/range {v11 .. v18}, Llp/xa;->c(Lx2/s;Lhp0/e;ILt3/k;Lay0/a;Ll2/o;II)V

    .line 1134
    .line 1135
    .line 1136
    move-object/from16 v11, v16

    .line 1137
    .line 1138
    invoke-static {v11}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1139
    .line 1140
    .line 1141
    move-result-object v1

    .line 1142
    iget v1, v1, Lj91/c;->d:F

    .line 1143
    .line 1144
    invoke-static {v5, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 1145
    .line 1146
    .line 1147
    move-result-object v1

    .line 1148
    invoke-static {v11, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1149
    .line 1150
    .line 1151
    const/4 v6, 0x0

    .line 1152
    invoke-static {v2, v0, v3, v11, v6}, Lh70/m;->j(Lg61/p;ZLay0/a;Ll2/o;I)V

    .line 1153
    .line 1154
    .line 1155
    const/4 v4, 0x1

    .line 1156
    invoke-virtual {v11, v4}, Ll2/t;->q(Z)V

    .line 1157
    .line 1158
    .line 1159
    goto :goto_15

    .line 1160
    :cond_1a
    move-object v11, v5

    .line 1161
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 1162
    .line 1163
    .line 1164
    :goto_15
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1165
    .line 1166
    return-object v0

    .line 1167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
