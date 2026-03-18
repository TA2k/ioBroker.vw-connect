.class public final Lf7/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lf7/f;->f:I

    iput-object p3, p0, Lf7/f;->h:Ljava/lang/Object;

    iput-object p4, p0, Lf7/f;->i:Ljava/lang/Object;

    iput-object p5, p0, Lf7/f;->g:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Llx0/e;)V
    .locals 0

    .line 2
    iput p1, p0, Lf7/f;->f:I

    iput-object p2, p0, Lf7/f;->h:Ljava/lang/Object;

    iput-object p3, p0, Lf7/f;->i:Ljava/lang/Object;

    iput-object p4, p0, Lf7/f;->g:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lx2/s;Lt2/b;Lt3/q0;I)V
    .locals 0

    const/4 p4, 0x1

    iput p4, p0, Lf7/f;->f:I

    .line 3
    iput-object p1, p0, Lf7/f;->h:Ljava/lang/Object;

    iput-object p2, p0, Lf7/f;->g:Ljava/lang/Object;

    iput-object p3, p0, Lf7/f;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf7/f;->f:I

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
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    iget-object v3, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v3, Lz4/k;

    .line 23
    .line 24
    const/4 v4, 0x3

    .line 25
    and-int/2addr v2, v4

    .line 26
    const/4 v5, 0x2

    .line 27
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    if-ne v2, v5, :cond_1

    .line 30
    .line 31
    move-object v2, v1

    .line 32
    check-cast v2, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-nez v5, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 42
    .line 43
    .line 44
    move-object/from16 p1, v6

    .line 45
    .line 46
    goto/16 :goto_2

    .line 47
    .line 48
    :cond_1
    :goto_0
    iget-object v2, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v2, Ll2/b1;

    .line 51
    .line 52
    invoke-interface {v2, v6}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget v2, v3, Lz4/k;->b:I

    .line 56
    .line 57
    invoke-virtual {v3}, Lz4/k;->e()V

    .line 58
    .line 59
    .line 60
    move-object v14, v1

    .line 61
    check-cast v14, Ll2/t;

    .line 62
    .line 63
    const v1, 0x5520dc70

    .line 64
    .line 65
    .line 66
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v3}, Lz4/k;->d()Lt1/j0;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    iget-object v1, v1, Lt1/j0;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v1, Lz4/k;

    .line 76
    .line 77
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    invoke-virtual {v1}, Lz4/k;->c()Lz4/f;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    const v7, 0x7f080239

    .line 86
    .line 87
    .line 88
    const/4 v8, 0x0

    .line 89
    invoke-static {v7, v8, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 90
    .line 91
    .line 92
    move-result-object v7

    .line 93
    sget v9, Lxf0/o0;->a:F

    .line 94
    .line 95
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 96
    .line 97
    invoke-static {v10, v9}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 98
    .line 99
    .line 100
    move-result-object v9

    .line 101
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v11

    .line 105
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 106
    .line 107
    if-ne v11, v12, :cond_2

    .line 108
    .line 109
    sget-object v11, Lxf0/e1;->i:Lxf0/e1;

    .line 110
    .line 111
    invoke-virtual {v14, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :cond_2
    check-cast v11, Lay0/k;

    .line 115
    .line 116
    invoke-static {v9, v5, v11}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    const/16 v15, 0x30

    .line 121
    .line 122
    const/16 v16, 0x78

    .line 123
    .line 124
    move v11, v8

    .line 125
    const/4 v8, 0x0

    .line 126
    move-object v13, v10

    .line 127
    const/4 v10, 0x0

    .line 128
    move/from16 v17, v11

    .line 129
    .line 130
    const/4 v11, 0x0

    .line 131
    move-object/from16 v18, v12

    .line 132
    .line 133
    const/4 v12, 0x0

    .line 134
    move-object/from16 v19, v13

    .line 135
    .line 136
    const/4 v13, 0x0

    .line 137
    move-object/from16 p1, v6

    .line 138
    .line 139
    move-object/from16 v20, v18

    .line 140
    .line 141
    move-object/from16 v6, v19

    .line 142
    .line 143
    invoke-static/range {v7 .. v16}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 144
    .line 145
    .line 146
    const/4 v7, 0x0

    .line 147
    invoke-static {v6, v7, v4}, Landroidx/compose/foundation/layout/d;->v(Lx2/s;Lx2/j;I)Lx2/s;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    invoke-virtual {v14, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v8

    .line 159
    if-nez v6, :cond_3

    .line 160
    .line 161
    move-object/from16 v6, v20

    .line 162
    .line 163
    if-ne v8, v6, :cond_4

    .line 164
    .line 165
    :cond_3
    new-instance v8, Lc40/g;

    .line 166
    .line 167
    const/16 v6, 0x11

    .line 168
    .line 169
    invoke-direct {v8, v5, v6}, Lc40/g;-><init>(Lz4/f;I)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v14, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    :cond_4
    check-cast v8, Lay0/k;

    .line 176
    .line 177
    invoke-static {v4, v1, v8}, Lz4/k;->b(Lx2/s;Lz4/f;Lay0/k;)Lx2/s;

    .line 178
    .line 179
    .line 180
    move-result-object v1

    .line 181
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 182
    .line 183
    const/4 v11, 0x0

    .line 184
    invoke-static {v4, v11}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 185
    .line 186
    .line 187
    move-result-object v4

    .line 188
    iget-wide v5, v14, Ll2/t;->T:J

    .line 189
    .line 190
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 191
    .line 192
    .line 193
    move-result v5

    .line 194
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 195
    .line 196
    .line 197
    move-result-object v6

    .line 198
    invoke-static {v14, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 203
    .line 204
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 208
    .line 209
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 210
    .line 211
    .line 212
    iget-boolean v9, v14, Ll2/t;->S:Z

    .line 213
    .line 214
    if-eqz v9, :cond_5

    .line 215
    .line 216
    invoke-virtual {v14, v8}, Ll2/t;->l(Lay0/a;)V

    .line 217
    .line 218
    .line 219
    goto :goto_1

    .line 220
    :cond_5
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 221
    .line 222
    .line 223
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 224
    .line 225
    invoke-static {v8, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 226
    .line 227
    .line 228
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 229
    .line 230
    invoke-static {v4, v6, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 231
    .line 232
    .line 233
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 234
    .line 235
    iget-boolean v6, v14, Ll2/t;->S:Z

    .line 236
    .line 237
    if-nez v6, :cond_6

    .line 238
    .line 239
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 244
    .line 245
    .line 246
    move-result-object v8

    .line 247
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v6

    .line 251
    if-nez v6, :cond_7

    .line 252
    .line 253
    :cond_6
    invoke-static {v5, v14, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 254
    .line 255
    .line 256
    :cond_7
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 257
    .line 258
    invoke-static {v4, v1, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 259
    .line 260
    .line 261
    const/4 v1, 0x1

    .line 262
    invoke-static {v11, v1, v14, v7}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v14, v11}, Ll2/t;->q(Z)V

    .line 269
    .line 270
    .line 271
    iget v1, v3, Lz4/k;->b:I

    .line 272
    .line 273
    if-eq v1, v2, :cond_8

    .line 274
    .line 275
    iget-object v0, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v0, Lay0/a;

    .line 278
    .line 279
    invoke-static {v0, v14}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 280
    .line 281
    .line 282
    :cond_8
    :goto_2
    return-object p1

    .line 283
    :pswitch_0
    move-object/from16 v1, p1

    .line 284
    .line 285
    check-cast v1, Ll2/o;

    .line 286
    .line 287
    move-object/from16 v2, p2

    .line 288
    .line 289
    check-cast v2, Ljava/lang/Number;

    .line 290
    .line 291
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 292
    .line 293
    .line 294
    iget-object v2, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v2, Lv3/o1;

    .line 297
    .line 298
    iget-object v3, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast v3, Lw3/r0;

    .line 301
    .line 302
    iget-object v0, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 303
    .line 304
    check-cast v0, Lay0/n;

    .line 305
    .line 306
    const/4 v4, 0x1

    .line 307
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    invoke-static {v2, v3, v0, v1, v4}, Lw3/h1;->a(Lv3/o1;Lw3/r0;Lay0/n;Ll2/o;I)V

    .line 312
    .line 313
    .line 314
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 315
    .line 316
    return-object v0

    .line 317
    :pswitch_1
    move-object/from16 v1, p1

    .line 318
    .line 319
    check-cast v1, Ll2/o;

    .line 320
    .line 321
    move-object/from16 v2, p2

    .line 322
    .line 323
    check-cast v2, Ljava/lang/Number;

    .line 324
    .line 325
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 326
    .line 327
    .line 328
    move-result v2

    .line 329
    and-int/lit8 v3, v2, 0x3

    .line 330
    .line 331
    const/4 v4, 0x2

    .line 332
    const/4 v5, 0x0

    .line 333
    const/4 v6, 0x1

    .line 334
    if-eq v3, v4, :cond_9

    .line 335
    .line 336
    move v3, v6

    .line 337
    goto :goto_3

    .line 338
    :cond_9
    move v3, v5

    .line 339
    :goto_3
    and-int/2addr v2, v6

    .line 340
    check-cast v1, Ll2/t;

    .line 341
    .line 342
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 343
    .line 344
    .line 345
    move-result v2

    .line 346
    if-eqz v2, :cond_a

    .line 347
    .line 348
    iget-object v2, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast v2, Lw3/t;

    .line 351
    .line 352
    iget-object v3, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v3, Lw3/r0;

    .line 355
    .line 356
    iget-object v0, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 357
    .line 358
    check-cast v0, Lay0/n;

    .line 359
    .line 360
    invoke-static {v2, v3, v0, v1, v5}, Lw3/h1;->a(Lv3/o1;Lw3/r0;Lay0/n;Ll2/o;I)V

    .line 361
    .line 362
    .line 363
    goto :goto_4

    .line 364
    :cond_a
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 365
    .line 366
    .line 367
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 368
    .line 369
    return-object v0

    .line 370
    :pswitch_2
    move-object/from16 v1, p1

    .line 371
    .line 372
    check-cast v1, Ll2/o;

    .line 373
    .line 374
    move-object/from16 v2, p2

    .line 375
    .line 376
    check-cast v2, Ljava/lang/Number;

    .line 377
    .line 378
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 379
    .line 380
    .line 381
    move-result v2

    .line 382
    iget-object v3, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 383
    .line 384
    check-cast v3, Lvv/m0;

    .line 385
    .line 386
    const/4 v4, 0x0

    .line 387
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 388
    .line 389
    .line 390
    move-result-object v5

    .line 391
    and-int/lit8 v2, v2, 0xb

    .line 392
    .line 393
    const/4 v6, 0x2

    .line 394
    if-ne v2, v6, :cond_c

    .line 395
    .line 396
    move-object v2, v1

    .line 397
    check-cast v2, Ll2/t;

    .line 398
    .line 399
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 400
    .line 401
    .line 402
    move-result v6

    .line 403
    if-nez v6, :cond_b

    .line 404
    .line 405
    goto :goto_5

    .line 406
    :cond_b
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 407
    .line 408
    .line 409
    goto/16 :goto_7

    .line 410
    .line 411
    :cond_c
    :goto_5
    invoke-static {v3, v1}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 412
    .line 413
    .line 414
    move-result-object v2

    .line 415
    invoke-static {v2}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 416
    .line 417
    .line 418
    move-result-object v2

    .line 419
    sget-object v6, Lw3/h1;->h:Ll2/u2;

    .line 420
    .line 421
    check-cast v1, Ll2/t;

    .line 422
    .line 423
    invoke-virtual {v1, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v6

    .line 427
    check-cast v6, Lt4/c;

    .line 428
    .line 429
    iget-object v2, v2, Lvv/n0;->a:Lt4/o;

    .line 430
    .line 431
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    iget-wide v7, v2, Lt4/o;->a:J

    .line 435
    .line 436
    invoke-interface {v6, v7, v8}, Lt4/c;->s(J)F

    .line 437
    .line 438
    .line 439
    move-result v2

    .line 440
    iget-object v6, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 441
    .line 442
    check-cast v6, Lx2/s;

    .line 443
    .line 444
    invoke-static {v2}, Lk1/j;->g(F)Lk1/h;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    iget-object v0, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 449
    .line 450
    check-cast v0, Lay0/o;

    .line 451
    .line 452
    const v7, -0x1cd0f17e

    .line 453
    .line 454
    .line 455
    invoke-virtual {v1, v7}, Ll2/t;->Z(I)V

    .line 456
    .line 457
    .line 458
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 459
    .line 460
    invoke-static {v2, v7, v1, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 461
    .line 462
    .line 463
    move-result-object v2

    .line 464
    const v7, -0x4ee9b9da

    .line 465
    .line 466
    .line 467
    invoke-virtual {v1, v7}, Ll2/t;->Z(I)V

    .line 468
    .line 469
    .line 470
    iget-wide v7, v1, Ll2/t;->T:J

    .line 471
    .line 472
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 473
    .line 474
    .line 475
    move-result v7

    .line 476
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 477
    .line 478
    .line 479
    move-result-object v8

    .line 480
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 481
    .line 482
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 483
    .line 484
    .line 485
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 486
    .line 487
    invoke-static {v6}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 488
    .line 489
    .line 490
    move-result-object v6

    .line 491
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 492
    .line 493
    .line 494
    iget-boolean v10, v1, Ll2/t;->S:Z

    .line 495
    .line 496
    if-eqz v10, :cond_d

    .line 497
    .line 498
    invoke-virtual {v1, v9}, Ll2/t;->l(Lay0/a;)V

    .line 499
    .line 500
    .line 501
    goto :goto_6

    .line 502
    :cond_d
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 503
    .line 504
    .line 505
    :goto_6
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 506
    .line 507
    invoke-static {v9, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 508
    .line 509
    .line 510
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 511
    .line 512
    invoke-static {v2, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 513
    .line 514
    .line 515
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 516
    .line 517
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 518
    .line 519
    if-nez v8, :cond_e

    .line 520
    .line 521
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object v8

    .line 525
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 526
    .line 527
    .line 528
    move-result-object v9

    .line 529
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 530
    .line 531
    .line 532
    move-result v8

    .line 533
    if-nez v8, :cond_f

    .line 534
    .line 535
    :cond_e
    invoke-static {v7, v1, v7, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 536
    .line 537
    .line 538
    :cond_f
    new-instance v2, Ll2/d2;

    .line 539
    .line 540
    invoke-direct {v2, v1}, Ll2/d2;-><init>(Ll2/o;)V

    .line 541
    .line 542
    .line 543
    invoke-virtual {v6, v2, v1, v5}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 544
    .line 545
    .line 546
    const v2, 0x7ab4aae9

    .line 547
    .line 548
    .line 549
    invoke-virtual {v1, v2}, Ll2/t;->Z(I)V

    .line 550
    .line 551
    .line 552
    invoke-interface {v0, v3, v1, v5}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 556
    .line 557
    .line 558
    const/4 v0, 0x1

    .line 559
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 560
    .line 561
    .line 562
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 563
    .line 564
    .line 565
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 566
    .line 567
    .line 568
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 569
    .line 570
    return-object v0

    .line 571
    :pswitch_3
    move-object/from16 v1, p1

    .line 572
    .line 573
    check-cast v1, Ll2/o;

    .line 574
    .line 575
    move-object/from16 v2, p2

    .line 576
    .line 577
    check-cast v2, Ljava/lang/Number;

    .line 578
    .line 579
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 580
    .line 581
    .line 582
    iget-object v2, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 583
    .line 584
    check-cast v2, Ljava/lang/String;

    .line 585
    .line 586
    iget-object v3, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 587
    .line 588
    check-cast v3, Ljava/lang/String;

    .line 589
    .line 590
    iget-object v0, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 591
    .line 592
    check-cast v0, Lx2/s;

    .line 593
    .line 594
    const/16 v4, 0xd81

    .line 595
    .line 596
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 597
    .line 598
    .line 599
    move-result v4

    .line 600
    invoke-static {v2, v3, v0, v1, v4}, Ltv/l;->a(Ljava/lang/String;Ljava/lang/String;Lx2/s;Ll2/o;I)V

    .line 601
    .line 602
    .line 603
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 604
    .line 605
    return-object v0

    .line 606
    :pswitch_4
    move-object/from16 v1, p1

    .line 607
    .line 608
    check-cast v1, Ll2/o;

    .line 609
    .line 610
    move-object/from16 v2, p2

    .line 611
    .line 612
    check-cast v2, Ljava/lang/Number;

    .line 613
    .line 614
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 615
    .line 616
    .line 617
    iget-object v2, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 618
    .line 619
    check-cast v2, Lx2/s;

    .line 620
    .line 621
    iget-object v3, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 622
    .line 623
    check-cast v3, Lt2/b;

    .line 624
    .line 625
    iget-object v0, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 626
    .line 627
    check-cast v0, Lt3/q0;

    .line 628
    .line 629
    const/16 v4, 0x31

    .line 630
    .line 631
    invoke-static {v4}, Ll2/b;->x(I)I

    .line 632
    .line 633
    .line 634
    move-result v4

    .line 635
    invoke-static {v2, v3, v0, v1, v4}, Lt3/k1;->a(Lx2/s;Lt2/b;Lt3/q0;Ll2/o;I)V

    .line 636
    .line 637
    .line 638
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 639
    .line 640
    return-object v0

    .line 641
    :pswitch_5
    move-object/from16 v1, p1

    .line 642
    .line 643
    check-cast v1, Ll2/o;

    .line 644
    .line 645
    move-object/from16 v2, p2

    .line 646
    .line 647
    check-cast v2, Ljava/lang/Number;

    .line 648
    .line 649
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 650
    .line 651
    .line 652
    iget-object v2, v0, Lf7/f;->h:Ljava/lang/Object;

    .line 653
    .line 654
    check-cast v2, Ly6/q;

    .line 655
    .line 656
    iget-object v3, v0, Lf7/f;->i:Ljava/lang/Object;

    .line 657
    .line 658
    check-cast v3, Lf7/c;

    .line 659
    .line 660
    iget-object v0, v0, Lf7/f;->g:Ljava/lang/Object;

    .line 661
    .line 662
    check-cast v0, Lt2/b;

    .line 663
    .line 664
    const/16 v4, 0x181

    .line 665
    .line 666
    invoke-static {v2, v3, v0, v1, v4}, Lkp/j7;->a(Ly6/q;Lf7/c;Lt2/b;Ll2/o;I)V

    .line 667
    .line 668
    .line 669
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 670
    .line 671
    return-object v0

    .line 672
    nop

    .line 673
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
