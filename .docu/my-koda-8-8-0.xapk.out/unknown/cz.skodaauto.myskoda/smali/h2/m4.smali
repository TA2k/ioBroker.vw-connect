.class public final Lh2/m4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/m4;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lh2/m4;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/m4;->a:Lh2/m4;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lh2/t8;Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    iget v2, v0, Lh2/t8;->g:F

    .line 6
    .line 7
    move-object/from16 v7, p2

    .line 8
    .line 9
    check-cast v7, Ll2/t;

    .line 10
    .line 11
    const v3, 0x7f677649

    .line 12
    .line 13
    .line 14
    invoke-virtual {v7, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x2

    .line 22
    const/4 v10, 0x4

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    move v3, v10

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move v3, v4

    .line 28
    :goto_0
    or-int v11, v1, v3

    .line 29
    .line 30
    and-int/lit8 v3, v11, 0x3

    .line 31
    .line 32
    const/4 v12, 0x0

    .line 33
    const/4 v13, 0x1

    .line 34
    if-eq v3, v4, :cond_1

    .line 35
    .line 36
    move v3, v13

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v3, v12

    .line 39
    :goto_1
    and-int/lit8 v4, v11, 0x1

    .line 40
    .line 41
    invoke-virtual {v7, v4, v3}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-eqz v3, :cond_10

    .line 46
    .line 47
    iget-object v14, v0, Lh2/t8;->i:Lh2/zb;

    .line 48
    .line 49
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-nez v3, :cond_f

    .line 54
    .line 55
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    const v3, 0x7fffffff

    .line 60
    .line 61
    .line 62
    and-int/2addr v2, v3

    .line 63
    const/high16 v3, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 64
    .line 65
    if-ge v2, v3, :cond_f

    .line 66
    .line 67
    invoke-virtual {v7, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    const/4 v3, 0x0

    .line 72
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    or-int/2addr v2, v3

    .line 77
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 82
    .line 83
    if-nez v2, :cond_2

    .line 84
    .line 85
    if-ne v3, v15, :cond_3

    .line 86
    .line 87
    :cond_2
    new-instance v2, Lep0/f;

    .line 88
    .line 89
    invoke-direct {v2, v0, v13}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    invoke-static {v2}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    invoke-virtual {v7, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_3
    check-cast v3, Ll2/t2;

    .line 100
    .line 101
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Le3/s;

    .line 106
    .line 107
    iget-wide v3, v2, Le3/s;->a:J

    .line 108
    .line 109
    sget-object v2, Lk2/w;->f:Lk2/w;

    .line 110
    .line 111
    invoke-static {v2, v7}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    const/4 v8, 0x0

    .line 116
    const/16 v9, 0xc

    .line 117
    .line 118
    const/4 v6, 0x0

    .line 119
    invoke-static/range {v3 .. v9}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    new-instance v3, Lal/q;

    .line 124
    .line 125
    invoke-direct {v3, v0, v10}, Lal/q;-><init>(Ljava/lang/Object;I)V

    .line 126
    .line 127
    .line 128
    const v4, -0x62e0c0ee

    .line 129
    .line 130
    .line 131
    invoke-static {v4, v7, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 132
    .line 133
    .line 134
    move-result-object v19

    .line 135
    const v3, 0x292236d1

    .line 136
    .line 137
    .line 138
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v7, v12}, Ll2/t;->q(Z)V

    .line 142
    .line 143
    .line 144
    iget-object v3, v0, Lh2/t8;->a:Lx2/s;

    .line 145
    .line 146
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 147
    .line 148
    invoke-interface {v3, v4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    invoke-virtual {v7, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v6

    .line 160
    if-nez v5, :cond_4

    .line 161
    .line 162
    if-ne v6, v15, :cond_5

    .line 163
    .line 164
    :cond_4
    new-instance v6, Lh2/j4;

    .line 165
    .line 166
    invoke-direct {v6, v2, v12}, Lh2/j4;-><init>(Ll2/t2;I)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v7, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    :cond_5
    check-cast v6, Lay0/k;

    .line 173
    .line 174
    invoke-static {v3, v6}, Landroidx/compose/ui/draw/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    if-ne v3, v15, :cond_6

    .line 183
    .line 184
    new-instance v3, Lh10/d;

    .line 185
    .line 186
    const/16 v5, 0xc

    .line 187
    .line 188
    invoke-direct {v3, v5}, Lh10/d;-><init>(I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v7, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    :cond_6
    check-cast v3, Lay0/k;

    .line 195
    .line 196
    invoke-static {v2, v12, v3}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    if-ne v3, v15, :cond_7

    .line 205
    .line 206
    sget-object v3, Lh2/l4;->e:Lh2/l4;

    .line 207
    .line 208
    invoke-virtual {v7, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    :cond_7
    check-cast v3, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 212
    .line 213
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 214
    .line 215
    invoke-static {v2, v5, v3}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 220
    .line 221
    invoke-static {v3, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 222
    .line 223
    .line 224
    move-result-object v3

    .line 225
    iget-wide v5, v7, Ll2/t;->T:J

    .line 226
    .line 227
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 232
    .line 233
    .line 234
    move-result-object v6

    .line 235
    invoke-static {v7, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 240
    .line 241
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 242
    .line 243
    .line 244
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 245
    .line 246
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 247
    .line 248
    .line 249
    iget-boolean v9, v7, Ll2/t;->S:Z

    .line 250
    .line 251
    if-eqz v9, :cond_8

    .line 252
    .line 253
    invoke-virtual {v7, v8}, Ll2/t;->l(Lay0/a;)V

    .line 254
    .line 255
    .line 256
    goto :goto_2

    .line 257
    :cond_8
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 258
    .line 259
    .line 260
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 261
    .line 262
    invoke-static {v8, v3, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 263
    .line 264
    .line 265
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 266
    .line 267
    invoke-static {v3, v6, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 268
    .line 269
    .line 270
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 271
    .line 272
    iget-boolean v6, v7, Ll2/t;->S:Z

    .line 273
    .line 274
    if-nez v6, :cond_9

    .line 275
    .line 276
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v6

    .line 280
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v8

    .line 284
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v6

    .line 288
    if-nez v6, :cond_a

    .line 289
    .line 290
    :cond_9
    invoke-static {v5, v7, v5, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 291
    .line 292
    .line 293
    :cond_a
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 294
    .line 295
    invoke-static {v3, v2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 296
    .line 297
    .line 298
    iget-object v2, v0, Lh2/t8;->h:Lk1/q1;

    .line 299
    .line 300
    invoke-static {v4, v2}, Lk1/d;->r(Lx2/s;Lk1/q1;)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    invoke-static {v2}, Ljp/ba;->d(Lx2/s;)Lx2/s;

    .line 305
    .line 306
    .line 307
    move-result-object v3

    .line 308
    sget-object v2, Lh2/q;->a:Ll2/e0;

    .line 309
    .line 310
    and-int/lit8 v2, v11, 0xe

    .line 311
    .line 312
    if-ne v2, v10, :cond_b

    .line 313
    .line 314
    move v2, v13

    .line 315
    goto :goto_3

    .line 316
    :cond_b
    move v2, v12

    .line 317
    :goto_3
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v4

    .line 321
    if-nez v2, :cond_c

    .line 322
    .line 323
    if-ne v4, v15, :cond_d

    .line 324
    .line 325
    :cond_c
    new-instance v4, Lh2/k4;

    .line 326
    .line 327
    invoke-direct {v4, v0, v12}, Lh2/k4;-><init>(Ljava/lang/Object;I)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v7, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    :cond_d
    check-cast v4, Li2/l0;

    .line 334
    .line 335
    iget-wide v5, v14, Lh2/zb;->c:J

    .line 336
    .line 337
    iget-wide v8, v14, Lh2/zb;->d:J

    .line 338
    .line 339
    iget-wide v11, v14, Lh2/zb;->e:J

    .line 340
    .line 341
    iget-wide v13, v14, Lh2/zb;->f:J

    .line 342
    .line 343
    move-wide/from16 v16, v8

    .line 344
    .line 345
    move-wide v9, v13

    .line 346
    iget-object v13, v0, Lh2/t8;->b:Lt2/b;

    .line 347
    .line 348
    iget-object v14, v0, Lh2/t8;->c:Lg4/p0;

    .line 349
    .line 350
    iget-object v2, v0, Lh2/t8;->d:Lg4/p0;

    .line 351
    .line 352
    move-wide/from16 v20, v16

    .line 353
    .line 354
    sget-object v17, Lk1/j;->e:Lk1/f;

    .line 355
    .line 356
    iget-object v8, v0, Lh2/t8;->e:Lt2/b;

    .line 357
    .line 358
    move-object/from16 v16, v2

    .line 359
    .line 360
    iget v2, v0, Lh2/t8;->g:F

    .line 361
    .line 362
    move/from16 v18, v2

    .line 363
    .line 364
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v2

    .line 368
    if-ne v2, v15, :cond_e

    .line 369
    .line 370
    new-instance v2, Lgz0/e0;

    .line 371
    .line 372
    const/16 v15, 0xb

    .line 373
    .line 374
    invoke-direct {v2, v15}, Lgz0/e0;-><init>(I)V

    .line 375
    .line 376
    .line 377
    invoke-virtual {v7, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 378
    .line 379
    .line 380
    :cond_e
    check-cast v2, Lay0/a;

    .line 381
    .line 382
    const/16 v22, 0x0

    .line 383
    .line 384
    move-object/from16 v15, v16

    .line 385
    .line 386
    move-object/from16 v16, v2

    .line 387
    .line 388
    const/4 v2, 0x1

    .line 389
    move-wide/from16 v23, v20

    .line 390
    .line 391
    move-object/from16 v21, v7

    .line 392
    .line 393
    move/from16 v20, v18

    .line 394
    .line 395
    move-object/from16 v18, v8

    .line 396
    .line 397
    move-wide/from16 v7, v23

    .line 398
    .line 399
    invoke-static/range {v3 .. v22}, Lh2/q;->c(Lx2/s;Li2/l0;JJJJLt2/b;Lg4/p0;Lg4/p0;Lay0/a;Lk1/i;Lt2/b;Lt2/b;FLl2/o;I)V

    .line 400
    .line 401
    .line 402
    move-object/from16 v7, v21

    .line 403
    .line 404
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 405
    .line 406
    .line 407
    goto :goto_4

    .line 408
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 409
    .line 410
    const-string v1, "The expandedHeight is expected to be specified and finite"

    .line 411
    .line 412
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 413
    .line 414
    .line 415
    throw v0

    .line 416
    :cond_10
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 417
    .line 418
    .line 419
    :goto_4
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 420
    .line 421
    .line 422
    move-result-object v2

    .line 423
    if-eqz v2, :cond_11

    .line 424
    .line 425
    new-instance v3, Ld90/m;

    .line 426
    .line 427
    const/16 v4, 0x16

    .line 428
    .line 429
    move-object/from16 v5, p0

    .line 430
    .line 431
    invoke-direct {v3, v1, v4, v5, v0}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 435
    .line 436
    :cond_11
    return-void
.end method
