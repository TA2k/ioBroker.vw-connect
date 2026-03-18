.class public final synthetic Lbk/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput p2, p0, Lbk/b;->d:I

    iput-object p1, p0, Lbk/b;->e:Ljava/lang/String;

    iput-object p3, p0, Lbk/b;->f:Ljava/lang/String;

    iput-object p4, p0, Lbk/b;->g:Ljava/lang/String;

    iput-object p5, p0, Lbk/b;->h:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    .line 2
    iput p6, p0, Lbk/b;->d:I

    iput-object p1, p0, Lbk/b;->e:Ljava/lang/String;

    iput-object p2, p0, Lbk/b;->f:Ljava/lang/String;

    iput-object p3, p0, Lbk/b;->g:Ljava/lang/String;

    iput-object p4, p0, Lbk/b;->h:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lbk/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p1

    .line 9
    .line 10
    check-cast v6, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 v1, 0xc31

    .line 20
    .line 21
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v7

    .line 25
    iget-object v2, v0, Lbk/b;->e:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v3, v0, Lbk/b;->f:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v4, v0, Lbk/b;->g:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v5, v0, Lbk/b;->h:Ljava/lang/String;

    .line 32
    .line 33
    invoke-static/range {v2 .. v7}, Lyj/a;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_0
    move-object/from16 v1, p1

    .line 40
    .line 41
    check-cast v1, Ll2/o;

    .line 42
    .line 43
    move-object/from16 v2, p2

    .line 44
    .line 45
    check-cast v2, Ljava/lang/Integer;

    .line 46
    .line 47
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    and-int/lit8 v3, v2, 0x3

    .line 52
    .line 53
    const/4 v4, 0x2

    .line 54
    const/4 v5, 0x1

    .line 55
    const/4 v6, 0x0

    .line 56
    if-eq v3, v4, :cond_0

    .line 57
    .line 58
    move v3, v5

    .line 59
    goto :goto_1

    .line 60
    :cond_0
    move v3, v6

    .line 61
    :goto_1
    and-int/2addr v2, v5

    .line 62
    check-cast v1, Ll2/t;

    .line 63
    .line 64
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_d

    .line 69
    .line 70
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 71
    .line 72
    const/high16 v3, 0x3f800000    # 1.0f

    .line 73
    .line 74
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    sget-object v7, Lk1/r0;->d:Lk1/r0;

    .line 79
    .line 80
    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    sget-object v7, Lj91/a;->a:Ll2/u2;

    .line 85
    .line 86
    invoke-virtual {v1, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v8

    .line 90
    check-cast v8, Lj91/c;

    .line 91
    .line 92
    iget v8, v8, Lj91/c;->j:F

    .line 93
    .line 94
    invoke-static {v4, v8}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    sget-object v8, Lk1/j;->a:Lk1/c;

    .line 99
    .line 100
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 101
    .line 102
    invoke-static {v8, v9, v1, v6}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 103
    .line 104
    .line 105
    move-result-object v8

    .line 106
    iget-wide v9, v1, Ll2/t;->T:J

    .line 107
    .line 108
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 113
    .line 114
    .line 115
    move-result-object v10

    .line 116
    invoke-static {v1, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 121
    .line 122
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 123
    .line 124
    .line 125
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 126
    .line 127
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 128
    .line 129
    .line 130
    iget-boolean v12, v1, Ll2/t;->S:Z

    .line 131
    .line 132
    if-eqz v12, :cond_1

    .line 133
    .line 134
    invoke-virtual {v1, v11}, Ll2/t;->l(Lay0/a;)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 139
    .line 140
    .line 141
    :goto_2
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 142
    .line 143
    invoke-static {v12, v8, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 147
    .line 148
    invoke-static {v8, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 152
    .line 153
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 154
    .line 155
    if-nez v13, :cond_2

    .line 156
    .line 157
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v13

    .line 161
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object v14

    .line 165
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v13

    .line 169
    if-nez v13, :cond_3

    .line 170
    .line 171
    :cond_2
    invoke-static {v9, v1, v9, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 172
    .line 173
    .line 174
    :cond_3
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 175
    .line 176
    invoke-static {v9, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 177
    .line 178
    .line 179
    float-to-double v13, v3

    .line 180
    const-wide/16 v15, 0x0

    .line 181
    .line 182
    cmpl-double v4, v13, v15

    .line 183
    .line 184
    if-lez v4, :cond_4

    .line 185
    .line 186
    goto :goto_3

    .line 187
    :cond_4
    const-string v4, "invalid weight; must be greater than zero"

    .line 188
    .line 189
    invoke-static {v4}, Ll1/a;->a(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    :goto_3
    new-instance v4, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 193
    .line 194
    invoke-direct {v4, v3, v5}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 195
    .line 196
    .line 197
    sget-object v13, Lk1/j;->c:Lk1/e;

    .line 198
    .line 199
    sget-object v14, Lx2/c;->p:Lx2/h;

    .line 200
    .line 201
    invoke-static {v13, v14, v1, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 202
    .line 203
    .line 204
    move-result-object v13

    .line 205
    iget-wide v14, v1, Ll2/t;->T:J

    .line 206
    .line 207
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 208
    .line 209
    .line 210
    move-result v14

    .line 211
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 212
    .line 213
    .line 214
    move-result-object v15

    .line 215
    invoke-static {v1, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object v4

    .line 219
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 220
    .line 221
    .line 222
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 223
    .line 224
    if-eqz v6, :cond_5

    .line 225
    .line 226
    invoke-virtual {v1, v11}, Ll2/t;->l(Lay0/a;)V

    .line 227
    .line 228
    .line 229
    goto :goto_4

    .line 230
    :cond_5
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 231
    .line 232
    .line 233
    :goto_4
    invoke-static {v12, v13, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 234
    .line 235
    .line 236
    invoke-static {v8, v15, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 237
    .line 238
    .line 239
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 240
    .line 241
    if-nez v6, :cond_6

    .line 242
    .line 243
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v6

    .line 247
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 248
    .line 249
    .line 250
    move-result-object v13

    .line 251
    invoke-static {v6, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v6

    .line 255
    if-nez v6, :cond_7

    .line 256
    .line 257
    :cond_6
    invoke-static {v14, v1, v14, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 258
    .line 259
    .line 260
    :cond_7
    invoke-static {v9, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 261
    .line 262
    .line 263
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 264
    .line 265
    invoke-virtual {v1, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v6

    .line 269
    check-cast v6, Lj91/f;

    .line 270
    .line 271
    invoke-virtual {v6}, Lj91/f;->a()Lg4/p0;

    .line 272
    .line 273
    .line 274
    move-result-object v6

    .line 275
    sget-object v13, Lj91/h;->a:Ll2/u2;

    .line 276
    .line 277
    invoke-virtual {v1, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v14

    .line 281
    check-cast v14, Lj91/e;

    .line 282
    .line 283
    invoke-virtual {v14}, Lj91/e;->s()J

    .line 284
    .line 285
    .line 286
    move-result-wide v14

    .line 287
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 288
    .line 289
    .line 290
    move-result-object v5

    .line 291
    const-string v3, "{departure_planner_card}_title"

    .line 292
    .line 293
    invoke-static {v5, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    const/16 v27, 0x6180

    .line 298
    .line 299
    const v28, 0xaff0

    .line 300
    .line 301
    .line 302
    move-object v5, v7

    .line 303
    iget-object v7, v0, Lbk/b;->e:Ljava/lang/String;

    .line 304
    .line 305
    move-object/from16 v16, v12

    .line 306
    .line 307
    move-object/from16 v17, v13

    .line 308
    .line 309
    const-wide/16 v12, 0x0

    .line 310
    .line 311
    move-object/from16 v18, v10

    .line 312
    .line 313
    move-wide/from16 v34, v14

    .line 314
    .line 315
    move-object v15, v11

    .line 316
    move-wide/from16 v10, v34

    .line 317
    .line 318
    const/4 v14, 0x0

    .line 319
    move-object/from16 v19, v15

    .line 320
    .line 321
    move-object/from16 v20, v16

    .line 322
    .line 323
    const-wide/16 v15, 0x0

    .line 324
    .line 325
    move-object/from16 v21, v17

    .line 326
    .line 327
    const/16 v17, 0x0

    .line 328
    .line 329
    move-object/from16 v22, v18

    .line 330
    .line 331
    const/16 v18, 0x0

    .line 332
    .line 333
    move-object/from16 v23, v19

    .line 334
    .line 335
    move-object/from16 v24, v20

    .line 336
    .line 337
    const-wide/16 v19, 0x0

    .line 338
    .line 339
    move-object/from16 v25, v21

    .line 340
    .line 341
    const/16 v21, 0x2

    .line 342
    .line 343
    move-object/from16 v26, v22

    .line 344
    .line 345
    const/16 v22, 0x0

    .line 346
    .line 347
    move-object/from16 v29, v23

    .line 348
    .line 349
    const/16 v23, 0x1

    .line 350
    .line 351
    move-object/from16 v30, v24

    .line 352
    .line 353
    const/16 v24, 0x0

    .line 354
    .line 355
    move-object/from16 v31, v26

    .line 356
    .line 357
    const/16 v26, 0x0

    .line 358
    .line 359
    move-object/from16 v32, v25

    .line 360
    .line 361
    move-object/from16 v25, v1

    .line 362
    .line 363
    move-object/from16 v1, v29

    .line 364
    .line 365
    move-object/from16 v29, v8

    .line 366
    .line 367
    move-object v8, v6

    .line 368
    move-object/from16 v6, v32

    .line 369
    .line 370
    move-object/from16 v33, v9

    .line 371
    .line 372
    move-object/from16 v32, v31

    .line 373
    .line 374
    move-object v9, v3

    .line 375
    move-object/from16 v3, v30

    .line 376
    .line 377
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 378
    .line 379
    .line 380
    move-object/from16 v7, v25

    .line 381
    .line 382
    invoke-virtual {v7, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v8

    .line 386
    check-cast v8, Lj91/c;

    .line 387
    .line 388
    iget v8, v8, Lj91/c;->c:F

    .line 389
    .line 390
    invoke-static {v2, v8, v7, v4}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v4

    .line 394
    check-cast v4, Lj91/f;

    .line 395
    .line 396
    invoke-virtual {v4}, Lj91/f;->k()Lg4/p0;

    .line 397
    .line 398
    .line 399
    move-result-object v8

    .line 400
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    check-cast v4, Lj91/e;

    .line 405
    .line 406
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 407
    .line 408
    .line 409
    move-result-wide v10

    .line 410
    const/high16 v4, 0x3f800000    # 1.0f

    .line 411
    .line 412
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 413
    .line 414
    .line 415
    move-result-object v6

    .line 416
    const-string v4, "{departure_planner_card}_subtitle"

    .line 417
    .line 418
    invoke-static {v6, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 419
    .line 420
    .line 421
    move-result-object v9

    .line 422
    iget-object v7, v0, Lbk/b;->f:Ljava/lang/String;

    .line 423
    .line 424
    const/16 v23, 0x2

    .line 425
    .line 426
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 427
    .line 428
    .line 429
    move-object/from16 v7, v25

    .line 430
    .line 431
    const/4 v4, 0x1

    .line 432
    invoke-virtual {v7, v4}, Ll2/t;->q(Z)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v7, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object v4

    .line 439
    check-cast v4, Lj91/c;

    .line 440
    .line 441
    iget v4, v4, Lj91/c;->d:F

    .line 442
    .line 443
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 444
    .line 445
    .line 446
    move-result-object v4

    .line 447
    invoke-static {v7, v4}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 448
    .line 449
    .line 450
    sget-object v4, Lx2/c;->r:Lx2/h;

    .line 451
    .line 452
    sget-object v5, Lk1/j;->g:Lk1/f;

    .line 453
    .line 454
    const/high16 v6, 0x3f800000    # 1.0f

    .line 455
    .line 456
    invoke-static {v2, v6}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 457
    .line 458
    .line 459
    move-result-object v2

    .line 460
    const/16 v6, 0x36

    .line 461
    .line 462
    invoke-static {v5, v4, v7, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 463
    .line 464
    .line 465
    move-result-object v4

    .line 466
    iget-wide v5, v7, Ll2/t;->T:J

    .line 467
    .line 468
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 469
    .line 470
    .line 471
    move-result v5

    .line 472
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 473
    .line 474
    .line 475
    move-result-object v6

    .line 476
    invoke-static {v7, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 477
    .line 478
    .line 479
    move-result-object v2

    .line 480
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 481
    .line 482
    .line 483
    iget-boolean v8, v7, Ll2/t;->S:Z

    .line 484
    .line 485
    if-eqz v8, :cond_8

    .line 486
    .line 487
    invoke-virtual {v7, v1}, Ll2/t;->l(Lay0/a;)V

    .line 488
    .line 489
    .line 490
    goto :goto_5

    .line 491
    :cond_8
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 492
    .line 493
    .line 494
    :goto_5
    invoke-static {v3, v4, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 495
    .line 496
    .line 497
    move-object/from16 v1, v29

    .line 498
    .line 499
    invoke-static {v1, v6, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 500
    .line 501
    .line 502
    iget-boolean v1, v7, Ll2/t;->S:Z

    .line 503
    .line 504
    if-nez v1, :cond_9

    .line 505
    .line 506
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 507
    .line 508
    .line 509
    move-result-object v1

    .line 510
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 511
    .line 512
    .line 513
    move-result-object v3

    .line 514
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 515
    .line 516
    .line 517
    move-result v1

    .line 518
    if-nez v1, :cond_a

    .line 519
    .line 520
    :cond_9
    move-object/from16 v1, v32

    .line 521
    .line 522
    goto :goto_7

    .line 523
    :cond_a
    :goto_6
    move-object/from16 v1, v33

    .line 524
    .line 525
    goto :goto_8

    .line 526
    :goto_7
    invoke-static {v5, v7, v5, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 527
    .line 528
    .line 529
    goto :goto_6

    .line 530
    :goto_8
    invoke-static {v1, v2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 531
    .line 532
    .line 533
    iget-object v1, v0, Lbk/b;->g:Ljava/lang/String;

    .line 534
    .line 535
    if-nez v1, :cond_b

    .line 536
    .line 537
    const v1, 0x41541c61

    .line 538
    .line 539
    .line 540
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 541
    .line 542
    .line 543
    const/4 v2, 0x0

    .line 544
    :goto_9
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 545
    .line 546
    .line 547
    goto :goto_a

    .line 548
    :cond_b
    const/4 v2, 0x0

    .line 549
    const v3, 0x41541c62

    .line 550
    .line 551
    .line 552
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 553
    .line 554
    .line 555
    const v3, 0x7f0803ad

    .line 556
    .line 557
    .line 558
    const-string v4, "{departure_planner_card}_ac"

    .line 559
    .line 560
    invoke-static {v1, v3, v4, v7, v2}, Lt10/a;->w(Ljava/lang/String;ILjava/lang/String;Ll2/o;I)V

    .line 561
    .line 562
    .line 563
    goto :goto_9

    .line 564
    :goto_a
    iget-object v0, v0, Lbk/b;->h:Ljava/lang/String;

    .line 565
    .line 566
    if-nez v0, :cond_c

    .line 567
    .line 568
    const v0, 0x415892a8

    .line 569
    .line 570
    .line 571
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 572
    .line 573
    .line 574
    :goto_b
    invoke-virtual {v7, v2}, Ll2/t;->q(Z)V

    .line 575
    .line 576
    .line 577
    const/4 v4, 0x1

    .line 578
    goto :goto_c

    .line 579
    :cond_c
    const v1, 0x415892a9

    .line 580
    .line 581
    .line 582
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 583
    .line 584
    .line 585
    const v1, 0x7f0802d5

    .line 586
    .line 587
    .line 588
    const-string v3, "{departure_planner_card}_charging"

    .line 589
    .line 590
    invoke-static {v0, v1, v3, v7, v2}, Lt10/a;->w(Ljava/lang/String;ILjava/lang/String;Ll2/o;I)V

    .line 591
    .line 592
    .line 593
    goto :goto_b

    .line 594
    :goto_c
    invoke-virtual {v7, v4}, Ll2/t;->q(Z)V

    .line 595
    .line 596
    .line 597
    invoke-virtual {v7, v4}, Ll2/t;->q(Z)V

    .line 598
    .line 599
    .line 600
    goto :goto_d

    .line 601
    :cond_d
    move-object v7, v1

    .line 602
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 603
    .line 604
    .line 605
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 606
    .line 607
    return-object v0

    .line 608
    :pswitch_1
    move-object/from16 v1, p1

    .line 609
    .line 610
    check-cast v1, Ll2/o;

    .line 611
    .line 612
    move-object/from16 v2, p2

    .line 613
    .line 614
    check-cast v2, Ljava/lang/Integer;

    .line 615
    .line 616
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 617
    .line 618
    .line 619
    move-result v2

    .line 620
    and-int/lit8 v3, v2, 0x3

    .line 621
    .line 622
    const/4 v4, 0x2

    .line 623
    const/4 v5, 0x0

    .line 624
    const/4 v6, 0x1

    .line 625
    if-eq v3, v4, :cond_e

    .line 626
    .line 627
    move v3, v6

    .line 628
    goto :goto_e

    .line 629
    :cond_e
    move v3, v5

    .line 630
    :goto_e
    and-int/2addr v2, v6

    .line 631
    check-cast v1, Ll2/t;

    .line 632
    .line 633
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 634
    .line 635
    .line 636
    move-result v2

    .line 637
    if-eqz v2, :cond_12

    .line 638
    .line 639
    const/high16 v2, 0x3f800000    # 1.0f

    .line 640
    .line 641
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 642
    .line 643
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 644
    .line 645
    .line 646
    move-result-object v2

    .line 647
    invoke-static {v1}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 648
    .line 649
    .line 650
    move-result-object v4

    .line 651
    iget v4, v4, Lj91/c;->j:F

    .line 652
    .line 653
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 654
    .line 655
    .line 656
    move-result-object v2

    .line 657
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 658
    .line 659
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 660
    .line 661
    invoke-static {v4, v7, v1, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 662
    .line 663
    .line 664
    move-result-object v4

    .line 665
    iget-wide v7, v1, Ll2/t;->T:J

    .line 666
    .line 667
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 668
    .line 669
    .line 670
    move-result v5

    .line 671
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 672
    .line 673
    .line 674
    move-result-object v7

    .line 675
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 676
    .line 677
    .line 678
    move-result-object v2

    .line 679
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 680
    .line 681
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 682
    .line 683
    .line 684
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 685
    .line 686
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 687
    .line 688
    .line 689
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 690
    .line 691
    if-eqz v9, :cond_f

    .line 692
    .line 693
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 694
    .line 695
    .line 696
    goto :goto_f

    .line 697
    :cond_f
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 698
    .line 699
    .line 700
    :goto_f
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 701
    .line 702
    invoke-static {v8, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 703
    .line 704
    .line 705
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 706
    .line 707
    invoke-static {v4, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 708
    .line 709
    .line 710
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 711
    .line 712
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 713
    .line 714
    if-nez v7, :cond_10

    .line 715
    .line 716
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 717
    .line 718
    .line 719
    move-result-object v7

    .line 720
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 721
    .line 722
    .line 723
    move-result-object v8

    .line 724
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 725
    .line 726
    .line 727
    move-result v7

    .line 728
    if-nez v7, :cond_11

    .line 729
    .line 730
    :cond_10
    invoke-static {v5, v1, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 731
    .line 732
    .line 733
    :cond_11
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 734
    .line 735
    invoke-static {v4, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 736
    .line 737
    .line 738
    invoke-static {v1}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 739
    .line 740
    .line 741
    move-result-object v2

    .line 742
    invoke-virtual {v2}, Lj91/f;->a()Lg4/p0;

    .line 743
    .line 744
    .line 745
    move-result-object v8

    .line 746
    invoke-static {v1}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 747
    .line 748
    .line 749
    move-result-object v2

    .line 750
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 751
    .line 752
    .line 753
    move-result-wide v10

    .line 754
    const-string v2, "_title"

    .line 755
    .line 756
    iget-object v4, v0, Lbk/b;->e:Ljava/lang/String;

    .line 757
    .line 758
    invoke-virtual {v4, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 759
    .line 760
    .line 761
    move-result-object v2

    .line 762
    invoke-static {v3, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 763
    .line 764
    .line 765
    move-result-object v9

    .line 766
    const/16 v27, 0x0

    .line 767
    .line 768
    const v28, 0xfff0

    .line 769
    .line 770
    .line 771
    iget-object v7, v0, Lbk/b;->f:Ljava/lang/String;

    .line 772
    .line 773
    const-wide/16 v12, 0x0

    .line 774
    .line 775
    const/4 v14, 0x0

    .line 776
    const-wide/16 v15, 0x0

    .line 777
    .line 778
    const/16 v17, 0x0

    .line 779
    .line 780
    const/16 v18, 0x0

    .line 781
    .line 782
    const-wide/16 v19, 0x0

    .line 783
    .line 784
    const/16 v21, 0x0

    .line 785
    .line 786
    const/16 v22, 0x0

    .line 787
    .line 788
    const/16 v23, 0x0

    .line 789
    .line 790
    const/16 v24, 0x0

    .line 791
    .line 792
    const/16 v26, 0x0

    .line 793
    .line 794
    move-object/from16 v25, v1

    .line 795
    .line 796
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 797
    .line 798
    .line 799
    invoke-static/range {v25 .. v25}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 800
    .line 801
    .line 802
    move-result-object v1

    .line 803
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 804
    .line 805
    .line 806
    move-result-object v1

    .line 807
    invoke-static/range {v25 .. v25}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 808
    .line 809
    .line 810
    move-result-object v2

    .line 811
    iget v9, v2, Lj91/c;->b:F

    .line 812
    .line 813
    const/4 v11, 0x0

    .line 814
    const/16 v12, 0xd

    .line 815
    .line 816
    const/4 v8, 0x0

    .line 817
    const/4 v10, 0x0

    .line 818
    move-object v7, v3

    .line 819
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 820
    .line 821
    .line 822
    move-result-object v2

    .line 823
    const-string v5, "_value"

    .line 824
    .line 825
    invoke-virtual {v4, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 826
    .line 827
    .line 828
    move-result-object v5

    .line 829
    invoke-static {v2, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 830
    .line 831
    .line 832
    move-result-object v9

    .line 833
    const v28, 0xfff8

    .line 834
    .line 835
    .line 836
    iget-object v7, v0, Lbk/b;->g:Ljava/lang/String;

    .line 837
    .line 838
    const-wide/16 v10, 0x0

    .line 839
    .line 840
    const-wide/16 v12, 0x0

    .line 841
    .line 842
    move-object v8, v1

    .line 843
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 844
    .line 845
    .line 846
    invoke-static/range {v25 .. v25}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 847
    .line 848
    .line 849
    move-result-object v1

    .line 850
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 851
    .line 852
    .line 853
    move-result-object v1

    .line 854
    invoke-static/range {v25 .. v25}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 855
    .line 856
    .line 857
    move-result-object v2

    .line 858
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 859
    .line 860
    .line 861
    move-result-wide v13

    .line 862
    invoke-static/range {v25 .. v25}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 863
    .line 864
    .line 865
    move-result-object v2

    .line 866
    iget v9, v2, Lj91/c;->c:F

    .line 867
    .line 868
    const/4 v11, 0x0

    .line 869
    const/16 v12, 0xd

    .line 870
    .line 871
    const/4 v8, 0x0

    .line 872
    const/4 v10, 0x0

    .line 873
    move-object v7, v3

    .line 874
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 875
    .line 876
    .line 877
    move-result-object v2

    .line 878
    const-string v3, "_description"

    .line 879
    .line 880
    invoke-virtual {v4, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 881
    .line 882
    .line 883
    move-result-object v3

    .line 884
    invoke-static {v2, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 885
    .line 886
    .line 887
    move-result-object v9

    .line 888
    const v28, 0xfff0

    .line 889
    .line 890
    .line 891
    iget-object v7, v0, Lbk/b;->h:Ljava/lang/String;

    .line 892
    .line 893
    move-wide v10, v13

    .line 894
    const-wide/16 v12, 0x0

    .line 895
    .line 896
    const/4 v14, 0x0

    .line 897
    move-object v8, v1

    .line 898
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 899
    .line 900
    .line 901
    move-object/from16 v1, v25

    .line 902
    .line 903
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 904
    .line 905
    .line 906
    goto :goto_10

    .line 907
    :cond_12
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 908
    .line 909
    .line 910
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 911
    .line 912
    return-object v0

    .line 913
    :pswitch_2
    move-object/from16 v5, p1

    .line 914
    .line 915
    check-cast v5, Ll2/o;

    .line 916
    .line 917
    move-object/from16 v1, p2

    .line 918
    .line 919
    check-cast v1, Ljava/lang/Integer;

    .line 920
    .line 921
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 922
    .line 923
    .line 924
    const/16 v1, 0xc31

    .line 925
    .line 926
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 927
    .line 928
    .line 929
    move-result v6

    .line 930
    iget-object v1, v0, Lbk/b;->e:Ljava/lang/String;

    .line 931
    .line 932
    iget-object v2, v0, Lbk/b;->f:Ljava/lang/String;

    .line 933
    .line 934
    iget-object v3, v0, Lbk/b;->g:Ljava/lang/String;

    .line 935
    .line 936
    iget-object v4, v0, Lbk/b;->h:Ljava/lang/String;

    .line 937
    .line 938
    invoke-static/range {v1 .. v6}, Lbk/a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 939
    .line 940
    .line 941
    goto/16 :goto_0

    .line 942
    .line 943
    :pswitch_3
    move-object/from16 v5, p1

    .line 944
    .line 945
    check-cast v5, Ll2/o;

    .line 946
    .line 947
    move-object/from16 v1, p2

    .line 948
    .line 949
    check-cast v1, Ljava/lang/Integer;

    .line 950
    .line 951
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 952
    .line 953
    .line 954
    const/16 v1, 0xc31

    .line 955
    .line 956
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 957
    .line 958
    .line 959
    move-result v6

    .line 960
    iget-object v1, v0, Lbk/b;->e:Ljava/lang/String;

    .line 961
    .line 962
    iget-object v2, v0, Lbk/b;->f:Ljava/lang/String;

    .line 963
    .line 964
    iget-object v3, v0, Lbk/b;->g:Ljava/lang/String;

    .line 965
    .line 966
    iget-object v4, v0, Lbk/b;->h:Ljava/lang/String;

    .line 967
    .line 968
    invoke-static/range {v1 .. v6}, Lbk/a;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 969
    .line 970
    .line 971
    goto/16 :goto_0

    .line 972
    .line 973
    :pswitch_4
    move-object/from16 v5, p1

    .line 974
    .line 975
    check-cast v5, Ll2/o;

    .line 976
    .line 977
    move-object/from16 v1, p2

    .line 978
    .line 979
    check-cast v1, Ljava/lang/Integer;

    .line 980
    .line 981
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 982
    .line 983
    .line 984
    const/16 v1, 0xc31

    .line 985
    .line 986
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 987
    .line 988
    .line 989
    move-result v6

    .line 990
    iget-object v1, v0, Lbk/b;->e:Ljava/lang/String;

    .line 991
    .line 992
    iget-object v2, v0, Lbk/b;->f:Ljava/lang/String;

    .line 993
    .line 994
    iget-object v3, v0, Lbk/b;->g:Ljava/lang/String;

    .line 995
    .line 996
    iget-object v4, v0, Lbk/b;->h:Ljava/lang/String;

    .line 997
    .line 998
    invoke-static/range {v1 .. v6}, Lbk/a;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 999
    .line 1000
    .line 1001
    goto/16 :goto_0

    .line 1002
    .line 1003
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
