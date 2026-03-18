.class public abstract Ljp/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lm10/a;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    check-cast v6, Ll2/t;

    .line 6
    .line 7
    const v2, 0x5e15dbb2

    .line 8
    .line 9
    .line 10
    invoke-virtual {v6, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v3

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v4, v2, 0x3

    .line 26
    .line 27
    const/4 v10, 0x0

    .line 28
    const/4 v11, 0x1

    .line 29
    if-eq v4, v3, :cond_1

    .line 30
    .line 31
    move v4, v11

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v4, v10

    .line 34
    :goto_1
    and-int/2addr v2, v11

    .line 35
    invoke-virtual {v6, v2, v4}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_b

    .line 40
    .line 41
    iget v2, v0, Lm10/a;->a:I

    .line 42
    .line 43
    new-instance v4, Lym/n;

    .line 44
    .line 45
    invoke-direct {v4, v2}, Lym/n;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v4, v6}, Lcom/google/android/gms/internal/measurement/c4;->d(Lym/n;Ll2/o;)Lym/m;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {v2}, Lym/m;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    check-cast v4, Lum/a;

    .line 57
    .line 58
    const v5, 0x7fffffff

    .line 59
    .line 60
    .line 61
    const/16 v7, 0x3be

    .line 62
    .line 63
    invoke-static {v4, v10, v5, v6, v7}, Lc21/c;->a(Lum/a;ZILl2/o;I)Lym/g;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    sget-object v5, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 68
    .line 69
    sget-object v12, Lj91/a;->a:Ll2/u2;

    .line 70
    .line 71
    invoke-virtual {v6, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v7

    .line 75
    check-cast v7, Lj91/c;

    .line 76
    .line 77
    iget v7, v7, Lj91/c;->j:F

    .line 78
    .line 79
    const/4 v13, 0x0

    .line 80
    invoke-static {v5, v7, v13, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    sget-object v5, Lk1/j;->c:Lk1/e;

    .line 85
    .line 86
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 87
    .line 88
    invoke-static {v5, v7, v6, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    iget-wide v7, v6, Ll2/t;->T:J

    .line 93
    .line 94
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 99
    .line 100
    .line 101
    move-result-object v8

    .line 102
    invoke-static {v6, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 107
    .line 108
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 112
    .line 113
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 114
    .line 115
    .line 116
    iget-boolean v9, v6, Ll2/t;->S:Z

    .line 117
    .line 118
    if-eqz v9, :cond_2

    .line 119
    .line 120
    invoke-virtual {v6, v14}, Ll2/t;->l(Lay0/a;)V

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :cond_2
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 125
    .line 126
    .line 127
    :goto_2
    sget-object v15, Lv3/j;->g:Lv3/h;

    .line 128
    .line 129
    invoke-static {v15, v5, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 133
    .line 134
    invoke-static {v5, v8, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 135
    .line 136
    .line 137
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 138
    .line 139
    iget-boolean v9, v6, Ll2/t;->S:Z

    .line 140
    .line 141
    if-nez v9, :cond_3

    .line 142
    .line 143
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v9

    .line 147
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 148
    .line 149
    .line 150
    move-result-object v10

    .line 151
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v9

    .line 155
    if-nez v9, :cond_4

    .line 156
    .line 157
    :cond_3
    invoke-static {v7, v6, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 158
    .line 159
    .line 160
    :cond_4
    sget-object v10, Lv3/j;->d:Lv3/h;

    .line 161
    .line 162
    invoke-static {v10, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 163
    .line 164
    .line 165
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 166
    .line 167
    const/high16 v7, 0x3f800000    # 1.0f

    .line 168
    .line 169
    invoke-static {v3, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 170
    .line 171
    .line 172
    move-result-object v9

    .line 173
    move-object/from16 v17, v14

    .line 174
    .line 175
    float-to-double v13, v7

    .line 176
    const-wide/16 v18, 0x0

    .line 177
    .line 178
    cmpl-double v13, v13, v18

    .line 179
    .line 180
    if-lez v13, :cond_5

    .line 181
    .line 182
    goto :goto_3

    .line 183
    :cond_5
    const-string v13, "invalid weight; must be greater than zero"

    .line 184
    .line 185
    invoke-static {v13}, Ll1/a;->a(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    :goto_3
    new-instance v13, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 189
    .line 190
    invoke-direct {v13, v7, v11}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 191
    .line 192
    .line 193
    invoke-interface {v9, v13}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 194
    .line 195
    .line 196
    move-result-object v9

    .line 197
    invoke-virtual {v2}, Lym/m;->getValue()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    check-cast v2, Lum/a;

    .line 202
    .line 203
    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v13

    .line 207
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v14

    .line 211
    if-nez v13, :cond_6

    .line 212
    .line 213
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 214
    .line 215
    if-ne v14, v13, :cond_7

    .line 216
    .line 217
    :cond_6
    new-instance v14, Lcz/f;

    .line 218
    .line 219
    const/4 v13, 0x7

    .line 220
    invoke-direct {v14, v4, v13}, Lcz/f;-><init>(Lym/g;I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v6, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    :cond_7
    check-cast v14, Lay0/a;

    .line 227
    .line 228
    move-object v4, v8

    .line 229
    const/4 v8, 0x0

    .line 230
    move-object v13, v4

    .line 231
    move-object v4, v9

    .line 232
    const v9, 0x1fff8

    .line 233
    .line 234
    .line 235
    move-object/from16 v18, v5

    .line 236
    .line 237
    const/4 v5, 0x0

    .line 238
    move/from16 v19, v7

    .line 239
    .line 240
    const/4 v7, 0x0

    .line 241
    move-object v1, v3

    .line 242
    move-object v3, v14

    .line 243
    move/from16 v11, v19

    .line 244
    .line 245
    move-object v14, v13

    .line 246
    move-object/from16 v13, v18

    .line 247
    .line 248
    invoke-static/range {v2 .. v9}, Lcom/google/android/gms/internal/measurement/z3;->a(Lum/a;Lay0/a;Lx2/s;Lt3/k;Ll2/o;III)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v6, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    check-cast v2, Lj91/c;

    .line 256
    .line 257
    iget v2, v2, Lj91/c;->d:F

    .line 258
    .line 259
    invoke-static {v1, v2, v6, v1, v11}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 260
    .line 261
    .line 262
    move-result-object v2

    .line 263
    const/16 v3, 0x30

    .line 264
    .line 265
    int-to-float v3, v3

    .line 266
    const/4 v4, 0x0

    .line 267
    const/4 v5, 0x1

    .line 268
    invoke-static {v2, v4, v3, v5}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 273
    .line 274
    const/4 v4, 0x0

    .line 275
    invoke-static {v3, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 276
    .line 277
    .line 278
    move-result-object v3

    .line 279
    iget-wide v7, v6, Ll2/t;->T:J

    .line 280
    .line 281
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 282
    .line 283
    .line 284
    move-result v4

    .line 285
    invoke-virtual {v6}, Ll2/t;->m()Ll2/p1;

    .line 286
    .line 287
    .line 288
    move-result-object v7

    .line 289
    invoke-static {v6, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 290
    .line 291
    .line 292
    move-result-object v2

    .line 293
    invoke-virtual {v6}, Ll2/t;->c0()V

    .line 294
    .line 295
    .line 296
    iget-boolean v8, v6, Ll2/t;->S:Z

    .line 297
    .line 298
    if-eqz v8, :cond_8

    .line 299
    .line 300
    move-object/from16 v8, v17

    .line 301
    .line 302
    invoke-virtual {v6, v8}, Ll2/t;->l(Lay0/a;)V

    .line 303
    .line 304
    .line 305
    goto :goto_4

    .line 306
    :cond_8
    invoke-virtual {v6}, Ll2/t;->m0()V

    .line 307
    .line 308
    .line 309
    :goto_4
    invoke-static {v15, v3, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 310
    .line 311
    .line 312
    invoke-static {v13, v7, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    iget-boolean v3, v6, Ll2/t;->S:Z

    .line 316
    .line 317
    if-nez v3, :cond_9

    .line 318
    .line 319
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v3

    .line 323
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 324
    .line 325
    .line 326
    move-result-object v7

    .line 327
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v3

    .line 331
    if-nez v3, :cond_a

    .line 332
    .line 333
    :cond_9
    invoke-static {v4, v6, v4, v14}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 334
    .line 335
    .line 336
    :cond_a
    invoke-static {v10, v2, v6}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 337
    .line 338
    .line 339
    invoke-static {v1, v11}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 340
    .line 341
    .line 342
    move-result-object v4

    .line 343
    iget-object v2, v0, Lm10/a;->b:Ljava/lang/String;

    .line 344
    .line 345
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 346
    .line 347
    invoke-virtual {v6, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v1

    .line 351
    check-cast v1, Lj91/f;

    .line 352
    .line 353
    invoke-virtual {v1}, Lj91/f;->k()Lg4/p0;

    .line 354
    .line 355
    .line 356
    move-result-object v3

    .line 357
    const/16 v22, 0x0

    .line 358
    .line 359
    const v23, 0xfff8

    .line 360
    .line 361
    .line 362
    move/from16 v18, v5

    .line 363
    .line 364
    move-object/from16 v20, v6

    .line 365
    .line 366
    const-wide/16 v5, 0x0

    .line 367
    .line 368
    const-wide/16 v7, 0x0

    .line 369
    .line 370
    const/4 v9, 0x0

    .line 371
    const-wide/16 v10, 0x0

    .line 372
    .line 373
    const/4 v12, 0x0

    .line 374
    const/4 v13, 0x0

    .line 375
    const-wide/16 v14, 0x0

    .line 376
    .line 377
    const/16 v16, 0x0

    .line 378
    .line 379
    const/16 v17, 0x0

    .line 380
    .line 381
    move/from16 v1, v18

    .line 382
    .line 383
    const/16 v18, 0x0

    .line 384
    .line 385
    const/16 v19, 0x0

    .line 386
    .line 387
    const/16 v21, 0x180

    .line 388
    .line 389
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 390
    .line 391
    .line 392
    move-object/from16 v6, v20

    .line 393
    .line 394
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    .line 395
    .line 396
    .line 397
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    .line 398
    .line 399
    .line 400
    goto :goto_5

    .line 401
    :cond_b
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 402
    .line 403
    .line 404
    :goto_5
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    if-eqz v1, :cond_c

    .line 409
    .line 410
    new-instance v2, Ln10/a;

    .line 411
    .line 412
    const/4 v3, 0x1

    .line 413
    move/from16 v4, p2

    .line 414
    .line 415
    invoke-direct {v2, v0, v4, v3}, Ln10/a;-><init>(Lm10/a;II)V

    .line 416
    .line 417
    .line 418
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 419
    .line 420
    :cond_c
    return-void
.end method

.method public static final b(Ll2/o;I)V
    .locals 12

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x266cfc47

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_6

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_5

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Lm10/d;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, Lm10/d;

    .line 73
    .line 74
    iget-object v2, v5, Lql0/j;->g:Lyy0/l1;

    .line 75
    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-static {v2, v3, p0, v0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, Lm10/c;

    .line 86
    .line 87
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 96
    .line 97
    if-nez v2, :cond_1

    .line 98
    .line 99
    if-ne v3, v11, :cond_2

    .line 100
    .line 101
    :cond_1
    new-instance v3, Ln10/b;

    .line 102
    .line 103
    const/4 v9, 0x0

    .line 104
    const/4 v10, 0x0

    .line 105
    const/4 v4, 0x0

    .line 106
    const-class v6, Lm10/d;

    .line 107
    .line 108
    const-string v7, "onLogin"

    .line 109
    .line 110
    const-string v8, "onLogin()V"

    .line 111
    .line 112
    invoke-direct/range {v3 .. v10}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_2
    check-cast v3, Lhy0/g;

    .line 119
    .line 120
    move-object v2, v3

    .line 121
    check-cast v2, Lay0/a;

    .line 122
    .line 123
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    if-nez v3, :cond_3

    .line 132
    .line 133
    if-ne v4, v11, :cond_4

    .line 134
    .line 135
    :cond_3
    new-instance v3, Ln10/b;

    .line 136
    .line 137
    const/4 v9, 0x0

    .line 138
    const/4 v10, 0x1

    .line 139
    const/4 v4, 0x0

    .line 140
    const-class v6, Lm10/d;

    .line 141
    .line 142
    const-string v7, "onClose"

    .line 143
    .line 144
    const-string v8, "onClose()V"

    .line 145
    .line 146
    invoke-direct/range {v3 .. v10}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    move-object v4, v3

    .line 153
    :cond_4
    check-cast v4, Lhy0/g;

    .line 154
    .line 155
    check-cast v4, Lay0/a;

    .line 156
    .line 157
    invoke-static {v0, v2, v4, p0, v1}, Ljp/t1;->c(Lm10/c;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 158
    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 162
    .line 163
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 164
    .line 165
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p0

    .line 169
    :cond_6
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 170
    .line 171
    .line 172
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    if-eqz p0, :cond_7

    .line 177
    .line 178
    new-instance v0, Lmo0/a;

    .line 179
    .line 180
    const/16 v1, 0x8

    .line 181
    .line 182
    invoke-direct {v0, p1, v1}, Lmo0/a;-><init>(II)V

    .line 183
    .line 184
    .line 185
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 186
    .line 187
    :cond_7
    return-void
.end method

.method public static final c(Lm10/c;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    move-object/from16 v0, p3

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v1, 0x62c2adb0

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x2

    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    const/4 v1, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v1, v2

    .line 27
    :goto_0
    or-int v1, p4, v1

    .line 28
    .line 29
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-eqz v6, :cond_1

    .line 34
    .line 35
    const/16 v6, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v6, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v1, v6

    .line 41
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_2

    .line 46
    .line 47
    const/16 v6, 0x100

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/16 v6, 0x80

    .line 51
    .line 52
    :goto_2
    or-int/2addr v1, v6

    .line 53
    and-int/lit16 v6, v1, 0x93

    .line 54
    .line 55
    const/16 v7, 0x92

    .line 56
    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v9, 0x1

    .line 59
    if-eq v6, v7, :cond_3

    .line 60
    .line 61
    move v6, v9

    .line 62
    goto :goto_3

    .line 63
    :cond_3
    move v6, v8

    .line 64
    :goto_3
    and-int/2addr v1, v9

    .line 65
    invoke-virtual {v0, v1, v6}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_6

    .line 70
    .line 71
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    if-nez v1, :cond_4

    .line 80
    .line 81
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 82
    .line 83
    if-ne v6, v1, :cond_5

    .line 84
    .line 85
    :cond_4
    new-instance v6, Lmc/e;

    .line 86
    .line 87
    const/4 v1, 0x6

    .line 88
    invoke-direct {v6, v3, v1}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_5
    check-cast v6, Lay0/a;

    .line 95
    .line 96
    const/4 v1, 0x6

    .line 97
    invoke-static {v8, v6, v0, v1, v2}, Lp1/y;->b(ILay0/a;Ll2/o;II)Lp1/b;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    new-instance v2, Li40/r0;

    .line 102
    .line 103
    const/16 v6, 0x1b

    .line 104
    .line 105
    invoke-direct {v2, v5, v6}, Li40/r0;-><init>(Lay0/a;I)V

    .line 106
    .line 107
    .line 108
    const v6, 0x5b475b74

    .line 109
    .line 110
    .line 111
    invoke-static {v6, v0, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    new-instance v2, Li40/r0;

    .line 116
    .line 117
    const/16 v6, 0x1c

    .line 118
    .line 119
    invoke-direct {v2, v4, v6}, Li40/r0;-><init>(Lay0/a;I)V

    .line 120
    .line 121
    .line 122
    const v6, -0x10d4ec4b

    .line 123
    .line 124
    .line 125
    invoke-static {v6, v0, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 126
    .line 127
    .line 128
    move-result-object v8

    .line 129
    new-instance v2, Li50/j;

    .line 130
    .line 131
    const/16 v6, 0xe

    .line 132
    .line 133
    invoke-direct {v2, v6, v1, v3}, Li50/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    const v1, 0x2d72faff

    .line 137
    .line 138
    .line 139
    invoke-static {v1, v0, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 140
    .line 141
    .line 142
    move-result-object v17

    .line 143
    const v19, 0x300001b0

    .line 144
    .line 145
    .line 146
    const/16 v20, 0x1f9

    .line 147
    .line 148
    const/4 v6, 0x0

    .line 149
    const/4 v9, 0x0

    .line 150
    const/4 v10, 0x0

    .line 151
    const/4 v11, 0x0

    .line 152
    const-wide/16 v12, 0x0

    .line 153
    .line 154
    const-wide/16 v14, 0x0

    .line 155
    .line 156
    const/16 v16, 0x0

    .line 157
    .line 158
    move-object/from16 v18, v0

    .line 159
    .line 160
    invoke-static/range {v6 .. v20}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 161
    .line 162
    .line 163
    goto :goto_4

    .line 164
    :cond_6
    move-object/from16 v18, v0

    .line 165
    .line 166
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 167
    .line 168
    .line 169
    :goto_4
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 170
    .line 171
    .line 172
    move-result-object v6

    .line 173
    if-eqz v6, :cond_7

    .line 174
    .line 175
    new-instance v0, Li91/k3;

    .line 176
    .line 177
    const/16 v2, 0xc

    .line 178
    .line 179
    move/from16 v1, p4

    .line 180
    .line 181
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 185
    .line 186
    :cond_7
    return-void
.end method

.method public static final d(Lm10/a;Ll2/o;I)V
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v2, -0x6bf2a920

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v9, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    const/4 v2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move v2, v3

    .line 23
    :goto_0
    or-int v2, p2, v2

    .line 24
    .line 25
    and-int/lit8 v4, v2, 0x3

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x1

    .line 29
    if-eq v4, v3, :cond_1

    .line 30
    .line 31
    move v4, v6

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v4, v5

    .line 34
    :goto_1
    and-int/2addr v2, v6

    .line 35
    invoke-virtual {v9, v2, v4}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_7

    .line 40
    .line 41
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 42
    .line 43
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 44
    .line 45
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v7

    .line 49
    check-cast v7, Lj91/c;

    .line 50
    .line 51
    iget v7, v7, Lj91/c;->j:F

    .line 52
    .line 53
    const/4 v8, 0x0

    .line 54
    invoke-static {v2, v7, v8, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 59
    .line 60
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 61
    .line 62
    invoke-static {v3, v7, v9, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    iget-wide v7, v9, Ll2/t;->T:J

    .line 67
    .line 68
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 69
    .line 70
    .line 71
    move-result v7

    .line 72
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 73
    .line 74
    .line 75
    move-result-object v8

    .line 76
    invoke-static {v9, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 81
    .line 82
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 86
    .line 87
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 88
    .line 89
    .line 90
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 91
    .line 92
    if-eqz v11, :cond_2

    .line 93
    .line 94
    invoke-virtual {v9, v10}, Ll2/t;->l(Lay0/a;)V

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_2
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 99
    .line 100
    .line 101
    :goto_2
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 102
    .line 103
    invoke-static {v10, v3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 104
    .line 105
    .line 106
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 107
    .line 108
    invoke-static {v3, v8, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 109
    .line 110
    .line 111
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 112
    .line 113
    iget-boolean v8, v9, Ll2/t;->S:Z

    .line 114
    .line 115
    if-nez v8, :cond_3

    .line 116
    .line 117
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v8

    .line 121
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    if-nez v8, :cond_4

    .line 130
    .line 131
    :cond_3
    invoke-static {v7, v9, v7, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 132
    .line 133
    .line 134
    :cond_4
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 135
    .line 136
    invoke-static {v3, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v9, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    check-cast v2, Lj91/c;

    .line 144
    .line 145
    iget v2, v2, Lj91/c;->e:F

    .line 146
    .line 147
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 148
    .line 149
    const/high16 v7, 0x3f800000    # 1.0f

    .line 150
    .line 151
    invoke-static {v3, v2, v9, v3, v7}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    move-object v8, v4

    .line 156
    move-object v4, v2

    .line 157
    iget-object v2, v0, Lm10/a;->b:Ljava/lang/String;

    .line 158
    .line 159
    sget-object v10, Lj91/j;->a:Ll2/u2;

    .line 160
    .line 161
    invoke-virtual {v9, v10}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v11

    .line 165
    check-cast v11, Lj91/f;

    .line 166
    .line 167
    invoke-virtual {v11}, Lj91/f;->i()Lg4/p0;

    .line 168
    .line 169
    .line 170
    move-result-object v11

    .line 171
    const/16 v22, 0x0

    .line 172
    .line 173
    const v23, 0xfff8

    .line 174
    .line 175
    .line 176
    move v12, v5

    .line 177
    move v13, v6

    .line 178
    const-wide/16 v5, 0x0

    .line 179
    .line 180
    move v15, v7

    .line 181
    move-object v14, v8

    .line 182
    const-wide/16 v7, 0x0

    .line 183
    .line 184
    move-object/from16 v20, v9

    .line 185
    .line 186
    const/4 v9, 0x0

    .line 187
    move-object/from16 v17, v3

    .line 188
    .line 189
    move-object/from16 v16, v10

    .line 190
    .line 191
    move-object v3, v11

    .line 192
    const-wide/16 v10, 0x0

    .line 193
    .line 194
    move/from16 v18, v12

    .line 195
    .line 196
    const/4 v12, 0x0

    .line 197
    move/from16 v19, v13

    .line 198
    .line 199
    const/4 v13, 0x0

    .line 200
    move-object/from16 v21, v14

    .line 201
    .line 202
    move/from16 v24, v15

    .line 203
    .line 204
    const-wide/16 v14, 0x0

    .line 205
    .line 206
    move-object/from16 v25, v16

    .line 207
    .line 208
    const/16 v16, 0x0

    .line 209
    .line 210
    move-object/from16 v26, v17

    .line 211
    .line 212
    const/16 v17, 0x0

    .line 213
    .line 214
    move/from16 v27, v18

    .line 215
    .line 216
    const/16 v18, 0x0

    .line 217
    .line 218
    move/from16 v28, v19

    .line 219
    .line 220
    const/16 v19, 0x0

    .line 221
    .line 222
    move-object/from16 v29, v21

    .line 223
    .line 224
    const/16 v21, 0x180

    .line 225
    .line 226
    move-object/from16 v30, v25

    .line 227
    .line 228
    move-object/from16 v0, v26

    .line 229
    .line 230
    move-object/from16 v1, v29

    .line 231
    .line 232
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 233
    .line 234
    .line 235
    move-object/from16 v9, v20

    .line 236
    .line 237
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    check-cast v1, Lj91/c;

    .line 242
    .line 243
    iget v1, v1, Lj91/c;->e:F

    .line 244
    .line 245
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    invoke-static {v9, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 250
    .line 251
    .line 252
    move-object/from16 v1, p0

    .line 253
    .line 254
    iget-object v2, v1, Lm10/a;->c:Ljava/lang/String;

    .line 255
    .line 256
    if-nez v2, :cond_5

    .line 257
    .line 258
    const v2, -0x6e500337

    .line 259
    .line 260
    .line 261
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 262
    .line 263
    .line 264
    const/4 v2, 0x0

    .line 265
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    move-object/from16 v26, v0

    .line 269
    .line 270
    move v0, v2

    .line 271
    goto :goto_3

    .line 272
    :cond_5
    const/4 v2, 0x0

    .line 273
    const v3, -0x6e500336

    .line 274
    .line 275
    .line 276
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 277
    .line 278
    .line 279
    const/high16 v3, 0x3f800000    # 1.0f

    .line 280
    .line 281
    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 282
    .line 283
    .line 284
    move-result-object v4

    .line 285
    move/from16 v32, v2

    .line 286
    .line 287
    iget-object v2, v1, Lm10/a;->c:Ljava/lang/String;

    .line 288
    .line 289
    move-object/from16 v5, v30

    .line 290
    .line 291
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v5

    .line 295
    check-cast v5, Lj91/f;

    .line 296
    .line 297
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 298
    .line 299
    .line 300
    move-result-object v5

    .line 301
    const/16 v22, 0x0

    .line 302
    .line 303
    const v23, 0xfff8

    .line 304
    .line 305
    .line 306
    move v15, v3

    .line 307
    move-object v3, v5

    .line 308
    const-wide/16 v5, 0x0

    .line 309
    .line 310
    const-wide/16 v7, 0x0

    .line 311
    .line 312
    move-object/from16 v20, v9

    .line 313
    .line 314
    const/4 v9, 0x0

    .line 315
    const-wide/16 v10, 0x0

    .line 316
    .line 317
    const/4 v12, 0x0

    .line 318
    const/4 v13, 0x0

    .line 319
    move/from16 v31, v15

    .line 320
    .line 321
    const-wide/16 v14, 0x0

    .line 322
    .line 323
    const/16 v16, 0x0

    .line 324
    .line 325
    const/16 v17, 0x0

    .line 326
    .line 327
    const/16 v18, 0x0

    .line 328
    .line 329
    const/16 v19, 0x0

    .line 330
    .line 331
    const/16 v21, 0x180

    .line 332
    .line 333
    move-object/from16 v26, v0

    .line 334
    .line 335
    move/from16 v0, v32

    .line 336
    .line 337
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 338
    .line 339
    .line 340
    move-object/from16 v9, v20

    .line 341
    .line 342
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 343
    .line 344
    .line 345
    :goto_3
    iget v2, v1, Lm10/a;->a:I

    .line 346
    .line 347
    invoke-static {v2, v0, v9}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 348
    .line 349
    .line 350
    move-result-object v2

    .line 351
    move-object/from16 v0, v26

    .line 352
    .line 353
    const/high16 v15, 0x3f800000    # 1.0f

    .line 354
    .line 355
    invoke-static {v0, v15}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    float-to-double v3, v15

    .line 360
    const-wide/16 v5, 0x0

    .line 361
    .line 362
    cmpl-double v3, v3, v5

    .line 363
    .line 364
    if-lez v3, :cond_6

    .line 365
    .line 366
    goto :goto_4

    .line 367
    :cond_6
    const-string v3, "invalid weight; must be greater than zero"

    .line 368
    .line 369
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 370
    .line 371
    .line 372
    :goto_4
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 373
    .line 374
    const/4 v13, 0x1

    .line 375
    invoke-direct {v3, v15, v13}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 376
    .line 377
    .line 378
    invoke-interface {v0, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 379
    .line 380
    .line 381
    move-result-object v4

    .line 382
    const/16 v10, 0x30

    .line 383
    .line 384
    const/16 v11, 0x78

    .line 385
    .line 386
    const/4 v3, 0x0

    .line 387
    const/4 v5, 0x0

    .line 388
    const/4 v6, 0x0

    .line 389
    const/4 v7, 0x0

    .line 390
    const/4 v8, 0x0

    .line 391
    invoke-static/range {v2 .. v11}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v9, v13}, Ll2/t;->q(Z)V

    .line 395
    .line 396
    .line 397
    goto :goto_5

    .line 398
    :cond_7
    move-object v1, v0

    .line 399
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 400
    .line 401
    .line 402
    :goto_5
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    if-eqz v0, :cond_8

    .line 407
    .line 408
    new-instance v2, Ln10/a;

    .line 409
    .line 410
    const/4 v3, 0x0

    .line 411
    move/from16 v4, p2

    .line 412
    .line 413
    invoke-direct {v2, v1, v4, v3}, Ln10/a;-><init>(Lm10/a;II)V

    .line 414
    .line 415
    .line 416
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 417
    .line 418
    :cond_8
    return-void
.end method

.method public static e(Lb/h0;Lb/t;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb/i0;

    .line 7
    .line 8
    invoke-direct {v0, p2}, Lb/i0;-><init>(Lay0/k;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1, v0}, Lb/h0;->a(Landroidx/lifecycle/x;Lb/a0;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method
