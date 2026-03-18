.class public abstract Llp/id;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Llx0/l;Ljava/lang/String;Lx2/s;Ll2/o;I)V
    .locals 19

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
    move/from16 v1, p4

    .line 8
    .line 9
    move-object/from16 v14, p3

    .line 10
    .line 11
    check-cast v14, Ll2/t;

    .line 12
    .line 13
    const v0, -0x6bf8734e

    .line 14
    .line 15
    .line 16
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, v1, 0x6

    .line 20
    .line 21
    const/4 v6, 0x2

    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    const/4 v0, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move v0, v6

    .line 33
    :goto_0
    or-int/2addr v0, v1

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v0, v1

    .line 36
    :goto_1
    and-int/lit8 v7, v1, 0x30

    .line 37
    .line 38
    if-nez v7, :cond_3

    .line 39
    .line 40
    invoke-virtual {v14, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    if-eqz v7, :cond_2

    .line 45
    .line 46
    const/16 v7, 0x20

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v7, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v7

    .line 52
    :cond_3
    and-int/lit16 v7, v1, 0x180

    .line 53
    .line 54
    const-string v8, "wallbox"

    .line 55
    .line 56
    if-nez v7, :cond_5

    .line 57
    .line 58
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v7

    .line 62
    if-eqz v7, :cond_4

    .line 63
    .line 64
    const/16 v7, 0x100

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_4
    const/16 v7, 0x80

    .line 68
    .line 69
    :goto_3
    or-int/2addr v0, v7

    .line 70
    :cond_5
    and-int/lit16 v7, v1, 0xc00

    .line 71
    .line 72
    if-nez v7, :cond_7

    .line 73
    .line 74
    invoke-virtual {v14, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    if-eqz v7, :cond_6

    .line 79
    .line 80
    const/16 v7, 0x800

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_6
    const/16 v7, 0x400

    .line 84
    .line 85
    :goto_4
    or-int/2addr v0, v7

    .line 86
    :cond_7
    and-int/lit16 v7, v1, 0x6000

    .line 87
    .line 88
    sget-object v10, Lt3/j;->b:Lt3/x0;

    .line 89
    .line 90
    if-nez v7, :cond_9

    .line 91
    .line 92
    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v7

    .line 96
    if-eqz v7, :cond_8

    .line 97
    .line 98
    const/16 v7, 0x4000

    .line 99
    .line 100
    goto :goto_5

    .line 101
    :cond_8
    const/16 v7, 0x2000

    .line 102
    .line 103
    :goto_5
    or-int/2addr v0, v7

    .line 104
    :cond_9
    const/high16 v7, 0x30000

    .line 105
    .line 106
    and-int/2addr v7, v1

    .line 107
    const/4 v9, 0x1

    .line 108
    if-nez v7, :cond_b

    .line 109
    .line 110
    invoke-virtual {v14, v9}, Ll2/t;->h(Z)Z

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    if-eqz v7, :cond_a

    .line 115
    .line 116
    const/high16 v7, 0x20000

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_a
    const/high16 v7, 0x10000

    .line 120
    .line 121
    :goto_6
    or-int/2addr v0, v7

    .line 122
    :cond_b
    const v7, 0x12493

    .line 123
    .line 124
    .line 125
    and-int/2addr v7, v0

    .line 126
    const v11, 0x12492

    .line 127
    .line 128
    .line 129
    const/4 v12, 0x0

    .line 130
    if-eq v7, v11, :cond_c

    .line 131
    .line 132
    move v7, v9

    .line 133
    goto :goto_7

    .line 134
    :cond_c
    move v7, v12

    .line 135
    :goto_7
    and-int/lit8 v11, v0, 0x1

    .line 136
    .line 137
    invoke-virtual {v14, v11, v7}, Ll2/t;->O(IZ)Z

    .line 138
    .line 139
    .line 140
    move-result v7

    .line 141
    if-eqz v7, :cond_11

    .line 142
    .line 143
    sget-object v7, Lx2/c;->h:Lx2/j;

    .line 144
    .line 145
    invoke-static {v5, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 146
    .line 147
    .line 148
    move-result-object v11

    .line 149
    invoke-static {v7, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    move-object/from16 p3, v10

    .line 154
    .line 155
    iget-wide v9, v14, Ll2/t;->T:J

    .line 156
    .line 157
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 158
    .line 159
    .line 160
    move-result v9

    .line 161
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 162
    .line 163
    .line 164
    move-result-object v10

    .line 165
    invoke-static {v14, v11}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 166
    .line 167
    .line 168
    move-result-object v11

    .line 169
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 170
    .line 171
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 175
    .line 176
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 177
    .line 178
    .line 179
    iget-boolean v12, v14, Ll2/t;->S:Z

    .line 180
    .line 181
    if-eqz v12, :cond_d

    .line 182
    .line 183
    invoke-virtual {v14, v15}, Ll2/t;->l(Lay0/a;)V

    .line 184
    .line 185
    .line 186
    goto :goto_8

    .line 187
    :cond_d
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 188
    .line 189
    .line 190
    :goto_8
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 191
    .line 192
    invoke-static {v12, v7, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 193
    .line 194
    .line 195
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 196
    .line 197
    invoke-static {v7, v10, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 201
    .line 202
    iget-boolean v10, v14, Ll2/t;->S:Z

    .line 203
    .line 204
    if-nez v10, :cond_e

    .line 205
    .line 206
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v10

    .line 210
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 211
    .line 212
    .line 213
    move-result-object v12

    .line 214
    invoke-static {v10, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v10

    .line 218
    if-nez v10, :cond_f

    .line 219
    .line 220
    :cond_e
    invoke-static {v9, v14, v9, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 221
    .line 222
    .line 223
    :cond_f
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 224
    .line 225
    invoke-static {v7, v11, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 226
    .line 227
    .line 228
    iget-object v7, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast v7, Lkc/e;

    .line 231
    .line 232
    sget-object v9, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 233
    .line 234
    const/4 v10, 0x1

    .line 235
    new-instance v13, Lkc/h;

    .line 236
    .line 237
    invoke-direct {v13, v6}, Lkc/h;-><init>(I)V

    .line 238
    .line 239
    .line 240
    and-int/lit16 v6, v0, 0x380

    .line 241
    .line 242
    const/4 v11, 0x6

    .line 243
    or-int/2addr v6, v11

    .line 244
    const v12, 0xe000

    .line 245
    .line 246
    .line 247
    and-int/2addr v12, v0

    .line 248
    or-int v15, v6, v12

    .line 249
    .line 250
    const/4 v6, 0x0

    .line 251
    const/16 v16, 0x68

    .line 252
    .line 253
    move v12, v6

    .line 254
    move-object v6, v9

    .line 255
    const/4 v9, 0x0

    .line 256
    move/from16 v17, v11

    .line 257
    .line 258
    const/4 v11, 0x0

    .line 259
    move/from16 v18, v12

    .line 260
    .line 261
    const/4 v12, 0x0

    .line 262
    move-object/from16 v10, p3

    .line 263
    .line 264
    move/from16 v2, v18

    .line 265
    .line 266
    invoke-static/range {v6 .. v16}, Lkc/d;->c(Lx2/s;Lkc/e;Ljava/lang/String;Lx2/e;Lt3/k;Lay0/n;Lay0/n;Lkc/i;Ll2/o;II)V

    .line 267
    .line 268
    .line 269
    move-object v15, v6

    .line 270
    move-object/from16 v17, v8

    .line 271
    .line 272
    move-object/from16 v16, v10

    .line 273
    .line 274
    iget-object v6, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 275
    .line 276
    move-object/from16 v18, v6

    .line 277
    .line 278
    check-cast v18, Lkc/e;

    .line 279
    .line 280
    if-nez v18, :cond_10

    .line 281
    .line 282
    const v0, 0x78eeeb18

    .line 283
    .line 284
    .line 285
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 286
    .line 287
    .line 288
    :goto_9
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 289
    .line 290
    .line 291
    const/4 v13, 0x1

    .line 292
    goto :goto_a

    .line 293
    :cond_10
    const v6, 0x78eeeb19

    .line 294
    .line 295
    .line 296
    invoke-virtual {v14, v6}, Ll2/t;->Y(I)V

    .line 297
    .line 298
    .line 299
    const-string v6, "CrossFadeNetworkImage-transition"

    .line 300
    .line 301
    invoke-static {v6, v14, v2}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    const/16 v7, 0x4b0

    .line 306
    .line 307
    const/4 v8, 0x0

    .line 308
    const/4 v9, 0x6

    .line 309
    invoke-static {v7, v2, v8, v9}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    sget-object v8, Lc1/t0;->e:Lc1/t0;

    .line 314
    .line 315
    const/4 v9, 0x4

    .line 316
    invoke-static {v7, v8, v9}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 317
    .line 318
    .line 319
    move-result-object v9

    .line 320
    const/16 v12, 0x71b8

    .line 321
    .line 322
    const/4 v13, 0x0

    .line 323
    const/4 v7, 0x0

    .line 324
    const/high16 v8, 0x3f800000    # 1.0f

    .line 325
    .line 326
    const-string v10, "CrossFadeNetworkImage"

    .line 327
    .line 328
    move-object v11, v14

    .line 329
    invoke-static/range {v6 .. v13}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 330
    .line 331
    .line 332
    move-result-object v6

    .line 333
    new-instance v13, Lkc/f;

    .line 334
    .line 335
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 336
    .line 337
    .line 338
    iget-object v6, v6, Lc1/g0;->g:Ll2/j1;

    .line 339
    .line 340
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v6

    .line 344
    check-cast v6, Ljava/lang/Number;

    .line 345
    .line 346
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 347
    .line 348
    .line 349
    move-result v6

    .line 350
    invoke-static {v15, v6}, Ljp/a2;->a(Lx2/s;F)Lx2/s;

    .line 351
    .line 352
    .line 353
    move-result-object v6

    .line 354
    const v7, 0xe380

    .line 355
    .line 356
    .line 357
    and-int v15, v0, v7

    .line 358
    .line 359
    move-object/from16 v10, v16

    .line 360
    .line 361
    const/16 v16, 0x68

    .line 362
    .line 363
    const/4 v9, 0x0

    .line 364
    const/4 v11, 0x0

    .line 365
    const/4 v12, 0x0

    .line 366
    move-object/from16 v8, v17

    .line 367
    .line 368
    move-object/from16 v7, v18

    .line 369
    .line 370
    invoke-static/range {v6 .. v16}, Lkc/d;->c(Lx2/s;Lkc/e;Ljava/lang/String;Lx2/e;Lt3/k;Lay0/n;Lay0/n;Lkc/i;Ll2/o;II)V

    .line 371
    .line 372
    .line 373
    goto :goto_9

    .line 374
    :goto_a
    invoke-virtual {v14, v13}, Ll2/t;->q(Z)V

    .line 375
    .line 376
    .line 377
    goto :goto_b

    .line 378
    :cond_11
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 379
    .line 380
    .line 381
    :goto_b
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 382
    .line 383
    .line 384
    move-result-object v6

    .line 385
    if-eqz v6, :cond_12

    .line 386
    .line 387
    new-instance v0, Li50/j0;

    .line 388
    .line 389
    const/4 v2, 0x6

    .line 390
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 391
    .line 392
    .line 393
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 394
    .line 395
    :cond_12
    return-void
.end method

.method public static final b(Ljava/lang/Integer;Lvh/u;Lay0/k;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v5, p2

    .line 4
    .line 5
    const-string v0, "event"

    .line 6
    .line 7
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v11, p3

    .line 11
    .line 12
    check-cast v11, Ll2/t;

    .line 13
    .line 14
    const v0, -0x7621b6de

    .line 15
    .line 16
    .line 17
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v1, 0x4

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    move v0, v1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int v0, p4, v0

    .line 31
    .line 32
    move-object/from16 v4, p1

    .line 33
    .line 34
    invoke-virtual {v11, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_1

    .line 39
    .line 40
    const/16 v2, 0x20

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    const/16 v2, 0x10

    .line 44
    .line 45
    :goto_1
    or-int/2addr v0, v2

    .line 46
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    const/16 v6, 0x100

    .line 51
    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    move v2, v6

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v2, 0x80

    .line 57
    .line 58
    :goto_2
    or-int/2addr v0, v2

    .line 59
    and-int/lit16 v2, v0, 0x93

    .line 60
    .line 61
    const/16 v7, 0x92

    .line 62
    .line 63
    const/4 v8, 0x0

    .line 64
    const/4 v9, 0x1

    .line 65
    if-eq v2, v7, :cond_3

    .line 66
    .line 67
    move v2, v9

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    move v2, v8

    .line 70
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 71
    .line 72
    invoke-virtual {v11, v7, v2}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-eqz v2, :cond_d

    .line 77
    .line 78
    and-int/lit8 v2, v0, 0xe

    .line 79
    .line 80
    if-ne v2, v1, :cond_4

    .line 81
    .line 82
    move v1, v9

    .line 83
    goto :goto_4

    .line 84
    :cond_4
    move v1, v8

    .line 85
    :goto_4
    and-int/lit16 v2, v0, 0x380

    .line 86
    .line 87
    if-ne v2, v6, :cond_5

    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_5
    move v9, v8

    .line 91
    :goto_5
    or-int/2addr v1, v9

    .line 92
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 97
    .line 98
    if-nez v1, :cond_6

    .line 99
    .line 100
    if-ne v2, v12, :cond_7

    .line 101
    .line 102
    :cond_6
    new-instance v2, Lwh/g;

    .line 103
    .line 104
    const/4 v1, 0x0

    .line 105
    invoke-direct {v2, v3, v5, v1}, Lwh/g;-><init>(Ljava/lang/Integer;Lay0/k;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_7
    check-cast v2, Lay0/k;

    .line 112
    .line 113
    sget-object v1, Lw3/q1;->a:Ll2/u2;

    .line 114
    .line 115
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    check-cast v1, Ljava/lang/Boolean;

    .line 120
    .line 121
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    if-eqz v1, :cond_8

    .line 126
    .line 127
    const v1, -0x105bcaaa

    .line 128
    .line 129
    .line 130
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V

    .line 134
    .line 135
    .line 136
    const/4 v1, 0x0

    .line 137
    goto :goto_6

    .line 138
    :cond_8
    const v1, 0x31054eee

    .line 139
    .line 140
    .line 141
    invoke-virtual {v11, v1}, Ll2/t;->Y(I)V

    .line 142
    .line 143
    .line 144
    sget-object v1, Lzb/x;->a:Ll2/u2;

    .line 145
    .line 146
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    check-cast v1, Lhi/a;

    .line 151
    .line 152
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    :goto_6
    new-instance v9, Lvh/i;

    .line 156
    .line 157
    const/4 v6, 0x3

    .line 158
    invoke-direct {v9, v6, v1, v2}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    if-eqz v7, :cond_c

    .line 166
    .line 167
    instance-of v1, v7, Landroidx/lifecycle/k;

    .line 168
    .line 169
    if-eqz v1, :cond_9

    .line 170
    .line 171
    move-object v1, v7

    .line 172
    check-cast v1, Landroidx/lifecycle/k;

    .line 173
    .line 174
    invoke-interface {v1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    :goto_7
    move-object v10, v1

    .line 179
    goto :goto_8

    .line 180
    :cond_9
    sget-object v1, Lp7/a;->b:Lp7/a;

    .line 181
    .line 182
    goto :goto_7

    .line 183
    :goto_8
    const-class v1, Lwh/h;

    .line 184
    .line 185
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 186
    .line 187
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 188
    .line 189
    .line 190
    move-result-object v6

    .line 191
    const/4 v8, 0x0

    .line 192
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    move-object v15, v1

    .line 197
    check-cast v15, Lwh/h;

    .line 198
    .line 199
    iget-object v1, v15, Lwh/h;->e:Lyy0/l1;

    .line 200
    .line 201
    invoke-static {v1, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    invoke-static {v11}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 206
    .line 207
    .line 208
    move-result-object v6

    .line 209
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    move-object v7, v1

    .line 214
    check-cast v7, Lwh/f;

    .line 215
    .line 216
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v1

    .line 220
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v2

    .line 224
    if-nez v1, :cond_a

    .line 225
    .line 226
    if-ne v2, v12, :cond_b

    .line 227
    .line 228
    :cond_a
    new-instance v13, Lwc/a;

    .line 229
    .line 230
    const/16 v19, 0x0

    .line 231
    .line 232
    const/16 v20, 0x2

    .line 233
    .line 234
    const/4 v14, 0x1

    .line 235
    const-class v16, Lwh/h;

    .line 236
    .line 237
    const-string v17, "onUiEvent"

    .line 238
    .line 239
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding2/solar/angle/EnterAngleScreenUiEvent;)V"

    .line 240
    .line 241
    invoke-direct/range {v13 .. v20}, Lwc/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    move-object v2, v13

    .line 248
    :cond_b
    check-cast v2, Lhy0/g;

    .line 249
    .line 250
    move-object v9, v2

    .line 251
    check-cast v9, Lay0/k;

    .line 252
    .line 253
    and-int/lit8 v0, v0, 0x70

    .line 254
    .line 255
    move-object v8, v4

    .line 256
    move-object v10, v11

    .line 257
    move v11, v0

    .line 258
    invoke-interface/range {v6 .. v11}, Leh/n;->C(Lwh/f;Lvh/u;Lay0/k;Ll2/o;I)V

    .line 259
    .line 260
    .line 261
    move-object v11, v10

    .line 262
    goto :goto_9

    .line 263
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 266
    .line 267
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    throw v0

    .line 271
    :cond_d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 272
    .line 273
    .line 274
    :goto_9
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    if-eqz v6, :cond_e

    .line 279
    .line 280
    new-instance v0, Luj/j0;

    .line 281
    .line 282
    const/16 v2, 0xc

    .line 283
    .line 284
    move-object/from16 v4, p1

    .line 285
    .line 286
    move/from16 v1, p4

    .line 287
    .line 288
    invoke-direct/range {v0 .. v5}, Luj/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 292
    .line 293
    :cond_e
    return-void
.end method
