.class public abstract Li91/y2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ls1/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    int-to-float v0, v0

    .line 3
    invoke-static {v0}, Ls1/f;->b(F)Ls1/e;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Li91/y2;->a:Ls1/e;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(IIILl2/o;Lx2/s;)V
    .locals 33

    .line 1
    move-object/from16 v5, p4

    .line 2
    .line 3
    move-object/from16 v0, p3

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, -0x22010cb0

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x4

    .line 18
    const/4 v3, 0x2

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    move v1, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v1, v3

    .line 24
    :goto_0
    or-int v1, p2, v1

    .line 25
    .line 26
    move/from16 v4, p0

    .line 27
    .line 28
    invoke-virtual {v0, v4}, Ll2/t;->e(I)Z

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    const/16 v7, 0x10

    .line 33
    .line 34
    if-eqz v6, :cond_1

    .line 35
    .line 36
    const/16 v6, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v6, v7

    .line 40
    :goto_1
    or-int/2addr v1, v6

    .line 41
    move/from16 v6, p1

    .line 42
    .line 43
    invoke-virtual {v0, v6}, Ll2/t;->e(I)Z

    .line 44
    .line 45
    .line 46
    move-result v8

    .line 47
    if-eqz v8, :cond_2

    .line 48
    .line 49
    const/16 v8, 0x100

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v8, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v1, v8

    .line 55
    and-int/lit16 v8, v1, 0x93

    .line 56
    .line 57
    const/16 v9, 0x92

    .line 58
    .line 59
    const/4 v10, 0x1

    .line 60
    if-eq v8, v9, :cond_3

    .line 61
    .line 62
    move v8, v10

    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/4 v8, 0x0

    .line 65
    :goto_3
    and-int/2addr v1, v10

    .line 66
    invoke-virtual {v0, v1, v8}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_7

    .line 71
    .line 72
    const/16 v1, 0x32

    .line 73
    .line 74
    int-to-float v1, v1

    .line 75
    const/16 v8, 0x18

    .line 76
    .line 77
    int-to-float v8, v8

    .line 78
    invoke-static {v5, v1, v8}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    sget-object v8, Li91/y2;->a:Ls1/e;

    .line 83
    .line 84
    invoke-static {v1, v8}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-static {v0}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 89
    .line 90
    .line 91
    move-result-object v8

    .line 92
    invoke-virtual {v8}, Lj91/e;->h()J

    .line 93
    .line 94
    .line 95
    move-result-wide v8

    .line 96
    sget-object v11, Le3/j0;->a:Le3/i0;

    .line 97
    .line 98
    invoke-static {v1, v8, v9, v11}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-static {v0}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 103
    .line 104
    .line 105
    move-result-object v8

    .line 106
    iget v8, v8, Lj91/c;->b:F

    .line 107
    .line 108
    invoke-static {v0}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 109
    .line 110
    .line 111
    move-result-object v9

    .line 112
    iget v9, v9, Lj91/c;->b:F

    .line 113
    .line 114
    invoke-static {v1, v9, v8}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    sget-object v8, Lk1/j;->e:Lk1/f;

    .line 119
    .line 120
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 121
    .line 122
    const/4 v11, 0x6

    .line 123
    invoke-static {v8, v9, v0, v11}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 124
    .line 125
    .line 126
    move-result-object v8

    .line 127
    iget-wide v12, v0, Ll2/t;->T:J

    .line 128
    .line 129
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 134
    .line 135
    .line 136
    move-result-object v12

    .line 137
    invoke-static {v0, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 142
    .line 143
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 147
    .line 148
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 149
    .line 150
    .line 151
    iget-boolean v14, v0, Ll2/t;->S:Z

    .line 152
    .line 153
    if-eqz v14, :cond_4

    .line 154
    .line 155
    invoke-virtual {v0, v13}, Ll2/t;->l(Lay0/a;)V

    .line 156
    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_4
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 160
    .line 161
    .line 162
    :goto_4
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 163
    .line 164
    invoke-static {v13, v8, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 165
    .line 166
    .line 167
    sget-object v8, Lv3/j;->f:Lv3/h;

    .line 168
    .line 169
    invoke-static {v8, v12, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 170
    .line 171
    .line 172
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 173
    .line 174
    iget-boolean v12, v0, Ll2/t;->S:Z

    .line 175
    .line 176
    if-nez v12, :cond_5

    .line 177
    .line 178
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v12

    .line 182
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 183
    .line 184
    .line 185
    move-result-object v13

    .line 186
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    move-result v12

    .line 190
    if-nez v12, :cond_6

    .line 191
    .line 192
    :cond_5
    invoke-static {v9, v0, v9, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 193
    .line 194
    .line 195
    :cond_6
    sget-object v8, Lv3/j;->d:Lv3/h;

    .line 196
    .line 197
    invoke-static {v8, v1, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 198
    .line 199
    .line 200
    int-to-float v1, v7

    .line 201
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 202
    .line 203
    const/4 v8, 0x0

    .line 204
    move v9, v8

    .line 205
    invoke-static {v7, v1, v9, v3}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    invoke-static {v4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    invoke-static {v0}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 214
    .line 215
    .line 216
    move-result-object v12

    .line 217
    invoke-virtual {v12}, Lj91/f;->f()Lg4/p0;

    .line 218
    .line 219
    .line 220
    move-result-object v12

    .line 221
    invoke-static {v0}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 222
    .line 223
    .line 224
    move-result-object v13

    .line 225
    invoke-virtual {v13}, Lj91/e;->q()J

    .line 226
    .line 227
    .line 228
    move-result-wide v13

    .line 229
    new-instance v15, Lr4/k;

    .line 230
    .line 231
    invoke-direct {v15, v11}, Lr4/k;-><init>(I)V

    .line 232
    .line 233
    .line 234
    const/16 v26, 0x0

    .line 235
    .line 236
    const v27, 0xfbf0

    .line 237
    .line 238
    .line 239
    move-object/from16 v17, v7

    .line 240
    .line 241
    move/from16 v16, v11

    .line 242
    .line 243
    move-object v7, v12

    .line 244
    const-wide/16 v11, 0x0

    .line 245
    .line 246
    move/from16 v18, v10

    .line 247
    .line 248
    move-wide/from16 v31, v13

    .line 249
    .line 250
    move v14, v9

    .line 251
    move-wide/from16 v9, v31

    .line 252
    .line 253
    const/4 v13, 0x0

    .line 254
    move/from16 v19, v14

    .line 255
    .line 256
    move-object/from16 v20, v17

    .line 257
    .line 258
    move-object/from16 v17, v15

    .line 259
    .line 260
    const-wide/16 v14, 0x0

    .line 261
    .line 262
    move/from16 v21, v16

    .line 263
    .line 264
    const/16 v16, 0x0

    .line 265
    .line 266
    move/from16 v23, v18

    .line 267
    .line 268
    move/from16 v22, v19

    .line 269
    .line 270
    const-wide/16 v18, 0x0

    .line 271
    .line 272
    move-object/from16 v24, v20

    .line 273
    .line 274
    const/16 v20, 0x0

    .line 275
    .line 276
    move/from16 v25, v21

    .line 277
    .line 278
    const/16 v21, 0x0

    .line 279
    .line 280
    move/from16 v28, v22

    .line 281
    .line 282
    const/16 v22, 0x0

    .line 283
    .line 284
    move/from16 v29, v23

    .line 285
    .line 286
    const/16 v23, 0x0

    .line 287
    .line 288
    move/from16 v30, v25

    .line 289
    .line 290
    const/16 v25, 0x180

    .line 291
    .line 292
    move-object/from16 v4, v24

    .line 293
    .line 294
    move-object/from16 v24, v0

    .line 295
    .line 296
    move/from16 v0, v28

    .line 297
    .line 298
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 299
    .line 300
    .line 301
    int-to-float v2, v2

    .line 302
    invoke-static {v4, v2, v0, v3}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 303
    .line 304
    .line 305
    move-result-object v8

    .line 306
    invoke-static/range {v24 .. v24}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 307
    .line 308
    .line 309
    move-result-object v2

    .line 310
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 311
    .line 312
    .line 313
    move-result-object v7

    .line 314
    invoke-static/range {v24 .. v24}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 315
    .line 316
    .line 317
    move-result-object v2

    .line 318
    invoke-virtual {v2}, Lj91/e;->s()J

    .line 319
    .line 320
    .line 321
    move-result-wide v9

    .line 322
    new-instance v2, Lr4/k;

    .line 323
    .line 324
    const/4 v6, 0x6

    .line 325
    invoke-direct {v2, v6}, Lr4/k;-><init>(I)V

    .line 326
    .line 327
    .line 328
    const-string v6, " / "

    .line 329
    .line 330
    const/16 v25, 0x186

    .line 331
    .line 332
    move-object/from16 v17, v2

    .line 333
    .line 334
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 335
    .line 336
    .line 337
    invoke-static {v4, v1, v0, v3}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 338
    .line 339
    .line 340
    move-result-object v8

    .line 341
    invoke-static/range {p1 .. p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v6

    .line 345
    invoke-static/range {v24 .. v24}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 346
    .line 347
    .line 348
    move-result-object v0

    .line 349
    invoke-virtual {v0}, Lj91/f;->e()Lg4/p0;

    .line 350
    .line 351
    .line 352
    move-result-object v7

    .line 353
    invoke-static/range {v24 .. v24}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 358
    .line 359
    .line 360
    move-result-wide v9

    .line 361
    const v27, 0xfff0

    .line 362
    .line 363
    .line 364
    const/16 v17, 0x0

    .line 365
    .line 366
    const/16 v25, 0x180

    .line 367
    .line 368
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 369
    .line 370
    .line 371
    move-object/from16 v0, v24

    .line 372
    .line 373
    const/4 v1, 0x1

    .line 374
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 375
    .line 376
    .line 377
    goto :goto_5

    .line 378
    :cond_7
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 379
    .line 380
    .line 381
    :goto_5
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 382
    .line 383
    .line 384
    move-result-object v6

    .line 385
    if-eqz v6, :cond_8

    .line 386
    .line 387
    new-instance v0, Ldl0/h;

    .line 388
    .line 389
    const/4 v4, 0x4

    .line 390
    move/from16 v1, p0

    .line 391
    .line 392
    move/from16 v2, p1

    .line 393
    .line 394
    move/from16 v3, p2

    .line 395
    .line 396
    invoke-direct/range {v0 .. v5}, Ldl0/h;-><init>(IIIILx2/s;)V

    .line 397
    .line 398
    .line 399
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 400
    .line 401
    :cond_8
    return-void
.end method
