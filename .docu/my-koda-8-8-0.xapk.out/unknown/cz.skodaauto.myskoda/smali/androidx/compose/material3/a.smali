.class public abstract Landroidx/compose/material3/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static b(Landroidx/compose/material3/a;)Lx2/s;
    .locals 11

    .line 1
    check-cast p0, Lh2/x4;

    .line 2
    .line 3
    iget-object v0, p0, Lh2/x4;->a:Lc3/q;

    .line 4
    .line 5
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 6
    .line 7
    invoke-static {v1, v0}, Landroidx/compose/ui/focus/a;->a(Lx2/s;Lc3/q;)Lx2/s;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    new-instance v2, Landroidx/compose/material3/ExposedDropdownMenuAnchorElement;

    .line 12
    .line 13
    iget-object v3, p0, Lh2/x4;->h:Ll2/b1;

    .line 14
    .line 15
    new-instance v4, La2/h;

    .line 16
    .line 17
    const/16 v5, 0x16

    .line 18
    .line 19
    invoke-direct {v4, v3, v5}, La2/h;-><init>(Ll2/b1;I)V

    .line 20
    .line 21
    .line 22
    invoke-direct {v2, v4}, Landroidx/compose/material3/ExposedDropdownMenuAnchorElement;-><init>(La2/h;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iget-boolean v5, p0, Lh2/x4;->b:Z

    .line 30
    .line 31
    iget-object v2, p0, Lh2/x4;->i:Lay0/k;

    .line 32
    .line 33
    new-instance v9, Lb71/o;

    .line 34
    .line 35
    invoke-direct {v9, v3, v2, v5}, Lb71/o;-><init>(Ll2/b1;Lay0/k;Z)V

    .line 36
    .line 37
    .line 38
    iget-object v2, p0, Lh2/x4;->c:Ll2/b1;

    .line 39
    .line 40
    iget-object v6, p0, Lh2/x4;->d:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v7, p0, Lh2/x4;->e:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v8, p0, Lh2/x4;->f:Ljava/lang/String;

    .line 45
    .line 46
    iget-object v10, p0, Lh2/x4;->g:Lw3/b2;

    .line 47
    .line 48
    new-instance p0, Lb2/b;

    .line 49
    .line 50
    const/4 v3, 0x6

    .line 51
    invoke-direct {p0, v9, v3}, Lb2/b;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    invoke-static {v1, v9, p0}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    new-instance v1, Lh2/y4;

    .line 59
    .line 60
    invoke-direct {v1, v9, v5, v2}, Lh2/y4;-><init>(Lb71/o;ZLl2/b1;)V

    .line 61
    .line 62
    .line 63
    invoke-static {p0, v1}, Landroidx/compose/ui/input/key/a;->b(Lx2/s;Lay0/k;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    new-instance v4, Let/g;

    .line 68
    .line 69
    invoke-direct/range {v4 .. v10}, Let/g;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lb71/o;Lw3/b2;)V

    .line 70
    .line 71
    .line 72
    const/4 v1, 0x0

    .line 73
    invoke-static {p0, v1, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-interface {v0, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method


# virtual methods
.method public final a(ZLay0/a;Lx2/s;Le1/n1;ZLe3/n0;JFFLt2/b;Ll2/o;II)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v13, p1

    .line 4
    .line 5
    move-object/from16 v14, p12

    .line 6
    .line 7
    check-cast v14, Ll2/t;

    .line 8
    .line 9
    const v0, -0x78f8dc3

    .line 10
    .line 11
    .line 12
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v14, v13}, Ll2/t;->h(Z)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v3, 0x2

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v3

    .line 25
    :goto_0
    or-int v0, p13, v0

    .line 26
    .line 27
    const v4, 0x36c96580

    .line 28
    .line 29
    .line 30
    or-int/2addr v0, v4

    .line 31
    and-int/lit8 v4, p14, 0x6

    .line 32
    .line 33
    move-object/from16 v12, p11

    .line 34
    .line 35
    if-nez v4, :cond_2

    .line 36
    .line 37
    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    const/4 v3, 0x4

    .line 44
    :cond_1
    or-int v3, p14, v3

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    move/from16 v3, p14

    .line 48
    .line 49
    :goto_1
    and-int/lit8 v4, p14, 0x30

    .line 50
    .line 51
    if-nez v4, :cond_4

    .line 52
    .line 53
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_3

    .line 58
    .line 59
    const/16 v4, 0x20

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    const/16 v4, 0x10

    .line 63
    .line 64
    :goto_2
    or-int/2addr v3, v4

    .line 65
    :cond_4
    const v4, 0x12492493

    .line 66
    .line 67
    .line 68
    and-int/2addr v4, v0

    .line 69
    const v6, 0x12492492

    .line 70
    .line 71
    .line 72
    const/4 v15, 0x0

    .line 73
    const/4 v7, 0x1

    .line 74
    if-ne v4, v6, :cond_6

    .line 75
    .line 76
    and-int/lit8 v3, v3, 0x13

    .line 77
    .line 78
    const/16 v4, 0x12

    .line 79
    .line 80
    if-eq v3, v4, :cond_5

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_5
    move v3, v15

    .line 84
    goto :goto_4

    .line 85
    :cond_6
    :goto_3
    move v3, v7

    .line 86
    :goto_4
    and-int/2addr v0, v7

    .line 87
    invoke-virtual {v14, v0, v3}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_25

    .line 92
    .line 93
    invoke-virtual {v14}, Ll2/t;->T()V

    .line 94
    .line 95
    .line 96
    and-int/lit8 v0, p13, 0x1

    .line 97
    .line 98
    if-eqz v0, :cond_8

    .line 99
    .line 100
    invoke-virtual {v14}, Ll2/t;->y()Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-eqz v0, :cond_7

    .line 105
    .line 106
    goto :goto_5

    .line 107
    :cond_7
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 108
    .line 109
    .line 110
    move-object/from16 v10, p3

    .line 111
    .line 112
    move-object/from16 v6, p4

    .line 113
    .line 114
    move/from16 v3, p5

    .line 115
    .line 116
    move-object/from16 v0, p6

    .line 117
    .line 118
    move-wide/from16 v8, p7

    .line 119
    .line 120
    move/from16 v4, p9

    .line 121
    .line 122
    move/from16 v11, p10

    .line 123
    .line 124
    goto :goto_6

    .line 125
    :cond_8
    :goto_5
    invoke-static {v15, v7, v14}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    sget v3, Lh2/m5;->a:F

    .line 130
    .line 131
    sget-object v3, Lk2/v;->c:Lk2/f0;

    .line 132
    .line 133
    invoke-static {v3, v14}, Lh2/i8;->b(Lk2/f0;Ll2/o;)Le3/n0;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    sget-object v4, Lk2/v;->a:Lk2/l;

    .line 138
    .line 139
    invoke-static {v4, v14}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 140
    .line 141
    .line 142
    move-result-wide v8

    .line 143
    sget v4, Lh2/m5;->a:F

    .line 144
    .line 145
    sget v6, Lh2/m5;->b:F

    .line 146
    .line 147
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 148
    .line 149
    move v11, v6

    .line 150
    move-object v6, v0

    .line 151
    move-object v0, v3

    .line 152
    move v3, v7

    .line 153
    :goto_6
    invoke-virtual {v14}, Ll2/t;->r()V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 161
    .line 162
    if-ne v5, v7, :cond_9

    .line 163
    .line 164
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    const/16 v17, 0x4

    .line 167
    .line 168
    sget-object v2, Ll2/x0;->f:Ll2/x0;

    .line 169
    .line 170
    invoke-static {v5, v2, v14}, Lf2/m0;->r(Llx0/b0;Ll2/x0;Ll2/t;)Ll2/j1;

    .line 171
    .line 172
    .line 173
    move-result-object v5

    .line 174
    goto :goto_7

    .line 175
    :cond_9
    const/16 v17, 0x4

    .line 176
    .line 177
    :goto_7
    check-cast v5, Ll2/b1;

    .line 178
    .line 179
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 180
    .line 181
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    check-cast v2, Lt4/c;

    .line 186
    .line 187
    sget-object v18, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 188
    .line 189
    invoke-static {v14}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 190
    .line 191
    .line 192
    move-result-object v15

    .line 193
    iget-object v15, v15, Lk1/r1;->f:Lk1/b;

    .line 194
    .line 195
    invoke-virtual {v15}, Lk1/b;->e()Ls5/b;

    .line 196
    .line 197
    .line 198
    move-result-object v15

    .line 199
    iget v15, v15, Ls5/b;->b:I

    .line 200
    .line 201
    move-object/from16 p3, v0

    .line 202
    .line 203
    if-eqz v13, :cond_b

    .line 204
    .line 205
    const v0, 0x258ce8ec

    .line 206
    .line 207
    .line 208
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    if-ne v0, v7, :cond_a

    .line 216
    .line 217
    new-instance v0, La2/h;

    .line 218
    .line 219
    const/16 v1, 0x15

    .line 220
    .line 221
    invoke-direct {v0, v5, v1}, La2/h;-><init>(Ll2/b1;I)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v14, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    :cond_a
    check-cast v0, Lay0/a;

    .line 228
    .line 229
    const/4 v1, 0x6

    .line 230
    invoke-static {v0, v14, v1}, Lh2/r;->o(Lay0/a;Ll2/o;I)V

    .line 231
    .line 232
    .line 233
    const/4 v0, 0x0

    .line 234
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 235
    .line 236
    .line 237
    goto :goto_8

    .line 238
    :cond_b
    const/4 v0, 0x0

    .line 239
    const v1, 0x258e3705

    .line 240
    .line 241
    .line 242
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 246
    .line 247
    .line 248
    :goto_8
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    if-ne v0, v7, :cond_c

    .line 253
    .line 254
    new-instance v0, Lc1/n0;

    .line 255
    .line 256
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 257
    .line 258
    invoke-direct {v0, v1}, Lc1/n0;-><init>(Ljava/lang/Object;)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v14, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 262
    .line 263
    .line 264
    :cond_c
    check-cast v0, Lc1/n0;

    .line 265
    .line 266
    invoke-static {v13}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 267
    .line 268
    .line 269
    move-result-object v1

    .line 270
    invoke-virtual {v0, v1}, Lc1/n0;->b0(Ljava/lang/Boolean;)V

    .line 271
    .line 272
    .line 273
    iget-object v1, v0, Lc1/n0;->f:Ll2/j1;

    .line 274
    .line 275
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    check-cast v1, Ljava/lang/Boolean;

    .line 280
    .line 281
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 282
    .line 283
    .line 284
    move-result v1

    .line 285
    if-nez v1, :cond_e

    .line 286
    .line 287
    iget-object v1, v0, Lc1/n0;->g:Ll2/j1;

    .line 288
    .line 289
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    check-cast v1, Ljava/lang/Boolean;

    .line 294
    .line 295
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    if-eqz v1, :cond_d

    .line 300
    .line 301
    goto :goto_9

    .line 302
    :cond_d
    const v0, 0x25a89d05

    .line 303
    .line 304
    .line 305
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 306
    .line 307
    .line 308
    const/4 v0, 0x0

    .line 309
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    move-object/from16 v7, p3

    .line 313
    .line 314
    move-object v2, v10

    .line 315
    move-object v0, v14

    .line 316
    move v10, v4

    .line 317
    goto/16 :goto_14

    .line 318
    .line 319
    :cond_e
    :goto_9
    const v1, 0x25931649

    .line 320
    .line 321
    .line 322
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v1

    .line 329
    if-ne v1, v7, :cond_f

    .line 330
    .line 331
    move-object/from16 p5, v0

    .line 332
    .line 333
    sget-wide v0, Le3/q0;->b:J

    .line 334
    .line 335
    move/from16 p6, v3

    .line 336
    .line 337
    new-instance v3, Le3/q0;

    .line 338
    .line 339
    invoke-direct {v3, v0, v1}, Le3/q0;-><init>(J)V

    .line 340
    .line 341
    .line 342
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 343
    .line 344
    .line 345
    move-result-object v1

    .line 346
    invoke-virtual {v14, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    goto :goto_a

    .line 350
    :cond_f
    move-object/from16 p5, v0

    .line 351
    .line 352
    move/from16 p6, v3

    .line 353
    .line 354
    :goto_a
    check-cast v1, Ll2/b1;

    .line 355
    .line 356
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    move-result v0

    .line 360
    invoke-virtual {v14, v15}, Ll2/t;->e(I)Z

    .line 361
    .line 362
    .line 363
    move-result v3

    .line 364
    or-int/2addr v0, v3

    .line 365
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v3

    .line 369
    if-nez v0, :cond_11

    .line 370
    .line 371
    if-ne v3, v7, :cond_10

    .line 372
    .line 373
    goto :goto_b

    .line 374
    :cond_10
    move/from16 p7, v4

    .line 375
    .line 376
    goto :goto_c

    .line 377
    :cond_11
    :goto_b
    new-instance v3, Lh2/z4;

    .line 378
    .line 379
    new-instance v0, Leh/c;

    .line 380
    .line 381
    move/from16 p7, v4

    .line 382
    .line 383
    const/16 v4, 0xd

    .line 384
    .line 385
    invoke-direct {v0, v1, v4}, Leh/c;-><init>(Ll2/b1;I)V

    .line 386
    .line 387
    .line 388
    invoke-direct {v3, v2, v15, v5, v0}, Lh2/z4;-><init>(Lt4/c;ILl2/b1;Leh/c;)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v14, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    :goto_c
    move-object v15, v3

    .line 395
    check-cast v15, Lh2/z4;

    .line 396
    .line 397
    move-object/from16 v0, p0

    .line 398
    .line 399
    check-cast v0, Lh2/x4;

    .line 400
    .line 401
    iget-object v2, v0, Lh2/x4;->h:Ll2/b1;

    .line 402
    .line 403
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object v2

    .line 407
    check-cast v2, Lh2/t4;

    .line 408
    .line 409
    iget-object v2, v2, Lh2/t4;->a:Ljava/lang/String;

    .line 410
    .line 411
    iget-object v0, v0, Lh2/x4;->c:Ll2/b1;

    .line 412
    .line 413
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    check-cast v0, Ljava/lang/Boolean;

    .line 418
    .line 419
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 420
    .line 421
    .line 422
    move-result v0

    .line 423
    const/4 v3, 0x7

    .line 424
    and-int/lit8 v3, v3, 0x4

    .line 425
    .line 426
    if-eqz v3, :cond_12

    .line 427
    .line 428
    const/4 v3, 0x1

    .line 429
    goto :goto_d

    .line 430
    :cond_12
    const/4 v3, 0x0

    .line 431
    :goto_d
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 432
    .line 433
    invoke-virtual {v14, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object v4

    .line 437
    check-cast v4, Landroid/content/Context;

    .line 438
    .line 439
    const-string v5, "accessibility"

    .line 440
    .line 441
    invoke-virtual {v4, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    move-result-object v4

    .line 445
    const-string v5, "null cannot be cast to non-null type android.view.accessibility.AccessibilityManager"

    .line 446
    .line 447
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    check-cast v4, Landroid/view/accessibility/AccessibilityManager;

    .line 451
    .line 452
    const/4 v5, 0x0

    .line 453
    and-int/lit8 v18, v5, 0xe

    .line 454
    .line 455
    move/from16 p4, v5

    .line 456
    .line 457
    const/16 v19, 0x6

    .line 458
    .line 459
    xor-int/lit8 v5, v18, 0x6

    .line 460
    .line 461
    move/from16 p8, v0

    .line 462
    .line 463
    move/from16 v0, v17

    .line 464
    .line 465
    if-le v5, v0, :cond_13

    .line 466
    .line 467
    const/4 v5, 0x1

    .line 468
    invoke-virtual {v14, v5}, Ll2/t;->h(Z)Z

    .line 469
    .line 470
    .line 471
    move-result v17

    .line 472
    if-nez v17, :cond_14

    .line 473
    .line 474
    :cond_13
    and-int/lit8 v5, p4, 0x6

    .line 475
    .line 476
    if-ne v5, v0, :cond_15

    .line 477
    .line 478
    :cond_14
    const/4 v0, 0x1

    .line 479
    goto :goto_e

    .line 480
    :cond_15
    move/from16 v0, p4

    .line 481
    .line 482
    :goto_e
    and-int/lit8 v5, p4, 0x70

    .line 483
    .line 484
    xor-int/lit8 v5, v5, 0x30

    .line 485
    .line 486
    move/from16 p9, v0

    .line 487
    .line 488
    const/16 v0, 0x20

    .line 489
    .line 490
    if-le v5, v0, :cond_16

    .line 491
    .line 492
    const/4 v5, 0x1

    .line 493
    invoke-virtual {v14, v5}, Ll2/t;->h(Z)Z

    .line 494
    .line 495
    .line 496
    move-result v17

    .line 497
    if-nez v17, :cond_17

    .line 498
    .line 499
    :cond_16
    and-int/lit8 v5, p4, 0x30

    .line 500
    .line 501
    if-ne v5, v0, :cond_18

    .line 502
    .line 503
    :cond_17
    const/4 v0, 0x1

    .line 504
    goto :goto_f

    .line 505
    :cond_18
    move/from16 v0, p4

    .line 506
    .line 507
    :goto_f
    or-int v0, p9, v0

    .line 508
    .line 509
    move/from16 v5, p4

    .line 510
    .line 511
    move/from16 p4, v0

    .line 512
    .line 513
    and-int/lit16 v0, v5, 0x380

    .line 514
    .line 515
    xor-int/lit16 v0, v0, 0x180

    .line 516
    .line 517
    const/16 v5, 0x100

    .line 518
    .line 519
    if-le v0, v5, :cond_19

    .line 520
    .line 521
    invoke-virtual {v14, v3}, Ll2/t;->h(Z)Z

    .line 522
    .line 523
    .line 524
    move-result v0

    .line 525
    if-nez v0, :cond_1a

    .line 526
    .line 527
    :cond_19
    move-object/from16 p9, v1

    .line 528
    .line 529
    const/4 v0, 0x0

    .line 530
    goto :goto_10

    .line 531
    :cond_1a
    move-object/from16 p9, v1

    .line 532
    .line 533
    goto :goto_11

    .line 534
    :goto_10
    and-int/lit16 v1, v0, 0x180

    .line 535
    .line 536
    if-ne v1, v5, :cond_1b

    .line 537
    .line 538
    :goto_11
    const/4 v0, 0x1

    .line 539
    goto :goto_12

    .line 540
    :cond_1b
    const/4 v0, 0x0

    .line 541
    :goto_12
    or-int v0, p4, v0

    .line 542
    .line 543
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 544
    .line 545
    .line 546
    move-result-object v1

    .line 547
    if-nez v0, :cond_1c

    .line 548
    .line 549
    if-ne v1, v7, :cond_1d

    .line 550
    .line 551
    :cond_1c
    new-instance v1, Li2/t0;

    .line 552
    .line 553
    const/4 v5, 0x1

    .line 554
    invoke-direct {v1, v5, v5, v3}, Li2/t0;-><init>(ZZZ)V

    .line 555
    .line 556
    .line 557
    invoke-virtual {v14, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 558
    .line 559
    .line 560
    :cond_1d
    check-cast v1, Li2/t0;

    .line 561
    .line 562
    sget-object v0, Ln7/c;->a:Ll2/s1;

    .line 563
    .line 564
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    check-cast v0, Landroidx/lifecycle/x;

    .line 569
    .line 570
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 571
    .line 572
    .line 573
    move-result v3

    .line 574
    invoke-virtual {v14, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 575
    .line 576
    .line 577
    move-result v5

    .line 578
    or-int/2addr v3, v5

    .line 579
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    move-result-object v5

    .line 583
    if-nez v3, :cond_1e

    .line 584
    .line 585
    if-ne v5, v7, :cond_1f

    .line 586
    .line 587
    :cond_1e
    new-instance v5, Let/g;

    .line 588
    .line 589
    const/16 v3, 0x19

    .line 590
    .line 591
    invoke-direct {v5, v3, v1, v4}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 592
    .line 593
    .line 594
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 595
    .line 596
    .line 597
    :cond_1f
    check-cast v5, Lay0/k;

    .line 598
    .line 599
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 600
    .line 601
    .line 602
    move-result v3

    .line 603
    invoke-virtual {v14, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 604
    .line 605
    .line 606
    move-result v17

    .line 607
    or-int v3, v3, v17

    .line 608
    .line 609
    move/from16 p4, v3

    .line 610
    .line 611
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object v3

    .line 615
    if-nez p4, :cond_20

    .line 616
    .line 617
    if-ne v3, v7, :cond_21

    .line 618
    .line 619
    :cond_20
    new-instance v3, Ld90/w;

    .line 620
    .line 621
    const/16 v7, 0x1d

    .line 622
    .line 623
    invoke-direct {v3, v7, v1, v4}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 624
    .line 625
    .line 626
    invoke-virtual {v14, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 627
    .line 628
    .line 629
    :cond_21
    check-cast v3, Lay0/a;

    .line 630
    .line 631
    const/4 v4, 0x0

    .line 632
    invoke-static {v0, v5, v3, v14, v4}, Li2/a1;->c(Landroidx/lifecycle/x;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 633
    .line 634
    .line 635
    invoke-virtual {v1}, Li2/t0;->getValue()Ljava/lang/Object;

    .line 636
    .line 637
    .line 638
    move-result-object v0

    .line 639
    check-cast v0, Ljava/lang/Boolean;

    .line 640
    .line 641
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 642
    .line 643
    .line 644
    move-result v0

    .line 645
    if-nez v0, :cond_22

    .line 646
    .line 647
    const v0, 0x60020

    .line 648
    .line 649
    .line 650
    goto :goto_13

    .line 651
    :cond_22
    const/high16 v0, 0x60000

    .line 652
    .line 653
    :goto_13
    const-string v3, "PrimaryEditable"

    .line 654
    .line 655
    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 656
    .line 657
    .line 658
    move-result v3

    .line 659
    if-nez v3, :cond_23

    .line 660
    .line 661
    const-string v3, "SecondaryEditable"

    .line 662
    .line 663
    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 664
    .line 665
    .line 666
    move-result v2

    .line 667
    if-eqz v2, :cond_24

    .line 668
    .line 669
    invoke-virtual {v1}, Li2/t0;->getValue()Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v1

    .line 673
    check-cast v1, Ljava/lang/Boolean;

    .line 674
    .line 675
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 676
    .line 677
    .line 678
    move-result v1

    .line 679
    if-nez v1, :cond_24

    .line 680
    .line 681
    :cond_23
    if-nez p8, :cond_24

    .line 682
    .line 683
    or-int/lit8 v0, v0, 0x8

    .line 684
    .line 685
    :cond_24
    new-instance v1, Lx4/w;

    .line 686
    .line 687
    const/4 v5, 0x1

    .line 688
    invoke-direct {v1, v0, v5, v5, v5}, Lx4/w;-><init>(IZZZ)V

    .line 689
    .line 690
    .line 691
    new-instance v0, Lh2/v4;

    .line 692
    .line 693
    move-object/from16 v7, p3

    .line 694
    .line 695
    move-object/from16 v4, p5

    .line 696
    .line 697
    move/from16 v3, p6

    .line 698
    .line 699
    move-object/from16 v5, p9

    .line 700
    .line 701
    move-object/from16 v16, v1

    .line 702
    .line 703
    move-object v2, v10

    .line 704
    move-object/from16 v1, p0

    .line 705
    .line 706
    move/from16 v10, p7

    .line 707
    .line 708
    invoke-direct/range {v0 .. v12}, Lh2/v4;-><init>(Landroidx/compose/material3/a;Lx2/s;ZLc1/n0;Ll2/b1;Le1/n1;Le3/n0;JFFLt2/b;)V

    .line 709
    .line 710
    .line 711
    const v1, 0x7af8b32d

    .line 712
    .line 713
    .line 714
    invoke-static {v1, v14, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 715
    .line 716
    .line 717
    move-result-object v0

    .line 718
    const/16 v1, 0xc30

    .line 719
    .line 720
    const/4 v4, 0x0

    .line 721
    move-object/from16 p4, p2

    .line 722
    .line 723
    move-object/from16 p6, v0

    .line 724
    .line 725
    move/from16 p8, v1

    .line 726
    .line 727
    move/from16 p9, v4

    .line 728
    .line 729
    move-object/from16 p7, v14

    .line 730
    .line 731
    move-object/from16 p3, v15

    .line 732
    .line 733
    move-object/from16 p5, v16

    .line 734
    .line 735
    invoke-static/range {p3 .. p9}, Lx4/i;->a(Lx4/v;Lay0/a;Lx4/w;Lt2/b;Ll2/o;II)V

    .line 736
    .line 737
    .line 738
    move-object/from16 v0, p7

    .line 739
    .line 740
    const/4 v5, 0x0

    .line 741
    invoke-virtual {v0, v5}, Ll2/t;->q(Z)V

    .line 742
    .line 743
    .line 744
    :goto_14
    move-object v4, v2

    .line 745
    move-object v5, v6

    .line 746
    move v6, v3

    .line 747
    goto :goto_15

    .line 748
    :cond_25
    move-object v0, v14

    .line 749
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 750
    .line 751
    .line 752
    move-object/from16 v4, p3

    .line 753
    .line 754
    move-object/from16 v5, p4

    .line 755
    .line 756
    move/from16 v6, p5

    .line 757
    .line 758
    move-object/from16 v7, p6

    .line 759
    .line 760
    move-wide/from16 v8, p7

    .line 761
    .line 762
    move/from16 v10, p9

    .line 763
    .line 764
    move/from16 v11, p10

    .line 765
    .line 766
    :goto_15
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 767
    .line 768
    .line 769
    move-result-object v15

    .line 770
    if-eqz v15, :cond_26

    .line 771
    .line 772
    new-instance v0, Lh2/u4;

    .line 773
    .line 774
    move-object/from16 v1, p0

    .line 775
    .line 776
    move-object/from16 v3, p2

    .line 777
    .line 778
    move-object/from16 v12, p11

    .line 779
    .line 780
    move/from16 v14, p14

    .line 781
    .line 782
    move v2, v13

    .line 783
    move/from16 v13, p13

    .line 784
    .line 785
    invoke-direct/range {v0 .. v14}, Lh2/u4;-><init>(Landroidx/compose/material3/a;ZLay0/a;Lx2/s;Le1/n1;ZLe3/n0;JFFLt2/b;II)V

    .line 786
    .line 787
    .line 788
    iput-object v0, v15, Ll2/u1;->d:Lay0/n;

    .line 789
    .line 790
    :cond_26
    return-void
.end method
