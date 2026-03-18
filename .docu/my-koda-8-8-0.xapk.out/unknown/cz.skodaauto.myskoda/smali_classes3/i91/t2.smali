.class public final Li91/t2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Li91/x1;ZJLjava/lang/String;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v6, p5

    .line 6
    .line 7
    move/from16 v7, p7

    .line 8
    .line 9
    const-string v0, "supportVisual"

    .line 10
    .line 11
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    move-object/from16 v13, p6

    .line 15
    .line 16
    check-cast v13, Ll2/t;

    .line 17
    .line 18
    const v0, 0x1c02bce0

    .line 19
    .line 20
    .line 21
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    and-int/lit8 v0, v7, 0x6

    .line 25
    .line 26
    if-nez v0, :cond_2

    .line 27
    .line 28
    and-int/lit8 v0, v7, 0x8

    .line 29
    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {v13, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v13, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    :goto_0
    if-eqz v0, :cond_1

    .line 42
    .line 43
    const/4 v0, 0x4

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    const/4 v0, 0x2

    .line 46
    :goto_1
    or-int/2addr v0, v7

    .line 47
    goto :goto_2

    .line 48
    :cond_2
    move v0, v7

    .line 49
    :goto_2
    and-int/lit8 v1, v7, 0x30

    .line 50
    .line 51
    if-nez v1, :cond_4

    .line 52
    .line 53
    invoke-virtual {v13, v3}, Ll2/t;->h(Z)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-eqz v1, :cond_3

    .line 58
    .line 59
    const/16 v1, 0x20

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_3
    const/16 v1, 0x10

    .line 63
    .line 64
    :goto_3
    or-int/2addr v0, v1

    .line 65
    :cond_4
    and-int/lit16 v1, v7, 0x180

    .line 66
    .line 67
    move-wide/from16 v4, p3

    .line 68
    .line 69
    if-nez v1, :cond_6

    .line 70
    .line 71
    invoke-virtual {v13, v4, v5}, Ll2/t;->f(J)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-eqz v1, :cond_5

    .line 76
    .line 77
    const/16 v1, 0x100

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_5
    const/16 v1, 0x80

    .line 81
    .line 82
    :goto_4
    or-int/2addr v0, v1

    .line 83
    :cond_6
    and-int/lit16 v1, v7, 0xc00

    .line 84
    .line 85
    if-nez v1, :cond_8

    .line 86
    .line 87
    invoke-virtual {v13, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_7

    .line 92
    .line 93
    const/16 v1, 0x800

    .line 94
    .line 95
    goto :goto_5

    .line 96
    :cond_7
    const/16 v1, 0x400

    .line 97
    .line 98
    :goto_5
    or-int/2addr v0, v1

    .line 99
    :cond_8
    and-int/lit16 v1, v0, 0x493

    .line 100
    .line 101
    const/16 v8, 0x492

    .line 102
    .line 103
    const/4 v10, 0x0

    .line 104
    if-eq v1, v8, :cond_9

    .line 105
    .line 106
    const/4 v1, 0x1

    .line 107
    goto :goto_6

    .line 108
    :cond_9
    move v1, v10

    .line 109
    :goto_6
    and-int/lit8 v8, v0, 0x1

    .line 110
    .line 111
    invoke-virtual {v13, v8, v1}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-eqz v1, :cond_13

    .line 116
    .line 117
    instance-of v1, v2, Li91/r1;

    .line 118
    .line 119
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 120
    .line 121
    const/4 v11, 0x0

    .line 122
    if-eqz v1, :cond_c

    .line 123
    .line 124
    const v1, -0x5d61be09

    .line 125
    .line 126
    .line 127
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 128
    .line 129
    .line 130
    move-object v1, v2

    .line 131
    check-cast v1, Li91/r1;

    .line 132
    .line 133
    iget-object v1, v1, Li91/r1;->a:Li3/c;

    .line 134
    .line 135
    if-nez v1, :cond_a

    .line 136
    .line 137
    const v1, -0x5d60629e

    .line 138
    .line 139
    .line 140
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 141
    .line 142
    .line 143
    const v1, -0x5d60629f

    .line 144
    .line 145
    .line 146
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    move-object v1, v11

    .line 156
    goto :goto_7

    .line 157
    :cond_a
    const v9, 0x26472d0f

    .line 158
    .line 159
    .line 160
    invoke-virtual {v13, v9}, Ll2/t;->Y(I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    :goto_7
    if-eqz v1, :cond_b

    .line 167
    .line 168
    const-string v9, "list_item_avatar"

    .line 169
    .line 170
    invoke-static {v11, v6, v9}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v9

    .line 174
    invoke-static {v8, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 175
    .line 176
    .line 177
    move-result-object v8

    .line 178
    sget-object v9, Li91/d1;->d:[Li91/d1;

    .line 179
    .line 180
    shl-int/lit8 v0, v0, 0x6

    .line 181
    .line 182
    and-int/lit16 v0, v0, 0x1c00

    .line 183
    .line 184
    or-int/lit8 v0, v0, 0x30

    .line 185
    .line 186
    invoke-static {v1, v8, v3, v13, v0}, Li91/j0;->e(Li3/c;Lx2/s;ZLl2/o;I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v13, v10}, Ll2/t;->q(Z)V

    .line 190
    .line 191
    .line 192
    goto/16 :goto_a

    .line 193
    .line 194
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 195
    .line 196
    const-string v1, "Either avatarImage or avatarImageRes must be specified in the ImageAvatarSupportVisual"

    .line 197
    .line 198
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    throw v0

    .line 202
    :cond_c
    instance-of v1, v2, Li91/s1;

    .line 203
    .line 204
    const/16 v12, 0x18

    .line 205
    .line 206
    if-eqz v1, :cond_10

    .line 207
    .line 208
    const v1, -0x5d4e633e

    .line 209
    .line 210
    .line 211
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 212
    .line 213
    .line 214
    move-object v1, v2

    .line 215
    check-cast v1, Li91/s1;

    .line 216
    .line 217
    const-string v14, "list_item_indicator"

    .line 218
    .line 219
    invoke-static {v11, v6, v14}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v11

    .line 223
    int-to-float v12, v12

    .line 224
    invoke-static {v8, v12}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 225
    .line 226
    .line 227
    move-result-object v12

    .line 228
    sget-object v14, Lx2/c;->h:Lx2/j;

    .line 229
    .line 230
    invoke-static {v14, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 231
    .line 232
    .line 233
    move-result-object v14

    .line 234
    iget-wide v9, v13, Ll2/t;->T:J

    .line 235
    .line 236
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 237
    .line 238
    .line 239
    move-result v9

    .line 240
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 241
    .line 242
    .line 243
    move-result-object v10

    .line 244
    invoke-static {v13, v12}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 245
    .line 246
    .line 247
    move-result-object v12

    .line 248
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 249
    .line 250
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 251
    .line 252
    .line 253
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 254
    .line 255
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 256
    .line 257
    .line 258
    move/from16 v17, v0

    .line 259
    .line 260
    iget-boolean v0, v13, Ll2/t;->S:Z

    .line 261
    .line 262
    if-eqz v0, :cond_d

    .line 263
    .line 264
    invoke-virtual {v13, v15}, Ll2/t;->l(Lay0/a;)V

    .line 265
    .line 266
    .line 267
    goto :goto_8

    .line 268
    :cond_d
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 269
    .line 270
    .line 271
    :goto_8
    sget-object v0, Lv3/j;->g:Lv3/h;

    .line 272
    .line 273
    invoke-static {v0, v14, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 274
    .line 275
    .line 276
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 277
    .line 278
    invoke-static {v0, v10, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 279
    .line 280
    .line 281
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 282
    .line 283
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 284
    .line 285
    if-nez v10, :cond_e

    .line 286
    .line 287
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v10

    .line 291
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 292
    .line 293
    .line 294
    move-result-object v14

    .line 295
    invoke-static {v10, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    move-result v10

    .line 299
    if-nez v10, :cond_f

    .line 300
    .line 301
    :cond_e
    invoke-static {v9, v13, v9, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 302
    .line 303
    .line 304
    :cond_f
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 305
    .line 306
    invoke-static {v0, v12, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 307
    .line 308
    .line 309
    invoke-static {v8, v11}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    iget-object v1, v1, Li91/s1;->a:Li91/k1;

    .line 314
    .line 315
    shl-int/lit8 v8, v17, 0x3

    .line 316
    .line 317
    and-int/lit16 v8, v8, 0x380

    .line 318
    .line 319
    invoke-static {v1, v0, v3, v13, v8}, Li91/j0;->I(Li91/k1;Lx2/s;ZLl2/o;I)V

    .line 320
    .line 321
    .line 322
    const/4 v0, 0x1

    .line 323
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 324
    .line 325
    .line 326
    const/4 v15, 0x0

    .line 327
    invoke-virtual {v13, v15}, Ll2/t;->q(Z)V

    .line 328
    .line 329
    .line 330
    goto :goto_a

    .line 331
    :cond_10
    move v15, v10

    .line 332
    instance-of v0, v2, Li91/q1;

    .line 333
    .line 334
    if-eqz v0, :cond_12

    .line 335
    .line 336
    const v0, -0x5d44da3c

    .line 337
    .line 338
    .line 339
    invoke-virtual {v13, v0}, Ll2/t;->Y(I)V

    .line 340
    .line 341
    .line 342
    move-object v0, v2

    .line 343
    check-cast v0, Li91/q1;

    .line 344
    .line 345
    const-string v1, "list_item_icon"

    .line 346
    .line 347
    invoke-static {v11, v6, v1}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 348
    .line 349
    .line 350
    move-result-object v1

    .line 351
    iget v9, v0, Li91/q1;->a:I

    .line 352
    .line 353
    invoke-static {v9, v15, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 354
    .line 355
    .line 356
    move-result-object v9

    .line 357
    iget-object v0, v0, Li91/q1;->b:Le3/s;

    .line 358
    .line 359
    if-eqz v0, :cond_11

    .line 360
    .line 361
    iget-wide v10, v0, Le3/s;->a:J

    .line 362
    .line 363
    goto :goto_9

    .line 364
    :cond_11
    move-wide v10, v4

    .line 365
    :goto_9
    int-to-float v0, v12

    .line 366
    invoke-static {v8, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    const/16 v14, 0x30

    .line 375
    .line 376
    move/from16 v16, v15

    .line 377
    .line 378
    const/4 v15, 0x0

    .line 379
    move-object v8, v9

    .line 380
    const-string v9, ""

    .line 381
    .line 382
    move-wide v11, v10

    .line 383
    move-object v10, v0

    .line 384
    move/from16 v0, v16

    .line 385
    .line 386
    invoke-static/range {v8 .. v15}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 390
    .line 391
    .line 392
    goto :goto_a

    .line 393
    :cond_12
    move v0, v15

    .line 394
    const v1, 0x26472835

    .line 395
    .line 396
    .line 397
    invoke-static {v1, v13, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    throw v0

    .line 402
    :cond_13
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 403
    .line 404
    .line 405
    :goto_a
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 406
    .line 407
    .line 408
    move-result-object v9

    .line 409
    if-eqz v9, :cond_14

    .line 410
    .line 411
    new-instance v0, Li91/h2;

    .line 412
    .line 413
    const/4 v8, 0x1

    .line 414
    move-object/from16 v1, p0

    .line 415
    .line 416
    invoke-direct/range {v0 .. v8}, Li91/h2;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZJLjava/lang/String;II)V

    .line 417
    .line 418
    .line 419
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 420
    .line 421
    :cond_14
    return-void
.end method
