.class public abstract Lkp/j6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lxh/e;Lyj/b;Lyj/b;Lxh/e;Lxh/e;Lxh/e;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v5, p7

    .line 2
    .line 3
    check-cast v5, Ll2/t;

    .line 4
    .line 5
    const v0, 0x197b3a0a

    .line 6
    .line 7
    .line 8
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v7, p0

    .line 12
    .line 13
    invoke-virtual {v5, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x4

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    move v0, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x2

    .line 23
    :goto_0
    or-int v0, p8, v0

    .line 24
    .line 25
    move-object/from16 v8, p1

    .line 26
    .line 27
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    move v2, v3

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v2, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v2

    .line 40
    move-object/from16 v9, p2

    .line 41
    .line 42
    invoke-virtual {v5, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    const/16 v4, 0x100

    .line 47
    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    move v2, v4

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v2, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v2

    .line 55
    move-object/from16 v10, p3

    .line 56
    .line 57
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-eqz v2, :cond_3

    .line 62
    .line 63
    const/16 v2, 0x800

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/16 v2, 0x400

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v2

    .line 69
    move-object/from16 v11, p4

    .line 70
    .line 71
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-eqz v2, :cond_4

    .line 76
    .line 77
    const/16 v2, 0x4000

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_4
    const/16 v2, 0x2000

    .line 81
    .line 82
    :goto_4
    or-int/2addr v0, v2

    .line 83
    move-object/from16 v2, p5

    .line 84
    .line 85
    invoke-virtual {v5, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v13

    .line 89
    const/high16 v14, 0x20000

    .line 90
    .line 91
    if-eqz v13, :cond_5

    .line 92
    .line 93
    move v13, v14

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    const/high16 v13, 0x10000

    .line 96
    .line 97
    :goto_5
    or-int/2addr v0, v13

    .line 98
    move-object/from16 v13, p6

    .line 99
    .line 100
    invoke-virtual {v5, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v15

    .line 104
    if-eqz v15, :cond_6

    .line 105
    .line 106
    const/high16 v15, 0x100000

    .line 107
    .line 108
    goto :goto_6

    .line 109
    :cond_6
    const/high16 v15, 0x80000

    .line 110
    .line 111
    :goto_6
    or-int/2addr v0, v15

    .line 112
    const v15, 0x92493

    .line 113
    .line 114
    .line 115
    and-int/2addr v15, v0

    .line 116
    const v12, 0x92492

    .line 117
    .line 118
    .line 119
    const/16 v16, 0x1

    .line 120
    .line 121
    const/4 v6, 0x0

    .line 122
    if-eq v15, v12, :cond_7

    .line 123
    .line 124
    move/from16 v12, v16

    .line 125
    .line 126
    goto :goto_7

    .line 127
    :cond_7
    move v12, v6

    .line 128
    :goto_7
    and-int/lit8 v15, v0, 0x1

    .line 129
    .line 130
    invoke-virtual {v5, v15, v12}, Ll2/t;->O(IZ)Z

    .line 131
    .line 132
    .line 133
    move-result v12

    .line 134
    if-eqz v12, :cond_16

    .line 135
    .line 136
    and-int/lit8 v12, v0, 0xe

    .line 137
    .line 138
    if-ne v12, v1, :cond_8

    .line 139
    .line 140
    move/from16 v1, v16

    .line 141
    .line 142
    goto :goto_8

    .line 143
    :cond_8
    move v1, v6

    .line 144
    :goto_8
    and-int/lit8 v12, v0, 0x70

    .line 145
    .line 146
    if-ne v12, v3, :cond_9

    .line 147
    .line 148
    move/from16 v3, v16

    .line 149
    .line 150
    goto :goto_9

    .line 151
    :cond_9
    move v3, v6

    .line 152
    :goto_9
    or-int/2addr v1, v3

    .line 153
    and-int/lit16 v3, v0, 0x380

    .line 154
    .line 155
    if-ne v3, v4, :cond_a

    .line 156
    .line 157
    move/from16 v3, v16

    .line 158
    .line 159
    goto :goto_a

    .line 160
    :cond_a
    move v3, v6

    .line 161
    :goto_a
    or-int/2addr v1, v3

    .line 162
    const/high16 v3, 0x70000

    .line 163
    .line 164
    and-int/2addr v3, v0

    .line 165
    if-ne v3, v14, :cond_b

    .line 166
    .line 167
    move/from16 v3, v16

    .line 168
    .line 169
    goto :goto_b

    .line 170
    :cond_b
    move v3, v6

    .line 171
    :goto_b
    or-int/2addr v1, v3

    .line 172
    and-int/lit16 v3, v0, 0x1c00

    .line 173
    .line 174
    const/16 v4, 0x800

    .line 175
    .line 176
    if-ne v3, v4, :cond_c

    .line 177
    .line 178
    move/from16 v3, v16

    .line 179
    .line 180
    goto :goto_c

    .line 181
    :cond_c
    move v3, v6

    .line 182
    :goto_c
    or-int/2addr v1, v3

    .line 183
    const v3, 0xe000

    .line 184
    .line 185
    .line 186
    and-int/2addr v3, v0

    .line 187
    const/16 v4, 0x4000

    .line 188
    .line 189
    if-ne v3, v4, :cond_d

    .line 190
    .line 191
    move/from16 v3, v16

    .line 192
    .line 193
    goto :goto_d

    .line 194
    :cond_d
    move v3, v6

    .line 195
    :goto_d
    or-int/2addr v1, v3

    .line 196
    const/high16 v3, 0x380000

    .line 197
    .line 198
    and-int/2addr v0, v3

    .line 199
    const/high16 v3, 0x100000

    .line 200
    .line 201
    if-ne v0, v3, :cond_e

    .line 202
    .line 203
    goto :goto_e

    .line 204
    :cond_e
    move/from16 v16, v6

    .line 205
    .line 206
    :goto_e
    or-int v0, v1, v16

    .line 207
    .line 208
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 213
    .line 214
    if-nez v0, :cond_f

    .line 215
    .line 216
    if-ne v1, v15, :cond_10

    .line 217
    .line 218
    :cond_f
    move v0, v6

    .line 219
    goto :goto_f

    .line 220
    :cond_10
    move v0, v6

    .line 221
    goto :goto_10

    .line 222
    :goto_f
    new-instance v6, Laa/d0;

    .line 223
    .line 224
    const/4 v14, 0x3

    .line 225
    move-object v12, v11

    .line 226
    move-object v11, v10

    .line 227
    move-object v10, v2

    .line 228
    invoke-direct/range {v6 .. v14}, Laa/d0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    move-object v1, v6

    .line 235
    :goto_10
    check-cast v1, Lay0/k;

    .line 236
    .line 237
    sget-object v2, Lw3/q1;->a:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {v5, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v2

    .line 243
    check-cast v2, Ljava/lang/Boolean;

    .line 244
    .line 245
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 246
    .line 247
    .line 248
    move-result v2

    .line 249
    if-eqz v2, :cond_11

    .line 250
    .line 251
    const v2, -0x105bcaaa

    .line 252
    .line 253
    .line 254
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 258
    .line 259
    .line 260
    const/4 v0, 0x0

    .line 261
    goto :goto_11

    .line 262
    :cond_11
    const v2, 0x31054eee

    .line 263
    .line 264
    .line 265
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 266
    .line 267
    .line 268
    sget-object v2, Lzb/x;->a:Ll2/u2;

    .line 269
    .line 270
    invoke-virtual {v5, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    check-cast v2, Lhi/a;

    .line 275
    .line 276
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 277
    .line 278
    .line 279
    move-object v0, v2

    .line 280
    :goto_11
    new-instance v3, Laf/a;

    .line 281
    .line 282
    const/16 v2, 0xa

    .line 283
    .line 284
    invoke-direct {v3, v0, v1, v2}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 285
    .line 286
    .line 287
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    if-eqz v1, :cond_15

    .line 292
    .line 293
    instance-of v0, v1, Landroidx/lifecycle/k;

    .line 294
    .line 295
    if-eqz v0, :cond_12

    .line 296
    .line 297
    move-object v0, v1

    .line 298
    check-cast v0, Landroidx/lifecycle/k;

    .line 299
    .line 300
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    :goto_12
    move-object v4, v0

    .line 305
    goto :goto_13

    .line 306
    :cond_12
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 307
    .line 308
    goto :goto_12

    .line 309
    :goto_13
    const-class v0, Lei/e;

    .line 310
    .line 311
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 312
    .line 313
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    const/4 v2, 0x0

    .line 318
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 319
    .line 320
    .line 321
    move-result-object v0

    .line 322
    move-object v8, v0

    .line 323
    check-cast v8, Lei/e;

    .line 324
    .line 325
    invoke-static {v5}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    iget-object v1, v8, Lei/e;->k:Lyy0/l1;

    .line 330
    .line 331
    invoke-static {v1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 332
    .line 333
    .line 334
    move-result-object v1

    .line 335
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v1

    .line 339
    check-cast v1, Llc/q;

    .line 340
    .line 341
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v3

    .line 349
    if-nez v2, :cond_13

    .line 350
    .line 351
    if-ne v3, v15, :cond_14

    .line 352
    .line 353
    :cond_13
    new-instance v6, Lei/a;

    .line 354
    .line 355
    const/4 v12, 0x0

    .line 356
    const/4 v13, 0x0

    .line 357
    const/4 v7, 0x1

    .line 358
    const-class v9, Lei/e;

    .line 359
    .line 360
    const-string v10, "onUiEvent"

    .line 361
    .line 362
    const-string v11, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/settings2/WallboxSettingsUiEvent;)V"

    .line 363
    .line 364
    invoke-direct/range {v6 .. v13}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 368
    .line 369
    .line 370
    move-object v3, v6

    .line 371
    :cond_14
    check-cast v3, Lhy0/g;

    .line 372
    .line 373
    check-cast v3, Lay0/k;

    .line 374
    .line 375
    const/16 v2, 0x8

    .line 376
    .line 377
    invoke-interface {v0, v1, v3, v5, v2}, Leh/n;->j(Llc/q;Lay0/k;Ll2/o;I)V

    .line 378
    .line 379
    .line 380
    goto :goto_14

    .line 381
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 382
    .line 383
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 384
    .line 385
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    throw v0

    .line 389
    :cond_16
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 390
    .line 391
    .line 392
    :goto_14
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    if-eqz v0, :cond_17

    .line 397
    .line 398
    new-instance v6, Lai/c;

    .line 399
    .line 400
    move-object/from16 v7, p0

    .line 401
    .line 402
    move-object/from16 v8, p1

    .line 403
    .line 404
    move-object/from16 v9, p2

    .line 405
    .line 406
    move-object/from16 v10, p3

    .line 407
    .line 408
    move-object/from16 v11, p4

    .line 409
    .line 410
    move-object/from16 v12, p5

    .line 411
    .line 412
    move-object/from16 v13, p6

    .line 413
    .line 414
    move/from16 v14, p8

    .line 415
    .line 416
    invoke-direct/range {v6 .. v14}, Lai/c;-><init>(Ljava/lang/String;Lxh/e;Lyj/b;Lyj/b;Lxh/e;Lxh/e;Lxh/e;I)V

    .line 417
    .line 418
    .line 419
    iput-object v6, v0, Ll2/u1;->d:Lay0/n;

    .line 420
    .line 421
    :cond_17
    return-void
.end method

.method public static final b(D)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0, p1}, Lkp/j6;->c(D)Llx0/l;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 8
    .line 9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p1, " "

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static final c(D)Llx0/l;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0, p0, p1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    sget-object p1, Lqr0/k;->e:Lqr0/k;

    .line 7
    .line 8
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    new-instance v0, Llx0/l;

    .line 13
    .line 14
    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method
