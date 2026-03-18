.class public abstract Ljp/eg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lxh/e;Lyj/b;Lyj/b;Lxh/e;Lxh/e;Lzb/s0;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v5, p7

    .line 2
    .line 3
    check-cast v5, Ll2/t;

    .line 4
    .line 5
    const v0, 0x65fc5348

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
    const/4 v14, 0x2

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
    const/16 v2, 0x8

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
    const-class v0, Ldi/o;

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
    check-cast v8, Ldi/o;

    .line 324
    .line 325
    invoke-static {v5}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    iget-object v1, v8, Ldi/o;->s:Lyy0/l1;

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
    new-instance v6, Lcz/j;

    .line 354
    .line 355
    const/4 v12, 0x0

    .line 356
    const/16 v13, 0x15

    .line 357
    .line 358
    const/4 v7, 0x1

    .line 359
    const-class v9, Ldi/o;

    .line 360
    .line 361
    const-string v10, "onUiEvent"

    .line 362
    .line 363
    const-string v11, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/settings/WallboxSettingsUiEvent;)V"

    .line 364
    .line 365
    invoke-direct/range {v6 .. v13}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    move-object v3, v6

    .line 372
    :cond_14
    check-cast v3, Lhy0/g;

    .line 373
    .line 374
    check-cast v3, Lay0/k;

    .line 375
    .line 376
    const/16 v2, 0x8

    .line 377
    .line 378
    invoke-interface {v0, v1, v3, v5, v2}, Leh/n;->B(Llc/q;Lay0/k;Ll2/o;I)V

    .line 379
    .line 380
    .line 381
    goto :goto_14

    .line 382
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 383
    .line 384
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 385
    .line 386
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 387
    .line 388
    .line 389
    throw v0

    .line 390
    :cond_16
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 391
    .line 392
    .line 393
    :goto_14
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    if-eqz v0, :cond_17

    .line 398
    .line 399
    new-instance v6, Lai/c;

    .line 400
    .line 401
    move-object/from16 v7, p0

    .line 402
    .line 403
    move-object/from16 v8, p1

    .line 404
    .line 405
    move-object/from16 v9, p2

    .line 406
    .line 407
    move-object/from16 v10, p3

    .line 408
    .line 409
    move-object/from16 v11, p4

    .line 410
    .line 411
    move-object/from16 v12, p5

    .line 412
    .line 413
    move-object/from16 v13, p6

    .line 414
    .line 415
    move/from16 v14, p8

    .line 416
    .line 417
    invoke-direct/range {v6 .. v14}, Lai/c;-><init>(Ljava/lang/String;Lxh/e;Lyj/b;Lyj/b;Lxh/e;Lxh/e;Lzb/s0;I)V

    .line 418
    .line 419
    .line 420
    iput-object v6, v0, Ll2/u1;->d:Lay0/n;

    .line 421
    .line 422
    :cond_17
    return-void
.end method

.method public static final b(Ljava/util/List;)Ljava/util/List;
    .locals 3

    .line 1
    check-cast p0, Ljava/lang/Iterable;

    .line 2
    .line 3
    new-instance v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    move-object v2, v1

    .line 23
    check-cast v2, Lqp0/b0;

    .line 24
    .line 25
    invoke-static {v2}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    const/4 p0, 0x1

    .line 36
    invoke-static {v0, p0}, Lmx0/q;->D(Ljava/lang/Iterable;I)Ljava/util/List;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-static {p0}, Lmx0/q;->E(Ljava/util/List;)Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method

.method public static final c(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Ljava/lang/Iterable;

    .line 7
    .line 8
    new-instance v0, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    move-object v2, v1

    .line 28
    check-cast v2, Lqp0/b0;

    .line 29
    .line 30
    invoke-static {v2}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-nez v2, :cond_0

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    return-object v0
.end method

.method public static final d(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v0, p0

    .line 7
    check-cast v0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v1, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v2, 0x0

    .line 19
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_3

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    add-int/lit8 v4, v2, 0x1

    .line 30
    .line 31
    if-ltz v2, :cond_2

    .line 32
    .line 33
    move-object v5, v3

    .line 34
    check-cast v5, Lqp0/b0;

    .line 35
    .line 36
    if-nez v2, :cond_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    add-int/lit8 v2, v2, -0x1

    .line 40
    .line 41
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Lqp0/b0;

    .line 46
    .line 47
    iget-object v2, v2, Lqp0/b0;->o:Ljava/lang/Boolean;

    .line 48
    .line 49
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 50
    .line 51
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-nez v2, :cond_1

    .line 56
    .line 57
    :goto_1
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    :cond_1
    move v2, v4

    .line 61
    goto :goto_0

    .line 62
    :cond_2
    invoke-static {}, Ljp/k1;->r()V

    .line 63
    .line 64
    .line 65
    const/4 p0, 0x0

    .line 66
    throw p0

    .line 67
    :cond_3
    return-object v1
.end method

.method public static final e(Lqp0/b0;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 7
    .line 8
    sget-object v0, Lqp0/c0;->a:Lqp0/c0;

    .line 9
    .line 10
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    sget-object v0, Lqp0/d0;->a:Lqp0/d0;

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 28
    return p0
.end method

.method public static final f(Lqp0/b0;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 7
    .line 8
    sget-object v0, Lqp0/f0;->a:Lqp0/f0;

    .line 9
    .line 10
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    sget-object v0, Lqp0/g0;->a:Lqp0/g0;

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 28
    return p0
.end method

.method public static final g(Lqp0/b0;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lqp0/b0;->c:Lqp0/t0;

    .line 7
    .line 8
    sget-object v0, Lqp0/d0;->a:Lqp0/d0;

    .line 9
    .line 10
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    sget-object v0, Lqp0/c0;->a:Lqp0/c0;

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    sget-object v0, Lqp0/f0;->a:Lqp0/f0;

    .line 25
    .line 26
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    sget-object v0, Lqp0/g0;->a:Lqp0/g0;

    .line 33
    .line 34
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 p0, 0x1

    .line 42
    return p0

    .line 43
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 44
    return p0
.end method

.method public static final h(ILjava/util/List;)Z
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/eg;->b(Ljava/util/List;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Ljava/lang/Iterable;

    .line 11
    .line 12
    instance-of v0, p1, Ljava/util/Collection;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move-object v0, p1

    .line 18
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    move v0, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    move v0, v1

    .line 33
    :cond_1
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lqp0/b0;

    .line 44
    .line 45
    invoke-static {v2}, Ljp/eg;->f(Lqp0/b0;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    if-ltz v0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    throw p0

    .line 61
    :cond_3
    :goto_1
    if-le v0, p0, :cond_4

    .line 62
    .line 63
    const/4 p0, 0x1

    .line 64
    return p0

    .line 65
    :cond_4
    return v1
.end method

.method public static final i(ILjava/util/List;)Z
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/eg;->b(Ljava/util/List;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Ljava/lang/Iterable;

    .line 11
    .line 12
    instance-of v0, p1, Ljava/util/Collection;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move-object v0, p1

    .line 18
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    move v0, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    move v0, v1

    .line 33
    :cond_1
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lqp0/b0;

    .line 44
    .line 45
    invoke-static {v2}, Ljp/eg;->f(Lqp0/b0;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    if-ltz v0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    throw p0

    .line 61
    :cond_3
    :goto_1
    if-lt v0, p0, :cond_4

    .line 62
    .line 63
    const/4 p0, 0x1

    .line 64
    return p0

    .line 65
    :cond_4
    return v1
.end method

.method public static final j(Ljava/util/List;)Z
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljp/eg;->b(Ljava/util/List;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/lang/Iterable;

    .line 11
    .line 12
    instance-of v0, p0, Ljava/util/Collection;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    move v0, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    move v0, v1

    .line 33
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lqp0/b0;

    .line 44
    .line 45
    invoke-static {v2}, Ljp/eg;->g(Lqp0/b0;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    if-ltz v0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    throw p0

    .line 61
    :cond_3
    :goto_1
    const/4 p0, 0x3

    .line 62
    if-le v0, p0, :cond_4

    .line 63
    .line 64
    const/4 p0, 0x1

    .line 65
    return p0

    .line 66
    :cond_4
    return v1
.end method

.method public static final k(Ljava/util/List;)Z
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljp/eg;->b(Ljava/util/List;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/lang/Iterable;

    .line 11
    .line 12
    instance-of v0, p0, Ljava/util/Collection;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    move v0, v1

    .line 27
    goto :goto_1

    .line 28
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    move v0, v1

    .line 33
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lqp0/b0;

    .line 44
    .line 45
    invoke-static {v2}, Ljp/eg;->g(Lqp0/b0;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    add-int/lit8 v0, v0, 0x1

    .line 52
    .line 53
    if-ltz v0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    invoke-static {}, Ljp/k1;->q()V

    .line 57
    .line 58
    .line 59
    const/4 p0, 0x0

    .line 60
    throw p0

    .line 61
    :cond_3
    :goto_1
    const/4 p0, 0x3

    .line 62
    if-lt v0, p0, :cond_4

    .line 63
    .line 64
    const/4 p0, 0x1

    .line 65
    return p0

    .line 66
    :cond_4
    return v1
.end method

.method public static final l(Lqp0/b0;C)Lxj0/r;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lqp0/b0;->d:Lxj0/f;

    .line 7
    .line 8
    if-eqz v0, :cond_2

    .line 9
    .line 10
    iget-object v1, p0, Lqp0/b0;->a:Ljava/lang/String;

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    new-instance v1, Ljava/security/SecureRandom;

    .line 15
    .line 16
    invoke-direct {v1}, Ljava/security/SecureRandom;-><init>()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/util/Random;->nextLong()J

    .line 20
    .line 21
    .line 22
    move-result-wide v1

    .line 23
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    :cond_0
    invoke-static {p0}, Ljp/eg;->f(Lqp0/b0;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    new-instance p0, Lxj0/n;

    .line 34
    .line 35
    invoke-direct {p0, v1, v0}, Lxj0/n;-><init>(Ljava/lang/String;Lxj0/f;)V

    .line 36
    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_1
    new-instance p0, Lxj0/o;

    .line 40
    .line 41
    invoke-direct {p0, v1, v0, p1}, Lxj0/o;-><init>(Ljava/lang/String;Lxj0/f;C)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_2
    const/4 p0, 0x0

    .line 46
    return-object p0
.end method
