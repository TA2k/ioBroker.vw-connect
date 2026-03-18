.class public abstract Llp/n1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lxh/e;Lxh/e;Lxh/e;Lyj/b;Lxh/e;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "vin"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v7, p6

    .line 9
    .line 10
    check-cast v7, Ll2/t;

    .line 11
    .line 12
    const v0, 0x1aa76f7c

    .line 13
    .line 14
    .line 15
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v2, 0x4

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    move v0, v2

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int v0, p7, v0

    .line 29
    .line 30
    move-object/from16 v3, p1

    .line 31
    .line 32
    invoke-virtual {v7, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    const/16 v5, 0x20

    .line 37
    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    move v4, v5

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v4, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v0, v4

    .line 45
    move-object/from16 v4, p2

    .line 46
    .line 47
    invoke-virtual {v7, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    const/16 v8, 0x100

    .line 52
    .line 53
    if-eqz v6, :cond_2

    .line 54
    .line 55
    move v6, v8

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v6, 0x80

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v6

    .line 60
    move-object/from16 v6, p3

    .line 61
    .line 62
    invoke-virtual {v7, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    const/16 v10, 0x800

    .line 67
    .line 68
    if-eqz v9, :cond_3

    .line 69
    .line 70
    move v9, v10

    .line 71
    goto :goto_3

    .line 72
    :cond_3
    const/16 v9, 0x400

    .line 73
    .line 74
    :goto_3
    or-int/2addr v0, v9

    .line 75
    move-object/from16 v9, p4

    .line 76
    .line 77
    invoke-virtual {v7, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v11

    .line 81
    const/16 v12, 0x4000

    .line 82
    .line 83
    if-eqz v11, :cond_4

    .line 84
    .line 85
    move v11, v12

    .line 86
    goto :goto_4

    .line 87
    :cond_4
    const/16 v11, 0x2000

    .line 88
    .line 89
    :goto_4
    or-int/2addr v0, v11

    .line 90
    move-object/from16 v11, p5

    .line 91
    .line 92
    invoke-virtual {v7, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v13

    .line 96
    if-eqz v13, :cond_5

    .line 97
    .line 98
    const/high16 v13, 0x20000

    .line 99
    .line 100
    goto :goto_5

    .line 101
    :cond_5
    const/high16 v13, 0x10000

    .line 102
    .line 103
    :goto_5
    or-int/2addr v0, v13

    .line 104
    const v13, 0x12493

    .line 105
    .line 106
    .line 107
    and-int/2addr v13, v0

    .line 108
    const v15, 0x12492

    .line 109
    .line 110
    .line 111
    const/16 v16, 0x1

    .line 112
    .line 113
    const/4 v14, 0x0

    .line 114
    if-eq v13, v15, :cond_6

    .line 115
    .line 116
    move/from16 v13, v16

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_6
    move v13, v14

    .line 120
    :goto_6
    and-int/lit8 v15, v0, 0x1

    .line 121
    .line 122
    invoke-virtual {v7, v15, v13}, Ll2/t;->O(IZ)Z

    .line 123
    .line 124
    .line 125
    move-result v13

    .line 126
    if-eqz v13, :cond_14

    .line 127
    .line 128
    and-int/lit8 v13, v0, 0xe

    .line 129
    .line 130
    if-ne v13, v2, :cond_7

    .line 131
    .line 132
    move/from16 v2, v16

    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_7
    move v2, v14

    .line 136
    :goto_7
    and-int/lit8 v13, v0, 0x70

    .line 137
    .line 138
    if-ne v13, v5, :cond_8

    .line 139
    .line 140
    move/from16 v5, v16

    .line 141
    .line 142
    goto :goto_8

    .line 143
    :cond_8
    move v5, v14

    .line 144
    :goto_8
    or-int/2addr v2, v5

    .line 145
    and-int/lit16 v5, v0, 0x380

    .line 146
    .line 147
    if-ne v5, v8, :cond_9

    .line 148
    .line 149
    move/from16 v5, v16

    .line 150
    .line 151
    goto :goto_9

    .line 152
    :cond_9
    move v5, v14

    .line 153
    :goto_9
    or-int/2addr v2, v5

    .line 154
    and-int/lit16 v5, v0, 0x1c00

    .line 155
    .line 156
    if-ne v5, v10, :cond_a

    .line 157
    .line 158
    move/from16 v5, v16

    .line 159
    .line 160
    goto :goto_a

    .line 161
    :cond_a
    move v5, v14

    .line 162
    :goto_a
    or-int/2addr v2, v5

    .line 163
    const v5, 0xe000

    .line 164
    .line 165
    .line 166
    and-int/2addr v5, v0

    .line 167
    if-ne v5, v12, :cond_b

    .line 168
    .line 169
    move/from16 v5, v16

    .line 170
    .line 171
    goto :goto_b

    .line 172
    :cond_b
    move v5, v14

    .line 173
    :goto_b
    or-int/2addr v2, v5

    .line 174
    const/high16 v5, 0x70000

    .line 175
    .line 176
    and-int/2addr v0, v5

    .line 177
    const/high16 v5, 0x20000

    .line 178
    .line 179
    if-ne v0, v5, :cond_c

    .line 180
    .line 181
    goto :goto_c

    .line 182
    :cond_c
    move/from16 v16, v14

    .line 183
    .line 184
    :goto_c
    or-int v0, v2, v16

    .line 185
    .line 186
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 191
    .line 192
    if-nez v0, :cond_d

    .line 193
    .line 194
    if-ne v2, v8, :cond_e

    .line 195
    .line 196
    :cond_d
    new-instance v0, Lbi/a;

    .line 197
    .line 198
    move-object v2, v3

    .line 199
    move-object v3, v4

    .line 200
    move-object v4, v6

    .line 201
    move-object v5, v9

    .line 202
    move-object v6, v11

    .line 203
    invoke-direct/range {v0 .. v6}, Lbi/a;-><init>(Ljava/lang/String;Lxh/e;Lxh/e;Lxh/e;Lyj/b;Lxh/e;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    move-object v2, v0

    .line 210
    :cond_e
    check-cast v2, Lay0/k;

    .line 211
    .line 212
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 213
    .line 214
    invoke-virtual {v7, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    check-cast v0, Ljava/lang/Boolean;

    .line 219
    .line 220
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    if-eqz v0, :cond_f

    .line 225
    .line 226
    const v0, -0x105bcaaa

    .line 227
    .line 228
    .line 229
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v7, v14}, Ll2/t;->q(Z)V

    .line 233
    .line 234
    .line 235
    const/4 v0, 0x0

    .line 236
    goto :goto_d

    .line 237
    :cond_f
    const v0, 0x31054eee

    .line 238
    .line 239
    .line 240
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 241
    .line 242
    .line 243
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 244
    .line 245
    invoke-virtual {v7, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    check-cast v0, Lhi/a;

    .line 250
    .line 251
    invoke-virtual {v7, v14}, Ll2/t;->q(Z)V

    .line 252
    .line 253
    .line 254
    :goto_d
    new-instance v4, Lnd/e;

    .line 255
    .line 256
    const/16 v1, 0x1b

    .line 257
    .line 258
    invoke-direct {v4, v0, v2, v1}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 259
    .line 260
    .line 261
    invoke-static {v7}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    if-eqz v2, :cond_13

    .line 266
    .line 267
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 268
    .line 269
    if-eqz v0, :cond_10

    .line 270
    .line 271
    move-object v0, v2

    .line 272
    check-cast v0, Landroidx/lifecycle/k;

    .line 273
    .line 274
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    :goto_e
    move-object v5, v0

    .line 279
    goto :goto_f

    .line 280
    :cond_10
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 281
    .line 282
    goto :goto_e

    .line 283
    :goto_f
    const-class v0, Luf/m;

    .line 284
    .line 285
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 286
    .line 287
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 288
    .line 289
    .line 290
    move-result-object v1

    .line 291
    const/4 v3, 0x0

    .line 292
    move-object v6, v7

    .line 293
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    move-object v11, v0

    .line 298
    check-cast v11, Luf/m;

    .line 299
    .line 300
    invoke-static {v6}, Ljp/of;->d(Ll2/o;)Lqf/d;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    iget-object v1, v11, Luf/m;->m:Lyy0/c2;

    .line 305
    .line 306
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 307
    .line 308
    .line 309
    move-result-object v1

    .line 310
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    check-cast v1, Llc/q;

    .line 315
    .line 316
    invoke-virtual {v6, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 317
    .line 318
    .line 319
    move-result v2

    .line 320
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v3

    .line 324
    if-nez v2, :cond_11

    .line 325
    .line 326
    if-ne v3, v8, :cond_12

    .line 327
    .line 328
    :cond_11
    new-instance v9, Lt10/k;

    .line 329
    .line 330
    const/4 v15, 0x0

    .line 331
    const/16 v16, 0x12

    .line 332
    .line 333
    const/4 v10, 0x1

    .line 334
    const-class v12, Luf/m;

    .line 335
    .line 336
    const-string v13, "onUiEvent"

    .line 337
    .line 338
    const-string v14, "onUiEvent(Lcariad/charging/multicharge/kitten/plugandcharge/presentation/overview/PlugAndChargeOverviewUiEvent;)V"

    .line 339
    .line 340
    invoke-direct/range {v9 .. v16}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {v6, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 344
    .line 345
    .line 346
    move-object v3, v9

    .line 347
    :cond_12
    check-cast v3, Lhy0/g;

    .line 348
    .line 349
    check-cast v3, Lay0/k;

    .line 350
    .line 351
    const/16 v2, 0x8

    .line 352
    .line 353
    invoke-interface {v0, v1, v3, v6, v2}, Lqf/d;->r(Llc/q;Lay0/k;Ll2/o;I)V

    .line 354
    .line 355
    .line 356
    goto :goto_10

    .line 357
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 358
    .line 359
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 360
    .line 361
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    throw v0

    .line 365
    :cond_14
    move-object v6, v7

    .line 366
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 367
    .line 368
    .line 369
    :goto_10
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 370
    .line 371
    .line 372
    move-result-object v9

    .line 373
    if-eqz v9, :cond_15

    .line 374
    .line 375
    new-instance v0, Lb41/a;

    .line 376
    .line 377
    const/16 v8, 0x16

    .line 378
    .line 379
    move-object/from16 v1, p0

    .line 380
    .line 381
    move-object/from16 v2, p1

    .line 382
    .line 383
    move-object/from16 v3, p2

    .line 384
    .line 385
    move-object/from16 v4, p3

    .line 386
    .line 387
    move-object/from16 v5, p4

    .line 388
    .line 389
    move-object/from16 v6, p5

    .line 390
    .line 391
    move/from16 v7, p7

    .line 392
    .line 393
    invoke-direct/range {v0 .. v8}, Lb41/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 394
    .line 395
    .line 396
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 397
    .line 398
    :cond_15
    return-void
.end method

.method public static final b(Li1/l;Ll2/o;I)Ll2/b1;
    .locals 4

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    check-cast v0, Ll2/b1;

    .line 21
    .line 22
    and-int/lit8 v2, p2, 0xe

    .line 23
    .line 24
    xor-int/lit8 v2, v2, 0x6

    .line 25
    .line 26
    const/4 v3, 0x4

    .line 27
    if-le v2, v3, :cond_1

    .line 28
    .line 29
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-nez v2, :cond_2

    .line 34
    .line 35
    :cond_1
    and-int/lit8 p2, p2, 0x6

    .line 36
    .line 37
    if-ne p2, v3, :cond_3

    .line 38
    .line 39
    :cond_2
    const/4 p2, 0x1

    .line 40
    goto :goto_0

    .line 41
    :cond_3
    const/4 p2, 0x0

    .line 42
    :goto_0
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    if-nez p2, :cond_4

    .line 47
    .line 48
    if-ne v2, v1, :cond_5

    .line 49
    .line 50
    :cond_4
    new-instance v2, Li1/h;

    .line 51
    .line 52
    const/4 p2, 0x0

    .line 53
    const/4 v1, 0x0

    .line 54
    invoke-direct {v2, p0, v0, v1, p2}, Li1/h;-><init>(Li1/l;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_5
    check-cast v2, Lay0/n;

    .line 61
    .line 62
    invoke-static {v2, p0, p1}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 63
    .line 64
    .line 65
    return-object v0
.end method
