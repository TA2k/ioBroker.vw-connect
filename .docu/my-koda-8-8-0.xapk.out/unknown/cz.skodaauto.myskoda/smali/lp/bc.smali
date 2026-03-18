.class public abstract Llp/bc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/time/OffsetDateTime;Lx2/s;ZLl2/o;II)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v4, p4

    .line 4
    .line 5
    move-object/from16 v6, p3

    .line 6
    .line 7
    check-cast v6, Ll2/t;

    .line 8
    .line 9
    const v0, 0x51014898

    .line 10
    .line 11
    .line 12
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v4, 0x6

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x2

    .line 28
    :goto_0
    or-int/2addr v0, v4

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move v0, v4

    .line 31
    :goto_1
    and-int/lit8 v2, p5, 0x2

    .line 32
    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    or-int/lit8 v0, v0, 0x30

    .line 36
    .line 37
    :cond_2
    move-object/from16 v3, p1

    .line 38
    .line 39
    goto :goto_3

    .line 40
    :cond_3
    and-int/lit8 v3, v4, 0x30

    .line 41
    .line 42
    if-nez v3, :cond_2

    .line 43
    .line 44
    move-object/from16 v3, p1

    .line 45
    .line 46
    invoke-virtual {v6, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    if-eqz v5, :cond_4

    .line 51
    .line 52
    const/16 v5, 0x20

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_4
    const/16 v5, 0x10

    .line 56
    .line 57
    :goto_2
    or-int/2addr v0, v5

    .line 58
    :goto_3
    and-int/lit8 v5, p5, 0x4

    .line 59
    .line 60
    const/16 v7, 0x100

    .line 61
    .line 62
    if-eqz v5, :cond_6

    .line 63
    .line 64
    or-int/lit16 v0, v0, 0x180

    .line 65
    .line 66
    :cond_5
    move/from16 v8, p2

    .line 67
    .line 68
    :goto_4
    move v9, v0

    .line 69
    goto :goto_6

    .line 70
    :cond_6
    and-int/lit16 v8, v4, 0x180

    .line 71
    .line 72
    if-nez v8, :cond_5

    .line 73
    .line 74
    move/from16 v8, p2

    .line 75
    .line 76
    invoke-virtual {v6, v8}, Ll2/t;->h(Z)Z

    .line 77
    .line 78
    .line 79
    move-result v9

    .line 80
    if-eqz v9, :cond_7

    .line 81
    .line 82
    move v9, v7

    .line 83
    goto :goto_5

    .line 84
    :cond_7
    const/16 v9, 0x80

    .line 85
    .line 86
    :goto_5
    or-int/2addr v0, v9

    .line 87
    goto :goto_4

    .line 88
    :goto_6
    and-int/lit16 v0, v9, 0x93

    .line 89
    .line 90
    const/16 v10, 0x92

    .line 91
    .line 92
    const/4 v11, 0x1

    .line 93
    const/4 v12, 0x0

    .line 94
    if-eq v0, v10, :cond_8

    .line 95
    .line 96
    move v0, v11

    .line 97
    goto :goto_7

    .line 98
    :cond_8
    move v0, v12

    .line 99
    :goto_7
    and-int/lit8 v10, v9, 0x1

    .line 100
    .line 101
    invoke-virtual {v6, v10, v0}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-eqz v0, :cond_14

    .line 106
    .line 107
    if-eqz v2, :cond_9

    .line 108
    .line 109
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 110
    .line 111
    move-object v2, v0

    .line 112
    goto :goto_8

    .line 113
    :cond_9
    move-object v2, v3

    .line 114
    :goto_8
    if-eqz v5, :cond_a

    .line 115
    .line 116
    move v3, v11

    .line 117
    goto :goto_9

    .line 118
    :cond_a
    move v3, v8

    .line 119
    :goto_9
    if-nez v1, :cond_b

    .line 120
    .line 121
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    if-eqz v7, :cond_15

    .line 126
    .line 127
    new-instance v0, Lvt0/a;

    .line 128
    .line 129
    const/4 v6, 0x0

    .line 130
    move/from16 v5, p5

    .line 131
    .line 132
    invoke-direct/range {v0 .. v6}, Lvt0/a;-><init>(Ljava/time/OffsetDateTime;Lx2/s;ZIII)V

    .line 133
    .line 134
    .line 135
    :goto_a
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 136
    .line 137
    return-void

    .line 138
    :cond_b
    invoke-static {v6}, Lxf0/y1;->F(Ll2/o;)Z

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    if-eqz v0, :cond_c

    .line 143
    .line 144
    const v0, -0x5b9de352

    .line 145
    .line 146
    .line 147
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 148
    .line 149
    .line 150
    new-instance v0, Lut0/a;

    .line 151
    .line 152
    const/4 v1, 0x6

    .line 153
    invoke-direct {v0, v1}, Lut0/a;-><init>(I)V

    .line 154
    .line 155
    .line 156
    and-int/lit8 v1, v9, 0x70

    .line 157
    .line 158
    invoke-static {v0, v2, v6, v1}, Llp/bc;->b(Lut0/a;Lx2/s;Ll2/o;I)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 165
    .line 166
    .line 167
    move-result-object v7

    .line 168
    if-eqz v7, :cond_15

    .line 169
    .line 170
    new-instance v0, Lvt0/a;

    .line 171
    .line 172
    const/4 v6, 0x1

    .line 173
    move-object/from16 v1, p0

    .line 174
    .line 175
    move/from16 v4, p4

    .line 176
    .line 177
    move/from16 v5, p5

    .line 178
    .line 179
    invoke-direct/range {v0 .. v6}, Lvt0/a;-><init>(Ljava/time/OffsetDateTime;Lx2/s;ZIII)V

    .line 180
    .line 181
    .line 182
    goto :goto_a

    .line 183
    :cond_c
    move-object/from16 v1, p0

    .line 184
    .line 185
    move-object v8, v2

    .line 186
    const v0, -0x5bb68f16

    .line 187
    .line 188
    .line 189
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 200
    .line 201
    if-ne v0, v2, :cond_d

    .line 202
    .line 203
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    invoke-virtual {v0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    :cond_d
    move-object v15, v0

    .line 215
    check-cast v15, Ljava/lang/String;

    .line 216
    .line 217
    invoke-static {v15}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v4

    .line 228
    if-nez v0, :cond_e

    .line 229
    .line 230
    if-ne v4, v2, :cond_f

    .line 231
    .line 232
    :cond_e
    new-instance v4, Lu2/a;

    .line 233
    .line 234
    const/16 v0, 0xe

    .line 235
    .line 236
    invoke-direct {v4, v1, v0}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v6, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    :cond_f
    move-object/from16 v19, v4

    .line 243
    .line 244
    check-cast v19, Lay0/a;

    .line 245
    .line 246
    const v0, -0x6040e0aa

    .line 247
    .line 248
    .line 249
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 250
    .line 251
    .line 252
    invoke-static {v6}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    if-eqz v0, :cond_13

    .line 257
    .line 258
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 259
    .line 260
    .line 261
    move-result-object v16

    .line 262
    invoke-static {v6}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 263
    .line 264
    .line 265
    move-result-object v18

    .line 266
    const-class v4, Lut0/b;

    .line 267
    .line 268
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 269
    .line 270
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 271
    .line 272
    .line 273
    move-result-object v13

    .line 274
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 275
    .line 276
    .line 277
    move-result-object v14

    .line 278
    const/16 v17, 0x0

    .line 279
    .line 280
    invoke-static/range {v13 .. v19}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 285
    .line 286
    .line 287
    check-cast v0, Lql0/j;

    .line 288
    .line 289
    invoke-static {v0, v6, v12, v11}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 290
    .line 291
    .line 292
    check-cast v0, Lut0/b;

    .line 293
    .line 294
    iget-object v4, v0, Lql0/j;->g:Lyy0/l1;

    .line 295
    .line 296
    const/4 v5, 0x0

    .line 297
    invoke-static {v4, v5, v6, v11}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 298
    .line 299
    .line 300
    move-result-object v10

    .line 301
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 302
    .line 303
    .line 304
    move-result-object v13

    .line 305
    invoke-virtual {v6, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result v4

    .line 309
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    move-result v14

    .line 313
    or-int/2addr v4, v14

    .line 314
    and-int/lit16 v14, v9, 0x380

    .line 315
    .line 316
    if-ne v14, v7, :cond_10

    .line 317
    .line 318
    goto :goto_b

    .line 319
    :cond_10
    move v11, v12

    .line 320
    :goto_b
    or-int/2addr v4, v11

    .line 321
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v7

    .line 325
    if-nez v4, :cond_11

    .line 326
    .line 327
    if-ne v7, v2, :cond_12

    .line 328
    .line 329
    :cond_11
    move-object v1, v0

    .line 330
    new-instance v0, Lbc/g;

    .line 331
    .line 332
    move-object v4, v5

    .line 333
    const/4 v5, 0x5

    .line 334
    move-object/from16 v2, p0

    .line 335
    .line 336
    invoke-direct/range {v0 .. v5}, Lbc/g;-><init>(Lql0/j;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 337
    .line 338
    .line 339
    move-object v1, v2

    .line 340
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 341
    .line 342
    .line 343
    move-object v7, v0

    .line 344
    :cond_12
    check-cast v7, Lay0/n;

    .line 345
    .line 346
    invoke-static {v1, v13, v7, v6}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 347
    .line 348
    .line 349
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    check-cast v0, Lut0/a;

    .line 354
    .line 355
    and-int/lit8 v2, v9, 0x70

    .line 356
    .line 357
    invoke-static {v0, v8, v6, v2}, Llp/bc;->b(Lut0/a;Lx2/s;Ll2/o;I)V

    .line 358
    .line 359
    .line 360
    move-object v2, v8

    .line 361
    goto :goto_c

    .line 362
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 363
    .line 364
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 365
    .line 366
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    throw v0

    .line 370
    :cond_14
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 371
    .line 372
    .line 373
    move-object v2, v3

    .line 374
    move v3, v8

    .line 375
    :goto_c
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 376
    .line 377
    .line 378
    move-result-object v7

    .line 379
    if-eqz v7, :cond_15

    .line 380
    .line 381
    new-instance v0, Lvt0/a;

    .line 382
    .line 383
    const/4 v6, 0x2

    .line 384
    move/from16 v4, p4

    .line 385
    .line 386
    move/from16 v5, p5

    .line 387
    .line 388
    invoke-direct/range {v0 .. v6}, Lvt0/a;-><init>(Ljava/time/OffsetDateTime;Lx2/s;ZIII)V

    .line 389
    .line 390
    .line 391
    goto/16 :goto_a

    .line 392
    .line 393
    :cond_15
    return-void
.end method

.method public static final b(Lut0/a;Lx2/s;Ll2/o;I)V
    .locals 8

    .line 1
    move-object v5, p2

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p2, -0x1bee0ff3

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p3, 0x6

    .line 11
    .line 12
    if-nez p2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    const/4 p2, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p2, 0x2

    .line 23
    :goto_0
    or-int/2addr p2, p3

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move p2, p3

    .line 26
    :goto_1
    and-int/lit8 v0, p3, 0x30

    .line 27
    .line 28
    if-nez v0, :cond_3

    .line 29
    .line 30
    invoke-virtual {v5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    const/16 v0, 0x20

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    const/16 v0, 0x10

    .line 40
    .line 41
    :goto_2
    or-int/2addr p2, v0

    .line 42
    :cond_3
    and-int/lit8 v0, p2, 0x13

    .line 43
    .line 44
    const/16 v1, 0x12

    .line 45
    .line 46
    const/4 v2, 0x1

    .line 47
    if-eq v0, v1, :cond_4

    .line 48
    .line 49
    move v0, v2

    .line 50
    goto :goto_3

    .line 51
    :cond_4
    const/4 v0, 0x0

    .line 52
    :goto_3
    and-int/2addr p2, v2

    .line 53
    invoke-virtual {v5, p2, v0}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eqz p2, :cond_5

    .line 58
    .line 59
    iget-object v0, p0, Lut0/a;->a:Ljava/lang/String;

    .line 60
    .line 61
    new-instance p2, Lvt0/b;

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    invoke-direct {p2, p1, v1}, Lvt0/b;-><init>(Lx2/s;I)V

    .line 65
    .line 66
    .line 67
    const v1, 0x400c808f

    .line 68
    .line 69
    .line 70
    invoke-static {v1, v5, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    const/16 v6, 0x6c00

    .line 75
    .line 76
    const/4 v7, 0x6

    .line 77
    const/4 v1, 0x0

    .line 78
    const/4 v2, 0x0

    .line 79
    const-string v3, "timestamp"

    .line 80
    .line 81
    invoke-static/range {v0 .. v7}, Ljp/w1;->b(Ljava/lang/Object;Lx2/s;Lc1/a0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 82
    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_5
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    :goto_4
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    if-eqz p2, :cond_6

    .line 93
    .line 94
    new-instance v0, Ltj/i;

    .line 95
    .line 96
    const/16 v1, 0xa

    .line 97
    .line 98
    invoke-direct {v0, p3, v1, p0, p1}, Ltj/i;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 102
    .line 103
    :cond_6
    return-void
.end method

.method public static final c(Lim/s;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Ljm/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ljm/c;

    .line 7
    .line 8
    iget v1, v0, Ljm/c;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ljm/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ljm/c;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ljm/c;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ljm/c;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ljm/c;->e:Lu01/f;

    .line 37
    .line 38
    iget-object v0, v0, Ljm/c;->d:Lim/s;

    .line 39
    .line 40
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto :goto_3

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :try_start_1
    new-instance p1, Lu01/f;

    .line 58
    .line 59
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object p0, v0, Ljm/c;->d:Lim/s;

    .line 63
    .line 64
    iput-object p1, v0, Ljm/c;->e:Lu01/f;

    .line 65
    .line 66
    iput v3, v0, Ljm/c;->g:I

    .line 67
    .line 68
    iget-object v0, p0, Lim/s;->d:Lu01/h;

    .line 69
    .line 70
    invoke-interface {v0, p1}, Lu01/h;->L(Lu01/g;)J

    .line 71
    .line 72
    .line 73
    sget-object v0, Llx0/b0;->a:Llx0/b0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 74
    .line 75
    if-ne v0, v1, :cond_3

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_3
    move-object v0, p0

    .line 79
    move-object p0, p1

    .line 80
    :goto_1
    const/4 p1, 0x0

    .line 81
    invoke-static {v0, p1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    return-object p0

    .line 85
    :goto_2
    move-object v0, p0

    .line 86
    move-object p0, p1

    .line 87
    goto :goto_3

    .line 88
    :catchall_1
    move-exception p1

    .line 89
    goto :goto_2

    .line 90
    :goto_3
    :try_start_2
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 91
    :catchall_2
    move-exception p1

    .line 92
    invoke-static {v0, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 93
    .line 94
    .line 95
    throw p1
.end method
