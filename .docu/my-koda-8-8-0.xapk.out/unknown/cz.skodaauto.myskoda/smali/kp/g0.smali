.class public abstract Lkp/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;ZLay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v5, p4

    .line 8
    .line 9
    move/from16 v0, p7

    .line 10
    .line 11
    const-string v2, "modifier"

    .line 12
    .line 13
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v2, "onTouchDown"

    .line 17
    .line 18
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v2, "onTouchUp"

    .line 22
    .line 23
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v2, "onTouchCanceled"

    .line 27
    .line 28
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    move-object/from16 v11, p6

    .line 32
    .line 33
    check-cast v11, Ll2/t;

    .line 34
    .line 35
    const v2, 0x14dbd6ec

    .line 36
    .line 37
    .line 38
    invoke-virtual {v11, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 39
    .line 40
    .line 41
    and-int/lit8 v2, v0, 0x6

    .line 42
    .line 43
    if-nez v2, :cond_1

    .line 44
    .line 45
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_0

    .line 50
    .line 51
    const/4 v2, 0x4

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 v2, 0x2

    .line 54
    :goto_0
    or-int/2addr v2, v0

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    move v2, v0

    .line 57
    :goto_1
    and-int/lit8 v6, v0, 0x30

    .line 58
    .line 59
    const/16 v7, 0x20

    .line 60
    .line 61
    if-nez v6, :cond_3

    .line 62
    .line 63
    move/from16 v6, p1

    .line 64
    .line 65
    invoke-virtual {v11, v6}, Ll2/t;->h(Z)Z

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    if-eqz v8, :cond_2

    .line 70
    .line 71
    move v8, v7

    .line 72
    goto :goto_2

    .line 73
    :cond_2
    const/16 v8, 0x10

    .line 74
    .line 75
    :goto_2
    or-int/2addr v2, v8

    .line 76
    goto :goto_3

    .line 77
    :cond_3
    move/from16 v6, p1

    .line 78
    .line 79
    :goto_3
    and-int/lit16 v8, v0, 0x180

    .line 80
    .line 81
    if-nez v8, :cond_5

    .line 82
    .line 83
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v8

    .line 87
    if-eqz v8, :cond_4

    .line 88
    .line 89
    const/16 v8, 0x100

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_4
    const/16 v8, 0x80

    .line 93
    .line 94
    :goto_4
    or-int/2addr v2, v8

    .line 95
    :cond_5
    and-int/lit16 v8, v0, 0xc00

    .line 96
    .line 97
    if-nez v8, :cond_7

    .line 98
    .line 99
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v8

    .line 103
    if-eqz v8, :cond_6

    .line 104
    .line 105
    const/16 v8, 0x800

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_6
    const/16 v8, 0x400

    .line 109
    .line 110
    :goto_5
    or-int/2addr v2, v8

    .line 111
    :cond_7
    and-int/lit16 v8, v0, 0x6000

    .line 112
    .line 113
    const/16 v14, 0x4000

    .line 114
    .line 115
    if-nez v8, :cond_9

    .line 116
    .line 117
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-eqz v8, :cond_8

    .line 122
    .line 123
    move v8, v14

    .line 124
    goto :goto_6

    .line 125
    :cond_8
    const/16 v8, 0x2000

    .line 126
    .line 127
    :goto_6
    or-int/2addr v2, v8

    .line 128
    :cond_9
    const/high16 v8, 0x30000

    .line 129
    .line 130
    and-int/2addr v8, v0

    .line 131
    move-object/from16 v15, p5

    .line 132
    .line 133
    if-nez v8, :cond_b

    .line 134
    .line 135
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v8

    .line 139
    if-eqz v8, :cond_a

    .line 140
    .line 141
    const/high16 v8, 0x20000

    .line 142
    .line 143
    goto :goto_7

    .line 144
    :cond_a
    const/high16 v8, 0x10000

    .line 145
    .line 146
    :goto_7
    or-int/2addr v2, v8

    .line 147
    :cond_b
    const v8, 0x12493

    .line 148
    .line 149
    .line 150
    and-int/2addr v8, v2

    .line 151
    const v9, 0x12492

    .line 152
    .line 153
    .line 154
    const/16 v16, 0x0

    .line 155
    .line 156
    const/16 v17, 0x1

    .line 157
    .line 158
    if-eq v8, v9, :cond_c

    .line 159
    .line 160
    move/from16 v8, v17

    .line 161
    .line 162
    goto :goto_8

    .line 163
    :cond_c
    move/from16 v8, v16

    .line 164
    .line 165
    :goto_8
    and-int/lit8 v9, v2, 0x1

    .line 166
    .line 167
    invoke-virtual {v11, v9, v8}, Ll2/t;->O(IZ)Z

    .line 168
    .line 169
    .line 170
    move-result v8

    .line 171
    if-eqz v8, :cond_18

    .line 172
    .line 173
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v8

    .line 177
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 178
    .line 179
    if-ne v8, v9, :cond_d

    .line 180
    .line 181
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 182
    .line 183
    .line 184
    move-result-object v8

    .line 185
    invoke-static {v8}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 186
    .line 187
    .line 188
    move-result-object v8

    .line 189
    invoke-virtual {v11, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    :cond_d
    check-cast v8, Ll2/b1;

    .line 193
    .line 194
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v10

    .line 198
    if-ne v10, v9, :cond_e

    .line 199
    .line 200
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 201
    .line 202
    invoke-static {v10}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 203
    .line 204
    .line 205
    move-result-object v10

    .line 206
    invoke-virtual {v11, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    :cond_e
    check-cast v10, Ll2/b1;

    .line 210
    .line 211
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 212
    .line 213
    .line 214
    move-result-object v13

    .line 215
    and-int/lit8 v12, v2, 0x70

    .line 216
    .line 217
    if-ne v12, v7, :cond_f

    .line 218
    .line 219
    move/from16 v7, v17

    .line 220
    .line 221
    goto :goto_9

    .line 222
    :cond_f
    move/from16 v7, v16

    .line 223
    .line 224
    :goto_9
    const v12, 0xe000

    .line 225
    .line 226
    .line 227
    and-int/2addr v12, v2

    .line 228
    if-ne v12, v14, :cond_10

    .line 229
    .line 230
    move/from16 v18, v17

    .line 231
    .line 232
    goto :goto_a

    .line 233
    :cond_10
    move/from16 v18, v16

    .line 234
    .line 235
    :goto_a
    or-int v7, v7, v18

    .line 236
    .line 237
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v14

    .line 241
    if-nez v7, :cond_12

    .line 242
    .line 243
    if-ne v14, v9, :cond_11

    .line 244
    .line 245
    goto :goto_b

    .line 246
    :cond_11
    move-object v7, v10

    .line 247
    move-object v5, v14

    .line 248
    move-object v14, v9

    .line 249
    goto :goto_c

    .line 250
    :cond_12
    :goto_b
    new-instance v5, Le71/d;

    .line 251
    .line 252
    move-object v7, v10

    .line 253
    const/4 v10, 0x0

    .line 254
    move-object v14, v9

    .line 255
    move-object v9, v7

    .line 256
    move-object/from16 v7, p4

    .line 257
    .line 258
    invoke-direct/range {v5 .. v10}, Le71/d;-><init>(ZLay0/a;Ll2/b1;Ll2/b1;Lkotlin/coroutines/Continuation;)V

    .line 259
    .line 260
    .line 261
    move-object v7, v9

    .line 262
    invoke-virtual {v11, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    :goto_c
    check-cast v5, Lay0/n;

    .line 266
    .line 267
    invoke-static {v5, v13, v11}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 268
    .line 269
    .line 270
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    move-object v9, v5

    .line 275
    check-cast v9, Ljava/lang/Boolean;

    .line 276
    .line 277
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 278
    .line 279
    .line 280
    and-int/lit16 v5, v2, 0x380

    .line 281
    .line 282
    const/16 v6, 0x100

    .line 283
    .line 284
    if-ne v5, v6, :cond_13

    .line 285
    .line 286
    move/from16 v5, v17

    .line 287
    .line 288
    goto :goto_d

    .line 289
    :cond_13
    move/from16 v5, v16

    .line 290
    .line 291
    :goto_d
    and-int/lit16 v6, v2, 0x1c00

    .line 292
    .line 293
    const/16 v10, 0x800

    .line 294
    .line 295
    if-ne v6, v10, :cond_14

    .line 296
    .line 297
    move/from16 v6, v17

    .line 298
    .line 299
    goto :goto_e

    .line 300
    :cond_14
    move/from16 v6, v16

    .line 301
    .line 302
    :goto_e
    or-int/2addr v5, v6

    .line 303
    const/16 v6, 0x4000

    .line 304
    .line 305
    if-ne v12, v6, :cond_15

    .line 306
    .line 307
    move/from16 v16, v17

    .line 308
    .line 309
    :cond_15
    or-int v5, v5, v16

    .line 310
    .line 311
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v6

    .line 315
    if-nez v5, :cond_16

    .line 316
    .line 317
    if-ne v6, v14, :cond_17

    .line 318
    .line 319
    :cond_16
    move v5, v2

    .line 320
    goto :goto_f

    .line 321
    :cond_17
    move-object/from16 v19, v8

    .line 322
    .line 323
    move v8, v2

    .line 324
    move-object v2, v6

    .line 325
    move-object/from16 v6, v19

    .line 326
    .line 327
    goto :goto_10

    .line 328
    :goto_f
    new-instance v2, Le71/f;

    .line 329
    .line 330
    move-object v6, v8

    .line 331
    move v8, v5

    .line 332
    move-object/from16 v5, p4

    .line 333
    .line 334
    invoke-direct/range {v2 .. v7}, Le71/f;-><init>(Lay0/a;Lay0/a;Lay0/a;Ll2/b1;Ll2/b1;)V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 338
    .line 339
    .line 340
    :goto_10
    check-cast v2, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 341
    .line 342
    invoke-static {v1, v9, v2}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    move-object v4, v3

    .line 351
    check-cast v4, Ljava/lang/Boolean;

    .line 352
    .line 353
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 354
    .line 355
    .line 356
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v3

    .line 360
    move-object v5, v3

    .line 361
    check-cast v5, Ljava/lang/Boolean;

    .line 362
    .line 363
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 364
    .line 365
    .line 366
    shr-int/lit8 v3, v8, 0x6

    .line 367
    .line 368
    and-int/lit16 v3, v3, 0x1c00

    .line 369
    .line 370
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 371
    .line 372
    .line 373
    move-result-object v8

    .line 374
    move-object v6, v2

    .line 375
    move-object v7, v11

    .line 376
    move-object v3, v15

    .line 377
    invoke-virtual/range {v3 .. v8}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    goto :goto_11

    .line 381
    :cond_18
    move-object v7, v11

    .line 382
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 383
    .line 384
    .line 385
    :goto_11
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 386
    .line 387
    .line 388
    move-result-object v8

    .line 389
    if-eqz v8, :cond_19

    .line 390
    .line 391
    new-instance v0, Le71/c;

    .line 392
    .line 393
    move/from16 v2, p1

    .line 394
    .line 395
    move-object/from16 v3, p2

    .line 396
    .line 397
    move-object/from16 v4, p3

    .line 398
    .line 399
    move-object/from16 v5, p4

    .line 400
    .line 401
    move-object/from16 v6, p5

    .line 402
    .line 403
    move/from16 v7, p7

    .line 404
    .line 405
    invoke-direct/range {v0 .. v7}, Le71/c;-><init>(Lx2/s;ZLay0/a;Lay0/a;Lay0/a;Lt2/b;I)V

    .line 406
    .line 407
    .line 408
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 409
    .line 410
    :cond_19
    return-void
.end method

.method public static final b(Lrh/v;)Lrh/s;
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lrh/v;->b:Ljava/util/List;

    .line 7
    .line 8
    iget-boolean v3, p0, Lrh/v;->a:Z

    .line 9
    .line 10
    iget-boolean v4, p0, Lrh/v;->c:Z

    .line 11
    .line 12
    iget-object v6, p0, Lrh/v;->d:Llc/l;

    .line 13
    .line 14
    iget-object v7, p0, Lrh/v;->e:Lrh/h;

    .line 15
    .line 16
    iget-boolean v8, p0, Lrh/v;->f:Z

    .line 17
    .line 18
    iget-object v9, p0, Lrh/v;->g:Ljava/lang/String;

    .line 19
    .line 20
    move-object p0, v2

    .line 21
    check-cast p0, Ljava/lang/Iterable;

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const/4 v0, 0x1

    .line 28
    :goto_0
    move v5, v0

    .line 29
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Lrh/d;

    .line 40
    .line 41
    if-eqz v5, :cond_0

    .line 42
    .line 43
    iget-object v1, v1, Lrh/d;->b:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_0

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const/4 v1, 0x0

    .line 53
    move v5, v1

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    new-instance v1, Lrh/s;

    .line 56
    .line 57
    invoke-direct/range {v1 .. v9}, Lrh/s;-><init>(Ljava/util/List;ZZZLlc/l;Lrh/h;ZLjava/lang/String;)V

    .line 58
    .line 59
    .line 60
    return-object v1
.end method
