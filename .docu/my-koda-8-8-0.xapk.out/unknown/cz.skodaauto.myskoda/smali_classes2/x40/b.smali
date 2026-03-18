.class public final synthetic Lx40/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lmy0/c;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lmy0/c;Lay0/k;Lay0/a;I)V
    .locals 0

    .line 1
    iput p4, p0, Lx40/b;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lx40/b;->e:Lmy0/c;

    .line 7
    .line 8
    iput-object p2, p0, Lx40/b;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p3, p0, Lx40/b;->g:Lay0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lx40/b;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    const/4 v4, 0x0

    .line 9
    iget-object v5, v0, Lx40/b;->g:Lay0/a;

    .line 10
    .line 11
    iget-object v6, v0, Lx40/b;->f:Lay0/k;

    .line 12
    .line 13
    iget-object v0, v0, Lx40/b;->e:Lmy0/c;

    .line 14
    .line 15
    const/4 v7, 0x1

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    move-object/from16 v1, p1

    .line 20
    .line 21
    check-cast v1, Ll2/o;

    .line 22
    .line 23
    move-object/from16 v8, p2

    .line 24
    .line 25
    check-cast v8, Ljava/lang/Integer;

    .line 26
    .line 27
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result v8

    .line 31
    sget-object v9, Lx40/d;->a:Ljava/util/List;

    .line 32
    .line 33
    and-int/lit8 v10, v8, 0x3

    .line 34
    .line 35
    if-eq v10, v3, :cond_0

    .line 36
    .line 37
    move v3, v7

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v3, v4

    .line 40
    :goto_0
    and-int/2addr v8, v7

    .line 41
    check-cast v1, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v1, v8, v3}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_8

    .line 48
    .line 49
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 54
    .line 55
    if-ne v3, v8, :cond_3

    .line 56
    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    iget-wide v10, v0, Lmy0/c;->d:J

    .line 60
    .line 61
    sget v0, Lmy0/c;->g:I

    .line 62
    .line 63
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 64
    .line 65
    invoke-static {v10, v11, v0}, Lmy0/c;->n(JLmy0/e;)J

    .line 66
    .line 67
    .line 68
    move-result-wide v12

    .line 69
    long-to-int v0, v12

    .line 70
    new-instance v3, Ljn/a;

    .line 71
    .line 72
    sget-object v12, Lmy0/e;->j:Lmy0/e;

    .line 73
    .line 74
    invoke-static {v10, v11, v12}, Lmy0/c;->n(JLmy0/e;)J

    .line 75
    .line 76
    .line 77
    move-result-wide v10

    .line 78
    long-to-int v10, v10

    .line 79
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object v11

    .line 83
    invoke-interface {v9, v11}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v11

    .line 87
    if-eqz v11, :cond_1

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_1
    move v0, v4

    .line 91
    :goto_1
    invoke-direct {v3, v10, v0}, Ljn/a;-><init>(II)V

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_2
    new-instance v3, Ljn/a;

    .line 96
    .line 97
    invoke-direct {v3, v7, v4}, Ljn/a;-><init>(II)V

    .line 98
    .line 99
    .line 100
    :goto_2
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :cond_3
    check-cast v3, Ll2/b1;

    .line 108
    .line 109
    sget-object v0, Lk1/j;->c:Lk1/e;

    .line 110
    .line 111
    sget-object v10, Lx2/c;->p:Lx2/h;

    .line 112
    .line 113
    invoke-static {v0, v10, v1, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    iget-wide v10, v1, Ll2/t;->T:J

    .line 118
    .line 119
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 120
    .line 121
    .line 122
    move-result v10

    .line 123
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 124
    .line 125
    .line 126
    move-result-object v11

    .line 127
    sget-object v12, Lx2/p;->b:Lx2/p;

    .line 128
    .line 129
    invoke-static {v1, v12}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 130
    .line 131
    .line 132
    move-result-object v13

    .line 133
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 134
    .line 135
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 139
    .line 140
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 141
    .line 142
    .line 143
    iget-boolean v15, v1, Ll2/t;->S:Z

    .line 144
    .line 145
    if-eqz v15, :cond_4

    .line 146
    .line 147
    invoke-virtual {v1, v14}, Ll2/t;->l(Lay0/a;)V

    .line 148
    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_4
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 152
    .line 153
    .line 154
    :goto_3
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 155
    .line 156
    invoke-static {v14, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 157
    .line 158
    .line 159
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 160
    .line 161
    invoke-static {v0, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 162
    .line 163
    .line 164
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 165
    .line 166
    iget-boolean v11, v1, Ll2/t;->S:Z

    .line 167
    .line 168
    if-nez v11, :cond_5

    .line 169
    .line 170
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v11

    .line 174
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object v14

    .line 178
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v11

    .line 182
    if-nez v11, :cond_6

    .line 183
    .line 184
    :cond_5
    invoke-static {v10, v1, v10, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 185
    .line 186
    .line 187
    :cond_6
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 188
    .line 189
    invoke-static {v0, v13, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 190
    .line 191
    .line 192
    invoke-static {v1, v4}, Lx40/d;->c(Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 196
    .line 197
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v10

    .line 201
    check-cast v10, Lj91/c;

    .line 202
    .line 203
    iget v10, v10, Lj91/c;->e:F

    .line 204
    .line 205
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v11

    .line 209
    check-cast v11, Lj91/c;

    .line 210
    .line 211
    iget v11, v11, Lj91/c;->h:F

    .line 212
    .line 213
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v13

    .line 217
    check-cast v13, Lj91/c;

    .line 218
    .line 219
    iget v13, v13, Lj91/c;->h:F

    .line 220
    .line 221
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    check-cast v0, Lj91/c;

    .line 226
    .line 227
    iget v0, v0, Lj91/c;->d:F

    .line 228
    .line 229
    invoke-static {v12, v11, v10, v13, v0}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 230
    .line 231
    .line 232
    move-result-object v10

    .line 233
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 234
    .line 235
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    check-cast v0, Lj91/e;

    .line 240
    .line 241
    invoke-virtual {v0}, Lj91/e;->e()J

    .line 242
    .line 243
    .line 244
    move-result-wide v17

    .line 245
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 246
    .line 247
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v0

    .line 251
    check-cast v0, Lj91/f;

    .line 252
    .line 253
    invoke-virtual {v0}, Lj91/f;->l()Lg4/p0;

    .line 254
    .line 255
    .line 256
    move-result-object v19

    .line 257
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    move-object v11, v0

    .line 262
    check-cast v11, Ljn/a;

    .line 263
    .line 264
    new-instance v0, Lgy0/j;

    .line 265
    .line 266
    const/16 v12, 0x18

    .line 267
    .line 268
    invoke-direct {v0, v4, v12, v7}, Lgy0/h;-><init>(III)V

    .line 269
    .line 270
    .line 271
    const/16 v12, 0x30

    .line 272
    .line 273
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 274
    .line 275
    .line 276
    move-result-object v12

    .line 277
    invoke-static {v0, v12}, Lmx0/q;->Z(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 278
    .line 279
    .line 280
    move-result-object v0

    .line 281
    const/16 v12, 0x48

    .line 282
    .line 283
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 284
    .line 285
    .line 286
    move-result-object v12

    .line 287
    invoke-static {v0, v12}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 288
    .line 289
    .line 290
    move-result-object v13

    .line 291
    move-object v14, v9

    .line 292
    check-cast v14, Ljava/lang/Iterable;

    .line 293
    .line 294
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    if-ne v0, v8, :cond_7

    .line 299
    .line 300
    new-instance v0, Lle/b;

    .line 301
    .line 302
    const/16 v8, 0x12

    .line 303
    .line 304
    invoke-direct {v0, v3, v8}, Lle/b;-><init>(Ll2/b1;I)V

    .line 305
    .line 306
    .line 307
    invoke-virtual {v1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 308
    .line 309
    .line 310
    :cond_7
    move-object/from16 v16, v0

    .line 311
    .line 312
    check-cast v16, Lay0/k;

    .line 313
    .line 314
    const v21, 0xc30180

    .line 315
    .line 316
    .line 317
    const/4 v12, 0x0

    .line 318
    sget-object v15, Lx40/a;->a:Lt2/b;

    .line 319
    .line 320
    move-object/from16 v20, v1

    .line 321
    .line 322
    invoke-static/range {v10 .. v21}, Llp/cc;->c(Lx2/s;Ljn/a;ZLjava/lang/Iterable;Ljava/lang/Iterable;Lay0/n;Lay0/k;JLg4/p0;Ll2/o;I)V

    .line 323
    .line 324
    .line 325
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    check-cast v0, Ljn/a;

    .line 330
    .line 331
    invoke-static {v0, v6, v5, v1, v4}, Lx40/d;->a(Ljn/a;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    .line 335
    .line 336
    .line 337
    goto :goto_4

    .line 338
    :cond_8
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 339
    .line 340
    .line 341
    :goto_4
    return-object v2

    .line 342
    :pswitch_0
    move-object/from16 v1, p1

    .line 343
    .line 344
    check-cast v1, Ll2/o;

    .line 345
    .line 346
    move-object/from16 v8, p2

    .line 347
    .line 348
    check-cast v8, Ljava/lang/Integer;

    .line 349
    .line 350
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 351
    .line 352
    .line 353
    move-result v8

    .line 354
    and-int/lit8 v9, v8, 0x3

    .line 355
    .line 356
    if-eq v9, v3, :cond_9

    .line 357
    .line 358
    move v4, v7

    .line 359
    :cond_9
    and-int/lit8 v3, v8, 0x1

    .line 360
    .line 361
    check-cast v1, Ll2/t;

    .line 362
    .line 363
    invoke-virtual {v1, v3, v4}, Ll2/t;->O(IZ)Z

    .line 364
    .line 365
    .line 366
    move-result v3

    .line 367
    if-eqz v3, :cond_a

    .line 368
    .line 369
    const/4 v3, 0x4

    .line 370
    int-to-float v3, v3

    .line 371
    invoke-static {v3}, Ls1/f;->b(F)Ls1/e;

    .line 372
    .line 373
    .line 374
    move-result-object v9

    .line 375
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 376
    .line 377
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v4

    .line 381
    check-cast v4, Lj91/e;

    .line 382
    .line 383
    invoke-virtual {v4}, Lj91/e;->i()J

    .line 384
    .line 385
    .line 386
    move-result-wide v10

    .line 387
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v3

    .line 391
    check-cast v3, Lj91/e;

    .line 392
    .line 393
    invoke-virtual {v3}, Lj91/e;->q()J

    .line 394
    .line 395
    .line 396
    move-result-wide v12

    .line 397
    new-instance v3, Lx40/b;

    .line 398
    .line 399
    invoke-direct {v3, v0, v6, v5, v7}, Lx40/b;-><init>(Lmy0/c;Lay0/k;Lay0/a;I)V

    .line 400
    .line 401
    .line 402
    const v0, 0x6571305f

    .line 403
    .line 404
    .line 405
    invoke-static {v0, v1, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 406
    .line 407
    .line 408
    move-result-object v17

    .line 409
    const/high16 v19, 0xc00000

    .line 410
    .line 411
    const/16 v20, 0x70

    .line 412
    .line 413
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 414
    .line 415
    const/4 v14, 0x0

    .line 416
    const/4 v15, 0x0

    .line 417
    const/16 v16, 0x0

    .line 418
    .line 419
    move-object/from16 v18, v1

    .line 420
    .line 421
    invoke-static/range {v8 .. v20}, Lh2/oa;->a(Lx2/s;Le3/n0;JJFFLe1/t;Lt2/b;Ll2/o;II)V

    .line 422
    .line 423
    .line 424
    goto :goto_5

    .line 425
    :cond_a
    move-object/from16 v18, v1

    .line 426
    .line 427
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 428
    .line 429
    .line 430
    :goto_5
    return-object v2

    .line 431
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
