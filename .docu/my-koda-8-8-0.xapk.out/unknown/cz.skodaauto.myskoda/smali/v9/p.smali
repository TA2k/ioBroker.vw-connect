.class public final Lv9/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# instance fields
.field public final a:Lv9/c0;

.field public final b:Z

.field public final c:Z

.field public final d:La8/n0;

.field public final e:La8/n0;

.field public final f:La8/n0;

.field public g:J

.field public final h:[Z

.field public i:Ljava/lang/String;

.field public j:Lo8/i0;

.field public k:Lv9/o;

.field public l:Z

.field public m:J

.field public n:Z

.field public final o:Lw7/p;


# direct methods
.method public constructor <init>(Lv9/c0;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv9/p;->a:Lv9/c0;

    .line 5
    .line 6
    iput-boolean p2, p0, Lv9/p;->b:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lv9/p;->c:Z

    .line 9
    .line 10
    const/4 p1, 0x3

    .line 11
    new-array p1, p1, [Z

    .line 12
    .line 13
    iput-object p1, p0, Lv9/p;->h:[Z

    .line 14
    .line 15
    new-instance p1, La8/n0;

    .line 16
    .line 17
    const/4 p2, 0x7

    .line 18
    invoke-direct {p1, p2}, La8/n0;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lv9/p;->d:La8/n0;

    .line 22
    .line 23
    new-instance p1, La8/n0;

    .line 24
    .line 25
    const/16 p2, 0x8

    .line 26
    .line 27
    invoke-direct {p1, p2}, La8/n0;-><init>(I)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lv9/p;->e:La8/n0;

    .line 31
    .line 32
    new-instance p1, La8/n0;

    .line 33
    .line 34
    const/4 p2, 0x6

    .line 35
    invoke-direct {p1, p2}, La8/n0;-><init>(I)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lv9/p;->f:La8/n0;

    .line 39
    .line 40
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    iput-wide p1, p0, Lv9/p;->m:J

    .line 46
    .line 47
    new-instance p1, Lw7/p;

    .line 48
    .line 49
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object p1, p0, Lv9/p;->o:Lw7/p;

    .line 53
    .line 54
    return-void
.end method


# virtual methods
.method public final a(JIIJ)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p4

    .line 4
    .line 5
    iget-object v2, v0, Lv9/p;->a:Lv9/c0;

    .line 6
    .line 7
    iget-object v2, v2, Lv9/c0;->d:Lca/j;

    .line 8
    .line 9
    iget-boolean v3, v0, Lv9/p;->l:Z

    .line 10
    .line 11
    const/4 v4, 0x4

    .line 12
    if-eqz v3, :cond_0

    .line 13
    .line 14
    iget-object v3, v0, Lv9/p;->k:Lv9/o;

    .line 15
    .line 16
    iget-boolean v3, v3, Lv9/o;->c:Z

    .line 17
    .line 18
    if-eqz v3, :cond_3

    .line 19
    .line 20
    :cond_0
    iget-object v3, v0, Lv9/p;->d:La8/n0;

    .line 21
    .line 22
    invoke-virtual {v3, v1}, La8/n0;->e(I)Z

    .line 23
    .line 24
    .line 25
    iget-object v6, v0, Lv9/p;->e:La8/n0;

    .line 26
    .line 27
    invoke-virtual {v6, v1}, La8/n0;->e(I)Z

    .line 28
    .line 29
    .line 30
    iget-boolean v7, v0, Lv9/p;->l:Z

    .line 31
    .line 32
    const/4 v8, 0x3

    .line 33
    if-nez v7, :cond_1

    .line 34
    .line 35
    iget-boolean v7, v3, La8/n0;->e:Z

    .line 36
    .line 37
    if-eqz v7, :cond_3

    .line 38
    .line 39
    iget-boolean v7, v6, La8/n0;->e:Z

    .line 40
    .line 41
    if-eqz v7, :cond_3

    .line 42
    .line 43
    new-instance v7, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    iget-object v9, v3, La8/n0;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v9, [B

    .line 51
    .line 52
    iget v10, v3, La8/n0;->c:I

    .line 53
    .line 54
    invoke-static {v9, v10}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 55
    .line 56
    .line 57
    move-result-object v9

    .line 58
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    iget-object v9, v6, La8/n0;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v9, [B

    .line 64
    .line 65
    iget v10, v6, La8/n0;->c:I

    .line 66
    .line 67
    invoke-static {v9, v10}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 68
    .line 69
    .line 70
    move-result-object v9

    .line 71
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    iget-object v9, v3, La8/n0;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v9, [B

    .line 77
    .line 78
    iget v10, v3, La8/n0;->c:I

    .line 79
    .line 80
    invoke-static {v9, v8, v10}, Lx7/n;->j([BII)Lx7/m;

    .line 81
    .line 82
    .line 83
    move-result-object v8

    .line 84
    iget v9, v8, Lx7/m;->s:I

    .line 85
    .line 86
    iget-object v10, v6, La8/n0;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v10, [B

    .line 89
    .line 90
    iget v11, v6, La8/n0;->c:I

    .line 91
    .line 92
    new-instance v12, Lm9/f;

    .line 93
    .line 94
    invoke-direct {v12, v10, v4, v11}, Lm9/f;-><init>([BII)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v12}, Lm9/f;->m()I

    .line 98
    .line 99
    .line 100
    move-result v10

    .line 101
    invoke-virtual {v12}, Lm9/f;->m()I

    .line 102
    .line 103
    .line 104
    move-result v11

    .line 105
    invoke-virtual {v12}, Lm9/f;->s()V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v12}, Lm9/f;->h()Z

    .line 109
    .line 110
    .line 111
    move-result v12

    .line 112
    new-instance v13, Lx7/l;

    .line 113
    .line 114
    invoke-direct {v13, v10, v11, v12}, Lx7/l;-><init>(IIZ)V

    .line 115
    .line 116
    .line 117
    iget v11, v8, Lx7/m;->a:I

    .line 118
    .line 119
    iget v12, v8, Lx7/m;->b:I

    .line 120
    .line 121
    iget v14, v8, Lx7/m;->c:I

    .line 122
    .line 123
    sget-object v15, Lw7/c;->a:[B

    .line 124
    .line 125
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v11

    .line 129
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v12

    .line 133
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 134
    .line 135
    .line 136
    move-result-object v14

    .line 137
    filled-new-array {v11, v12, v14}, [Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v11

    .line 141
    const-string v12, "avc1.%02X%02X%02X"

    .line 142
    .line 143
    invoke-static {v12, v11}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v11

    .line 147
    iget-object v12, v0, Lv9/p;->j:Lo8/i0;

    .line 148
    .line 149
    new-instance v14, Lt7/n;

    .line 150
    .line 151
    invoke-direct {v14}, Lt7/n;-><init>()V

    .line 152
    .line 153
    .line 154
    iget-object v15, v0, Lv9/p;->i:Ljava/lang/String;

    .line 155
    .line 156
    iput-object v15, v14, Lt7/n;->a:Ljava/lang/String;

    .line 157
    .line 158
    const-string v15, "video/mp2t"

    .line 159
    .line 160
    invoke-static {v15}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v15

    .line 164
    iput-object v15, v14, Lt7/n;->l:Ljava/lang/String;

    .line 165
    .line 166
    const-string v15, "video/avc"

    .line 167
    .line 168
    invoke-static {v15}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v15

    .line 172
    iput-object v15, v14, Lt7/n;->m:Ljava/lang/String;

    .line 173
    .line 174
    iput-object v11, v14, Lt7/n;->j:Ljava/lang/String;

    .line 175
    .line 176
    iget v11, v8, Lx7/m;->e:I

    .line 177
    .line 178
    iput v11, v14, Lt7/n;->t:I

    .line 179
    .line 180
    iget v11, v8, Lx7/m;->f:I

    .line 181
    .line 182
    iput v11, v14, Lt7/n;->u:I

    .line 183
    .line 184
    iget v11, v8, Lx7/m;->p:I

    .line 185
    .line 186
    iget v15, v8, Lx7/m;->q:I

    .line 187
    .line 188
    iget v4, v8, Lx7/m;->r:I

    .line 189
    .line 190
    iget v5, v8, Lx7/m;->h:I

    .line 191
    .line 192
    add-int/lit8 v19, v5, 0x8

    .line 193
    .line 194
    iget v5, v8, Lx7/m;->i:I

    .line 195
    .line 196
    add-int/lit8 v20, v5, 0x8

    .line 197
    .line 198
    move/from16 v17, v15

    .line 199
    .line 200
    new-instance v15, Lt7/f;

    .line 201
    .line 202
    const/16 v21, 0x0

    .line 203
    .line 204
    move/from16 v18, v4

    .line 205
    .line 206
    move/from16 v16, v11

    .line 207
    .line 208
    invoke-direct/range {v15 .. v21}, Lt7/f;-><init>(IIIII[B)V

    .line 209
    .line 210
    .line 211
    iput-object v15, v14, Lt7/n;->C:Lt7/f;

    .line 212
    .line 213
    iget v4, v8, Lx7/m;->g:F

    .line 214
    .line 215
    iput v4, v14, Lt7/n;->z:F

    .line 216
    .line 217
    iput-object v7, v14, Lt7/n;->p:Ljava/util/List;

    .line 218
    .line 219
    iput v9, v14, Lt7/n;->o:I

    .line 220
    .line 221
    invoke-static {v14, v12}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 222
    .line 223
    .line 224
    const/4 v4, 0x1

    .line 225
    iput-boolean v4, v0, Lv9/p;->l:Z

    .line 226
    .line 227
    invoke-virtual {v2, v9}, Lca/j;->m(I)V

    .line 228
    .line 229
    .line 230
    iget-object v4, v0, Lv9/p;->k:Lv9/o;

    .line 231
    .line 232
    iget-object v4, v4, Lv9/o;->d:Landroid/util/SparseArray;

    .line 233
    .line 234
    iget v5, v8, Lx7/m;->d:I

    .line 235
    .line 236
    invoke-virtual {v4, v5, v8}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    iget-object v4, v0, Lv9/p;->k:Lv9/o;

    .line 240
    .line 241
    iget-object v4, v4, Lv9/o;->e:Landroid/util/SparseArray;

    .line 242
    .line 243
    invoke-virtual {v4, v10, v13}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v3}, La8/n0;->g()V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v6}, La8/n0;->g()V

    .line 250
    .line 251
    .line 252
    goto :goto_0

    .line 253
    :cond_1
    iget-boolean v4, v3, La8/n0;->e:Z

    .line 254
    .line 255
    if-eqz v4, :cond_2

    .line 256
    .line 257
    iget-object v4, v3, La8/n0;->f:Ljava/lang/Object;

    .line 258
    .line 259
    check-cast v4, [B

    .line 260
    .line 261
    iget v5, v3, La8/n0;->c:I

    .line 262
    .line 263
    invoke-static {v4, v8, v5}, Lx7/n;->j([BII)Lx7/m;

    .line 264
    .line 265
    .line 266
    move-result-object v4

    .line 267
    iget v5, v4, Lx7/m;->s:I

    .line 268
    .line 269
    invoke-virtual {v2, v5}, Lca/j;->m(I)V

    .line 270
    .line 271
    .line 272
    iget-object v5, v0, Lv9/p;->k:Lv9/o;

    .line 273
    .line 274
    iget-object v5, v5, Lv9/o;->d:Landroid/util/SparseArray;

    .line 275
    .line 276
    iget v6, v4, Lx7/m;->d:I

    .line 277
    .line 278
    invoke-virtual {v5, v6, v4}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v3}, La8/n0;->g()V

    .line 282
    .line 283
    .line 284
    goto :goto_0

    .line 285
    :cond_2
    iget-boolean v3, v6, La8/n0;->e:Z

    .line 286
    .line 287
    if-eqz v3, :cond_3

    .line 288
    .line 289
    iget-object v3, v6, La8/n0;->f:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v3, [B

    .line 292
    .line 293
    iget v4, v6, La8/n0;->c:I

    .line 294
    .line 295
    new-instance v5, Lm9/f;

    .line 296
    .line 297
    const/4 v7, 0x4

    .line 298
    invoke-direct {v5, v3, v7, v4}, Lm9/f;-><init>([BII)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v5}, Lm9/f;->m()I

    .line 302
    .line 303
    .line 304
    move-result v3

    .line 305
    invoke-virtual {v5}, Lm9/f;->m()I

    .line 306
    .line 307
    .line 308
    move-result v4

    .line 309
    invoke-virtual {v5}, Lm9/f;->s()V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v5}, Lm9/f;->h()Z

    .line 313
    .line 314
    .line 315
    move-result v5

    .line 316
    new-instance v7, Lx7/l;

    .line 317
    .line 318
    invoke-direct {v7, v3, v4, v5}, Lx7/l;-><init>(IIZ)V

    .line 319
    .line 320
    .line 321
    iget-object v4, v0, Lv9/p;->k:Lv9/o;

    .line 322
    .line 323
    iget-object v4, v4, Lv9/o;->e:Landroid/util/SparseArray;

    .line 324
    .line 325
    invoke-virtual {v4, v3, v7}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {v6}, La8/n0;->g()V

    .line 329
    .line 330
    .line 331
    :cond_3
    :goto_0
    iget-object v3, v0, Lv9/p;->f:La8/n0;

    .line 332
    .line 333
    invoke-virtual {v3, v1}, La8/n0;->e(I)Z

    .line 334
    .line 335
    .line 336
    move-result v1

    .line 337
    if-eqz v1, :cond_4

    .line 338
    .line 339
    iget-object v1, v3, La8/n0;->f:Ljava/lang/Object;

    .line 340
    .line 341
    check-cast v1, [B

    .line 342
    .line 343
    iget v4, v3, La8/n0;->c:I

    .line 344
    .line 345
    invoke-static {v4, v1}, Lx7/n;->m(I[B)I

    .line 346
    .line 347
    .line 348
    move-result v1

    .line 349
    iget-object v3, v3, La8/n0;->f:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v3, [B

    .line 352
    .line 353
    iget-object v4, v0, Lv9/p;->o:Lw7/p;

    .line 354
    .line 355
    invoke-virtual {v4, v1, v3}, Lw7/p;->G(I[B)V

    .line 356
    .line 357
    .line 358
    const/4 v7, 0x4

    .line 359
    invoke-virtual {v4, v7}, Lw7/p;->I(I)V

    .line 360
    .line 361
    .line 362
    move-wide/from16 v5, p5

    .line 363
    .line 364
    invoke-virtual {v2, v5, v6, v4}, Lca/j;->a(JLw7/p;)V

    .line 365
    .line 366
    .line 367
    :cond_4
    iget-object v1, v0, Lv9/p;->k:Lv9/o;

    .line 368
    .line 369
    iget-boolean v2, v0, Lv9/p;->l:Z

    .line 370
    .line 371
    iget v3, v1, Lv9/o;->i:I

    .line 372
    .line 373
    const/16 v4, 0x9

    .line 374
    .line 375
    const/4 v5, 0x0

    .line 376
    if-eq v3, v4, :cond_b

    .line 377
    .line 378
    iget-boolean v3, v1, Lv9/o;->c:Z

    .line 379
    .line 380
    if-eqz v3, :cond_e

    .line 381
    .line 382
    iget-object v3, v1, Lv9/o;->n:Lv9/n;

    .line 383
    .line 384
    iget-object v4, v1, Lv9/o;->m:Lv9/n;

    .line 385
    .line 386
    iget-boolean v6, v3, Lv9/n;->a:Z

    .line 387
    .line 388
    if-nez v6, :cond_5

    .line 389
    .line 390
    goto/16 :goto_3

    .line 391
    .line 392
    :cond_5
    iget-boolean v6, v4, Lv9/n;->a:Z

    .line 393
    .line 394
    if-nez v6, :cond_6

    .line 395
    .line 396
    goto :goto_1

    .line 397
    :cond_6
    iget-object v6, v3, Lv9/n;->c:Lx7/m;

    .line 398
    .line 399
    invoke-static {v6}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 400
    .line 401
    .line 402
    iget-object v7, v4, Lv9/n;->c:Lx7/m;

    .line 403
    .line 404
    invoke-static {v7}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 405
    .line 406
    .line 407
    iget v7, v7, Lx7/m;->m:I

    .line 408
    .line 409
    iget v8, v3, Lv9/n;->f:I

    .line 410
    .line 411
    iget v9, v4, Lv9/n;->f:I

    .line 412
    .line 413
    if-ne v8, v9, :cond_b

    .line 414
    .line 415
    iget v8, v3, Lv9/n;->g:I

    .line 416
    .line 417
    iget v9, v4, Lv9/n;->g:I

    .line 418
    .line 419
    if-ne v8, v9, :cond_b

    .line 420
    .line 421
    iget-boolean v8, v3, Lv9/n;->h:Z

    .line 422
    .line 423
    iget-boolean v9, v4, Lv9/n;->h:Z

    .line 424
    .line 425
    if-ne v8, v9, :cond_b

    .line 426
    .line 427
    iget-boolean v8, v3, Lv9/n;->i:Z

    .line 428
    .line 429
    if-eqz v8, :cond_7

    .line 430
    .line 431
    iget-boolean v8, v4, Lv9/n;->i:Z

    .line 432
    .line 433
    if-eqz v8, :cond_7

    .line 434
    .line 435
    iget-boolean v8, v3, Lv9/n;->j:Z

    .line 436
    .line 437
    iget-boolean v9, v4, Lv9/n;->j:Z

    .line 438
    .line 439
    if-ne v8, v9, :cond_b

    .line 440
    .line 441
    :cond_7
    iget v8, v3, Lv9/n;->d:I

    .line 442
    .line 443
    iget v9, v4, Lv9/n;->d:I

    .line 444
    .line 445
    if-eq v8, v9, :cond_8

    .line 446
    .line 447
    if-eqz v8, :cond_b

    .line 448
    .line 449
    if-eqz v9, :cond_b

    .line 450
    .line 451
    :cond_8
    iget v6, v6, Lx7/m;->m:I

    .line 452
    .line 453
    if-nez v6, :cond_9

    .line 454
    .line 455
    if-nez v7, :cond_9

    .line 456
    .line 457
    iget v8, v3, Lv9/n;->m:I

    .line 458
    .line 459
    iget v9, v4, Lv9/n;->m:I

    .line 460
    .line 461
    if-ne v8, v9, :cond_b

    .line 462
    .line 463
    iget v8, v3, Lv9/n;->n:I

    .line 464
    .line 465
    iget v9, v4, Lv9/n;->n:I

    .line 466
    .line 467
    if-ne v8, v9, :cond_b

    .line 468
    .line 469
    :cond_9
    const/4 v8, 0x1

    .line 470
    if-ne v6, v8, :cond_a

    .line 471
    .line 472
    if-ne v7, v8, :cond_a

    .line 473
    .line 474
    iget v6, v3, Lv9/n;->o:I

    .line 475
    .line 476
    iget v7, v4, Lv9/n;->o:I

    .line 477
    .line 478
    if-ne v6, v7, :cond_b

    .line 479
    .line 480
    iget v6, v3, Lv9/n;->p:I

    .line 481
    .line 482
    iget v7, v4, Lv9/n;->p:I

    .line 483
    .line 484
    if-ne v6, v7, :cond_b

    .line 485
    .line 486
    :cond_a
    iget-boolean v6, v3, Lv9/n;->k:Z

    .line 487
    .line 488
    iget-boolean v7, v4, Lv9/n;->k:Z

    .line 489
    .line 490
    if-ne v6, v7, :cond_b

    .line 491
    .line 492
    if-eqz v6, :cond_e

    .line 493
    .line 494
    iget v3, v3, Lv9/n;->l:I

    .line 495
    .line 496
    iget v4, v4, Lv9/n;->l:I

    .line 497
    .line 498
    if-eq v3, v4, :cond_e

    .line 499
    .line 500
    :cond_b
    :goto_1
    if-eqz v2, :cond_d

    .line 501
    .line 502
    iget-boolean v2, v1, Lv9/o;->o:Z

    .line 503
    .line 504
    if-eqz v2, :cond_d

    .line 505
    .line 506
    iget-wide v2, v1, Lv9/o;->j:J

    .line 507
    .line 508
    sub-long v6, p1, v2

    .line 509
    .line 510
    long-to-int v4, v6

    .line 511
    add-int v11, p3, v4

    .line 512
    .line 513
    iget-wide v7, v1, Lv9/o;->q:J

    .line 514
    .line 515
    const-wide v9, -0x7fffffffffffffffL    # -4.9E-324

    .line 516
    .line 517
    .line 518
    .line 519
    .line 520
    cmp-long v4, v7, v9

    .line 521
    .line 522
    if-eqz v4, :cond_d

    .line 523
    .line 524
    iget-wide v9, v1, Lv9/o;->p:J

    .line 525
    .line 526
    cmp-long v4, v2, v9

    .line 527
    .line 528
    if-nez v4, :cond_c

    .line 529
    .line 530
    goto :goto_2

    .line 531
    :cond_c
    move-wide v12, v9

    .line 532
    iget-boolean v9, v1, Lv9/o;->r:Z

    .line 533
    .line 534
    sub-long/2addr v2, v12

    .line 535
    long-to-int v10, v2

    .line 536
    iget-object v6, v1, Lv9/o;->a:Lo8/i0;

    .line 537
    .line 538
    const/4 v12, 0x0

    .line 539
    invoke-interface/range {v6 .. v12}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 540
    .line 541
    .line 542
    :cond_d
    :goto_2
    iget-wide v2, v1, Lv9/o;->j:J

    .line 543
    .line 544
    iput-wide v2, v1, Lv9/o;->p:J

    .line 545
    .line 546
    iget-wide v2, v1, Lv9/o;->l:J

    .line 547
    .line 548
    iput-wide v2, v1, Lv9/o;->q:J

    .line 549
    .line 550
    iput-boolean v5, v1, Lv9/o;->r:Z

    .line 551
    .line 552
    const/4 v4, 0x1

    .line 553
    iput-boolean v4, v1, Lv9/o;->o:Z

    .line 554
    .line 555
    :cond_e
    :goto_3
    iget-boolean v2, v1, Lv9/o;->b:Z

    .line 556
    .line 557
    if-eqz v2, :cond_11

    .line 558
    .line 559
    iget-object v2, v1, Lv9/o;->n:Lv9/n;

    .line 560
    .line 561
    iget-boolean v3, v2, Lv9/n;->b:Z

    .line 562
    .line 563
    if-eqz v3, :cond_10

    .line 564
    .line 565
    iget v2, v2, Lv9/n;->e:I

    .line 566
    .line 567
    const/4 v3, 0x7

    .line 568
    if-eq v2, v3, :cond_f

    .line 569
    .line 570
    const/4 v3, 0x2

    .line 571
    if-ne v2, v3, :cond_10

    .line 572
    .line 573
    :cond_f
    const/4 v4, 0x1

    .line 574
    goto :goto_4

    .line 575
    :cond_10
    move v4, v5

    .line 576
    goto :goto_4

    .line 577
    :cond_11
    iget-boolean v4, v1, Lv9/o;->s:Z

    .line 578
    .line 579
    :goto_4
    iget-boolean v2, v1, Lv9/o;->r:Z

    .line 580
    .line 581
    iget v3, v1, Lv9/o;->i:I

    .line 582
    .line 583
    const/4 v6, 0x5

    .line 584
    if-eq v3, v6, :cond_13

    .line 585
    .line 586
    if-eqz v4, :cond_12

    .line 587
    .line 588
    const/4 v4, 0x1

    .line 589
    if-ne v3, v4, :cond_12

    .line 590
    .line 591
    goto :goto_5

    .line 592
    :cond_12
    move v4, v5

    .line 593
    goto :goto_5

    .line 594
    :cond_13
    const/4 v4, 0x1

    .line 595
    :goto_5
    or-int/2addr v2, v4

    .line 596
    iput-boolean v2, v1, Lv9/o;->r:Z

    .line 597
    .line 598
    const/16 v3, 0x18

    .line 599
    .line 600
    iput v3, v1, Lv9/o;->i:I

    .line 601
    .line 602
    if-eqz v2, :cond_14

    .line 603
    .line 604
    iput-boolean v5, v0, Lv9/p;->n:Z

    .line 605
    .line 606
    :cond_14
    return-void
.end method

.method public final b(Lw7/p;)V
    .locals 15

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    iget-object v2, p0, Lv9/p;->j:Lo8/i0;

    .line 4
    .line 5
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget v2, v1, Lw7/p;->b:I

    .line 11
    .line 12
    iget v7, v1, Lw7/p;->c:I

    .line 13
    .line 14
    iget-object v8, v1, Lw7/p;->a:[B

    .line 15
    .line 16
    iget-wide v3, p0, Lv9/p;->g:J

    .line 17
    .line 18
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    int-to-long v5, v5

    .line 23
    add-long/2addr v3, v5

    .line 24
    iput-wide v3, p0, Lv9/p;->g:J

    .line 25
    .line 26
    iget-object v3, p0, Lv9/p;->j:Lo8/i0;

    .line 27
    .line 28
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    const/4 v9, 0x0

    .line 33
    invoke-interface {v3, v1, v4, v9}, Lo8/i0;->a(Lw7/p;II)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iget-object v1, p0, Lv9/p;->h:[Z

    .line 37
    .line 38
    invoke-static {v8, v2, v7, v1}, Lx7/n;->b([BII[Z)I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-ne v1, v7, :cond_0

    .line 43
    .line 44
    invoke-virtual {p0, v8, v2, v7}, Lv9/p;->g([BII)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_0
    add-int/lit8 v3, v1, 0x3

    .line 49
    .line 50
    aget-byte v3, v8, v3

    .line 51
    .line 52
    and-int/lit8 v10, v3, 0x1f

    .line 53
    .line 54
    if-lez v1, :cond_1

    .line 55
    .line 56
    add-int/lit8 v3, v1, -0x1

    .line 57
    .line 58
    aget-byte v3, v8, v3

    .line 59
    .line 60
    if-nez v3, :cond_1

    .line 61
    .line 62
    add-int/lit8 v1, v1, -0x1

    .line 63
    .line 64
    const/4 v3, 0x4

    .line 65
    :goto_1
    move v11, v1

    .line 66
    move v12, v3

    .line 67
    goto :goto_2

    .line 68
    :cond_1
    const/4 v3, 0x3

    .line 69
    goto :goto_1

    .line 70
    :goto_2
    sub-int v1, v11, v2

    .line 71
    .line 72
    if-lez v1, :cond_2

    .line 73
    .line 74
    invoke-virtual {p0, v8, v2, v11}, Lv9/p;->g([BII)V

    .line 75
    .line 76
    .line 77
    :cond_2
    sub-int v3, v7, v11

    .line 78
    .line 79
    iget-wide v4, p0, Lv9/p;->g:J

    .line 80
    .line 81
    int-to-long v13, v3

    .line 82
    sub-long/2addr v4, v13

    .line 83
    if-gez v1, :cond_3

    .line 84
    .line 85
    neg-int v1, v1

    .line 86
    :goto_3
    move-wide v13, v4

    .line 87
    goto :goto_4

    .line 88
    :cond_3
    move v1, v9

    .line 89
    goto :goto_3

    .line 90
    :goto_4
    iget-wide v5, p0, Lv9/p;->m:J

    .line 91
    .line 92
    move-object v0, p0

    .line 93
    move v4, v1

    .line 94
    move-wide v1, v13

    .line 95
    invoke-virtual/range {v0 .. v6}, Lv9/p;->a(JIIJ)V

    .line 96
    .line 97
    .line 98
    iget-wide v4, p0, Lv9/p;->m:J

    .line 99
    .line 100
    move-wide v2, v1

    .line 101
    move v1, v10

    .line 102
    invoke-virtual/range {v0 .. v5}, Lv9/p;->h(IJJ)V

    .line 103
    .line 104
    .line 105
    add-int v2, v11, v12

    .line 106
    .line 107
    goto :goto_0
.end method

.method public final c()V
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lv9/p;->g:J

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lv9/p;->n:Z

    .line 7
    .line 8
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    iput-wide v1, p0, Lv9/p;->m:J

    .line 14
    .line 15
    iget-object v1, p0, Lv9/p;->h:[Z

    .line 16
    .line 17
    invoke-static {v1}, Lx7/n;->a([Z)V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lv9/p;->d:La8/n0;

    .line 21
    .line 22
    invoke-virtual {v1}, La8/n0;->g()V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lv9/p;->e:La8/n0;

    .line 26
    .line 27
    invoke-virtual {v1}, La8/n0;->g()V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Lv9/p;->f:La8/n0;

    .line 31
    .line 32
    invoke-virtual {v1}, La8/n0;->g()V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lv9/p;->a:Lv9/c0;

    .line 36
    .line 37
    iget-object v1, v1, Lv9/c0;->d:Lca/j;

    .line 38
    .line 39
    invoke-virtual {v1, v0}, Lca/j;->d(I)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lv9/p;->k:Lv9/o;

    .line 43
    .line 44
    if-eqz p0, :cond_0

    .line 45
    .line 46
    iput-boolean v0, p0, Lv9/o;->k:Z

    .line 47
    .line 48
    iput-boolean v0, p0, Lv9/o;->o:Z

    .line 49
    .line 50
    iget-object p0, p0, Lv9/o;->n:Lv9/n;

    .line 51
    .line 52
    iput-boolean v0, p0, Lv9/n;->b:Z

    .line 53
    .line 54
    iput-boolean v0, p0, Lv9/n;->a:Z

    .line 55
    .line 56
    :cond_0
    return-void
.end method

.method public final d(Lo8/q;Lh11/h;)V
    .locals 4

    .line 1
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/lang/String;

    .line 10
    .line 11
    iput-object v0, p0, Lv9/p;->i:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 14
    .line 15
    .line 16
    iget v0, p2, Lh11/h;->f:I

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lv9/p;->j:Lo8/i0;

    .line 24
    .line 25
    new-instance v1, Lv9/o;

    .line 26
    .line 27
    iget-boolean v2, p0, Lv9/p;->b:Z

    .line 28
    .line 29
    iget-boolean v3, p0, Lv9/p;->c:Z

    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lv9/o;-><init>(Lo8/i0;ZZ)V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lv9/p;->k:Lv9/o;

    .line 35
    .line 36
    iget-object p0, p0, Lv9/p;->a:Lv9/c0;

    .line 37
    .line 38
    invoke-virtual {p0, p1, p2}, Lv9/c0;->b(Lo8/q;Lh11/h;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public final e(Z)V
    .locals 7

    .line 1
    iget-object v1, p0, Lv9/p;->j:Lo8/i0;

    .line 2
    .line 3
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    iget-object v1, p0, Lv9/p;->a:Lv9/c0;

    .line 11
    .line 12
    iget-object v1, v1, Lv9/c0;->d:Lca/j;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v1, v2}, Lca/j;->d(I)V

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lv9/p;->g:J

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    iget-wide v5, p0, Lv9/p;->m:J

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    move-object v0, p0

    .line 25
    invoke-virtual/range {v0 .. v6}, Lv9/p;->a(JIIJ)V

    .line 26
    .line 27
    .line 28
    iget-wide v2, p0, Lv9/p;->g:J

    .line 29
    .line 30
    const/16 v1, 0x9

    .line 31
    .line 32
    iget-wide v4, p0, Lv9/p;->m:J

    .line 33
    .line 34
    invoke-virtual/range {v0 .. v5}, Lv9/p;->h(IJJ)V

    .line 35
    .line 36
    .line 37
    iget-wide v1, p0, Lv9/p;->g:J

    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    iget-wide v5, p0, Lv9/p;->m:J

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    invoke-virtual/range {v0 .. v6}, Lv9/p;->a(JIIJ)V

    .line 44
    .line 45
    .line 46
    :cond_0
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/p;->m:J

    .line 2
    .line 3
    iget-boolean p2, p0, Lv9/p;->n:Z

    .line 4
    .line 5
    and-int/lit8 p1, p1, 0x2

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 p1, 0x0

    .line 12
    :goto_0
    or-int/2addr p1, p2

    .line 13
    iput-boolean p1, p0, Lv9/p;->n:Z

    .line 14
    .line 15
    return-void
.end method

.method public final g([BII)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    iget-boolean v4, v0, Lv9/p;->l:Z

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    iget-object v4, v0, Lv9/p;->k:Lv9/o;

    .line 14
    .line 15
    iget-boolean v4, v4, Lv9/o;->c:Z

    .line 16
    .line 17
    if-eqz v4, :cond_1

    .line 18
    .line 19
    :cond_0
    iget-object v4, v0, Lv9/p;->d:La8/n0;

    .line 20
    .line 21
    invoke-virtual {v4, v1, v2, v3}, La8/n0;->a([BII)V

    .line 22
    .line 23
    .line 24
    iget-object v4, v0, Lv9/p;->e:La8/n0;

    .line 25
    .line 26
    invoke-virtual {v4, v1, v2, v3}, La8/n0;->a([BII)V

    .line 27
    .line 28
    .line 29
    :cond_1
    iget-object v4, v0, Lv9/p;->f:La8/n0;

    .line 30
    .line 31
    invoke-virtual {v4, v1, v2, v3}, La8/n0;->a([BII)V

    .line 32
    .line 33
    .line 34
    iget-object v0, v0, Lv9/p;->k:Lv9/o;

    .line 35
    .line 36
    iget-object v4, v0, Lv9/o;->e:Landroid/util/SparseArray;

    .line 37
    .line 38
    iget-object v5, v0, Lv9/o;->f:Lm9/f;

    .line 39
    .line 40
    iget-boolean v6, v0, Lv9/o;->k:Z

    .line 41
    .line 42
    if-nez v6, :cond_2

    .line 43
    .line 44
    goto/16 :goto_7

    .line 45
    .line 46
    :cond_2
    sub-int/2addr v3, v2

    .line 47
    iget-object v6, v0, Lv9/o;->g:[B

    .line 48
    .line 49
    array-length v7, v6

    .line 50
    iget v8, v0, Lv9/o;->h:I

    .line 51
    .line 52
    add-int/2addr v8, v3

    .line 53
    const/4 v9, 0x2

    .line 54
    if-ge v7, v8, :cond_3

    .line 55
    .line 56
    mul-int/2addr v8, v9

    .line 57
    invoke-static {v6, v8}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    iput-object v6, v0, Lv9/o;->g:[B

    .line 62
    .line 63
    :cond_3
    iget-object v6, v0, Lv9/o;->g:[B

    .line 64
    .line 65
    iget v7, v0, Lv9/o;->h:I

    .line 66
    .line 67
    invoke-static {v1, v2, v6, v7, v3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 68
    .line 69
    .line 70
    iget v1, v0, Lv9/o;->h:I

    .line 71
    .line 72
    add-int/2addr v1, v3

    .line 73
    iput v1, v0, Lv9/o;->h:I

    .line 74
    .line 75
    iget-object v2, v0, Lv9/o;->g:[B

    .line 76
    .line 77
    iput-object v2, v5, Lm9/f;->b:[B

    .line 78
    .line 79
    const/4 v2, 0x0

    .line 80
    iput v2, v5, Lm9/f;->d:I

    .line 81
    .line 82
    iput v1, v5, Lm9/f;->c:I

    .line 83
    .line 84
    iput v2, v5, Lm9/f;->e:I

    .line 85
    .line 86
    invoke-virtual {v5}, Lm9/f;->a()V

    .line 87
    .line 88
    .line 89
    const/16 v1, 0x8

    .line 90
    .line 91
    invoke-virtual {v5, v1}, Lm9/f;->d(I)Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-nez v1, :cond_4

    .line 96
    .line 97
    goto/16 :goto_7

    .line 98
    .line 99
    :cond_4
    invoke-virtual {v5}, Lm9/f;->s()V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v5, v9}, Lm9/f;->i(I)I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    const/4 v3, 0x5

    .line 107
    invoke-virtual {v5, v3}, Lm9/f;->t(I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    if-nez v6, :cond_5

    .line 115
    .line 116
    goto/16 :goto_7

    .line 117
    .line 118
    :cond_5
    invoke-virtual {v5}, Lm9/f;->m()I

    .line 119
    .line 120
    .line 121
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 122
    .line 123
    .line 124
    move-result v6

    .line 125
    if-nez v6, :cond_6

    .line 126
    .line 127
    goto/16 :goto_7

    .line 128
    .line 129
    :cond_6
    invoke-virtual {v5}, Lm9/f;->m()I

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    iget-boolean v7, v0, Lv9/o;->c:Z

    .line 134
    .line 135
    const/4 v8, 0x1

    .line 136
    if-nez v7, :cond_7

    .line 137
    .line 138
    iput-boolean v2, v0, Lv9/o;->k:Z

    .line 139
    .line 140
    iget-object v0, v0, Lv9/o;->n:Lv9/n;

    .line 141
    .line 142
    iput v6, v0, Lv9/n;->e:I

    .line 143
    .line 144
    iput-boolean v8, v0, Lv9/n;->b:Z

    .line 145
    .line 146
    return-void

    .line 147
    :cond_7
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 148
    .line 149
    .line 150
    move-result v7

    .line 151
    if-nez v7, :cond_8

    .line 152
    .line 153
    goto/16 :goto_7

    .line 154
    .line 155
    :cond_8
    invoke-virtual {v5}, Lm9/f;->m()I

    .line 156
    .line 157
    .line 158
    move-result v7

    .line 159
    invoke-virtual {v4, v7}, Landroid/util/SparseArray;->indexOfKey(I)I

    .line 160
    .line 161
    .line 162
    move-result v10

    .line 163
    if-gez v10, :cond_9

    .line 164
    .line 165
    iput-boolean v2, v0, Lv9/o;->k:Z

    .line 166
    .line 167
    return-void

    .line 168
    :cond_9
    invoke-virtual {v4, v7}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v4

    .line 172
    check-cast v4, Lx7/l;

    .line 173
    .line 174
    iget-object v10, v0, Lv9/o;->d:Landroid/util/SparseArray;

    .line 175
    .line 176
    iget v11, v4, Lx7/l;->a:I

    .line 177
    .line 178
    iget-boolean v4, v4, Lx7/l;->b:Z

    .line 179
    .line 180
    invoke-virtual {v10, v11}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v10

    .line 184
    check-cast v10, Lx7/m;

    .line 185
    .line 186
    iget-boolean v11, v10, Lx7/m;->j:Z

    .line 187
    .line 188
    iget v12, v10, Lx7/m;->n:I

    .line 189
    .line 190
    iget v13, v10, Lx7/m;->l:I

    .line 191
    .line 192
    if-eqz v11, :cond_b

    .line 193
    .line 194
    invoke-virtual {v5, v9}, Lm9/f;->d(I)Z

    .line 195
    .line 196
    .line 197
    move-result v11

    .line 198
    if-nez v11, :cond_a

    .line 199
    .line 200
    goto/16 :goto_7

    .line 201
    .line 202
    :cond_a
    invoke-virtual {v5, v9}, Lm9/f;->t(I)V

    .line 203
    .line 204
    .line 205
    :cond_b
    invoke-virtual {v5, v13}, Lm9/f;->d(I)Z

    .line 206
    .line 207
    .line 208
    move-result v9

    .line 209
    if-nez v9, :cond_c

    .line 210
    .line 211
    goto/16 :goto_7

    .line 212
    .line 213
    :cond_c
    invoke-virtual {v5, v13}, Lm9/f;->i(I)I

    .line 214
    .line 215
    .line 216
    move-result v9

    .line 217
    iget-boolean v11, v10, Lx7/m;->k:Z

    .line 218
    .line 219
    if-nez v11, :cond_10

    .line 220
    .line 221
    invoke-virtual {v5, v8}, Lm9/f;->d(I)Z

    .line 222
    .line 223
    .line 224
    move-result v11

    .line 225
    if-nez v11, :cond_d

    .line 226
    .line 227
    goto/16 :goto_7

    .line 228
    .line 229
    :cond_d
    invoke-virtual {v5}, Lm9/f;->h()Z

    .line 230
    .line 231
    .line 232
    move-result v11

    .line 233
    if-eqz v11, :cond_f

    .line 234
    .line 235
    invoke-virtual {v5, v8}, Lm9/f;->d(I)Z

    .line 236
    .line 237
    .line 238
    move-result v13

    .line 239
    if-nez v13, :cond_e

    .line 240
    .line 241
    goto/16 :goto_7

    .line 242
    .line 243
    :cond_e
    invoke-virtual {v5}, Lm9/f;->h()Z

    .line 244
    .line 245
    .line 246
    move-result v13

    .line 247
    move v14, v8

    .line 248
    goto :goto_1

    .line 249
    :cond_f
    move v13, v2

    .line 250
    :goto_0
    move v14, v13

    .line 251
    goto :goto_1

    .line 252
    :cond_10
    move v11, v2

    .line 253
    move v13, v11

    .line 254
    goto :goto_0

    .line 255
    :goto_1
    iget v15, v0, Lv9/o;->i:I

    .line 256
    .line 257
    if-ne v15, v3, :cond_11

    .line 258
    .line 259
    move v3, v8

    .line 260
    goto :goto_2

    .line 261
    :cond_11
    move v3, v2

    .line 262
    :goto_2
    if-eqz v3, :cond_13

    .line 263
    .line 264
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 265
    .line 266
    .line 267
    move-result v15

    .line 268
    if-nez v15, :cond_12

    .line 269
    .line 270
    goto :goto_7

    .line 271
    :cond_12
    invoke-virtual {v5}, Lm9/f;->m()I

    .line 272
    .line 273
    .line 274
    move-result v15

    .line 275
    goto :goto_3

    .line 276
    :cond_13
    move v15, v2

    .line 277
    :goto_3
    iget v2, v10, Lx7/m;->m:I

    .line 278
    .line 279
    if-nez v2, :cond_17

    .line 280
    .line 281
    invoke-virtual {v5, v12}, Lm9/f;->d(I)Z

    .line 282
    .line 283
    .line 284
    move-result v2

    .line 285
    if-nez v2, :cond_14

    .line 286
    .line 287
    goto :goto_7

    .line 288
    :cond_14
    invoke-virtual {v5, v12}, Lm9/f;->i(I)I

    .line 289
    .line 290
    .line 291
    move-result v2

    .line 292
    if-eqz v4, :cond_16

    .line 293
    .line 294
    if-nez v11, :cond_16

    .line 295
    .line 296
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 297
    .line 298
    .line 299
    move-result v4

    .line 300
    if-nez v4, :cond_15

    .line 301
    .line 302
    goto :goto_7

    .line 303
    :cond_15
    invoke-virtual {v5}, Lm9/f;->n()I

    .line 304
    .line 305
    .line 306
    move-result v4

    .line 307
    move v5, v4

    .line 308
    const/4 v4, 0x0

    .line 309
    :goto_4
    const/4 v12, 0x0

    .line 310
    goto :goto_8

    .line 311
    :cond_16
    :goto_5
    const/4 v4, 0x0

    .line 312
    :goto_6
    const/4 v5, 0x0

    .line 313
    goto :goto_4

    .line 314
    :cond_17
    if-ne v2, v8, :cond_1b

    .line 315
    .line 316
    iget-boolean v2, v10, Lx7/m;->o:Z

    .line 317
    .line 318
    if-nez v2, :cond_1b

    .line 319
    .line 320
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 321
    .line 322
    .line 323
    move-result v2

    .line 324
    if-nez v2, :cond_18

    .line 325
    .line 326
    goto :goto_7

    .line 327
    :cond_18
    invoke-virtual {v5}, Lm9/f;->n()I

    .line 328
    .line 329
    .line 330
    move-result v2

    .line 331
    if-eqz v4, :cond_1a

    .line 332
    .line 333
    if-nez v11, :cond_1a

    .line 334
    .line 335
    invoke-virtual {v5}, Lm9/f;->e()Z

    .line 336
    .line 337
    .line 338
    move-result v4

    .line 339
    if-nez v4, :cond_19

    .line 340
    .line 341
    :goto_7
    return-void

    .line 342
    :cond_19
    invoke-virtual {v5}, Lm9/f;->n()I

    .line 343
    .line 344
    .line 345
    move-result v4

    .line 346
    move v12, v4

    .line 347
    const/4 v5, 0x0

    .line 348
    move v4, v2

    .line 349
    const/4 v2, 0x0

    .line 350
    goto :goto_8

    .line 351
    :cond_1a
    move v4, v2

    .line 352
    const/4 v2, 0x0

    .line 353
    goto :goto_6

    .line 354
    :cond_1b
    const/4 v2, 0x0

    .line 355
    goto :goto_5

    .line 356
    :goto_8
    iget-object v8, v0, Lv9/o;->n:Lv9/n;

    .line 357
    .line 358
    iput-object v10, v8, Lv9/n;->c:Lx7/m;

    .line 359
    .line 360
    iput v1, v8, Lv9/n;->d:I

    .line 361
    .line 362
    iput v6, v8, Lv9/n;->e:I

    .line 363
    .line 364
    iput v9, v8, Lv9/n;->f:I

    .line 365
    .line 366
    iput v7, v8, Lv9/n;->g:I

    .line 367
    .line 368
    iput-boolean v11, v8, Lv9/n;->h:Z

    .line 369
    .line 370
    iput-boolean v14, v8, Lv9/n;->i:Z

    .line 371
    .line 372
    iput-boolean v13, v8, Lv9/n;->j:Z

    .line 373
    .line 374
    iput-boolean v3, v8, Lv9/n;->k:Z

    .line 375
    .line 376
    iput v15, v8, Lv9/n;->l:I

    .line 377
    .line 378
    iput v2, v8, Lv9/n;->m:I

    .line 379
    .line 380
    iput v5, v8, Lv9/n;->n:I

    .line 381
    .line 382
    iput v4, v8, Lv9/n;->o:I

    .line 383
    .line 384
    iput v12, v8, Lv9/n;->p:I

    .line 385
    .line 386
    const/4 v1, 0x1

    .line 387
    iput-boolean v1, v8, Lv9/n;->a:Z

    .line 388
    .line 389
    iput-boolean v1, v8, Lv9/n;->b:Z

    .line 390
    .line 391
    const/4 v1, 0x0

    .line 392
    iput-boolean v1, v0, Lv9/o;->k:Z

    .line 393
    .line 394
    return-void
.end method

.method public final h(IJJ)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv9/p;->l:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lv9/p;->k:Lv9/o;

    .line 6
    .line 7
    iget-boolean v0, v0, Lv9/o;->c:Z

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lv9/p;->d:La8/n0;

    .line 12
    .line 13
    invoke-virtual {v0, p1}, La8/n0;->h(I)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lv9/p;->e:La8/n0;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, La8/n0;->h(I)V

    .line 19
    .line 20
    .line 21
    :cond_1
    iget-object v0, p0, Lv9/p;->f:La8/n0;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, La8/n0;->h(I)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lv9/p;->k:Lv9/o;

    .line 27
    .line 28
    iget-boolean p0, p0, Lv9/p;->n:Z

    .line 29
    .line 30
    iput p1, v0, Lv9/o;->i:I

    .line 31
    .line 32
    iput-wide p4, v0, Lv9/o;->l:J

    .line 33
    .line 34
    iput-wide p2, v0, Lv9/o;->j:J

    .line 35
    .line 36
    iput-boolean p0, v0, Lv9/o;->s:Z

    .line 37
    .line 38
    iget-boolean p0, v0, Lv9/o;->b:Z

    .line 39
    .line 40
    const/4 p2, 0x1

    .line 41
    if-eqz p0, :cond_2

    .line 42
    .line 43
    if-eq p1, p2, :cond_3

    .line 44
    .line 45
    :cond_2
    iget-boolean p0, v0, Lv9/o;->c:Z

    .line 46
    .line 47
    if-eqz p0, :cond_4

    .line 48
    .line 49
    const/4 p0, 0x5

    .line 50
    if-eq p1, p0, :cond_3

    .line 51
    .line 52
    if-eq p1, p2, :cond_3

    .line 53
    .line 54
    const/4 p0, 0x2

    .line 55
    if-ne p1, p0, :cond_4

    .line 56
    .line 57
    :cond_3
    iget-object p0, v0, Lv9/o;->m:Lv9/n;

    .line 58
    .line 59
    iget-object p1, v0, Lv9/o;->n:Lv9/n;

    .line 60
    .line 61
    iput-object p1, v0, Lv9/o;->m:Lv9/n;

    .line 62
    .line 63
    iput-object p0, v0, Lv9/o;->n:Lv9/n;

    .line 64
    .line 65
    const/4 p1, 0x0

    .line 66
    iput-boolean p1, p0, Lv9/n;->b:Z

    .line 67
    .line 68
    iput-boolean p1, p0, Lv9/n;->a:Z

    .line 69
    .line 70
    iput p1, v0, Lv9/o;->h:I

    .line 71
    .line 72
    iput-boolean p2, v0, Lv9/o;->k:Z

    .line 73
    .line 74
    :cond_4
    return-void
.end method
