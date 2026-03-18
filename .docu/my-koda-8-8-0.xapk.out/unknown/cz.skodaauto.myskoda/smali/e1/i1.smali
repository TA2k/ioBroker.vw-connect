.class public final synthetic Le1/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Le1/i1;->d:I

    iput-object p3, p0, Le1/i1;->f:Ljava/lang/Object;

    iput p1, p0, Le1/i1;->e:I

    iput-object p4, p0, Le1/i1;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ll2/b1;I)V
    .locals 1

    .line 2
    const/4 v0, 0x4

    iput v0, p0, Le1/i1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le1/i1;->f:Ljava/lang/Object;

    iput-object p2, p0, Le1/i1;->g:Ljava/lang/Object;

    iput p3, p0, Le1/i1;->e:I

    return-void
.end method

.method public synthetic constructor <init>(Lt1/p1;Lt3/e1;I)V
    .locals 1

    .line 3
    const/4 v0, 0x2

    iput v0, p0, Le1/i1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le1/i1;->f:Ljava/lang/Object;

    iput-object p2, p0, Le1/i1;->g:Ljava/lang/Object;

    iput p3, p0, Le1/i1;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le1/i1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Le1/i1;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/util/List;

    .line 11
    .line 12
    iget-object v2, v0, Le1/i1;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ll2/b1;

    .line 15
    .line 16
    move-object/from16 v3, p1

    .line 17
    .line 18
    check-cast v3, Lm1/f;

    .line 19
    .line 20
    const-string v4, "$this$LazyRow"

    .line 21
    .line 22
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    new-instance v5, Lxk0/o;

    .line 30
    .line 31
    iget v0, v0, Le1/i1;->e:I

    .line 32
    .line 33
    invoke-direct {v5, v1, v2, v0}, Lxk0/o;-><init>(Ljava/util/List;Ll2/b1;I)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Lt2/b;

    .line 37
    .line 38
    const/4 v1, 0x1

    .line 39
    const v2, -0x169b5448

    .line 40
    .line 41
    .line 42
    invoke-direct {v0, v5, v1, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 43
    .line 44
    .line 45
    invoke-static {v3, v4, v0}, Lm1/f;->q(Lm1/f;ILt2/b;)V

    .line 46
    .line 47
    .line 48
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object v0

    .line 51
    :pswitch_0
    iget-object v1, v0, Le1/i1;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v1, Ljava/util/List;

    .line 54
    .line 55
    iget-object v2, v0, Le1/i1;->g:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v2, Lay0/k;

    .line 58
    .line 59
    move-object/from16 v3, p1

    .line 60
    .line 61
    check-cast v3, Lm1/f;

    .line 62
    .line 63
    const-string v4, "$this$LazyColumn"

    .line 64
    .line 65
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    sget-object v4, Lx80/a;->a:Lt2/b;

    .line 69
    .line 70
    const/4 v5, 0x3

    .line 71
    invoke-static {v3, v4, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 72
    .line 73
    .line 74
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    new-instance v5, Lnu0/c;

    .line 79
    .line 80
    const/4 v6, 0x7

    .line 81
    invoke-direct {v5, v1, v6}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 82
    .line 83
    .line 84
    new-instance v6, Li40/h2;

    .line 85
    .line 86
    const/4 v7, 0x1

    .line 87
    iget v0, v0, Le1/i1;->e:I

    .line 88
    .line 89
    invoke-direct {v6, v0, v7, v2, v1}, Li40/h2;-><init>(IILay0/k;Ljava/util/List;)V

    .line 90
    .line 91
    .line 92
    new-instance v0, Lt2/b;

    .line 93
    .line 94
    const/4 v1, 0x1

    .line 95
    const v2, 0x799532c4

    .line 96
    .line 97
    .line 98
    invoke-direct {v0, v6, v1, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 99
    .line 100
    .line 101
    const/4 v1, 0x0

    .line 102
    invoke-virtual {v3, v4, v1, v5, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :pswitch_1
    iget-object v1, v0, Le1/i1;->f:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v1, Lt1/p1;

    .line 109
    .line 110
    iget-object v2, v0, Le1/i1;->g:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v2, Lt3/e1;

    .line 113
    .line 114
    move-object/from16 v3, p1

    .line 115
    .line 116
    check-cast v3, Lt3/d1;

    .line 117
    .line 118
    iget v4, v1, Lt1/p1;->c:I

    .line 119
    .line 120
    iget-object v9, v1, Lt1/p1;->b:Lt1/h1;

    .line 121
    .line 122
    iget-object v5, v1, Lt1/p1;->d:Ll4/b0;

    .line 123
    .line 124
    iget-object v1, v1, Lt1/p1;->e:Lay0/a;

    .line 125
    .line 126
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    check-cast v1, Lt1/j1;

    .line 131
    .line 132
    if-eqz v1, :cond_0

    .line 133
    .line 134
    iget-object v1, v1, Lt1/j1;->a:Lg4/l0;

    .line 135
    .line 136
    :goto_1
    move-object v6, v1

    .line 137
    goto :goto_2

    .line 138
    :cond_0
    const/4 v1, 0x0

    .line 139
    goto :goto_1

    .line 140
    :goto_2
    const/4 v7, 0x0

    .line 141
    iget v8, v2, Lt3/e1;->d:I

    .line 142
    .line 143
    invoke-static/range {v3 .. v8}, Lt1/l0;->l(Lt3/d1;ILl4/b0;Lg4/l0;ZI)Ld3/c;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 148
    .line 149
    iget v5, v2, Lt3/e1;->e:I

    .line 150
    .line 151
    iget v0, v0, Le1/i1;->e:I

    .line 152
    .line 153
    invoke-virtual {v9, v4, v1, v0, v5}, Lt1/h1;->a(Lg1/w1;Ld3/c;II)V

    .line 154
    .line 155
    .line 156
    iget-object v0, v9, Lt1/h1;->a:Ll2/f1;

    .line 157
    .line 158
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    neg-float v0, v0

    .line 163
    const/4 v1, 0x0

    .line 164
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    invoke-static {v3, v2, v1, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 169
    .line 170
    .line 171
    goto :goto_0

    .line 172
    :pswitch_2
    iget-object v1, v0, Le1/i1;->f:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v1, Ll2/u1;

    .line 175
    .line 176
    iget-object v2, v0, Le1/i1;->g:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v2, Landroidx/collection/h0;

    .line 179
    .line 180
    move-object/from16 v3, p1

    .line 181
    .line 182
    check-cast v3, Ll2/w;

    .line 183
    .line 184
    iget v4, v1, Ll2/u1;->e:I

    .line 185
    .line 186
    iget v0, v0, Le1/i1;->e:I

    .line 187
    .line 188
    if-ne v4, v0, :cond_9

    .line 189
    .line 190
    iget-object v4, v1, Ll2/u1;->f:Landroidx/collection/h0;

    .line 191
    .line 192
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result v4

    .line 196
    if-eqz v4, :cond_9

    .line 197
    .line 198
    instance-of v4, v3, Ll2/a0;

    .line 199
    .line 200
    if-eqz v4, :cond_9

    .line 201
    .line 202
    iget-object v4, v2, Landroidx/collection/h0;->a:[J

    .line 203
    .line 204
    array-length v5, v4

    .line 205
    add-int/lit8 v5, v5, -0x2

    .line 206
    .line 207
    if-ltz v5, :cond_9

    .line 208
    .line 209
    const/4 v7, 0x0

    .line 210
    :goto_3
    aget-wide v8, v4, v7

    .line 211
    .line 212
    not-long v10, v8

    .line 213
    const/4 v12, 0x7

    .line 214
    shl-long/2addr v10, v12

    .line 215
    and-long/2addr v10, v8

    .line 216
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 217
    .line 218
    .line 219
    .line 220
    .line 221
    and-long/2addr v10, v12

    .line 222
    cmp-long v10, v10, v12

    .line 223
    .line 224
    if-eqz v10, :cond_8

    .line 225
    .line 226
    sub-int v10, v7, v5

    .line 227
    .line 228
    not-int v10, v10

    .line 229
    ushr-int/lit8 v10, v10, 0x1f

    .line 230
    .line 231
    const/16 v11, 0x8

    .line 232
    .line 233
    rsub-int/lit8 v10, v10, 0x8

    .line 234
    .line 235
    const/4 v12, 0x0

    .line 236
    :goto_4
    if-ge v12, v10, :cond_7

    .line 237
    .line 238
    const-wide/16 v13, 0xff

    .line 239
    .line 240
    and-long/2addr v13, v8

    .line 241
    const-wide/16 v15, 0x80

    .line 242
    .line 243
    cmp-long v13, v13, v15

    .line 244
    .line 245
    if-gez v13, :cond_5

    .line 246
    .line 247
    shl-int/lit8 v13, v7, 0x3

    .line 248
    .line 249
    add-int/2addr v13, v12

    .line 250
    iget-object v14, v2, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 251
    .line 252
    aget-object v14, v14, v13

    .line 253
    .line 254
    iget-object v15, v2, Landroidx/collection/h0;->c:[I

    .line 255
    .line 256
    aget v15, v15, v13

    .line 257
    .line 258
    if-eq v15, v0, :cond_1

    .line 259
    .line 260
    const/4 v15, 0x1

    .line 261
    goto :goto_5

    .line 262
    :cond_1
    const/4 v15, 0x0

    .line 263
    :goto_5
    if-eqz v15, :cond_3

    .line 264
    .line 265
    move-object v6, v3

    .line 266
    check-cast v6, Ll2/a0;

    .line 267
    .line 268
    move/from16 p1, v11

    .line 269
    .line 270
    iget-object v11, v6, Ll2/a0;->j:Landroidx/collection/q0;

    .line 271
    .line 272
    invoke-static {v11, v14, v1}, Ljp/v1;->i(Landroidx/collection/q0;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move/from16 v16, v0

    .line 276
    .line 277
    instance-of v0, v14, Ll2/h0;

    .line 278
    .line 279
    if-eqz v0, :cond_4

    .line 280
    .line 281
    move-object v0, v14

    .line 282
    check-cast v0, Ll2/h0;

    .line 283
    .line 284
    invoke-virtual {v11, v0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v11

    .line 288
    if-nez v11, :cond_2

    .line 289
    .line 290
    iget-object v6, v6, Ll2/a0;->m:Landroidx/collection/q0;

    .line 291
    .line 292
    invoke-static {v6, v0}, Ljp/v1;->j(Landroidx/collection/q0;Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    :cond_2
    iget-object v0, v1, Ll2/u1;->g:Landroidx/collection/q0;

    .line 296
    .line 297
    if-eqz v0, :cond_4

    .line 298
    .line 299
    invoke-virtual {v0, v14}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_3
    move/from16 v16, v0

    .line 304
    .line 305
    move/from16 p1, v11

    .line 306
    .line 307
    :cond_4
    :goto_6
    if-eqz v15, :cond_6

    .line 308
    .line 309
    invoke-virtual {v2, v13}, Landroidx/collection/h0;->g(I)V

    .line 310
    .line 311
    .line 312
    goto :goto_7

    .line 313
    :cond_5
    move/from16 v16, v0

    .line 314
    .line 315
    move/from16 p1, v11

    .line 316
    .line 317
    :cond_6
    :goto_7
    shr-long v8, v8, p1

    .line 318
    .line 319
    add-int/lit8 v12, v12, 0x1

    .line 320
    .line 321
    move/from16 v11, p1

    .line 322
    .line 323
    move/from16 v0, v16

    .line 324
    .line 325
    goto :goto_4

    .line 326
    :cond_7
    move/from16 v16, v0

    .line 327
    .line 328
    move v0, v11

    .line 329
    if-ne v10, v0, :cond_9

    .line 330
    .line 331
    goto :goto_8

    .line 332
    :cond_8
    move/from16 v16, v0

    .line 333
    .line 334
    :goto_8
    if-eq v7, v5, :cond_9

    .line 335
    .line 336
    add-int/lit8 v7, v7, 0x1

    .line 337
    .line 338
    move/from16 v0, v16

    .line 339
    .line 340
    goto/16 :goto_3

    .line 341
    .line 342
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 343
    .line 344
    return-object v0

    .line 345
    :pswitch_3
    iget-object v1, v0, Le1/i1;->f:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v1, Le1/k1;

    .line 348
    .line 349
    iget-object v2, v0, Le1/i1;->g:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v2, Lt3/e1;

    .line 352
    .line 353
    move-object/from16 v3, p1

    .line 354
    .line 355
    check-cast v3, Lt3/d1;

    .line 356
    .line 357
    iget-object v4, v1, Le1/k1;->r:Le1/n1;

    .line 358
    .line 359
    iget-object v4, v4, Le1/n1;->a:Ll2/g1;

    .line 360
    .line 361
    invoke-virtual {v4}, Ll2/g1;->o()I

    .line 362
    .line 363
    .line 364
    move-result v4

    .line 365
    const/4 v5, 0x0

    .line 366
    if-gez v4, :cond_a

    .line 367
    .line 368
    move v4, v5

    .line 369
    :cond_a
    iget v0, v0, Le1/i1;->e:I

    .line 370
    .line 371
    if-le v4, v0, :cond_b

    .line 372
    .line 373
    move v4, v0

    .line 374
    :cond_b
    iget-boolean v6, v1, Le1/k1;->s:Z

    .line 375
    .line 376
    if-eqz v6, :cond_c

    .line 377
    .line 378
    sub-int/2addr v4, v0

    .line 379
    goto :goto_9

    .line 380
    :cond_c
    neg-int v4, v4

    .line 381
    :goto_9
    iget-boolean v0, v1, Le1/k1;->t:Z

    .line 382
    .line 383
    if-eqz v0, :cond_d

    .line 384
    .line 385
    move v1, v5

    .line 386
    goto :goto_a

    .line 387
    :cond_d
    move v1, v4

    .line 388
    :goto_a
    if-eqz v0, :cond_e

    .line 389
    .line 390
    goto :goto_b

    .line 391
    :cond_e
    move v4, v5

    .line 392
    :goto_b
    const/4 v0, 0x1

    .line 393
    iput-boolean v0, v3, Lt3/d1;->d:Z

    .line 394
    .line 395
    invoke-static {v3, v2, v1, v4}, Lt3/d1;->p(Lt3/d1;Lt3/e1;II)V

    .line 396
    .line 397
    .line 398
    iput-boolean v5, v3, Lt3/d1;->d:Z

    .line 399
    .line 400
    goto/16 :goto_0

    .line 401
    .line 402
    nop

    .line 403
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
