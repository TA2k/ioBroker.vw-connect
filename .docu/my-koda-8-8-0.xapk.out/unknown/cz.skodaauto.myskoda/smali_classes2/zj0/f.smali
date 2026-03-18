.class public final synthetic Lzj0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lxj0/j;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Lxj0/j;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lzj0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lzj0/f;->e:Ljava/util/List;

    iput-object p2, p0, Lzj0/f;->f:Lxj0/j;

    iput-object p3, p0, Lzj0/f;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lxj0/j;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Lzj0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lzj0/f;->e:Ljava/util/List;

    iput-object p2, p0, Lzj0/f;->f:Lxj0/j;

    iput-object p3, p0, Lzj0/f;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lzj0/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v3, v0, Lzj0/f;->e:Ljava/util/List;

    .line 25
    .line 26
    iget-object v4, v0, Lzj0/f;->f:Lxj0/j;

    .line 27
    .line 28
    iget-object v0, v0, Lzj0/f;->g:Lay0/k;

    .line 29
    .line 30
    invoke-static {v3, v4, v0, v1, v2}, Lzj0/j;->k(Ljava/util/List;Lxj0/j;Lay0/k;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_0
    move-object/from16 v1, p1

    .line 37
    .line 38
    check-cast v1, Ll2/o;

    .line 39
    .line 40
    move-object/from16 v2, p2

    .line 41
    .line 42
    check-cast v2, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    and-int/lit8 v3, v2, 0x3

    .line 49
    .line 50
    const/4 v4, 0x2

    .line 51
    const/4 v5, 0x0

    .line 52
    const/4 v6, 0x1

    .line 53
    if-eq v3, v4, :cond_0

    .line 54
    .line 55
    move v3, v6

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    move v3, v5

    .line 58
    :goto_0
    and-int/2addr v2, v6

    .line 59
    check-cast v1, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_d

    .line 66
    .line 67
    iget-object v2, v0, Lzj0/f;->e:Ljava/util/List;

    .line 68
    .line 69
    check-cast v2, Ljava/lang/Iterable;

    .line 70
    .line 71
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_e

    .line 80
    .line 81
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    check-cast v3, Lxj0/s;

    .line 86
    .line 87
    const-string v4, "<this>"

    .line 88
    .line 89
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    iget-boolean v4, v3, Lxj0/s;->d:Z

    .line 93
    .line 94
    iget-boolean v7, v3, Lxj0/s;->c:Z

    .line 95
    .line 96
    const-string v8, "mapTileType"

    .line 97
    .line 98
    iget-object v9, v0, Lzj0/f;->f:Lxj0/j;

    .line 99
    .line 100
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 104
    .line 105
    .line 106
    move-result v8

    .line 107
    if-eqz v8, :cond_4

    .line 108
    .line 109
    if-ne v8, v6, :cond_3

    .line 110
    .line 111
    const v8, -0x56f117e5

    .line 112
    .line 113
    .line 114
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    if-eqz v7, :cond_1

    .line 118
    .line 119
    const v8, -0x3967530f

    .line 120
    .line 121
    .line 122
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 123
    .line 124
    .line 125
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 126
    .line 127
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v8

    .line 131
    check-cast v8, Lj91/e;

    .line 132
    .line 133
    invoke-virtual {v8}, Lj91/e;->e()J

    .line 134
    .line 135
    .line 136
    move-result-wide v10

    .line 137
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 138
    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_1
    if-nez v4, :cond_2

    .line 142
    .line 143
    const v8, -0x39674d8a

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 150
    .line 151
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v8

    .line 155
    check-cast v8, Lj91/e;

    .line 156
    .line 157
    invoke-virtual {v8}, Lj91/e;->k()J

    .line 158
    .line 159
    .line 160
    move-result-wide v10

    .line 161
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 162
    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_2
    const v8, -0x396747b0

    .line 166
    .line 167
    .line 168
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 169
    .line 170
    .line 171
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 172
    .line 173
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v8

    .line 177
    check-cast v8, Lj91/e;

    .line 178
    .line 179
    invoke-virtual {v8}, Lj91/e;->q()J

    .line 180
    .line 181
    .line 182
    move-result-wide v10

    .line 183
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    :goto_2
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 187
    .line 188
    .line 189
    :goto_3
    move-wide v12, v10

    .line 190
    goto :goto_6

    .line 191
    :cond_3
    const v0, -0x56f125eb

    .line 192
    .line 193
    .line 194
    invoke-static {v0, v1, v5}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    throw v0

    .line 199
    :cond_4
    const v8, -0x56f12015

    .line 200
    .line 201
    .line 202
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 203
    .line 204
    .line 205
    if-eqz v7, :cond_5

    .line 206
    .line 207
    const v8, 0x4c0521b9    # 3.4899684E7f

    .line 208
    .line 209
    .line 210
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 211
    .line 212
    .line 213
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 214
    .line 215
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v8

    .line 219
    check-cast v8, Lj91/e;

    .line 220
    .line 221
    invoke-virtual {v8}, Lj91/e;->e()J

    .line 222
    .line 223
    .line 224
    move-result-wide v10

    .line 225
    :goto_4
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 226
    .line 227
    .line 228
    goto :goto_5

    .line 229
    :cond_5
    const v8, 0x4c05261e    # 3.4904184E7f

    .line 230
    .line 231
    .line 232
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 233
    .line 234
    .line 235
    sget-object v8, Lj91/h;->a:Ll2/u2;

    .line 236
    .line 237
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    check-cast v8, Lj91/e;

    .line 242
    .line 243
    invoke-virtual {v8}, Lj91/e;->k()J

    .line 244
    .line 245
    .line 246
    move-result-wide v10

    .line 247
    goto :goto_4

    .line 248
    :goto_5
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 249
    .line 250
    .line 251
    goto :goto_3

    .line 252
    :goto_6
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 253
    .line 254
    .line 255
    move-result v8

    .line 256
    if-eqz v8, :cond_8

    .line 257
    .line 258
    if-ne v8, v6, :cond_7

    .line 259
    .line 260
    const v8, -0x56f10039

    .line 261
    .line 262
    .line 263
    invoke-virtual {v1, v8}, Ll2/t;->Y(I)V

    .line 264
    .line 265
    .line 266
    if-eqz v4, :cond_6

    .line 267
    .line 268
    if-eqz v7, :cond_6

    .line 269
    .line 270
    const v7, 0x3f4ccccd    # 0.8f

    .line 271
    .line 272
    .line 273
    invoke-static {v12, v13, v7}, Le3/s;->b(JF)J

    .line 274
    .line 275
    .line 276
    move-result-wide v7

    .line 277
    goto :goto_7

    .line 278
    :cond_6
    const v7, 0x3f19999a    # 0.6f

    .line 279
    .line 280
    .line 281
    invoke-static {v12, v13, v7}, Le3/s;->b(JF)J

    .line 282
    .line 283
    .line 284
    move-result-wide v7

    .line 285
    :goto_7
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 286
    .line 287
    .line 288
    :goto_8
    move-wide v9, v7

    .line 289
    goto :goto_9

    .line 290
    :cond_7
    const v0, -0x56f10e20

    .line 291
    .line 292
    .line 293
    invoke-static {v0, v1, v5}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 294
    .line 295
    .line 296
    move-result-object v0

    .line 297
    throw v0

    .line 298
    :cond_8
    const v7, -0x56f106e2

    .line 299
    .line 300
    .line 301
    invoke-virtual {v1, v7}, Ll2/t;->Y(I)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    const v7, 0x3ecccccd    # 0.4f

    .line 308
    .line 309
    .line 310
    invoke-static {v12, v13, v7}, Le3/s;->b(JF)J

    .line 311
    .line 312
    .line 313
    move-result-wide v7

    .line 314
    goto :goto_8

    .line 315
    :goto_9
    new-instance v7, Le3/s;

    .line 316
    .line 317
    new-instance v7, Le3/s;

    .line 318
    .line 319
    iget-object v7, v3, Lxj0/s;->b:Ljava/util/List;

    .line 320
    .line 321
    check-cast v7, Ljava/lang/Iterable;

    .line 322
    .line 323
    new-instance v8, Ljava/util/ArrayList;

    .line 324
    .line 325
    const/16 v11, 0xa

    .line 326
    .line 327
    invoke-static {v7, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 328
    .line 329
    .line 330
    move-result v11

    .line 331
    invoke-direct {v8, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 332
    .line 333
    .line 334
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 335
    .line 336
    .line 337
    move-result-object v7

    .line 338
    :goto_a
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 339
    .line 340
    .line 341
    move-result v11

    .line 342
    if-eqz v11, :cond_9

    .line 343
    .line 344
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v11

    .line 348
    check-cast v11, Lxj0/f;

    .line 349
    .line 350
    invoke-static {v11}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 351
    .line 352
    .line 353
    move-result-object v11

    .line 354
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 355
    .line 356
    .line 357
    goto :goto_a

    .line 358
    :cond_9
    int-to-float v7, v6

    .line 359
    invoke-static {v7}, Lxf0/i0;->O(F)I

    .line 360
    .line 361
    .line 362
    move-result v7

    .line 363
    int-to-float v14, v7

    .line 364
    if-eqz v4, :cond_a

    .line 365
    .line 366
    const/high16 v4, 0x3f800000    # 1.0f

    .line 367
    .line 368
    :goto_b
    move/from16 v16, v4

    .line 369
    .line 370
    goto :goto_c

    .line 371
    :cond_a
    const/4 v4, 0x0

    .line 372
    goto :goto_b

    .line 373
    :goto_c
    iget-object v4, v0, Lzj0/f;->g:Lay0/k;

    .line 374
    .line 375
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 376
    .line 377
    .line 378
    move-result v7

    .line 379
    invoke-virtual {v1, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 380
    .line 381
    .line 382
    move-result v11

    .line 383
    or-int/2addr v7, v11

    .line 384
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v11

    .line 388
    if-nez v7, :cond_b

    .line 389
    .line 390
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 391
    .line 392
    if-ne v11, v7, :cond_c

    .line 393
    .line 394
    :cond_b
    new-instance v11, Lxh/e;

    .line 395
    .line 396
    invoke-direct {v11, v4, v3}, Lxh/e;-><init>(Lay0/k;Lxj0/s;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v1, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 400
    .line 401
    .line 402
    :cond_c
    move-object/from16 v17, v11

    .line 403
    .line 404
    check-cast v17, Lay0/k;

    .line 405
    .line 406
    const/16 v19, 0x30

    .line 407
    .line 408
    move-object v7, v8

    .line 409
    const/4 v8, 0x1

    .line 410
    const/4 v11, 0x0

    .line 411
    const/4 v15, 0x0

    .line 412
    move-object/from16 v18, v1

    .line 413
    .line 414
    invoke-static/range {v7 .. v19}, Llp/ja;->a(Ljava/util/ArrayList;ZJLjava/util/List;JFZFLay0/k;Ll2/o;I)V

    .line 415
    .line 416
    .line 417
    goto/16 :goto_1

    .line 418
    .line 419
    :cond_d
    move-object/from16 v18, v1

    .line 420
    .line 421
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 422
    .line 423
    .line 424
    :cond_e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 425
    .line 426
    return-object v0

    .line 427
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
