.class public final Laa/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p6, p0, Laa/k0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laa/k0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Laa/k0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Laa/k0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Laa/k0;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Laa/k0;->i:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Laa/k0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move-object/from16 v3, p3

    .line 21
    .line 22
    check-cast v3, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v4, p4

    .line 25
    .line 26
    check-cast v4, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    iget-object v5, v0, Laa/k0;->i:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v5, Lay0/k;

    .line 35
    .line 36
    iget-object v6, v0, Laa/k0;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v6, Lxf0/d2;

    .line 39
    .line 40
    iget-object v7, v0, Laa/k0;->g:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v7, Lvy0/b0;

    .line 43
    .line 44
    and-int/lit8 v8, v4, 0x6

    .line 45
    .line 46
    const/4 v9, 0x2

    .line 47
    if-nez v8, :cond_1

    .line 48
    .line 49
    move-object v8, v3

    .line 50
    check-cast v8, Ll2/t;

    .line 51
    .line 52
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_0

    .line 57
    .line 58
    const/4 v1, 0x4

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    move v1, v9

    .line 61
    :goto_0
    or-int/2addr v1, v4

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    move v1, v4

    .line 64
    :goto_1
    and-int/lit8 v4, v4, 0x30

    .line 65
    .line 66
    const/16 v8, 0x20

    .line 67
    .line 68
    if-nez v4, :cond_3

    .line 69
    .line 70
    move-object v4, v3

    .line 71
    check-cast v4, Ll2/t;

    .line 72
    .line 73
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_2

    .line 78
    .line 79
    move v4, v8

    .line 80
    goto :goto_2

    .line 81
    :cond_2
    const/16 v4, 0x10

    .line 82
    .line 83
    :goto_2
    or-int/2addr v1, v4

    .line 84
    :cond_3
    and-int/lit16 v4, v1, 0x93

    .line 85
    .line 86
    const/16 v10, 0x92

    .line 87
    .line 88
    const/4 v11, 0x1

    .line 89
    const/4 v12, 0x0

    .line 90
    if-eq v4, v10, :cond_4

    .line 91
    .line 92
    move v4, v11

    .line 93
    goto :goto_3

    .line 94
    :cond_4
    move v4, v12

    .line 95
    :goto_3
    and-int/lit8 v10, v1, 0x1

    .line 96
    .line 97
    check-cast v3, Ll2/t;

    .line 98
    .line 99
    invoke-virtual {v3, v10, v4}, Ll2/t;->O(IZ)Z

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    if-eqz v4, :cond_c

    .line 104
    .line 105
    iget-object v4, v0, Laa/k0;->e:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v4, Ljava/util/List;

    .line 108
    .line 109
    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    check-cast v4, Lf90/a;

    .line 114
    .line 115
    const v10, -0x9ac7a57

    .line 116
    .line 117
    .line 118
    invoke-virtual {v3, v10}, Ll2/t;->Y(I)V

    .line 119
    .line 120
    .line 121
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 122
    .line 123
    if-lez v2, :cond_5

    .line 124
    .line 125
    const v13, -0x9aca89a

    .line 126
    .line 127
    .line 128
    invoke-virtual {v3, v13}, Ll2/t;->Y(I)V

    .line 129
    .line 130
    .line 131
    sget-object v13, Lj91/a;->a:Ll2/u2;

    .line 132
    .line 133
    invoke-virtual {v3, v13}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v13

    .line 137
    check-cast v13, Lj91/c;

    .line 138
    .line 139
    iget v13, v13, Lj91/c;->k:F

    .line 140
    .line 141
    const/4 v14, 0x0

    .line 142
    invoke-static {v10, v13, v14, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object v9

    .line 146
    invoke-static {v12, v12, v3, v9}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 147
    .line 148
    .line 149
    :goto_4
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 150
    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_5
    const v9, -0x9cb3669

    .line 154
    .line 155
    .line 156
    invoke-virtual {v3, v9}, Ll2/t;->Y(I)V

    .line 157
    .line 158
    .line 159
    goto :goto_4

    .line 160
    :goto_5
    iget-object v13, v4, Lf90/a;->a:Ljava/lang/String;

    .line 161
    .line 162
    iget-boolean v9, v4, Lf90/a;->b:Z

    .line 163
    .line 164
    if-eqz v9, :cond_6

    .line 165
    .line 166
    new-instance v9, Li91/p1;

    .line 167
    .line 168
    const v14, 0x7f080321

    .line 169
    .line 170
    .line 171
    invoke-direct {v9, v14}, Li91/p1;-><init>(I)V

    .line 172
    .line 173
    .line 174
    :goto_6
    move-object/from16 v17, v9

    .line 175
    .line 176
    goto :goto_7

    .line 177
    :cond_6
    const/4 v9, 0x0

    .line 178
    goto :goto_6

    .line 179
    :goto_7
    iget-object v4, v4, Lf90/a;->c:Ljava/lang/String;

    .line 180
    .line 181
    invoke-static {v10, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 182
    .line 183
    .line 184
    move-result-object v14

    .line 185
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 186
    .line 187
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v4

    .line 191
    check-cast v4, Lj91/c;

    .line 192
    .line 193
    iget v4, v4, Lj91/c;->k:F

    .line 194
    .line 195
    iget-object v0, v0, Laa/k0;->f:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v0, Ljava/lang/String;

    .line 198
    .line 199
    const-string v9, "_item"

    .line 200
    .line 201
    invoke-static {v0, v9}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v22

    .line 205
    invoke-virtual {v3, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v0

    .line 209
    invoke-virtual {v3, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result v9

    .line 213
    or-int/2addr v0, v9

    .line 214
    invoke-virtual {v3, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v9

    .line 218
    or-int/2addr v0, v9

    .line 219
    and-int/lit8 v9, v1, 0x70

    .line 220
    .line 221
    xor-int/lit8 v9, v9, 0x30

    .line 222
    .line 223
    if-le v9, v8, :cond_7

    .line 224
    .line 225
    invoke-virtual {v3, v2}, Ll2/t;->e(I)Z

    .line 226
    .line 227
    .line 228
    move-result v9

    .line 229
    if-nez v9, :cond_9

    .line 230
    .line 231
    :cond_7
    and-int/lit8 v1, v1, 0x30

    .line 232
    .line 233
    if-ne v1, v8, :cond_8

    .line 234
    .line 235
    goto :goto_8

    .line 236
    :cond_8
    move v11, v12

    .line 237
    :cond_9
    :goto_8
    or-int/2addr v0, v11

    .line 238
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    if-nez v0, :cond_a

    .line 243
    .line 244
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 245
    .line 246
    if-ne v1, v0, :cond_b

    .line 247
    .line 248
    :cond_a
    new-instance v1, Lh90/c;

    .line 249
    .line 250
    invoke-direct {v1, v7, v6, v5, v2}, Lh90/c;-><init>(Lvy0/b0;Lxf0/d2;Lay0/k;I)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    :cond_b
    move-object/from16 v20, v1

    .line 257
    .line 258
    check-cast v20, Lay0/a;

    .line 259
    .line 260
    const/16 v25, 0x0

    .line 261
    .line 262
    const/16 v26, 0x66c

    .line 263
    .line 264
    const/4 v15, 0x0

    .line 265
    const/16 v16, 0x0

    .line 266
    .line 267
    const/16 v18, 0x0

    .line 268
    .line 269
    const/16 v19, 0x0

    .line 270
    .line 271
    const/16 v24, 0x0

    .line 272
    .line 273
    move-object/from16 v23, v3

    .line 274
    .line 275
    move/from16 v21, v4

    .line 276
    .line 277
    invoke-static/range {v13 .. v26}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 281
    .line 282
    .line 283
    goto :goto_9

    .line 284
    :cond_c
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 288
    .line 289
    return-object v0

    .line 290
    :pswitch_0
    move-object/from16 v1, p1

    .line 291
    .line 292
    check-cast v1, Lb1/n;

    .line 293
    .line 294
    move-object/from16 v2, p2

    .line 295
    .line 296
    check-cast v2, Lz9/k;

    .line 297
    .line 298
    move-object/from16 v3, p3

    .line 299
    .line 300
    check-cast v3, Ll2/o;

    .line 301
    .line 302
    move-object/from16 v4, p4

    .line 303
    .line 304
    check-cast v4, Ljava/lang/Number;

    .line 305
    .line 306
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 307
    .line 308
    .line 309
    iget-object v4, v0, Laa/k0;->e:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v4, Lc1/c1;

    .line 312
    .line 313
    iget-object v4, v4, Lc1/c1;->g:Ll2/j1;

    .line 314
    .line 315
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object v4

    .line 319
    iget-object v5, v0, Laa/k0;->f:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v5, Lz9/k;

    .line 322
    .line 323
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    move-result v4

    .line 327
    iget-object v5, v0, Laa/k0;->h:Ljava/lang/Object;

    .line 328
    .line 329
    check-cast v5, Ll2/b1;

    .line 330
    .line 331
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v5

    .line 335
    check-cast v5, Ljava/lang/Boolean;

    .line 336
    .line 337
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    if-nez v5, :cond_10

    .line 342
    .line 343
    if-eqz v4, :cond_d

    .line 344
    .line 345
    goto :goto_b

    .line 346
    :cond_d
    iget-object v4, v0, Laa/k0;->i:Ljava/lang/Object;

    .line 347
    .line 348
    check-cast v4, Ll2/t2;

    .line 349
    .line 350
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v4

    .line 354
    check-cast v4, Ljava/util/List;

    .line 355
    .line 356
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 357
    .line 358
    .line 359
    move-result v5

    .line 360
    invoke-interface {v4, v5}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    .line 361
    .line 362
    .line 363
    move-result-object v4

    .line 364
    :cond_e
    invoke-interface {v4}, Ljava/util/ListIterator;->hasPrevious()Z

    .line 365
    .line 366
    .line 367
    move-result v5

    .line 368
    if-eqz v5, :cond_f

    .line 369
    .line 370
    invoke-interface {v4}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v5

    .line 374
    move-object v6, v5

    .line 375
    check-cast v6, Lz9/k;

    .line 376
    .line 377
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 378
    .line 379
    .line 380
    move-result v6

    .line 381
    if-eqz v6, :cond_e

    .line 382
    .line 383
    goto :goto_a

    .line 384
    :cond_f
    const/4 v5, 0x0

    .line 385
    :goto_a
    move-object v2, v5

    .line 386
    check-cast v2, Lz9/k;

    .line 387
    .line 388
    :cond_10
    :goto_b
    const/4 v4, 0x0

    .line 389
    check-cast v3, Ll2/t;

    .line 390
    .line 391
    if-nez v2, :cond_11

    .line 392
    .line 393
    const v0, 0x650602c

    .line 394
    .line 395
    .line 396
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 397
    .line 398
    .line 399
    :goto_c
    invoke-virtual {v3, v4}, Ll2/t;->q(Z)V

    .line 400
    .line 401
    .line 402
    goto :goto_d

    .line 403
    :cond_11
    const v5, -0x5aa2918b

    .line 404
    .line 405
    .line 406
    invoke-virtual {v3, v5}, Ll2/t;->Y(I)V

    .line 407
    .line 408
    .line 409
    iget-object v0, v0, Laa/k0;->g:Ljava/lang/Object;

    .line 410
    .line 411
    check-cast v0, Lu2/c;

    .line 412
    .line 413
    new-instance v5, Laa/p;

    .line 414
    .line 415
    invoke-direct {v5, v2, v1}, Laa/p;-><init>(Lz9/k;Lb1/n;)V

    .line 416
    .line 417
    .line 418
    const v1, -0x4b4ff5b3

    .line 419
    .line 420
    .line 421
    invoke-static {v1, v3, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    const/16 v5, 0x180

    .line 426
    .line 427
    invoke-static {v2, v0, v1, v3, v5}, Ljp/q0;->a(Lz9/k;Lu2/c;Lt2/b;Ll2/o;I)V

    .line 428
    .line 429
    .line 430
    goto :goto_c

    .line 431
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 432
    .line 433
    return-object v0

    .line 434
    nop

    .line 435
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
