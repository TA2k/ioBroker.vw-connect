.class public final synthetic Lf41/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p5, p0, Lf41/d;->d:I

    iput-object p1, p0, Lf41/d;->e:Lay0/a;

    iput-object p2, p0, Lf41/d;->f:Ljava/lang/String;

    iput-object p3, p0, Lf41/d;->g:Ljava/lang/String;

    iput-object p4, p0, Lf41/d;->h:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    .line 2
    iput p6, p0, Lf41/d;->d:I

    iput-object p1, p0, Lf41/d;->e:Lay0/a;

    iput-object p2, p0, Lf41/d;->f:Ljava/lang/String;

    iput-object p3, p0, Lf41/d;->g:Ljava/lang/String;

    iput-object p4, p0, Lf41/d;->h:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf41/d;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p1

    .line 9
    .line 10
    check-cast v6, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v7

    .line 24
    iget-object v2, v0, Lf41/d;->e:Lay0/a;

    .line 25
    .line 26
    iget-object v3, v0, Lf41/d;->f:Ljava/lang/String;

    .line 27
    .line 28
    iget-object v4, v0, Lf41/d;->g:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v5, v0, Lf41/d;->h:Ljava/lang/String;

    .line 31
    .line 32
    invoke-static/range {v2 .. v7}, Lcy0/a;->b(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 33
    .line 34
    .line 35
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object v0

    .line 38
    :pswitch_0
    move-object/from16 v1, p1

    .line 39
    .line 40
    check-cast v1, Ll2/o;

    .line 41
    .line 42
    move-object/from16 v2, p2

    .line 43
    .line 44
    check-cast v2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    and-int/lit8 v3, v2, 0x3

    .line 51
    .line 52
    const/4 v4, 0x2

    .line 53
    const/4 v5, 0x1

    .line 54
    if-eq v3, v4, :cond_0

    .line 55
    .line 56
    move v3, v5

    .line 57
    goto :goto_1

    .line 58
    :cond_0
    const/4 v3, 0x0

    .line 59
    :goto_1
    and-int/2addr v2, v5

    .line 60
    check-cast v1, Ll2/t;

    .line 61
    .line 62
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eqz v2, :cond_3

    .line 67
    .line 68
    iget-object v2, v0, Lf41/d;->e:Lay0/a;

    .line 69
    .line 70
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    if-nez v3, :cond_1

    .line 79
    .line 80
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 81
    .line 82
    if-ne v4, v3, :cond_2

    .line 83
    .line 84
    :cond_1
    new-instance v4, Lha0/f;

    .line 85
    .line 86
    const/16 v3, 0x13

    .line 87
    .line 88
    invoke-direct {v4, v2, v3}, Lha0/f;-><init>(Lay0/a;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_2
    check-cast v4, Lay0/a;

    .line 95
    .line 96
    new-instance v3, Lf41/c;

    .line 97
    .line 98
    const/4 v5, 0x3

    .line 99
    iget-object v6, v0, Lf41/d;->f:Ljava/lang/String;

    .line 100
    .line 101
    invoke-direct {v3, v5, v2, v6}, Lf41/c;-><init>(ILay0/a;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    const v2, 0x358592ac

    .line 105
    .line 106
    .line 107
    invoke-static {v2, v1, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    new-instance v2, Ll20/d;

    .line 112
    .line 113
    const/4 v3, 0x4

    .line 114
    iget-object v6, v0, Lf41/d;->g:Ljava/lang/String;

    .line 115
    .line 116
    invoke-direct {v2, v6, v3}, Ll20/d;-><init>(Ljava/lang/String;I)V

    .line 117
    .line 118
    .line 119
    const v3, -0x3058e6d8

    .line 120
    .line 121
    .line 122
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 123
    .line 124
    .line 125
    move-result-object v7

    .line 126
    new-instance v2, Ll20/d;

    .line 127
    .line 128
    const/4 v3, 0x3

    .line 129
    iget-object v0, v0, Lf41/d;->h:Ljava/lang/String;

    .line 130
    .line 131
    invoke-direct {v2, v0, v3}, Ll20/d;-><init>(Ljava/lang/String;I)V

    .line 132
    .line 133
    .line 134
    const v0, -0x49d08539

    .line 135
    .line 136
    .line 137
    invoke-static {v0, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 138
    .line 139
    .line 140
    move-result-object v8

    .line 141
    const/16 v19, 0x0

    .line 142
    .line 143
    const v21, 0x1b0030

    .line 144
    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    const/4 v9, 0x0

    .line 148
    const-wide/16 v10, 0x0

    .line 149
    .line 150
    const-wide/16 v12, 0x0

    .line 151
    .line 152
    const-wide/16 v14, 0x0

    .line 153
    .line 154
    const-wide/16 v16, 0x0

    .line 155
    .line 156
    const/16 v18, 0x0

    .line 157
    .line 158
    move-object/from16 v20, v1

    .line 159
    .line 160
    invoke-static/range {v4 .. v21}, Lh2/r;->a(Lay0/a;Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JJJJFLx4/p;Ll2/o;I)V

    .line 161
    .line 162
    .line 163
    goto :goto_2

    .line 164
    :cond_3
    move-object/from16 v20, v1

    .line 165
    .line 166
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 167
    .line 168
    .line 169
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    return-object v0

    .line 172
    :pswitch_1
    move-object/from16 v5, p1

    .line 173
    .line 174
    check-cast v5, Ll2/o;

    .line 175
    .line 176
    move-object/from16 v1, p2

    .line 177
    .line 178
    check-cast v1, Ljava/lang/Integer;

    .line 179
    .line 180
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 181
    .line 182
    .line 183
    const/4 v1, 0x1

    .line 184
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 185
    .line 186
    .line 187
    move-result v6

    .line 188
    iget-object v1, v0, Lf41/d;->e:Lay0/a;

    .line 189
    .line 190
    iget-object v2, v0, Lf41/d;->f:Ljava/lang/String;

    .line 191
    .line 192
    iget-object v3, v0, Lf41/d;->g:Ljava/lang/String;

    .line 193
    .line 194
    iget-object v4, v0, Lf41/d;->h:Ljava/lang/String;

    .line 195
    .line 196
    invoke-static/range {v1 .. v6}, Llp/xe;->b(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 197
    .line 198
    .line 199
    goto/16 :goto_0

    .line 200
    .line 201
    :pswitch_2
    move-object/from16 v1, p1

    .line 202
    .line 203
    check-cast v1, Ll2/o;

    .line 204
    .line 205
    move-object/from16 v2, p2

    .line 206
    .line 207
    check-cast v2, Ljava/lang/Integer;

    .line 208
    .line 209
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 210
    .line 211
    .line 212
    move-result v2

    .line 213
    and-int/lit8 v3, v2, 0x3

    .line 214
    .line 215
    const/4 v4, 0x2

    .line 216
    const/4 v5, 0x1

    .line 217
    if-eq v3, v4, :cond_4

    .line 218
    .line 219
    move v3, v5

    .line 220
    goto :goto_3

    .line 221
    :cond_4
    const/4 v3, 0x0

    .line 222
    :goto_3
    and-int/2addr v2, v5

    .line 223
    check-cast v1, Ll2/t;

    .line 224
    .line 225
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 226
    .line 227
    .line 228
    move-result v2

    .line 229
    if-eqz v2, :cond_7

    .line 230
    .line 231
    iget-object v2, v0, Lf41/d;->e:Lay0/a;

    .line 232
    .line 233
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v3

    .line 237
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v4

    .line 241
    if-nez v3, :cond_5

    .line 242
    .line 243
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 244
    .line 245
    if-ne v4, v3, :cond_6

    .line 246
    .line 247
    :cond_5
    new-instance v4, Lha0/f;

    .line 248
    .line 249
    const/16 v3, 0x11

    .line 250
    .line 251
    invoke-direct {v4, v2, v3}, Lha0/f;-><init>(Lay0/a;I)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    :cond_6
    check-cast v4, Lay0/a;

    .line 258
    .line 259
    new-instance v3, Lf41/c;

    .line 260
    .line 261
    const/4 v5, 0x2

    .line 262
    iget-object v6, v0, Lf41/d;->f:Ljava/lang/String;

    .line 263
    .line 264
    invoke-direct {v3, v5, v2, v6}, Lf41/c;-><init>(ILay0/a;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    const v2, 0x43b8ca74

    .line 268
    .line 269
    .line 270
    invoke-static {v2, v1, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 271
    .line 272
    .line 273
    move-result-object v5

    .line 274
    new-instance v2, Ll20/d;

    .line 275
    .line 276
    const/4 v3, 0x2

    .line 277
    iget-object v6, v0, Lf41/d;->g:Ljava/lang/String;

    .line 278
    .line 279
    invoke-direct {v2, v6, v3}, Ll20/d;-><init>(Ljava/lang/String;I)V

    .line 280
    .line 281
    .line 282
    const v3, 0x23a283f0

    .line 283
    .line 284
    .line 285
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 286
    .line 287
    .line 288
    move-result-object v7

    .line 289
    new-instance v2, Ll20/d;

    .line 290
    .line 291
    const/4 v3, 0x1

    .line 292
    iget-object v0, v0, Lf41/d;->h:Ljava/lang/String;

    .line 293
    .line 294
    invoke-direct {v2, v0, v3}, Ll20/d;-><init>(Ljava/lang/String;I)V

    .line 295
    .line 296
    .line 297
    const v0, 0x1b9cf24f

    .line 298
    .line 299
    .line 300
    invoke-static {v0, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 301
    .line 302
    .line 303
    move-result-object v8

    .line 304
    const/16 v19, 0x0

    .line 305
    .line 306
    const v21, 0x1b0030

    .line 307
    .line 308
    .line 309
    const/4 v6, 0x0

    .line 310
    const/4 v9, 0x0

    .line 311
    const-wide/16 v10, 0x0

    .line 312
    .line 313
    const-wide/16 v12, 0x0

    .line 314
    .line 315
    const-wide/16 v14, 0x0

    .line 316
    .line 317
    const-wide/16 v16, 0x0

    .line 318
    .line 319
    const/16 v18, 0x0

    .line 320
    .line 321
    move-object/from16 v20, v1

    .line 322
    .line 323
    invoke-static/range {v4 .. v21}, Lh2/r;->a(Lay0/a;Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JJJJFLx4/p;Ll2/o;I)V

    .line 324
    .line 325
    .line 326
    goto :goto_4

    .line 327
    :cond_7
    move-object/from16 v20, v1

    .line 328
    .line 329
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 330
    .line 331
    .line 332
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 333
    .line 334
    return-object v0

    .line 335
    :pswitch_3
    move-object/from16 v5, p1

    .line 336
    .line 337
    check-cast v5, Ll2/o;

    .line 338
    .line 339
    move-object/from16 v1, p2

    .line 340
    .line 341
    check-cast v1, Ljava/lang/Integer;

    .line 342
    .line 343
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 344
    .line 345
    .line 346
    const/4 v1, 0x1

    .line 347
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 348
    .line 349
    .line 350
    move-result v6

    .line 351
    iget-object v1, v0, Lf41/d;->e:Lay0/a;

    .line 352
    .line 353
    iget-object v2, v0, Lf41/d;->f:Ljava/lang/String;

    .line 354
    .line 355
    iget-object v3, v0, Lf41/d;->g:Ljava/lang/String;

    .line 356
    .line 357
    iget-object v4, v0, Lf41/d;->h:Ljava/lang/String;

    .line 358
    .line 359
    invoke-static/range {v1 .. v6}, Lkp/h7;->c(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 360
    .line 361
    .line 362
    goto/16 :goto_0

    .line 363
    .line 364
    :pswitch_4
    move-object/from16 v1, p1

    .line 365
    .line 366
    check-cast v1, Ll2/o;

    .line 367
    .line 368
    move-object/from16 v2, p2

    .line 369
    .line 370
    check-cast v2, Ljava/lang/Integer;

    .line 371
    .line 372
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    and-int/lit8 v3, v2, 0x3

    .line 377
    .line 378
    const/4 v4, 0x2

    .line 379
    const/4 v5, 0x1

    .line 380
    if-eq v3, v4, :cond_8

    .line 381
    .line 382
    move v3, v5

    .line 383
    goto :goto_5

    .line 384
    :cond_8
    const/4 v3, 0x0

    .line 385
    :goto_5
    and-int/2addr v2, v5

    .line 386
    check-cast v1, Ll2/t;

    .line 387
    .line 388
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 389
    .line 390
    .line 391
    move-result v2

    .line 392
    if-eqz v2, :cond_b

    .line 393
    .line 394
    iget-object v2, v0, Lf41/d;->e:Lay0/a;

    .line 395
    .line 396
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 397
    .line 398
    .line 399
    move-result v3

    .line 400
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    if-nez v3, :cond_9

    .line 405
    .line 406
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 407
    .line 408
    if-ne v4, v3, :cond_a

    .line 409
    .line 410
    :cond_9
    new-instance v4, Lb71/i;

    .line 411
    .line 412
    const/16 v3, 0x11

    .line 413
    .line 414
    invoke-direct {v4, v2, v3}, Lb71/i;-><init>(Lay0/a;I)V

    .line 415
    .line 416
    .line 417
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 418
    .line 419
    .line 420
    :cond_a
    check-cast v4, Lay0/a;

    .line 421
    .line 422
    new-instance v3, Lf41/c;

    .line 423
    .line 424
    const/4 v5, 0x0

    .line 425
    iget-object v6, v0, Lf41/d;->f:Ljava/lang/String;

    .line 426
    .line 427
    invoke-direct {v3, v5, v2, v6}, Lf41/c;-><init>(ILay0/a;Ljava/lang/String;)V

    .line 428
    .line 429
    .line 430
    const v2, 0x207ed794

    .line 431
    .line 432
    .line 433
    invoke-static {v2, v1, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 434
    .line 435
    .line 436
    move-result-object v5

    .line 437
    new-instance v2, La71/d;

    .line 438
    .line 439
    const/16 v3, 0x10

    .line 440
    .line 441
    iget-object v6, v0, Lf41/d;->g:Ljava/lang/String;

    .line 442
    .line 443
    invoke-direct {v2, v6, v3}, La71/d;-><init>(Ljava/lang/String;I)V

    .line 444
    .line 445
    .line 446
    const v3, 0x19b77310

    .line 447
    .line 448
    .line 449
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 450
    .line 451
    .line 452
    move-result-object v7

    .line 453
    new-instance v2, La71/d;

    .line 454
    .line 455
    const/16 v3, 0x11

    .line 456
    .line 457
    iget-object v0, v0, Lf41/d;->h:Ljava/lang/String;

    .line 458
    .line 459
    invoke-direct {v2, v0, v3}, La71/d;-><init>(Ljava/lang/String;I)V

    .line 460
    .line 461
    .line 462
    const v0, -0x67fa6611

    .line 463
    .line 464
    .line 465
    invoke-static {v0, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 466
    .line 467
    .line 468
    move-result-object v8

    .line 469
    const/16 v19, 0x0

    .line 470
    .line 471
    const v21, 0x1b0030

    .line 472
    .line 473
    .line 474
    const/4 v6, 0x0

    .line 475
    const/4 v9, 0x0

    .line 476
    const-wide/16 v10, 0x0

    .line 477
    .line 478
    const-wide/16 v12, 0x0

    .line 479
    .line 480
    const-wide/16 v14, 0x0

    .line 481
    .line 482
    const-wide/16 v16, 0x0

    .line 483
    .line 484
    const/16 v18, 0x0

    .line 485
    .line 486
    move-object/from16 v20, v1

    .line 487
    .line 488
    invoke-static/range {v4 .. v21}, Lh2/r;->a(Lay0/a;Lt2/b;Lx2/s;Lay0/n;Lay0/n;Le3/n0;JJJJFLx4/p;Ll2/o;I)V

    .line 489
    .line 490
    .line 491
    goto :goto_6

    .line 492
    :cond_b
    move-object/from16 v20, v1

    .line 493
    .line 494
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 495
    .line 496
    .line 497
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 498
    .line 499
    return-object v0

    .line 500
    nop

    .line 501
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
