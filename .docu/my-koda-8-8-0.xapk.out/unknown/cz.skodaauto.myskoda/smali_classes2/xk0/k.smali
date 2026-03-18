.class public final synthetic Lxk0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    const/4 p2, 0x6

    iput p2, p0, Lxk0/k;->d:I

    sget-object p2, Li91/k1;->d:Li91/k1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/k;->e:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;IB)V
    .locals 0

    .line 2
    iput p2, p0, Lxk0/k;->d:I

    iput-object p1, p0, Lxk0/k;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 3
    iput p3, p0, Lxk0/k;->d:I

    iput-object p1, p0, Lxk0/k;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lxk0/k;->d:I

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x2

    .line 8
    const/4 v5, 0x1

    .line 9
    iget-object v6, v0, Lxk0/k;->e:Ljava/lang/String;

    .line 10
    .line 11
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    move-object/from16 v0, p1

    .line 17
    .line 18
    check-cast v0, Ll2/o;

    .line 19
    .line 20
    move-object/from16 v1, p2

    .line 21
    .line 22
    check-cast v1, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    invoke-static {v6, v0, v1}, Lzb/b;->o(Ljava/lang/String;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    return-object v7

    .line 35
    :pswitch_0
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Ll2/o;

    .line 38
    .line 39
    move-object/from16 v2, p2

    .line 40
    .line 41
    check-cast v2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    and-int/lit8 v6, v2, 0x3

    .line 48
    .line 49
    if-eq v6, v4, :cond_0

    .line 50
    .line 51
    move v3, v5

    .line 52
    :cond_0
    and-int/2addr v2, v5

    .line 53
    check-cast v1, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_1

    .line 60
    .line 61
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    check-cast v2, Lj91/f;

    .line 68
    .line 69
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 70
    .line 71
    .line 72
    move-result-object v9

    .line 73
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 74
    .line 75
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Lj91/e;

    .line 80
    .line 81
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 82
    .line 83
    .line 84
    move-result-wide v11

    .line 85
    const/16 v28, 0x0

    .line 86
    .line 87
    const v29, 0xfff4

    .line 88
    .line 89
    .line 90
    iget-object v8, v0, Lxk0/k;->e:Ljava/lang/String;

    .line 91
    .line 92
    const/4 v10, 0x0

    .line 93
    const-wide/16 v13, 0x0

    .line 94
    .line 95
    const/4 v15, 0x0

    .line 96
    const-wide/16 v16, 0x0

    .line 97
    .line 98
    const/16 v18, 0x0

    .line 99
    .line 100
    const/16 v19, 0x0

    .line 101
    .line 102
    const-wide/16 v20, 0x0

    .line 103
    .line 104
    const/16 v22, 0x0

    .line 105
    .line 106
    const/16 v23, 0x0

    .line 107
    .line 108
    const/16 v24, 0x0

    .line 109
    .line 110
    const/16 v25, 0x0

    .line 111
    .line 112
    const/16 v27, 0x0

    .line 113
    .line 114
    move-object/from16 v26, v1

    .line 115
    .line 116
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 117
    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_1
    move-object/from16 v26, v1

    .line 121
    .line 122
    invoke-virtual/range {v26 .. v26}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    :goto_0
    return-object v7

    .line 126
    :pswitch_1
    move-object/from16 v1, p1

    .line 127
    .line 128
    check-cast v1, Ll2/o;

    .line 129
    .line 130
    move-object/from16 v2, p2

    .line 131
    .line 132
    check-cast v2, Ljava/lang/Integer;

    .line 133
    .line 134
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    and-int/lit8 v6, v2, 0x3

    .line 139
    .line 140
    if-eq v6, v4, :cond_2

    .line 141
    .line 142
    move v3, v5

    .line 143
    :cond_2
    and-int/2addr v2, v5

    .line 144
    check-cast v1, Ll2/t;

    .line 145
    .line 146
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 147
    .line 148
    .line 149
    move-result v2

    .line 150
    if-eqz v2, :cond_3

    .line 151
    .line 152
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 153
    .line 154
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    check-cast v2, Lj91/f;

    .line 159
    .line 160
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 161
    .line 162
    .line 163
    move-result-object v9

    .line 164
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 165
    .line 166
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    check-cast v2, Lj91/e;

    .line 171
    .line 172
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 173
    .line 174
    .line 175
    move-result-wide v11

    .line 176
    const/16 v28, 0x0

    .line 177
    .line 178
    const v29, 0xfff4

    .line 179
    .line 180
    .line 181
    iget-object v8, v0, Lxk0/k;->e:Ljava/lang/String;

    .line 182
    .line 183
    const/4 v10, 0x0

    .line 184
    const-wide/16 v13, 0x0

    .line 185
    .line 186
    const/4 v15, 0x0

    .line 187
    const-wide/16 v16, 0x0

    .line 188
    .line 189
    const/16 v18, 0x0

    .line 190
    .line 191
    const/16 v19, 0x0

    .line 192
    .line 193
    const-wide/16 v20, 0x0

    .line 194
    .line 195
    const/16 v22, 0x0

    .line 196
    .line 197
    const/16 v23, 0x0

    .line 198
    .line 199
    const/16 v24, 0x0

    .line 200
    .line 201
    const/16 v25, 0x0

    .line 202
    .line 203
    const/16 v27, 0x0

    .line 204
    .line 205
    move-object/from16 v26, v1

    .line 206
    .line 207
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 208
    .line 209
    .line 210
    goto :goto_1

    .line 211
    :cond_3
    move-object/from16 v26, v1

    .line 212
    .line 213
    invoke-virtual/range {v26 .. v26}, Ll2/t;->R()V

    .line 214
    .line 215
    .line 216
    :goto_1
    return-object v7

    .line 217
    :pswitch_2
    move-object/from16 v1, p1

    .line 218
    .line 219
    check-cast v1, Ll2/o;

    .line 220
    .line 221
    move-object/from16 v2, p2

    .line 222
    .line 223
    check-cast v2, Ljava/lang/Integer;

    .line 224
    .line 225
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 226
    .line 227
    .line 228
    move-result v2

    .line 229
    and-int/lit8 v6, v2, 0x3

    .line 230
    .line 231
    if-eq v6, v4, :cond_4

    .line 232
    .line 233
    move v3, v5

    .line 234
    :cond_4
    and-int/2addr v2, v5

    .line 235
    check-cast v1, Ll2/t;

    .line 236
    .line 237
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 238
    .line 239
    .line 240
    move-result v2

    .line 241
    if-eqz v2, :cond_5

    .line 242
    .line 243
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 244
    .line 245
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v2

    .line 249
    check-cast v2, Lj91/f;

    .line 250
    .line 251
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 252
    .line 253
    .line 254
    move-result-object v9

    .line 255
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 256
    .line 257
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v2

    .line 261
    check-cast v2, Lj91/e;

    .line 262
    .line 263
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 264
    .line 265
    .line 266
    move-result-wide v11

    .line 267
    const/16 v28, 0x0

    .line 268
    .line 269
    const v29, 0xfff4

    .line 270
    .line 271
    .line 272
    iget-object v8, v0, Lxk0/k;->e:Ljava/lang/String;

    .line 273
    .line 274
    const/4 v10, 0x0

    .line 275
    const-wide/16 v13, 0x0

    .line 276
    .line 277
    const/4 v15, 0x0

    .line 278
    const-wide/16 v16, 0x0

    .line 279
    .line 280
    const/16 v18, 0x0

    .line 281
    .line 282
    const/16 v19, 0x0

    .line 283
    .line 284
    const-wide/16 v20, 0x0

    .line 285
    .line 286
    const/16 v22, 0x0

    .line 287
    .line 288
    const/16 v23, 0x0

    .line 289
    .line 290
    const/16 v24, 0x0

    .line 291
    .line 292
    const/16 v25, 0x0

    .line 293
    .line 294
    const/16 v27, 0x0

    .line 295
    .line 296
    move-object/from16 v26, v1

    .line 297
    .line 298
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 299
    .line 300
    .line 301
    goto :goto_2

    .line 302
    :cond_5
    move-object/from16 v26, v1

    .line 303
    .line 304
    invoke-virtual/range {v26 .. v26}, Ll2/t;->R()V

    .line 305
    .line 306
    .line 307
    :goto_2
    return-object v7

    .line 308
    :pswitch_3
    move-object/from16 v0, p1

    .line 309
    .line 310
    check-cast v0, Ll2/o;

    .line 311
    .line 312
    move-object/from16 v1, p2

    .line 313
    .line 314
    check-cast v1, Ljava/lang/Integer;

    .line 315
    .line 316
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 317
    .line 318
    .line 319
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 320
    .line 321
    .line 322
    move-result v1

    .line 323
    invoke-static {v6, v0, v1}, Lz70/l;->m(Ljava/lang/String;Ll2/o;I)V

    .line 324
    .line 325
    .line 326
    return-object v7

    .line 327
    :pswitch_4
    sget-object v0, Li91/k1;->d:Li91/k1;

    .line 328
    .line 329
    move-object/from16 v0, p1

    .line 330
    .line 331
    check-cast v0, Ll2/o;

    .line 332
    .line 333
    move-object/from16 v1, p2

    .line 334
    .line 335
    check-cast v1, Ljava/lang/Integer;

    .line 336
    .line 337
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 338
    .line 339
    .line 340
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 341
    .line 342
    .line 343
    move-result v1

    .line 344
    invoke-static {v6, v0, v1}, Lz70/l;->i(Ljava/lang/String;Ll2/o;I)V

    .line 345
    .line 346
    .line 347
    return-object v7

    .line 348
    :pswitch_5
    move-object/from16 v0, p1

    .line 349
    .line 350
    check-cast v0, Ll2/o;

    .line 351
    .line 352
    move-object/from16 v1, p2

    .line 353
    .line 354
    check-cast v1, Ljava/lang/Integer;

    .line 355
    .line 356
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 357
    .line 358
    .line 359
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 360
    .line 361
    .line 362
    move-result v1

    .line 363
    invoke-static {v6, v0, v1}, Lxk0/e0;->b(Ljava/lang/String;Ll2/o;I)V

    .line 364
    .line 365
    .line 366
    return-object v7

    .line 367
    :pswitch_6
    move-object/from16 v0, p1

    .line 368
    .line 369
    check-cast v0, Ll2/o;

    .line 370
    .line 371
    move-object/from16 v1, p2

    .line 372
    .line 373
    check-cast v1, Ljava/lang/Integer;

    .line 374
    .line 375
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 376
    .line 377
    .line 378
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 379
    .line 380
    .line 381
    move-result v1

    .line 382
    invoke-static {v6, v0, v1}, Lxk0/h;->e0(Ljava/lang/String;Ll2/o;I)V

    .line 383
    .line 384
    .line 385
    return-object v7

    .line 386
    :pswitch_7
    move-object/from16 v0, p1

    .line 387
    .line 388
    check-cast v0, Ll2/o;

    .line 389
    .line 390
    move-object/from16 v1, p2

    .line 391
    .line 392
    check-cast v1, Ljava/lang/Integer;

    .line 393
    .line 394
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 395
    .line 396
    .line 397
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 398
    .line 399
    .line 400
    move-result v1

    .line 401
    invoke-static {v6, v0, v1}, Lxk0/h;->d0(Ljava/lang/String;Ll2/o;I)V

    .line 402
    .line 403
    .line 404
    return-object v7

    .line 405
    :pswitch_8
    move-object/from16 v0, p1

    .line 406
    .line 407
    check-cast v0, Ll2/o;

    .line 408
    .line 409
    move-object/from16 v1, p2

    .line 410
    .line 411
    check-cast v1, Ljava/lang/Integer;

    .line 412
    .line 413
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 417
    .line 418
    .line 419
    move-result v1

    .line 420
    invoke-static {v6, v0, v1}, Lxk0/h;->c0(Ljava/lang/String;Ll2/o;I)V

    .line 421
    .line 422
    .line 423
    return-object v7

    .line 424
    :pswitch_9
    move-object/from16 v0, p1

    .line 425
    .line 426
    check-cast v0, Ll2/o;

    .line 427
    .line 428
    move-object/from16 v1, p2

    .line 429
    .line 430
    check-cast v1, Ljava/lang/Integer;

    .line 431
    .line 432
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 433
    .line 434
    .line 435
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 436
    .line 437
    .line 438
    move-result v1

    .line 439
    invoke-static {v6, v0, v1}, Lxk0/h;->L(Ljava/lang/String;Ll2/o;I)V

    .line 440
    .line 441
    .line 442
    return-object v7

    .line 443
    :pswitch_a
    move-object/from16 v0, p1

    .line 444
    .line 445
    check-cast v0, Ll2/o;

    .line 446
    .line 447
    move-object/from16 v1, p2

    .line 448
    .line 449
    check-cast v1, Ljava/lang/Integer;

    .line 450
    .line 451
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 452
    .line 453
    .line 454
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 455
    .line 456
    .line 457
    move-result v1

    .line 458
    invoke-static {v6, v0, v1}, Lxk0/h;->v(Ljava/lang/String;Ll2/o;I)V

    .line 459
    .line 460
    .line 461
    return-object v7

    .line 462
    nop

    .line 463
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
