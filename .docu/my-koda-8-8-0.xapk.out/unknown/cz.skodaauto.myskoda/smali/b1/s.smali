.class public final Lb1/s;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lb1/t;


# direct methods
.method public synthetic constructor <init>(Lb1/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb1/s;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/s;->g:Lb1/t;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lb1/s;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 13
    .line 14
    iget-object v0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 15
    .line 16
    iget-object v1, p0, Lb1/t;->a:Lc1/w1;

    .line 17
    .line 18
    iget-object v1, v1, Lc1/w1;->d:Ll2/j1;

    .line 19
    .line 20
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Ll2/t2;

    .line 29
    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Lt4/l;

    .line 37
    .line 38
    iget-wide v0, v0, Lt4/l;->a:J

    .line 39
    .line 40
    :goto_0
    move-wide v5, v0

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    const-wide/16 v0, 0x0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :goto_1
    int-to-long v0, p1

    .line 46
    const/16 p1, 0x20

    .line 47
    .line 48
    shl-long v2, v0, p1

    .line 49
    .line 50
    const-wide v8, 0xffffffffL

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    and-long/2addr v0, v8

    .line 56
    or-long v3, v2, v0

    .line 57
    .line 58
    iget-object v2, p0, Lb1/t;->b:Lx2/e;

    .line 59
    .line 60
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 61
    .line 62
    invoke-interface/range {v2 .. v7}, Lx2/e;->a(JJLt4/m;)J

    .line 63
    .line 64
    .line 65
    move-result-wide p0

    .line 66
    and-long/2addr p0, v8

    .line 67
    long-to-int p0, p0

    .line 68
    neg-int p0, p0

    .line 69
    and-long v0, v5, v8

    .line 70
    .line 71
    long-to-int p1, v0

    .line 72
    add-int/2addr p0, p1

    .line 73
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 79
    .line 80
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 85
    .line 86
    iget-object v0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 87
    .line 88
    iget-object v1, p0, Lb1/t;->a:Lc1/w1;

    .line 89
    .line 90
    iget-object v1, v1, Lc1/w1;->d:Ll2/j1;

    .line 91
    .line 92
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    check-cast v0, Ll2/t2;

    .line 101
    .line 102
    if-eqz v0, :cond_1

    .line 103
    .line 104
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    check-cast v0, Lt4/l;

    .line 109
    .line 110
    iget-wide v0, v0, Lt4/l;->a:J

    .line 111
    .line 112
    :goto_2
    move-wide v5, v0

    .line 113
    goto :goto_3

    .line 114
    :cond_1
    const-wide/16 v0, 0x0

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :goto_3
    int-to-long v0, p1

    .line 118
    const/16 v2, 0x20

    .line 119
    .line 120
    shl-long v2, v0, v2

    .line 121
    .line 122
    const-wide v8, 0xffffffffL

    .line 123
    .line 124
    .line 125
    .line 126
    .line 127
    and-long/2addr v0, v8

    .line 128
    or-long v3, v2, v0

    .line 129
    .line 130
    iget-object v2, p0, Lb1/t;->b:Lx2/e;

    .line 131
    .line 132
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 133
    .line 134
    invoke-interface/range {v2 .. v7}, Lx2/e;->a(JJLt4/m;)J

    .line 135
    .line 136
    .line 137
    move-result-wide v0

    .line 138
    and-long/2addr v0, v8

    .line 139
    long-to-int p0, v0

    .line 140
    neg-int p0, p0

    .line 141
    sub-int/2addr p0, p1

    .line 142
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    return-object p0

    .line 147
    :pswitch_1
    check-cast p1, Ljava/lang/Number;

    .line 148
    .line 149
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 154
    .line 155
    iget-object v0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 156
    .line 157
    iget-object v1, p0, Lb1/t;->a:Lc1/w1;

    .line 158
    .line 159
    iget-object v1, v1, Lc1/w1;->d:Ll2/j1;

    .line 160
    .line 161
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    check-cast v0, Ll2/t2;

    .line 170
    .line 171
    if-eqz v0, :cond_2

    .line 172
    .line 173
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    check-cast v0, Lt4/l;

    .line 178
    .line 179
    iget-wide v0, v0, Lt4/l;->a:J

    .line 180
    .line 181
    :goto_4
    move-wide v5, v0

    .line 182
    goto :goto_5

    .line 183
    :cond_2
    const-wide/16 v0, 0x0

    .line 184
    .line 185
    goto :goto_4

    .line 186
    :goto_5
    int-to-long v0, p1

    .line 187
    const/16 p1, 0x20

    .line 188
    .line 189
    shl-long v2, v0, p1

    .line 190
    .line 191
    const-wide v7, 0xffffffffL

    .line 192
    .line 193
    .line 194
    .line 195
    .line 196
    and-long/2addr v0, v7

    .line 197
    or-long v3, v2, v0

    .line 198
    .line 199
    iget-object v2, p0, Lb1/t;->b:Lx2/e;

    .line 200
    .line 201
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 202
    .line 203
    invoke-interface/range {v2 .. v7}, Lx2/e;->a(JJLt4/m;)J

    .line 204
    .line 205
    .line 206
    move-result-wide v0

    .line 207
    shr-long/2addr v0, p1

    .line 208
    long-to-int p0, v0

    .line 209
    neg-int p0, p0

    .line 210
    shr-long v0, v5, p1

    .line 211
    .line 212
    long-to-int p1, v0

    .line 213
    add-int/2addr p0, p1

    .line 214
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    return-object p0

    .line 219
    :pswitch_2
    check-cast p1, Ljava/lang/Number;

    .line 220
    .line 221
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 222
    .line 223
    .line 224
    move-result p1

    .line 225
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 226
    .line 227
    iget-object v0, p0, Lb1/t;->e:Landroidx/collection/q0;

    .line 228
    .line 229
    iget-object v1, p0, Lb1/t;->a:Lc1/w1;

    .line 230
    .line 231
    iget-object v1, v1, Lc1/w1;->d:Ll2/j1;

    .line 232
    .line 233
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v1

    .line 237
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    check-cast v0, Ll2/t2;

    .line 242
    .line 243
    if-eqz v0, :cond_3

    .line 244
    .line 245
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    check-cast v0, Lt4/l;

    .line 250
    .line 251
    iget-wide v0, v0, Lt4/l;->a:J

    .line 252
    .line 253
    :goto_6
    move-wide v5, v0

    .line 254
    goto :goto_7

    .line 255
    :cond_3
    const-wide/16 v0, 0x0

    .line 256
    .line 257
    goto :goto_6

    .line 258
    :goto_7
    int-to-long v0, p1

    .line 259
    const/16 v8, 0x20

    .line 260
    .line 261
    shl-long v2, v0, v8

    .line 262
    .line 263
    const-wide v9, 0xffffffffL

    .line 264
    .line 265
    .line 266
    .line 267
    .line 268
    and-long/2addr v0, v9

    .line 269
    or-long v3, v2, v0

    .line 270
    .line 271
    iget-object v2, p0, Lb1/t;->b:Lx2/e;

    .line 272
    .line 273
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 274
    .line 275
    invoke-interface/range {v2 .. v7}, Lx2/e;->a(JJLt4/m;)J

    .line 276
    .line 277
    .line 278
    move-result-wide v0

    .line 279
    shr-long/2addr v0, v8

    .line 280
    long-to-int p0, v0

    .line 281
    neg-int p0, p0

    .line 282
    sub-int/2addr p0, p1

    .line 283
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    return-object p0

    .line 288
    :pswitch_3
    check-cast p1, Ljava/lang/Number;

    .line 289
    .line 290
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 291
    .line 292
    .line 293
    move-result p1

    .line 294
    int-to-long v0, p1

    .line 295
    const/16 v2, 0x20

    .line 296
    .line 297
    shl-long v2, v0, v2

    .line 298
    .line 299
    const-wide v4, 0xffffffffL

    .line 300
    .line 301
    .line 302
    .line 303
    .line 304
    and-long/2addr v0, v4

    .line 305
    or-long v7, v2, v0

    .line 306
    .line 307
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 308
    .line 309
    invoke-static {p0}, Lb1/t;->d(Lb1/t;)J

    .line 310
    .line 311
    .line 312
    move-result-wide v9

    .line 313
    iget-object v6, p0, Lb1/t;->b:Lx2/e;

    .line 314
    .line 315
    sget-object v11, Lt4/m;->d:Lt4/m;

    .line 316
    .line 317
    invoke-interface/range {v6 .. v11}, Lx2/e;->a(JJLt4/m;)J

    .line 318
    .line 319
    .line 320
    move-result-wide v0

    .line 321
    and-long/2addr v0, v4

    .line 322
    long-to-int p0, v0

    .line 323
    neg-int p0, p0

    .line 324
    sub-int/2addr p0, p1

    .line 325
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object p0

    .line 329
    return-object p0

    .line 330
    :pswitch_4
    check-cast p1, Ljava/lang/Number;

    .line 331
    .line 332
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 333
    .line 334
    .line 335
    move-result p1

    .line 336
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 337
    .line 338
    invoke-static {p0}, Lb1/t;->d(Lb1/t;)J

    .line 339
    .line 340
    .line 341
    move-result-wide v0

    .line 342
    const-wide v2, 0xffffffffL

    .line 343
    .line 344
    .line 345
    .line 346
    .line 347
    and-long/2addr v0, v2

    .line 348
    long-to-int v0, v0

    .line 349
    int-to-long v4, p1

    .line 350
    const/16 p1, 0x20

    .line 351
    .line 352
    shl-long v6, v4, p1

    .line 353
    .line 354
    and-long/2addr v4, v2

    .line 355
    or-long v9, v6, v4

    .line 356
    .line 357
    invoke-static {p0}, Lb1/t;->d(Lb1/t;)J

    .line 358
    .line 359
    .line 360
    move-result-wide v11

    .line 361
    iget-object v8, p0, Lb1/t;->b:Lx2/e;

    .line 362
    .line 363
    sget-object v13, Lt4/m;->d:Lt4/m;

    .line 364
    .line 365
    invoke-interface/range {v8 .. v13}, Lx2/e;->a(JJLt4/m;)J

    .line 366
    .line 367
    .line 368
    move-result-wide p0

    .line 369
    and-long/2addr p0, v2

    .line 370
    long-to-int p0, p0

    .line 371
    sub-int/2addr v0, p0

    .line 372
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    return-object p0

    .line 377
    :pswitch_5
    check-cast p1, Ljava/lang/Number;

    .line 378
    .line 379
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 380
    .line 381
    .line 382
    move-result p1

    .line 383
    int-to-long v0, p1

    .line 384
    const/16 v2, 0x20

    .line 385
    .line 386
    shl-long v3, v0, v2

    .line 387
    .line 388
    const-wide v5, 0xffffffffL

    .line 389
    .line 390
    .line 391
    .line 392
    .line 393
    and-long/2addr v0, v5

    .line 394
    or-long v6, v3, v0

    .line 395
    .line 396
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 397
    .line 398
    invoke-static {p0}, Lb1/t;->d(Lb1/t;)J

    .line 399
    .line 400
    .line 401
    move-result-wide v8

    .line 402
    iget-object v5, p0, Lb1/t;->b:Lx2/e;

    .line 403
    .line 404
    sget-object v10, Lt4/m;->d:Lt4/m;

    .line 405
    .line 406
    invoke-interface/range {v5 .. v10}, Lx2/e;->a(JJLt4/m;)J

    .line 407
    .line 408
    .line 409
    move-result-wide v0

    .line 410
    shr-long/2addr v0, v2

    .line 411
    long-to-int p0, v0

    .line 412
    neg-int p0, p0

    .line 413
    sub-int/2addr p0, p1

    .line 414
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 415
    .line 416
    .line 417
    move-result-object p0

    .line 418
    return-object p0

    .line 419
    :pswitch_6
    check-cast p1, Ljava/lang/Number;

    .line 420
    .line 421
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 422
    .line 423
    .line 424
    move-result p1

    .line 425
    iget-object p0, p0, Lb1/s;->g:Lb1/t;

    .line 426
    .line 427
    invoke-static {p0}, Lb1/t;->d(Lb1/t;)J

    .line 428
    .line 429
    .line 430
    move-result-wide v0

    .line 431
    const/16 v2, 0x20

    .line 432
    .line 433
    shr-long/2addr v0, v2

    .line 434
    long-to-int v0, v0

    .line 435
    int-to-long v3, p1

    .line 436
    shl-long v5, v3, v2

    .line 437
    .line 438
    const-wide v7, 0xffffffffL

    .line 439
    .line 440
    .line 441
    .line 442
    .line 443
    and-long/2addr v3, v7

    .line 444
    or-long v8, v5, v3

    .line 445
    .line 446
    invoke-static {p0}, Lb1/t;->d(Lb1/t;)J

    .line 447
    .line 448
    .line 449
    move-result-wide v10

    .line 450
    iget-object v7, p0, Lb1/t;->b:Lx2/e;

    .line 451
    .line 452
    sget-object v12, Lt4/m;->d:Lt4/m;

    .line 453
    .line 454
    invoke-interface/range {v7 .. v12}, Lx2/e;->a(JJLt4/m;)J

    .line 455
    .line 456
    .line 457
    move-result-wide p0

    .line 458
    shr-long/2addr p0, v2

    .line 459
    long-to-int p0, p0

    .line 460
    sub-int/2addr v0, p0

    .line 461
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 462
    .line 463
    .line 464
    move-result-object p0

    .line 465
    return-object p0

    .line 466
    nop

    .line 467
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
