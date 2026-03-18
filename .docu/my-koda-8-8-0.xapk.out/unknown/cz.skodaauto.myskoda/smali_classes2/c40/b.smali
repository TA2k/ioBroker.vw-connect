.class public final Lc40/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ll2/b1;

.field public final synthetic c:Lz4/p;

.field public final synthetic d:Lz4/m;

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lz4/p;Lz4/m;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p5, p0, Lc40/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lc40/b;->b:Ll2/b1;

    .line 4
    .line 5
    iput-object p2, p0, Lc40/b;->c:Lz4/p;

    .line 6
    .line 7
    iput-object p3, p0, Lc40/b;->d:Lz4/m;

    .line 8
    .line 9
    iput-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 8

    .line 1
    iget v0, p0, Lc40/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v7, Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-direct {v7}, Ljava/util/LinkedHashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lc40/b;->b:Ll2/b1;

    .line 12
    .line 13
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    iget-object v5, p0, Lc40/b;->d:Lz4/m;

    .line 21
    .line 22
    iget-object v1, p0, Lc40/b;->c:Lz4/p;

    .line 23
    .line 24
    move-object v6, p2

    .line 25
    move-wide v2, p3

    .line 26
    invoke-virtual/range {v1 .. v7}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 27
    .line 28
    .line 29
    move-result-wide p2

    .line 30
    move-object v5, v6

    .line 31
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 32
    .line 33
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    const/16 p4, 0x20

    .line 37
    .line 38
    shr-long v0, p2, p4

    .line 39
    .line 40
    long-to-int p4, v0

    .line 41
    const-wide v0, 0xffffffffL

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    and-long/2addr p2, v0

    .line 47
    long-to-int p2, p2

    .line 48
    new-instance p3, Lc40/a;

    .line 49
    .line 50
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 51
    .line 52
    const/16 v0, 0x13

    .line 53
    .line 54
    invoke-direct {p3, p0, v5, v7, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 55
    .line 56
    .line 57
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 58
    .line 59
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_0
    move-object v5, p2

    .line 65
    move-wide v1, p3

    .line 66
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 67
    .line 68
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 69
    .line 70
    .line 71
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 72
    .line 73
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 81
    .line 82
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 83
    .line 84
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 85
    .line 86
    .line 87
    move-result-wide p2

    .line 88
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 89
    .line 90
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    const/16 p4, 0x20

    .line 94
    .line 95
    shr-long v0, p2, p4

    .line 96
    .line 97
    long-to-int p4, v0

    .line 98
    const-wide v0, 0xffffffffL

    .line 99
    .line 100
    .line 101
    .line 102
    .line 103
    and-long/2addr p2, v0

    .line 104
    long-to-int p2, p2

    .line 105
    new-instance p3, Lc40/a;

    .line 106
    .line 107
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 108
    .line 109
    const/16 v0, 0x12

    .line 110
    .line 111
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 112
    .line 113
    .line 114
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 115
    .line 116
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0

    .line 121
    :pswitch_1
    move-object v5, p2

    .line 122
    move-wide v1, p3

    .line 123
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 124
    .line 125
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 126
    .line 127
    .line 128
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 129
    .line 130
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 138
    .line 139
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 140
    .line 141
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 142
    .line 143
    .line 144
    move-result-wide p2

    .line 145
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 146
    .line 147
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    const/16 p4, 0x20

    .line 151
    .line 152
    shr-long v0, p2, p4

    .line 153
    .line 154
    long-to-int p4, v0

    .line 155
    const-wide v0, 0xffffffffL

    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    and-long/2addr p2, v0

    .line 161
    long-to-int p2, p2

    .line 162
    new-instance p3, Lc40/a;

    .line 163
    .line 164
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 165
    .line 166
    const/16 v0, 0x11

    .line 167
    .line 168
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 169
    .line 170
    .line 171
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 172
    .line 173
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :pswitch_2
    move-object v5, p2

    .line 179
    move-wide v1, p3

    .line 180
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 181
    .line 182
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 183
    .line 184
    .line 185
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 186
    .line 187
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 195
    .line 196
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 197
    .line 198
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 199
    .line 200
    .line 201
    move-result-wide p2

    .line 202
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 203
    .line 204
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    const/16 p4, 0x20

    .line 208
    .line 209
    shr-long v0, p2, p4

    .line 210
    .line 211
    long-to-int p4, v0

    .line 212
    const-wide v0, 0xffffffffL

    .line 213
    .line 214
    .line 215
    .line 216
    .line 217
    and-long/2addr p2, v0

    .line 218
    long-to-int p2, p2

    .line 219
    new-instance p3, Lc40/a;

    .line 220
    .line 221
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 222
    .line 223
    const/16 v0, 0x10

    .line 224
    .line 225
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 226
    .line 227
    .line 228
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 229
    .line 230
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    return-object p0

    .line 235
    :pswitch_3
    move-object v5, p2

    .line 236
    move-wide v1, p3

    .line 237
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 238
    .line 239
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 240
    .line 241
    .line 242
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 243
    .line 244
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 252
    .line 253
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 254
    .line 255
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 256
    .line 257
    .line 258
    move-result-wide p2

    .line 259
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 260
    .line 261
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    const/16 p4, 0x20

    .line 265
    .line 266
    shr-long v0, p2, p4

    .line 267
    .line 268
    long-to-int p4, v0

    .line 269
    const-wide v0, 0xffffffffL

    .line 270
    .line 271
    .line 272
    .line 273
    .line 274
    and-long/2addr p2, v0

    .line 275
    long-to-int p2, p2

    .line 276
    new-instance p3, Lc40/a;

    .line 277
    .line 278
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 279
    .line 280
    const/16 v0, 0xf

    .line 281
    .line 282
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 283
    .line 284
    .line 285
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 286
    .line 287
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    return-object p0

    .line 292
    :pswitch_4
    move-object v5, p2

    .line 293
    move-wide v1, p3

    .line 294
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 295
    .line 296
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 297
    .line 298
    .line 299
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 300
    .line 301
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 305
    .line 306
    .line 307
    move-result-object v3

    .line 308
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 309
    .line 310
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 311
    .line 312
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 313
    .line 314
    .line 315
    move-result-wide p2

    .line 316
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 317
    .line 318
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    const/16 p4, 0x20

    .line 322
    .line 323
    shr-long v0, p2, p4

    .line 324
    .line 325
    long-to-int p4, v0

    .line 326
    const-wide v0, 0xffffffffL

    .line 327
    .line 328
    .line 329
    .line 330
    .line 331
    and-long/2addr p2, v0

    .line 332
    long-to-int p2, p2

    .line 333
    new-instance p3, Lc40/a;

    .line 334
    .line 335
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 336
    .line 337
    const/16 v0, 0xe

    .line 338
    .line 339
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 340
    .line 341
    .line 342
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 343
    .line 344
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 345
    .line 346
    .line 347
    move-result-object p0

    .line 348
    return-object p0

    .line 349
    :pswitch_5
    move-object v5, p2

    .line 350
    move-wide v1, p3

    .line 351
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 352
    .line 353
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 354
    .line 355
    .line 356
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 357
    .line 358
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 366
    .line 367
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 368
    .line 369
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 370
    .line 371
    .line 372
    move-result-wide p2

    .line 373
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 374
    .line 375
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    const/16 p4, 0x20

    .line 379
    .line 380
    shr-long v0, p2, p4

    .line 381
    .line 382
    long-to-int p4, v0

    .line 383
    const-wide v0, 0xffffffffL

    .line 384
    .line 385
    .line 386
    .line 387
    .line 388
    and-long/2addr p2, v0

    .line 389
    long-to-int p2, p2

    .line 390
    new-instance p3, Lc40/a;

    .line 391
    .line 392
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 393
    .line 394
    const/16 v0, 0xd

    .line 395
    .line 396
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 397
    .line 398
    .line 399
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 400
    .line 401
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 402
    .line 403
    .line 404
    move-result-object p0

    .line 405
    return-object p0

    .line 406
    :pswitch_6
    move-object v5, p2

    .line 407
    move-wide v1, p3

    .line 408
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 409
    .line 410
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 411
    .line 412
    .line 413
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 414
    .line 415
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 419
    .line 420
    .line 421
    move-result-object v3

    .line 422
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 423
    .line 424
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 425
    .line 426
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 427
    .line 428
    .line 429
    move-result-wide p2

    .line 430
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 431
    .line 432
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    const/16 p4, 0x20

    .line 436
    .line 437
    shr-long v0, p2, p4

    .line 438
    .line 439
    long-to-int p4, v0

    .line 440
    const-wide v0, 0xffffffffL

    .line 441
    .line 442
    .line 443
    .line 444
    .line 445
    and-long/2addr p2, v0

    .line 446
    long-to-int p2, p2

    .line 447
    new-instance p3, Lc40/a;

    .line 448
    .line 449
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 450
    .line 451
    const/16 v0, 0xc

    .line 452
    .line 453
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 454
    .line 455
    .line 456
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 457
    .line 458
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 459
    .line 460
    .line 461
    move-result-object p0

    .line 462
    return-object p0

    .line 463
    :pswitch_7
    move-object v5, p2

    .line 464
    move-wide v1, p3

    .line 465
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 466
    .line 467
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 468
    .line 469
    .line 470
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 471
    .line 472
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 476
    .line 477
    .line 478
    move-result-object v3

    .line 479
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 480
    .line 481
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 482
    .line 483
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 484
    .line 485
    .line 486
    move-result-wide p2

    .line 487
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 488
    .line 489
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    const/16 p4, 0x20

    .line 493
    .line 494
    shr-long v0, p2, p4

    .line 495
    .line 496
    long-to-int p4, v0

    .line 497
    const-wide v0, 0xffffffffL

    .line 498
    .line 499
    .line 500
    .line 501
    .line 502
    and-long/2addr p2, v0

    .line 503
    long-to-int p2, p2

    .line 504
    new-instance p3, Lc40/a;

    .line 505
    .line 506
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 507
    .line 508
    const/16 v0, 0xb

    .line 509
    .line 510
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 511
    .line 512
    .line 513
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 514
    .line 515
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 516
    .line 517
    .line 518
    move-result-object p0

    .line 519
    return-object p0

    .line 520
    :pswitch_8
    move-object v5, p2

    .line 521
    move-wide v1, p3

    .line 522
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 523
    .line 524
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 525
    .line 526
    .line 527
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 528
    .line 529
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 533
    .line 534
    .line 535
    move-result-object v3

    .line 536
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 537
    .line 538
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 539
    .line 540
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 541
    .line 542
    .line 543
    move-result-wide p2

    .line 544
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 545
    .line 546
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    const/16 p4, 0x20

    .line 550
    .line 551
    shr-long v0, p2, p4

    .line 552
    .line 553
    long-to-int p4, v0

    .line 554
    const-wide v0, 0xffffffffL

    .line 555
    .line 556
    .line 557
    .line 558
    .line 559
    and-long/2addr p2, v0

    .line 560
    long-to-int p2, p2

    .line 561
    new-instance p3, Lc40/a;

    .line 562
    .line 563
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 564
    .line 565
    const/16 v0, 0xa

    .line 566
    .line 567
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 568
    .line 569
    .line 570
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 571
    .line 572
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 573
    .line 574
    .line 575
    move-result-object p0

    .line 576
    return-object p0

    .line 577
    :pswitch_9
    move-object v5, p2

    .line 578
    move-wide v1, p3

    .line 579
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 580
    .line 581
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 582
    .line 583
    .line 584
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 585
    .line 586
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 590
    .line 591
    .line 592
    move-result-object v3

    .line 593
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 594
    .line 595
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 596
    .line 597
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 598
    .line 599
    .line 600
    move-result-wide p2

    .line 601
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 602
    .line 603
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    const/16 p4, 0x20

    .line 607
    .line 608
    shr-long v0, p2, p4

    .line 609
    .line 610
    long-to-int p4, v0

    .line 611
    const-wide v0, 0xffffffffL

    .line 612
    .line 613
    .line 614
    .line 615
    .line 616
    and-long/2addr p2, v0

    .line 617
    long-to-int p2, p2

    .line 618
    new-instance p3, Lc40/a;

    .line 619
    .line 620
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 621
    .line 622
    const/16 v0, 0x9

    .line 623
    .line 624
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 625
    .line 626
    .line 627
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 628
    .line 629
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 630
    .line 631
    .line 632
    move-result-object p0

    .line 633
    return-object p0

    .line 634
    :pswitch_a
    move-object v5, p2

    .line 635
    move-wide v1, p3

    .line 636
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 637
    .line 638
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 639
    .line 640
    .line 641
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 642
    .line 643
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 644
    .line 645
    .line 646
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 647
    .line 648
    .line 649
    move-result-object v3

    .line 650
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 651
    .line 652
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 653
    .line 654
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 655
    .line 656
    .line 657
    move-result-wide p2

    .line 658
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 659
    .line 660
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 661
    .line 662
    .line 663
    const/16 p4, 0x20

    .line 664
    .line 665
    shr-long v0, p2, p4

    .line 666
    .line 667
    long-to-int p4, v0

    .line 668
    const-wide v0, 0xffffffffL

    .line 669
    .line 670
    .line 671
    .line 672
    .line 673
    and-long/2addr p2, v0

    .line 674
    long-to-int p2, p2

    .line 675
    new-instance p3, Lc40/a;

    .line 676
    .line 677
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 678
    .line 679
    const/16 v0, 0x8

    .line 680
    .line 681
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 682
    .line 683
    .line 684
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 685
    .line 686
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 687
    .line 688
    .line 689
    move-result-object p0

    .line 690
    return-object p0

    .line 691
    :pswitch_b
    move-object v5, p2

    .line 692
    move-wide v1, p3

    .line 693
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 694
    .line 695
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 696
    .line 697
    .line 698
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 699
    .line 700
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 701
    .line 702
    .line 703
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 704
    .line 705
    .line 706
    move-result-object v3

    .line 707
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 708
    .line 709
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 710
    .line 711
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 712
    .line 713
    .line 714
    move-result-wide p2

    .line 715
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 716
    .line 717
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 718
    .line 719
    .line 720
    const/16 p4, 0x20

    .line 721
    .line 722
    shr-long v0, p2, p4

    .line 723
    .line 724
    long-to-int p4, v0

    .line 725
    const-wide v0, 0xffffffffL

    .line 726
    .line 727
    .line 728
    .line 729
    .line 730
    and-long/2addr p2, v0

    .line 731
    long-to-int p2, p2

    .line 732
    new-instance p3, Lc40/a;

    .line 733
    .line 734
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 735
    .line 736
    const/4 v0, 0x7

    .line 737
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 738
    .line 739
    .line 740
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 741
    .line 742
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 743
    .line 744
    .line 745
    move-result-object p0

    .line 746
    return-object p0

    .line 747
    :pswitch_c
    move-object v5, p2

    .line 748
    move-wide v1, p3

    .line 749
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 750
    .line 751
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 752
    .line 753
    .line 754
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 755
    .line 756
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 757
    .line 758
    .line 759
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 760
    .line 761
    .line 762
    move-result-object v3

    .line 763
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 764
    .line 765
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 766
    .line 767
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 768
    .line 769
    .line 770
    move-result-wide p2

    .line 771
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 772
    .line 773
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 774
    .line 775
    .line 776
    const/16 p4, 0x20

    .line 777
    .line 778
    shr-long v0, p2, p4

    .line 779
    .line 780
    long-to-int p4, v0

    .line 781
    const-wide v0, 0xffffffffL

    .line 782
    .line 783
    .line 784
    .line 785
    .line 786
    and-long/2addr p2, v0

    .line 787
    long-to-int p2, p2

    .line 788
    new-instance p3, Lc40/a;

    .line 789
    .line 790
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 791
    .line 792
    const/4 v0, 0x6

    .line 793
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 794
    .line 795
    .line 796
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 797
    .line 798
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 799
    .line 800
    .line 801
    move-result-object p0

    .line 802
    return-object p0

    .line 803
    :pswitch_d
    move-object v5, p2

    .line 804
    move-wide v1, p3

    .line 805
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 806
    .line 807
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 808
    .line 809
    .line 810
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 811
    .line 812
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 813
    .line 814
    .line 815
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 816
    .line 817
    .line 818
    move-result-object v3

    .line 819
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 820
    .line 821
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 822
    .line 823
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 824
    .line 825
    .line 826
    move-result-wide p2

    .line 827
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 828
    .line 829
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 830
    .line 831
    .line 832
    const/16 p4, 0x20

    .line 833
    .line 834
    shr-long v0, p2, p4

    .line 835
    .line 836
    long-to-int p4, v0

    .line 837
    const-wide v0, 0xffffffffL

    .line 838
    .line 839
    .line 840
    .line 841
    .line 842
    and-long/2addr p2, v0

    .line 843
    long-to-int p2, p2

    .line 844
    new-instance p3, Lc40/a;

    .line 845
    .line 846
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 847
    .line 848
    const/4 v0, 0x5

    .line 849
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 850
    .line 851
    .line 852
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 853
    .line 854
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 855
    .line 856
    .line 857
    move-result-object p0

    .line 858
    return-object p0

    .line 859
    :pswitch_e
    move-object v5, p2

    .line 860
    move-wide v1, p3

    .line 861
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 862
    .line 863
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 864
    .line 865
    .line 866
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 867
    .line 868
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 869
    .line 870
    .line 871
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 872
    .line 873
    .line 874
    move-result-object v3

    .line 875
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 876
    .line 877
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 878
    .line 879
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 880
    .line 881
    .line 882
    move-result-wide p2

    .line 883
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 884
    .line 885
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 886
    .line 887
    .line 888
    const/16 p4, 0x20

    .line 889
    .line 890
    shr-long v0, p2, p4

    .line 891
    .line 892
    long-to-int p4, v0

    .line 893
    const-wide v0, 0xffffffffL

    .line 894
    .line 895
    .line 896
    .line 897
    .line 898
    and-long/2addr p2, v0

    .line 899
    long-to-int p2, p2

    .line 900
    new-instance p3, Lc40/a;

    .line 901
    .line 902
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 903
    .line 904
    const/4 v0, 0x4

    .line 905
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 906
    .line 907
    .line 908
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 909
    .line 910
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 911
    .line 912
    .line 913
    move-result-object p0

    .line 914
    return-object p0

    .line 915
    :pswitch_f
    move-object v5, p2

    .line 916
    move-wide v1, p3

    .line 917
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 918
    .line 919
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 920
    .line 921
    .line 922
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 923
    .line 924
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 925
    .line 926
    .line 927
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 928
    .line 929
    .line 930
    move-result-object v3

    .line 931
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 932
    .line 933
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 934
    .line 935
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 936
    .line 937
    .line 938
    move-result-wide p2

    .line 939
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 940
    .line 941
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    const/16 p4, 0x20

    .line 945
    .line 946
    shr-long v0, p2, p4

    .line 947
    .line 948
    long-to-int p4, v0

    .line 949
    const-wide v0, 0xffffffffL

    .line 950
    .line 951
    .line 952
    .line 953
    .line 954
    and-long/2addr p2, v0

    .line 955
    long-to-int p2, p2

    .line 956
    new-instance p3, Lc40/a;

    .line 957
    .line 958
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 959
    .line 960
    const/4 v0, 0x3

    .line 961
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 962
    .line 963
    .line 964
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 965
    .line 966
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 967
    .line 968
    .line 969
    move-result-object p0

    .line 970
    return-object p0

    .line 971
    :pswitch_10
    move-object v5, p2

    .line 972
    move-wide v1, p3

    .line 973
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 974
    .line 975
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 976
    .line 977
    .line 978
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 979
    .line 980
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 981
    .line 982
    .line 983
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 984
    .line 985
    .line 986
    move-result-object v3

    .line 987
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 988
    .line 989
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 990
    .line 991
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 992
    .line 993
    .line 994
    move-result-wide p2

    .line 995
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 996
    .line 997
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 998
    .line 999
    .line 1000
    const/16 p4, 0x20

    .line 1001
    .line 1002
    shr-long v0, p2, p4

    .line 1003
    .line 1004
    long-to-int p4, v0

    .line 1005
    const-wide v0, 0xffffffffL

    .line 1006
    .line 1007
    .line 1008
    .line 1009
    .line 1010
    and-long/2addr p2, v0

    .line 1011
    long-to-int p2, p2

    .line 1012
    new-instance p3, Lc40/a;

    .line 1013
    .line 1014
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 1015
    .line 1016
    const/4 v0, 0x2

    .line 1017
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 1018
    .line 1019
    .line 1020
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 1021
    .line 1022
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 1023
    .line 1024
    .line 1025
    move-result-object p0

    .line 1026
    return-object p0

    .line 1027
    :pswitch_11
    move-object v5, p2

    .line 1028
    move-wide v1, p3

    .line 1029
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 1030
    .line 1031
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1032
    .line 1033
    .line 1034
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 1035
    .line 1036
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1037
    .line 1038
    .line 1039
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v3

    .line 1043
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 1044
    .line 1045
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 1046
    .line 1047
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 1048
    .line 1049
    .line 1050
    move-result-wide p2

    .line 1051
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 1052
    .line 1053
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1054
    .line 1055
    .line 1056
    const/16 p4, 0x20

    .line 1057
    .line 1058
    shr-long v0, p2, p4

    .line 1059
    .line 1060
    long-to-int p4, v0

    .line 1061
    const-wide v0, 0xffffffffL

    .line 1062
    .line 1063
    .line 1064
    .line 1065
    .line 1066
    and-long/2addr p2, v0

    .line 1067
    long-to-int p2, p2

    .line 1068
    new-instance p3, Lc40/a;

    .line 1069
    .line 1070
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 1071
    .line 1072
    const/4 v0, 0x1

    .line 1073
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 1074
    .line 1075
    .line 1076
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 1077
    .line 1078
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 1079
    .line 1080
    .line 1081
    move-result-object p0

    .line 1082
    return-object p0

    .line 1083
    :pswitch_12
    move-object v5, p2

    .line 1084
    move-wide v1, p3

    .line 1085
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 1086
    .line 1087
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 1088
    .line 1089
    .line 1090
    iget-object p2, p0, Lc40/b;->b:Ll2/b1;

    .line 1091
    .line 1092
    invoke-interface {p2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1093
    .line 1094
    .line 1095
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 1096
    .line 1097
    .line 1098
    move-result-object v3

    .line 1099
    iget-object v4, p0, Lc40/b;->d:Lz4/m;

    .line 1100
    .line 1101
    iget-object v0, p0, Lc40/b;->c:Lz4/p;

    .line 1102
    .line 1103
    invoke-virtual/range {v0 .. v6}, Lz4/p;->f(JLt4/m;Lz4/m;Ljava/util/List;Ljava/util/LinkedHashMap;)J

    .line 1104
    .line 1105
    .line 1106
    move-result-wide p2

    .line 1107
    iget-object p4, p0, Lc40/b;->e:Ll2/b1;

    .line 1108
    .line 1109
    invoke-interface {p4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1110
    .line 1111
    .line 1112
    const/16 p4, 0x20

    .line 1113
    .line 1114
    shr-long v0, p2, p4

    .line 1115
    .line 1116
    long-to-int p4, v0

    .line 1117
    const-wide v0, 0xffffffffL

    .line 1118
    .line 1119
    .line 1120
    .line 1121
    .line 1122
    and-long/2addr p2, v0

    .line 1123
    long-to-int p2, p2

    .line 1124
    new-instance p3, Lc40/a;

    .line 1125
    .line 1126
    iget-object p0, p0, Lc40/b;->c:Lz4/p;

    .line 1127
    .line 1128
    const/4 v0, 0x0

    .line 1129
    invoke-direct {p3, p0, v5, v6, v0}, Lc40/a;-><init>(Lz4/p;Ljava/util/List;Ljava/util/LinkedHashMap;I)V

    .line 1130
    .line 1131
    .line 1132
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 1133
    .line 1134
    invoke-interface {p1, p4, p2, p0, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 1135
    .line 1136
    .line 1137
    move-result-object p0

    .line 1138
    return-object p0

    .line 1139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
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
