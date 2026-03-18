.class public final Lk01/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# static fields
.field public static final g:Ljava/util/logging/Logger;


# instance fields
.field public final d:Lu01/h;

.field public final e:Lk01/s;

.field public final f:Lk01/e;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lk01/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v1, "getLogger(...)"

    .line 12
    .line 13
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lk01/t;->g:Ljava/util/logging/Logger;

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>(Lu01/b0;)V
    .locals 1

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lk01/t;->d:Lu01/h;

    .line 10
    .line 11
    new-instance v0, Lk01/s;

    .line 12
    .line 13
    invoke-direct {v0, p1}, Lk01/s;-><init>(Lu01/h;)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lk01/t;->e:Lk01/s;

    .line 17
    .line 18
    new-instance p1, Lk01/e;

    .line 19
    .line 20
    invoke-direct {p1, v0}, Lk01/e;-><init>(Lk01/s;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lk01/t;->f:Lk01/e;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(ZLc41/f;)Z
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget-object v1, p0, Lk01/t;->d:Lu01/h;

    .line 3
    .line 4
    const-wide/16 v2, 0x9

    .line 5
    .line 6
    invoke-interface {v1, v2, v3}, Lu01/h;->e(J)V
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_1

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lk01/t;->d:Lu01/h;

    .line 10
    .line 11
    invoke-static {v1}, Le01/e;->o(Lu01/h;)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/16 v2, 0x4000

    .line 16
    .line 17
    if-gt v1, v2, :cond_2f

    .line 18
    .line 19
    iget-object v3, p0, Lk01/t;->d:Lu01/h;

    .line 20
    .line 21
    invoke-interface {v3}, Lu01/h;->readByte()B

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    and-int/lit16 v3, v3, 0xff

    .line 26
    .line 27
    iget-object v4, p0, Lk01/t;->d:Lu01/h;

    .line 28
    .line 29
    invoke-interface {v4}, Lu01/h;->readByte()B

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    and-int/lit16 v5, v4, 0xff

    .line 34
    .line 35
    iget-object v6, p0, Lk01/t;->d:Lu01/h;

    .line 36
    .line 37
    invoke-interface {v6}, Lu01/h;->readInt()I

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    const v7, 0x7fffffff

    .line 42
    .line 43
    .line 44
    and-int/2addr v7, v6

    .line 45
    const/16 v8, 0x8

    .line 46
    .line 47
    const/4 v9, 0x1

    .line 48
    if-eq v3, v8, :cond_0

    .line 49
    .line 50
    sget-object v10, Lk01/t;->g:Ljava/util/logging/Logger;

    .line 51
    .line 52
    sget-object v11, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 53
    .line 54
    invoke-virtual {v10, v11}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 55
    .line 56
    .line 57
    move-result v11

    .line 58
    if-eqz v11, :cond_0

    .line 59
    .line 60
    invoke-static {v7, v1, v3, v5, v9}, Lk01/h;->b(IIIIZ)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v11

    .line 64
    invoke-virtual {v10, v11}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_0
    const/4 v10, 0x4

    .line 68
    if-eqz p1, :cond_2

    .line 69
    .line 70
    if-ne v3, v10, :cond_1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 74
    .line 75
    new-instance p1, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    const-string p2, "Expected a SETTINGS frame but was "

    .line 78
    .line 79
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v3}, Lk01/h;->a(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_2
    :goto_0
    const/4 p1, 0x0

    .line 98
    const/4 v11, 0x5

    .line 99
    const/4 v12, 0x2

    .line 100
    packed-switch v3, :pswitch_data_0

    .line 101
    .line 102
    .line 103
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 104
    .line 105
    int-to-long p1, v1

    .line 106
    invoke-interface {p0, p1, p2}, Lu01/h;->skip(J)V

    .line 107
    .line 108
    .line 109
    return v9

    .line 110
    :pswitch_0
    const-string p1, "TYPE_WINDOW_UPDATE length !=4: "

    .line 111
    .line 112
    if-ne v1, v10, :cond_7

    .line 113
    .line 114
    :try_start_1
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 115
    .line 116
    invoke-interface {p0}, Lu01/h;->readInt()I

    .line 117
    .line 118
    .line 119
    move-result p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 120
    const-wide/32 v2, 0x7fffffff

    .line 121
    .line 122
    .line 123
    int-to-long p0, p0

    .line 124
    and-long/2addr p0, v2

    .line 125
    const-wide/16 v2, 0x0

    .line 126
    .line 127
    cmp-long v0, p0, v2

    .line 128
    .line 129
    if-eqz v0, :cond_6

    .line 130
    .line 131
    sget-object v2, Lk01/t;->g:Ljava/util/logging/Logger;

    .line 132
    .line 133
    sget-object v3, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 134
    .line 135
    invoke-virtual {v2, v3}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    if-eqz v3, :cond_3

    .line 140
    .line 141
    invoke-static {p0, p1, v7, v1, v9}, Lk01/h;->c(JIIZ)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    invoke-virtual {v2, v1}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    :cond_3
    if-nez v7, :cond_4

    .line 149
    .line 150
    iget-object p2, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast p2, Lk01/p;

    .line 153
    .line 154
    monitor-enter p2

    .line 155
    :try_start_2
    iget-wide v0, p2, Lk01/p;->x:J

    .line 156
    .line 157
    add-long/2addr v0, p0

    .line 158
    iput-wide v0, p2, Lk01/p;->x:J

    .line 159
    .line 160
    invoke-virtual {p2}, Ljava/lang/Object;->notifyAll()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 161
    .line 162
    .line 163
    monitor-exit p2

    .line 164
    return v9

    .line 165
    :catchall_0
    move-exception v0

    .line 166
    move-object p0, v0

    .line 167
    monitor-exit p2

    .line 168
    throw p0

    .line 169
    :cond_4
    iget-object p2, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast p2, Lk01/p;

    .line 172
    .line 173
    invoke-virtual {p2, v7}, Lk01/p;->b(I)Lk01/x;

    .line 174
    .line 175
    .line 176
    move-result-object p2

    .line 177
    if-eqz p2, :cond_29

    .line 178
    .line 179
    monitor-enter p2

    .line 180
    :try_start_3
    iget-wide v1, p2, Lk01/x;->h:J

    .line 181
    .line 182
    add-long/2addr v1, p0

    .line 183
    iput-wide v1, p2, Lk01/x;->h:J

    .line 184
    .line 185
    if-lez v0, :cond_5

    .line 186
    .line 187
    invoke-virtual {p2}, Ljava/lang/Object;->notifyAll()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 188
    .line 189
    .line 190
    :cond_5
    monitor-exit p2

    .line 191
    return v9

    .line 192
    :catchall_1
    move-exception v0

    .line 193
    move-object p0, v0

    .line 194
    monitor-exit p2

    .line 195
    throw p0

    .line 196
    :cond_6
    :try_start_4
    new-instance p0, Ljava/io/IOException;

    .line 197
    .line 198
    const-string p1, "windowSizeIncrement was 0"

    .line 199
    .line 200
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0

    .line 204
    :catch_0
    move-exception v0

    .line 205
    move-object p0, v0

    .line 206
    goto :goto_1

    .line 207
    :cond_7
    new-instance p0, Ljava/io/IOException;

    .line 208
    .line 209
    new-instance p2, Ljava/lang/StringBuilder;

    .line 210
    .line 211
    invoke-direct {p2, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p1

    .line 221
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p0
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 225
    :goto_1
    sget-object p1, Lk01/t;->g:Ljava/util/logging/Logger;

    .line 226
    .line 227
    invoke-static {v7, v1, v8, v5, v9}, Lk01/h;->b(IIIIZ)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object p2

    .line 231
    invoke-virtual {p1, p2}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    throw p0

    .line 235
    :pswitch_1
    if-lt v1, v8, :cond_f

    .line 236
    .line 237
    if-nez v7, :cond_e

    .line 238
    .line 239
    iget-object v2, p0, Lk01/t;->d:Lu01/h;

    .line 240
    .line 241
    invoke-interface {v2}, Lu01/h;->readInt()I

    .line 242
    .line 243
    .line 244
    move-result v2

    .line 245
    iget-object v3, p0, Lk01/t;->d:Lu01/h;

    .line 246
    .line 247
    invoke-interface {v3}, Lu01/h;->readInt()I

    .line 248
    .line 249
    .line 250
    move-result v3

    .line 251
    sub-int/2addr v1, v8

    .line 252
    sget-object v4, Lk01/b;->e:Lk01/a0;

    .line 253
    .line 254
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 255
    .line 256
    .line 257
    invoke-static {}, Lk01/b;->values()[Lk01/b;

    .line 258
    .line 259
    .line 260
    move-result-object v4

    .line 261
    array-length v5, v4

    .line 262
    move v6, v0

    .line 263
    :goto_2
    if-ge v6, v5, :cond_9

    .line 264
    .line 265
    aget-object v7, v4, v6

    .line 266
    .line 267
    iget v8, v7, Lk01/b;->d:I

    .line 268
    .line 269
    if-ne v8, v3, :cond_8

    .line 270
    .line 271
    move-object p1, v7

    .line 272
    goto :goto_3

    .line 273
    :cond_8
    add-int/lit8 v6, v6, 0x1

    .line 274
    .line 275
    goto :goto_2

    .line 276
    :cond_9
    :goto_3
    if-eqz p1, :cond_d

    .line 277
    .line 278
    sget-object p1, Lu01/i;->g:Lu01/i;

    .line 279
    .line 280
    if-lez v1, :cond_a

    .line 281
    .line 282
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 283
    .line 284
    int-to-long v3, v1

    .line 285
    invoke-interface {p0, v3, v4}, Lu01/h;->S(J)Lu01/i;

    .line 286
    .line 287
    .line 288
    move-result-object p1

    .line 289
    :cond_a
    const-string p0, "debugData"

    .line 290
    .line 291
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {p1}, Lu01/i;->d()I

    .line 295
    .line 296
    .line 297
    iget-object p0, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 298
    .line 299
    check-cast p0, Lk01/p;

    .line 300
    .line 301
    monitor-enter p0

    .line 302
    :try_start_5
    iget-object p1, p0, Lk01/p;->e:Ljava/util/LinkedHashMap;

    .line 303
    .line 304
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 305
    .line 306
    .line 307
    move-result-object p1

    .line 308
    new-array v1, v0, [Lk01/x;

    .line 309
    .line 310
    invoke-interface {p1, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object p1

    .line 314
    iput-boolean v9, p0, Lk01/p;->i:Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 315
    .line 316
    monitor-exit p0

    .line 317
    check-cast p1, [Lk01/x;

    .line 318
    .line 319
    array-length p0, p1

    .line 320
    :goto_4
    if-ge v0, p0, :cond_29

    .line 321
    .line 322
    aget-object v1, p1, v0

    .line 323
    .line 324
    iget v3, v1, Lk01/x;->d:I

    .line 325
    .line 326
    if-le v3, v2, :cond_c

    .line 327
    .line 328
    invoke-virtual {v1}, Lk01/x;->h()Z

    .line 329
    .line 330
    .line 331
    move-result v3

    .line 332
    if-eqz v3, :cond_c

    .line 333
    .line 334
    sget-object v3, Lk01/b;->j:Lk01/b;

    .line 335
    .line 336
    monitor-enter v1

    .line 337
    :try_start_6
    invoke-virtual {v1}, Lk01/x;->g()Lk01/b;

    .line 338
    .line 339
    .line 340
    move-result-object v4

    .line 341
    if-nez v4, :cond_b

    .line 342
    .line 343
    iput-object v3, v1, Lk01/x;->o:Lk01/b;

    .line 344
    .line 345
    invoke-virtual {v1}, Ljava/lang/Object;->notifyAll()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 346
    .line 347
    .line 348
    goto :goto_5

    .line 349
    :catchall_2
    move-exception v0

    .line 350
    move-object p0, v0

    .line 351
    goto :goto_6

    .line 352
    :cond_b
    :goto_5
    monitor-exit v1

    .line 353
    iget-object v3, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast v3, Lk01/p;

    .line 356
    .line 357
    iget v1, v1, Lk01/x;->d:I

    .line 358
    .line 359
    invoke-virtual {v3, v1}, Lk01/p;->d(I)Lk01/x;

    .line 360
    .line 361
    .line 362
    goto :goto_7

    .line 363
    :goto_6
    monitor-exit v1

    .line 364
    throw p0

    .line 365
    :cond_c
    :goto_7
    add-int/lit8 v0, v0, 0x1

    .line 366
    .line 367
    goto :goto_4

    .line 368
    :catchall_3
    move-exception v0

    .line 369
    move-object p1, v0

    .line 370
    monitor-exit p0

    .line 371
    throw p1

    .line 372
    :cond_d
    new-instance p0, Ljava/io/IOException;

    .line 373
    .line 374
    const-string p1, "TYPE_GOAWAY unexpected error code: "

    .line 375
    .line 376
    invoke-static {v3, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object p1

    .line 380
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    throw p0

    .line 384
    :cond_e
    new-instance p0, Ljava/io/IOException;

    .line 385
    .line 386
    const-string p1, "TYPE_GOAWAY streamId != 0"

    .line 387
    .line 388
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    throw p0

    .line 392
    :cond_f
    new-instance p0, Ljava/io/IOException;

    .line 393
    .line 394
    const-string p1, "TYPE_GOAWAY length < 8: "

    .line 395
    .line 396
    invoke-static {v1, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object p1

    .line 400
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    throw p0

    .line 404
    :pswitch_2
    if-ne v1, v8, :cond_16

    .line 405
    .line 406
    if-nez v7, :cond_15

    .line 407
    .line 408
    iget-object p1, p0, Lk01/t;->d:Lu01/h;

    .line 409
    .line 410
    invoke-interface {p1}, Lu01/h;->readInt()I

    .line 411
    .line 412
    .line 413
    move-result p1

    .line 414
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 415
    .line 416
    invoke-interface {p0}, Lu01/h;->readInt()I

    .line 417
    .line 418
    .line 419
    move-result p0

    .line 420
    and-int/lit8 v1, v4, 0x1

    .line 421
    .line 422
    if-eqz v1, :cond_10

    .line 423
    .line 424
    move v0, v9

    .line 425
    :cond_10
    if-eqz v0, :cond_14

    .line 426
    .line 427
    iget-object p0, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 428
    .line 429
    check-cast p0, Lk01/p;

    .line 430
    .line 431
    monitor-enter p0

    .line 432
    const-wide/16 v0, 0x1

    .line 433
    .line 434
    if-eq p1, v9, :cond_13

    .line 435
    .line 436
    if-eq p1, v12, :cond_12

    .line 437
    .line 438
    const/4 p2, 0x3

    .line 439
    if-eq p1, p2, :cond_11

    .line 440
    .line 441
    goto :goto_8

    .line 442
    :cond_11
    :try_start_7
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    .line 443
    .line 444
    .line 445
    goto :goto_8

    .line 446
    :catchall_4
    move-exception v0

    .line 447
    move-object p1, v0

    .line 448
    goto :goto_9

    .line 449
    :cond_12
    iget-wide p1, p0, Lk01/p;->q:J

    .line 450
    .line 451
    add-long/2addr p1, v0

    .line 452
    iput-wide p1, p0, Lk01/p;->q:J

    .line 453
    .line 454
    goto :goto_8

    .line 455
    :cond_13
    iget-wide p1, p0, Lk01/p;->o:J

    .line 456
    .line 457
    add-long/2addr p1, v0

    .line 458
    iput-wide p1, p0, Lk01/p;->o:J
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 459
    .line 460
    :goto_8
    monitor-exit p0

    .line 461
    return v9

    .line 462
    :goto_9
    monitor-exit p0

    .line 463
    throw p1

    .line 464
    :cond_14
    iget-object v0, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 465
    .line 466
    check-cast v0, Lk01/p;

    .line 467
    .line 468
    iget-object v1, v0, Lk01/p;->k:Lg01/b;

    .line 469
    .line 470
    new-instance v0, Ljava/lang/StringBuilder;

    .line 471
    .line 472
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 473
    .line 474
    .line 475
    iget-object v2, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 476
    .line 477
    check-cast v2, Lk01/p;

    .line 478
    .line 479
    iget-object v2, v2, Lk01/p;->f:Ljava/lang/String;

    .line 480
    .line 481
    const-string v3, " ping"

    .line 482
    .line 483
    invoke-static {v0, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 484
    .line 485
    .line 486
    move-result-object v2

    .line 487
    iget-object p2, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 488
    .line 489
    check-cast p2, Lk01/p;

    .line 490
    .line 491
    new-instance v5, Lk01/o;

    .line 492
    .line 493
    invoke-direct {v5, p2, p1, p0}, Lk01/o;-><init>(Lk01/p;II)V

    .line 494
    .line 495
    .line 496
    const/4 v6, 0x6

    .line 497
    const-wide/16 v3, 0x0

    .line 498
    .line 499
    invoke-static/range {v1 .. v6}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 500
    .line 501
    .line 502
    return v9

    .line 503
    :cond_15
    new-instance p0, Ljava/io/IOException;

    .line 504
    .line 505
    const-string p1, "TYPE_PING streamId != 0"

    .line 506
    .line 507
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 508
    .line 509
    .line 510
    throw p0

    .line 511
    :cond_16
    new-instance p0, Ljava/io/IOException;

    .line 512
    .line 513
    const-string p1, "TYPE_PING length != 8: "

    .line 514
    .line 515
    invoke-static {v1, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object p1

    .line 519
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 520
    .line 521
    .line 522
    throw p0

    .line 523
    :pswitch_3
    invoke-virtual {p0, p2, v1, v5, v7}, Lk01/t;->g(Lc41/f;III)V

    .line 524
    .line 525
    .line 526
    return v9

    .line 527
    :pswitch_4
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 528
    .line 529
    if-nez v7, :cond_24

    .line 530
    .line 531
    and-int/lit8 p1, v4, 0x1

    .line 532
    .line 533
    if-eqz p1, :cond_18

    .line 534
    .line 535
    if-nez v1, :cond_17

    .line 536
    .line 537
    goto/16 :goto_10

    .line 538
    .line 539
    :cond_17
    new-instance p0, Ljava/io/IOException;

    .line 540
    .line 541
    const-string p1, "FRAME_SIZE_ERROR ack frame should be empty!"

    .line 542
    .line 543
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 544
    .line 545
    .line 546
    throw p0

    .line 547
    :cond_18
    rem-int/lit8 p1, v1, 0x6

    .line 548
    .line 549
    if-nez p1, :cond_23

    .line 550
    .line 551
    new-instance p1, Lk01/b0;

    .line 552
    .line 553
    invoke-direct {p1}, Lk01/b0;-><init>()V

    .line 554
    .line 555
    .line 556
    invoke-static {v0, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 557
    .line 558
    .line 559
    move-result-object v0

    .line 560
    const/4 v1, 0x6

    .line 561
    invoke-static {v1, v0}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 562
    .line 563
    .line 564
    move-result-object v0

    .line 565
    iget v1, v0, Lgy0/h;->d:I

    .line 566
    .line 567
    iget v3, v0, Lgy0/h;->e:I

    .line 568
    .line 569
    iget v0, v0, Lgy0/h;->f:I

    .line 570
    .line 571
    if-lez v0, :cond_19

    .line 572
    .line 573
    if-le v1, v3, :cond_1a

    .line 574
    .line 575
    :cond_19
    if-gez v0, :cond_22

    .line 576
    .line 577
    if-gt v3, v1, :cond_22

    .line 578
    .line 579
    :cond_1a
    :goto_a
    invoke-interface {p0}, Lu01/h;->readShort()S

    .line 580
    .line 581
    .line 582
    move-result v4

    .line 583
    sget-object v5, Le01/e;->a:[B

    .line 584
    .line 585
    const v5, 0xffff

    .line 586
    .line 587
    .line 588
    and-int/2addr v4, v5

    .line 589
    invoke-interface {p0}, Lu01/h;->readInt()I

    .line 590
    .line 591
    .line 592
    move-result v5

    .line 593
    if-eq v4, v12, :cond_1f

    .line 594
    .line 595
    if-eq v4, v10, :cond_1d

    .line 596
    .line 597
    if-eq v4, v11, :cond_1b

    .line 598
    .line 599
    goto :goto_b

    .line 600
    :cond_1b
    if-lt v5, v2, :cond_1c

    .line 601
    .line 602
    const v6, 0xffffff

    .line 603
    .line 604
    .line 605
    if-gt v5, v6, :cond_1c

    .line 606
    .line 607
    goto :goto_b

    .line 608
    :cond_1c
    new-instance p0, Ljava/io/IOException;

    .line 609
    .line 610
    const-string p1, "PROTOCOL_ERROR SETTINGS_MAX_FRAME_SIZE: "

    .line 611
    .line 612
    invoke-static {v5, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 613
    .line 614
    .line 615
    move-result-object p1

    .line 616
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    throw p0

    .line 620
    :cond_1d
    if-ltz v5, :cond_1e

    .line 621
    .line 622
    goto :goto_b

    .line 623
    :cond_1e
    new-instance p0, Ljava/io/IOException;

    .line 624
    .line 625
    const-string p1, "PROTOCOL_ERROR SETTINGS_INITIAL_WINDOW_SIZE > 2^31 - 1"

    .line 626
    .line 627
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 628
    .line 629
    .line 630
    throw p0

    .line 631
    :cond_1f
    if-eqz v5, :cond_21

    .line 632
    .line 633
    if-ne v5, v9, :cond_20

    .line 634
    .line 635
    goto :goto_b

    .line 636
    :cond_20
    new-instance p0, Ljava/io/IOException;

    .line 637
    .line 638
    const-string p1, "PROTOCOL_ERROR SETTINGS_ENABLE_PUSH != 0 or 1"

    .line 639
    .line 640
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    throw p0

    .line 644
    :cond_21
    :goto_b
    invoke-virtual {p1, v4, v5}, Lk01/b0;->c(II)V

    .line 645
    .line 646
    .line 647
    if-eq v1, v3, :cond_22

    .line 648
    .line 649
    add-int/2addr v1, v0

    .line 650
    goto :goto_a

    .line 651
    :cond_22
    iget-object p0, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 652
    .line 653
    check-cast p0, Lk01/p;

    .line 654
    .line 655
    iget-object v0, p0, Lk01/p;->k:Lg01/b;

    .line 656
    .line 657
    new-instance v1, Ljava/lang/StringBuilder;

    .line 658
    .line 659
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 660
    .line 661
    .line 662
    iget-object p0, p0, Lk01/p;->f:Ljava/lang/String;

    .line 663
    .line 664
    const-string v2, " applyAndAckSettings"

    .line 665
    .line 666
    invoke-static {v1, p0, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 667
    .line 668
    .line 669
    move-result-object v1

    .line 670
    new-instance v4, Li2/t;

    .line 671
    .line 672
    const/16 p0, 0x15

    .line 673
    .line 674
    invoke-direct {v4, p0, p2, p1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 675
    .line 676
    .line 677
    const/4 v5, 0x6

    .line 678
    const-wide/16 v2, 0x0

    .line 679
    .line 680
    invoke-static/range {v0 .. v5}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 681
    .line 682
    .line 683
    return v9

    .line 684
    :cond_23
    new-instance p0, Ljava/io/IOException;

    .line 685
    .line 686
    const-string p1, "TYPE_SETTINGS length % 6 != 0: "

    .line 687
    .line 688
    invoke-static {v1, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 689
    .line 690
    .line 691
    move-result-object p1

    .line 692
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 693
    .line 694
    .line 695
    throw p0

    .line 696
    :cond_24
    new-instance p0, Ljava/io/IOException;

    .line 697
    .line 698
    const-string p1, "TYPE_SETTINGS streamId != 0"

    .line 699
    .line 700
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 701
    .line 702
    .line 703
    throw p0

    .line 704
    :pswitch_5
    if-ne v1, v10, :cond_2c

    .line 705
    .line 706
    if-eqz v7, :cond_2b

    .line 707
    .line 708
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 709
    .line 710
    invoke-interface {p0}, Lu01/h;->readInt()I

    .line 711
    .line 712
    .line 713
    move-result p0

    .line 714
    sget-object v1, Lk01/b;->e:Lk01/a0;

    .line 715
    .line 716
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 717
    .line 718
    .line 719
    invoke-static {}, Lk01/b;->values()[Lk01/b;

    .line 720
    .line 721
    .line 722
    move-result-object v1

    .line 723
    array-length v2, v1

    .line 724
    :goto_c
    if-ge v0, v2, :cond_26

    .line 725
    .line 726
    aget-object v3, v1, v0

    .line 727
    .line 728
    iget v4, v3, Lk01/b;->d:I

    .line 729
    .line 730
    if-ne v4, p0, :cond_25

    .line 731
    .line 732
    move-object p1, v3

    .line 733
    goto :goto_d

    .line 734
    :cond_25
    add-int/lit8 v0, v0, 0x1

    .line 735
    .line 736
    goto :goto_c

    .line 737
    :cond_26
    :goto_d
    if-eqz p1, :cond_2a

    .line 738
    .line 739
    iget-object p0, p2, Lc41/f;->f:Ljava/lang/Object;

    .line 740
    .line 741
    check-cast p0, Lk01/p;

    .line 742
    .line 743
    if-eqz v7, :cond_27

    .line 744
    .line 745
    and-int/lit8 p2, v6, 0x1

    .line 746
    .line 747
    if-nez p2, :cond_27

    .line 748
    .line 749
    iget-object v0, p0, Lk01/p;->l:Lg01/b;

    .line 750
    .line 751
    new-instance p2, Ljava/lang/StringBuilder;

    .line 752
    .line 753
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 754
    .line 755
    .line 756
    iget-object v1, p0, Lk01/p;->f:Ljava/lang/String;

    .line 757
    .line 758
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 759
    .line 760
    .line 761
    const/16 v1, 0x5b

    .line 762
    .line 763
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 764
    .line 765
    .line 766
    invoke-virtual {p2, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 767
    .line 768
    .line 769
    const-string v1, "] onReset"

    .line 770
    .line 771
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 772
    .line 773
    .line 774
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 775
    .line 776
    .line 777
    move-result-object v1

    .line 778
    new-instance v4, Lba0/h;

    .line 779
    .line 780
    invoke-direct {v4, p0, v7, p1}, Lba0/h;-><init>(Lk01/p;ILk01/b;)V

    .line 781
    .line 782
    .line 783
    const/4 v5, 0x6

    .line 784
    const-wide/16 v2, 0x0

    .line 785
    .line 786
    invoke-static/range {v0 .. v5}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 787
    .line 788
    .line 789
    return v9

    .line 790
    :cond_27
    invoke-virtual {p0, v7}, Lk01/p;->d(I)Lk01/x;

    .line 791
    .line 792
    .line 793
    move-result-object p0

    .line 794
    if-eqz p0, :cond_29

    .line 795
    .line 796
    monitor-enter p0

    .line 797
    :try_start_8
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 798
    .line 799
    .line 800
    move-result-object p2

    .line 801
    if-nez p2, :cond_28

    .line 802
    .line 803
    iput-object p1, p0, Lk01/x;->o:Lk01/b;

    .line 804
    .line 805
    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 806
    .line 807
    .line 808
    goto :goto_e

    .line 809
    :catchall_5
    move-exception v0

    .line 810
    move-object p1, v0

    .line 811
    goto :goto_f

    .line 812
    :cond_28
    :goto_e
    monitor-exit p0

    .line 813
    return v9

    .line 814
    :goto_f
    monitor-exit p0

    .line 815
    throw p1

    .line 816
    :cond_29
    :goto_10
    return v9

    .line 817
    :cond_2a
    new-instance p1, Ljava/io/IOException;

    .line 818
    .line 819
    const-string p2, "TYPE_RST_STREAM unexpected error code: "

    .line 820
    .line 821
    invoke-static {p0, p2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 822
    .line 823
    .line 824
    move-result-object p0

    .line 825
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    throw p1

    .line 829
    :cond_2b
    new-instance p0, Ljava/io/IOException;

    .line 830
    .line 831
    const-string p1, "TYPE_RST_STREAM streamId == 0"

    .line 832
    .line 833
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 834
    .line 835
    .line 836
    throw p0

    .line 837
    :cond_2c
    new-instance p0, Ljava/io/IOException;

    .line 838
    .line 839
    const-string p1, "TYPE_RST_STREAM length: "

    .line 840
    .line 841
    const-string p2, " != 4"

    .line 842
    .line 843
    invoke-static {p1, v1, p2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 844
    .line 845
    .line 846
    move-result-object p1

    .line 847
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 848
    .line 849
    .line 850
    throw p0

    .line 851
    :pswitch_6
    if-ne v1, v11, :cond_2e

    .line 852
    .line 853
    if-eqz v7, :cond_2d

    .line 854
    .line 855
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 856
    .line 857
    invoke-interface {p0}, Lu01/h;->readInt()I

    .line 858
    .line 859
    .line 860
    invoke-interface {p0}, Lu01/h;->readByte()B

    .line 861
    .line 862
    .line 863
    return v9

    .line 864
    :cond_2d
    new-instance p0, Ljava/io/IOException;

    .line 865
    .line 866
    const-string p1, "TYPE_PRIORITY streamId == 0"

    .line 867
    .line 868
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 869
    .line 870
    .line 871
    throw p0

    .line 872
    :cond_2e
    new-instance p0, Ljava/io/IOException;

    .line 873
    .line 874
    const-string p1, "TYPE_PRIORITY length: "

    .line 875
    .line 876
    const-string p2, " != 5"

    .line 877
    .line 878
    invoke-static {p1, v1, p2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 879
    .line 880
    .line 881
    move-result-object p1

    .line 882
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 883
    .line 884
    .line 885
    throw p0

    .line 886
    :pswitch_7
    invoke-virtual {p0, p2, v1, v5, v7}, Lk01/t;->f(Lc41/f;III)V

    .line 887
    .line 888
    .line 889
    return v9

    .line 890
    :pswitch_8
    invoke-virtual {p0, p2, v1, v5, v7}, Lk01/t;->b(Lc41/f;III)V

    .line 891
    .line 892
    .line 893
    return v9

    .line 894
    :cond_2f
    new-instance p0, Ljava/io/IOException;

    .line 895
    .line 896
    const-string p1, "FRAME_SIZE_ERROR: "

    .line 897
    .line 898
    invoke-static {v1, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 899
    .line 900
    .line 901
    move-result-object p1

    .line 902
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 903
    .line 904
    .line 905
    throw p0

    .line 906
    :catch_1
    return v0

    .line 907
    :pswitch_data_0
    .packed-switch 0x0
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

.method public final b(Lc41/f;III)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move/from16 v3, p4

    .line 8
    .line 9
    if-eqz v3, :cond_e

    .line 10
    .line 11
    and-int/lit8 v4, v2, 0x1

    .line 12
    .line 13
    const/4 v6, 0x1

    .line 14
    if-eqz v4, :cond_0

    .line 15
    .line 16
    move v4, v6

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v4, v6

    .line 19
    const/4 v6, 0x0

    .line 20
    :goto_0
    and-int/lit8 v7, v2, 0x20

    .line 21
    .line 22
    if-nez v7, :cond_d

    .line 23
    .line 24
    and-int/lit8 v7, v2, 0x8

    .line 25
    .line 26
    if-eqz v7, :cond_1

    .line 27
    .line 28
    iget-object v7, v0, Lk01/t;->d:Lu01/h;

    .line 29
    .line 30
    invoke-interface {v7}, Lu01/h;->readByte()B

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    sget-object v8, Le01/e;->a:[B

    .line 35
    .line 36
    and-int/lit16 v7, v7, 0xff

    .line 37
    .line 38
    :goto_1
    move/from16 v8, p2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_1
    const/4 v7, 0x0

    .line 42
    goto :goto_1

    .line 43
    :goto_2
    invoke-static {v8, v2, v7}, Lk01/r;->a(III)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    iget-object v8, v0, Lk01/t;->d:Lu01/h;

    .line 48
    .line 49
    const-string v9, "source"

    .line 50
    .line 51
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-object v9, v1, Lc41/f;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v9, Lk01/p;

    .line 57
    .line 58
    if-eqz v3, :cond_2

    .line 59
    .line 60
    and-int/lit8 v10, v3, 0x1

    .line 61
    .line 62
    if-nez v10, :cond_2

    .line 63
    .line 64
    new-instance v4, Lu01/f;

    .line 65
    .line 66
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 67
    .line 68
    .line 69
    int-to-long v10, v2

    .line 70
    invoke-interface {v8, v10, v11}, Lu01/h;->e(J)V

    .line 71
    .line 72
    .line 73
    invoke-interface {v8, v4, v10, v11}, Lu01/h0;->A(Lu01/f;J)J

    .line 74
    .line 75
    .line 76
    iget-object v12, v9, Lk01/p;->l:Lg01/b;

    .line 77
    .line 78
    new-instance v1, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 81
    .line 82
    .line 83
    iget-object v5, v9, Lk01/p;->f:Ljava/lang/String;

    .line 84
    .line 85
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const/16 v5, 0x5b

    .line 89
    .line 90
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string v5, "] onData"

    .line 97
    .line 98
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v13

    .line 105
    new-instance v16, Lk01/k;

    .line 106
    .line 107
    move v5, v2

    .line 108
    move-object v2, v9

    .line 109
    move-object/from16 v1, v16

    .line 110
    .line 111
    invoke-direct/range {v1 .. v6}, Lk01/k;-><init>(Lk01/p;ILu01/f;IZ)V

    .line 112
    .line 113
    .line 114
    const/16 v17, 0x6

    .line 115
    .line 116
    const-wide/16 v14, 0x0

    .line 117
    .line 118
    invoke-static/range {v12 .. v17}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 119
    .line 120
    .line 121
    goto/16 :goto_9

    .line 122
    .line 123
    :cond_2
    invoke-virtual {v9, v3}, Lk01/p;->b(I)Lk01/x;

    .line 124
    .line 125
    .line 126
    move-result-object v9

    .line 127
    if-nez v9, :cond_3

    .line 128
    .line 129
    iget-object v4, v1, Lc41/f;->f:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v4, Lk01/p;

    .line 132
    .line 133
    sget-object v5, Lk01/b;->g:Lk01/b;

    .line 134
    .line 135
    invoke-virtual {v4, v3, v5}, Lk01/p;->j(ILk01/b;)V

    .line 136
    .line 137
    .line 138
    iget-object v1, v1, Lc41/f;->f:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v1, Lk01/p;

    .line 141
    .line 142
    int-to-long v2, v2

    .line 143
    invoke-virtual {v1, v2, v3}, Lk01/p;->g(J)V

    .line 144
    .line 145
    .line 146
    invoke-interface {v8, v2, v3}, Lu01/h;->skip(J)V

    .line 147
    .line 148
    .line 149
    goto/16 :goto_9

    .line 150
    .line 151
    :cond_3
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 152
    .line 153
    iget-object v1, v9, Lk01/x;->k:Lk01/v;

    .line 154
    .line 155
    int-to-long v2, v2

    .line 156
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    move-wide v10, v2

    .line 160
    :goto_3
    const-wide/16 v12, 0x0

    .line 161
    .line 162
    cmp-long v14, v10, v12

    .line 163
    .line 164
    if-lez v14, :cond_b

    .line 165
    .line 166
    iget-object v14, v1, Lk01/v;->j:Lk01/x;

    .line 167
    .line 168
    monitor-enter v14

    .line 169
    :try_start_0
    iget-boolean v15, v1, Lk01/v;->e:Z

    .line 170
    .line 171
    iget-object v5, v1, Lk01/v;->g:Lu01/f;

    .line 172
    .line 173
    move-wide/from16 p1, v12

    .line 174
    .line 175
    iget-wide v12, v5, Lu01/f;->e:J

    .line 176
    .line 177
    add-long/2addr v12, v10

    .line 178
    iget-wide v4, v1, Lk01/v;->d:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 179
    .line 180
    cmp-long v4, v12, v4

    .line 181
    .line 182
    if-lez v4, :cond_4

    .line 183
    .line 184
    const/4 v4, 0x1

    .line 185
    goto :goto_4

    .line 186
    :cond_4
    const/4 v4, 0x0

    .line 187
    :goto_4
    monitor-exit v14

    .line 188
    if-eqz v4, :cond_5

    .line 189
    .line 190
    invoke-interface {v8, v10, v11}, Lu01/h;->skip(J)V

    .line 191
    .line 192
    .line 193
    iget-object v1, v1, Lk01/v;->j:Lk01/x;

    .line 194
    .line 195
    sget-object v2, Lk01/b;->i:Lk01/b;

    .line 196
    .line 197
    invoke-virtual {v1, v2}, Lk01/x;->f(Lk01/b;)V

    .line 198
    .line 199
    .line 200
    goto :goto_8

    .line 201
    :cond_5
    if-eqz v15, :cond_6

    .line 202
    .line 203
    invoke-interface {v8, v10, v11}, Lu01/h;->skip(J)V

    .line 204
    .line 205
    .line 206
    goto :goto_8

    .line 207
    :cond_6
    iget-object v4, v1, Lk01/v;->f:Lu01/f;

    .line 208
    .line 209
    invoke-interface {v8, v4, v10, v11}, Lu01/h0;->A(Lu01/f;J)J

    .line 210
    .line 211
    .line 212
    move-result-wide v4

    .line 213
    const-wide/16 v12, -0x1

    .line 214
    .line 215
    cmp-long v12, v4, v12

    .line 216
    .line 217
    if-eqz v12, :cond_a

    .line 218
    .line 219
    sub-long/2addr v10, v4

    .line 220
    iget-object v4, v1, Lk01/v;->j:Lk01/x;

    .line 221
    .line 222
    monitor-enter v4

    .line 223
    :try_start_1
    iget-boolean v5, v1, Lk01/v;->i:Z

    .line 224
    .line 225
    if-eqz v5, :cond_7

    .line 226
    .line 227
    iget-object v5, v1, Lk01/v;->f:Lu01/f;

    .line 228
    .line 229
    invoke-virtual {v5}, Lu01/f;->a()V

    .line 230
    .line 231
    .line 232
    goto :goto_6

    .line 233
    :catchall_0
    move-exception v0

    .line 234
    goto :goto_7

    .line 235
    :cond_7
    iget-object v5, v1, Lk01/v;->g:Lu01/f;

    .line 236
    .line 237
    iget-wide v12, v5, Lu01/f;->e:J

    .line 238
    .line 239
    cmp-long v12, v12, p1

    .line 240
    .line 241
    if-nez v12, :cond_8

    .line 242
    .line 243
    const/4 v12, 0x1

    .line 244
    goto :goto_5

    .line 245
    :cond_8
    const/4 v12, 0x0

    .line 246
    :goto_5
    iget-object v13, v1, Lk01/v;->f:Lu01/f;

    .line 247
    .line 248
    invoke-virtual {v5, v13}, Lu01/f;->P(Lu01/h0;)J

    .line 249
    .line 250
    .line 251
    if-eqz v12, :cond_9

    .line 252
    .line 253
    invoke-virtual {v4}, Ljava/lang/Object;->notifyAll()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 254
    .line 255
    .line 256
    :cond_9
    :goto_6
    monitor-exit v4

    .line 257
    const/4 v4, 0x1

    .line 258
    goto :goto_3

    .line 259
    :goto_7
    monitor-exit v4

    .line 260
    throw v0

    .line 261
    :cond_a
    new-instance v0, Ljava/io/EOFException;

    .line 262
    .line 263
    invoke-direct {v0}, Ljava/io/EOFException;-><init>()V

    .line 264
    .line 265
    .line 266
    throw v0

    .line 267
    :catchall_1
    move-exception v0

    .line 268
    monitor-exit v14

    .line 269
    throw v0

    .line 270
    :cond_b
    iget-object v4, v1, Lk01/v;->j:Lk01/x;

    .line 271
    .line 272
    sget-object v5, Le01/g;->a:Ljava/util/TimeZone;

    .line 273
    .line 274
    iget-object v4, v4, Lk01/x;->e:Lk01/p;

    .line 275
    .line 276
    invoke-virtual {v4, v2, v3}, Lk01/p;->g(J)V

    .line 277
    .line 278
    .line 279
    iget-object v1, v1, Lk01/v;->j:Lk01/x;

    .line 280
    .line 281
    iget-object v1, v1, Lk01/x;->e:Lk01/p;

    .line 282
    .line 283
    iget-object v1, v1, Lk01/p;->s:Lk01/c;

    .line 284
    .line 285
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 286
    .line 287
    .line 288
    :goto_8
    if-eqz v6, :cond_c

    .line 289
    .line 290
    sget-object v1, Ld01/y;->e:Ld01/y;

    .line 291
    .line 292
    const/4 v4, 0x1

    .line 293
    invoke-virtual {v9, v1, v4}, Lk01/x;->j(Ld01/y;Z)V

    .line 294
    .line 295
    .line 296
    :cond_c
    :goto_9
    iget-object v0, v0, Lk01/t;->d:Lu01/h;

    .line 297
    .line 298
    int-to-long v1, v7

    .line 299
    invoke-interface {v0, v1, v2}, Lu01/h;->skip(J)V

    .line 300
    .line 301
    .line 302
    return-void

    .line 303
    :cond_d
    new-instance v0, Ljava/io/IOException;

    .line 304
    .line 305
    const-string v1, "PROTOCOL_ERROR: FLAG_COMPRESSED without SETTINGS_COMPRESS_DATA"

    .line 306
    .line 307
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw v0

    .line 311
    :cond_e
    new-instance v0, Ljava/io/IOException;

    .line 312
    .line 313
    const-string v1, "PROTOCOL_ERROR: TYPE_DATA streamId == 0"

    .line 314
    .line 315
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    throw v0
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/t;->d:Lu01/h;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d(IIII)Ljava/util/List;
    .locals 2

    .line 1
    iget-object v0, p0, Lk01/t;->e:Lk01/s;

    .line 2
    .line 3
    iput p1, v0, Lk01/s;->h:I

    .line 4
    .line 5
    iput p1, v0, Lk01/s;->e:I

    .line 6
    .line 7
    iput p2, v0, Lk01/s;->i:I

    .line 8
    .line 9
    iput p3, v0, Lk01/s;->f:I

    .line 10
    .line 11
    iput p4, v0, Lk01/s;->g:I

    .line 12
    .line 13
    iget-object p0, p0, Lk01/t;->f:Lk01/e;

    .line 14
    .line 15
    iget-object p1, p0, Lk01/e;->c:Lu01/b0;

    .line 16
    .line 17
    iget-object p2, p0, Lk01/e;->b:Ljava/util/ArrayList;

    .line 18
    .line 19
    :cond_0
    :goto_0
    invoke-virtual {p1}, Lu01/b0;->Z()Z

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    if-nez p3, :cond_c

    .line 24
    .line 25
    invoke-virtual {p1}, Lu01/b0;->readByte()B

    .line 26
    .line 27
    .line 28
    move-result p3

    .line 29
    sget-object p4, Le01/e;->a:[B

    .line 30
    .line 31
    and-int/lit16 p4, p3, 0xff

    .line 32
    .line 33
    const/16 v0, 0x80

    .line 34
    .line 35
    if-eq p4, v0, :cond_b

    .line 36
    .line 37
    and-int/lit16 v1, p3, 0x80

    .line 38
    .line 39
    if-ne v1, v0, :cond_3

    .line 40
    .line 41
    const/16 p3, 0x7f

    .line 42
    .line 43
    invoke-virtual {p0, p4, p3}, Lk01/e;->e(II)I

    .line 44
    .line 45
    .line 46
    move-result p3

    .line 47
    add-int/lit8 p4, p3, -0x1

    .line 48
    .line 49
    if-ltz p4, :cond_1

    .line 50
    .line 51
    sget-object v0, Lk01/g;->a:[Lk01/d;

    .line 52
    .line 53
    array-length v1, v0

    .line 54
    add-int/lit8 v1, v1, -0x1

    .line 55
    .line 56
    if-gt p4, v1, :cond_1

    .line 57
    .line 58
    aget-object p3, v0, p4

    .line 59
    .line 60
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    sget-object v0, Lk01/g;->a:[Lk01/d;

    .line 65
    .line 66
    array-length v0, v0

    .line 67
    sub-int/2addr p4, v0

    .line 68
    iget v0, p0, Lk01/e;->e:I

    .line 69
    .line 70
    add-int/lit8 v0, v0, 0x1

    .line 71
    .line 72
    add-int/2addr v0, p4

    .line 73
    if-ltz v0, :cond_2

    .line 74
    .line 75
    iget-object p4, p0, Lk01/e;->d:[Lk01/d;

    .line 76
    .line 77
    array-length v1, p4

    .line 78
    if-ge v0, v1, :cond_2

    .line 79
    .line 80
    aget-object p3, p4, v0

    .line 81
    .line 82
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 90
    .line 91
    const-string p1, "Header index too large "

    .line 92
    .line 93
    invoke-static {p3, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :cond_3
    const/16 v0, 0x40

    .line 102
    .line 103
    if-ne p4, v0, :cond_4

    .line 104
    .line 105
    sget-object p3, Lk01/g;->a:[Lk01/d;

    .line 106
    .line 107
    invoke-virtual {p0}, Lk01/e;->d()Lu01/i;

    .line 108
    .line 109
    .line 110
    move-result-object p3

    .line 111
    invoke-static {p3}, Lk01/g;->a(Lu01/i;)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {p0}, Lk01/e;->d()Lu01/i;

    .line 115
    .line 116
    .line 117
    move-result-object p4

    .line 118
    new-instance v0, Lk01/d;

    .line 119
    .line 120
    invoke-direct {v0, p3, p4}, Lk01/d;-><init>(Lu01/i;Lu01/i;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p0, v0}, Lk01/e;->c(Lk01/d;)V

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :cond_4
    and-int/lit8 v1, p3, 0x40

    .line 128
    .line 129
    if-ne v1, v0, :cond_5

    .line 130
    .line 131
    const/16 p3, 0x3f

    .line 132
    .line 133
    invoke-virtual {p0, p4, p3}, Lk01/e;->e(II)I

    .line 134
    .line 135
    .line 136
    move-result p3

    .line 137
    add-int/lit8 p3, p3, -0x1

    .line 138
    .line 139
    invoke-virtual {p0, p3}, Lk01/e;->b(I)Lu01/i;

    .line 140
    .line 141
    .line 142
    move-result-object p3

    .line 143
    invoke-virtual {p0}, Lk01/e;->d()Lu01/i;

    .line 144
    .line 145
    .line 146
    move-result-object p4

    .line 147
    new-instance v0, Lk01/d;

    .line 148
    .line 149
    invoke-direct {v0, p3, p4}, Lk01/d;-><init>(Lu01/i;Lu01/i;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p0, v0}, Lk01/e;->c(Lk01/d;)V

    .line 153
    .line 154
    .line 155
    goto/16 :goto_0

    .line 156
    .line 157
    :cond_5
    and-int/lit8 p3, p3, 0x20

    .line 158
    .line 159
    const/16 v0, 0x20

    .line 160
    .line 161
    if-ne p3, v0, :cond_8

    .line 162
    .line 163
    const/16 p3, 0x1f

    .line 164
    .line 165
    invoke-virtual {p0, p4, p3}, Lk01/e;->e(II)I

    .line 166
    .line 167
    .line 168
    move-result p3

    .line 169
    iput p3, p0, Lk01/e;->a:I

    .line 170
    .line 171
    if-ltz p3, :cond_7

    .line 172
    .line 173
    const/16 p4, 0x1000

    .line 174
    .line 175
    if-gt p3, p4, :cond_7

    .line 176
    .line 177
    iget p4, p0, Lk01/e;->g:I

    .line 178
    .line 179
    if-ge p3, p4, :cond_0

    .line 180
    .line 181
    if-nez p3, :cond_6

    .line 182
    .line 183
    iget-object p3, p0, Lk01/e;->d:[Lk01/d;

    .line 184
    .line 185
    const/4 p4, 0x0

    .line 186
    invoke-static {p3, p4}, Lmx0/n;->s([Ljava/lang/Object;Lj51/i;)V

    .line 187
    .line 188
    .line 189
    iget-object p3, p0, Lk01/e;->d:[Lk01/d;

    .line 190
    .line 191
    array-length p3, p3

    .line 192
    add-int/lit8 p3, p3, -0x1

    .line 193
    .line 194
    iput p3, p0, Lk01/e;->e:I

    .line 195
    .line 196
    const/4 p3, 0x0

    .line 197
    iput p3, p0, Lk01/e;->f:I

    .line 198
    .line 199
    iput p3, p0, Lk01/e;->g:I

    .line 200
    .line 201
    goto/16 :goto_0

    .line 202
    .line 203
    :cond_6
    sub-int/2addr p4, p3

    .line 204
    invoke-virtual {p0, p4}, Lk01/e;->a(I)I

    .line 205
    .line 206
    .line 207
    goto/16 :goto_0

    .line 208
    .line 209
    :cond_7
    new-instance p1, Ljava/io/IOException;

    .line 210
    .line 211
    new-instance p2, Ljava/lang/StringBuilder;

    .line 212
    .line 213
    const-string p3, "Invalid dynamic table size update "

    .line 214
    .line 215
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    iget p0, p0, Lk01/e;->a:I

    .line 219
    .line 220
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw p1

    .line 231
    :cond_8
    const/16 p3, 0x10

    .line 232
    .line 233
    if-eq p4, p3, :cond_a

    .line 234
    .line 235
    if-nez p4, :cond_9

    .line 236
    .line 237
    goto :goto_1

    .line 238
    :cond_9
    const/16 p3, 0xf

    .line 239
    .line 240
    invoke-virtual {p0, p4, p3}, Lk01/e;->e(II)I

    .line 241
    .line 242
    .line 243
    move-result p3

    .line 244
    add-int/lit8 p3, p3, -0x1

    .line 245
    .line 246
    invoke-virtual {p0, p3}, Lk01/e;->b(I)Lu01/i;

    .line 247
    .line 248
    .line 249
    move-result-object p3

    .line 250
    invoke-virtual {p0}, Lk01/e;->d()Lu01/i;

    .line 251
    .line 252
    .line 253
    move-result-object p4

    .line 254
    new-instance v0, Lk01/d;

    .line 255
    .line 256
    invoke-direct {v0, p3, p4}, Lk01/d;-><init>(Lu01/i;Lu01/i;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    goto/16 :goto_0

    .line 263
    .line 264
    :cond_a
    :goto_1
    sget-object p3, Lk01/g;->a:[Lk01/d;

    .line 265
    .line 266
    invoke-virtual {p0}, Lk01/e;->d()Lu01/i;

    .line 267
    .line 268
    .line 269
    move-result-object p3

    .line 270
    invoke-static {p3}, Lk01/g;->a(Lu01/i;)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {p0}, Lk01/e;->d()Lu01/i;

    .line 274
    .line 275
    .line 276
    move-result-object p4

    .line 277
    new-instance v0, Lk01/d;

    .line 278
    .line 279
    invoke-direct {v0, p3, p4}, Lk01/d;-><init>(Lu01/i;Lu01/i;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    goto/16 :goto_0

    .line 286
    .line 287
    :cond_b
    new-instance p0, Ljava/io/IOException;

    .line 288
    .line 289
    const-string p1, "index == 0"

    .line 290
    .line 291
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    throw p0

    .line 295
    :cond_c
    invoke-static {p2}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 296
    .line 297
    .line 298
    move-result-object p0

    .line 299
    invoke-virtual {p2}, Ljava/util/ArrayList;->clear()V

    .line 300
    .line 301
    .line 302
    return-object p0
.end method

.method public final f(Lc41/f;III)V
    .locals 11

    .line 1
    if-eqz p4, :cond_8

    .line 2
    .line 3
    and-int/lit8 v2, p3, 0x1

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    if-eqz v2, :cond_0

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    move v4, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v4, v3

    .line 12
    :goto_0
    and-int/lit8 v2, p3, 0x8

    .line 13
    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    iget-object v2, p0, Lk01/t;->d:Lu01/h;

    .line 17
    .line 18
    invoke-interface {v2}, Lu01/h;->readByte()B

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    sget-object v3, Le01/e;->a:[B

    .line 23
    .line 24
    and-int/lit16 v3, v2, 0xff

    .line 25
    .line 26
    :cond_1
    and-int/lit8 v2, p3, 0x20

    .line 27
    .line 28
    if-eqz v2, :cond_2

    .line 29
    .line 30
    iget-object v2, p0, Lk01/t;->d:Lu01/h;

    .line 31
    .line 32
    invoke-interface {v2}, Lu01/h;->readInt()I

    .line 33
    .line 34
    .line 35
    invoke-interface {v2}, Lu01/h;->readByte()B

    .line 36
    .line 37
    .line 38
    sget-object v2, Le01/e;->a:[B

    .line 39
    .line 40
    add-int/lit8 v2, p2, -0x5

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    move v2, p2

    .line 44
    :goto_1
    invoke-static {v2, p3, v3}, Lk01/r;->a(III)I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    invoke-virtual {p0, v2, v3, p3, p4}, Lk01/t;->d(IIII)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    iget-object p1, p1, Lc41/f;->f:Ljava/lang/Object;

    .line 53
    .line 54
    move-object v2, p1

    .line 55
    check-cast v2, Lk01/p;

    .line 56
    .line 57
    const/16 p1, 0x5b

    .line 58
    .line 59
    if-eqz p4, :cond_3

    .line 60
    .line 61
    and-int/lit8 v0, p4, 0x1

    .line 62
    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    iget-object v5, v2, Lk01/p;->l:Lg01/b;

    .line 66
    .line 67
    new-instance v0, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 70
    .line 71
    .line 72
    iget-object v3, v2, Lk01/p;->f:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string p1, "] onHeaders"

    .line 84
    .line 85
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    new-instance v9, Lk01/l;

    .line 93
    .line 94
    invoke-direct {v9, v2, p4, p0, v4}, Lk01/l;-><init>(Lk01/p;ILjava/util/List;Z)V

    .line 95
    .line 96
    .line 97
    const/4 v10, 0x6

    .line 98
    const-wide/16 v7, 0x0

    .line 99
    .line 100
    invoke-static/range {v5 .. v10}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :cond_3
    monitor-enter v2

    .line 105
    :try_start_0
    invoke-virtual {v2, p4}, Lk01/p;->b(I)Lk01/x;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    if-nez v0, :cond_7

    .line 110
    .line 111
    iget-boolean v0, v2, Lk01/p;->i:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 112
    .line 113
    if-eqz v0, :cond_4

    .line 114
    .line 115
    monitor-exit v2

    .line 116
    return-void

    .line 117
    :cond_4
    :try_start_1
    iget v0, v2, Lk01/p;->g:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 118
    .line 119
    if-gt p4, v0, :cond_5

    .line 120
    .line 121
    monitor-exit v2

    .line 122
    return-void

    .line 123
    :cond_5
    :try_start_2
    rem-int/lit8 v0, p4, 0x2

    .line 124
    .line 125
    iget v3, v2, Lk01/p;->h:I

    .line 126
    .line 127
    rem-int/lit8 v3, v3, 0x2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 128
    .line 129
    if-ne v0, v3, :cond_6

    .line 130
    .line 131
    monitor-exit v2

    .line 132
    return-void

    .line 133
    :cond_6
    :try_start_3
    invoke-static {p0}, Le01/g;->h(Ljava/util/List;)Ld01/y;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    new-instance v0, Lk01/x;

    .line 138
    .line 139
    const/4 v3, 0x0

    .line 140
    move v1, p4

    .line 141
    invoke-direct/range {v0 .. v5}, Lk01/x;-><init>(ILk01/p;ZZLd01/y;)V

    .line 142
    .line 143
    .line 144
    iput p4, v2, Lk01/p;->g:I

    .line 145
    .line 146
    iget-object p0, v2, Lk01/p;->e:Ljava/util/LinkedHashMap;

    .line 147
    .line 148
    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    invoke-interface {p0, v3, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    iget-object p0, v2, Lk01/p;->j:Lg01/c;

    .line 156
    .line 157
    invoke-virtual {p0}, Lg01/c;->d()Lg01/b;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    new-instance p0, Ljava/lang/StringBuilder;

    .line 162
    .line 163
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 164
    .line 165
    .line 166
    iget-object v4, v2, Lk01/p;->f:Ljava/lang/String;

    .line 167
    .line 168
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    const-string p1, "] onStream"

    .line 178
    .line 179
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v4

    .line 186
    new-instance v7, Li2/t;

    .line 187
    .line 188
    const/16 p0, 0x14

    .line 189
    .line 190
    invoke-direct {v7, p0, v2, v0}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    const/4 v8, 0x6

    .line 194
    const-wide/16 v5, 0x0

    .line 195
    .line 196
    invoke-static/range {v3 .. v8}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 197
    .line 198
    .line 199
    monitor-exit v2

    .line 200
    return-void

    .line 201
    :catchall_0
    move-exception v0

    .line 202
    move-object p0, v0

    .line 203
    goto :goto_2

    .line 204
    :cond_7
    monitor-exit v2

    .line 205
    invoke-static {p0}, Le01/g;->h(Ljava/util/List;)Ld01/y;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-virtual {v0, p0, v4}, Lk01/x;->j(Ld01/y;Z)V

    .line 210
    .line 211
    .line 212
    return-void

    .line 213
    :goto_2
    monitor-exit v2

    .line 214
    throw p0

    .line 215
    :cond_8
    new-instance p0, Ljava/io/IOException;

    .line 216
    .line 217
    const-string p1, "PROTOCOL_ERROR: TYPE_HEADERS streamId == 0"

    .line 218
    .line 219
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    throw p0
.end method

.method public final g(Lc41/f;III)V
    .locals 8

    .line 1
    if-eqz p4, :cond_2

    .line 2
    .line 3
    and-int/lit8 v0, p3, 0x8

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lk01/t;->d:Lu01/h;

    .line 8
    .line 9
    invoke-interface {v0}, Lu01/h;->readByte()B

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    sget-object v1, Le01/e;->a:[B

    .line 14
    .line 15
    and-int/lit16 v0, v0, 0xff

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v0, 0x0

    .line 19
    :goto_0
    iget-object v1, p0, Lk01/t;->d:Lu01/h;

    .line 20
    .line 21
    invoke-interface {v1}, Lu01/h;->readInt()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const v2, 0x7fffffff

    .line 26
    .line 27
    .line 28
    and-int/2addr v1, v2

    .line 29
    add-int/lit8 p2, p2, -0x4

    .line 30
    .line 31
    invoke-static {p2, p3, v0}, Lk01/r;->a(III)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    invoke-virtual {p0, p2, v0, p3, p4}, Lk01/t;->d(IIII)Ljava/util/List;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    iget-object p1, p1, Lc41/f;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Lk01/p;

    .line 42
    .line 43
    monitor-enter p1

    .line 44
    :try_start_0
    iget-object p2, p1, Lk01/p;->B:Ljava/util/LinkedHashSet;

    .line 45
    .line 46
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 47
    .line 48
    .line 49
    move-result-object p3

    .line 50
    invoke-interface {p2, p3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    if-eqz p2, :cond_1

    .line 55
    .line 56
    sget-object p0, Lk01/b;->g:Lk01/b;

    .line 57
    .line 58
    invoke-virtual {p1, v1, p0}, Lk01/p;->j(ILk01/b;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    monitor-exit p1

    .line 62
    return-void

    .line 63
    :catchall_0
    move-exception v0

    .line 64
    move-object p0, v0

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    :try_start_1
    iget-object p2, p1, Lk01/p;->B:Ljava/util/LinkedHashSet;

    .line 67
    .line 68
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object p3

    .line 72
    invoke-interface {p2, p3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    .line 74
    .line 75
    monitor-exit p1

    .line 76
    iget-object v2, p1, Lk01/p;->l:Lg01/b;

    .line 77
    .line 78
    new-instance p2, Ljava/lang/StringBuilder;

    .line 79
    .line 80
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 81
    .line 82
    .line 83
    iget-object p3, p1, Lk01/p;->f:Ljava/lang/String;

    .line 84
    .line 85
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const/16 p3, 0x5b

    .line 89
    .line 90
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string p3, "] onRequest"

    .line 97
    .line 98
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    new-instance v6, Lk01/l;

    .line 106
    .line 107
    invoke-direct {v6, p1, v1, p0}, Lk01/l;-><init>(Lk01/p;ILjava/util/List;)V

    .line 108
    .line 109
    .line 110
    const/4 v7, 0x6

    .line 111
    const-wide/16 v4, 0x0

    .line 112
    .line 113
    invoke-static/range {v2 .. v7}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 114
    .line 115
    .line 116
    return-void

    .line 117
    :goto_1
    monitor-exit p1

    .line 118
    throw p0

    .line 119
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 120
    .line 121
    const-string p1, "PROTOCOL_ERROR: TYPE_PUSH_PROMISE streamId == 0"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0
.end method
