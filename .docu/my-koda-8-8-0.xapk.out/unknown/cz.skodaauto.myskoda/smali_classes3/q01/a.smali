.class public final Lq01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lu01/i;

.field public static final c:Ljava/util/List;

.field public static final d:Lq01/a;


# instance fields
.field public final a:Lin/z1;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v1, v0, [B

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    const/16 v3, 0x2a

    .line 6
    .line 7
    aput-byte v3, v1, v2

    .line 8
    .line 9
    new-instance v3, Lu01/i;

    .line 10
    .line 11
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    const-string v4, "copyOf(...)"

    .line 16
    .line 17
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-direct {v3, v1}, Lu01/i;-><init>([B)V

    .line 21
    .line 22
    .line 23
    sput-object v3, Lq01/a;->b:Lu01/i;

    .line 24
    .line 25
    const-string v1, "*"

    .line 26
    .line 27
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    sput-object v1, Lq01/a;->c:Ljava/util/List;

    .line 32
    .line 33
    new-instance v1, Lq01/a;

    .line 34
    .line 35
    new-instance v3, Lin/z1;

    .line 36
    .line 37
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    new-instance v4, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 41
    .line 42
    invoke-direct {v4, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 43
    .line 44
    .line 45
    iput-object v4, v3, Lin/z1;->a:Ljava/lang/Object;

    .line 46
    .line 47
    new-instance v2, Ljava/util/concurrent/CountDownLatch;

    .line 48
    .line 49
    invoke-direct {v2, v0}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 50
    .line 51
    .line 52
    iput-object v2, v3, Lin/z1;->b:Ljava/lang/Object;

    .line 53
    .line 54
    const-string v0, "PublicSuffixDatabase.list"

    .line 55
    .line 56
    iput-object v0, v3, Lin/z1;->f:Ljava/lang/Object;

    .line 57
    .line 58
    invoke-direct {v1, v3}, Lq01/a;-><init>(Lin/z1;)V

    .line 59
    .line 60
    .line 61
    sput-object v1, Lq01/a;->d:Lq01/a;

    .line 62
    .line 63
    return-void
.end method

.method public constructor <init>(Lin/z1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq01/a;->a:Lin/z1;

    .line 5
    .line 6
    return-void
.end method

.method public static b(Ljava/lang/String;)Ljava/util/List;
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v0, v0, [C

    .line 3
    .line 4
    const/16 v1, 0x2e

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    aput-char v1, v0, v2

    .line 8
    .line 9
    invoke-static {p0, v0}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, ""

    .line 18
    .line 19
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-static {p0}, Lmx0/q;->E(Ljava/util/List;)Ljava/util/List;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    :cond_0
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Ljava/lang/String;
    .locals 12

    .line 1
    invoke-static {p1}, Ljava/net/IDN;->toUnicode(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lq01/a;->b(Ljava/lang/String;)Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Lq01/a;->a:Lin/z1;

    .line 13
    .line 14
    iget-object v1, p0, Lin/z1;->a:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/4 v3, 0x1

    .line 23
    const/4 v4, 0x0

    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    invoke-virtual {v1, v4, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    move v1, v4

    .line 33
    :goto_0
    :try_start_0
    invoke-virtual {p0}, Lin/z1;->T()V
    :try_end_0
    .catch Ljava/io/InterruptedIOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    .line 35
    .line 36
    if-eqz v1, :cond_2

    .line 37
    .line 38
    :goto_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-virtual {v1}, Ljava/lang/Thread;->interrupt()V

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_2

    .line 48
    :catch_0
    move-exception v2

    .line 49
    :try_start_1
    iput-object v2, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 50
    .line 51
    if-eqz v1, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :catch_1
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 55
    .line 56
    .line 57
    move v1, v3

    .line 58
    goto :goto_0

    .line 59
    :goto_2
    if-eqz v1, :cond_0

    .line 60
    .line 61
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p1}, Ljava/lang/Thread;->interrupt()V

    .line 66
    .line 67
    .line 68
    :cond_0
    throw p0

    .line 69
    :cond_1
    :try_start_2
    iget-object v1, p0, Lin/z1;->b:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v1, Ljava/util/concurrent/CountDownLatch;

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/util/concurrent/CountDownLatch;->await()V
    :try_end_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_2

    .line 74
    .line 75
    .line 76
    goto :goto_3

    .line 77
    :catch_2
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {v1}, Ljava/lang/Thread;->interrupt()V

    .line 82
    .line 83
    .line 84
    :cond_2
    :goto_3
    iget-object v1, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v1, Lu01/i;

    .line 87
    .line 88
    if-eqz v1, :cond_14

    .line 89
    .line 90
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    new-array v2, v1, [Lu01/i;

    .line 95
    .line 96
    move v5, v4

    .line 97
    :goto_4
    if-ge v5, v1, :cond_3

    .line 98
    .line 99
    sget-object v6, Lu01/i;->g:Lu01/i;

    .line 100
    .line 101
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    check-cast v6, Ljava/lang/String;

    .line 106
    .line 107
    invoke-static {v6}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 108
    .line 109
    .line 110
    move-result-object v6

    .line 111
    aput-object v6, v2, v5

    .line 112
    .line 113
    add-int/lit8 v5, v5, 0x1

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_3
    move v5, v4

    .line 117
    :goto_5
    const-string v6, "bytes"

    .line 118
    .line 119
    const/4 v7, 0x0

    .line 120
    if-ge v5, v1, :cond_6

    .line 121
    .line 122
    iget-object v8, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v8, Lu01/i;

    .line 125
    .line 126
    if-eqz v8, :cond_5

    .line 127
    .line 128
    invoke-static {v8, v2, v5}, Lip/v;->b(Lu01/i;[Lu01/i;I)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v8

    .line 132
    if-eqz v8, :cond_4

    .line 133
    .line 134
    goto :goto_6

    .line 135
    :cond_4
    add-int/lit8 v5, v5, 0x1

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_5
    invoke-static {v6}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw v7

    .line 142
    :cond_6
    move-object v8, v7

    .line 143
    :goto_6
    if-le v1, v3, :cond_9

    .line 144
    .line 145
    invoke-virtual {v2}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v5

    .line 149
    check-cast v5, [Lu01/i;

    .line 150
    .line 151
    array-length v9, v5

    .line 152
    sub-int/2addr v9, v3

    .line 153
    move v10, v4

    .line 154
    :goto_7
    if-ge v10, v9, :cond_9

    .line 155
    .line 156
    sget-object v11, Lq01/a;->b:Lu01/i;

    .line 157
    .line 158
    aput-object v11, v5, v10

    .line 159
    .line 160
    iget-object v11, p0, Lin/z1;->c:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v11, Lu01/i;

    .line 163
    .line 164
    if-eqz v11, :cond_8

    .line 165
    .line 166
    invoke-static {v11, v5, v10}, Lip/v;->b(Lu01/i;[Lu01/i;I)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v11

    .line 170
    if-eqz v11, :cond_7

    .line 171
    .line 172
    goto :goto_8

    .line 173
    :cond_7
    add-int/lit8 v10, v10, 0x1

    .line 174
    .line 175
    goto :goto_7

    .line 176
    :cond_8
    invoke-static {v6}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw v7

    .line 180
    :cond_9
    move-object v11, v7

    .line 181
    :goto_8
    if-eqz v11, :cond_c

    .line 182
    .line 183
    sub-int/2addr v1, v3

    .line 184
    move v5, v4

    .line 185
    :goto_9
    if-ge v5, v1, :cond_c

    .line 186
    .line 187
    iget-object v6, p0, Lin/z1;->d:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast v6, Lu01/i;

    .line 190
    .line 191
    if-eqz v6, :cond_b

    .line 192
    .line 193
    invoke-static {v6, v2, v5}, Lip/v;->b(Lu01/i;[Lu01/i;I)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v6

    .line 197
    if-eqz v6, :cond_a

    .line 198
    .line 199
    goto :goto_a

    .line 200
    :cond_a
    add-int/lit8 v5, v5, 0x1

    .line 201
    .line 202
    goto :goto_9

    .line 203
    :cond_b
    const-string p0, "exceptionBytes"

    .line 204
    .line 205
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw v7

    .line 209
    :cond_c
    move-object v6, v7

    .line 210
    :goto_a
    const/16 p0, 0x2e

    .line 211
    .line 212
    if-eqz v6, :cond_d

    .line 213
    .line 214
    const-string v1, "!"

    .line 215
    .line 216
    invoke-virtual {v1, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    new-array v2, v3, [C

    .line 221
    .line 222
    aput-char p0, v2, v4

    .line 223
    .line 224
    invoke-static {v1, v2}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    goto :goto_c

    .line 229
    :cond_d
    if-nez v8, :cond_e

    .line 230
    .line 231
    if-nez v11, :cond_e

    .line 232
    .line 233
    sget-object p0, Lq01/a;->c:Ljava/util/List;

    .line 234
    .line 235
    goto :goto_c

    .line 236
    :cond_e
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 237
    .line 238
    if-eqz v8, :cond_f

    .line 239
    .line 240
    new-array v2, v3, [C

    .line 241
    .line 242
    aput-char p0, v2, v4

    .line 243
    .line 244
    invoke-static {v8, v2}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 245
    .line 246
    .line 247
    move-result-object v2

    .line 248
    goto :goto_b

    .line 249
    :cond_f
    move-object v2, v1

    .line 250
    :goto_b
    if-eqz v11, :cond_10

    .line 251
    .line 252
    new-array v1, v3, [C

    .line 253
    .line 254
    aput-char p0, v1, v4

    .line 255
    .line 256
    invoke-static {v11, v1}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    :cond_10
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 265
    .line 266
    .line 267
    move-result v5

    .line 268
    if-le p0, v5, :cond_11

    .line 269
    .line 270
    move-object p0, v2

    .line 271
    goto :goto_c

    .line 272
    :cond_11
    move-object p0, v1

    .line 273
    :goto_c
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 278
    .line 279
    .line 280
    move-result v2

    .line 281
    const/16 v5, 0x21

    .line 282
    .line 283
    if-ne v1, v2, :cond_12

    .line 284
    .line 285
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    check-cast v1, Ljava/lang/String;

    .line 290
    .line 291
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    if-eq v1, v5, :cond_12

    .line 296
    .line 297
    return-object v7

    .line 298
    :cond_12
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v1

    .line 302
    check-cast v1, Ljava/lang/String;

    .line 303
    .line 304
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 305
    .line 306
    .line 307
    move-result v1

    .line 308
    if-ne v1, v5, :cond_13

    .line 309
    .line 310
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 311
    .line 312
    .line 313
    move-result v0

    .line 314
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 315
    .line 316
    .line 317
    move-result p0

    .line 318
    :goto_d
    sub-int/2addr v0, p0

    .line 319
    goto :goto_e

    .line 320
    :cond_13
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 321
    .line 322
    .line 323
    move-result v0

    .line 324
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 325
    .line 326
    .line 327
    move-result p0

    .line 328
    add-int/2addr p0, v3

    .line 329
    goto :goto_d

    .line 330
    :goto_e
    invoke-static {p1}, Lq01/a;->b(Ljava/lang/String;)Ljava/util/List;

    .line 331
    .line 332
    .line 333
    move-result-object p0

    .line 334
    check-cast p0, Ljava/lang/Iterable;

    .line 335
    .line 336
    invoke-static {p0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 337
    .line 338
    .line 339
    move-result-object p0

    .line 340
    invoke-static {p0, v0}, Lky0/l;->d(Lky0/j;I)Lky0/j;

    .line 341
    .line 342
    .line 343
    move-result-object p0

    .line 344
    const-string p1, "."

    .line 345
    .line 346
    invoke-static {p0, p1}, Lky0/l;->l(Lky0/j;Ljava/lang/String;)Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    return-object p0

    .line 351
    :cond_14
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 352
    .line 353
    new-instance v0, Ljava/lang/StringBuilder;

    .line 354
    .line 355
    const-string v1, "Unable to load "

    .line 356
    .line 357
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    iget-object v1, p0, Lin/z1;->f:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v1, Ljava/lang/String;

    .line 363
    .line 364
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 365
    .line 366
    .line 367
    const-string v1, " resource."

    .line 368
    .line 369
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 370
    .line 371
    .line 372
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 377
    .line 378
    .line 379
    iget-object p0, p0, Lin/z1;->e:Ljava/lang/Object;

    .line 380
    .line 381
    check-cast p0, Ljava/io/IOException;

    .line 382
    .line 383
    invoke-virtual {p1, p0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 384
    .line 385
    .line 386
    throw p1
.end method
