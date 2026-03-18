.class public final Ld01/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/util/concurrent/ExecutorService;

.field public final b:Ljava/util/ArrayDeque;

.field public final c:Ljava/util/ArrayDeque;

.field public final d:Ljava/util/ArrayDeque;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 3
    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 4
    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Ld01/t;->d:Ljava/util/ArrayDeque;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/ExecutorService;)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ld01/t;-><init>()V

    .line 6
    iput-object p1, p0, Ld01/t;->a:Ljava/util/concurrent/ExecutorService;

    return-void
.end method

.method public static d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V
    .locals 8

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object p1, v1

    .line 7
    :cond_0
    and-int/lit8 v0, p4, 0x2

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    move-object p2, v1

    .line 12
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 13
    .line 14
    if-eqz p4, :cond_2

    .line 15
    .line 16
    move-object p3, v1

    .line 17
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    sget-object p4, Le01/g;->a:Ljava/util/TimeZone;

    .line 21
    .line 22
    invoke-virtual {p0}, Ld01/t;->b()Ljava/util/concurrent/ExecutorService;

    .line 23
    .line 24
    .line 25
    move-result-object p4

    .line 26
    invoke-interface {p4}, Ljava/util/concurrent/ExecutorService;->isShutdown()Z

    .line 27
    .line 28
    .line 29
    move-result p4

    .line 30
    monitor-enter p0

    .line 31
    if-eqz p2, :cond_4

    .line 32
    .line 33
    :try_start_0
    iget-object v0, p0, Ld01/t;->d:Ljava/util/ArrayDeque;

    .line 34
    .line 35
    invoke-virtual {v0, p2}, Ljava/util/ArrayDeque;->remove(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_3
    const-string p1, "Call wasn\'t in-flight!"

    .line 43
    .line 44
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p2

    .line 50
    :catchall_0
    move-exception p1

    .line 51
    goto/16 :goto_8

    .line 52
    .line 53
    :cond_4
    :goto_0
    if-eqz p3, :cond_6

    .line 54
    .line 55
    iget-object v0, p3, Lh01/l;->e:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 61
    .line 62
    invoke-virtual {v0, p3}, Ljava/util/ArrayDeque;->remove(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_5

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_5
    const-string p1, "Call wasn\'t in-flight!"

    .line 70
    .line 71
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 72
    .line 73
    invoke-direct {p2, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p2

    .line 77
    :cond_6
    :goto_1
    if-eqz p1, :cond_7

    .line 78
    .line 79
    iget-object v0, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 80
    .line 81
    invoke-virtual {v0, p1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    iget-object v0, p1, Lh01/l;->f:Lh01/o;

    .line 85
    .line 86
    iget-boolean v2, v0, Lh01/o;->f:Z

    .line 87
    .line 88
    if-nez v2, :cond_7

    .line 89
    .line 90
    iget-object v0, v0, Lh01/o;->e:Ld01/k0;

    .line 91
    .line 92
    iget-object v0, v0, Ld01/k0;->a:Ld01/a0;

    .line 93
    .line 94
    iget-object v0, v0, Ld01/a0;->d:Ljava/lang/String;

    .line 95
    .line 96
    invoke-virtual {p0, v0}, Ld01/t;->c(Ljava/lang/String;)Lh01/l;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    if-eqz v0, :cond_7

    .line 101
    .line 102
    iget-object v0, v0, Lh01/l;->e:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 103
    .line 104
    iput-object v0, p1, Lh01/l;->e:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 105
    .line 106
    :cond_7
    if-nez p2, :cond_8

    .line 107
    .line 108
    if-eqz p3, :cond_a

    .line 109
    .line 110
    :cond_8
    if-nez p4, :cond_9

    .line 111
    .line 112
    iget-object p2, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 113
    .line 114
    invoke-virtual {p2}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    if-eqz p2, :cond_a

    .line 119
    .line 120
    :cond_9
    iget-object p2, p0, Ld01/t;->d:Ljava/util/ArrayDeque;

    .line 121
    .line 122
    invoke-virtual {p2}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 123
    .line 124
    .line 125
    :cond_a
    if-eqz p4, :cond_b

    .line 126
    .line 127
    iget-object p2, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 128
    .line 129
    invoke-static {p2}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    iget-object p3, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 134
    .line 135
    invoke-virtual {p3}, Ljava/util/ArrayDeque;->clear()V

    .line 136
    .line 137
    .line 138
    new-instance p3, Ld01/s;

    .line 139
    .line 140
    invoke-direct {p3, p2}, Ld01/s;-><init>(Ljava/util/List;)V

    .line 141
    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_b
    new-instance p2, Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 147
    .line 148
    .line 149
    iget-object p3, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 150
    .line 151
    invoke-virtual {p3}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 152
    .line 153
    .line 154
    move-result-object p3

    .line 155
    const-string v0, "iterator(...)"

    .line 156
    .line 157
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    :cond_c
    :goto_2
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 161
    .line 162
    .line 163
    move-result v0

    .line 164
    if-eqz v0, :cond_d

    .line 165
    .line 166
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    check-cast v0, Lh01/l;

    .line 171
    .line 172
    iget-object v2, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 173
    .line 174
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->size()I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    const/16 v3, 0x40

    .line 179
    .line 180
    if-ge v2, v3, :cond_d

    .line 181
    .line 182
    iget-object v2, v0, Lh01/l;->e:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 183
    .line 184
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    const/4 v3, 0x5

    .line 189
    if-ge v2, v3, :cond_c

    .line 190
    .line 191
    invoke-interface {p3}, Ljava/util/Iterator;->remove()V

    .line 192
    .line 193
    .line 194
    iget-object v2, v0, Lh01/l;->e:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 195
    .line 196
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 197
    .line 198
    .line 199
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    iget-object v2, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 203
    .line 204
    invoke-virtual {v2, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    goto :goto_2

    .line 208
    :cond_d
    new-instance p3, Ld01/s;

    .line 209
    .line 210
    invoke-direct {p3, p2}, Ld01/s;-><init>(Ljava/util/List;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 211
    .line 212
    .line 213
    :goto_3
    monitor-exit p0

    .line 214
    iget-object p2, p3, Ld01/s;->d:Ljava/util/List;

    .line 215
    .line 216
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 217
    .line 218
    .line 219
    move-result p2

    .line 220
    const/4 v0, 0x0

    .line 221
    :goto_4
    if-ge v0, p2, :cond_10

    .line 222
    .line 223
    iget-object v2, p3, Ld01/s;->d:Ljava/util/List;

    .line 224
    .line 225
    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v2

    .line 229
    check-cast v2, Lh01/l;

    .line 230
    .line 231
    if-ne v2, p1, :cond_e

    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_e
    iget-object v3, v2, Lh01/l;->f:Lh01/o;

    .line 235
    .line 236
    :goto_5
    if-eqz p4, :cond_f

    .line 237
    .line 238
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 239
    .line 240
    .line 241
    new-instance v3, Ljava/io/InterruptedIOException;

    .line 242
    .line 243
    const-string v4, "executor rejected"

    .line 244
    .line 245
    invoke-direct {v3, v4}, Ljava/io/InterruptedIOException;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v3, v1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 249
    .line 250
    .line 251
    iget-object v4, v2, Lh01/l;->f:Lh01/o;

    .line 252
    .line 253
    invoke-virtual {v4, v3}, Lh01/o;->h(Ljava/io/IOException;)Ljava/io/IOException;

    .line 254
    .line 255
    .line 256
    iget-object v2, v2, Lh01/l;->d:Ld01/k;

    .line 257
    .line 258
    invoke-interface {v2, v4, v3}, Ld01/k;->onFailure(Ld01/j;Ljava/io/IOException;)V

    .line 259
    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_f
    invoke-virtual {p0}, Ld01/t;->b()Ljava/util/concurrent/ExecutorService;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 267
    .line 268
    .line 269
    iget-object v4, v2, Lh01/l;->f:Lh01/o;

    .line 270
    .line 271
    iget-object v5, v4, Lh01/o;->d:Ld01/h0;

    .line 272
    .line 273
    iget-object v5, v5, Ld01/h0;->a:Ld01/t;

    .line 274
    .line 275
    const-string v6, "<this>"

    .line 276
    .line 277
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    const/4 v5, 0x3

    .line 281
    :try_start_1
    invoke-interface {v3, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 282
    .line 283
    .line 284
    goto :goto_6

    .line 285
    :catchall_1
    move-exception p0

    .line 286
    goto :goto_7

    .line 287
    :catch_0
    move-exception v3

    .line 288
    :try_start_2
    new-instance v6, Ljava/io/InterruptedIOException;

    .line 289
    .line 290
    const-string v7, "executor rejected"

    .line 291
    .line 292
    invoke-direct {v6, v7}, Ljava/io/InterruptedIOException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v6, v3}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 296
    .line 297
    .line 298
    iget-object v3, v2, Lh01/l;->f:Lh01/o;

    .line 299
    .line 300
    invoke-virtual {v3, v6}, Lh01/o;->h(Ljava/io/IOException;)Ljava/io/IOException;

    .line 301
    .line 302
    .line 303
    iget-object v7, v2, Lh01/l;->d:Ld01/k;

    .line 304
    .line 305
    invoke-interface {v7, v3, v6}, Ld01/k;->onFailure(Ld01/j;Ljava/io/IOException;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 306
    .line 307
    .line 308
    iget-object v3, v4, Lh01/o;->d:Ld01/h0;

    .line 309
    .line 310
    iget-object v3, v3, Ld01/h0;->a:Ld01/t;

    .line 311
    .line 312
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 313
    .line 314
    .line 315
    invoke-static {v3, v1, v1, v2, v5}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V

    .line 316
    .line 317
    .line 318
    :goto_6
    add-int/lit8 v0, v0, 0x1

    .line 319
    .line 320
    goto :goto_4

    .line 321
    :goto_7
    iget-object p1, v4, Lh01/o;->d:Ld01/h0;

    .line 322
    .line 323
    iget-object p1, p1, Ld01/h0;->a:Ld01/t;

    .line 324
    .line 325
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 326
    .line 327
    .line 328
    invoke-static {p1, v1, v1, v2, v5}, Ld01/t;->d(Ld01/t;Lh01/l;Lh01/o;Lh01/l;I)V

    .line 329
    .line 330
    .line 331
    throw p0

    .line 332
    :cond_10
    return-void

    .line 333
    :goto_8
    monitor-exit p0

    .line 334
    throw p1
.end method


# virtual methods
.method public final declared-synchronized a()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 3
    .line 4
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    const-string v1, "iterator(...)"

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    check-cast v1, Lh01/l;

    .line 24
    .line 25
    iget-object v1, v1, Lh01/l;->f:Lh01/o;

    .line 26
    .line 27
    invoke-virtual {v1}, Lh01/o;->cancel()V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception v0

    .line 32
    goto :goto_3

    .line 33
    :cond_0
    iget-object v0, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const-string v1, "iterator(...)"

    .line 40
    .line 41
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_1

    .line 49
    .line 50
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Lh01/l;

    .line 55
    .line 56
    iget-object v1, v1, Lh01/l;->f:Lh01/o;

    .line 57
    .line 58
    invoke-virtual {v1}, Lh01/o;->cancel()V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    iget-object v0, p0, Ld01/t;->d:Ljava/util/ArrayDeque;

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    const-string v1, "iterator(...)"

    .line 69
    .line 70
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-eqz v1, :cond_2

    .line 78
    .line 79
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    check-cast v1, Lh01/o;

    .line 84
    .line 85
    invoke-virtual {v1}, Lh01/o;->cancel()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_2
    monitor-exit p0

    .line 90
    return-void

    .line 91
    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 92
    throw v0
.end method

.method public final declared-synchronized b()Ljava/util/concurrent/ExecutorService;
    .locals 9

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Ld01/t;->a:Ljava/util/concurrent/ExecutorService;

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    new-instance v1, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 7
    .line 8
    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 9
    .line 10
    new-instance v7, Ljava/util/concurrent/SynchronousQueue;

    .line 11
    .line 12
    invoke-direct {v7}, Ljava/util/concurrent/SynchronousQueue;-><init>()V

    .line 13
    .line 14
    .line 15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    sget-object v2, Le01/g;->b:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v2, " Dispatcher"

    .line 26
    .line 27
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const-string v2, "name"

    .line 35
    .line 36
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    new-instance v8, Le01/f;

    .line 40
    .line 41
    const/4 v2, 0x0

    .line 42
    invoke-direct {v8, v0, v2}, Le01/f;-><init>(Ljava/lang/String;Z)V

    .line 43
    .line 44
    .line 45
    const/4 v2, 0x0

    .line 46
    const v3, 0x7fffffff

    .line 47
    .line 48
    .line 49
    const-wide/16 v4, 0x3c

    .line 50
    .line 51
    invoke-direct/range {v1 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    .line 52
    .line 53
    .line 54
    iput-object v1, p0, Ld01/t;->a:Ljava/util/concurrent/ExecutorService;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :catchall_0
    move-exception v0

    .line 58
    goto :goto_1

    .line 59
    :cond_0
    :goto_0
    iget-object v0, p0, Ld01/t;->a:Ljava/util/concurrent/ExecutorService;

    .line 60
    .line 61
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    .line 63
    .line 64
    monitor-exit p0

    .line 65
    return-object v0

    .line 66
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 67
    throw v0
.end method

.method public final c(Ljava/lang/String;)Lh01/l;
    .locals 4

    .line 1
    iget-object v0, p0, Ld01/t;->c:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "iterator(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Lh01/l;

    .line 23
    .line 24
    iget-object v3, v2, Lh01/l;->f:Lh01/o;

    .line 25
    .line 26
    iget-object v3, v3, Lh01/o;->e:Ld01/k0;

    .line 27
    .line 28
    iget-object v3, v3, Ld01/k0;->a:Ld01/a0;

    .line 29
    .line 30
    iget-object v3, v3, Ld01/a0;->d:Ljava/lang/String;

    .line 31
    .line 32
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_0

    .line 37
    .line 38
    return-object v2

    .line 39
    :cond_1
    iget-object p0, p0, Ld01/t;->b:Ljava/util/ArrayDeque;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    check-cast v0, Lh01/l;

    .line 59
    .line 60
    iget-object v1, v0, Lh01/l;->f:Lh01/o;

    .line 61
    .line 62
    iget-object v1, v1, Lh01/o;->e:Ld01/k0;

    .line 63
    .line 64
    iget-object v1, v1, Ld01/k0;->a:Ld01/a0;

    .line 65
    .line 66
    iget-object v1, v1, Ld01/a0;->d:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-eqz v1, :cond_2

    .line 73
    .line 74
    return-object v0

    .line 75
    :cond_3
    const/4 p0, 0x0

    .line 76
    return-object p0
.end method
