.class public final Lgb/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfb/g;
.implements Lib/f;
.implements Lfb/b;


# static fields
.field public static final r:Ljava/lang/String;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Ljava/util/HashMap;

.field public final f:Lgb/a;

.field public g:Z

.field public final h:Ljava/lang/Object;

.field public final i:Lb81/a;

.field public final j:Lfb/e;

.field public final k:Lb81/b;

.field public final l:Leb/b;

.field public final m:Ljava/util/HashMap;

.field public n:Ljava/lang/Boolean;

.field public final o:Laq/m;

.field public final p:Lob/a;

.field public final q:Lgb/d;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "GreedyScheduler"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lgb/c;->r:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Leb/b;Lkb/i;Lfb/e;Lb81/b;Lob/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lgb/c;->e:Ljava/util/HashMap;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lgb/c;->h:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance v0, Lfb/k;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    invoke-direct {v0, v1}, Lfb/k;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lb81/a;

    .line 25
    .line 26
    invoke-direct {v1, v0}, Lb81/a;-><init>(Lfb/k;)V

    .line 27
    .line 28
    .line 29
    iput-object v1, p0, Lgb/c;->i:Lb81/a;

    .line 30
    .line 31
    new-instance v0, Ljava/util/HashMap;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lgb/c;->m:Ljava/util/HashMap;

    .line 37
    .line 38
    iput-object p1, p0, Lgb/c;->d:Landroid/content/Context;

    .line 39
    .line 40
    iget-object p1, p2, Leb/b;->g:Laq/a;

    .line 41
    .line 42
    new-instance v0, Lgb/a;

    .line 43
    .line 44
    iget-object v1, p2, Leb/b;->d:Leb/j;

    .line 45
    .line 46
    invoke-direct {v0, p0, p1, v1}, Lgb/a;-><init>(Lgb/c;Laq/a;Leb/j;)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p0, Lgb/c;->f:Lgb/a;

    .line 50
    .line 51
    new-instance v0, Lgb/d;

    .line 52
    .line 53
    invoke-direct {v0, p1, p5}, Lgb/d;-><init>(Laq/a;Lb81/b;)V

    .line 54
    .line 55
    .line 56
    iput-object v0, p0, Lgb/c;->q:Lgb/d;

    .line 57
    .line 58
    iput-object p6, p0, Lgb/c;->p:Lob/a;

    .line 59
    .line 60
    new-instance p1, Laq/m;

    .line 61
    .line 62
    invoke-direct {p1, p3}, Laq/m;-><init>(Lkb/i;)V

    .line 63
    .line 64
    .line 65
    iput-object p1, p0, Lgb/c;->o:Laq/m;

    .line 66
    .line 67
    iput-object p2, p0, Lgb/c;->l:Leb/b;

    .line 68
    .line 69
    iput-object p4, p0, Lgb/c;->j:Lfb/e;

    .line 70
    .line 71
    iput-object p5, p0, Lgb/c;->k:Lb81/b;

    .line 72
    .line 73
    return-void
.end method


# virtual methods
.method public final varargs a([Lmb/o;)V
    .locals 14

    .line 1
    iget-object v0, p0, Lgb/c;->n:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lgb/c;->d:Landroid/content/Context;

    .line 6
    .line 7
    iget-object v1, p0, Lgb/c;->l:Leb/b;

    .line 8
    .line 9
    invoke-static {v0, v1}, Lnb/g;->a(Landroid/content/Context;Leb/b;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iput-object v0, p0, Lgb/c;->n:Ljava/lang/Boolean;

    .line 18
    .line 19
    :cond_0
    iget-object v0, p0, Lgb/c;->n:Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    sget-object p1, Lgb/c;->r:Ljava/lang/String;

    .line 32
    .line 33
    const-string v0, "Ignoring schedule request in a secondary process"

    .line 34
    .line 35
    invoke-virtual {p0, p1, v0}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    iget-boolean v0, p0, Lgb/c;->g:Z

    .line 40
    .line 41
    if-nez v0, :cond_2

    .line 42
    .line 43
    iget-object v0, p0, Lgb/c;->j:Lfb/e;

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Lfb/e;->a(Lfb/b;)V

    .line 46
    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    iput-boolean v0, p0, Lgb/c;->g:Z

    .line 50
    .line 51
    :cond_2
    new-instance v0, Ljava/util/HashSet;

    .line 52
    .line 53
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 54
    .line 55
    .line 56
    new-instance v1, Ljava/util/HashSet;

    .line 57
    .line 58
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 59
    .line 60
    .line 61
    array-length v2, p1

    .line 62
    const/4 v3, 0x0

    .line 63
    move v4, v3

    .line 64
    :goto_0
    if-ge v4, v2, :cond_b

    .line 65
    .line 66
    aget-object v5, p1, v4

    .line 67
    .line 68
    invoke-static {v5}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    iget-object v7, p0, Lgb/c;->i:Lb81/a;

    .line 73
    .line 74
    invoke-virtual {v7, v6}, Lb81/a;->l(Lmb/i;)Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    if-eqz v6, :cond_3

    .line 79
    .line 80
    goto/16 :goto_2

    .line 81
    .line 82
    :cond_3
    iget-object v6, p0, Lgb/c;->h:Ljava/lang/Object;

    .line 83
    .line 84
    monitor-enter v6

    .line 85
    :try_start_0
    invoke-static {v5}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    iget-object v8, p0, Lgb/c;->m:Ljava/util/HashMap;

    .line 90
    .line 91
    invoke-virtual {v8, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    check-cast v8, Lgb/b;

    .line 96
    .line 97
    if-nez v8, :cond_4

    .line 98
    .line 99
    new-instance v8, Lgb/b;

    .line 100
    .line 101
    iget v9, v5, Lmb/o;->k:I

    .line 102
    .line 103
    iget-object v10, p0, Lgb/c;->l:Leb/b;

    .line 104
    .line 105
    iget-object v10, v10, Leb/b;->d:Leb/j;

    .line 106
    .line 107
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 111
    .line 112
    .line 113
    move-result-wide v10

    .line 114
    invoke-direct {v8, v9, v10, v11}, Lgb/b;-><init>(IJ)V

    .line 115
    .line 116
    .line 117
    iget-object v9, p0, Lgb/c;->m:Ljava/util/HashMap;

    .line 118
    .line 119
    invoke-virtual {v9, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :catchall_0
    move-exception p0

    .line 124
    goto/16 :goto_3

    .line 125
    .line 126
    :cond_4
    :goto_1
    iget-wide v9, v8, Lgb/b;->b:J

    .line 127
    .line 128
    iget v7, v5, Lmb/o;->k:I

    .line 129
    .line 130
    iget v8, v8, Lgb/b;->a:I

    .line 131
    .line 132
    sub-int/2addr v7, v8

    .line 133
    add-int/lit8 v7, v7, -0x5

    .line 134
    .line 135
    invoke-static {v7, v3}, Ljava/lang/Math;->max(II)I

    .line 136
    .line 137
    .line 138
    move-result v7

    .line 139
    int-to-long v7, v7

    .line 140
    const-wide/16 v11, 0x7530

    .line 141
    .line 142
    mul-long/2addr v7, v11

    .line 143
    add-long/2addr v7, v9

    .line 144
    monitor-exit v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 145
    invoke-virtual {v5}, Lmb/o;->a()J

    .line 146
    .line 147
    .line 148
    move-result-wide v9

    .line 149
    invoke-static {v9, v10, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 150
    .line 151
    .line 152
    move-result-wide v6

    .line 153
    iget-object v8, p0, Lgb/c;->l:Leb/b;

    .line 154
    .line 155
    iget-object v8, v8, Leb/b;->d:Leb/j;

    .line 156
    .line 157
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 161
    .line 162
    .line 163
    move-result-wide v8

    .line 164
    iget-object v10, v5, Lmb/o;->b:Leb/h0;

    .line 165
    .line 166
    sget-object v11, Leb/h0;->d:Leb/h0;

    .line 167
    .line 168
    if-ne v10, v11, :cond_a

    .line 169
    .line 170
    cmp-long v8, v8, v6

    .line 171
    .line 172
    if-gez v8, :cond_6

    .line 173
    .line 174
    iget-object v8, p0, Lgb/c;->f:Lgb/a;

    .line 175
    .line 176
    if-eqz v8, :cond_a

    .line 177
    .line 178
    iget-object v9, v8, Lgb/a;->b:Laq/a;

    .line 179
    .line 180
    iget-object v10, v8, Lgb/a;->d:Ljava/util/HashMap;

    .line 181
    .line 182
    iget-object v11, v5, Lmb/o;->a:Ljava/lang/String;

    .line 183
    .line 184
    invoke-virtual {v10, v11}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v11

    .line 188
    check-cast v11, Ljava/lang/Runnable;

    .line 189
    .line 190
    if-eqz v11, :cond_5

    .line 191
    .line 192
    iget-object v12, v9, Laq/a;->e:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v12, Landroid/os/Handler;

    .line 195
    .line 196
    invoke-virtual {v12, v11}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 197
    .line 198
    .line 199
    :cond_5
    new-instance v11, Llr/b;

    .line 200
    .line 201
    const/4 v12, 0x7

    .line 202
    const/4 v13, 0x0

    .line 203
    invoke-direct {v11, v8, v5, v13, v12}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 204
    .line 205
    .line 206
    iget-object v5, v5, Lmb/o;->a:Ljava/lang/String;

    .line 207
    .line 208
    invoke-virtual {v10, v5, v11}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    iget-object v5, v8, Lgb/a;->c:Leb/j;

    .line 212
    .line 213
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 214
    .line 215
    .line 216
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 217
    .line 218
    .line 219
    move-result-wide v12

    .line 220
    sub-long/2addr v6, v12

    .line 221
    iget-object v5, v9, Laq/a;->e:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v5, Landroid/os/Handler;

    .line 224
    .line 225
    invoke-virtual {v5, v11, v6, v7}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 226
    .line 227
    .line 228
    goto/16 :goto_2

    .line 229
    .line 230
    :cond_6
    sget-object v6, Leb/e;->j:Leb/e;

    .line 231
    .line 232
    iget-object v7, v5, Lmb/o;->j:Leb/e;

    .line 233
    .line 234
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v6

    .line 238
    if-nez v6, :cond_9

    .line 239
    .line 240
    iget-object v6, v5, Lmb/o;->j:Leb/e;

    .line 241
    .line 242
    iget-boolean v7, v6, Leb/e;->d:Z

    .line 243
    .line 244
    if-eqz v7, :cond_7

    .line 245
    .line 246
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 247
    .line 248
    .line 249
    move-result-object v6

    .line 250
    sget-object v7, Lgb/c;->r:Ljava/lang/String;

    .line 251
    .line 252
    new-instance v8, Ljava/lang/StringBuilder;

    .line 253
    .line 254
    const-string v9, "Ignoring "

    .line 255
    .line 256
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    const-string v5, ". Requires device idle."

    .line 263
    .line 264
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    invoke-virtual {v6, v7, v5}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    goto :goto_2

    .line 275
    :cond_7
    invoke-virtual {v6}, Leb/e;->b()Z

    .line 276
    .line 277
    .line 278
    move-result v6

    .line 279
    if-eqz v6, :cond_8

    .line 280
    .line 281
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    sget-object v7, Lgb/c;->r:Ljava/lang/String;

    .line 286
    .line 287
    new-instance v8, Ljava/lang/StringBuilder;

    .line 288
    .line 289
    const-string v9, "Ignoring "

    .line 290
    .line 291
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 295
    .line 296
    .line 297
    const-string v5, ". Requires ContentUri triggers."

    .line 298
    .line 299
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 300
    .line 301
    .line 302
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v5

    .line 306
    invoke-virtual {v6, v7, v5}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    goto :goto_2

    .line 310
    :cond_8
    invoke-virtual {v0, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    iget-object v5, v5, Lmb/o;->a:Ljava/lang/String;

    .line 314
    .line 315
    invoke-virtual {v1, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    goto :goto_2

    .line 319
    :cond_9
    iget-object v6, p0, Lgb/c;->i:Lb81/a;

    .line 320
    .line 321
    invoke-static {v5}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 322
    .line 323
    .line 324
    move-result-object v7

    .line 325
    invoke-virtual {v6, v7}, Lb81/a;->l(Lmb/i;)Z

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    if-nez v6, :cond_a

    .line 330
    .line 331
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 332
    .line 333
    .line 334
    move-result-object v6

    .line 335
    sget-object v7, Lgb/c;->r:Ljava/lang/String;

    .line 336
    .line 337
    new-instance v8, Ljava/lang/StringBuilder;

    .line 338
    .line 339
    const-string v9, "Starting work for "

    .line 340
    .line 341
    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    iget-object v9, v5, Lmb/o;->a:Ljava/lang/String;

    .line 345
    .line 346
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 347
    .line 348
    .line 349
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v8

    .line 353
    invoke-virtual {v6, v7, v8}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    iget-object v6, p0, Lgb/c;->i:Lb81/a;

    .line 357
    .line 358
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 359
    .line 360
    .line 361
    invoke-static {v5}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 362
    .line 363
    .line 364
    move-result-object v5

    .line 365
    invoke-virtual {v6, v5}, Lb81/a;->s(Lmb/i;)Lfb/j;

    .line 366
    .line 367
    .line 368
    move-result-object v5

    .line 369
    iget-object v6, p0, Lgb/c;->q:Lgb/d;

    .line 370
    .line 371
    invoke-virtual {v6, v5}, Lgb/d;->b(Lfb/j;)V

    .line 372
    .line 373
    .line 374
    iget-object v6, p0, Lgb/c;->k:Lb81/b;

    .line 375
    .line 376
    iget-object v7, v6, Lb81/b;->f:Ljava/lang/Object;

    .line 377
    .line 378
    check-cast v7, Lob/a;

    .line 379
    .line 380
    new-instance v8, La8/y0;

    .line 381
    .line 382
    const/16 v9, 0x8

    .line 383
    .line 384
    const/4 v10, 0x0

    .line 385
    invoke-direct {v8, v6, v5, v10, v9}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 386
    .line 387
    .line 388
    iget-object v5, v7, Lob/a;->a:Lla/a0;

    .line 389
    .line 390
    invoke-virtual {v5, v8}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 391
    .line 392
    .line 393
    :cond_a
    :goto_2
    add-int/lit8 v4, v4, 0x1

    .line 394
    .line 395
    goto/16 :goto_0

    .line 396
    .line 397
    :goto_3
    :try_start_1
    monitor-exit v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 398
    throw p0

    .line 399
    :cond_b
    iget-object p1, p0, Lgb/c;->h:Ljava/lang/Object;

    .line 400
    .line 401
    monitor-enter p1

    .line 402
    :try_start_2
    invoke-virtual {v0}, Ljava/util/HashSet;->isEmpty()Z

    .line 403
    .line 404
    .line 405
    move-result v2

    .line 406
    if-nez v2, :cond_d

    .line 407
    .line 408
    const-string v2, ","

    .line 409
    .line 410
    invoke-static {v2, v1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v1

    .line 414
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 415
    .line 416
    .line 417
    move-result-object v2

    .line 418
    sget-object v3, Lgb/c;->r:Ljava/lang/String;

    .line 419
    .line 420
    new-instance v4, Ljava/lang/StringBuilder;

    .line 421
    .line 422
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 423
    .line 424
    .line 425
    const-string v5, "Starting tracking for "

    .line 426
    .line 427
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 428
    .line 429
    .line 430
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 431
    .line 432
    .line 433
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 434
    .line 435
    .line 436
    move-result-object v1

    .line 437
    invoke-virtual {v2, v3, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    :cond_c
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 445
    .line 446
    .line 447
    move-result v1

    .line 448
    if-eqz v1, :cond_d

    .line 449
    .line 450
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v1

    .line 454
    check-cast v1, Lmb/o;

    .line 455
    .line 456
    invoke-static {v1}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 457
    .line 458
    .line 459
    move-result-object v2

    .line 460
    iget-object v3, p0, Lgb/c;->e:Ljava/util/HashMap;

    .line 461
    .line 462
    invoke-virtual {v3, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 463
    .line 464
    .line 465
    move-result v3

    .line 466
    if-nez v3, :cond_c

    .line 467
    .line 468
    iget-object v3, p0, Lgb/c;->o:Laq/m;

    .line 469
    .line 470
    iget-object v4, p0, Lgb/c;->p:Lob/a;

    .line 471
    .line 472
    iget-object v4, v4, Lob/a;->b:Lvy0/x;

    .line 473
    .line 474
    invoke-static {v3, v1, v4, p0}, Lib/j;->a(Laq/m;Lmb/o;Lvy0/x;Lib/f;)Lvy0/x1;

    .line 475
    .line 476
    .line 477
    move-result-object v1

    .line 478
    iget-object v3, p0, Lgb/c;->e:Ljava/util/HashMap;

    .line 479
    .line 480
    invoke-virtual {v3, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    goto :goto_4

    .line 484
    :catchall_1
    move-exception p0

    .line 485
    goto :goto_5

    .line 486
    :cond_d
    monitor-exit p1

    .line 487
    return-void

    .line 488
    :goto_5
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 489
    throw p0
.end method

.method public final b(Lmb/i;Z)V
    .locals 5

    .line 1
    iget-object v0, p0, Lgb/c;->i:Lb81/a;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lb81/a;->r(Lmb/i;)Lfb/j;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v1, p0, Lgb/c;->q:Lgb/d;

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Lgb/d;->a(Lfb/j;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-object v0, p0, Lgb/c;->h:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v0

    .line 17
    :try_start_0
    iget-object v1, p0, Lgb/c;->e:Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    check-cast v1, Lvy0/i1;

    .line 24
    .line 25
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sget-object v2, Lgb/c;->r:Ljava/lang/String;

    .line 33
    .line 34
    new-instance v3, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v4, "Stopping tracking for "

    .line 37
    .line 38
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-virtual {v0, v2, v3}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    invoke-interface {v1, v0}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    if-nez p2, :cond_2

    .line 56
    .line 57
    iget-object p2, p0, Lgb/c;->h:Ljava/lang/Object;

    .line 58
    .line 59
    monitor-enter p2

    .line 60
    :try_start_1
    iget-object p0, p0, Lgb/c;->m:Ljava/util/HashMap;

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    monitor-exit p2

    .line 66
    return-void

    .line 67
    :catchall_0
    move-exception p0

    .line 68
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 69
    throw p0

    .line 70
    :cond_2
    return-void

    .line 71
    :catchall_1
    move-exception p0

    .line 72
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 73
    throw p0
.end method

.method public final c(Ljava/lang/String;)V
    .locals 4

    .line 1
    sget-object v0, Lgb/c;->r:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lgb/c;->n:Ljava/lang/Boolean;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lgb/c;->d:Landroid/content/Context;

    .line 8
    .line 9
    iget-object v2, p0, Lgb/c;->l:Leb/b;

    .line 10
    .line 11
    invoke-static {v1, v2}, Lnb/g;->a(Landroid/content/Context;Leb/b;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    iput-object v1, p0, Lgb/c;->n:Ljava/lang/Boolean;

    .line 20
    .line 21
    :cond_0
    iget-object v1, p0, Lgb/c;->n:Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_1

    .line 28
    .line 29
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string p1, "Ignoring schedule request in non-main process"

    .line 34
    .line 35
    invoke-virtual {p0, v0, p1}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    iget-boolean v1, p0, Lgb/c;->g:Z

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    iget-object v1, p0, Lgb/c;->j:Lfb/e;

    .line 44
    .line 45
    invoke-virtual {v1, p0}, Lfb/e;->a(Lfb/b;)V

    .line 46
    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    iput-boolean v1, p0, Lgb/c;->g:Z

    .line 50
    .line 51
    :cond_2
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    new-instance v2, Ljava/lang/StringBuilder;

    .line 56
    .line 57
    const-string v3, "Cancelling work ID "

    .line 58
    .line 59
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v1, v0, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Lgb/c;->f:Lgb/a;

    .line 73
    .line 74
    if-eqz v0, :cond_3

    .line 75
    .line 76
    iget-object v1, v0, Lgb/a;->d:Ljava/util/HashMap;

    .line 77
    .line 78
    invoke-virtual {v1, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    check-cast v1, Ljava/lang/Runnable;

    .line 83
    .line 84
    if-eqz v1, :cond_3

    .line 85
    .line 86
    iget-object v0, v0, Lgb/a;->b:Laq/a;

    .line 87
    .line 88
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v0, Landroid/os/Handler;

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 93
    .line 94
    .line 95
    :cond_3
    iget-object v0, p0, Lgb/c;->i:Lb81/a;

    .line 96
    .line 97
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    const-string v1, "workSpecId"

    .line 101
    .line 102
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    iget-object v1, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 106
    .line 107
    monitor-enter v1

    .line 108
    :try_start_0
    iget-object v0, v0, Lb81/a;->e:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v0, Lfb/k;

    .line 111
    .line 112
    invoke-virtual {v0, p1}, Lfb/k;->f(Ljava/lang/String;)Ljava/util/List;

    .line 113
    .line 114
    .line 115
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 116
    monitor-exit v1

    .line 117
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-eqz v0, :cond_4

    .line 126
    .line 127
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    check-cast v0, Lfb/j;

    .line 132
    .line 133
    iget-object v1, p0, Lgb/c;->q:Lgb/d;

    .line 134
    .line 135
    invoke-virtual {v1, v0}, Lgb/d;->a(Lfb/j;)V

    .line 136
    .line 137
    .line 138
    iget-object v1, p0, Lgb/c;->k:Lb81/b;

    .line 139
    .line 140
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    const/16 v2, -0x200

    .line 144
    .line 145
    invoke-virtual {v1, v0, v2}, Lb81/b;->z(Lfb/j;I)V

    .line 146
    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_4
    return-void

    .line 150
    :catchall_0
    move-exception p0

    .line 151
    monitor-exit v1

    .line 152
    throw p0
.end method

.method public final d(Lmb/o;Lib/c;)V
    .locals 6

    .line 1
    invoke-static {p1}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    instance-of v0, p2, Lib/a;

    .line 6
    .line 7
    iget-object v1, p0, Lgb/c;->k:Lb81/b;

    .line 8
    .line 9
    iget-object v2, p0, Lgb/c;->q:Lgb/d;

    .line 10
    .line 11
    sget-object v3, Lgb/c;->r:Ljava/lang/String;

    .line 12
    .line 13
    iget-object p0, p0, Lgb/c;->i:Lb81/a;

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lb81/a;->l(Lmb/i;)Z

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    if-nez p2, :cond_1

    .line 22
    .line 23
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    new-instance v0, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v4, "Constraints met: Scheduling work ID "

    .line 30
    .line 31
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {p2, v3, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lb81/a;->s(Lmb/i;)Lfb/j;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {v2, p0}, Lgb/d;->b(Lfb/j;)V

    .line 49
    .line 50
    .line 51
    iget-object p1, v1, Lb81/b;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p1, Lob/a;

    .line 54
    .line 55
    new-instance p2, La8/y0;

    .line 56
    .line 57
    const/16 v0, 0x8

    .line 58
    .line 59
    const/4 v2, 0x0

    .line 60
    invoke-direct {p2, v1, p0, v2, v0}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    iget-object p0, p1, Lob/a;->a:Lla/a0;

    .line 64
    .line 65
    invoke-virtual {p0, p2}, Lla/a0;->execute(Ljava/lang/Runnable;)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_0
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    new-instance v4, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    const-string v5, "Constraints not met: Cancelling work ID "

    .line 76
    .line 77
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v4, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    invoke-virtual {v0, v3, v4}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, p1}, Lb81/a;->r(Lmb/i;)Lfb/j;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-eqz p0, :cond_1

    .line 95
    .line 96
    invoke-virtual {v2, p0}, Lgb/d;->a(Lfb/j;)V

    .line 97
    .line 98
    .line 99
    check-cast p2, Lib/b;

    .line 100
    .line 101
    iget p1, p2, Lib/b;->a:I

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1, p0, p1}, Lb81/b;->z(Lfb/j;I)V

    .line 107
    .line 108
    .line 109
    :cond_1
    return-void
.end method

.method public final e()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
