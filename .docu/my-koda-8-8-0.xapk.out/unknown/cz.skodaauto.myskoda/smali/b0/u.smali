.class public final Lb0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:Ljava/lang/Object;

.field public static final s:Landroid/util/SparseArray;


# instance fields
.field public final a:Lh0/i0;

.field public final b:Ljava/lang/Object;

.field public final c:Lb0/w;

.field public final d:Ljava/util/concurrent/Executor;

.field public final e:Landroid/os/Handler;

.field public final f:Landroid/os/HandlerThread;

.field public g:Lu/n;

.field public h:Lu/d0;

.field public i:Lu/g0;

.field public j:Lc2/k;

.field public k:Lcom/google/firebase/messaging/w;

.field public final l:Lb0/m1;

.field public final m:Ly4/k;

.field public final n:Lh0/e0;

.field public o:I

.field public p:Lcom/google/common/util/concurrent/ListenableFuture;

.field public final q:Ljava/lang/Integer;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lb0/u;->r:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v0, Landroid/util/SparseArray;

    .line 9
    .line 10
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lb0/u;->s:Landroid/util/SparseArray;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lv0/c;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance p2, Lh0/i0;

    .line 5
    .line 6
    invoke-direct {p2}, Lh0/i0;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lb0/u;->a:Lh0/i0;

    .line 10
    .line 11
    new-instance p2, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p2, p0, Lb0/u;->b:Ljava/lang/Object;

    .line 17
    .line 18
    const/4 p2, 0x1

    .line 19
    iput p2, p0, Lb0/u;->o:I

    .line 20
    .line 21
    sget-object v0, Lk0/j;->f:Lk0/j;

    .line 22
    .line 23
    iput-object v0, p0, Lb0/u;->p:Lcom/google/common/util/concurrent/ListenableFuture;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    const-string v1, "CameraX"

    .line 27
    .line 28
    invoke-static {p1}, Llp/i1;->a(Landroid/content/Context;)Landroid/content/Context;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    :goto_0
    instance-of v3, v2, Landroid/content/ContextWrapper;

    .line 33
    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    instance-of v3, v2, Landroid/app/Application;

    .line 37
    .line 38
    if-eqz v3, :cond_0

    .line 39
    .line 40
    check-cast v2, Landroid/app/Application;

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_0
    check-cast v2, Landroid/content/ContextWrapper;

    .line 44
    .line 45
    invoke-virtual {v2}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    goto :goto_0

    .line 50
    :cond_1
    move-object v2, v0

    .line 51
    :goto_1
    instance-of v3, v2, Lb0/v;

    .line 52
    .line 53
    const/16 v4, 0x280

    .line 54
    .line 55
    if-eqz v3, :cond_2

    .line 56
    .line 57
    check-cast v2, Lb0/v;

    .line 58
    .line 59
    goto :goto_5

    .line 60
    :cond_2
    :try_start_0
    invoke-static {p1}, Llp/i1;->a(Landroid/content/Context;)Landroid/content/Context;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-virtual {v2}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    new-instance v5, Landroid/content/ComponentName;

    .line 69
    .line 70
    const-class v6, Landroidx/camera/core/impl/MetadataHolderService;

    .line 71
    .line 72
    invoke-direct {v5, v2, v6}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3, v5, v4}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    iget-object v2, v2, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;

    .line 80
    .line 81
    if-eqz v2, :cond_3

    .line 82
    .line 83
    const-string v3, "androidx.camera.core.impl.MetadataHolderService.DEFAULT_CONFIG_PROVIDER"

    .line 84
    .line 85
    invoke-virtual {v2, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v2

    .line 89
    goto :goto_2

    .line 90
    :catch_0
    move-exception v2

    .line 91
    goto :goto_4

    .line 92
    :cond_3
    move-object v2, v0

    .line 93
    :goto_2
    if-nez v2, :cond_4

    .line 94
    .line 95
    const-string v2, "No default CameraXConfig.Provider specified in meta-data. The most likely cause is you did not include a default implementation in your build such as \'camera-camera2\'."

    .line 96
    .line 97
    invoke-static {v1, v2}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    :goto_3
    move-object v2, v0

    .line 101
    goto :goto_5

    .line 102
    :cond_4
    invoke-static {v2}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    invoke-virtual {v2, v0}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    invoke-virtual {v2, v0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    check-cast v2, Lb0/v;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 115
    .line 116
    goto :goto_5

    .line 117
    :goto_4
    const-string v3, "Failed to retrieve default CameraXConfig.Provider from meta-data"

    .line 118
    .line 119
    invoke-static {v1, v3, v2}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :goto_5
    if-eqz v2, :cond_12

    .line 124
    .line 125
    invoke-interface {v2}, Lb0/v;->getCameraXConfig()Lb0/w;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    iput-object v1, p0, Lb0/u;->c:Lb0/w;

    .line 130
    .line 131
    iget-object v1, v1, Lb0/w;->d:Lh0/n1;

    .line 132
    .line 133
    sget-object v2, Lb0/w;->n:Lh0/g;

    .line 134
    .line 135
    invoke-virtual {v1, v2, v0}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    check-cast v1, Lh0/q1;

    .line 140
    .line 141
    if-eqz v1, :cond_5

    .line 142
    .line 143
    const-string v2, "CameraX"

    .line 144
    .line 145
    new-instance v3, Ljava/lang/StringBuilder;

    .line 146
    .line 147
    const-string v4, "QuirkSettings from CameraXConfig: "

    .line 148
    .line 149
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    invoke-static {v2, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    goto :goto_8

    .line 163
    :cond_5
    const-string v1, "QuirkSettingsLoader"

    .line 164
    .line 165
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 166
    .line 167
    .line 168
    move-result-object v2

    .line 169
    :try_start_1
    new-instance v3, Landroid/content/ComponentName;

    .line 170
    .line 171
    const-class v5, Lh0/s1;

    .line 172
    .line 173
    invoke-direct {v3, p1, v5}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v2, v3, v4}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    iget-object v2, v2, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;

    .line 181
    .line 182
    if-nez v2, :cond_6

    .line 183
    .line 184
    const-string v2, "No metadata in MetadataHolderService."

    .line 185
    .line 186
    invoke-static {v1, v2}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    :goto_6
    move-object v1, v0

    .line 190
    goto :goto_7

    .line 191
    :cond_6
    invoke-static {p1, v2}, Lkp/z9;->b(Landroid/content/Context;Landroid/os/Bundle;)Lh0/q1;

    .line 192
    .line 193
    .line 194
    move-result-object v1
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_1

    .line 195
    goto :goto_7

    .line 196
    :catch_1
    const-string v2, "QuirkSettings$MetadataHolderService is not found."

    .line 197
    .line 198
    invoke-static {v1, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    goto :goto_6

    .line 202
    :goto_7
    const-string v2, "CameraX"

    .line 203
    .line 204
    new-instance v3, Ljava/lang/StringBuilder;

    .line 205
    .line 206
    const-string v4, "QuirkSettings from app metadata: "

    .line 207
    .line 208
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v3

    .line 218
    invoke-static {v2, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    :goto_8
    if-nez v1, :cond_7

    .line 222
    .line 223
    sget-object v1, Lh0/r1;->b:Lh0/q1;

    .line 224
    .line 225
    const-string v2, "CameraX"

    .line 226
    .line 227
    new-instance v3, Ljava/lang/StringBuilder;

    .line 228
    .line 229
    const-string v4, "QuirkSettings by default: "

    .line 230
    .line 231
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 235
    .line 236
    .line 237
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    invoke-static {v2, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    :cond_7
    sget-object v2, Lh0/r1;->c:Lh0/r1;

    .line 245
    .line 246
    iget-object v2, v2, Lh0/r1;->a:Lf8/d;

    .line 247
    .line 248
    iget-object v3, v2, Lf8/d;->f:Ljava/lang/Object;

    .line 249
    .line 250
    monitor-enter v3

    .line 251
    :try_start_2
    iget-object v4, v2, Lf8/d;->g:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast v4, Ljava/util/concurrent/atomic/AtomicReference;

    .line 254
    .line 255
    invoke-virtual {v4, v1}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v4

    .line 259
    invoke-static {v4, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v1

    .line 263
    const/4 v4, 0x0

    .line 264
    if-eqz v1, :cond_8

    .line 265
    .line 266
    monitor-exit v3

    .line 267
    goto :goto_a

    .line 268
    :catchall_0
    move-exception p0

    .line 269
    goto/16 :goto_12

    .line 270
    .line 271
    :cond_8
    iget v1, v2, Lf8/d;->d:I

    .line 272
    .line 273
    add-int/2addr v1, p2

    .line 274
    iput v1, v2, Lf8/d;->d:I

    .line 275
    .line 276
    iget-boolean v5, v2, Lf8/d;->e:Z

    .line 277
    .line 278
    if-eqz v5, :cond_9

    .line 279
    .line 280
    monitor-exit v3

    .line 281
    goto :goto_a

    .line 282
    :cond_9
    iput-boolean p2, v2, Lf8/d;->e:Z

    .line 283
    .line 284
    iget-object v5, v2, Lf8/d;->i:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v5, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 287
    .line 288
    invoke-virtual {v5}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 289
    .line 290
    .line 291
    move-result-object v5

    .line 292
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 293
    :goto_9
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 294
    .line 295
    .line 296
    move-result v3

    .line 297
    if-eqz v3, :cond_a

    .line 298
    .line 299
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v3

    .line 303
    check-cast v3, Lh0/b2;

    .line 304
    .line 305
    invoke-virtual {v3, v1}, Lh0/b2;->a(I)V

    .line 306
    .line 307
    .line 308
    goto :goto_9

    .line 309
    :cond_a
    iget-object v5, v2, Lf8/d;->f:Ljava/lang/Object;

    .line 310
    .line 311
    monitor-enter v5

    .line 312
    :try_start_3
    iget v3, v2, Lf8/d;->d:I

    .line 313
    .line 314
    if-ne v3, v1, :cond_11

    .line 315
    .line 316
    iput-boolean v4, v2, Lf8/d;->e:Z

    .line 317
    .line 318
    monitor-exit v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 319
    :goto_a
    iget-object v1, p0, Lb0/u;->c:Lb0/w;

    .line 320
    .line 321
    iget-object v1, v1, Lb0/w;->d:Lh0/n1;

    .line 322
    .line 323
    sget-object v2, Lb0/w;->o:Lh0/g;

    .line 324
    .line 325
    const/4 v3, -0x1

    .line 326
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 327
    .line 328
    .line 329
    move-result-object v3

    .line 330
    invoke-virtual {v1, v2, v3}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    check-cast v1, Ljava/lang/Integer;

    .line 335
    .line 336
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 337
    .line 338
    .line 339
    iget-object v1, p0, Lb0/u;->c:Lb0/w;

    .line 340
    .line 341
    iget-object v1, v1, Lb0/w;->d:Lh0/n1;

    .line 342
    .line 343
    sget-object v2, Lb0/w;->h:Lh0/g;

    .line 344
    .line 345
    invoke-virtual {v1, v2, v0}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    check-cast v1, Ljava/util/concurrent/Executor;

    .line 350
    .line 351
    iget-object v2, p0, Lb0/u;->c:Lb0/w;

    .line 352
    .line 353
    iget-object v2, v2, Lb0/w;->d:Lh0/n1;

    .line 354
    .line 355
    sget-object v3, Lb0/w;->i:Lh0/g;

    .line 356
    .line 357
    invoke-virtual {v2, v3, v0}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v2

    .line 361
    check-cast v2, Landroid/os/Handler;

    .line 362
    .line 363
    if-nez v1, :cond_b

    .line 364
    .line 365
    new-instance v1, Lb0/o;

    .line 366
    .line 367
    invoke-direct {v1}, Lb0/o;-><init>()V

    .line 368
    .line 369
    .line 370
    :cond_b
    iput-object v1, p0, Lb0/u;->d:Ljava/util/concurrent/Executor;

    .line 371
    .line 372
    if-nez v2, :cond_c

    .line 373
    .line 374
    new-instance v2, Landroid/os/HandlerThread;

    .line 375
    .line 376
    const-string v3, "CameraX-scheduler"

    .line 377
    .line 378
    const/16 v5, 0xa

    .line 379
    .line 380
    invoke-direct {v2, v3, v5}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;I)V

    .line 381
    .line 382
    .line 383
    iput-object v2, p0, Lb0/u;->f:Landroid/os/HandlerThread;

    .line 384
    .line 385
    invoke-virtual {v2}, Ljava/lang/Thread;->start()V

    .line 386
    .line 387
    .line 388
    invoke-virtual {v2}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 389
    .line 390
    .line 391
    move-result-object v2

    .line 392
    invoke-static {v2}, Landroid/os/Handler;->createAsync(Landroid/os/Looper;)Landroid/os/Handler;

    .line 393
    .line 394
    .line 395
    move-result-object v2

    .line 396
    iput-object v2, p0, Lb0/u;->e:Landroid/os/Handler;

    .line 397
    .line 398
    goto :goto_b

    .line 399
    :cond_c
    iput-object v0, p0, Lb0/u;->f:Landroid/os/HandlerThread;

    .line 400
    .line 401
    iput-object v2, p0, Lb0/u;->e:Landroid/os/Handler;

    .line 402
    .line 403
    :goto_b
    iget-object v2, p0, Lb0/u;->c:Lb0/w;

    .line 404
    .line 405
    sget-object v3, Lb0/w;->j:Lh0/g;

    .line 406
    .line 407
    invoke-interface {v2, v3, v0}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v0

    .line 411
    check-cast v0, Ljava/lang/Integer;

    .line 412
    .line 413
    iput-object v0, p0, Lb0/u;->q:Ljava/lang/Integer;

    .line 414
    .line 415
    sget-object v2, Lb0/u;->r:Ljava/lang/Object;

    .line 416
    .line 417
    monitor-enter v2

    .line 418
    if-nez v0, :cond_d

    .line 419
    .line 420
    :try_start_4
    monitor-exit v2

    .line 421
    goto :goto_d

    .line 422
    :catchall_1
    move-exception p0

    .line 423
    goto/16 :goto_10

    .line 424
    .line 425
    :cond_d
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 426
    .line 427
    .line 428
    move-result v3

    .line 429
    const-string v5, "minLogLevel"

    .line 430
    .line 431
    const/4 v6, 0x3

    .line 432
    const/4 v7, 0x6

    .line 433
    invoke-static {v3, v6, v7, v5}, Ljp/ed;->c(IIILjava/lang/String;)V

    .line 434
    .line 435
    .line 436
    sget-object v3, Lb0/u;->s:Landroid/util/SparseArray;

    .line 437
    .line 438
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 439
    .line 440
    .line 441
    move-result v5

    .line 442
    invoke-virtual {v3, v5}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 443
    .line 444
    .line 445
    move-result-object v5

    .line 446
    if-eqz v5, :cond_e

    .line 447
    .line 448
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 449
    .line 450
    .line 451
    move-result v5

    .line 452
    invoke-virtual {v3, v5}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    move-result-object v5

    .line 456
    check-cast v5, Ljava/lang/Integer;

    .line 457
    .line 458
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 459
    .line 460
    .line 461
    move-result v5

    .line 462
    add-int/2addr v5, p2

    .line 463
    goto :goto_c

    .line 464
    :cond_e
    move v5, p2

    .line 465
    :goto_c
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 466
    .line 467
    .line 468
    move-result v0

    .line 469
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 470
    .line 471
    .line 472
    move-result-object v5

    .line 473
    invoke-virtual {v3, v0, v5}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 474
    .line 475
    .line 476
    invoke-static {}, Lb0/u;->b()V

    .line 477
    .line 478
    .line 479
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 480
    :goto_d
    iget-object v0, p0, Lb0/u;->c:Lb0/w;

    .line 481
    .line 482
    iget-object v0, v0, Lb0/w;->d:Lh0/n1;

    .line 483
    .line 484
    sget-object v2, Lb0/w;->m:Lh0/g;

    .line 485
    .line 486
    sget-object v3, Lb0/m1;->a:Lh0/g0;

    .line 487
    .line 488
    invoke-virtual {v0, v2, v3}, Lh0/n1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    check-cast v0, Lb0/m1;

    .line 493
    .line 494
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    invoke-interface {v0}, Lb0/m1;->a()J

    .line 498
    .line 499
    .line 500
    move-result-wide v2

    .line 501
    instance-of v5, v0, Lh0/g0;

    .line 502
    .line 503
    if-eqz v5, :cond_f

    .line 504
    .line 505
    check-cast v0, Lh0/g0;

    .line 506
    .line 507
    iget v0, v0, Lh0/g0;->b:I

    .line 508
    .line 509
    packed-switch v0, :pswitch_data_0

    .line 510
    .line 511
    .line 512
    new-instance v0, Lh0/g0;

    .line 513
    .line 514
    const/4 v5, 0x1

    .line 515
    invoke-direct {v0, v2, v3, v5}, Lh0/g0;-><init>(JI)V

    .line 516
    .line 517
    .line 518
    goto :goto_e

    .line 519
    :pswitch_0
    new-instance v0, Lh0/g0;

    .line 520
    .line 521
    const/4 v5, 0x0

    .line 522
    invoke-direct {v0, v2, v3, v5}, Lh0/g0;-><init>(JI)V

    .line 523
    .line 524
    .line 525
    goto :goto_e

    .line 526
    :cond_f
    new-instance v5, Lh0/k2;

    .line 527
    .line 528
    invoke-direct {v5, v2, v3, v0}, Lh0/k2;-><init>(JLb0/m1;)V

    .line 529
    .line 530
    .line 531
    move-object v0, v5

    .line 532
    :goto_e
    iput-object v0, p0, Lb0/u;->l:Lb0/m1;

    .line 533
    .line 534
    new-instance v0, Lh0/e0;

    .line 535
    .line 536
    invoke-direct {v0, v1}, Lh0/e0;-><init>(Ljava/util/concurrent/Executor;)V

    .line 537
    .line 538
    .line 539
    iput-object v0, p0, Lb0/u;->n:Lh0/e0;

    .line 540
    .line 541
    iget-object v0, p0, Lb0/u;->b:Ljava/lang/Object;

    .line 542
    .line 543
    monitor-enter v0

    .line 544
    :try_start_5
    iget v1, p0, Lb0/u;->o:I

    .line 545
    .line 546
    if-ne v1, p2, :cond_10

    .line 547
    .line 548
    goto :goto_f

    .line 549
    :cond_10
    move p2, v4

    .line 550
    :goto_f
    const-string v1, "CameraX.initInternal() should only be called once per instance"

    .line 551
    .line 552
    invoke-static {v1, p2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 553
    .line 554
    .line 555
    const/4 p2, 0x2

    .line 556
    iput p2, p0, Lb0/u;->o:I

    .line 557
    .line 558
    new-instance p2, La0/h;

    .line 559
    .line 560
    const/4 v1, 0x1

    .line 561
    invoke-direct {p2, v1, p0, p1}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 562
    .line 563
    .line 564
    invoke-static {p2}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 565
    .line 566
    .line 567
    move-result-object p1

    .line 568
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 569
    iput-object p1, p0, Lb0/u;->m:Ly4/k;

    .line 570
    .line 571
    return-void

    .line 572
    :catchall_2
    move-exception p0

    .line 573
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 574
    throw p0

    .line 575
    :goto_10
    :try_start_7
    monitor-exit v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 576
    throw p0

    .line 577
    :catchall_3
    move-exception p0

    .line 578
    goto :goto_11

    .line 579
    :cond_11
    :try_start_8
    iget-object v1, v2, Lf8/d;->i:Ljava/lang/Object;

    .line 580
    .line 581
    check-cast v1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 582
    .line 583
    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 584
    .line 585
    .line 586
    move-result-object v1

    .line 587
    iget v3, v2, Lf8/d;->d:I

    .line 588
    .line 589
    monitor-exit v5

    .line 590
    move-object v5, v1

    .line 591
    move v1, v3

    .line 592
    goto/16 :goto_9

    .line 593
    .line 594
    :goto_11
    monitor-exit v5
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 595
    throw p0

    .line 596
    :goto_12
    :try_start_9
    monitor-exit v3
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 597
    throw p0

    .line 598
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 599
    .line 600
    const-string p1, "CameraX is not configured properly. The most likely cause is you did not include a default implementation in your build such as \'camera-camera2\'."

    .line 601
    .line 602
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 603
    .line 604
    .line 605
    throw p0

    .line 606
    nop

    .line 607
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public static a(Ljava/lang/Integer;)V
    .locals 3

    .line 1
    sget-object v0, Lb0/u;->r:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    if-nez p0, :cond_0

    .line 5
    .line 6
    :try_start_0
    monitor-exit v0

    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    goto :goto_1

    .line 10
    :cond_0
    sget-object v1, Lb0/u;->s:Landroid/util/SparseArray;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-virtual {v1, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    check-cast v2, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    add-int/lit8 v2, v2, -0x1

    .line 27
    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    invoke-virtual {v1, p0}, Landroid/util/SparseArray;->remove(I)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-virtual {v1, p0, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    :goto_0
    invoke-static {}, Lb0/u;->b()V

    .line 50
    .line 51
    .line 52
    monitor-exit v0

    .line 53
    return-void

    .line 54
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    throw p0
.end method

.method public static b()V
    .locals 3

    .line 1
    sget-object v0, Lb0/u;->s:Landroid/util/SparseArray;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x3

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    sput v2, Ljp/v1;->a:I

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-virtual {v0, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    sput v2, Ljp/v1;->a:I

    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    const/4 v1, 0x4

    .line 23
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-eqz v2, :cond_2

    .line 28
    .line 29
    sput v1, Ljp/v1;->a:I

    .line 30
    .line 31
    return-void

    .line 32
    :cond_2
    const/4 v1, 0x5

    .line 33
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    sput v1, Ljp/v1;->a:I

    .line 40
    .line 41
    return-void

    .line 42
    :cond_3
    const/4 v1, 0x6

    .line 43
    invoke-virtual {v0, v1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    if-eqz v0, :cond_4

    .line 48
    .line 49
    sput v1, Ljp/v1;->a:I

    .line 50
    .line 51
    :cond_4
    return-void
.end method
