.class public final synthetic Lh0/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lh0/h0;->d:I

    iput-object p2, p0, Lh0/h0;->e:Ljava/lang/Object;

    iput-object p3, p0, Lh0/h0;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lms/p;Ljava/lang/Throwable;)V
    .locals 1

    .line 2
    const/16 v0, 0x17

    iput v0, p0, Lh0/h0;->d:I

    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh0/h0;->e:Ljava/lang/Object;

    iput-object p2, p0, Lh0/h0;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 10

    .line 1
    iget v0, p0, Lh0/h0;->d:I

    .line 2
    .line 3
    const/16 v1, 0x19

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lno/nordicsemi/android/ble/i0;

    .line 13
    .line 14
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Landroid/bluetooth/BluetoothDevice;

    .line 17
    .line 18
    iget-object v0, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    :try_start_0
    invoke-interface {v0, p0}, Lyz0/d;->e(Landroid/bluetooth/BluetoothDevice;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception v0

    .line 27
    move-object p0, v0

    .line 28
    const-string v0, "i0"

    .line 29
    .line 30
    const-string v1, "Exception in Success callback"

    .line 31
    .line 32
    invoke-static {v0, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 33
    .line 34
    .line 35
    :cond_0
    :goto_0
    return-void

    .line 36
    :pswitch_0
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lno/nordicsemi/android/ble/d;

    .line 39
    .line 40
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lno/nordicsemi/android/ble/c0;

    .line 43
    .line 44
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 45
    .line 46
    if-nez p0, :cond_2

    .line 47
    .line 48
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 49
    .line 50
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    const/4 v1, 0x5

    .line 55
    if-lt v1, p0, :cond_1

    .line 56
    .line 57
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 58
    .line 59
    const-string v2, "Callback not received in 1000 ms"

    .line 60
    .line 61
    invoke-virtual {p0, v1, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 62
    .line 63
    .line 64
    :cond_1
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/d;->t()Z

    .line 65
    .line 66
    .line 67
    :cond_2
    return-void

    .line 68
    :pswitch_1
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v0, Lno/nordicsemi/android/ble/s;

    .line 71
    .line 72
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Lb01/b;

    .line 75
    .line 76
    invoke-interface {v0, p0}, Lno/nordicsemi/android/ble/s;->a(Lb01/b;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :pswitch_2
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Lfb/u;

    .line 83
    .line 84
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p0, Ljava/util/UUID;

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    const-string v1, "toString(...)"

    .line 93
    .line 94
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-static {v0, p0}, Lnb/e;->a(Lfb/u;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :pswitch_3
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v0, Ln8/k;

    .line 104
    .line 105
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p0, Landroid/graphics/SurfaceTexture;

    .line 108
    .line 109
    iget-object v1, v0, Ln8/k;->j:Landroid/graphics/SurfaceTexture;

    .line 110
    .line 111
    iget-object v2, v0, Ln8/k;->k:Landroid/view/Surface;

    .line 112
    .line 113
    new-instance v3, Landroid/view/Surface;

    .line 114
    .line 115
    invoke-direct {v3, p0}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 116
    .line 117
    .line 118
    iput-object p0, v0, Ln8/k;->j:Landroid/graphics/SurfaceTexture;

    .line 119
    .line 120
    iput-object v3, v0, Ln8/k;->k:Landroid/view/Surface;

    .line 121
    .line 122
    iget-object p0, v0, Ln8/k;->d:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    if-eqz v0, :cond_3

    .line 133
    .line 134
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, La8/f0;

    .line 139
    .line 140
    iget-object v0, v0, La8/f0;->d:La8/i0;

    .line 141
    .line 142
    invoke-virtual {v0, v3}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_3
    if-eqz v1, :cond_4

    .line 147
    .line 148
    invoke-virtual {v1}, Landroid/graphics/SurfaceTexture;->release()V

    .line 149
    .line 150
    .line 151
    :cond_4
    if-eqz v2, :cond_5

    .line 152
    .line 153
    invoke-virtual {v2}, Landroid/view/Surface;->release()V

    .line 154
    .line 155
    .line 156
    :cond_5
    return-void

    .line 157
    :pswitch_4
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v0, Lms/p;

    .line 160
    .line 161
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast p0, Ljava/lang/String;

    .line 164
    .line 165
    iget-object v0, v0, Lms/p;->h:Lms/l;

    .line 166
    .line 167
    iget-object v0, v0, Lms/l;->d:Lss/b;

    .line 168
    .line 169
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 170
    .line 171
    .line 172
    const/16 v1, 0x400

    .line 173
    .line 174
    invoke-static {v1, p0}, Los/e;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    iget-object v1, v0, Lss/b;->k:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast v1, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 181
    .line 182
    monitor-enter v1

    .line 183
    :try_start_1
    iget-object v2, v0, Lss/b;->k:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast v2, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 186
    .line 187
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    check-cast v2, Ljava/lang/String;

    .line 192
    .line 193
    if-nez p0, :cond_7

    .line 194
    .line 195
    if-nez v2, :cond_6

    .line 196
    .line 197
    move v2, v3

    .line 198
    goto :goto_2

    .line 199
    :cond_6
    const/4 v2, 0x0

    .line 200
    goto :goto_2

    .line 201
    :cond_7
    invoke-virtual {p0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    :goto_2
    if-eqz v2, :cond_8

    .line 206
    .line 207
    monitor-exit v1

    .line 208
    goto :goto_3

    .line 209
    :catchall_1
    move-exception v0

    .line 210
    move-object p0, v0

    .line 211
    goto :goto_4

    .line 212
    :cond_8
    iget-object v2, v0, Lss/b;->k:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v2, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 215
    .line 216
    invoke-virtual {v2, p0, v3}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->set(Ljava/lang/Object;Z)V

    .line 217
    .line 218
    .line 219
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 220
    iget-object p0, v0, Lss/b;->g:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast p0, Lns/d;

    .line 223
    .line 224
    iget-object p0, p0, Lns/d;->b:Lns/b;

    .line 225
    .line 226
    new-instance v1, Lm8/o;

    .line 227
    .line 228
    const/4 v2, 0x3

    .line 229
    invoke-direct {v1, v0, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {p0, v1}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 233
    .line 234
    .line 235
    :goto_3
    return-void

    .line 236
    :goto_4
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 237
    throw p0

    .line 238
    :pswitch_5
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast v0, Lms/p;

    .line 241
    .line 242
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 243
    .line 244
    move-object v4, p0

    .line 245
    check-cast v4, Ljava/lang/Throwable;

    .line 246
    .line 247
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 248
    .line 249
    iget-object v0, v0, Lms/p;->h:Lms/l;

    .line 250
    .line 251
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 252
    .line 253
    .line 254
    move-result-object v5

    .line 255
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 256
    .line 257
    .line 258
    const-string v1, "FirebaseCrashlytics"

    .line 259
    .line 260
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 261
    .line 262
    .line 263
    move-result-wide v6

    .line 264
    iget-object v3, v0, Lms/l;->n:Lms/r;

    .line 265
    .line 266
    if-eqz v3, :cond_9

    .line 267
    .line 268
    iget-object v3, v3, Lms/r;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 269
    .line 270
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 271
    .line 272
    .line 273
    move-result v3

    .line 274
    if-eqz v3, :cond_9

    .line 275
    .line 276
    goto :goto_5

    .line 277
    :cond_9
    const-wide/16 v8, 0x3e8

    .line 278
    .line 279
    div-long/2addr v6, v8

    .line 280
    invoke-virtual {v0}, Lms/l;->e()Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v3

    .line 284
    if-nez v3, :cond_a

    .line 285
    .line 286
    const-string p0, "Tried to write a non-fatal exception while no session was open."

    .line 287
    .line 288
    invoke-static {v1, p0, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 289
    .line 290
    .line 291
    goto :goto_5

    .line 292
    :cond_a
    move-wide v8, v6

    .line 293
    new-instance v7, Los/c;

    .line 294
    .line 295
    invoke-direct {v7, v3, v8, v9, p0}, Los/c;-><init>(Ljava/lang/String;JLjava/util/Map;)V

    .line 296
    .line 297
    .line 298
    iget-object p0, v0, Lms/l;->m:Lss/b;

    .line 299
    .line 300
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 301
    .line 302
    .line 303
    const-string v0, "Persisting non-fatal event for session "

    .line 304
    .line 305
    invoke-virtual {v0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    const/4 v3, 0x2

    .line 310
    invoke-static {v1, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 311
    .line 312
    .line 313
    move-result v3

    .line 314
    if-eqz v3, :cond_b

    .line 315
    .line 316
    invoke-static {v1, v0, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 317
    .line 318
    .line 319
    :cond_b
    const-string v6, "error"

    .line 320
    .line 321
    const/4 v8, 0x0

    .line 322
    move-object v3, p0

    .line 323
    invoke-virtual/range {v3 .. v8}, Lss/b;->j(Ljava/lang/Throwable;Ljava/lang/Thread;Ljava/lang/String;Los/c;Z)V

    .line 324
    .line 325
    .line 326
    :goto_5
    return-void

    .line 327
    :pswitch_6
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 328
    .line 329
    check-cast v0, Lms/l;

    .line 330
    .line 331
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 332
    .line 333
    check-cast p0, Ljava/lang/String;

    .line 334
    .line 335
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 336
    .line 337
    invoke-virtual {v0, p0, v1}, Lms/l;->c(Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 338
    .line 339
    .line 340
    return-void

    .line 341
    :pswitch_7
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v0, Lb81/b;

    .line 344
    .line 345
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast p0, La8/g;

    .line 348
    .line 349
    monitor-enter p0

    .line 350
    monitor-exit p0

    .line 351
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 352
    .line 353
    check-cast v0, La8/f0;

    .line 354
    .line 355
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 356
    .line 357
    iget-object v0, v0, La8/f0;->d:La8/i0;

    .line 358
    .line 359
    iget-object v0, v0, La8/i0;->w:Lb8/e;

    .line 360
    .line 361
    iget-object v1, v0, Lb8/e;->g:Lin/z1;

    .line 362
    .line 363
    iget-object v1, v1, Lin/z1;->e:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v1, Lh8/b0;

    .line 366
    .line 367
    invoke-virtual {v0, v1}, Lb8/e;->I(Lh8/b0;)Lb8/a;

    .line 368
    .line 369
    .line 370
    move-result-object v1

    .line 371
    new-instance v2, La8/t;

    .line 372
    .line 373
    const/16 v3, 0xb

    .line 374
    .line 375
    invoke-direct {v2, v1, p0, v3}, La8/t;-><init>(Lb8/a;Ljava/lang/Object;I)V

    .line 376
    .line 377
    .line 378
    const/16 p0, 0x3fc

    .line 379
    .line 380
    invoke-virtual {v0, v1, p0, v2}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 381
    .line 382
    .line 383
    return-void

    .line 384
    :pswitch_8
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 385
    .line 386
    check-cast v0, Lb81/b;

    .line 387
    .line 388
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast p0, Lt7/a1;

    .line 391
    .line 392
    iget-object v0, v0, Lb81/b;->f:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast v0, La8/f0;

    .line 395
    .line 396
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 397
    .line 398
    iget-object v0, v0, La8/f0;->d:La8/i0;

    .line 399
    .line 400
    iput-object p0, v0, La8/i0;->w1:Lt7/a1;

    .line 401
    .line 402
    iget-object v0, v0, La8/i0;->q:Le30/v;

    .line 403
    .line 404
    new-instance v2, La8/e0;

    .line 405
    .line 406
    invoke-direct {v2, p0}, La8/e0;-><init>(Lt7/a1;)V

    .line 407
    .line 408
    .line 409
    invoke-virtual {v0, v1, v2}, Le30/v;->e(ILw7/j;)V

    .line 410
    .line 411
    .line 412
    return-void

    .line 413
    :pswitch_9
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 414
    .line 415
    check-cast v0, Lb81/a;

    .line 416
    .line 417
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 418
    .line 419
    check-cast p0, Lt7/a1;

    .line 420
    .line 421
    iget-object v0, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 422
    .line 423
    check-cast v0, Lm8/c;

    .line 424
    .line 425
    iget-object v0, v0, Lm8/c;->g:Lm8/g0;

    .line 426
    .line 427
    invoke-interface {v0, p0}, Lm8/g0;->a(Lt7/a1;)V

    .line 428
    .line 429
    .line 430
    return-void

    .line 431
    :pswitch_a
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 432
    .line 433
    check-cast v0, Ljava/lang/Runnable;

    .line 434
    .line 435
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast p0, Lla/a0;

    .line 438
    .line 439
    :try_start_3
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 440
    .line 441
    .line 442
    invoke-virtual {p0}, Lla/a0;->a()V

    .line 443
    .line 444
    .line 445
    return-void

    .line 446
    :catchall_2
    move-exception v0

    .line 447
    invoke-virtual {p0}, Lla/a0;->a()V

    .line 448
    .line 449
    .line 450
    throw v0

    .line 451
    :pswitch_b
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 452
    .line 453
    check-cast v0, Ljava/util/List;

    .line 454
    .line 455
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast p0, Lh2/s;

    .line 458
    .line 459
    check-cast v0, Ljava/lang/Iterable;

    .line 460
    .line 461
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 466
    .line 467
    .line 468
    move-result v1

    .line 469
    if-eqz v1, :cond_c

    .line 470
    .line 471
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object v1

    .line 475
    check-cast v1, Ljb/a;

    .line 476
    .line 477
    iget-object v2, p0, Lh2/s;->e:Ljava/lang/Object;

    .line 478
    .line 479
    invoke-virtual {v1, v2}, Ljb/a;->a(Ljava/lang/Object;)V

    .line 480
    .line 481
    .line 482
    goto :goto_6

    .line 483
    :cond_c
    return-void

    .line 484
    :pswitch_c
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 485
    .line 486
    check-cast v0, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;

    .line 487
    .line 488
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 489
    .line 490
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 491
    .line 492
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;->b(Lio/opentelemetry/sdk/trace/export/SimpleSpanProcessor;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 493
    .line 494
    .line 495
    return-void

    .line 496
    :pswitch_d
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 497
    .line 498
    check-cast v0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 499
    .line 500
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 501
    .line 502
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 503
    .line 504
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/metrics/export/PeriodicMetricReader;->j(Lio/opentelemetry/sdk/common/CompletableResultCode;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 505
    .line 506
    .line 507
    return-void

    .line 508
    :pswitch_e
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 509
    .line 510
    check-cast v0, Lio/opentelemetry/sdk/logs/export/SimpleLogRecordProcessor;

    .line 511
    .line 512
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 513
    .line 514
    check-cast p0, Lio/opentelemetry/sdk/common/CompletableResultCode;

    .line 515
    .line 516
    invoke-static {v0, p0}, Lio/opentelemetry/sdk/logs/export/SimpleLogRecordProcessor;->b(Lio/opentelemetry/sdk/logs/export/SimpleLogRecordProcessor;Lio/opentelemetry/sdk/common/CompletableResultCode;)V

    .line 517
    .line 518
    .line 519
    return-void

    .line 520
    :pswitch_f
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 521
    .line 522
    check-cast v0, Lio/opentelemetry/exporter/internal/otlp/traces/SpanReusableDataMarshaler;

    .line 523
    .line 524
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 525
    .line 526
    check-cast p0, Lio/opentelemetry/exporter/internal/otlp/traces/LowAllocationTraceRequestMarshaler;

    .line 527
    .line 528
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/traces/SpanReusableDataMarshaler;->a(Lio/opentelemetry/exporter/internal/otlp/traces/SpanReusableDataMarshaler;Lio/opentelemetry/exporter/internal/otlp/traces/LowAllocationTraceRequestMarshaler;)V

    .line 529
    .line 530
    .line 531
    return-void

    .line 532
    :pswitch_10
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 533
    .line 534
    check-cast v0, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;

    .line 535
    .line 536
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast p0, Lio/opentelemetry/exporter/internal/otlp/metrics/LowAllocationMetricsRequestMarshaler;

    .line 539
    .line 540
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;->a(Lio/opentelemetry/exporter/internal/otlp/metrics/MetricReusableDataMarshaler;Lio/opentelemetry/exporter/internal/otlp/metrics/LowAllocationMetricsRequestMarshaler;)V

    .line 541
    .line 542
    .line 543
    return-void

    .line 544
    :pswitch_11
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 545
    .line 546
    check-cast v0, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;

    .line 547
    .line 548
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 549
    .line 550
    check-cast p0, Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;

    .line 551
    .line 552
    invoke-static {v0, p0}, Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;->a(Lio/opentelemetry/exporter/internal/otlp/logs/LogReusableDataMarshaler;Lio/opentelemetry/exporter/internal/otlp/logs/LowAllocationLogsRequestMarshaler;)V

    .line 553
    .line 554
    .line 555
    return-void

    .line 556
    :pswitch_12
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 557
    .line 558
    check-cast v0, Lio/opentelemetry/context/Context;

    .line 559
    .line 560
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 561
    .line 562
    check-cast p0, Ljava/lang/Runnable;

    .line 563
    .line 564
    invoke-static {v0, p0}, Lio/opentelemetry/context/Context;->f(Lio/opentelemetry/context/Context;Ljava/lang/Runnable;)V

    .line 565
    .line 566
    .line 567
    return-void

    .line 568
    :pswitch_13
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 569
    .line 570
    check-cast v0, Lm8/o;

    .line 571
    .line 572
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 573
    .line 574
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 575
    .line 576
    :try_start_4
    invoke-virtual {v0}, Lm8/o;->run()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 577
    .line 578
    .line 579
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 580
    .line 581
    .line 582
    return-void

    .line 583
    :catchall_3
    move-exception v0

    .line 584
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 585
    .line 586
    .line 587
    throw v0

    .line 588
    :pswitch_14
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 589
    .line 590
    check-cast v0, Li0/e;

    .line 591
    .line 592
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 593
    .line 594
    check-cast p0, Landroidx/lifecycle/g0;

    .line 595
    .line 596
    new-instance v4, Le81/w;

    .line 597
    .line 598
    invoke-direct {v4, v0, v1}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 599
    .line 600
    .line 601
    new-instance v1, Lh0/g1;

    .line 602
    .line 603
    invoke-direct {v1, v4, v3}, Lh0/g1;-><init>(Ljava/lang/Object;I)V

    .line 604
    .line 605
    .line 606
    if-eqz p0, :cond_13

    .line 607
    .line 608
    new-instance v4, Landroidx/lifecycle/h0;

    .line 609
    .line 610
    invoke-direct {v4, p0, v1}, Landroidx/lifecycle/h0;-><init>(Landroidx/lifecycle/g0;Lh0/g1;)V

    .line 611
    .line 612
    .line 613
    iget-object v5, v0, Li0/e;->l:Lo/f;

    .line 614
    .line 615
    invoke-virtual {v5, p0}, Lo/f;->c(Ljava/lang/Object;)Lo/c;

    .line 616
    .line 617
    .line 618
    move-result-object v6

    .line 619
    if-eqz v6, :cond_d

    .line 620
    .line 621
    iget-object v2, v6, Lo/c;->e:Ljava/lang/Object;

    .line 622
    .line 623
    goto :goto_7

    .line 624
    :cond_d
    new-instance v6, Lo/c;

    .line 625
    .line 626
    invoke-direct {v6, p0, v4}, Lo/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 627
    .line 628
    .line 629
    iget v7, v5, Lo/f;->g:I

    .line 630
    .line 631
    add-int/2addr v7, v3

    .line 632
    iput v7, v5, Lo/f;->g:I

    .line 633
    .line 634
    iget-object v3, v5, Lo/f;->e:Lo/c;

    .line 635
    .line 636
    if-nez v3, :cond_e

    .line 637
    .line 638
    iput-object v6, v5, Lo/f;->d:Lo/c;

    .line 639
    .line 640
    iput-object v6, v5, Lo/f;->e:Lo/c;

    .line 641
    .line 642
    goto :goto_7

    .line 643
    :cond_e
    iput-object v6, v3, Lo/c;->f:Lo/c;

    .line 644
    .line 645
    iput-object v3, v6, Lo/c;->g:Lo/c;

    .line 646
    .line 647
    iput-object v6, v5, Lo/f;->e:Lo/c;

    .line 648
    .line 649
    :goto_7
    check-cast v2, Landroidx/lifecycle/h0;

    .line 650
    .line 651
    if-eqz v2, :cond_10

    .line 652
    .line 653
    iget-object v3, v2, Landroidx/lifecycle/h0;->b:Lh0/g1;

    .line 654
    .line 655
    if-ne v3, v1, :cond_f

    .line 656
    .line 657
    goto :goto_8

    .line 658
    :cond_f
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 659
    .line 660
    const-string v0, "This source was already added with the different observer"

    .line 661
    .line 662
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 663
    .line 664
    .line 665
    throw p0

    .line 666
    :cond_10
    :goto_8
    if-eqz v2, :cond_11

    .line 667
    .line 668
    goto :goto_9

    .line 669
    :cond_11
    iget v0, v0, Landroidx/lifecycle/g0;->c:I

    .line 670
    .line 671
    if-lez v0, :cond_12

    .line 672
    .line 673
    invoke-virtual {p0, v4}, Landroidx/lifecycle/g0;->f(Landroidx/lifecycle/j0;)V

    .line 674
    .line 675
    .line 676
    :cond_12
    :goto_9
    return-void

    .line 677
    :cond_13
    new-instance p0, Ljava/lang/NullPointerException;

    .line 678
    .line 679
    const-string v0, "source cannot be null"

    .line 680
    .line 681
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 682
    .line 683
    .line 684
    throw p0

    .line 685
    :pswitch_15
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 686
    .line 687
    check-cast v0, Ljava/util/concurrent/Callable;

    .line 688
    .line 689
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 690
    .line 691
    check-cast p0, La0/j;

    .line 692
    .line 693
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 694
    .line 695
    check-cast p0, Lhs/h;

    .line 696
    .line 697
    :try_start_5
    invoke-interface {v0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    .line 698
    .line 699
    .line 700
    move-result-object v0

    .line 701
    invoke-virtual {p0, v0}, Ly4/g;->j(Ljava/lang/Object;)Z
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0

    .line 702
    .line 703
    .line 704
    goto :goto_a

    .line 705
    :catch_0
    move-exception v0

    .line 706
    invoke-virtual {p0, v0}, Ly4/g;->k(Ljava/lang/Throwable;)Z

    .line 707
    .line 708
    .line 709
    :goto_a
    return-void

    .line 710
    :pswitch_16
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 711
    .line 712
    check-cast v0, Lhs/a;

    .line 713
    .line 714
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 715
    .line 716
    check-cast p0, Ljava/lang/Runnable;

    .line 717
    .line 718
    iget v1, v0, Lhs/a;->c:I

    .line 719
    .line 720
    invoke-static {v1}, Landroid/os/Process;->setThreadPriority(I)V

    .line 721
    .line 722
    .line 723
    iget-object v0, v0, Lhs/a;->d:Landroid/os/StrictMode$ThreadPolicy;

    .line 724
    .line 725
    if-eqz v0, :cond_14

    .line 726
    .line 727
    invoke-static {v0}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 728
    .line 729
    .line 730
    :cond_14
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 731
    .line 732
    .line 733
    return-void

    .line 734
    :pswitch_17
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 735
    .line 736
    check-cast v0, Lh8/r0;

    .line 737
    .line 738
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 739
    .line 740
    check-cast p0, Lo8/c0;

    .line 741
    .line 742
    invoke-virtual {v0, p0}, Lh8/r0;->C(Lo8/c0;)V

    .line 743
    .line 744
    .line 745
    return-void

    .line 746
    :pswitch_18
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 747
    .line 748
    check-cast v0, Lw7/f;

    .line 749
    .line 750
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 751
    .line 752
    invoke-interface {v0, p0}, Lw7/f;->accept(Ljava/lang/Object;)V

    .line 753
    .line 754
    .line 755
    return-void

    .line 756
    :pswitch_19
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 757
    .line 758
    check-cast v0, Ljava/util/Map$Entry;

    .line 759
    .line 760
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 761
    .line 762
    check-cast p0, Lh0/h1;

    .line 763
    .line 764
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 765
    .line 766
    .line 767
    move-result-object v0

    .line 768
    check-cast v0, Lh0/l1;

    .line 769
    .line 770
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 771
    .line 772
    .line 773
    iget-object p0, p0, Lh0/h1;->a:Lh0/a0;

    .line 774
    .line 775
    invoke-interface {v0, p0}, Lh0/l1;->a(Ljava/lang/Object;)V

    .line 776
    .line 777
    .line 778
    return-void

    .line 779
    :pswitch_1a
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 780
    .line 781
    check-cast v0, Lgw0/c;

    .line 782
    .line 783
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 784
    .line 785
    check-cast p0, Lw0/c;

    .line 786
    .line 787
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 788
    .line 789
    check-cast v0, Landroidx/lifecycle/i0;

    .line 790
    .line 791
    invoke-virtual {v0}, Landroidx/lifecycle/g0;->d()Ljava/lang/Object;

    .line 792
    .line 793
    .line 794
    move-result-object v0

    .line 795
    check-cast v0, Lh0/h1;

    .line 796
    .line 797
    if-nez v0, :cond_15

    .line 798
    .line 799
    goto :goto_b

    .line 800
    :cond_15
    iget-object v0, v0, Lh0/h1;->a:Lh0/a0;

    .line 801
    .line 802
    invoke-virtual {p0, v0}, Lw0/c;->a(Ljava/lang/Object;)V

    .line 803
    .line 804
    .line 805
    :goto_b
    return-void

    .line 806
    :pswitch_1b
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 807
    .line 808
    move-object v1, v0

    .line 809
    check-cast v1, Lh0/t0;

    .line 810
    .line 811
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 812
    .line 813
    check-cast p0, Ljava/lang/String;

    .line 814
    .line 815
    :try_start_6
    iget-object v0, v1, Lh0/t0;->e:Ly4/k;

    .line 816
    .line 817
    invoke-virtual {v0}, Ly4/k;->get()Ljava/lang/Object;

    .line 818
    .line 819
    .line 820
    const-string v0, "Surface terminated"

    .line 821
    .line 822
    sget-object v2, Lh0/t0;->n:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 823
    .line 824
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 825
    .line 826
    .line 827
    move-result v2

    .line 828
    sget-object v3, Lh0/t0;->m:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 829
    .line 830
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 831
    .line 832
    .line 833
    move-result v3

    .line 834
    invoke-virtual {v1, v2, v3, v0}, Lh0/t0;->e(IILjava/lang/String;)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_1

    .line 835
    .line 836
    .line 837
    return-void

    .line 838
    :catch_1
    move-exception v0

    .line 839
    const-string v2, "DeferrableSurface"

    .line 840
    .line 841
    new-instance v3, Ljava/lang/StringBuilder;

    .line 842
    .line 843
    const-string v4, "Unexpected surface termination for "

    .line 844
    .line 845
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 846
    .line 847
    .line 848
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 849
    .line 850
    .line 851
    const-string v4, "\nStack Trace:\n"

    .line 852
    .line 853
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 854
    .line 855
    .line 856
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 857
    .line 858
    .line 859
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 860
    .line 861
    .line 862
    move-result-object p0

    .line 863
    invoke-static {v2, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 864
    .line 865
    .line 866
    iget-object v3, v1, Lh0/t0;->a:Ljava/lang/Object;

    .line 867
    .line 868
    monitor-enter v3

    .line 869
    :try_start_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 870
    .line 871
    const-string v2, "DeferrableSurface %s [closed: %b, use_count: %s] terminated with unexpected exception."

    .line 872
    .line 873
    iget-boolean v4, v1, Lh0/t0;->c:Z

    .line 874
    .line 875
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 876
    .line 877
    .line 878
    move-result-object v4

    .line 879
    iget v5, v1, Lh0/t0;->b:I

    .line 880
    .line 881
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 882
    .line 883
    .line 884
    move-result-object v5

    .line 885
    filled-new-array {v1, v4, v5}, [Ljava/lang/Object;

    .line 886
    .line 887
    .line 888
    move-result-object v1

    .line 889
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 890
    .line 891
    .line 892
    move-result-object v1

    .line 893
    invoke-direct {p0, v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 894
    .line 895
    .line 896
    throw p0

    .line 897
    :catchall_4
    move-exception v0

    .line 898
    move-object p0, v0

    .line 899
    monitor-exit v3
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 900
    throw p0

    .line 901
    :pswitch_1c
    iget-object v0, p0, Lh0/h0;->e:Ljava/lang/Object;

    .line 902
    .line 903
    check-cast v0, Lh0/i0;

    .line 904
    .line 905
    iget-object p0, p0, Lh0/h0;->f:Ljava/lang/Object;

    .line 906
    .line 907
    check-cast p0, Lh0/b0;

    .line 908
    .line 909
    iget-object v1, v0, Lh0/i0;->a:Ljava/lang/Object;

    .line 910
    .line 911
    monitor-enter v1

    .line 912
    :try_start_8
    iget-object v3, v0, Lh0/i0;->c:Ljava/util/HashSet;

    .line 913
    .line 914
    invoke-virtual {v3, p0}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 915
    .line 916
    .line 917
    iget-object p0, v0, Lh0/i0;->c:Ljava/util/HashSet;

    .line 918
    .line 919
    invoke-virtual {p0}, Ljava/util/HashSet;->isEmpty()Z

    .line 920
    .line 921
    .line 922
    move-result p0

    .line 923
    if-eqz p0, :cond_16

    .line 924
    .line 925
    iget-object p0, v0, Lh0/i0;->e:Ly4/h;

    .line 926
    .line 927
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 928
    .line 929
    .line 930
    iget-object p0, v0, Lh0/i0;->e:Ly4/h;

    .line 931
    .line 932
    invoke-virtual {p0, v2}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 933
    .line 934
    .line 935
    iput-object v2, v0, Lh0/i0;->e:Ly4/h;

    .line 936
    .line 937
    iput-object v2, v0, Lh0/i0;->d:Ly4/k;

    .line 938
    .line 939
    goto :goto_c

    .line 940
    :catchall_5
    move-exception v0

    .line 941
    move-object p0, v0

    .line 942
    goto :goto_d

    .line 943
    :cond_16
    :goto_c
    monitor-exit v1

    .line 944
    return-void

    .line 945
    :goto_d
    monitor-exit v1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 946
    throw p0

    .line 947
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
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
