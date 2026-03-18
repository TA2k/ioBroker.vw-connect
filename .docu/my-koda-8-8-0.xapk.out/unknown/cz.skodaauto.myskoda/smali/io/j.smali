.class public final synthetic Lio/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Landroid/os/Parcelable;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/iid/FirebaseInstanceIdReceiver;Landroid/content/Intent;Landroid/content/Context;ZLandroid/content/BroadcastReceiver$PendingResult;)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, Lio/j;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lio/j;->f:Landroid/os/Parcelable;

    iput-object p3, p0, Lio/j;->g:Ljava/lang/Object;

    iput-boolean p4, p0, Lio/j;->e:Z

    iput-object p5, p0, Lio/j;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lvp/d3;Lvp/f4;ZLoo/a;I)V
    .locals 0

    .line 2
    iput p5, p0, Lio/j;->d:I

    iput-object p2, p0, Lio/j;->f:Landroid/os/Parcelable;

    iput-boolean p3, p0, Lio/j;->e:Z

    iput-object p4, p0, Lio/j;->g:Ljava/lang/Object;

    iput-object p1, p0, Lio/j;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lvp/d3;Lvp/f4;ZLvp/f;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lio/j;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lio/j;->f:Landroid/os/Parcelable;

    iput-boolean p3, p0, Lio/j;->e:Z

    iput-object p4, p0, Lio/j;->g:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lio/j;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lio/j;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lio/j;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lvp/d3;

    .line 11
    .line 12
    iget-object v2, v1, Lvp/d3;->h:Lvp/c0;

    .line 13
    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lvp/g1;

    .line 19
    .line 20
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 26
    .line 27
    const-string v1, "Discarding data. Failed to send conditional user property to service"

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_0
    iget-object v3, v0, Lio/j;->f:Landroid/os/Parcelable;

    .line 34
    .line 35
    check-cast v3, Lvp/f4;

    .line 36
    .line 37
    iget-boolean v4, v0, Lio/j;->e:Z

    .line 38
    .line 39
    if-eqz v4, :cond_1

    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    iget-object v0, v0, Lio/j;->g:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v0, Lvp/f;

    .line 46
    .line 47
    :goto_0
    invoke-virtual {v1, v2, v0, v3}, Lvp/d3;->s0(Lvp/c0;Loo/a;Lvp/f4;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1}, Lvp/d3;->n0()V

    .line 51
    .line 52
    .line 53
    :goto_1
    return-void

    .line 54
    :pswitch_0
    iget-object v1, v0, Lio/j;->h:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v1, Lvp/d3;

    .line 57
    .line 58
    iget-object v2, v1, Lvp/d3;->h:Lvp/c0;

    .line 59
    .line 60
    if-nez v2, :cond_2

    .line 61
    .line 62
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lvp/g1;

    .line 65
    .line 66
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 67
    .line 68
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 69
    .line 70
    .line 71
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 72
    .line 73
    const-string v1, "Discarding data. Failed to send event to service"

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_2
    iget-object v3, v0, Lio/j;->f:Landroid/os/Parcelable;

    .line 80
    .line 81
    check-cast v3, Lvp/f4;

    .line 82
    .line 83
    iget-boolean v4, v0, Lio/j;->e:Z

    .line 84
    .line 85
    if-eqz v4, :cond_3

    .line 86
    .line 87
    const/4 v0, 0x0

    .line 88
    goto :goto_2

    .line 89
    :cond_3
    iget-object v0, v0, Lio/j;->g:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Lvp/t;

    .line 92
    .line 93
    :goto_2
    invoke-virtual {v1, v2, v0, v3}, Lvp/d3;->s0(Lvp/c0;Loo/a;Lvp/f4;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v1}, Lvp/d3;->n0()V

    .line 97
    .line 98
    .line 99
    :goto_3
    return-void

    .line 100
    :pswitch_1
    iget-object v1, v0, Lio/j;->h:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v1, Lvp/d3;

    .line 103
    .line 104
    iget-object v2, v1, Lvp/d3;->h:Lvp/c0;

    .line 105
    .line 106
    if-nez v2, :cond_4

    .line 107
    .line 108
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v0, Lvp/g1;

    .line 111
    .line 112
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 113
    .line 114
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 115
    .line 116
    .line 117
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 118
    .line 119
    const-string v1, "Discarding data. Failed to set user property"

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_4
    iget-object v3, v0, Lio/j;->f:Landroid/os/Parcelable;

    .line 126
    .line 127
    check-cast v3, Lvp/f4;

    .line 128
    .line 129
    iget-boolean v4, v0, Lio/j;->e:Z

    .line 130
    .line 131
    if-eqz v4, :cond_5

    .line 132
    .line 133
    const/4 v0, 0x0

    .line 134
    goto :goto_4

    .line 135
    :cond_5
    iget-object v0, v0, Lio/j;->g:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v0, Lvp/b4;

    .line 138
    .line 139
    :goto_4
    invoke-virtual {v1, v2, v0, v3}, Lvp/d3;->s0(Lvp/c0;Loo/a;Lvp/f4;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1}, Lvp/d3;->n0()V

    .line 143
    .line 144
    .line 145
    :goto_5
    return-void

    .line 146
    :pswitch_2
    iget-object v1, v0, Lio/j;->f:Landroid/os/Parcelable;

    .line 147
    .line 148
    check-cast v1, Landroid/content/Intent;

    .line 149
    .line 150
    iget-object v2, v0, Lio/j;->g:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v2, Landroid/content/Context;

    .line 153
    .line 154
    iget-boolean v3, v0, Lio/j;->e:Z

    .line 155
    .line 156
    iget-object v0, v0, Lio/j;->h:Ljava/lang/Object;

    .line 157
    .line 158
    move-object v4, v0

    .line 159
    check-cast v4, Landroid/content/BroadcastReceiver$PendingResult;

    .line 160
    .line 161
    :try_start_0
    const-string v0, "wrapped_intent"

    .line 162
    .line 163
    invoke-virtual {v1, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    instance-of v5, v0, Landroid/content/Intent;

    .line 168
    .line 169
    const/4 v6, 0x0

    .line 170
    if-eqz v5, :cond_6

    .line 171
    .line 172
    check-cast v0, Landroid/content/Intent;

    .line 173
    .line 174
    goto :goto_6

    .line 175
    :catchall_0
    move-exception v0

    .line 176
    goto/16 :goto_c

    .line 177
    .line 178
    :cond_6
    move-object v0, v6

    .line 179
    :goto_6
    if-eqz v0, :cond_7

    .line 180
    .line 181
    invoke-static {v0}, Lcom/google/firebase/iid/FirebaseInstanceIdReceiver;->a(Landroid/content/Intent;)I

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    goto/16 :goto_a

    .line 186
    .line 187
    :cond_7
    invoke-virtual {v1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    const/16 v5, 0x1f4

    .line 192
    .line 193
    if-nez v0, :cond_9

    .line 194
    .line 195
    :cond_8
    :goto_7
    move v0, v5

    .line 196
    goto/16 :goto_a

    .line 197
    .line 198
    :cond_9
    new-instance v0, Lio/a;

    .line 199
    .line 200
    invoke-direct {v0, v1}, Lio/a;-><init>(Landroid/content/Intent;)V

    .line 201
    .line 202
    .line 203
    new-instance v7, Ljava/util/concurrent/CountDownLatch;

    .line 204
    .line 205
    const/4 v8, 0x1

    .line 206
    invoke-direct {v7, v8}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 207
    .line 208
    .line 209
    const-class v9, Lcom/google/firebase/iid/FirebaseInstanceIdReceiver;

    .line 210
    .line 211
    monitor-enter v9
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 212
    :try_start_1
    sget-object v10, Lcom/google/firebase/iid/FirebaseInstanceIdReceiver;->b:Ljava/lang/ref/SoftReference;

    .line 213
    .line 214
    if-eqz v10, :cond_a

    .line 215
    .line 216
    invoke-virtual {v10}, Ljava/lang/ref/SoftReference;->get()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v6

    .line 220
    check-cast v6, Ljava/util/concurrent/Executor;

    .line 221
    .line 222
    goto :goto_8

    .line 223
    :catchall_1
    move-exception v0

    .line 224
    goto/16 :goto_b

    .line 225
    .line 226
    :cond_a
    :goto_8
    if-nez v6, :cond_b

    .line 227
    .line 228
    new-instance v6, Luo/a;

    .line 229
    .line 230
    const-string v10, "pscm-ack-executor"

    .line 231
    .line 232
    invoke-direct {v6, v10}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    new-instance v10, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 236
    .line 237
    sget-object v15, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 238
    .line 239
    new-instance v16, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 240
    .line 241
    invoke-direct/range {v16 .. v16}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 242
    .line 243
    .line 244
    const/4 v11, 0x1

    .line 245
    const/4 v12, 0x1

    .line 246
    const-wide/16 v13, 0x3c

    .line 247
    .line 248
    move-object/from16 v17, v6

    .line 249
    .line 250
    invoke-direct/range {v10 .. v17}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v10, v8}, Ljava/util/concurrent/ThreadPoolExecutor;->allowCoreThreadTimeOut(Z)V

    .line 254
    .line 255
    .line 256
    invoke-static {v10}, Ljava/util/concurrent/Executors;->unconfigurableExecutorService(Ljava/util/concurrent/ExecutorService;)Ljava/util/concurrent/ExecutorService;

    .line 257
    .line 258
    .line 259
    move-result-object v6

    .line 260
    new-instance v8, Ljava/lang/ref/SoftReference;

    .line 261
    .line 262
    invoke-direct {v8, v6}, Ljava/lang/ref/SoftReference;-><init>(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    sput-object v8, Lcom/google/firebase/iid/FirebaseInstanceIdReceiver;->b:Ljava/lang/ref/SoftReference;

    .line 266
    .line 267
    :cond_b
    monitor-exit v9
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 268
    :try_start_2
    new-instance v8, Lio/i;

    .line 269
    .line 270
    const/4 v9, 0x0

    .line 271
    invoke-direct {v8, v2, v0, v7, v9}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 272
    .line 273
    .line 274
    invoke-interface {v6, v8}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 275
    .line 276
    .line 277
    :try_start_3
    new-instance v0, Lcom/google/firebase/messaging/j;

    .line 278
    .line 279
    invoke-direct {v0, v2}, Lcom/google/firebase/messaging/j;-><init>(Landroid/content/Context;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0, v1}, Lcom/google/firebase/messaging/j;->b(Landroid/content/Intent;)Laq/t;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    invoke-static {v0}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    check-cast v0, Ljava/lang/Integer;

    .line 291
    .line 292
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 293
    .line 294
    .line 295
    move-result v0
    :try_end_3
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_3 .. :try_end_3} :catch_0
    .catch Ljava/lang/InterruptedException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 296
    move v5, v0

    .line 297
    goto :goto_9

    .line 298
    :catch_0
    move-exception v0

    .line 299
    :try_start_4
    const-string v1, "FirebaseMessaging"

    .line 300
    .line 301
    const-string v2, "Failed to send message to service."

    .line 302
    .line 303
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 304
    .line 305
    .line 306
    :goto_9
    :try_start_5
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 307
    .line 308
    const-wide/16 v1, 0x1

    .line 309
    .line 310
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 311
    .line 312
    .line 313
    move-result-wide v0

    .line 314
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 315
    .line 316
    invoke-virtual {v7, v0, v1, v2}, Ljava/util/concurrent/CountDownLatch;->await(JLjava/util/concurrent/TimeUnit;)Z

    .line 317
    .line 318
    .line 319
    move-result v0

    .line 320
    if-nez v0, :cond_8

    .line 321
    .line 322
    const-string v0, "CloudMessagingReceiver"

    .line 323
    .line 324
    const-string v1, "Message ack timed out"

    .line 325
    .line 326
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_5
    .catch Ljava/lang/InterruptedException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 327
    .line 328
    .line 329
    goto/16 :goto_7

    .line 330
    .line 331
    :catch_1
    move-exception v0

    .line 332
    :try_start_6
    const-string v1, "CloudMessagingReceiver"

    .line 333
    .line 334
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    const-string v2, "Message ack failed: "

    .line 339
    .line 340
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v0

    .line 344
    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 345
    .line 346
    .line 347
    goto/16 :goto_7

    .line 348
    .line 349
    :goto_a
    if-eqz v3, :cond_c

    .line 350
    .line 351
    if-eqz v4, :cond_c

    .line 352
    .line 353
    invoke-virtual {v4, v0}, Landroid/content/BroadcastReceiver$PendingResult;->setResultCode(I)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 354
    .line 355
    .line 356
    :cond_c
    if-eqz v4, :cond_d

    .line 357
    .line 358
    invoke-virtual {v4}, Landroid/content/BroadcastReceiver$PendingResult;->finish()V

    .line 359
    .line 360
    .line 361
    :cond_d
    return-void

    .line 362
    :goto_b
    :try_start_7
    monitor-exit v9
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 363
    :try_start_8
    throw v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 364
    :goto_c
    if-eqz v4, :cond_e

    .line 365
    .line 366
    invoke-virtual {v4}, Landroid/content/BroadcastReceiver$PendingResult;->finish()V

    .line 367
    .line 368
    .line 369
    :cond_e
    throw v0

    .line 370
    nop

    .line 371
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
