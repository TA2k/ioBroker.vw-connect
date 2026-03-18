.class public Lcom/google/firebase/messaging/FirebaseMessagingService;
.super Lcom/google/firebase/messaging/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ACTION_DIRECT_BOOT_REMOTE_INTENT:Ljava/lang/String; = "com.google.firebase.messaging.RECEIVE_DIRECT_BOOT"

.field static final ACTION_NEW_TOKEN:Ljava/lang/String; = "com.google.firebase.messaging.NEW_TOKEN"

.field static final ACTION_REMOTE_INTENT:Ljava/lang/String; = "com.google.android.c2dm.intent.RECEIVE"

.field static final EXTRA_TOKEN:Ljava/lang/String; = "token"

.field private static final RECENTLY_RECEIVED_MESSAGE_IDS_MAX_SIZE:I = 0xa

.field private static final recentlyReceivedMessageIds:Ljava/util/Queue;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Queue<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private rpc:Lio/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/ArrayDeque;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/ArrayDeque;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/firebase/messaging/FirebaseMessagingService;->recentlyReceivedMessageIds:Ljava/util/Queue;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/firebase/messaging/g;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static resetForTesting()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/firebase/messaging/FirebaseMessagingService;->recentlyReceivedMessageIds:Ljava/util/Queue;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->clear()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public getStartCommandIntent(Landroid/content/Intent;)Landroid/content/Intent;
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/ArrayDeque;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Landroid/content/Intent;

    .line 14
    .line 15
    return-object p0
.end method

.method public handleIntent(Landroid/content/Intent;)V
    .locals 10

    .line 1
    const-string v0, "FirebaseMessaging"

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const-string v2, "com.google.android.c2dm.intent.RECEIVE"

    .line 8
    .line 9
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-nez v2, :cond_2

    .line 14
    .line 15
    const-string v2, "com.google.firebase.messaging.RECEIVE_DIRECT_BOOT"

    .line 16
    .line 17
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const-string v2, "com.google.firebase.messaging.NEW_TOKEN"

    .line 25
    .line 26
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    const-string v0, "token"

    .line 33
    .line 34
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/FirebaseMessagingService;->onNewToken(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v1, "Unknown intent action: "

    .line 45
    .line 46
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :cond_2
    :goto_0
    const-string v1, "google.product_id"

    .line 65
    .line 66
    const-string v2, "message_id"

    .line 67
    .line 68
    const-string v3, "google.message_id"

    .line 69
    .line 70
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    const/4 v6, 0x3

    .line 79
    const/4 v7, 0x0

    .line 80
    if-eqz v5, :cond_3

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_3
    sget-object v5, Lcom/google/firebase/messaging/FirebaseMessagingService;->recentlyReceivedMessageIds:Ljava/util/Queue;

    .line 84
    .line 85
    invoke-interface {v5, v4}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v8

    .line 89
    if-eqz v8, :cond_4

    .line 90
    .line 91
    invoke-static {v0, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    if-eqz v5, :cond_10

    .line 96
    .line 97
    new-instance v5, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v8, "Received duplicate message: "

    .line 100
    .line 101
    invoke-direct {v5, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v4

    .line 111
    invoke-static {v0, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 112
    .line 113
    .line 114
    goto/16 :goto_5

    .line 115
    .line 116
    :cond_4
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 117
    .line 118
    .line 119
    move-result v8

    .line 120
    const/16 v9, 0xa

    .line 121
    .line 122
    if-lt v8, v9, :cond_5

    .line 123
    .line 124
    invoke-interface {v5}, Ljava/util/Queue;->remove()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    :cond_5
    invoke-interface {v5, v4}, Ljava/util/Queue;->add(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    :goto_1
    const-string v4, "message_type"

    .line 131
    .line 132
    invoke-virtual {p1, v4}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    if-nez v4, :cond_6

    .line 137
    .line 138
    const-string v4, "gcm"

    .line 139
    .line 140
    :cond_6
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 141
    .line 142
    .line 143
    move-result v5

    .line 144
    const/4 v8, -0x1

    .line 145
    sparse-switch v5, :sswitch_data_0

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :sswitch_0
    const-string v5, "send_event"

    .line 150
    .line 151
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v5

    .line 155
    if-nez v5, :cond_7

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_7
    move v8, v6

    .line 159
    goto :goto_2

    .line 160
    :sswitch_1
    const-string v5, "send_error"

    .line 161
    .line 162
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v5

    .line 166
    if-nez v5, :cond_8

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_8
    const/4 v8, 0x2

    .line 170
    goto :goto_2

    .line 171
    :sswitch_2
    const-string v5, "gcm"

    .line 172
    .line 173
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result v5

    .line 177
    if-nez v5, :cond_9

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_9
    const/4 v8, 0x1

    .line 181
    goto :goto_2

    .line 182
    :sswitch_3
    const-string v5, "deleted_messages"

    .line 183
    .line 184
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v5

    .line 188
    if-nez v5, :cond_a

    .line 189
    .line 190
    goto :goto_2

    .line 191
    :cond_a
    move v8, v7

    .line 192
    :goto_2
    packed-switch v8, :pswitch_data_0

    .line 193
    .line 194
    .line 195
    const-string v5, "Received message with unknown type: "

    .line 196
    .line 197
    invoke-virtual {v5, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    invoke-static {v0, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 202
    .line 203
    .line 204
    goto/16 :goto_5

    .line 205
    .line 206
    :pswitch_0
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/FirebaseMessagingService;->onMessageSent(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    goto/16 :goto_5

    .line 214
    .line 215
    :pswitch_1
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    if-nez v0, :cond_b

    .line 220
    .line 221
    invoke-virtual {p1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    :cond_b
    new-instance v4, Lb0/l;

    .line 226
    .line 227
    const-string v5, "error"

    .line 228
    .line 229
    invoke-virtual {p1, v5}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v5

    .line 233
    invoke-direct {v4, v5}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    if-nez v5, :cond_c

    .line 237
    .line 238
    goto :goto_3

    .line 239
    :cond_c
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 240
    .line 241
    invoke-virtual {v5, v8}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v5

    .line 245
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 246
    .line 247
    .line 248
    :goto_3
    invoke-virtual {p0, v0, v4}, Lcom/google/firebase/messaging/FirebaseMessagingService;->onSendError(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 249
    .line 250
    .line 251
    goto :goto_5

    .line 252
    :pswitch_2
    invoke-static {p1}, Ljp/je;->b(Landroid/content/Intent;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    if-nez v0, :cond_d

    .line 260
    .line 261
    new-instance v0, Landroid/os/Bundle;

    .line 262
    .line 263
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 264
    .line 265
    .line 266
    :cond_d
    const-string v4, "androidx.content.wakelockid"

    .line 267
    .line 268
    invoke-virtual {v0, v4}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    invoke-static {v0}, Laq/a;->z(Landroid/os/Bundle;)Z

    .line 272
    .line 273
    .line 274
    move-result v4

    .line 275
    if-eqz v4, :cond_f

    .line 276
    .line 277
    new-instance v4, Laq/a;

    .line 278
    .line 279
    invoke-direct {v4, v0}, Laq/a;-><init>(Landroid/os/Bundle;)V

    .line 280
    .line 281
    .line 282
    new-instance v5, Luo/a;

    .line 283
    .line 284
    const-string v8, "Firebase-Messaging-Network-Io"

    .line 285
    .line 286
    invoke-direct {v5, v8}, Luo/a;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    invoke-static {v5}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor(Ljava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 290
    .line 291
    .line 292
    move-result-object v5

    .line 293
    new-instance v8, Lgw0/c;

    .line 294
    .line 295
    invoke-direct {v8, p0, v4, v5}, Lgw0/c;-><init>(Lcom/google/firebase/messaging/FirebaseMessagingService;Laq/a;Ljava/util/concurrent/ExecutorService;)V

    .line 296
    .line 297
    .line 298
    :try_start_0
    invoke-virtual {v8}, Lgw0/c;->p()Z

    .line 299
    .line 300
    .line 301
    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 302
    if-eqz v4, :cond_e

    .line 303
    .line 304
    invoke-interface {v5}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 305
    .line 306
    .line 307
    goto :goto_5

    .line 308
    :cond_e
    invoke-interface {v5}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 309
    .line 310
    .line 311
    invoke-static {p1}, Ljp/je;->f(Landroid/content/Intent;)Z

    .line 312
    .line 313
    .line 314
    move-result v4

    .line 315
    if-eqz v4, :cond_f

    .line 316
    .line 317
    const-string v4, "_nf"

    .line 318
    .line 319
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 320
    .line 321
    .line 322
    move-result-object v5

    .line 323
    invoke-static {v4, v5}, Ljp/je;->c(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 324
    .line 325
    .line 326
    goto :goto_4

    .line 327
    :catchall_0
    move-exception p0

    .line 328
    invoke-interface {v5}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 329
    .line 330
    .line 331
    throw p0

    .line 332
    :cond_f
    :goto_4
    new-instance v4, Lcom/google/firebase/messaging/v;

    .line 333
    .line 334
    invoke-direct {v4, v0}, Lcom/google/firebase/messaging/v;-><init>(Landroid/os/Bundle;)V

    .line 335
    .line 336
    .line 337
    invoke-virtual {p0, v4}, Lcom/google/firebase/messaging/FirebaseMessagingService;->onMessageReceived(Lcom/google/firebase/messaging/v;)V

    .line 338
    .line 339
    .line 340
    goto :goto_5

    .line 341
    :pswitch_3
    invoke-virtual {p0}, Lcom/google/firebase/messaging/FirebaseMessagingService;->onDeletedMessages()V

    .line 342
    .line 343
    .line 344
    :cond_10
    :goto_5
    iget-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessagingService;->rpc:Lio/b;

    .line 345
    .line 346
    if-nez v0, :cond_11

    .line 347
    .line 348
    new-instance v0, Lio/b;

    .line 349
    .line 350
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 351
    .line 352
    .line 353
    move-result-object v4

    .line 354
    invoke-direct {v0, v4}, Lio/b;-><init>(Landroid/content/Context;)V

    .line 355
    .line 356
    .line 357
    iput-object v0, p0, Lcom/google/firebase/messaging/FirebaseMessagingService;->rpc:Lio/b;

    .line 358
    .line 359
    :cond_11
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessagingService;->rpc:Lio/b;

    .line 360
    .line 361
    iget-object v0, p0, Lio/b;->c:Lc1/m2;

    .line 362
    .line 363
    invoke-virtual {v0}, Lc1/m2;->q()I

    .line 364
    .line 365
    .line 366
    move-result v0

    .line 367
    const v4, 0xdedfaa0

    .line 368
    .line 369
    .line 370
    if-lt v0, v4, :cond_15

    .line 371
    .line 372
    new-instance v0, Landroid/os/Bundle;

    .line 373
    .line 374
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 375
    .line 376
    .line 377
    invoke-virtual {p1, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v4

    .line 381
    if-nez v4, :cond_12

    .line 382
    .line 383
    invoke-virtual {p1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v4

    .line 387
    :cond_12
    invoke-virtual {v0, v3, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {p1, v1}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 391
    .line 392
    .line 393
    move-result v2

    .line 394
    if-eqz v2, :cond_13

    .line 395
    .line 396
    invoke-virtual {p1, v1, v7}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 397
    .line 398
    .line 399
    move-result p1

    .line 400
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 401
    .line 402
    .line 403
    move-result-object p1

    .line 404
    goto :goto_6

    .line 405
    :cond_13
    const/4 p1, 0x0

    .line 406
    :goto_6
    if-eqz p1, :cond_14

    .line 407
    .line 408
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 409
    .line 410
    .line 411
    move-result p1

    .line 412
    invoke-virtual {v0, v1, p1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 413
    .line 414
    .line 415
    :cond_14
    iget-object p0, p0, Lio/b;->b:Landroid/content/Context;

    .line 416
    .line 417
    invoke-static {p0}, Lio/o;->d(Landroid/content/Context;)Lio/o;

    .line 418
    .line 419
    .line 420
    move-result-object p0

    .line 421
    new-instance p1, Lio/n;

    .line 422
    .line 423
    monitor-enter p0

    .line 424
    :try_start_1
    iget v1, p0, Lio/o;->d:I

    .line 425
    .line 426
    add-int/lit8 v2, v1, 0x1

    .line 427
    .line 428
    iput v2, p0, Lio/o;->d:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 429
    .line 430
    monitor-exit p0

    .line 431
    invoke-direct {p1, v1, v6, v0, v7}, Lio/n;-><init>(IILandroid/os/Bundle;I)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {p0, p1}, Lio/o;->e(Lio/n;)Laq/t;

    .line 435
    .line 436
    .line 437
    return-void

    .line 438
    :catchall_1
    move-exception p1

    .line 439
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 440
    throw p1

    .line 441
    :cond_15
    new-instance p0, Ljava/io/IOException;

    .line 442
    .line 443
    const-string p1, "SERVICE_NOT_AVAILABLE"

    .line 444
    .line 445
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 449
    .line 450
    .line 451
    return-void

    .line 452
    nop

    .line 453
    :sswitch_data_0
    .sparse-switch
        -0x7aedf14e -> :sswitch_3
        0x18f11 -> :sswitch_2
        0x308f3e91 -> :sswitch_1
        0x3090df23 -> :sswitch_0
    .end sparse-switch

    .line 454
    .line 455
    .line 456
    .line 457
    .line 458
    .line 459
    .line 460
    .line 461
    .line 462
    .line 463
    .line 464
    .line 465
    .line 466
    .line 467
    .line 468
    .line 469
    .line 470
    .line 471
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public onDeletedMessages()V
    .locals 0

    .line 1
    return-void
.end method

.method public onMessageReceived(Lcom/google/firebase/messaging/v;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onMessageSent(Ljava/lang/String;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public onNewToken(Ljava/lang/String;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onSendError(Ljava/lang/String;Ljava/lang/Exception;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public setRpcForTesting(Lio/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/firebase/messaging/FirebaseMessagingService;->rpc:Lio/b;

    .line 2
    .line 3
    return-void
.end method
