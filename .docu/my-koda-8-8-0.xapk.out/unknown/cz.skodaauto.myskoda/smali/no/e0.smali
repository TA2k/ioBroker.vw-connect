.class public final Lno/e0;
.super Lbp/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lno/e;


# direct methods
.method public constructor <init>(Lno/e;Landroid/os/Looper;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/e0;->a:Lno/e;

    .line 2
    .line 3
    const/4 p1, 0x4

    .line 4
    invoke-direct {p0, p2, p1}, Lbp/c;-><init>(Landroid/os/Looper;I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lno/e0;->a:Lno/e;

    .line 2
    .line 3
    iget-object v0, v0, Lno/e;->w:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget v1, p1, Landroid/os/Message;->arg1:I

    .line 10
    .line 11
    const/4 v2, 0x7

    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x1

    .line 14
    if-eq v0, v1, :cond_2

    .line 15
    .line 16
    iget p0, p1, Landroid/os/Message;->what:I

    .line 17
    .line 18
    if-eq p0, v3, :cond_1

    .line 19
    .line 20
    if-eq p0, v4, :cond_1

    .line 21
    .line 22
    if-ne p0, v2, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void

    .line 26
    :cond_1
    :goto_0
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lno/w;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Lno/w;->c()V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_2
    iget v0, p1, Landroid/os/Message;->what:I

    .line 38
    .line 39
    const/4 v1, 0x4

    .line 40
    const/4 v5, 0x5

    .line 41
    if-eq v0, v4, :cond_4

    .line 42
    .line 43
    if-eq v0, v2, :cond_4

    .line 44
    .line 45
    if-ne v0, v1, :cond_3

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_3
    if-ne v0, v5, :cond_5

    .line 49
    .line 50
    :cond_4
    :goto_1
    iget-object v0, p0, Lno/e0;->a:Lno/e;

    .line 51
    .line 52
    invoke-virtual {v0}, Lno/e;->b()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_1a

    .line 57
    .line 58
    :cond_5
    iget v0, p1, Landroid/os/Message;->what:I

    .line 59
    .line 60
    const/16 v6, 0x8

    .line 61
    .line 62
    const/4 v7, 0x3

    .line 63
    const/4 v8, 0x0

    .line 64
    if-ne v0, v1, :cond_b

    .line 65
    .line 66
    iget-object v0, p0, Lno/e0;->a:Lno/e;

    .line 67
    .line 68
    new-instance v1, Ljo/b;

    .line 69
    .line 70
    iget p1, p1, Landroid/os/Message;->arg2:I

    .line 71
    .line 72
    invoke-direct {v1, p1}, Ljo/b;-><init>(I)V

    .line 73
    .line 74
    .line 75
    iput-object v1, v0, Lno/e;->t:Ljo/b;

    .line 76
    .line 77
    iget-boolean p1, v0, Lno/e;->u:Z

    .line 78
    .line 79
    if-eqz p1, :cond_6

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_6
    invoke-virtual {v0}, Lno/e;->s()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    if-eqz p1, :cond_7

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_7
    invoke-static {v8}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    if-eqz p1, :cond_8

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_8
    :try_start_0
    invoke-virtual {v0}, Lno/e;->s()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 105
    .line 106
    .line 107
    iget-object p1, p0, Lno/e0;->a:Lno/e;

    .line 108
    .line 109
    iget-boolean v0, p1, Lno/e;->u:Z

    .line 110
    .line 111
    if-eqz v0, :cond_9

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_9
    invoke-virtual {p1, v7, v8}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :catch_0
    :goto_2
    iget-object p0, p0, Lno/e0;->a:Lno/e;

    .line 119
    .line 120
    iget-object p1, p0, Lno/e;->t:Ljo/b;

    .line 121
    .line 122
    if-eqz p1, :cond_a

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_a
    new-instance p1, Ljo/b;

    .line 126
    .line 127
    invoke-direct {p1, v6}, Ljo/b;-><init>(I)V

    .line 128
    .line 129
    .line 130
    :goto_3
    iget-object p0, p0, Lno/e;->j:Lno/d;

    .line 131
    .line 132
    invoke-interface {p0, p1}, Lno/d;->d(Ljo/b;)V

    .line 133
    .line 134
    .line 135
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 136
    .line 137
    .line 138
    return-void

    .line 139
    :cond_b
    if-ne v0, v5, :cond_d

    .line 140
    .line 141
    iget-object p0, p0, Lno/e0;->a:Lno/e;

    .line 142
    .line 143
    iget-object p1, p0, Lno/e;->t:Ljo/b;

    .line 144
    .line 145
    if-eqz p1, :cond_c

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_c
    new-instance p1, Ljo/b;

    .line 149
    .line 150
    invoke-direct {p1, v6}, Ljo/b;-><init>(I)V

    .line 151
    .line 152
    .line 153
    :goto_4
    iget-object p0, p0, Lno/e;->j:Lno/d;

    .line 154
    .line 155
    invoke-interface {p0, p1}, Lno/d;->d(Ljo/b;)V

    .line 156
    .line 157
    .line 158
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 159
    .line 160
    .line 161
    return-void

    .line 162
    :cond_d
    if-ne v0, v7, :cond_f

    .line 163
    .line 164
    iget-object v0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 165
    .line 166
    instance-of v1, v0, Landroid/app/PendingIntent;

    .line 167
    .line 168
    if-eqz v1, :cond_e

    .line 169
    .line 170
    move-object v8, v0

    .line 171
    check-cast v8, Landroid/app/PendingIntent;

    .line 172
    .line 173
    :cond_e
    new-instance v0, Ljo/b;

    .line 174
    .line 175
    iget p1, p1, Landroid/os/Message;->arg2:I

    .line 176
    .line 177
    invoke-direct {v0, p1, v8}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 178
    .line 179
    .line 180
    iget-object p0, p0, Lno/e0;->a:Lno/e;

    .line 181
    .line 182
    iget-object p0, p0, Lno/e;->j:Lno/d;

    .line 183
    .line 184
    invoke-interface {p0, v0}, Lno/d;->d(Ljo/b;)V

    .line 185
    .line 186
    .line 187
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 188
    .line 189
    .line 190
    return-void

    .line 191
    :cond_f
    const/4 v1, 0x6

    .line 192
    if-ne v0, v1, :cond_11

    .line 193
    .line 194
    iget-object v0, p0, Lno/e0;->a:Lno/e;

    .line 195
    .line 196
    invoke-virtual {v0, v5, v8}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 197
    .line 198
    .line 199
    iget-object v0, p0, Lno/e0;->a:Lno/e;

    .line 200
    .line 201
    iget-object v0, v0, Lno/e;->o:Lno/b;

    .line 202
    .line 203
    if-eqz v0, :cond_10

    .line 204
    .line 205
    iget p1, p1, Landroid/os/Message;->arg2:I

    .line 206
    .line 207
    invoke-interface {v0, p1}, Lno/b;->c(I)V

    .line 208
    .line 209
    .line 210
    :cond_10
    iget-object p1, p0, Lno/e0;->a:Lno/e;

    .line 211
    .line 212
    invoke-virtual {p1}, Lno/e;->w()V

    .line 213
    .line 214
    .line 215
    iget-object p0, p0, Lno/e0;->a:Lno/e;

    .line 216
    .line 217
    invoke-static {p0, v5, v4, v8}, Lno/e;->A(Lno/e;IILandroid/os/IInterface;)Z

    .line 218
    .line 219
    .line 220
    return-void

    .line 221
    :cond_11
    if-ne v0, v3, :cond_13

    .line 222
    .line 223
    iget-object p0, p0, Lno/e0;->a:Lno/e;

    .line 224
    .line 225
    invoke-virtual {p0}, Lno/e;->isConnected()Z

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    if-eqz p0, :cond_12

    .line 230
    .line 231
    goto :goto_5

    .line 232
    :cond_12
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast p0, Lno/w;

    .line 235
    .line 236
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    invoke-virtual {p0}, Lno/w;->c()V

    .line 240
    .line 241
    .line 242
    return-void

    .line 243
    :cond_13
    :goto_5
    iget p0, p1, Landroid/os/Message;->what:I

    .line 244
    .line 245
    if-eq p0, v3, :cond_15

    .line 246
    .line 247
    if-eq p0, v4, :cond_15

    .line 248
    .line 249
    if-ne p0, v2, :cond_14

    .line 250
    .line 251
    goto :goto_6

    .line 252
    :cond_14
    const-string p1, "Don\'t know how to handle message: "

    .line 253
    .line 254
    invoke-static {p0, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    new-instance p1, Ljava/lang/Exception;

    .line 259
    .line 260
    invoke-direct {p1}, Ljava/lang/Exception;-><init>()V

    .line 261
    .line 262
    .line 263
    const-string v0, "GmsClient"

    .line 264
    .line 265
    invoke-static {v0, p0, p1}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 266
    .line 267
    .line 268
    return-void

    .line 269
    :cond_15
    :goto_6
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 270
    .line 271
    check-cast p0, Lno/w;

    .line 272
    .line 273
    const-string p1, "Callback proxy "

    .line 274
    .line 275
    monitor-enter p0

    .line 276
    :try_start_1
    iget-object v0, p0, Lno/w;->a:Ljava/lang/Boolean;

    .line 277
    .line 278
    iget-boolean v1, p0, Lno/w;->b:Z

    .line 279
    .line 280
    if-eqz v1, :cond_16

    .line 281
    .line 282
    const-string v1, "GmsClient"

    .line 283
    .line 284
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v2

    .line 288
    new-instance v3, Ljava/lang/StringBuilder;

    .line 289
    .line 290
    invoke-direct {v3, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    const-string p1, " being reused. This is not safe."

    .line 297
    .line 298
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object p1

    .line 305
    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 306
    .line 307
    .line 308
    goto :goto_7

    .line 309
    :catchall_0
    move-exception p1

    .line 310
    goto :goto_9

    .line 311
    :cond_16
    :goto_7
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 312
    if-eqz v0, :cond_19

    .line 313
    .line 314
    iget-object p1, p0, Lno/w;->f:Lno/e;

    .line 315
    .line 316
    iget v0, p0, Lno/w;->d:I

    .line 317
    .line 318
    if-nez v0, :cond_17

    .line 319
    .line 320
    invoke-virtual {p0}, Lno/w;->b()Z

    .line 321
    .line 322
    .line 323
    move-result v0

    .line 324
    if-nez v0, :cond_19

    .line 325
    .line 326
    invoke-virtual {p1, v4, v8}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 327
    .line 328
    .line 329
    new-instance p1, Ljo/b;

    .line 330
    .line 331
    invoke-direct {p1, v6, v8}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {p0, p1}, Lno/w;->a(Ljo/b;)V

    .line 335
    .line 336
    .line 337
    goto :goto_8

    .line 338
    :cond_17
    invoke-virtual {p1, v4, v8}, Lno/e;->B(ILandroid/os/IInterface;)V

    .line 339
    .line 340
    .line 341
    iget-object p1, p0, Lno/w;->e:Landroid/os/Bundle;

    .line 342
    .line 343
    if-eqz p1, :cond_18

    .line 344
    .line 345
    const-string v1, "pendingIntent"

    .line 346
    .line 347
    invoke-virtual {p1, v1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 348
    .line 349
    .line 350
    move-result-object p1

    .line 351
    move-object v8, p1

    .line 352
    check-cast v8, Landroid/app/PendingIntent;

    .line 353
    .line 354
    :cond_18
    new-instance p1, Ljo/b;

    .line 355
    .line 356
    invoke-direct {p1, v0, v8}, Ljo/b;-><init>(ILandroid/app/PendingIntent;)V

    .line 357
    .line 358
    .line 359
    invoke-virtual {p0, p1}, Lno/w;->a(Ljo/b;)V

    .line 360
    .line 361
    .line 362
    :cond_19
    :goto_8
    monitor-enter p0

    .line 363
    :try_start_2
    iput-boolean v4, p0, Lno/w;->b:Z

    .line 364
    .line 365
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 366
    invoke-virtual {p0}, Lno/w;->c()V

    .line 367
    .line 368
    .line 369
    return-void

    .line 370
    :catchall_1
    move-exception p1

    .line 371
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 372
    throw p1

    .line 373
    :goto_9
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 374
    throw p1

    .line 375
    :cond_1a
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 376
    .line 377
    check-cast p0, Lno/w;

    .line 378
    .line 379
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    invoke-virtual {p0}, Lno/w;->c()V

    .line 383
    .line 384
    .line 385
    return-void
.end method
