.class public final Ld6/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    .line 1
    iput p1, p0, Ld6/z0;->d:I

    iput-object p2, p0, Ld6/z0;->h:Ljava/lang/Object;

    iput-object p3, p0, Ld6/z0;->e:Ljava/lang/Object;

    iput-object p4, p0, Ld6/z0;->f:Ljava/lang/Object;

    iput-object p5, p0, Ld6/z0;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p5, p0, Ld6/z0;->d:I

    iput-object p1, p0, Ld6/z0;->e:Ljava/lang/Object;

    iput-object p2, p0, Ld6/z0;->f:Ljava/lang/Object;

    iput-object p3, p0, Ld6/z0;->g:Ljava/lang/Object;

    iput-object p4, p0, Ld6/z0;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Ld6/z0;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Ld6/z0;->e:Ljava/lang/Object;

    iput-object p3, p0, Ld6/z0;->f:Ljava/lang/Object;

    iput-object p4, p0, Ld6/z0;->g:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Ld6/z0;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld6/z0;->d:I

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    const/4 v3, 0x4

    .line 8
    const/4 v4, 0x1

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v6, 0x0

    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lro/f;

    .line 17
    .line 18
    iget-object v1, v1, Lro/f;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Lvp/z3;

    .line 21
    .line 22
    invoke-virtual {v1}, Lvp/z3;->j0()Lvp/d4;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v1}, Lvp/z3;->l()Lto/a;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 34
    .line 35
    .line 36
    move-result-wide v6

    .line 37
    iget-object v3, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v9, v3

    .line 40
    check-cast v9, Ljava/lang/String;

    .line 41
    .line 42
    iget-object v3, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v3, Ljava/lang/String;

    .line 45
    .line 46
    iget-object v0, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 47
    .line 48
    move-object v4, v0

    .line 49
    check-cast v4, Landroid/os/Bundle;

    .line 50
    .line 51
    const-string v5, "auto"

    .line 52
    .line 53
    const/4 v8, 0x0

    .line 54
    invoke-virtual/range {v2 .. v8}, Lvp/d4;->C0(Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/String;JZ)Lvp/t;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v9, v0}, Lvp/z3;->c(Ljava/lang/String;Lvp/t;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :pswitch_0
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v1, Lvp/d3;

    .line 68
    .line 69
    iget-object v2, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v2, Ljava/util/concurrent/atomic/AtomicReference;

    .line 72
    .line 73
    iget-object v3, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v3, Lvp/f4;

    .line 76
    .line 77
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Lvp/s3;

    .line 80
    .line 81
    monitor-enter v2

    .line 82
    :try_start_0
    iget-object v4, v1, Lvp/d3;->h:Lvp/c0;

    .line 83
    .line 84
    if-nez v4, :cond_0

    .line 85
    .line 86
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Lvp/g1;

    .line 89
    .line 90
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 91
    .line 92
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 93
    .line 94
    .line 95
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 96
    .line 97
    const-string v3, "[sgtm] Failed to get upload batches; not connected to service"

    .line 98
    .line 99
    invoke-virtual {v0, v3}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 100
    .line 101
    .line 102
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 103
    goto :goto_2

    .line 104
    :catchall_0
    move-exception v0

    .line 105
    goto :goto_3

    .line 106
    :catch_0
    move-exception v0

    .line 107
    goto :goto_0

    .line 108
    :cond_0
    :try_start_2
    new-instance v5, Lvp/x2;

    .line 109
    .line 110
    invoke-direct {v5, v1, v2}, Lvp/x2;-><init>(Lvp/d3;Ljava/util/concurrent/atomic/AtomicReference;)V

    .line 111
    .line 112
    .line 113
    invoke-interface {v4, v3, v0, v5}, Lvp/c0;->d(Lvp/f4;Lvp/s3;Lvp/g0;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v1}, Lvp/d3;->n0()V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 117
    .line 118
    .line 119
    goto :goto_1

    .line 120
    :goto_0
    :try_start_3
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v1, Lvp/g1;

    .line 123
    .line 124
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 125
    .line 126
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 127
    .line 128
    .line 129
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 130
    .line 131
    const-string v3, "[sgtm] Failed to get upload batches; remote exception"

    .line 132
    .line 133
    invoke-virtual {v1, v0, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v2}, Ljava/lang/Object;->notifyAll()V

    .line 137
    .line 138
    .line 139
    :goto_1
    monitor-exit v2

    .line 140
    :goto_2
    return-void

    .line 141
    :goto_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 142
    throw v0

    .line 143
    :pswitch_1
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v1, Lvp/d3;

    .line 146
    .line 147
    iget-object v2, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v2, Ljava/util/concurrent/atomic/AtomicReference;

    .line 150
    .line 151
    iget-object v3, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v3, Lvp/f4;

    .line 154
    .line 155
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Landroid/os/Bundle;

    .line 158
    .line 159
    monitor-enter v2

    .line 160
    :try_start_4
    iget-object v4, v1, Lvp/d3;->h:Lvp/c0;

    .line 161
    .line 162
    if-nez v4, :cond_1

    .line 163
    .line 164
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast v0, Lvp/g1;

    .line 167
    .line 168
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 169
    .line 170
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 171
    .line 172
    .line 173
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 174
    .line 175
    const-string v3, "Failed to request trigger URIs; not connected to service"

    .line 176
    .line 177
    invoke-virtual {v0, v3}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 178
    .line 179
    .line 180
    :try_start_5
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 181
    goto :goto_6

    .line 182
    :catchall_1
    move-exception v0

    .line 183
    goto :goto_7

    .line 184
    :catch_1
    move-exception v0

    .line 185
    goto :goto_4

    .line 186
    :cond_1
    :try_start_6
    new-instance v5, Lvp/w2;

    .line 187
    .line 188
    invoke-direct {v5, v1, v2}, Lvp/w2;-><init>(Lvp/d3;Ljava/util/concurrent/atomic/AtomicReference;)V

    .line 189
    .line 190
    .line 191
    invoke-interface {v4, v3, v0, v5}, Lvp/c0;->v(Lvp/f4;Landroid/os/Bundle;Lvp/e0;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v1}, Lvp/d3;->n0()V
    :try_end_6
    .catch Landroid/os/RemoteException; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 195
    .line 196
    .line 197
    goto :goto_5

    .line 198
    :goto_4
    :try_start_7
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v1, Lvp/g1;

    .line 201
    .line 202
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 203
    .line 204
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 205
    .line 206
    .line 207
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 208
    .line 209
    const-string v3, "Failed to request trigger URIs; remote exception"

    .line 210
    .line 211
    invoke-virtual {v1, v0, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v2}, Ljava/lang/Object;->notifyAll()V

    .line 215
    .line 216
    .line 217
    :goto_5
    monitor-exit v2

    .line 218
    :goto_6
    return-void

    .line 219
    :goto_7
    monitor-exit v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 220
    throw v0

    .line 221
    :pswitch_2
    iget-object v1, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v1, Lcom/google/android/gms/internal/measurement/m0;

    .line 224
    .line 225
    iget-object v2, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v2, Lvp/d3;

    .line 228
    .line 229
    :try_start_8
    iget-object v3, v2, Lvp/d3;->h:Lvp/c0;

    .line 230
    .line 231
    if-nez v3, :cond_2

    .line 232
    .line 233
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast v0, Lvp/g1;

    .line 236
    .line 237
    iget-object v3, v0, Lvp/g1;->i:Lvp/p0;

    .line 238
    .line 239
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 240
    .line 241
    .line 242
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 243
    .line 244
    const-string v4, "Discarding data. Failed to send event to service to bundle"

    .line 245
    .line 246
    invoke-virtual {v3, v4}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_8
    .catch Landroid/os/RemoteException; {:try_start_8 .. :try_end_8} :catch_2
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 247
    .line 248
    .line 249
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 250
    .line 251
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v0, v1, v5}, Lvp/d4;->L0(Lcom/google/android/gms/internal/measurement/m0;[B)V

    .line 255
    .line 256
    .line 257
    goto :goto_9

    .line 258
    :cond_2
    :try_start_9
    iget-object v4, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast v4, Lvp/t;

    .line 261
    .line 262
    iget-object v0, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v0, Ljava/lang/String;

    .line 265
    .line 266
    invoke-interface {v3, v0, v4}, Lvp/c0;->q(Ljava/lang/String;Lvp/t;)[B

    .line 267
    .line 268
    .line 269
    move-result-object v5

    .line 270
    invoke-virtual {v2}, Lvp/d3;->n0()V
    :try_end_9
    .catch Landroid/os/RemoteException; {:try_start_9 .. :try_end_9} :catch_2
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 271
    .line 272
    .line 273
    goto :goto_8

    .line 274
    :catchall_2
    move-exception v0

    .line 275
    goto :goto_a

    .line 276
    :catch_2
    move-exception v0

    .line 277
    :try_start_a
    iget-object v3, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v3, Lvp/g1;

    .line 280
    .line 281
    iget-object v3, v3, Lvp/g1;->i:Lvp/p0;

    .line 282
    .line 283
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 284
    .line 285
    .line 286
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 287
    .line 288
    const-string v4, "Failed to send event to the service to bundle"

    .line 289
    .line 290
    invoke-virtual {v3, v0, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 291
    .line 292
    .line 293
    :goto_8
    iget-object v0, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v0, Lvp/g1;

    .line 296
    .line 297
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 298
    .line 299
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v0, v1, v5}, Lvp/d4;->L0(Lcom/google/android/gms/internal/measurement/m0;[B)V

    .line 303
    .line 304
    .line 305
    :goto_9
    return-void

    .line 306
    :goto_a
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 307
    .line 308
    check-cast v2, Lvp/g1;

    .line 309
    .line 310
    iget-object v2, v2, Lvp/g1;->l:Lvp/d4;

    .line 311
    .line 312
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v2, v1, v5}, Lvp/d4;->L0(Lcom/google/android/gms/internal/measurement/m0;[B)V

    .line 316
    .line 317
    .line 318
    throw v0

    .line 319
    :pswitch_3
    iget-object v1, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    .line 322
    .line 323
    iget-object v1, v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 324
    .line 325
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 326
    .line 327
    .line 328
    move-result-object v8

    .line 329
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 330
    .line 331
    move-object v12, v1

    .line 332
    check-cast v12, Lcom/google/android/gms/internal/measurement/m0;

    .line 333
    .line 334
    iget-object v1, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 335
    .line 336
    move-object v9, v1

    .line 337
    check-cast v9, Ljava/lang/String;

    .line 338
    .line 339
    iget-object v0, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 340
    .line 341
    move-object v10, v0

    .line 342
    check-cast v10, Ljava/lang/String;

    .line 343
    .line 344
    invoke-virtual {v8}, Lvp/x;->a0()V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v8}, Lvp/b0;->b0()V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v8, v6}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 351
    .line 352
    .line 353
    move-result-object v11

    .line 354
    new-instance v7, Lfv/p;

    .line 355
    .line 356
    const/4 v13, 0x3

    .line 357
    invoke-direct/range {v7 .. v13}, Lfv/p;-><init>(Lvp/d3;Ljava/io/Serializable;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 358
    .line 359
    .line 360
    invoke-virtual {v8, v7}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 361
    .line 362
    .line 363
    return-void

    .line 364
    :pswitch_4
    iget-object v1, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 365
    .line 366
    move-object v10, v1

    .line 367
    check-cast v10, Ljava/lang/String;

    .line 368
    .line 369
    iget-object v1, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 370
    .line 371
    move-object v11, v1

    .line 372
    check-cast v11, Ljava/lang/String;

    .line 373
    .line 374
    iget-object v1, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 375
    .line 376
    check-cast v1, Lvp/j2;

    .line 377
    .line 378
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 379
    .line 380
    check-cast v1, Lvp/g1;

    .line 381
    .line 382
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 383
    .line 384
    .line 385
    move-result-object v8

    .line 386
    iget-object v0, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 387
    .line 388
    move-object v9, v0

    .line 389
    check-cast v9, Ljava/util/concurrent/atomic/AtomicReference;

    .line 390
    .line 391
    invoke-virtual {v8}, Lvp/x;->a0()V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v8}, Lvp/b0;->b0()V

    .line 395
    .line 396
    .line 397
    invoke-virtual {v8, v6}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 398
    .line 399
    .line 400
    move-result-object v12

    .line 401
    new-instance v7, Lfv/p;

    .line 402
    .line 403
    const/4 v13, 0x2

    .line 404
    invoke-direct/range {v7 .. v13}, Lfv/p;-><init>(Lvp/d3;Ljava/io/Serializable;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 405
    .line 406
    .line 407
    invoke-virtual {v8, v7}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 408
    .line 409
    .line 410
    return-void

    .line 411
    :pswitch_5
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 412
    .line 413
    check-cast v1, Lvp/m1;

    .line 414
    .line 415
    iget-object v2, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 416
    .line 417
    move-object v15, v2

    .line 418
    check-cast v15, Landroid/os/Bundle;

    .line 419
    .line 420
    iget-object v2, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 421
    .line 422
    move-object v9, v2

    .line 423
    check-cast v9, Ljava/lang/String;

    .line 424
    .line 425
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 426
    .line 427
    move-object v2, v0

    .line 428
    check-cast v2, Lvp/f4;

    .line 429
    .line 430
    iget-object v1, v1, Lvp/m1;->c:Lvp/z3;

    .line 431
    .line 432
    invoke-virtual {v1}, Lvp/z3;->d0()Lvp/h;

    .line 433
    .line 434
    .line 435
    move-result-object v0

    .line 436
    sget-object v3, Lvp/z;->V0:Lvp/y;

    .line 437
    .line 438
    invoke-virtual {v0, v5, v3}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 439
    .line 440
    .line 441
    move-result v0

    .line 442
    invoke-virtual {v15}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 443
    .line 444
    .line 445
    move-result v3

    .line 446
    if-eqz v3, :cond_3

    .line 447
    .line 448
    if-eqz v0, :cond_3

    .line 449
    .line 450
    iget-object v1, v1, Lvp/z3;->f:Lvp/n;

    .line 451
    .line 452
    invoke-static {v1}, Lvp/z3;->T(Lvp/u3;)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v1}, Lvp/u3;->b0()V

    .line 459
    .line 460
    .line 461
    :try_start_b
    invoke-virtual {v1}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    const-string v2, "delete from default_event_params where app_id=?"

    .line 466
    .line 467
    filled-new-array {v9}, [Ljava/lang/String;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    invoke-virtual {v0, v2, v3}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_b .. :try_end_b} :catch_3

    .line 472
    .line 473
    .line 474
    goto/16 :goto_c

    .line 475
    .line 476
    :catch_3
    move-exception v0

    .line 477
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 478
    .line 479
    check-cast v1, Lvp/g1;

    .line 480
    .line 481
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 482
    .line 483
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 484
    .line 485
    .line 486
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 487
    .line 488
    const-string v2, "Error clearing default event params"

    .line 489
    .line 490
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    goto/16 :goto_c

    .line 494
    .line 495
    :cond_3
    iget-object v0, v1, Lvp/z3;->f:Lvp/n;

    .line 496
    .line 497
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 498
    .line 499
    .line 500
    iget-object v3, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 501
    .line 502
    check-cast v3, Lvp/g1;

    .line 503
    .line 504
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 505
    .line 506
    .line 507
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 508
    .line 509
    .line 510
    iget-object v4, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 511
    .line 512
    move-object v7, v4

    .line 513
    check-cast v7, Lvp/g1;

    .line 514
    .line 515
    const-string v10, "dep"

    .line 516
    .line 517
    new-instance v6, Lh01/k;

    .line 518
    .line 519
    const-string v8, ""

    .line 520
    .line 521
    const-wide/16 v11, 0x0

    .line 522
    .line 523
    const-wide/16 v13, 0x0

    .line 524
    .line 525
    invoke-direct/range {v6 .. v15}, Lh01/k;-><init>(Lvp/g1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJLandroid/os/Bundle;)V

    .line 526
    .line 527
    .line 528
    iget-object v4, v0, Lvp/q3;->f:Lvp/z3;

    .line 529
    .line 530
    iget-object v4, v4, Lvp/z3;->j:Lvp/s0;

    .line 531
    .line 532
    invoke-static {v4}, Lvp/z3;->T(Lvp/u3;)V

    .line 533
    .line 534
    .line 535
    invoke-virtual {v4, v6}, Lvp/s0;->C0(Lh01/k;)Lcom/google/android/gms/internal/measurement/b3;

    .line 536
    .line 537
    .line 538
    move-result-object v4

    .line 539
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 540
    .line 541
    .line 542
    move-result-object v4

    .line 543
    iget-object v3, v3, Lvp/g1;->i:Lvp/p0;

    .line 544
    .line 545
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 546
    .line 547
    .line 548
    iget-object v6, v3, Lvp/p0;->r:Lvp/n0;

    .line 549
    .line 550
    array-length v7, v4

    .line 551
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 552
    .line 553
    .line 554
    move-result-object v7

    .line 555
    const-string v8, "Saving default event parameters, appId, data size"

    .line 556
    .line 557
    invoke-virtual {v6, v9, v7, v8}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 558
    .line 559
    .line 560
    new-instance v6, Landroid/content/ContentValues;

    .line 561
    .line 562
    invoke-direct {v6}, Landroid/content/ContentValues;-><init>()V

    .line 563
    .line 564
    .line 565
    const-string v7, "app_id"

    .line 566
    .line 567
    invoke-virtual {v6, v7, v9}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 568
    .line 569
    .line 570
    const-string v7, "parameters"

    .line 571
    .line 572
    invoke-virtual {v6, v7, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 573
    .line 574
    .line 575
    :try_start_c
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 576
    .line 577
    .line 578
    move-result-object v0

    .line 579
    const-string v4, "default_event_params"

    .line 580
    .line 581
    const/4 v7, 0x5

    .line 582
    invoke-virtual {v0, v4, v5, v6, v7}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 583
    .line 584
    .line 585
    move-result-wide v6

    .line 586
    const-wide/16 v10, -0x1

    .line 587
    .line 588
    cmp-long v0, v6, v10

    .line 589
    .line 590
    if-nez v0, :cond_4

    .line 591
    .line 592
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 593
    .line 594
    .line 595
    iget-object v0, v3, Lvp/p0;->j:Lvp/n0;

    .line 596
    .line 597
    const-string v4, "Failed to insert default event parameters (got -1). appId"

    .line 598
    .line 599
    invoke-static {v9}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 600
    .line 601
    .line 602
    move-result-object v6

    .line 603
    invoke-virtual {v0, v6, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_c
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_c .. :try_end_c} :catch_4

    .line 604
    .line 605
    .line 606
    goto :goto_b

    .line 607
    :catch_4
    move-exception v0

    .line 608
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 609
    .line 610
    .line 611
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 612
    .line 613
    invoke-static {v9}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 614
    .line 615
    .line 616
    move-result-object v4

    .line 617
    const-string v6, "Error storing default event parameters. appId"

    .line 618
    .line 619
    invoke-virtual {v3, v4, v0, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 620
    .line 621
    .line 622
    :cond_4
    :goto_b
    iget-object v3, v1, Lvp/z3;->f:Lvp/n;

    .line 623
    .line 624
    invoke-static {v3}, Lvp/z3;->T(Lvp/u3;)V

    .line 625
    .line 626
    .line 627
    iget-wide v6, v2, Lvp/f4;->G:J

    .line 628
    .line 629
    :try_start_d
    const-string v0, "select count(*) from raw_events where app_id=? and timestamp >= ? and name not like \'!_%\' escape \'!\' limit 1;"

    .line 630
    .line 631
    invoke-static {v6, v7}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 632
    .line 633
    .line 634
    move-result-object v2

    .line 635
    filled-new-array {v9, v2}, [Ljava/lang/String;

    .line 636
    .line 637
    .line 638
    move-result-object v2

    .line 639
    const-wide/16 v10, 0x0

    .line 640
    .line 641
    invoke-virtual {v3, v0, v2, v10, v11}, Lvp/n;->L0(Ljava/lang/String;[Ljava/lang/String;J)J

    .line 642
    .line 643
    .line 644
    move-result-wide v12

    .line 645
    cmp-long v0, v12, v10

    .line 646
    .line 647
    if-lez v0, :cond_5

    .line 648
    .line 649
    goto :goto_c

    .line 650
    :cond_5
    const-string v0, "select count(*) from raw_events where app_id=? and timestamp >= ? and name like \'!_%\' escape \'!\' limit 1;"

    .line 651
    .line 652
    invoke-static {v6, v7}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 653
    .line 654
    .line 655
    move-result-object v2

    .line 656
    filled-new-array {v9, v2}, [Ljava/lang/String;

    .line 657
    .line 658
    .line 659
    move-result-object v2

    .line 660
    invoke-virtual {v3, v0, v2, v10, v11}, Lvp/n;->L0(Ljava/lang/String;[Ljava/lang/String;J)J

    .line 661
    .line 662
    .line 663
    move-result-wide v2
    :try_end_d
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_d .. :try_end_d} :catch_5

    .line 664
    cmp-long v0, v2, v10

    .line 665
    .line 666
    if-lez v0, :cond_6

    .line 667
    .line 668
    iget-object v0, v1, Lvp/z3;->f:Lvp/n;

    .line 669
    .line 670
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 671
    .line 672
    .line 673
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 674
    .line 675
    .line 676
    move-result-object v1

    .line 677
    invoke-virtual {v0, v9, v1, v5, v15}, Lvp/n;->s0(Ljava/lang/String;Ljava/lang/Long;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 678
    .line 679
    .line 680
    goto :goto_c

    .line 681
    :catch_5
    move-exception v0

    .line 682
    iget-object v1, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 683
    .line 684
    check-cast v1, Lvp/g1;

    .line 685
    .line 686
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 687
    .line 688
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 689
    .line 690
    .line 691
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 692
    .line 693
    const-string v2, "Error checking backfill conditions"

    .line 694
    .line 695
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 696
    .line 697
    .line 698
    :cond_6
    :goto_c
    return-void

    .line 699
    :pswitch_6
    iget-object v1, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 700
    .line 701
    check-cast v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    .line 702
    .line 703
    iget-object v1, v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 704
    .line 705
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 706
    .line 707
    .line 708
    move-result-object v9

    .line 709
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 710
    .line 711
    move-object v12, v1

    .line 712
    check-cast v12, Lcom/google/android/gms/internal/measurement/m0;

    .line 713
    .line 714
    iget-object v1, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 715
    .line 716
    move-object v10, v1

    .line 717
    check-cast v10, Lvp/t;

    .line 718
    .line 719
    iget-object v0, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 720
    .line 721
    move-object v11, v0

    .line 722
    check-cast v11, Ljava/lang/String;

    .line 723
    .line 724
    invoke-virtual {v9}, Lvp/x;->a0()V

    .line 725
    .line 726
    .line 727
    invoke-virtual {v9}, Lvp/b0;->b0()V

    .line 728
    .line 729
    .line 730
    iget-object v0, v9, Lap0/o;->e:Ljava/lang/Object;

    .line 731
    .line 732
    check-cast v0, Lvp/g1;

    .line 733
    .line 734
    iget-object v1, v0, Lvp/g1;->l:Lvp/d4;

    .line 735
    .line 736
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 737
    .line 738
    .line 739
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 740
    .line 741
    check-cast v1, Lvp/g1;

    .line 742
    .line 743
    sget-object v2, Ljo/f;->b:Ljo/f;

    .line 744
    .line 745
    iget-object v1, v1, Lvp/g1;->d:Landroid/content/Context;

    .line 746
    .line 747
    const v3, 0xbdfcb8

    .line 748
    .line 749
    .line 750
    invoke-virtual {v2, v1, v3}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 751
    .line 752
    .line 753
    move-result v1

    .line 754
    if-eqz v1, :cond_7

    .line 755
    .line 756
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 757
    .line 758
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 759
    .line 760
    .line 761
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 762
    .line 763
    const-string v2, "Not bundling data. Service unavailable or out of date"

    .line 764
    .line 765
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 766
    .line 767
    .line 768
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 769
    .line 770
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 771
    .line 772
    .line 773
    new-array v1, v6, [B

    .line 774
    .line 775
    invoke-virtual {v0, v12, v1}, Lvp/d4;->L0(Lcom/google/android/gms/internal/measurement/m0;[B)V

    .line 776
    .line 777
    .line 778
    goto :goto_d

    .line 779
    :cond_7
    new-instance v7, Ld6/z0;

    .line 780
    .line 781
    const/16 v8, 0x9

    .line 782
    .line 783
    const/4 v13, 0x0

    .line 784
    invoke-direct/range {v7 .. v13}, Ld6/z0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 785
    .line 786
    .line 787
    invoke-virtual {v9, v7}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 788
    .line 789
    .line 790
    :goto_d
    return-void

    .line 791
    :pswitch_7
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 792
    .line 793
    check-cast v1, Lvp/m1;

    .line 794
    .line 795
    iget-object v2, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 796
    .line 797
    check-cast v2, Ljava/lang/String;

    .line 798
    .line 799
    iget-object v3, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 800
    .line 801
    check-cast v3, Lvp/s3;

    .line 802
    .line 803
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 804
    .line 805
    check-cast v0, Lvp/g0;

    .line 806
    .line 807
    iget-object v1, v1, Lvp/m1;->c:Lvp/z3;

    .line 808
    .line 809
    invoke-virtual {v1}, Lvp/z3;->B()V

    .line 810
    .line 811
    .line 812
    invoke-virtual {v1}, Lvp/z3;->f()Lvp/e1;

    .line 813
    .line 814
    .line 815
    move-result-object v4

    .line 816
    invoke-virtual {v4}, Lvp/e1;->a0()V

    .line 817
    .line 818
    .line 819
    invoke-virtual {v1}, Lvp/z3;->k0()V

    .line 820
    .line 821
    .line 822
    iget-object v4, v1, Lvp/z3;->f:Lvp/n;

    .line 823
    .line 824
    invoke-static {v4}, Lvp/z3;->T(Lvp/u3;)V

    .line 825
    .line 826
    .line 827
    sget-object v7, Lvp/z;->B:Lvp/y;

    .line 828
    .line 829
    invoke-virtual {v7, v5}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 830
    .line 831
    .line 832
    move-result-object v7

    .line 833
    check-cast v7, Ljava/lang/Integer;

    .line 834
    .line 835
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 836
    .line 837
    .line 838
    move-result v7

    .line 839
    invoke-virtual {v4, v2, v3, v7}, Lvp/n;->f0(Ljava/lang/String;Lvp/s3;I)Ljava/util/List;

    .line 840
    .line 841
    .line 842
    move-result-object v3

    .line 843
    new-instance v4, Ljava/util/ArrayList;

    .line 844
    .line 845
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 846
    .line 847
    .line 848
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 849
    .line 850
    .line 851
    move-result-object v3

    .line 852
    :goto_e
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 853
    .line 854
    .line 855
    move-result v7

    .line 856
    if-eqz v7, :cond_f

    .line 857
    .line 858
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 859
    .line 860
    .line 861
    move-result-object v7

    .line 862
    check-cast v7, Lvp/a4;

    .line 863
    .line 864
    iget-object v8, v7, Lvp/a4;->c:Ljava/lang/String;

    .line 865
    .line 866
    iget-wide v9, v7, Lvp/a4;->h:J

    .line 867
    .line 868
    iget-wide v11, v7, Lvp/a4;->a:J

    .line 869
    .line 870
    invoke-virtual {v1, v2, v8}, Lvp/z3;->s(Ljava/lang/String;Ljava/lang/String;)Z

    .line 871
    .line 872
    .line 873
    move-result v8

    .line 874
    if-nez v8, :cond_8

    .line 875
    .line 876
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 877
    .line 878
    .line 879
    move-result-object v8

    .line 880
    iget-object v8, v8, Lvp/p0;->r:Lvp/n0;

    .line 881
    .line 882
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 883
    .line 884
    .line 885
    move-result-object v9

    .line 886
    iget-object v7, v7, Lvp/a4;->c:Ljava/lang/String;

    .line 887
    .line 888
    const-string v10, "[sgtm] batch skipped due to destination in backoff. appId, rowId, url"

    .line 889
    .line 890
    invoke-virtual {v8, v10, v2, v9, v7}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 891
    .line 892
    .line 893
    goto :goto_e

    .line 894
    :cond_8
    iget v8, v7, Lvp/a4;->i:I

    .line 895
    .line 896
    if-gtz v8, :cond_9

    .line 897
    .line 898
    goto :goto_f

    .line 899
    :cond_9
    sget-object v13, Lvp/z;->z:Lvp/y;

    .line 900
    .line 901
    invoke-virtual {v13, v5}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 902
    .line 903
    .line 904
    move-result-object v13

    .line 905
    check-cast v13, Ljava/lang/Integer;

    .line 906
    .line 907
    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    .line 908
    .line 909
    .line 910
    move-result v13

    .line 911
    if-le v8, v13, :cond_a

    .line 912
    .line 913
    goto/16 :goto_13

    .line 914
    .line 915
    :cond_a
    sget-object v13, Lvp/z;->x:Lvp/y;

    .line 916
    .line 917
    invoke-virtual {v13, v5}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 918
    .line 919
    .line 920
    move-result-object v13

    .line 921
    check-cast v13, Ljava/lang/Long;

    .line 922
    .line 923
    invoke-virtual {v13}, Ljava/lang/Long;->longValue()J

    .line 924
    .line 925
    .line 926
    move-result-wide v13

    .line 927
    add-int/lit8 v8, v8, -0x1

    .line 928
    .line 929
    const-wide/16 v15, 0x1

    .line 930
    .line 931
    shl-long/2addr v15, v8

    .line 932
    mul-long/2addr v13, v15

    .line 933
    sget-object v8, Lvp/z;->y:Lvp/y;

    .line 934
    .line 935
    invoke-virtual {v8, v5}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move-result-object v8

    .line 939
    check-cast v8, Ljava/lang/Long;

    .line 940
    .line 941
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 942
    .line 943
    .line 944
    move-result-wide v5

    .line 945
    invoke-static {v13, v14, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 946
    .line 947
    .line 948
    move-result-wide v5

    .line 949
    invoke-virtual {v1}, Lvp/z3;->l()Lto/a;

    .line 950
    .line 951
    .line 952
    move-result-object v8

    .line 953
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 954
    .line 955
    .line 956
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 957
    .line 958
    .line 959
    move-result-wide v13

    .line 960
    add-long/2addr v5, v9

    .line 961
    cmp-long v5, v13, v5

    .line 962
    .line 963
    if-ltz v5, :cond_e

    .line 964
    .line 965
    :goto_f
    new-instance v5, Landroid/os/Bundle;

    .line 966
    .line 967
    invoke-direct {v5}, Landroid/os/Bundle;-><init>()V

    .line 968
    .line 969
    .line 970
    iget-object v6, v7, Lvp/a4;->d:Ljava/util/HashMap;

    .line 971
    .line 972
    invoke-virtual {v6}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 973
    .line 974
    .line 975
    move-result-object v6

    .line 976
    invoke-interface {v6}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 977
    .line 978
    .line 979
    move-result-object v6

    .line 980
    :goto_10
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 981
    .line 982
    .line 983
    move-result v8

    .line 984
    if-eqz v8, :cond_b

    .line 985
    .line 986
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 987
    .line 988
    .line 989
    move-result-object v8

    .line 990
    check-cast v8, Ljava/util/Map$Entry;

    .line 991
    .line 992
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 993
    .line 994
    .line 995
    move-result-object v9

    .line 996
    check-cast v9, Ljava/lang/String;

    .line 997
    .line 998
    invoke-interface {v8}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 999
    .line 1000
    .line 1001
    move-result-object v8

    .line 1002
    check-cast v8, Ljava/lang/String;

    .line 1003
    .line 1004
    invoke-virtual {v5, v9, v8}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1005
    .line 1006
    .line 1007
    goto :goto_10

    .line 1008
    :cond_b
    iget-wide v8, v7, Lvp/a4;->a:J

    .line 1009
    .line 1010
    iget-object v6, v7, Lvp/a4;->b:Lcom/google/android/gms/internal/measurement/h3;

    .line 1011
    .line 1012
    iget-object v10, v7, Lvp/a4;->c:Ljava/lang/String;

    .line 1013
    .line 1014
    iget-object v11, v7, Lvp/a4;->e:Lvp/q2;

    .line 1015
    .line 1016
    iget-wide v12, v7, Lvp/a4;->g:J

    .line 1017
    .line 1018
    new-instance v17, Lvp/r3;

    .line 1019
    .line 1020
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 1021
    .line 1022
    .line 1023
    move-result-object v20

    .line 1024
    iget v6, v11, Lvp/q2;->d:I

    .line 1025
    .line 1026
    const-string v26, ""

    .line 1027
    .line 1028
    move-object/from16 v22, v5

    .line 1029
    .line 1030
    move/from16 v23, v6

    .line 1031
    .line 1032
    move-wide/from16 v18, v8

    .line 1033
    .line 1034
    move-object/from16 v21, v10

    .line 1035
    .line 1036
    move-wide/from16 v24, v12

    .line 1037
    .line 1038
    invoke-direct/range {v17 .. v26}, Lvp/r3;-><init>(J[BLjava/lang/String;Landroid/os/Bundle;IJLjava/lang/String;)V

    .line 1039
    .line 1040
    .line 1041
    move-object/from16 v5, v17

    .line 1042
    .line 1043
    :try_start_e
    invoke-static {}, Lcom/google/android/gms/internal/measurement/h3;->w()Lcom/google/android/gms/internal/measurement/g3;

    .line 1044
    .line 1045
    .line 1046
    move-result-object v6

    .line 1047
    iget-object v7, v5, Lvp/r3;->e:[B

    .line 1048
    .line 1049
    invoke-static {v6, v7}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 1050
    .line 1051
    .line 1052
    move-result-object v6

    .line 1053
    check-cast v6, Lcom/google/android/gms/internal/measurement/g3;

    .line 1054
    .line 1055
    const/4 v7, 0x0

    .line 1056
    :goto_11
    iget-object v8, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 1057
    .line 1058
    check-cast v8, Lcom/google/android/gms/internal/measurement/h3;

    .line 1059
    .line 1060
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/h3;->q()I

    .line 1061
    .line 1062
    .line 1063
    move-result v8

    .line 1064
    if-ge v7, v8, :cond_c

    .line 1065
    .line 1066
    iget-object v8, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 1067
    .line 1068
    check-cast v8, Lcom/google/android/gms/internal/measurement/h3;

    .line 1069
    .line 1070
    invoke-virtual {v8, v7}, Lcom/google/android/gms/internal/measurement/h3;->r(I)Lcom/google/android/gms/internal/measurement/j3;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v8

    .line 1074
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/l5;->i()Lcom/google/android/gms/internal/measurement/k5;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v8

    .line 1078
    check-cast v8, Lcom/google/android/gms/internal/measurement/i3;

    .line 1079
    .line 1080
    invoke-virtual {v1}, Lvp/z3;->l()Lto/a;

    .line 1081
    .line 1082
    .line 1083
    move-result-object v9

    .line 1084
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1085
    .line 1086
    .line 1087
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1088
    .line 1089
    .line 1090
    move-result-wide v9

    .line 1091
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 1092
    .line 1093
    .line 1094
    iget-object v11, v8, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 1095
    .line 1096
    check-cast v11, Lcom/google/android/gms/internal/measurement/j3;

    .line 1097
    .line 1098
    invoke-virtual {v11, v9, v10}, Lcom/google/android/gms/internal/measurement/j3;->f0(J)V

    .line 1099
    .line 1100
    .line 1101
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 1102
    .line 1103
    .line 1104
    iget-object v9, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 1105
    .line 1106
    check-cast v9, Lcom/google/android/gms/internal/measurement/h3;

    .line 1107
    .line 1108
    invoke-virtual {v8}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v8

    .line 1112
    check-cast v8, Lcom/google/android/gms/internal/measurement/j3;

    .line 1113
    .line 1114
    invoke-virtual {v9, v7, v8}, Lcom/google/android/gms/internal/measurement/h3;->y(ILcom/google/android/gms/internal/measurement/j3;)V

    .line 1115
    .line 1116
    .line 1117
    add-int/lit8 v7, v7, 0x1

    .line 1118
    .line 1119
    goto :goto_11

    .line 1120
    :cond_c
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v7

    .line 1124
    check-cast v7, Lcom/google/android/gms/internal/measurement/h3;

    .line 1125
    .line 1126
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 1127
    .line 1128
    .line 1129
    move-result-object v7

    .line 1130
    iput-object v7, v5, Lvp/r3;->e:[B

    .line 1131
    .line 1132
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v7

    .line 1136
    invoke-virtual {v7}, Lvp/p0;->k0()Ljava/lang/String;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v7

    .line 1140
    const/4 v8, 0x2

    .line 1141
    invoke-static {v7, v8}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 1142
    .line 1143
    .line 1144
    move-result v7

    .line 1145
    if-eqz v7, :cond_d

    .line 1146
    .line 1147
    iget-object v7, v1, Lvp/z3;->j:Lvp/s0;

    .line 1148
    .line 1149
    invoke-static {v7}, Lvp/z3;->T(Lvp/u3;)V

    .line 1150
    .line 1151
    .line 1152
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v6

    .line 1156
    check-cast v6, Lcom/google/android/gms/internal/measurement/h3;

    .line 1157
    .line 1158
    invoke-virtual {v7, v6}, Lvp/s0;->D0(Lcom/google/android/gms/internal/measurement/h3;)Ljava/lang/String;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v6

    .line 1162
    iput-object v6, v5, Lvp/r3;->j:Ljava/lang/String;
    :try_end_e
    .catch Lcom/google/android/gms/internal/measurement/u5; {:try_start_e .. :try_end_e} :catch_6

    .line 1163
    .line 1164
    :cond_d
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1165
    .line 1166
    .line 1167
    :goto_12
    const/4 v5, 0x0

    .line 1168
    const/4 v6, 0x0

    .line 1169
    goto/16 :goto_e

    .line 1170
    .line 1171
    :catch_6
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v5

    .line 1175
    iget-object v5, v5, Lvp/p0;->m:Lvp/n0;

    .line 1176
    .line 1177
    const-string v6, "Failed to parse queued batch. appId"

    .line 1178
    .line 1179
    invoke-virtual {v5, v2, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1180
    .line 1181
    .line 1182
    goto :goto_12

    .line 1183
    :cond_e
    :goto_13
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v5

    .line 1187
    iget-object v5, v5, Lvp/p0;->r:Lvp/n0;

    .line 1188
    .line 1189
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v6

    .line 1193
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1194
    .line 1195
    .line 1196
    move-result-object v7

    .line 1197
    const-string v8, "[sgtm] batch skipped waiting for next retry. appId, rowId, lastUploadMillis"

    .line 1198
    .line 1199
    invoke-virtual {v5, v8, v2, v6, v7}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1200
    .line 1201
    .line 1202
    goto :goto_12

    .line 1203
    :cond_f
    new-instance v3, Lvp/t3;

    .line 1204
    .line 1205
    invoke-direct {v3, v4}, Lvp/t3;-><init>(Ljava/util/ArrayList;)V

    .line 1206
    .line 1207
    .line 1208
    :try_start_f
    invoke-interface {v0, v3}, Lvp/g0;->G(Lvp/t3;)V

    .line 1209
    .line 1210
    .line 1211
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1212
    .line 1213
    .line 1214
    move-result-object v0

    .line 1215
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 1216
    .line 1217
    const-string v3, "[sgtm] Sending queued upload batches to client. appId, count"

    .line 1218
    .line 1219
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 1220
    .line 1221
    .line 1222
    move-result v4

    .line 1223
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v4

    .line 1227
    invoke-virtual {v0, v2, v4, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_f
    .catch Landroid/os/RemoteException; {:try_start_f .. :try_end_f} :catch_7

    .line 1228
    .line 1229
    .line 1230
    goto :goto_14

    .line 1231
    :catch_7
    move-exception v0

    .line 1232
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v1

    .line 1236
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 1237
    .line 1238
    const-string v3, "[sgtm] Failed to return upload batches for app"

    .line 1239
    .line 1240
    invoke-virtual {v1, v2, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 1241
    .line 1242
    .line 1243
    :goto_14
    return-void

    .line 1244
    :pswitch_8
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 1245
    .line 1246
    check-cast v1, Llp/lg;

    .line 1247
    .line 1248
    iget-object v5, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 1249
    .line 1250
    check-cast v5, Lbb/g0;

    .line 1251
    .line 1252
    iget-object v6, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 1253
    .line 1254
    check-cast v6, Llp/ub;

    .line 1255
    .line 1256
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 1257
    .line 1258
    check-cast v0, Ljava/lang/String;

    .line 1259
    .line 1260
    iget-object v7, v5, Lbb/g0;->f:Ljava/lang/Object;

    .line 1261
    .line 1262
    check-cast v7, Lin/z1;

    .line 1263
    .line 1264
    iput-object v6, v7, Lin/z1;->b:Ljava/lang/Object;

    .line 1265
    .line 1266
    iget-object v6, v7, Lin/z1;->a:Ljava/lang/Object;

    .line 1267
    .line 1268
    check-cast v6, Llp/lf;

    .line 1269
    .line 1270
    if-eqz v6, :cond_10

    .line 1271
    .line 1272
    iget-object v6, v6, Llp/lf;->d:Ljava/lang/String;

    .line 1273
    .line 1274
    invoke-static {v6}, Lm20/k;->b(Ljava/lang/String;)Z

    .line 1275
    .line 1276
    .line 1277
    move-result v7

    .line 1278
    if-nez v7, :cond_10

    .line 1279
    .line 1280
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 1281
    .line 1282
    .line 1283
    goto :goto_15

    .line 1284
    :cond_10
    const-string v6, "NA"

    .line 1285
    .line 1286
    :goto_15
    new-instance v7, Ljp/uf;

    .line 1287
    .line 1288
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 1289
    .line 1290
    .line 1291
    iget-object v8, v1, Llp/lg;->a:Ljava/lang/String;

    .line 1292
    .line 1293
    iput-object v8, v7, Ljp/uf;->a:Ljava/lang/Object;

    .line 1294
    .line 1295
    iget-object v8, v1, Llp/lg;->b:Ljava/lang/String;

    .line 1296
    .line 1297
    iput-object v8, v7, Ljp/uf;->b:Ljava/lang/Object;

    .line 1298
    .line 1299
    const-class v8, Llp/lg;

    .line 1300
    .line 1301
    monitor-enter v8

    .line 1302
    :try_start_10
    sget-object v9, Llp/lg;->k:Llp/u;
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_3

    .line 1303
    .line 1304
    if-eqz v9, :cond_11

    .line 1305
    .line 1306
    monitor-exit v8

    .line 1307
    goto :goto_17

    .line 1308
    :cond_11
    :try_start_11
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v9

    .line 1312
    invoke-virtual {v9}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v9

    .line 1316
    invoke-virtual {v9}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 1317
    .line 1318
    .line 1319
    move-result-object v9

    .line 1320
    new-instance v10, Ly5/c;

    .line 1321
    .line 1322
    new-instance v11, Ly5/d;

    .line 1323
    .line 1324
    invoke-direct {v11, v9}, Ly5/d;-><init>(Landroid/os/LocaleList;)V

    .line 1325
    .line 1326
    .line 1327
    invoke-direct {v10, v11}, Ly5/c;-><init>(Ly5/d;)V

    .line 1328
    .line 1329
    .line 1330
    new-array v3, v3, [Ljava/lang/Object;

    .line 1331
    .line 1332
    const/4 v9, 0x0

    .line 1333
    const/4 v11, 0x0

    .line 1334
    :goto_16
    invoke-virtual {v10}, Ly5/c;->c()I

    .line 1335
    .line 1336
    .line 1337
    move-result v12

    .line 1338
    if-ge v9, v12, :cond_15

    .line 1339
    .line 1340
    invoke-virtual {v10, v9}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 1341
    .line 1342
    .line 1343
    move-result-object v12

    .line 1344
    sget-object v13, Lfv/c;->a:Lb81/b;

    .line 1345
    .line 1346
    invoke-virtual {v12}, Ljava/util/Locale;->toLanguageTag()Ljava/lang/String;

    .line 1347
    .line 1348
    .line 1349
    move-result-object v12

    .line 1350
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1351
    .line 1352
    .line 1353
    add-int/lit8 v13, v11, 0x1

    .line 1354
    .line 1355
    array-length v14, v3

    .line 1356
    if-ge v14, v13, :cond_14

    .line 1357
    .line 1358
    shr-int/lit8 v15, v14, 0x1

    .line 1359
    .line 1360
    add-int/2addr v14, v15

    .line 1361
    add-int/2addr v14, v4

    .line 1362
    if-ge v14, v13, :cond_12

    .line 1363
    .line 1364
    invoke-static {v11}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 1365
    .line 1366
    .line 1367
    move-result v14

    .line 1368
    add-int/2addr v14, v14

    .line 1369
    :cond_12
    if-gez v14, :cond_13

    .line 1370
    .line 1371
    const v14, 0x7fffffff

    .line 1372
    .line 1373
    .line 1374
    :cond_13
    invoke-static {v3, v14}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 1375
    .line 1376
    .line 1377
    move-result-object v3

    .line 1378
    :cond_14
    aput-object v12, v3, v11

    .line 1379
    .line 1380
    add-int/lit8 v9, v9, 0x1

    .line 1381
    .line 1382
    move v11, v13

    .line 1383
    goto :goto_16

    .line 1384
    :catchall_3
    move-exception v0

    .line 1385
    goto :goto_19

    .line 1386
    :cond_15
    invoke-static {v11, v3}, Llp/o;->m(I[Ljava/lang/Object;)Llp/u;

    .line 1387
    .line 1388
    .line 1389
    move-result-object v9

    .line 1390
    sput-object v9, Llp/lg;->k:Llp/u;
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_3

    .line 1391
    .line 1392
    monitor-exit v8

    .line 1393
    :goto_17
    iput-object v9, v7, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 1394
    .line 1395
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1396
    .line 1397
    iput-object v3, v7, Ljp/uf;->g:Ljava/lang/Object;

    .line 1398
    .line 1399
    iput-object v6, v7, Ljp/uf;->d:Ljava/lang/Object;

    .line 1400
    .line 1401
    iput-object v0, v7, Ljp/uf;->c:Ljava/lang/Object;

    .line 1402
    .line 1403
    iget-object v0, v1, Llp/lg;->f:Laq/t;

    .line 1404
    .line 1405
    invoke-virtual {v0}, Laq/t;->i()Z

    .line 1406
    .line 1407
    .line 1408
    move-result v0

    .line 1409
    if-eqz v0, :cond_16

    .line 1410
    .line 1411
    iget-object v0, v1, Llp/lg;->f:Laq/t;

    .line 1412
    .line 1413
    invoke-virtual {v0}, Laq/t;->g()Ljava/lang/Object;

    .line 1414
    .line 1415
    .line 1416
    move-result-object v0

    .line 1417
    check-cast v0, Ljava/lang/String;

    .line 1418
    .line 1419
    goto :goto_18

    .line 1420
    :cond_16
    iget-object v0, v1, Llp/lg;->d:Lfv/i;

    .line 1421
    .line 1422
    invoke-virtual {v0}, Lfv/i;->a()Ljava/lang/String;

    .line 1423
    .line 1424
    .line 1425
    move-result-object v0

    .line 1426
    :goto_18
    iput-object v0, v7, Ljp/uf;->e:Ljava/lang/Object;

    .line 1427
    .line 1428
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1429
    .line 1430
    .line 1431
    move-result-object v0

    .line 1432
    iput-object v0, v7, Ljp/uf;->i:Ljava/io/Serializable;

    .line 1433
    .line 1434
    iget v0, v1, Llp/lg;->h:I

    .line 1435
    .line 1436
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1437
    .line 1438
    .line 1439
    move-result-object v0

    .line 1440
    iput-object v0, v7, Ljp/uf;->j:Ljava/lang/Object;

    .line 1441
    .line 1442
    iput-object v7, v5, Lbb/g0;->g:Ljava/lang/Object;

    .line 1443
    .line 1444
    iget-object v0, v1, Llp/lg;->c:Llp/ig;

    .line 1445
    .line 1446
    invoke-virtual {v0, v5}, Llp/ig;->a(Lbb/g0;)V

    .line 1447
    .line 1448
    .line 1449
    return-void

    .line 1450
    :goto_19
    :try_start_12
    monitor-exit v8
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_3

    .line 1451
    throw v0

    .line 1452
    :pswitch_9
    iget-object v1, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 1453
    .line 1454
    check-cast v1, Lhu/q;

    .line 1455
    .line 1456
    iget-object v1, v1, Lhu/q;->e:Ljava/lang/Object;

    .line 1457
    .line 1458
    check-cast v1, Ll/f;

    .line 1459
    .line 1460
    iget-object v2, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 1461
    .line 1462
    check-cast v2, Ll/n;

    .line 1463
    .line 1464
    iget-object v5, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 1465
    .line 1466
    check-cast v5, Ll/e;

    .line 1467
    .line 1468
    if-eqz v5, :cond_17

    .line 1469
    .line 1470
    iput-boolean v4, v1, Ll/f;->C:Z

    .line 1471
    .line 1472
    iget-object v4, v5, Ll/e;->b:Ll/l;

    .line 1473
    .line 1474
    const/4 v5, 0x0

    .line 1475
    invoke-virtual {v4, v5}, Ll/l;->c(Z)V

    .line 1476
    .line 1477
    .line 1478
    iput-boolean v5, v1, Ll/f;->C:Z

    .line 1479
    .line 1480
    :cond_17
    invoke-virtual {v2}, Ll/n;->isEnabled()Z

    .line 1481
    .line 1482
    .line 1483
    move-result v1

    .line 1484
    if-eqz v1, :cond_18

    .line 1485
    .line 1486
    invoke-virtual {v2}, Ll/n;->hasSubMenu()Z

    .line 1487
    .line 1488
    .line 1489
    move-result v1

    .line 1490
    if-eqz v1, :cond_18

    .line 1491
    .line 1492
    iget-object v0, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 1493
    .line 1494
    check-cast v0, Ll/l;

    .line 1495
    .line 1496
    const/4 v15, 0x0

    .line 1497
    invoke-virtual {v0, v2, v15, v3}, Ll/l;->q(Landroid/view/MenuItem;Ll/x;I)Z

    .line 1498
    .line 1499
    .line 1500
    :cond_18
    return-void

    .line 1501
    :pswitch_a
    move v5, v6

    .line 1502
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 1503
    .line 1504
    check-cast v1, Ljp/vg;

    .line 1505
    .line 1506
    iget-object v3, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 1507
    .line 1508
    check-cast v3, Lbb/g0;

    .line 1509
    .line 1510
    iget-object v4, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 1511
    .line 1512
    check-cast v4, Ljp/bc;

    .line 1513
    .line 1514
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 1515
    .line 1516
    check-cast v0, Ljava/lang/String;

    .line 1517
    .line 1518
    iget-object v6, v3, Lbb/g0;->f:Ljava/lang/Object;

    .line 1519
    .line 1520
    check-cast v6, Lin/z1;

    .line 1521
    .line 1522
    iput-object v4, v6, Lin/z1;->b:Ljava/lang/Object;

    .line 1523
    .line 1524
    iget-object v4, v6, Lin/z1;->a:Ljava/lang/Object;

    .line 1525
    .line 1526
    check-cast v4, Ljp/vf;

    .line 1527
    .line 1528
    if-eqz v4, :cond_1a

    .line 1529
    .line 1530
    iget-object v4, v4, Ljp/vf;->d:Ljava/lang/String;

    .line 1531
    .line 1532
    if-eqz v4, :cond_1a

    .line 1533
    .line 1534
    invoke-virtual {v4}, Ljava/lang/String;->isEmpty()Z

    .line 1535
    .line 1536
    .line 1537
    move-result v6

    .line 1538
    if-eqz v6, :cond_19

    .line 1539
    .line 1540
    goto :goto_1a

    .line 1541
    :cond_19
    invoke-static {v4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 1542
    .line 1543
    .line 1544
    goto :goto_1b

    .line 1545
    :cond_1a
    :goto_1a
    const-string v4, "NA"

    .line 1546
    .line 1547
    :goto_1b
    new-instance v6, Ljp/uf;

    .line 1548
    .line 1549
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 1550
    .line 1551
    .line 1552
    iget-object v7, v1, Ljp/vg;->a:Ljava/lang/String;

    .line 1553
    .line 1554
    iput-object v7, v6, Ljp/uf;->a:Ljava/lang/Object;

    .line 1555
    .line 1556
    iget-object v7, v1, Ljp/vg;->b:Ljava/lang/String;

    .line 1557
    .line 1558
    iput-object v7, v6, Ljp/uf;->b:Ljava/lang/Object;

    .line 1559
    .line 1560
    const-class v7, Ljp/vg;

    .line 1561
    .line 1562
    monitor-enter v7

    .line 1563
    :try_start_13
    sget-object v8, Ljp/vg;->k:Ljp/c0;
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_4

    .line 1564
    .line 1565
    if-eqz v8, :cond_1b

    .line 1566
    .line 1567
    monitor-exit v7

    .line 1568
    goto :goto_1d

    .line 1569
    :cond_1b
    :try_start_14
    invoke-static {}, Landroid/content/res/Resources;->getSystem()Landroid/content/res/Resources;

    .line 1570
    .line 1571
    .line 1572
    move-result-object v8

    .line 1573
    invoke-virtual {v8}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 1574
    .line 1575
    .line 1576
    move-result-object v8

    .line 1577
    invoke-virtual {v8}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 1578
    .line 1579
    .line 1580
    move-result-object v8

    .line 1581
    new-instance v9, Ly5/c;

    .line 1582
    .line 1583
    new-instance v10, Ly5/d;

    .line 1584
    .line 1585
    invoke-direct {v10, v8}, Ly5/d;-><init>(Landroid/os/LocaleList;)V

    .line 1586
    .line 1587
    .line 1588
    invoke-direct {v9, v10}, Ly5/c;-><init>(Ly5/d;)V

    .line 1589
    .line 1590
    .line 1591
    new-instance v8, Lin/o;

    .line 1592
    .line 1593
    invoke-direct {v8}, Lin/o;-><init>()V

    .line 1594
    .line 1595
    .line 1596
    :goto_1c
    invoke-virtual {v9}, Ly5/c;->c()I

    .line 1597
    .line 1598
    .line 1599
    move-result v10

    .line 1600
    if-ge v5, v10, :cond_1c

    .line 1601
    .line 1602
    invoke-virtual {v9, v5}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 1603
    .line 1604
    .line 1605
    move-result-object v10

    .line 1606
    sget-object v11, Lfv/c;->a:Lb81/b;

    .line 1607
    .line 1608
    invoke-virtual {v10}, Ljava/util/Locale;->toLanguageTag()Ljava/lang/String;

    .line 1609
    .line 1610
    .line 1611
    move-result-object v10

    .line 1612
    invoke-virtual {v8, v10}, Lin/o;->q(Ljava/lang/Object;)V

    .line 1613
    .line 1614
    .line 1615
    add-int/lit8 v5, v5, 0x1

    .line 1616
    .line 1617
    goto :goto_1c

    .line 1618
    :catchall_4
    move-exception v0

    .line 1619
    goto :goto_1f

    .line 1620
    :cond_1c
    invoke-virtual {v8}, Lin/o;->s()Ljp/c0;

    .line 1621
    .line 1622
    .line 1623
    move-result-object v8

    .line 1624
    sput-object v8, Ljp/vg;->k:Ljp/c0;
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_4

    .line 1625
    .line 1626
    monitor-exit v7

    .line 1627
    :goto_1d
    iput-object v8, v6, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 1628
    .line 1629
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1630
    .line 1631
    iput-object v5, v6, Ljp/uf;->g:Ljava/lang/Object;

    .line 1632
    .line 1633
    iput-object v4, v6, Ljp/uf;->d:Ljava/lang/Object;

    .line 1634
    .line 1635
    iput-object v0, v6, Ljp/uf;->c:Ljava/lang/Object;

    .line 1636
    .line 1637
    iget-object v0, v1, Ljp/vg;->f:Laq/t;

    .line 1638
    .line 1639
    invoke-virtual {v0}, Laq/t;->i()Z

    .line 1640
    .line 1641
    .line 1642
    move-result v0

    .line 1643
    if-eqz v0, :cond_1d

    .line 1644
    .line 1645
    iget-object v0, v1, Ljp/vg;->f:Laq/t;

    .line 1646
    .line 1647
    invoke-virtual {v0}, Laq/t;->g()Ljava/lang/Object;

    .line 1648
    .line 1649
    .line 1650
    move-result-object v0

    .line 1651
    check-cast v0, Ljava/lang/String;

    .line 1652
    .line 1653
    goto :goto_1e

    .line 1654
    :cond_1d
    iget-object v0, v1, Ljp/vg;->d:Lfv/i;

    .line 1655
    .line 1656
    invoke-virtual {v0}, Lfv/i;->a()Ljava/lang/String;

    .line 1657
    .line 1658
    .line 1659
    move-result-object v0

    .line 1660
    :goto_1e
    iput-object v0, v6, Ljp/uf;->e:Ljava/lang/Object;

    .line 1661
    .line 1662
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1663
    .line 1664
    .line 1665
    move-result-object v0

    .line 1666
    iput-object v0, v6, Ljp/uf;->i:Ljava/io/Serializable;

    .line 1667
    .line 1668
    iget v0, v1, Ljp/vg;->h:I

    .line 1669
    .line 1670
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1671
    .line 1672
    .line 1673
    move-result-object v0

    .line 1674
    iput-object v0, v6, Ljp/uf;->j:Ljava/lang/Object;

    .line 1675
    .line 1676
    iput-object v6, v3, Lbb/g0;->g:Ljava/lang/Object;

    .line 1677
    .line 1678
    iget-object v0, v1, Ljp/vg;->c:Ljp/tg;

    .line 1679
    .line 1680
    invoke-virtual {v0, v3}, Ljp/tg;->a(Lbb/g0;)V

    .line 1681
    .line 1682
    .line 1683
    return-void

    .line 1684
    :goto_1f
    :try_start_15
    monitor-exit v7
    :try_end_15
    .catchall {:try_start_15 .. :try_end_15} :catchall_4

    .line 1685
    throw v0

    .line 1686
    :pswitch_b
    iget-object v1, v0, Ld6/z0;->e:Ljava/lang/Object;

    .line 1687
    .line 1688
    check-cast v1, Landroid/view/View;

    .line 1689
    .line 1690
    iget-object v2, v0, Ld6/z0;->f:Ljava/lang/Object;

    .line 1691
    .line 1692
    check-cast v2, Ld6/f1;

    .line 1693
    .line 1694
    iget-object v3, v0, Ld6/z0;->g:Ljava/lang/Object;

    .line 1695
    .line 1696
    check-cast v3, Lb81/d;

    .line 1697
    .line 1698
    invoke-static {v1, v2, v3}, Ld6/b1;->i(Landroid/view/View;Ld6/f1;Lb81/d;)V

    .line 1699
    .line 1700
    .line 1701
    iget-object v0, v0, Ld6/z0;->h:Ljava/lang/Object;

    .line 1702
    .line 1703
    check-cast v0, Landroid/animation/ValueAnimator;

    .line 1704
    .line 1705
    invoke-virtual {v0}, Landroid/animation/ValueAnimator;->start()V

    .line 1706
    .line 1707
    .line 1708
    return-void

    .line 1709
    :pswitch_data_0
    .packed-switch 0x0
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
