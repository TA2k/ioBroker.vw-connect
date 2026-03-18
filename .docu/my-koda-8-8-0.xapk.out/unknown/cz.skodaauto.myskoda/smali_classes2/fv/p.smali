.class public final synthetic Lfv/p;
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

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p6, p0, Lfv/p;->d:I

    iput-object p1, p0, Lfv/p;->e:Ljava/lang/Object;

    iput-object p2, p0, Lfv/p;->f:Ljava/lang/Object;

    iput-object p3, p0, Lfv/p;->g:Ljava/lang/Object;

    iput-object p4, p0, Lfv/p;->h:Ljava/lang/Object;

    iput-object p5, p0, Lfv/p;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lvp/d3;Ljava/io/Serializable;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p6, p0, Lfv/p;->d:I

    iput-object p2, p0, Lfv/p;->e:Ljava/lang/Object;

    iput-object p3, p0, Lfv/p;->f:Ljava/lang/Object;

    iput-object p4, p0, Lfv/p;->g:Ljava/lang/Object;

    iput-object p5, p0, Lfv/p;->h:Ljava/lang/Object;

    iput-object p1, p0, Lfv/p;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    .line 1
    iget v0, p0, Lfv/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lfv/p;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lcom/google/android/gms/internal/measurement/m0;

    .line 9
    .line 10
    iget-object v1, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/lang/String;

    .line 13
    .line 14
    iget-object v2, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Ljava/lang/String;

    .line 17
    .line 18
    iget-object v3, p0, Lfv/p;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Lvp/d3;

    .line 21
    .line 22
    new-instance v4, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    :try_start_0
    iget-object v5, v3, Lvp/d3;->h:Lvp/c0;

    .line 28
    .line 29
    if-nez v5, :cond_0

    .line 30
    .line 31
    iget-object p0, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Lvp/g1;

    .line 34
    .line 35
    iget-object v5, p0, Lvp/g1;->i:Lvp/p0;

    .line 36
    .line 37
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 38
    .line 39
    .line 40
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 41
    .line 42
    const-string v6, "Failed to get conditional properties; not connected to service"

    .line 43
    .line 44
    invoke-virtual {v5, v2, v1, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 48
    .line 49
    :goto_0
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, v0, v4}, Lvp/d4;->O0(Lcom/google/android/gms/internal/measurement/m0;Ljava/util/ArrayList;)V

    .line 53
    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_0
    :try_start_1
    iget-object p0, p0, Lfv/p;->g:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lvp/f4;

    .line 59
    .line 60
    invoke-interface {v5, v2, v1, p0}, Lvp/c0;->t(Ljava/lang/String;Ljava/lang/String;Lvp/f4;)Ljava/util/List;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-static {p0}, Lvp/d4;->P0(Ljava/util/List;)Ljava/util/ArrayList;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-virtual {v3}, Lvp/d3;->n0()V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :catchall_0
    move-exception p0

    .line 73
    goto :goto_3

    .line 74
    :catch_0
    move-exception p0

    .line 75
    :try_start_2
    iget-object v5, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v5, Lvp/g1;

    .line 78
    .line 79
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 80
    .line 81
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 82
    .line 83
    .line 84
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 85
    .line 86
    const-string v6, "Failed to get conditional properties; remote exception"

    .line 87
    .line 88
    invoke-virtual {v5, v6, v2, v1, p0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 89
    .line 90
    .line 91
    :goto_1
    iget-object p0, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Lvp/g1;

    .line 94
    .line 95
    iget-object p0, p0, Lvp/g1;->l:Lvp/d4;

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :goto_2
    return-void

    .line 99
    :goto_3
    iget-object v1, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v1, Lvp/g1;

    .line 102
    .line 103
    iget-object v1, v1, Lvp/g1;->l:Lvp/d4;

    .line 104
    .line 105
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v1, v0, v4}, Lvp/d4;->O0(Lcom/google/android/gms/internal/measurement/m0;Ljava/util/ArrayList;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :pswitch_0
    iget-object v0, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 115
    .line 116
    monitor-enter v0

    .line 117
    const/4 v1, 0x0

    .line 118
    :try_start_3
    iget-object v2, p0, Lfv/p;->i:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v2, Lvp/d3;

    .line 121
    .line 122
    iget-object v3, v2, Lvp/d3;->h:Lvp/c0;

    .line 123
    .line 124
    if-nez v3, :cond_1

    .line 125
    .line 126
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v2, Lvp/g1;

    .line 129
    .line 130
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 131
    .line 132
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 133
    .line 134
    .line 135
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 136
    .line 137
    const-string v3, "(legacy) Failed to get conditional properties; not connected to service"

    .line 138
    .line 139
    iget-object v4, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v4, Ljava/lang/String;

    .line 142
    .line 143
    iget-object v5, p0, Lfv/p;->g:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v5, Ljava/lang/String;

    .line 146
    .line 147
    invoke-virtual {v2, v3, v1, v4, v5}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 151
    .line 152
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 153
    .line 154
    .line 155
    :try_start_4
    invoke-virtual {v0}, Ljava/lang/Object;->notify()V

    .line 156
    .line 157
    .line 158
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 159
    goto :goto_8

    .line 160
    :catchall_1
    move-exception p0

    .line 161
    goto :goto_a

    .line 162
    :catchall_2
    move-exception v1

    .line 163
    goto :goto_9

    .line 164
    :catch_1
    move-exception v2

    .line 165
    goto :goto_6

    .line 166
    :cond_1
    :try_start_5
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    if-eqz v4, :cond_2

    .line 171
    .line 172
    iget-object v4, p0, Lfv/p;->h:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v4, Lvp/f4;

    .line 175
    .line 176
    iget-object v5, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v5, Ljava/lang/String;

    .line 179
    .line 180
    iget-object v6, p0, Lfv/p;->g:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v6, Ljava/lang/String;

    .line 183
    .line 184
    invoke-interface {v3, v5, v6, v4}, Lvp/c0;->t(Ljava/lang/String;Ljava/lang/String;Lvp/f4;)Ljava/util/List;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    goto :goto_4

    .line 192
    :cond_2
    iget-object v4, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v4, Ljava/lang/String;

    .line 195
    .line 196
    iget-object v5, p0, Lfv/p;->g:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v5, Ljava/lang/String;

    .line 199
    .line 200
    invoke-interface {v3, v1, v4, v5}, Lvp/c0;->h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    :goto_4
    invoke-virtual {v2}, Lvp/d3;->n0()V
    :try_end_5
    .catch Landroid/os/RemoteException; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 208
    .line 209
    .line 210
    :try_start_6
    iget-object p0, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 213
    .line 214
    :goto_5
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 215
    .line 216
    .line 217
    goto :goto_7

    .line 218
    :goto_6
    :try_start_7
    iget-object v3, p0, Lfv/p;->i:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v3, Lvp/d3;

    .line 221
    .line 222
    iget-object v3, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast v3, Lvp/g1;

    .line 225
    .line 226
    iget-object v3, v3, Lvp/g1;->i:Lvp/p0;

    .line 227
    .line 228
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 229
    .line 230
    .line 231
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 232
    .line 233
    const-string v4, "(legacy) Failed to get conditional properties; remote exception"

    .line 234
    .line 235
    iget-object v5, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v5, Ljava/lang/String;

    .line 238
    .line 239
    invoke-virtual {v3, v4, v1, v5, v2}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    iget-object v1, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 245
    .line 246
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 247
    .line 248
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 249
    .line 250
    .line 251
    :try_start_8
    iget-object p0, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 254
    .line 255
    goto :goto_5

    .line 256
    :goto_7
    monitor-exit v0

    .line 257
    :goto_8
    return-void

    .line 258
    :goto_9
    iget-object p0, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 261
    .line 262
    invoke-virtual {p0}, Ljava/lang/Object;->notify()V

    .line 263
    .line 264
    .line 265
    throw v1

    .line 266
    :goto_a
    monitor-exit v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 267
    throw p0

    .line 268
    :pswitch_1
    iget-object v0, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast v0, Lvp/m1;

    .line 271
    .line 272
    iget-object v1, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast v1, Lvp/f4;

    .line 275
    .line 276
    iget-object v2, p0, Lfv/p;->g:Ljava/lang/Object;

    .line 277
    .line 278
    check-cast v2, Landroid/os/Bundle;

    .line 279
    .line 280
    iget-object v3, p0, Lfv/p;->h:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast v3, Lvp/e0;

    .line 283
    .line 284
    iget-object p0, p0, Lfv/p;->i:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast p0, Ljava/lang/String;

    .line 287
    .line 288
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 289
    .line 290
    invoke-virtual {v0}, Lvp/z3;->B()V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v0, v2, v1}, Lvp/z3;->c0(Landroid/os/Bundle;Lvp/f4;)Ljava/util/List;

    .line 294
    .line 295
    .line 296
    move-result-object v1

    .line 297
    :try_start_9
    invoke-interface {v3, v1}, Lvp/e0;->s(Ljava/util/List;)V
    :try_end_9
    .catch Landroid/os/RemoteException; {:try_start_9 .. :try_end_9} :catch_2

    .line 298
    .line 299
    .line 300
    goto :goto_b

    .line 301
    :catch_2
    move-exception v1

    .line 302
    invoke-virtual {v0}, Lvp/z3;->d()Lvp/p0;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 307
    .line 308
    const-string v2, "Failed to return trigger URIs for app"

    .line 309
    .line 310
    invoke-virtual {v0, p0, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    :goto_b
    return-void

    .line 314
    :pswitch_2
    iget-object v0, p0, Lfv/p;->e:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast v0, Leb/j0;

    .line 317
    .line 318
    iget-object v1, p0, Lfv/p;->f:Ljava/lang/Object;

    .line 319
    .line 320
    check-cast v1, La0/j;

    .line 321
    .line 322
    iget-object v2, p0, Lfv/p;->g:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v2, Laq/a;

    .line 325
    .line 326
    iget-object v3, p0, Lfv/p;->h:Ljava/lang/Object;

    .line 327
    .line 328
    check-cast v3, Ljava/util/concurrent/Callable;

    .line 329
    .line 330
    iget-object p0, p0, Lfv/p;->i:Ljava/lang/Object;

    .line 331
    .line 332
    check-cast p0, Laq/k;

    .line 333
    .line 334
    iget-object v4, v0, Leb/j0;->g:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast v4, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 337
    .line 338
    iget-object v1, v1, La0/j;->e:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v1, Laq/t;

    .line 341
    .line 342
    invoke-virtual {v1}, Laq/t;->h()Z

    .line 343
    .line 344
    .line 345
    move-result v5

    .line 346
    if-eqz v5, :cond_3

    .line 347
    .line 348
    invoke-virtual {v2}, Laq/a;->k()V

    .line 349
    .line 350
    .line 351
    goto :goto_f

    .line 352
    :cond_3
    :try_start_a
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 353
    .line 354
    .line 355
    move-result v5

    .line 356
    if-nez v5, :cond_4

    .line 357
    .line 358
    invoke-virtual {v0}, Leb/j0;->x()V

    .line 359
    .line 360
    .line 361
    const/4 v0, 0x1

    .line 362
    invoke-virtual {v4, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 363
    .line 364
    .line 365
    goto :goto_c

    .line 366
    :catch_3
    move-exception v0

    .line 367
    goto :goto_e

    .line 368
    :catch_4
    move-exception v0

    .line 369
    goto :goto_d

    .line 370
    :cond_4
    :goto_c
    invoke-virtual {v1}, Laq/t;->h()Z

    .line 371
    .line 372
    .line 373
    move-result v0

    .line 374
    if-eqz v0, :cond_5

    .line 375
    .line 376
    invoke-virtual {v2}, Laq/a;->k()V

    .line 377
    .line 378
    .line 379
    goto :goto_f

    .line 380
    :cond_5
    invoke-interface {v3}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v0
    :try_end_a
    .catch Ljava/lang/RuntimeException; {:try_start_a .. :try_end_a} :catch_4
    .catch Ljava/lang/Exception; {:try_start_a .. :try_end_a} :catch_3

    .line 384
    :try_start_b
    invoke-virtual {v1}, Laq/t;->h()Z

    .line 385
    .line 386
    .line 387
    move-result v3

    .line 388
    if-eqz v3, :cond_6

    .line 389
    .line 390
    invoke-virtual {v2}, Laq/a;->k()V

    .line 391
    .line 392
    .line 393
    goto :goto_f

    .line 394
    :cond_6
    invoke-virtual {p0, v0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 395
    .line 396
    .line 397
    goto :goto_f

    .line 398
    :goto_d
    new-instance v3, Lbv/a;

    .line 399
    .line 400
    const-string v4, "Internal error has occurred when executing ML Kit tasks"

    .line 401
    .line 402
    invoke-direct {v3, v4, v0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 403
    .line 404
    .line 405
    throw v3
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_3

    .line 406
    :goto_e
    invoke-virtual {v1}, Laq/t;->h()Z

    .line 407
    .line 408
    .line 409
    move-result v1

    .line 410
    if-eqz v1, :cond_7

    .line 411
    .line 412
    invoke-virtual {v2}, Laq/a;->k()V

    .line 413
    .line 414
    .line 415
    goto :goto_f

    .line 416
    :cond_7
    invoke-virtual {p0, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 417
    .line 418
    .line 419
    :goto_f
    return-void

    .line 420
    nop

    .line 421
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
