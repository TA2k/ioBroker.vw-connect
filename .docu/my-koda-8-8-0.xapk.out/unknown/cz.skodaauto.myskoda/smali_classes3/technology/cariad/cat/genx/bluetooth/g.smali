.class public final synthetic Ltechnology/cariad/cat/genx/bluetooth/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Ltechnology/cariad/cat/genx/bluetooth/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/g;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltechnology/cariad/cat/genx/bluetooth/g;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x4

    .line 9
    const-string v6, " - "

    .line 10
    .line 11
    const-string v7, "Network status: "

    .line 12
    .line 13
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    iget-object v9, v0, Ltechnology/cariad/cat/genx/bluetooth/g;->g:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v10, v0, Ltechnology/cariad/cat/genx/bluetooth/g;->f:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v0, v0, Ltechnology/cariad/cat/genx/bluetooth/g;->e:Ljava/lang/Object;

    .line 20
    .line 21
    packed-switch v1, :pswitch_data_0

    .line 22
    .line 23
    .line 24
    check-cast v0, Lqu/c;

    .line 25
    .line 26
    check-cast v10, Lay0/k;

    .line 27
    .line 28
    check-cast v9, Lay0/k;

    .line 29
    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance v1, Lnd0/c;

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v1, v2, v10}, Lnd0/c;-><init>(ILay0/k;)V

    .line 37
    .line 38
    .line 39
    iput-object v1, v0, Lqu/c;->n:Lnd0/c;

    .line 40
    .line 41
    iget-object v2, v0, Lqu/c;->h:Lsu/a;

    .line 42
    .line 43
    check-cast v2, Lsu/i;

    .line 44
    .line 45
    iput-object v1, v2, Lsu/i;->p:Lnd0/c;

    .line 46
    .line 47
    new-instance v1, Lnd0/c;

    .line 48
    .line 49
    invoke-direct {v1, v5, v9}, Lnd0/c;-><init>(ILay0/k;)V

    .line 50
    .line 51
    .line 52
    iput-object v1, v0, Lqu/c;->m:Lnd0/c;

    .line 53
    .line 54
    iput-object v1, v2, Lsu/i;->q:Lnd0/c;

    .line 55
    .line 56
    :goto_0
    return-object v8

    .line 57
    :pswitch_0
    check-cast v0, Luu/g;

    .line 58
    .line 59
    check-cast v10, Lxj0/f;

    .line 60
    .line 61
    check-cast v9, Ll2/b1;

    .line 62
    .line 63
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 64
    .line 65
    invoke-interface {v9, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    invoke-static {v10}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-static {v1}, Ljp/wf;->c(Lcom/google/android/gms/maps/model/LatLng;)Lpv/g;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    invoke-virtual {v0, v1}, Luu/g;->e(Lpv/g;)V

    .line 77
    .line 78
    .line 79
    return-object v8

    .line 80
    :pswitch_1
    check-cast v0, Ly70/k;

    .line 81
    .line 82
    check-cast v10, Lay0/a;

    .line 83
    .line 84
    check-cast v9, Lay0/a;

    .line 85
    .line 86
    iget-boolean v0, v0, Ly70/k;->d:Z

    .line 87
    .line 88
    if-eqz v0, :cond_1

    .line 89
    .line 90
    invoke-interface {v10}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_1
    invoke-interface {v9}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    :goto_1
    return-object v8

    .line 98
    :pswitch_2
    check-cast v0, Landroid/content/Context;

    .line 99
    .line 100
    check-cast v10, Ly70/d;

    .line 101
    .line 102
    check-cast v9, Lay0/k;

    .line 103
    .line 104
    invoke-static {v0}, Ljp/oa;->b(Landroid/content/Context;)Landroid/app/Activity;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    const-string v1, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity"

    .line 109
    .line 110
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    check-cast v0, Lh/i;

    .line 114
    .line 115
    invoke-static {v10, v0, v9}, Lz70/l;->f0(Ly70/d;Lh/i;Lay0/k;)V

    .line 116
    .line 117
    .line 118
    return-object v8

    .line 119
    :pswitch_3
    check-cast v0, Ly70/d;

    .line 120
    .line 121
    check-cast v10, Lh/i;

    .line 122
    .line 123
    check-cast v9, Lay0/k;

    .line 124
    .line 125
    invoke-static {v0, v10, v9}, Lz70/l;->f0(Ly70/d;Lh/i;Lay0/k;)V

    .line 126
    .line 127
    .line 128
    return-object v8

    .line 129
    :pswitch_4
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 130
    .line 131
    check-cast v10, Lt71/c;

    .line 132
    .line 133
    check-cast v9, Lay0/a;

    .line 134
    .line 135
    invoke-static {v0, v10, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Lay0/a;)Llx0/b0;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    return-object v0

    .line 140
    :pswitch_5
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 141
    .line 142
    check-cast v10, Lt71/c;

    .line 143
    .line 144
    check-cast v9, Ljava/lang/String;

    .line 145
    .line 146
    invoke-static {v0, v10, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/c;Ljava/lang/String;)Llx0/b0;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    return-object v0

    .line 151
    :pswitch_6
    check-cast v0, Ljava/lang/String;

    .line 152
    .line 153
    check-cast v10, Ljava/lang/String;

    .line 154
    .line 155
    check-cast v9, Ly51/e;

    .line 156
    .line 157
    const-string v1, " - status: "

    .line 158
    .line 159
    invoke-static {v7, v0, v6, v10, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    return-object v0

    .line 171
    :pswitch_7
    check-cast v0, Ljava/lang/String;

    .line 172
    .line 173
    check-cast v10, Ljava/lang/String;

    .line 174
    .line 175
    check-cast v9, [I

    .line 176
    .line 177
    const-string v1, "capabilities"

    .line 178
    .line 179
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    const/16 v1, 0xc

    .line 183
    .line 184
    invoke-static {v1, v9}, Lmx0/n;->d(I[I)Z

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    if-eqz v1, :cond_2

    .line 189
    .line 190
    const-string v1, "NET_CAPABILITY_INTERNET"

    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_2
    const/16 v1, 0x10

    .line 194
    .line 195
    invoke-static {v1, v9}, Lmx0/n;->d(I[I)Z

    .line 196
    .line 197
    .line 198
    move-result v1

    .line 199
    if-eqz v1, :cond_3

    .line 200
    .line 201
    const-string v1, "NET_CAPABILITY_VALIDATED"

    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_3
    const/16 v1, 0x11

    .line 205
    .line 206
    invoke-static {v1, v9}, Lmx0/n;->d(I[I)Z

    .line 207
    .line 208
    .line 209
    move-result v1

    .line 210
    if-eqz v1, :cond_4

    .line 211
    .line 212
    const-string v1, "NET_CAPABILITY_CAPTIVE_PORTAL"

    .line 213
    .line 214
    goto :goto_2

    .line 215
    :cond_4
    invoke-static {v5, v9}, Lmx0/n;->d(I[I)Z

    .line 216
    .line 217
    .line 218
    move-result v1

    .line 219
    if-eqz v1, :cond_5

    .line 220
    .line 221
    const-string v1, "TRANSPORT_VPN"

    .line 222
    .line 223
    goto :goto_2

    .line 224
    :cond_5
    const-string v1, "Unknown"

    .line 225
    .line 226
    :goto_2
    const-string v2, " - capability: "

    .line 227
    .line 228
    invoke-static {v7, v0, v6, v10, v2}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 233
    .line 234
    .line 235
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    return-object v0

    .line 240
    :pswitch_8
    check-cast v0, Ljava/lang/String;

    .line 241
    .line 242
    check-cast v10, Ljava/lang/String;

    .line 243
    .line 244
    check-cast v9, Landroid/net/ConnectivityManager;

    .line 245
    .line 246
    invoke-virtual {v9}, Landroid/net/ConnectivityManager;->getActiveNetwork()Landroid/net/Network;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    const-string v2, " - activeNetwork: "

    .line 251
    .line 252
    invoke-static {v7, v0, v6, v10, v2}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    return-object v0

    .line 264
    :pswitch_9
    check-cast v0, Ljava/lang/String;

    .line 265
    .line 266
    check-cast v10, Ljava/lang/String;

    .line 267
    .line 268
    check-cast v9, Landroid/net/Network;

    .line 269
    .line 270
    const-string v1, " - network: "

    .line 271
    .line 272
    invoke-static {v7, v0, v6, v10, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 277
    .line 278
    .line 279
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    return-object v0

    .line 284
    :pswitch_a
    check-cast v0, Lxy0/x;

    .line 285
    .line 286
    check-cast v10, Landroidx/lifecycle/r;

    .line 287
    .line 288
    check-cast v9, Landroidx/lifecycle/m;

    .line 289
    .line 290
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 291
    .line 292
    sget-object v1, Laz0/m;->a:Lwy0/c;

    .line 293
    .line 294
    iget-object v1, v1, Lwy0/c;->h:Lwy0/c;

    .line 295
    .line 296
    new-instance v5, Lxi/d;

    .line 297
    .line 298
    invoke-direct {v5, v10, v9, v4, v3}, Lxi/d;-><init>(Landroidx/lifecycle/r;Landroidx/lifecycle/m;Lkotlin/coroutines/Continuation;I)V

    .line 299
    .line 300
    .line 301
    invoke-static {v0, v1, v4, v5, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 302
    .line 303
    .line 304
    return-object v8

    .line 305
    :pswitch_b
    check-cast v0, Ll2/b1;

    .line 306
    .line 307
    check-cast v10, Ll2/b1;

    .line 308
    .line 309
    check-cast v9, Lle/a;

    .line 310
    .line 311
    sget-object v1, Lqe/a;->d:Lqe/a;

    .line 312
    .line 313
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    check-cast v0, Lqe/a;

    .line 321
    .line 322
    invoke-static {}, Ljp/kf;->b()Ljava/util/ArrayList;

    .line 323
    .line 324
    .line 325
    move-result-object v1

    .line 326
    const-string v2, "season"

    .line 327
    .line 328
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 329
    .line 330
    .line 331
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v3

    .line 335
    check-cast v3, Lqe/d;

    .line 336
    .line 337
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v4

    .line 341
    check-cast v4, Lqe/d;

    .line 342
    .line 343
    invoke-virtual {v4, v0}, Lqe/d;->b(Lqe/a;)Lqe/e;

    .line 344
    .line 345
    .line 346
    move-result-object v4

    .line 347
    iget-object v5, v4, Lqe/e;->a:Lqe/a;

    .line 348
    .line 349
    iget-object v4, v4, Lqe/e;->c:Ljava/util/Map;

    .line 350
    .line 351
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    const-string v2, "daySlot"

    .line 355
    .line 356
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 357
    .line 358
    .line 359
    new-instance v2, Lqe/e;

    .line 360
    .line 361
    invoke-direct {v2, v5, v1, v4}, Lqe/e;-><init>(Lqe/a;Ljava/util/List;Ljava/util/Map;)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 365
    .line 366
    .line 367
    iget-object v1, v3, Lqe/d;->c:Ljava/util/Map;

    .line 368
    .line 369
    invoke-interface {v1, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    invoke-virtual {v9}, Lle/a;->invoke()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    return-object v8

    .line 376
    :pswitch_c
    check-cast v0, Ljava/util/Set;

    .line 377
    .line 378
    check-cast v10, Ljava/util/ArrayList;

    .line 379
    .line 380
    check-cast v9, Ljava/lang/String;

    .line 381
    .line 382
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 383
    .line 384
    .line 385
    move-result v0

    .line 386
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 387
    .line 388
    .line 389
    move-result v1

    .line 390
    add-int/2addr v1, v0

    .line 391
    new-instance v0, Ljava/lang/StringBuilder;

    .line 392
    .line 393
    const-string v2, "migrate(): After migration "

    .line 394
    .line 395
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 396
    .line 397
    .line 398
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 399
    .line 400
    .line 401
    const-string v1, " pairings are stored in "

    .line 402
    .line 403
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 404
    .line 405
    .line 406
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 407
    .line 408
    .line 409
    const-string v1, "."

    .line 410
    .line 411
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 412
    .line 413
    .line 414
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    return-object v0

    .line 419
    :pswitch_d
    check-cast v0, Lul0/e;

    .line 420
    .line 421
    check-cast v10, Lz9/y;

    .line 422
    .line 423
    move-object v13, v9

    .line 424
    check-cast v13, Lvl0/b;

    .line 425
    .line 426
    instance-of v1, v0, Lul0/b;

    .line 427
    .line 428
    const/4 v6, 0x0

    .line 429
    if-eqz v1, :cond_6

    .line 430
    .line 431
    invoke-virtual {v10}, Lz9/y;->g()V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v13}, Lql0/j;->a()Lql0/h;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    check-cast v0, Lvl0/a;

    .line 439
    .line 440
    invoke-static {v0, v4, v6, v2}, Lvl0/a;->a(Lvl0/a;Lul0/e;ZI)Lvl0/a;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    invoke-virtual {v13, v0}, Lql0/j;->g(Lql0/h;)V

    .line 445
    .line 446
    .line 447
    goto/16 :goto_b

    .line 448
    .line 449
    :cond_6
    instance-of v1, v0, Lul0/d;

    .line 450
    .line 451
    if-eqz v1, :cond_9

    .line 452
    .line 453
    iget-object v1, v10, Lz9/y;->b:Lca/g;

    .line 454
    .line 455
    invoke-virtual {v1}, Lca/g;->h()Lz9/u;

    .line 456
    .line 457
    .line 458
    move-result-object v1

    .line 459
    if-eqz v1, :cond_7

    .line 460
    .line 461
    iget-object v1, v1, Lz9/u;->e:Lca/j;

    .line 462
    .line 463
    iget-object v1, v1, Lca/j;->e:Ljava/lang/Object;

    .line 464
    .line 465
    check-cast v1, Ljava/lang/String;

    .line 466
    .line 467
    goto :goto_3

    .line 468
    :cond_7
    move-object v1, v4

    .line 469
    :goto_3
    check-cast v0, Lul0/d;

    .line 470
    .line 471
    iget-object v3, v0, Lul0/d;->a:Lly/b;

    .line 472
    .line 473
    invoke-virtual {v3}, Lly/b;->invoke()Ljava/lang/String;

    .line 474
    .line 475
    .line 476
    move-result-object v5

    .line 477
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    move-result v1

    .line 481
    if-nez v1, :cond_8

    .line 482
    .line 483
    invoke-virtual {v3}, Lly/b;->invoke()Ljava/lang/String;

    .line 484
    .line 485
    .line 486
    move-result-object v1

    .line 487
    iget-boolean v0, v0, Lul0/d;->b:Z

    .line 488
    .line 489
    invoke-static {v10, v1, v0}, Lz9/y;->i(Lz9/y;Ljava/lang/String;Z)Z

    .line 490
    .line 491
    .line 492
    :cond_8
    invoke-virtual {v13}, Lql0/j;->a()Lql0/h;

    .line 493
    .line 494
    .line 495
    move-result-object v0

    .line 496
    check-cast v0, Lvl0/a;

    .line 497
    .line 498
    invoke-static {v0, v4, v6, v2}, Lvl0/a;->a(Lvl0/a;Lul0/e;ZI)Lvl0/a;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    invoke-virtual {v13, v0}, Lql0/j;->g(Lql0/h;)V

    .line 503
    .line 504
    .line 505
    goto/16 :goto_b

    .line 506
    .line 507
    :cond_9
    instance-of v1, v0, Lul0/c;

    .line 508
    .line 509
    if-eqz v1, :cond_11

    .line 510
    .line 511
    check-cast v0, Lul0/c;

    .line 512
    .line 513
    new-instance v11, Lw00/h;

    .line 514
    .line 515
    const/16 v17, 0x0

    .line 516
    .line 517
    const/16 v18, 0x7

    .line 518
    .line 519
    const/4 v12, 0x0

    .line 520
    const-class v14, Lvl0/b;

    .line 521
    .line 522
    const-string v15, "onNavigationEventConsumed"

    .line 523
    .line 524
    const-string v16, "onNavigationEventConsumed()V"

    .line 525
    .line 526
    invoke-direct/range {v11 .. v18}, Lw00/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 527
    .line 528
    .line 529
    iget-object v1, v10, Lz9/y;->b:Lca/g;

    .line 530
    .line 531
    invoke-virtual {v1}, Lca/g;->h()Lz9/u;

    .line 532
    .line 533
    .line 534
    move-result-object v1

    .line 535
    if-eqz v1, :cond_a

    .line 536
    .line 537
    iget-object v1, v1, Lz9/u;->e:Lca/j;

    .line 538
    .line 539
    iget-object v1, v1, Lca/j;->e:Ljava/lang/Object;

    .line 540
    .line 541
    check-cast v1, Ljava/lang/String;

    .line 542
    .line 543
    goto :goto_4

    .line 544
    :cond_a
    move-object v1, v4

    .line 545
    :goto_4
    iget-object v2, v0, Lul0/c;->a:Lul0/f;

    .line 546
    .line 547
    invoke-interface {v2}, Lul0/f;->invoke()Ljava/lang/String;

    .line 548
    .line 549
    .line 550
    move-result-object v7

    .line 551
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 552
    .line 553
    .line 554
    move-result v1

    .line 555
    if-nez v1, :cond_10

    .line 556
    .line 557
    iget-boolean v1, v0, Lul0/c;->b:Z

    .line 558
    .line 559
    if-eqz v1, :cond_d

    .line 560
    .line 561
    iget-object v1, v0, Lul0/c;->c:Lul0/f;

    .line 562
    .line 563
    if-eqz v1, :cond_b

    .line 564
    .line 565
    invoke-interface {v1}, Lul0/f;->invoke()Ljava/lang/String;

    .line 566
    .line 567
    .line 568
    move-result-object v1

    .line 569
    iget-boolean v7, v0, Lul0/c;->d:Z

    .line 570
    .line 571
    const/4 v9, -0x1

    .line 572
    move/from16 v18, v7

    .line 573
    .line 574
    move/from16 v17, v9

    .line 575
    .line 576
    goto :goto_5

    .line 577
    :cond_b
    move-object v1, v4

    .line 578
    move/from16 v17, v6

    .line 579
    .line 580
    move/from16 v18, v17

    .line 581
    .line 582
    :goto_5
    const/16 v16, 0x0

    .line 583
    .line 584
    const/4 v15, 0x0

    .line 585
    const/16 v20, -0x1

    .line 586
    .line 587
    if-eqz v1, :cond_c

    .line 588
    .line 589
    new-instance v14, Lz9/b0;

    .line 590
    .line 591
    sget v7, Lz9/u;->h:I

    .line 592
    .line 593
    const-string v7, "android-app://androidx.navigation/"

    .line 594
    .line 595
    invoke-virtual {v7, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 596
    .line 597
    .line 598
    move-result-object v7

    .line 599
    invoke-virtual {v7}, Ljava/lang/String;->hashCode()I

    .line 600
    .line 601
    .line 602
    move-result v17

    .line 603
    move/from16 v21, v20

    .line 604
    .line 605
    move/from16 v19, v6

    .line 606
    .line 607
    invoke-direct/range {v14 .. v21}, Lz9/b0;-><init>(ZZIZZII)V

    .line 608
    .line 609
    .line 610
    iput-object v1, v14, Lz9/b0;->h:Ljava/lang/String;

    .line 611
    .line 612
    :goto_6
    move/from16 v1, v19

    .line 613
    .line 614
    goto :goto_7

    .line 615
    :cond_c
    move/from16 v19, v6

    .line 616
    .line 617
    new-instance v14, Lz9/b0;

    .line 618
    .line 619
    move/from16 v21, v20

    .line 620
    .line 621
    invoke-direct/range {v14 .. v21}, Lz9/b0;-><init>(ZZIZZII)V

    .line 622
    .line 623
    .line 624
    goto :goto_6

    .line 625
    :cond_d
    move v1, v6

    .line 626
    move-object v14, v4

    .line 627
    :goto_7
    iget-object v6, v0, Lul0/c;->e:Ljava/util/List;

    .line 628
    .line 629
    if-eqz v6, :cond_e

    .line 630
    .line 631
    check-cast v6, Ljava/lang/Iterable;

    .line 632
    .line 633
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 634
    .line 635
    .line 636
    move-result-object v6

    .line 637
    :goto_8
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 638
    .line 639
    .line 640
    move-result v7

    .line 641
    if-eqz v7, :cond_e

    .line 642
    .line 643
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 644
    .line 645
    .line 646
    move-result-object v7

    .line 647
    check-cast v7, Lul0/f;

    .line 648
    .line 649
    invoke-interface {v7}, Lul0/f;->invoke()Ljava/lang/String;

    .line 650
    .line 651
    .line 652
    move-result-object v7

    .line 653
    invoke-static {v10, v7, v14, v5}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 654
    .line 655
    .line 656
    move-object v14, v4

    .line 657
    goto :goto_8

    .line 658
    :cond_e
    :try_start_0
    invoke-interface {v2}, Lul0/f;->invoke()Ljava/lang/String;

    .line 659
    .line 660
    .line 661
    move-result-object v4

    .line 662
    invoke-virtual {v10, v4}, Lz9/y;->b(Ljava/lang/String;)Lz9/k;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 663
    .line 664
    .line 665
    goto :goto_9

    .line 666
    :catch_0
    move v3, v1

    .line 667
    :goto_9
    iget-boolean v0, v0, Lul0/c;->f:Z

    .line 668
    .line 669
    if-eqz v0, :cond_f

    .line 670
    .line 671
    if-eqz v3, :cond_f

    .line 672
    .line 673
    invoke-interface {v2}, Lul0/f;->invoke()Ljava/lang/String;

    .line 674
    .line 675
    .line 676
    move-result-object v0

    .line 677
    invoke-static {v10, v0, v1}, Lz9/y;->i(Lz9/y;Ljava/lang/String;Z)Z

    .line 678
    .line 679
    .line 680
    goto :goto_a

    .line 681
    :cond_f
    invoke-interface {v2}, Lul0/f;->invoke()Ljava/lang/String;

    .line 682
    .line 683
    .line 684
    move-result-object v0

    .line 685
    invoke-static {v10, v0, v14, v5}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 686
    .line 687
    .line 688
    :goto_a
    invoke-virtual {v11}, Lw00/h;->invoke()Ljava/lang/Object;

    .line 689
    .line 690
    .line 691
    :cond_10
    :goto_b
    return-object v8

    .line 692
    :cond_11
    new-instance v0, La8/r0;

    .line 693
    .line 694
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 695
    .line 696
    .line 697
    throw v0

    .line 698
    :pswitch_e
    check-cast v0, Lay0/k;

    .line 699
    .line 700
    check-cast v10, Ll2/b1;

    .line 701
    .line 702
    check-cast v9, Lay0/a;

    .line 703
    .line 704
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 705
    .line 706
    .line 707
    move-result-object v1

    .line 708
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 709
    .line 710
    .line 711
    invoke-interface {v9}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    return-object v8

    .line 715
    :pswitch_f
    check-cast v0, Luu/x;

    .line 716
    .line 717
    check-cast v10, Lay0/n;

    .line 718
    .line 719
    new-instance v1, Luu/y;

    .line 720
    .line 721
    iget-object v0, v0, Luu/x;->h:Lqp/g;

    .line 722
    .line 723
    invoke-direct {v1, v0, v10, v9}, Luu/y;-><init>(Lqp/g;Lay0/n;Ljava/lang/Object;)V

    .line 724
    .line 725
    .line 726
    return-object v1

    .line 727
    :pswitch_10
    check-cast v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 728
    .line 729
    check-cast v10, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 730
    .line 731
    check-cast v9, Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 732
    .line 733
    invoke-static {v0, v10, v9}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->y(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Llx0/b0;

    .line 734
    .line 735
    .line 736
    move-result-object v0

    .line 737
    return-object v0

    .line 738
    :pswitch_11
    check-cast v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 739
    .line 740
    check-cast v10, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 741
    .line 742
    check-cast v9, Ltechnology/cariad/cat/genx/GenXError;

    .line 743
    .line 744
    invoke-static {v0, v10, v9}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->X(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/GenXError;)Llx0/b0;

    .line 745
    .line 746
    .line 747
    move-result-object v0

    .line 748
    return-object v0

    .line 749
    :pswitch_12
    check-cast v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 750
    .line 751
    check-cast v10, [B

    .line 752
    .line 753
    check-cast v9, [B

    .line 754
    .line 755
    invoke-static {v0, v10, v9}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->b(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;[B[B)I

    .line 756
    .line 757
    .line 758
    move-result v0

    .line 759
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 760
    .line 761
    .line 762
    move-result-object v0

    .line 763
    return-object v0

    .line 764
    :pswitch_13
    check-cast v0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 765
    .line 766
    check-cast v10, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 767
    .line 768
    check-cast v9, Ljava/util/UUID;

    .line 769
    .line 770
    invoke-static {v0, v10, v9}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->V(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)Ljava/lang/String;

    .line 771
    .line 772
    .line 773
    move-result-object v0

    .line 774
    return-object v0

    .line 775
    :pswitch_data_0
    .packed-switch 0x0
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
