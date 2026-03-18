.class public final synthetic Lvu/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lvu/d;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lvu/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lvu/d;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lvu/d;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    const/4 v4, 0x0

    .line 7
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    iget-object v6, p0, Lvu/d;->f:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object p0, p0, Lvu/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    check-cast p0, Lxg0/b;

    .line 17
    .line 18
    check-cast v6, Ljava/util/List;

    .line 19
    .line 20
    const-string v0, "data"

    .line 21
    .line 22
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    new-instance v2, Lwp0/c;

    .line 30
    .line 31
    const/4 v3, 0x5

    .line 32
    invoke-direct {v2, v3, p0, v6, v4}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    invoke-static {v0, v4, v4, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 36
    .line 37
    .line 38
    return-object v5

    .line 39
    :pswitch_0
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 40
    .line 41
    check-cast v6, Lt71/f;

    .line 42
    .line 43
    invoke-static {p0, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lt71/f;)Llx0/b0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 49
    .line 50
    check-cast v6, Lk71/c;

    .line 51
    .line 52
    invoke-static {p0, v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;Lk71/c;)Llx0/b0;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p0, Ly70/u1;

    .line 58
    .line 59
    check-cast v6, Ljava/lang/String;

    .line 60
    .line 61
    new-instance v0, Llj0/b;

    .line 62
    .line 63
    iget-object p0, p0, Ly70/u1;->z:Lij0/a;

    .line 64
    .line 65
    const v1, 0x7f1211c8

    .line 66
    .line 67
    .line 68
    check-cast p0, Ljj0/f;

    .line 69
    .line 70
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-direct {v0, p0, v6}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    return-object v0

    .line 78
    :pswitch_3
    check-cast p0, Lcq0/n;

    .line 79
    .line 80
    check-cast v6, Lcq0/m;

    .line 81
    .line 82
    new-instance v0, Lx20/c;

    .line 83
    .line 84
    iget-object p0, p0, Lcq0/n;->a:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v1, v6, Lcq0/m;->a:Lcq0/e;

    .line 87
    .line 88
    if-eqz v1, :cond_0

    .line 89
    .line 90
    iget-object v1, v1, Lcq0/e;->d:Lqr0/d;

    .line 91
    .line 92
    if-eqz v1, :cond_0

    .line 93
    .line 94
    iget-wide v1, v1, Lqr0/d;->a:D

    .line 95
    .line 96
    const-wide v3, 0x408f400000000000L    # 1000.0

    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    div-double/2addr v1, v3

    .line 102
    double-to-int v3, v1

    .line 103
    :cond_0
    invoke-direct {v0, p0, v3}, Lx20/c;-><init>(Ljava/lang/String;I)V

    .line 104
    .line 105
    .line 106
    return-object v0

    .line 107
    :pswitch_4
    check-cast p0, Landroid/net/ConnectivityManager;

    .line 108
    .line 109
    check-cast v6, Ly51/a;

    .line 110
    .line 111
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 112
    .line 113
    new-instance v1, Lxf/b;

    .line 114
    .line 115
    const/16 v2, 0x12

    .line 116
    .line 117
    invoke-direct {v1, v2}, Lxf/b;-><init>(I)V

    .line 118
    .line 119
    .line 120
    const/4 v2, 0x7

    .line 121
    invoke-static {v0, v4, v1, v2}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0, v6}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 125
    .line 126
    .line 127
    return-object v5

    .line 128
    :pswitch_5
    check-cast p0, Landroid/content/Context;

    .line 129
    .line 130
    check-cast v6, Landroid/view/textclassifier/TextClassification;

    .line 131
    .line 132
    invoke-virtual {v6}, Landroid/view/textclassifier/TextClassification;->getText()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    if-eqz v0, :cond_1

    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 139
    .line 140
    .line 141
    move-result v3

    .line 142
    :cond_1
    invoke-virtual {v6}, Landroid/view/textclassifier/TextClassification;->getIntent()Landroid/content/Intent;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    const/high16 v1, 0xc000000

    .line 147
    .line 148
    invoke-static {p0, v3, v0, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 153
    .line 154
    const/16 v1, 0x22

    .line 155
    .line 156
    if-lt v0, v1, :cond_2

    .line 157
    .line 158
    :try_start_0
    invoke-static {}, Landroid/app/ActivityOptions;->makeBasic()Landroid/app/ActivityOptions;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    invoke-static {v0}, Lt51/b;->b(Landroid/app/ActivityOptions;)Landroid/app/ActivityOptions;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    invoke-virtual {v0}, Landroid/app/ActivityOptions;->toBundle()Landroid/os/Bundle;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    invoke-static {p0, v0}, Lt51/b;->p(Landroid/app/PendingIntent;Landroid/os/Bundle;)V
    :try_end_0
    .catch Landroid/app/PendingIntent$CanceledException; {:try_start_0 .. :try_end_0} :catch_0

    .line 171
    .line 172
    .line 173
    goto :goto_0

    .line 174
    :catch_0
    move-exception v0

    .line 175
    new-instance v1, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    const-string v2, "error sending pendingIntent: "

    .line 178
    .line 179
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    const-string p0, " error: "

    .line 186
    .line 187
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 188
    .line 189
    .line 190
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    const-string v0, "TextClassification"

    .line 198
    .line 199
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 200
    .line 201
    .line 202
    goto :goto_0

    .line 203
    :cond_2
    invoke-virtual {p0}, Landroid/app/PendingIntent;->send()V

    .line 204
    .line 205
    .line 206
    :goto_0
    return-object v5

    .line 207
    :pswitch_6
    check-cast p0, Lw1/d;

    .line 208
    .line 209
    check-cast v6, Lw1/g;

    .line 210
    .line 211
    iget-object p0, p0, Lw1/d;->d:Lay0/k;

    .line 212
    .line 213
    invoke-interface {p0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    return-object v5

    .line 217
    :pswitch_7
    check-cast p0, La2/k;

    .line 218
    .line 219
    check-cast v6, Lay0/a;

    .line 220
    .line 221
    invoke-interface {v6}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    check-cast v0, Lt3/y;

    .line 226
    .line 227
    invoke-interface {p0, v0}, La2/k;->B0(Lt3/y;)J

    .line 228
    .line 229
    .line 230
    move-result-wide v0

    .line 231
    invoke-static {v0, v1}, Lkp/d9;->b(J)J

    .line 232
    .line 233
    .line 234
    move-result-wide v0

    .line 235
    new-instance p0, Lt4/j;

    .line 236
    .line 237
    invoke-direct {p0, v0, v1}, Lt4/j;-><init>(J)V

    .line 238
    .line 239
    .line 240
    return-object p0

    .line 241
    :pswitch_8
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 242
    .line 243
    check-cast v6, Lay0/a;

    .line 244
    .line 245
    invoke-interface {v6}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    iput-object v0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 250
    .line 251
    return-object v5

    .line 252
    :pswitch_9
    check-cast p0, Lay0/k;

    .line 253
    .line 254
    check-cast v6, Lwk0/g0;

    .line 255
    .line 256
    iget-object v0, v6, Lwk0/g0;->c:Lqp0/b0;

    .line 257
    .line 258
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    return-object v5

    .line 262
    :pswitch_a
    check-cast p0, Lay0/k;

    .line 263
    .line 264
    check-cast v6, Lwk0/u2;

    .line 265
    .line 266
    iget-object v0, v6, Lwk0/u2;->b:Ljava/lang/String;

    .line 267
    .line 268
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    return-object v5

    .line 272
    :pswitch_b
    check-cast p0, Lay0/k;

    .line 273
    .line 274
    check-cast v6, Lwk0/c;

    .line 275
    .line 276
    iget-object v0, v6, Lwk0/c;->d:Ljava/lang/String;

    .line 277
    .line 278
    new-instance v1, Lto0/h;

    .line 279
    .line 280
    invoke-direct {v1, v0}, Lto0/h;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    return-object v5

    .line 287
    :pswitch_c
    check-cast p0, Lay0/k;

    .line 288
    .line 289
    check-cast v6, Lwk0/g;

    .line 290
    .line 291
    iget-object v0, v6, Lwk0/g;->f:Ljava/lang/String;

    .line 292
    .line 293
    new-instance v1, Lto0/h;

    .line 294
    .line 295
    invoke-direct {v1, v0}, Lto0/h;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    return-object v5

    .line 302
    :pswitch_d
    check-cast p0, Lvy0/b0;

    .line 303
    .line 304
    check-cast v6, Lay0/k;

    .line 305
    .line 306
    new-instance v0, Lmy/r;

    .line 307
    .line 308
    invoke-direct {v0, v6, v4, v2}, Lmy/r;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 309
    .line 310
    .line 311
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 312
    .line 313
    .line 314
    return-object v5

    .line 315
    :pswitch_e
    check-cast p0, Ll2/b1;

    .line 316
    .line 317
    check-cast v6, Lle/a;

    .line 318
    .line 319
    invoke-static {}, Ljp/kf;->a()Ljava/util/ArrayList;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v6}, Lle/a;->invoke()Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    return-object v5

    .line 330
    :pswitch_f
    check-cast p0, Ll2/b1;

    .line 331
    .line 332
    check-cast v6, Lle/a;

    .line 333
    .line 334
    sget-object v0, Lqe/a;->f:Lqe/a;

    .line 335
    .line 336
    invoke-interface {p0, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v6}, Lle/a;->invoke()Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    return-object v5

    .line 343
    :pswitch_10
    check-cast p0, Lay0/k;

    .line 344
    .line 345
    check-cast v6, Lw80/f;

    .line 346
    .line 347
    iget-object v0, v6, Lw80/f;->e:Ler0/c;

    .line 348
    .line 349
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    return-object v5

    .line 353
    :pswitch_11
    check-cast p0, Lay0/k;

    .line 354
    .line 355
    check-cast v6, Ler0/f;

    .line 356
    .line 357
    invoke-interface {p0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    return-object v5

    .line 361
    :pswitch_12
    check-cast p0, Ljava/util/Set;

    .line 362
    .line 363
    move-object v0, v6

    .line 364
    check-cast v0, Ljava/util/ArrayList;

    .line 365
    .line 366
    move-object v1, p0

    .line 367
    check-cast v1, Ljava/lang/Iterable;

    .line 368
    .line 369
    const/4 v5, 0x0

    .line 370
    const/16 v6, 0x3f

    .line 371
    .line 372
    const/4 v2, 0x0

    .line 373
    const/4 v3, 0x0

    .line 374
    const/4 v4, 0x0

    .line 375
    invoke-static/range {v1 .. v6}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object p0

    .line 379
    const/16 v5, 0x3f

    .line 380
    .line 381
    const/4 v1, 0x0

    .line 382
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object v0

    .line 386
    const-string v1, "migrate(): Mapped "

    .line 387
    .line 388
    const-string v2, " to "

    .line 389
    .line 390
    invoke-static {v1, p0, v2, v0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 391
    .line 392
    .line 393
    move-result-object p0

    .line 394
    return-object p0

    .line 395
    :pswitch_13
    check-cast p0, Ljava/lang/String;

    .line 396
    .line 397
    check-cast v6, Ltechnology/cariad/cat/genx/Antenna;

    .line 398
    .line 399
    new-instance v0, Ljava/lang/StringBuilder;

    .line 400
    .line 401
    const-string v1, "removeQRCodePairing(): vin = "

    .line 402
    .line 403
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 407
    .line 408
    .line 409
    const-string p0, ", antenna = "

    .line 410
    .line 411
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 412
    .line 413
    .line 414
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 415
    .line 416
    .line 417
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object p0

    .line 421
    return-object p0

    .line 422
    :pswitch_14
    check-cast p0, Ljava/util/Set;

    .line 423
    .line 424
    check-cast v6, Ljava/util/Set;

    .line 425
    .line 426
    move-object v0, p0

    .line 427
    check-cast v0, Ljava/lang/Iterable;

    .line 428
    .line 429
    const/4 v4, 0x0

    .line 430
    const/16 v5, 0x3f

    .line 431
    .line 432
    const/4 v1, 0x0

    .line 433
    const/4 v2, 0x0

    .line 434
    const/4 v3, 0x0

    .line 435
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 436
    .line 437
    .line 438
    move-result-object p0

    .line 439
    move-object v0, v6

    .line 440
    check-cast v0, Ljava/lang/Iterable;

    .line 441
    .line 442
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 443
    .line 444
    .line 445
    move-result-object v0

    .line 446
    const-string v1, " and "

    .line 447
    .line 448
    const-string v2, " to VehicleInformation"

    .line 449
    .line 450
    const-string v3, "updateRegisteredPairings(): Merge "

    .line 451
    .line 452
    invoke-static {v3, p0, v1, v0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 453
    .line 454
    .line 455
    move-result-object p0

    .line 456
    return-object p0

    .line 457
    :pswitch_15
    check-cast p0, Lay0/k;

    .line 458
    .line 459
    check-cast v6, Lon0/u;

    .line 460
    .line 461
    invoke-interface {p0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 462
    .line 463
    .line 464
    return-object v5

    .line 465
    :pswitch_16
    check-cast p0, Lay0/k;

    .line 466
    .line 467
    check-cast v6, Ljn/a;

    .line 468
    .line 469
    sget v0, Lmy0/c;->g:I

    .line 470
    .line 471
    iget v0, v6, Ljn/a;->a:I

    .line 472
    .line 473
    sget-object v1, Lmy0/e;->j:Lmy0/e;

    .line 474
    .line 475
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 476
    .line 477
    .line 478
    move-result-wide v0

    .line 479
    iget v2, v6, Ljn/a;->b:I

    .line 480
    .line 481
    sget-object v3, Lmy0/e;->i:Lmy0/e;

    .line 482
    .line 483
    invoke-static {v2, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 484
    .line 485
    .line 486
    move-result-wide v2

    .line 487
    invoke-static {v0, v1, v2, v3}, Lmy0/c;->k(JJ)J

    .line 488
    .line 489
    .line 490
    move-result-wide v0

    .line 491
    new-instance v2, Lmy0/c;

    .line 492
    .line 493
    invoke-direct {v2, v0, v1}, Lmy0/c;-><init>(J)V

    .line 494
    .line 495
    .line 496
    invoke-interface {p0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    return-object v5

    .line 500
    :pswitch_17
    check-cast p0, Lsz0/g;

    .line 501
    .line 502
    check-cast v6, Lvz0/d;

    .line 503
    .line 504
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 505
    .line 506
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 507
    .line 508
    .line 509
    iget-object v1, v6, Lvz0/d;->a:Lvz0/k;

    .line 510
    .line 511
    invoke-static {p0, v6}, Lwz0/p;->o(Lsz0/g;Lvz0/d;)V

    .line 512
    .line 513
    .line 514
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 515
    .line 516
    .line 517
    move-result v1

    .line 518
    move v2, v3

    .line 519
    :goto_1
    if-ge v2, v1, :cond_8

    .line 520
    .line 521
    invoke-interface {p0, v2}, Lsz0/g;->f(I)Ljava/util/List;

    .line 522
    .line 523
    .line 524
    move-result-object v4

    .line 525
    check-cast v4, Ljava/lang/Iterable;

    .line 526
    .line 527
    new-instance v5, Ljava/util/ArrayList;

    .line 528
    .line 529
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 530
    .line 531
    .line 532
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 533
    .line 534
    .line 535
    move-result-object v4

    .line 536
    :cond_3
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 537
    .line 538
    .line 539
    move-result v6

    .line 540
    if-eqz v6, :cond_4

    .line 541
    .line 542
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    move-result-object v6

    .line 546
    instance-of v7, v6, Lvz0/w;

    .line 547
    .line 548
    if-eqz v7, :cond_3

    .line 549
    .line 550
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 551
    .line 552
    .line 553
    goto :goto_2

    .line 554
    :cond_4
    invoke-static {v5}, Lmx0/q;->k0(Ljava/util/List;)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    move-result-object v4

    .line 558
    check-cast v4, Lvz0/w;

    .line 559
    .line 560
    if-eqz v4, :cond_7

    .line 561
    .line 562
    invoke-interface {v4}, Lvz0/w;->names()[Ljava/lang/String;

    .line 563
    .line 564
    .line 565
    move-result-object v4

    .line 566
    if-eqz v4, :cond_7

    .line 567
    .line 568
    array-length v5, v4

    .line 569
    move v6, v3

    .line 570
    :goto_3
    if-ge v6, v5, :cond_7

    .line 571
    .line 572
    aget-object v7, v4, v6

    .line 573
    .line 574
    invoke-interface {p0}, Lsz0/g;->getKind()Lkp/y8;

    .line 575
    .line 576
    .line 577
    move-result-object v8

    .line 578
    sget-object v9, Lsz0/j;->b:Lsz0/j;

    .line 579
    .line 580
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 581
    .line 582
    .line 583
    move-result v8

    .line 584
    if-eqz v8, :cond_5

    .line 585
    .line 586
    const-string v8, "enum value"

    .line 587
    .line 588
    goto :goto_4

    .line 589
    :cond_5
    const-string v8, "property"

    .line 590
    .line 591
    :goto_4
    invoke-interface {v0, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 592
    .line 593
    .line 594
    move-result v9

    .line 595
    if-nez v9, :cond_6

    .line 596
    .line 597
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 598
    .line 599
    .line 600
    move-result-object v8

    .line 601
    invoke-interface {v0, v7, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 602
    .line 603
    .line 604
    add-int/lit8 v6, v6, 0x1

    .line 605
    .line 606
    goto :goto_3

    .line 607
    :cond_6
    new-instance v1, Lqz0/k;

    .line 608
    .line 609
    new-instance v3, Ljava/lang/StringBuilder;

    .line 610
    .line 611
    const-string v4, "The suggested name \'"

    .line 612
    .line 613
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 617
    .line 618
    .line 619
    const-string v4, "\' for "

    .line 620
    .line 621
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 622
    .line 623
    .line 624
    invoke-virtual {v3, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 625
    .line 626
    .line 627
    const/16 v4, 0x20

    .line 628
    .line 629
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 630
    .line 631
    .line 632
    invoke-interface {p0, v2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 633
    .line 634
    .line 635
    move-result-object v2

    .line 636
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 637
    .line 638
    .line 639
    const-string v2, " is already one of the names for "

    .line 640
    .line 641
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 642
    .line 643
    .line 644
    invoke-virtual {v3, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 645
    .line 646
    .line 647
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 648
    .line 649
    .line 650
    invoke-static {v0, v7}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 651
    .line 652
    .line 653
    move-result-object v0

    .line 654
    check-cast v0, Ljava/lang/Number;

    .line 655
    .line 656
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 657
    .line 658
    .line 659
    move-result v0

    .line 660
    invoke-interface {p0, v0}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 661
    .line 662
    .line 663
    move-result-object v0

    .line 664
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 665
    .line 666
    .line 667
    const-string v0, " in "

    .line 668
    .line 669
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 670
    .line 671
    .line 672
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 673
    .line 674
    .line 675
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 676
    .line 677
    .line 678
    move-result-object p0

    .line 679
    const-string v0, "message"

    .line 680
    .line 681
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 682
    .line 683
    .line 684
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 685
    .line 686
    .line 687
    throw v1

    .line 688
    :cond_7
    add-int/lit8 v2, v2, 0x1

    .line 689
    .line 690
    goto/16 :goto_1

    .line 691
    .line 692
    :cond_8
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 693
    .line 694
    .line 695
    move-result p0

    .line 696
    if-eqz p0, :cond_9

    .line 697
    .line 698
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 699
    .line 700
    :cond_9
    return-object v0

    .line 701
    :pswitch_18
    check-cast p0, Lw2/b;

    .line 702
    .line 703
    iget-object p0, p0, Lw2/b;->d:Ll2/t;

    .line 704
    .line 705
    iget-object v0, p0, Ll2/t;->c:Ll2/f2;

    .line 706
    .line 707
    iget-boolean v1, p0, Ll2/t;->C:Z

    .line 708
    .line 709
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 710
    .line 711
    if-nez v1, :cond_a

    .line 712
    .line 713
    goto/16 :goto_f

    .line 714
    .line 715
    :cond_a
    invoke-virtual {v0}, Ll2/f2;->g()Ll2/e2;

    .line 716
    .line 717
    .line 718
    move-result-object v1

    .line 719
    move v5, v3

    .line 720
    :goto_5
    :try_start_1
    iget v7, v0, Ll2/f2;->e:I

    .line 721
    .line 722
    if-ge v5, v7, :cond_14

    .line 723
    .line 724
    invoke-virtual {v1, v5}, Ll2/e2;->l(I)Z

    .line 725
    .line 726
    .line 727
    move-result v7

    .line 728
    if-eqz v7, :cond_e

    .line 729
    .line 730
    invoke-virtual {v1, v5}, Ll2/e2;->n(I)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v7

    .line 734
    if-eq v7, v6, :cond_d

    .line 735
    .line 736
    instance-of v8, v7, Ll2/a2;

    .line 737
    .line 738
    if-eqz v8, :cond_b

    .line 739
    .line 740
    check-cast v7, Ll2/a2;

    .line 741
    .line 742
    goto :goto_6

    .line 743
    :cond_b
    move-object v7, v4

    .line 744
    :goto_6
    if-eqz v7, :cond_c

    .line 745
    .line 746
    iget-object v7, v7, Ll2/a2;->a:Ll2/z1;

    .line 747
    .line 748
    goto :goto_7

    .line 749
    :cond_c
    move-object v7, v4

    .line 750
    :goto_7
    if-ne v7, v6, :cond_e

    .line 751
    .line 752
    :cond_d
    new-instance v3, Lw2/g;

    .line 753
    .line 754
    invoke-direct {v3, v5, v4}, Lw2/g;-><init>(ILjava/lang/Integer;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 755
    .line 756
    .line 757
    invoke-virtual {v1}, Ll2/e2;->c()V

    .line 758
    .line 759
    .line 760
    move-object v4, v3

    .line 761
    goto :goto_d

    .line 762
    :catchall_0
    move-exception v0

    .line 763
    move-object p0, v0

    .line 764
    goto/16 :goto_10

    .line 765
    .line 766
    :cond_e
    :try_start_2
    iget-object v7, v1, Ll2/e2;->b:[I

    .line 767
    .line 768
    invoke-static {v5, v7}, Ll2/h2;->c(I[I)I

    .line 769
    .line 770
    .line 771
    move-result v8

    .line 772
    add-int/lit8 v9, v5, 0x1

    .line 773
    .line 774
    iget v10, v1, Ll2/e2;->c:I

    .line 775
    .line 776
    if-ge v9, v10, :cond_f

    .line 777
    .line 778
    mul-int/lit8 v10, v9, 0x5

    .line 779
    .line 780
    add-int/lit8 v10, v10, 0x4

    .line 781
    .line 782
    aget v7, v7, v10

    .line 783
    .line 784
    goto :goto_8

    .line 785
    :cond_f
    iget v7, v1, Ll2/e2;->e:I

    .line 786
    .line 787
    :goto_8
    sub-int/2addr v7, v8

    .line 788
    move v8, v3

    .line 789
    :goto_9
    if-ge v8, v7, :cond_15

    .line 790
    .line 791
    invoke-virtual {v1, v5, v8}, Ll2/e2;->h(II)Ljava/lang/Object;

    .line 792
    .line 793
    .line 794
    move-result-object v10

    .line 795
    if-eq v10, v6, :cond_13

    .line 796
    .line 797
    instance-of v11, v10, Ll2/a2;

    .line 798
    .line 799
    if-eqz v11, :cond_10

    .line 800
    .line 801
    check-cast v10, Ll2/a2;

    .line 802
    .line 803
    goto :goto_a

    .line 804
    :cond_10
    move-object v10, v4

    .line 805
    :goto_a
    if-eqz v10, :cond_11

    .line 806
    .line 807
    iget-object v10, v10, Ll2/a2;->a:Ll2/z1;

    .line 808
    .line 809
    goto :goto_b

    .line 810
    :cond_11
    move-object v10, v4

    .line 811
    :goto_b
    if-ne v10, v6, :cond_12

    .line 812
    .line 813
    goto :goto_c

    .line 814
    :cond_12
    add-int/lit8 v8, v8, 0x1

    .line 815
    .line 816
    goto :goto_9

    .line 817
    :cond_13
    :goto_c
    new-instance v4, Lw2/g;

    .line 818
    .line 819
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 820
    .line 821
    .line 822
    move-result-object v3

    .line 823
    invoke-direct {v4, v5, v3}, Lw2/g;-><init>(ILjava/lang/Integer;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 824
    .line 825
    .line 826
    :cond_14
    invoke-virtual {v1}, Ll2/e2;->c()V

    .line 827
    .line 828
    .line 829
    goto :goto_d

    .line 830
    :cond_15
    move v5, v9

    .line 831
    goto :goto_5

    .line 832
    :goto_d
    if-eqz v4, :cond_17

    .line 833
    .line 834
    iget v1, v4, Lw2/g;->a:I

    .line 835
    .line 836
    iget-object v3, v4, Lw2/g;->b:Ljava/lang/Integer;

    .line 837
    .line 838
    iget-boolean v4, p0, Ll2/t;->C:Z

    .line 839
    .line 840
    if-nez v4, :cond_16

    .line 841
    .line 842
    goto :goto_e

    .line 843
    :cond_16
    invoke-virtual {v0}, Ll2/f2;->g()Ll2/e2;

    .line 844
    .line 845
    .line 846
    move-result-object v2

    .line 847
    :try_start_3
    invoke-static {v2, v1, v3}, Llp/sc;->e(Ll2/e2;ILjava/lang/Integer;)Ljava/util/ArrayList;

    .line 848
    .line 849
    .line 850
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 851
    invoke-virtual {v2}, Ll2/e2;->c()V

    .line 852
    .line 853
    .line 854
    move-object v2, v0

    .line 855
    :goto_e
    check-cast v2, Ljava/util/Collection;

    .line 856
    .line 857
    invoke-virtual {p0}, Ll2/t;->E()Ljava/util/List;

    .line 858
    .line 859
    .line 860
    move-result-object p0

    .line 861
    check-cast p0, Ljava/lang/Iterable;

    .line 862
    .line 863
    invoke-static {p0, v2}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 864
    .line 865
    .line 866
    move-result-object v2

    .line 867
    goto :goto_f

    .line 868
    :catchall_1
    move-exception v0

    .line 869
    move-object p0, v0

    .line 870
    invoke-virtual {v2}, Ll2/e2;->c()V

    .line 871
    .line 872
    .line 873
    throw p0

    .line 874
    :cond_17
    :goto_f
    return-object v2

    .line 875
    :goto_10
    invoke-virtual {v1}, Ll2/e2;->c()V

    .line 876
    .line 877
    .line 878
    throw p0

    .line 879
    :pswitch_19
    check-cast p0, Lay0/k;

    .line 880
    .line 881
    check-cast v6, Lmh0/b;

    .line 882
    .line 883
    invoke-interface {p0, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 884
    .line 885
    .line 886
    return-object v5

    .line 887
    :pswitch_1a
    check-cast p0, Lvy/v;

    .line 888
    .line 889
    check-cast v6, Lcn0/c;

    .line 890
    .line 891
    iget-object v0, v6, Lcn0/c;->e:Lcn0/a;

    .line 892
    .line 893
    sget-object v1, Lcn0/a;->v:Lcn0/a;

    .line 894
    .line 895
    if-ne v0, v1, :cond_18

    .line 896
    .line 897
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 898
    .line 899
    .line 900
    move-result-object v0

    .line 901
    move-object v6, v0

    .line 902
    check-cast v6, Lvy/p;

    .line 903
    .line 904
    iget-object v0, p0, Lvy/v;->h:Lij0/a;

    .line 905
    .line 906
    const-string v1, "<this>"

    .line 907
    .line 908
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 909
    .line 910
    .line 911
    const-string v1, "stringResource"

    .line 912
    .line 913
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 914
    .line 915
    .line 916
    invoke-static {v0}, Ljp/za;->d(Lij0/a;)Lbo0/l;

    .line 917
    .line 918
    .line 919
    move-result-object v10

    .line 920
    const/4 v12, 0x0

    .line 921
    const/16 v13, 0x1bf

    .line 922
    .line 923
    const/4 v7, 0x0

    .line 924
    const/4 v8, 0x0

    .line 925
    const/4 v9, 0x0

    .line 926
    const/4 v11, 0x0

    .line 927
    invoke-static/range {v6 .. v13}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 928
    .line 929
    .line 930
    move-result-object v0

    .line 931
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 932
    .line 933
    .line 934
    :cond_18
    return-object v5

    .line 935
    :pswitch_1b
    check-cast p0, Lkotlin/jvm/internal/b0;

    .line 936
    .line 937
    check-cast v6, Lxy0/x;

    .line 938
    .line 939
    iget-boolean v0, p0, Lkotlin/jvm/internal/b0;->d:Z

    .line 940
    .line 941
    if-nez v0, :cond_19

    .line 942
    .line 943
    new-instance v0, Lvu/j;

    .line 944
    .line 945
    invoke-direct {v0, v3, v6, p0, v4}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 946
    .line 947
    .line 948
    invoke-static {v6, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 949
    .line 950
    .line 951
    iput-boolean v2, p0, Lkotlin/jvm/internal/b0;->d:Z

    .line 952
    .line 953
    :cond_19
    return-object v5

    .line 954
    :pswitch_1c
    check-cast p0, Lvy0/x1;

    .line 955
    .line 956
    check-cast v6, Luu/p0;

    .line 957
    .line 958
    invoke-virtual {p0, v4}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 959
    .line 960
    .line 961
    iget-object p0, v6, Luu/p0;->d:Luu/m1;

    .line 962
    .line 963
    iget-object v0, v6, Luu/p0;->e:Lw3/a;

    .line 964
    .line 965
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 966
    .line 967
    .line 968
    return-object v5

    .line 969
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
