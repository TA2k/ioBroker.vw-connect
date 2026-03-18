.class public final synthetic Laa/k;
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
    iput p1, p0, Laa/k;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Laa/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Laa/k;->f:Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Laa/k;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    iget-object v3, p0, Laa/k;->f:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p0, p0, Laa/k;->e:Ljava/lang/Object;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    check-cast p0, Lay0/k;

    .line 14
    .line 15
    check-cast v3, Lc90/s;

    .line 16
    .line 17
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    return-object v2

    .line 21
    :pswitch_0
    check-cast p0, Lay0/k;

    .line 22
    .line 23
    check-cast v3, Lb90/k;

    .line 24
    .line 25
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    return-object v2

    .line 29
    :pswitch_1
    check-cast p0, Ld71/c;

    .line 30
    .line 31
    check-cast v3, Ld71/a;

    .line 32
    .line 33
    iget-object p0, p0, Ld71/c;->b:Ll2/j1;

    .line 34
    .line 35
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_0

    .line 44
    .line 45
    invoke-virtual {p0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    :cond_0
    return-object v2

    .line 49
    :pswitch_2
    check-cast v3, Llx0/o;

    .line 50
    .line 51
    invoke-static {p0}, Llx0/o;->b(Ljava/lang/Object;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    iget-object v0, v3, Llx0/o;->d:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-static {v0}, Llx0/o;->b(Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    const-string v1, ", but still had uncleared result "

    .line 62
    .line 63
    const-string v2, ". Overwriting!"

    .line 64
    .line 65
    const-string v3, "Received "

    .line 66
    .line 67
    invoke-static {v3, p0, v1, v0, v2}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_3
    check-cast p0, Lay0/k;

    .line 73
    .line 74
    check-cast v3, Lc00/m1;

    .line 75
    .line 76
    iget-wide v0, v3, Lc00/m1;->a:J

    .line 77
    .line 78
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    return-object v2

    .line 86
    :pswitch_4
    check-cast p0, Lay0/k;

    .line 87
    .line 88
    check-cast v3, Lbz/i;

    .line 89
    .line 90
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    return-object v2

    .line 94
    :pswitch_5
    check-cast p0, Lay0/k;

    .line 95
    .line 96
    check-cast v3, Lbz/k;

    .line 97
    .line 98
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    return-object v2

    .line 102
    :pswitch_6
    check-cast p0, Lay0/k;

    .line 103
    .line 104
    check-cast v3, Laz/a;

    .line 105
    .line 106
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    return-object v2

    .line 110
    :pswitch_7
    check-cast p0, Lay0/k;

    .line 111
    .line 112
    check-cast v3, Lbo0/q;

    .line 113
    .line 114
    iget-boolean v0, v3, Lbo0/q;->e:Z

    .line 115
    .line 116
    xor-int/lit8 v0, v0, 0x1

    .line 117
    .line 118
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    return-object v2

    .line 126
    :pswitch_8
    check-cast p0, Lay0/k;

    .line 127
    .line 128
    check-cast v3, Ljava/time/DayOfWeek;

    .line 129
    .line 130
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    return-object v2

    .line 134
    :pswitch_9
    check-cast p0, Lay0/k;

    .line 135
    .line 136
    check-cast v3, Lbo0/h;

    .line 137
    .line 138
    iget-wide v0, v3, Lbo0/h;->a:J

    .line 139
    .line 140
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    return-object v2

    .line 148
    :pswitch_a
    check-cast p0, Lay0/k;

    .line 149
    .line 150
    check-cast v3, Ltd/e;

    .line 151
    .line 152
    new-instance v0, Ltd/m;

    .line 153
    .line 154
    invoke-direct {v0, v3}, Ltd/m;-><init>(Ltd/e;)V

    .line 155
    .line 156
    .line 157
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    return-object v2

    .line 161
    :pswitch_b
    check-cast p0, Lay0/k;

    .line 162
    .line 163
    check-cast v3, Lba0/t;

    .line 164
    .line 165
    iget-object v0, v3, Lba0/t;->a:Ljava/lang/String;

    .line 166
    .line 167
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    return-object v2

    .line 171
    :pswitch_c
    check-cast p0, Lay0/k;

    .line 172
    .line 173
    check-cast v3, Lba0/f;

    .line 174
    .line 175
    iget-object v0, v3, Lba0/f;->a:Ljava/lang/String;

    .line 176
    .line 177
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    return-object v2

    .line 181
    :pswitch_d
    check-cast p0, Lc81/d;

    .line 182
    .line 183
    check-cast v3, Landroidx/lifecycle/c1;

    .line 184
    .line 185
    iget-object p0, p0, Lc81/d;->i:Lc81/e;

    .line 186
    .line 187
    if-eqz p0, :cond_1

    .line 188
    .line 189
    iget-object v0, v3, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v0, Le81/x;

    .line 192
    .line 193
    invoke-virtual {v0}, Le81/x;->toRPAViewModel$remoteparkassistcoremeb_release()Le81/t;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    invoke-interface {p0, v0}, Lc81/e;->navigateTo(Le81/t;)V

    .line 198
    .line 199
    .line 200
    :cond_1
    return-object v2

    .line 201
    :pswitch_e
    check-cast p0, Lc81/d;

    .line 202
    .line 203
    check-cast v3, Ln71/c;

    .line 204
    .line 205
    iget-object p0, p0, Lc81/d;->e:Lt71/a;

    .line 206
    .line 207
    if-eqz p0, :cond_2

    .line 208
    .line 209
    const-string v0, "value"

    .line 210
    .line 211
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    iget-object v0, p0, Lt71/a;->a:Ln71/c;

    .line 215
    .line 216
    if-eq v0, v3, :cond_2

    .line 217
    .line 218
    iput-object v3, p0, Lt71/a;->a:Ln71/c;

    .line 219
    .line 220
    iget-object v0, p0, Lt71/a;->g:Lt71/b;

    .line 221
    .line 222
    if-eqz v0, :cond_2

    .line 223
    .line 224
    invoke-interface {v0, p0}, Lt71/b;->lifecycleDidChange(Lt71/a;)V

    .line 225
    .line 226
    .line 227
    :cond_2
    return-object v2

    .line 228
    :pswitch_f
    check-cast p0, Lay0/k;

    .line 229
    .line 230
    check-cast v3, Lp31/g;

    .line 231
    .line 232
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    return-object v2

    .line 236
    :pswitch_10
    check-cast p0, Lxy0/n;

    .line 237
    .line 238
    invoke-interface {p0, v3}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    return-object v2

    .line 242
    :pswitch_11
    check-cast p0, Lc00/k1;

    .line 243
    .line 244
    check-cast v3, Lcn0/c;

    .line 245
    .line 246
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    new-instance v4, La60/f;

    .line 251
    .line 252
    const/16 v5, 0xf

    .line 253
    .line 254
    invoke-direct {v4, v5, p0, v3, v1}, La60/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 255
    .line 256
    .line 257
    const/4 p0, 0x3

    .line 258
    invoke-static {v0, v1, v1, v4, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 259
    .line 260
    .line 261
    return-object v2

    .line 262
    :pswitch_12
    check-cast p0, Lc00/i0;

    .line 263
    .line 264
    check-cast v3, Lcn0/c;

    .line 265
    .line 266
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    check-cast v0, Lc00/d0;

    .line 271
    .line 272
    iget-object v1, p0, Lc00/i0;->j:Lij0/a;

    .line 273
    .line 274
    iget-object v3, v3, Lcn0/c;->e:Lcn0/a;

    .line 275
    .line 276
    invoke-static {v0, v1, v3}, Ljp/dc;->c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;

    .line 277
    .line 278
    .line 279
    move-result-object v0

    .line 280
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 281
    .line 282
    .line 283
    return-object v2

    .line 284
    :pswitch_13
    check-cast p0, Lcom/google/firebase/messaging/v;

    .line 285
    .line 286
    check-cast v3, Ljava/lang/String;

    .line 287
    .line 288
    sget v0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->j:I

    .line 289
    .line 290
    iget-object p0, p0, Lcom/google/firebase/messaging/v;->d:Landroid/os/Bundle;

    .line 291
    .line 292
    const-string v0, "google.message_id"

    .line 293
    .line 294
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    if-nez v0, :cond_3

    .line 299
    .line 300
    const-string v0, "message_id"

    .line 301
    .line 302
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    :cond_3
    const-string p0, "onMessageReceived: "

    .line 307
    .line 308
    const-string v1, "\n"

    .line 309
    .line 310
    invoke-static {p0, v0, v1, v3}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    return-object p0

    .line 315
    :pswitch_14
    check-cast p0, Lbo0/p;

    .line 316
    .line 317
    check-cast v3, Lbo0/r;

    .line 318
    .line 319
    sget-object v0, Lbo0/p;->d:Lbo0/p;

    .line 320
    .line 321
    if-ne p0, v0, :cond_4

    .line 322
    .line 323
    const p0, 0x7f120095

    .line 324
    .line 325
    .line 326
    goto :goto_0

    .line 327
    :cond_4
    const p0, 0x7f120096

    .line 328
    .line 329
    .line 330
    :goto_0
    iget-object v0, v3, Lbo0/r;->j:Lij0/a;

    .line 331
    .line 332
    check-cast v0, Ljj0/f;

    .line 333
    .line 334
    invoke-virtual {v0, p0}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object p0

    .line 338
    new-instance v0, Llj0/a;

    .line 339
    .line 340
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    return-object v0

    .line 344
    :pswitch_15
    check-cast p0, Lay0/k;

    .line 345
    .line 346
    check-cast v3, La60/c;

    .line 347
    .line 348
    iget v0, v3, La60/c;->a:I

    .line 349
    .line 350
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    return-object v2

    .line 358
    :pswitch_16
    check-cast p0, Lay0/k;

    .line 359
    .line 360
    check-cast v3, La10/c;

    .line 361
    .line 362
    iget-boolean v0, v3, La10/c;->b:Z

    .line 363
    .line 364
    xor-int/lit8 v0, v0, 0x1

    .line 365
    .line 366
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 367
    .line 368
    .line 369
    move-result-object v0

    .line 370
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    return-object v2

    .line 374
    :pswitch_17
    check-cast p0, Lay0/k;

    .line 375
    .line 376
    check-cast v3, Lfh/f;

    .line 377
    .line 378
    new-instance v0, Lfh/c;

    .line 379
    .line 380
    iget-boolean v1, v3, Lfh/f;->a:Z

    .line 381
    .line 382
    xor-int/lit8 v1, v1, 0x1

    .line 383
    .line 384
    invoke-direct {v0, v1}, Lfh/c;-><init>(Z)V

    .line 385
    .line 386
    .line 387
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    return-object v2

    .line 391
    :pswitch_18
    check-cast p0, Lay0/k;

    .line 392
    .line 393
    check-cast v3, Lnd/c;

    .line 394
    .line 395
    new-instance v0, Lnd/f;

    .line 396
    .line 397
    iget-object v1, v3, Lnd/c;->a:Ljava/lang/String;

    .line 398
    .line 399
    invoke-direct {v0, v1}, Lnd/f;-><init>(Ljava/lang/String;)V

    .line 400
    .line 401
    .line 402
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    return-object v2

    .line 406
    :pswitch_19
    check-cast p0, Lay0/k;

    .line 407
    .line 408
    check-cast v3, Lmd/b;

    .line 409
    .line 410
    new-instance v0, Lmd/a;

    .line 411
    .line 412
    iget-object v1, v3, Lmd/b;->a:Ljava/lang/String;

    .line 413
    .line 414
    invoke-direct {v0, v1}, Lmd/a;-><init>(Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 418
    .line 419
    .line 420
    return-object v2

    .line 421
    :pswitch_1a
    check-cast p0, Ljava/lang/String;

    .line 422
    .line 423
    check-cast v3, Ljava/lang/Exception;

    .line 424
    .line 425
    new-instance v0, Ljava/lang/StringBuilder;

    .line 426
    .line 427
    const-string v1, "Topic `"

    .line 428
    .line 429
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 430
    .line 431
    .line 432
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 433
    .line 434
    .line 435
    const-string p0, "` was not cleared due to exception "

    .line 436
    .line 437
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 438
    .line 439
    .line 440
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 441
    .line 442
    .line 443
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 444
    .line 445
    .line 446
    move-result-object p0

    .line 447
    return-object p0

    .line 448
    :pswitch_1b
    check-cast p0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 449
    .line 450
    check-cast v3, Ljava/lang/String;

    .line 451
    .line 452
    if-eqz p0, :cond_5

    .line 453
    .line 454
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->toString()Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    :cond_5
    const-string p0, "\' was received on \'"

    .line 459
    .line 460
    const-string v0, "\'"

    .line 461
    .line 462
    const-string v2, "MQTT message \'"

    .line 463
    .line 464
    invoke-static {v2, v1, p0, v3, v0}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 465
    .line 466
    .line 467
    move-result-object p0

    .line 468
    return-object p0

    .line 469
    :pswitch_1c
    check-cast p0, Laa/v;

    .line 470
    .line 471
    check-cast v3, Lz9/k;

    .line 472
    .line 473
    const/4 v0, 0x0

    .line 474
    invoke-virtual {p0, v3, v0}, Laa/v;->e(Lz9/k;Z)V

    .line 475
    .line 476
    .line 477
    return-object v2

    .line 478
    nop

    .line 479
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
