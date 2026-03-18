.class public final Lc8/e;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc8/e;->a:I

    iput-object p1, p0, Lc8/e;->b:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    return-void
.end method

.method public constructor <init>(Lvp/g1;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lc8/e;->a:I

    .line 2
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    iput-object p1, p0, Lc8/e;->b:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 4

    .line 1
    iget v0, p0, Lc8/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p2, Lw7/o;

    .line 9
    .line 10
    iget-object p2, p2, Lw7/o;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p2, Ljava/util/concurrent/Executor;

    .line 13
    .line 14
    new-instance v0, Lno/nordicsemi/android/ble/o0;

    .line 15
    .line 16
    const/16 v1, 0x1a

    .line 17
    .line 18
    invoke-direct {v0, v1, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_0
    iget-object p1, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Lvp/g1;

    .line 28
    .line 29
    if-nez p2, :cond_0

    .line 30
    .line 31
    iget-object p0, p1, Lvp/g1;->i:Lvp/p0;

    .line 32
    .line 33
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 37
    .line 38
    const-string p1, "App receiver called with null intent"

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    goto/16 :goto_1

    .line 44
    .line 45
    :cond_0
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p2

    .line 49
    if-nez p2, :cond_1

    .line 50
    .line 51
    iget-object p0, p1, Lvp/g1;->i:Lvp/p0;

    .line 52
    .line 53
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 57
    .line 58
    const-string p1, "App receiver called with null action"

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_1

    .line 64
    .line 65
    :cond_1
    invoke-virtual {p2}, Ljava/lang/String;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    const v1, -0x72ee9a21

    .line 70
    .line 71
    .line 72
    if-eq v0, v1, :cond_3

    .line 73
    .line 74
    const v1, 0x4c497878    # 5.2814304E7f

    .line 75
    .line 76
    .line 77
    if-eq v0, v1, :cond_2

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_2
    const-string v0, "com.google.android.gms.measurement.BATCHES_AVAILABLE"

    .line 81
    .line 82
    invoke-virtual {p2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p2

    .line 86
    if-eqz p2, :cond_5

    .line 87
    .line 88
    iget-object p2, p1, Lvp/g1;->i:Lvp/p0;

    .line 89
    .line 90
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 91
    .line 92
    .line 93
    iget-object p2, p2, Lvp/p0;->r:Lvp/n0;

    .line 94
    .line 95
    const-string v0, "[sgtm] App Receiver notified batches are available"

    .line 96
    .line 97
    invoke-virtual {p2, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 101
    .line 102
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 103
    .line 104
    .line 105
    new-instance p2, Lvp/g4;

    .line 106
    .line 107
    const/4 v0, 0x0

    .line 108
    invoke-direct {p2, p0, v0}, Lvp/g4;-><init>(Ljava/lang/Object;I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p1, p2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_3
    const-string p0, "com.google.android.gms.measurement.TRIGGERS_AVAILABLE"

    .line 116
    .line 117
    invoke-virtual {p2, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    if-eqz p0, :cond_5

    .line 122
    .line 123
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 124
    .line 125
    .line 126
    iget-object p0, p1, Lvp/g1;->g:Lvp/h;

    .line 127
    .line 128
    const/4 p2, 0x0

    .line 129
    sget-object v0, Lvp/z;->Q0:Lvp/y;

    .line 130
    .line 131
    invoke-virtual {p0, p2, v0}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    if-nez p0, :cond_4

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_4
    iget-object p0, p1, Lvp/g1;->i:Lvp/p0;

    .line 139
    .line 140
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 144
    .line 145
    const-string p2, "App receiver notified triggers are available"

    .line 146
    .line 147
    invoke-virtual {p0, p2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    iget-object p0, p1, Lvp/g1;->j:Lvp/e1;

    .line 151
    .line 152
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 153
    .line 154
    .line 155
    new-instance p2, Lvp/g4;

    .line 156
    .line 157
    const/4 v0, 0x1

    .line 158
    invoke-direct {p2, p1, v0}, Lvp/g4;-><init>(Ljava/lang/Object;I)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {p0, p2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 162
    .line 163
    .line 164
    goto :goto_1

    .line 165
    :cond_5
    :goto_0
    iget-object p0, p1, Lvp/g1;->i:Lvp/p0;

    .line 166
    .line 167
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 168
    .line 169
    .line 170
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 171
    .line 172
    const-string p1, "App receiver called with unknown action"

    .line 173
    .line 174
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    :goto_1
    return-void

    .line 178
    :pswitch_1
    const-string p2, "context"

    .line 179
    .line 180
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    const-string p2, "Got LOCALE_CHANGED Broadcast"

    .line 184
    .line 185
    invoke-static {p2}, Let/d;->c(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    iget-object p0, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast p0, Lcom/google/android/material/datepicker/d;

    .line 191
    .line 192
    invoke-static {p1}, Llp/na;->b(Landroid/content/Context;)Ljava/util/Locale;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    new-instance p2, Ljava/lang/StringBuilder;

    .line 197
    .line 198
    const-string v0, "Setting default Locale Code: "

    .line 199
    .line 200
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p1}, Ljava/util/Locale;->toString()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    const-string v1, "defaultLocale.toString()"

    .line 208
    .line 209
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    invoke-static {v0}, Llp/na;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p2

    .line 223
    invoke-static {p2}, Let/d;->c(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    iget-object p2, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p2, Luw/b;

    .line 229
    .line 230
    const/4 v0, 0x0

    .line 231
    const/16 v1, 0xb

    .line 232
    .line 233
    invoke-static {p2, p1, v0, v1}, Luw/b;->a(Luw/b;Ljava/util/Locale;Ljava/lang/String;I)Luw/b;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/d;->a(Luw/b;)V

    .line 238
    .line 239
    .line 240
    return-void

    .line 241
    :pswitch_2
    const-string v0, "context"

    .line 242
    .line 243
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    const-string p1, "intent"

    .line 247
    .line 248
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    iget-object p0, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p0, Lkb/a;

    .line 254
    .line 255
    iget p1, p0, Lkb/a;->g:I

    .line 256
    .line 257
    packed-switch p1, :pswitch_data_1

    .line 258
    .line 259
    .line 260
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object p1

    .line 264
    if-nez p1, :cond_6

    .line 265
    .line 266
    goto/16 :goto_2

    .line 267
    .line 268
    :cond_6
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    sget-object v0, Lkb/h;->a:Ljava/lang/String;

    .line 273
    .line 274
    new-instance v1, Ljava/lang/StringBuilder;

    .line 275
    .line 276
    const-string v2, "Received "

    .line 277
    .line 278
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v2

    .line 285
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 286
    .line 287
    .line 288
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    invoke-virtual {p1, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object p1

    .line 299
    if-eqz p1, :cond_15

    .line 300
    .line 301
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    .line 302
    .line 303
    .line 304
    move-result p2

    .line 305
    const v0, -0x46671f94

    .line 306
    .line 307
    .line 308
    if-eq p2, v0, :cond_9

    .line 309
    .line 310
    const v0, -0x2b8fb65c

    .line 311
    .line 312
    .line 313
    if-eq p2, v0, :cond_7

    .line 314
    .line 315
    goto/16 :goto_2

    .line 316
    .line 317
    :cond_7
    const-string p2, "android.intent.action.DEVICE_STORAGE_OK"

    .line 318
    .line 319
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    move-result p1

    .line 323
    if-nez p1, :cond_8

    .line 324
    .line 325
    goto/16 :goto_2

    .line 326
    .line 327
    :cond_8
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 328
    .line 329
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    goto/16 :goto_2

    .line 333
    .line 334
    :cond_9
    const-string p2, "android.intent.action.DEVICE_STORAGE_LOW"

    .line 335
    .line 336
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 337
    .line 338
    .line 339
    move-result p1

    .line 340
    if-nez p1, :cond_a

    .line 341
    .line 342
    goto/16 :goto_2

    .line 343
    .line 344
    :cond_a
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 345
    .line 346
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    goto/16 :goto_2

    .line 350
    .line 351
    :pswitch_3
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object p1

    .line 355
    if-nez p1, :cond_b

    .line 356
    .line 357
    goto/16 :goto_2

    .line 358
    .line 359
    :cond_b
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 360
    .line 361
    .line 362
    move-result-object p1

    .line 363
    sget-object v0, Lkb/c;->a:Ljava/lang/String;

    .line 364
    .line 365
    new-instance v1, Ljava/lang/StringBuilder;

    .line 366
    .line 367
    const-string v2, "Received "

    .line 368
    .line 369
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 370
    .line 371
    .line 372
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v2

    .line 376
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 377
    .line 378
    .line 379
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    invoke-virtual {p1, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 387
    .line 388
    .line 389
    move-result-object p1

    .line 390
    if-eqz p1, :cond_15

    .line 391
    .line 392
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    .line 393
    .line 394
    .line 395
    move-result p2

    .line 396
    const v0, -0x7606c095    # -6.0004207E-33f

    .line 397
    .line 398
    .line 399
    if-eq p2, v0, :cond_e

    .line 400
    .line 401
    const v0, 0x1d398bfd

    .line 402
    .line 403
    .line 404
    if-eq p2, v0, :cond_c

    .line 405
    .line 406
    goto/16 :goto_2

    .line 407
    .line 408
    :cond_c
    const-string p2, "android.intent.action.BATTERY_LOW"

    .line 409
    .line 410
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 411
    .line 412
    .line 413
    move-result p1

    .line 414
    if-nez p1, :cond_d

    .line 415
    .line 416
    goto/16 :goto_2

    .line 417
    .line 418
    :cond_d
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 419
    .line 420
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 421
    .line 422
    .line 423
    goto/16 :goto_2

    .line 424
    .line 425
    :cond_e
    const-string p2, "android.intent.action.BATTERY_OKAY"

    .line 426
    .line 427
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 428
    .line 429
    .line 430
    move-result p1

    .line 431
    if-nez p1, :cond_f

    .line 432
    .line 433
    goto :goto_2

    .line 434
    :cond_f
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 435
    .line 436
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 437
    .line 438
    .line 439
    goto :goto_2

    .line 440
    :pswitch_4
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object p1

    .line 444
    if-nez p1, :cond_10

    .line 445
    .line 446
    goto :goto_2

    .line 447
    :cond_10
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 448
    .line 449
    .line 450
    move-result-object p2

    .line 451
    sget-object v0, Lkb/b;->a:Ljava/lang/String;

    .line 452
    .line 453
    const-string v1, "Received "

    .line 454
    .line 455
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 456
    .line 457
    .line 458
    move-result-object v1

    .line 459
    invoke-virtual {p2, v0, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    .line 463
    .line 464
    .line 465
    move-result p2

    .line 466
    sparse-switch p2, :sswitch_data_0

    .line 467
    .line 468
    .line 469
    goto :goto_2

    .line 470
    :sswitch_0
    const-string p2, "android.intent.action.ACTION_POWER_CONNECTED"

    .line 471
    .line 472
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    move-result p1

    .line 476
    if-nez p1, :cond_11

    .line 477
    .line 478
    goto :goto_2

    .line 479
    :cond_11
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 480
    .line 481
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 482
    .line 483
    .line 484
    goto :goto_2

    .line 485
    :sswitch_1
    const-string p2, "android.os.action.CHARGING"

    .line 486
    .line 487
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 488
    .line 489
    .line 490
    move-result p1

    .line 491
    if-nez p1, :cond_12

    .line 492
    .line 493
    goto :goto_2

    .line 494
    :cond_12
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 495
    .line 496
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 497
    .line 498
    .line 499
    goto :goto_2

    .line 500
    :sswitch_2
    const-string p2, "android.os.action.DISCHARGING"

    .line 501
    .line 502
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 503
    .line 504
    .line 505
    move-result p1

    .line 506
    if-nez p1, :cond_13

    .line 507
    .line 508
    goto :goto_2

    .line 509
    :cond_13
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 510
    .line 511
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 512
    .line 513
    .line 514
    goto :goto_2

    .line 515
    :sswitch_3
    const-string p2, "android.intent.action.ACTION_POWER_DISCONNECTED"

    .line 516
    .line 517
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 518
    .line 519
    .line 520
    move-result p1

    .line 521
    if-nez p1, :cond_14

    .line 522
    .line 523
    goto :goto_2

    .line 524
    :cond_14
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 525
    .line 526
    invoke-virtual {p0, p1}, Lh2/s;->c(Ljava/lang/Object;)V

    .line 527
    .line 528
    .line 529
    :cond_15
    :goto_2
    return-void

    .line 530
    :pswitch_5
    iget-object v0, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 531
    .line 532
    check-cast v0, Lk61/b;

    .line 533
    .line 534
    iget-object v0, v0, Lk61/b;->e:Lyy0/c2;

    .line 535
    .line 536
    const-string v1, "context"

    .line 537
    .line 538
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    const-string p1, "intent"

    .line 542
    .line 543
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 544
    .line 545
    .line 546
    const-string p1, "android.bluetooth.adapter.extra.STATE"

    .line 547
    .line 548
    const/16 v1, 0xa

    .line 549
    .line 550
    invoke-virtual {p2, p1, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 551
    .line 552
    .line 553
    move-result p1

    .line 554
    const-string v2, "android.bluetooth.adapter.extra.PREVIOUS_STATE"

    .line 555
    .line 556
    invoke-virtual {p2, v2, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 557
    .line 558
    .line 559
    move-result p2

    .line 560
    new-instance v2, Lk61/a;

    .line 561
    .line 562
    const/4 v3, 0x0

    .line 563
    invoke-direct {v2, p2, p1, v3}, Lk61/a;-><init>(III)V

    .line 564
    .line 565
    .line 566
    invoke-static {p0, v2}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 567
    .line 568
    .line 569
    if-eq p1, v1, :cond_17

    .line 570
    .line 571
    const/16 p0, 0xc

    .line 572
    .line 573
    if-eq p1, p0, :cond_16

    .line 574
    .line 575
    goto :goto_3

    .line 576
    :cond_16
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object p0

    .line 580
    move-object p1, p0

    .line 581
    check-cast p1, Ljava/lang/Boolean;

    .line 582
    .line 583
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 584
    .line 585
    .line 586
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 587
    .line 588
    invoke-virtual {v0, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 589
    .line 590
    .line 591
    move-result p0

    .line 592
    if-eqz p0, :cond_16

    .line 593
    .line 594
    goto :goto_3

    .line 595
    :cond_17
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 596
    .line 597
    .line 598
    move-result-object p0

    .line 599
    move-object p1, p0

    .line 600
    check-cast p1, Ljava/lang/Boolean;

    .line 601
    .line 602
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 603
    .line 604
    .line 605
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 606
    .line 607
    invoke-virtual {v0, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 608
    .line 609
    .line 610
    move-result p0

    .line 611
    if-eqz p0, :cond_17

    .line 612
    .line 613
    :goto_3
    return-void

    .line 614
    :pswitch_6
    iget-object p0, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 615
    .line 616
    check-cast p0, Lh/w;

    .line 617
    .line 618
    invoke-virtual {p0}, Lh/w;->k()V

    .line 619
    .line 620
    .line 621
    return-void

    .line 622
    :pswitch_7
    invoke-virtual {p0}, Landroid/content/BroadcastReceiver;->isInitialStickyBroadcast()Z

    .line 623
    .line 624
    .line 625
    move-result v0

    .line 626
    if-nez v0, :cond_18

    .line 627
    .line 628
    iget-object p0, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 629
    .line 630
    check-cast p0, Lc8/f;

    .line 631
    .line 632
    iget-object v0, p0, Lc8/f;->j:Ljava/lang/Object;

    .line 633
    .line 634
    check-cast v0, Lt7/c;

    .line 635
    .line 636
    iget-object v1, p0, Lc8/f;->i:Ljava/lang/Object;

    .line 637
    .line 638
    check-cast v1, La0/j;

    .line 639
    .line 640
    invoke-static {p1, p2, v0, v1}, Lc8/b;->b(Landroid/content/Context;Landroid/content/Intent;Lt7/c;La0/j;)Lc8/b;

    .line 641
    .line 642
    .line 643
    move-result-object p1

    .line 644
    invoke-virtual {p0, p1}, Lc8/f;->d(Lc8/b;)V

    .line 645
    .line 646
    .line 647
    :cond_18
    return-void

    .line 648
    nop

    .line 649
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 650
    .line 651
    .line 652
    .line 653
    .line 654
    .line 655
    .line 656
    .line 657
    .line 658
    .line 659
    .line 660
    .line 661
    .line 662
    .line 663
    .line 664
    .line 665
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
    .end packed-switch

    .line 666
    .line 667
    .line 668
    .line 669
    .line 670
    .line 671
    .line 672
    .line 673
    :sswitch_data_0
    .sparse-switch
        -0x7073f927 -> :sswitch_3
        -0x3465cce -> :sswitch_2
        0x388694fe -> :sswitch_1
        0x3cbf870b -> :sswitch_0
    .end sparse-switch
.end method
