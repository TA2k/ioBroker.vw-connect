.class public final Leh0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Leh0/e;


# direct methods
.method public synthetic constructor <init>(Leh0/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Leh0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Leh0/b;->e:Leh0/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Leh0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Leh0/b;->e:Leh0/e;

    .line 9
    .line 10
    iget-object p2, p0, Leh0/e;->b:Lzg0/a;

    .line 11
    .line 12
    iget-object p0, p0, Leh0/e;->a:Landroid/content/Context;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    :try_start_0
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 16
    .line 17
    const/16 v2, 0x21

    .line 18
    .line 19
    if-lt v1, v2, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {}, Lb/s;->b()Landroid/content/pm/PackageManager$PackageInfoFlags;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-static {p0, p1, v1}, Lb/s;->u(Landroid/content/pm/PackageManager;Ljava/lang/String;Landroid/content/pm/PackageManager$PackageInfoFlags;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p0, p1, v0}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 38
    .line 39
    .line 40
    :goto_0
    const/4 v0, 0x1

    .line 41
    :catch_0
    iget-object p0, p2, Lzg0/a;->h:Lyy0/q1;

    .line 42
    .line 43
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_0
    check-cast p1, Lzg0/h;

    .line 54
    .line 55
    instance-of v0, p1, Lzg0/e;

    .line 56
    .line 57
    const-string v1, ""

    .line 58
    .line 59
    const/4 v2, 0x0

    .line 60
    const/high16 v3, 0x10000000

    .line 61
    .line 62
    iget-object p0, p0, Leh0/b;->e:Leh0/e;

    .line 63
    .line 64
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    check-cast p1, Lzg0/e;

    .line 69
    .line 70
    iget-object p1, p1, Lzg0/e;->a:Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    new-instance v0, Landroid/content/Intent;

    .line 76
    .line 77
    const-string v5, "mailto"

    .line 78
    .line 79
    invoke-static {v5, p1, v2}, Landroid/net/Uri;->fromParts(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    const-string v5, "android.intent.action.SENDTO"

    .line 84
    .line 85
    invoke-direct {v0, v5, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 86
    .line 87
    .line 88
    invoke-static {v0, v1}, Landroid/content/Intent;->createChooser(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-virtual {v0, v3}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 93
    .line 94
    .line 95
    new-instance v1, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    const-string v2, "Can\'t send email to "

    .line 98
    .line 99
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-virtual {p0, v0, p1, p2}, Leh0/e;->a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 114
    .line 115
    if-ne p0, p1, :cond_1

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_1
    move-object p0, v4

    .line 119
    :goto_1
    if-ne p0, p1, :cond_12

    .line 120
    .line 121
    :goto_2
    move-object v4, p0

    .line 122
    goto/16 :goto_a

    .line 123
    .line 124
    :cond_2
    instance-of v0, p1, Lzg0/f;

    .line 125
    .line 126
    if-eqz v0, :cond_4

    .line 127
    .line 128
    check-cast p1, Lzg0/f;

    .line 129
    .line 130
    iget-object p1, p1, Lzg0/f;->a:Ljava/lang/String;

    .line 131
    .line 132
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    new-instance v0, Landroid/content/Intent;

    .line 136
    .line 137
    const-string v1, "tel"

    .line 138
    .line 139
    invoke-static {v1, p1, v2}, Landroid/net/Uri;->fromParts(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    const-string v2, "android.intent.action.DIAL"

    .line 144
    .line 145
    invoke-direct {v0, v2, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 149
    .line 150
    .line 151
    new-instance v1, Ljava/lang/StringBuilder;

    .line 152
    .line 153
    const-string v2, "Can\'t call phone number "

    .line 154
    .line 155
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    invoke-virtual {p0, v0, p1, p2}, Leh0/e;->a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 170
    .line 171
    if-ne p0, p1, :cond_3

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_3
    move-object p0, v4

    .line 175
    :goto_3
    if-ne p0, p1, :cond_12

    .line 176
    .line 177
    goto :goto_2

    .line 178
    :cond_4
    instance-of v0, p1, Lzg0/c;

    .line 179
    .line 180
    const-string v5, "android.intent.action.VIEW"

    .line 181
    .line 182
    if-eqz v0, :cond_6

    .line 183
    .line 184
    check-cast p1, Lzg0/c;

    .line 185
    .line 186
    iget-object p1, p1, Lzg0/c;->a:Ljava/lang/String;

    .line 187
    .line 188
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 189
    .line 190
    .line 191
    new-instance v0, Landroid/content/Intent;

    .line 192
    .line 193
    invoke-direct {v0, v5}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    new-instance v1, Ljava/lang/StringBuilder;

    .line 197
    .line 198
    const-string v2, "https://play.google.com/store/apps/details?id="

    .line 199
    .line 200
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 215
    .line 216
    .line 217
    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 218
    .line 219
    .line 220
    new-instance v1, Ljava/lang/StringBuilder;

    .line 221
    .line 222
    const-string v2, "Can\'t open Google Play detail for app "

    .line 223
    .line 224
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    invoke-virtual {p0, v0, p1, p2}, Leh0/e;->a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 239
    .line 240
    if-ne p0, p1, :cond_5

    .line 241
    .line 242
    goto :goto_4

    .line 243
    :cond_5
    move-object p0, v4

    .line 244
    :goto_4
    if-ne p0, p1, :cond_12

    .line 245
    .line 246
    goto :goto_2

    .line 247
    :cond_6
    instance-of v0, p1, Lzg0/b;

    .line 248
    .line 249
    if-eqz v0, :cond_c

    .line 250
    .line 251
    check-cast p1, Lzg0/b;

    .line 252
    .line 253
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 254
    .line 255
    .line 256
    iget-object v0, p1, Lzg0/b;->a:Ldh0/a;

    .line 257
    .line 258
    iget-object p1, p1, Lzg0/b;->b:Ljava/lang/String;

    .line 259
    .line 260
    sget-object v1, Leh0/a;->a:[I

    .line 261
    .line 262
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 263
    .line 264
    .line 265
    move-result v6

    .line 266
    iget-object v0, v0, Ldh0/a;->d:Ljava/lang/String;

    .line 267
    .line 268
    aget v1, v1, v6

    .line 269
    .line 270
    const/4 v6, 0x1

    .line 271
    if-ne v1, v6, :cond_8

    .line 272
    .line 273
    new-instance v1, Landroid/content/Intent;

    .line 274
    .line 275
    invoke-direct {v1, v5}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    if-eqz p1, :cond_7

    .line 279
    .line 280
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    :cond_7
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 285
    .line 286
    .line 287
    invoke-virtual {v1, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 288
    .line 289
    .line 290
    invoke-virtual {v1, v0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 291
    .line 292
    .line 293
    :goto_5
    move-object v2, v1

    .line 294
    goto :goto_6

    .line 295
    :cond_8
    iget-object v1, p0, Leh0/e;->a:Landroid/content/Context;

    .line 296
    .line 297
    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    invoke-virtual {v1, v0}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    if-eqz v1, :cond_a

    .line 306
    .line 307
    if-eqz p1, :cond_9

    .line 308
    .line 309
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 310
    .line 311
    .line 312
    move-result-object p1

    .line 313
    invoke-virtual {v1, p1}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 314
    .line 315
    .line 316
    :cond_9
    invoke-virtual {v1, v5}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 317
    .line 318
    .line 319
    goto :goto_5

    .line 320
    :cond_a
    :goto_6
    const-string p1, "Can\'t open app with "

    .line 321
    .line 322
    const-string v1, " package name. Probably app is not installed."

    .line 323
    .line 324
    invoke-static {p1, v0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 325
    .line 326
    .line 327
    move-result-object p1

    .line 328
    invoke-virtual {p0, v2, p1, p2}, Leh0/e;->a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 333
    .line 334
    if-ne p0, p1, :cond_b

    .line 335
    .line 336
    goto :goto_7

    .line 337
    :cond_b
    move-object p0, v4

    .line 338
    :goto_7
    if-ne p0, p1, :cond_12

    .line 339
    .line 340
    goto/16 :goto_2

    .line 341
    .line 342
    :cond_c
    instance-of v0, p1, Lzg0/g;

    .line 343
    .line 344
    if-eqz v0, :cond_f

    .line 345
    .line 346
    check-cast p1, Lzg0/g;

    .line 347
    .line 348
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 349
    .line 350
    .line 351
    new-instance v0, Landroid/content/Intent;

    .line 352
    .line 353
    const-string v1, "android.settings.APP_NOTIFICATION_SETTINGS"

    .line 354
    .line 355
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 359
    .line 360
    .line 361
    iget-object v1, p0, Leh0/e;->a:Landroid/content/Context;

    .line 362
    .line 363
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    const-string v2, "android.provider.extra.APP_PACKAGE"

    .line 368
    .line 369
    invoke-virtual {v0, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 370
    .line 371
    .line 372
    iget-object p1, p1, Lzg0/g;->a:Ljava/lang/String;

    .line 373
    .line 374
    if-eqz p1, :cond_d

    .line 375
    .line 376
    const-string v1, "android.provider.extra.CHANNEL_ID"

    .line 377
    .line 378
    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 379
    .line 380
    .line 381
    :cond_d
    const-string p1, "Can\'t open System App Notification Settings"

    .line 382
    .line 383
    invoke-virtual {p0, v0, p1, p2}, Leh0/e;->a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object p0

    .line 387
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 388
    .line 389
    if-ne p0, p1, :cond_e

    .line 390
    .line 391
    goto :goto_8

    .line 392
    :cond_e
    move-object p0, v4

    .line 393
    :goto_8
    if-ne p0, p1, :cond_12

    .line 394
    .line 395
    goto/16 :goto_2

    .line 396
    .line 397
    :cond_f
    instance-of v0, p1, Lzg0/d;

    .line 398
    .line 399
    if-eqz v0, :cond_13

    .line 400
    .line 401
    check-cast p1, Lzg0/d;

    .line 402
    .line 403
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 404
    .line 405
    .line 406
    new-instance v0, Landroid/content/Intent;

    .line 407
    .line 408
    const-string v2, "android.intent.action.INSERT"

    .line 409
    .line 410
    invoke-direct {v0, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 411
    .line 412
    .line 413
    sget-object v2, Landroid/provider/CalendarContract$Events;->CONTENT_URI:Landroid/net/Uri;

    .line 414
    .line 415
    invoke-virtual {v0, v2}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 416
    .line 417
    .line 418
    const-string v2, "title"

    .line 419
    .line 420
    iget-object v5, p1, Lzg0/d;->a:Ljava/lang/String;

    .line 421
    .line 422
    invoke-virtual {v0, v2, v5}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 423
    .line 424
    .line 425
    iget-object p1, p1, Lzg0/d;->b:Ljava/time/OffsetDateTime;

    .line 426
    .line 427
    if-eqz p1, :cond_10

    .line 428
    .line 429
    invoke-virtual {p1}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 430
    .line 431
    .line 432
    move-result-object p1

    .line 433
    invoke-virtual {p1}, Ljava/time/Instant;->toEpochMilli()J

    .line 434
    .line 435
    .line 436
    move-result-wide v5

    .line 437
    const-string p1, "beginTime"

    .line 438
    .line 439
    invoke-virtual {v0, p1, v5, v6}, Landroid/content/Intent;->putExtra(Ljava/lang/String;J)Landroid/content/Intent;

    .line 440
    .line 441
    .line 442
    :cond_10
    invoke-static {v0, v1}, Landroid/content/Intent;->createChooser(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;

    .line 443
    .line 444
    .line 445
    move-result-object p1

    .line 446
    invoke-virtual {p1, v3}, Landroid/content/Intent;->setFlags(I)Landroid/content/Intent;

    .line 447
    .line 448
    .line 449
    const-string v0, "Can\'t open calendar app"

    .line 450
    .line 451
    invoke-virtual {p0, p1, v0, p2}, Leh0/e;->a(Landroid/content/Intent;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object p0

    .line 455
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 456
    .line 457
    if-ne p0, p1, :cond_11

    .line 458
    .line 459
    goto :goto_9

    .line 460
    :cond_11
    move-object p0, v4

    .line 461
    :goto_9
    if-ne p0, p1, :cond_12

    .line 462
    .line 463
    goto/16 :goto_2

    .line 464
    .line 465
    :cond_12
    :goto_a
    return-object v4

    .line 466
    :cond_13
    new-instance p0, La8/r0;

    .line 467
    .line 468
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 469
    .line 470
    .line 471
    throw p0

    .line 472
    nop

    .line 473
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
