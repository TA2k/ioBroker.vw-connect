.class public final synthetic Lyp0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lyp0/d;->d:I

    iput-object p2, p0, Lyp0/d;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lyp0/d;->d:I

    iput-object p1, p0, Lyp0/d;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lyp0/d;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lyp0/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lcw0/c;

    .line 9
    .line 10
    check-cast p1, Ljava/lang/Throwable;

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    check-cast p0, Lfw0/t;

    .line 19
    .line 20
    check-cast p1, Lzv0/c;

    .line 21
    .line 22
    const-string v0, "scope"

    .line 23
    .line 24
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, p1, Lzv0/c;->m:Lvw0/d;

    .line 28
    .line 29
    sget-object v1, Lfw0/u;->a:Lvw0/a;

    .line 30
    .line 31
    new-instance v2, Lzm0/c;

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    invoke-direct {v2, v3}, Lzm0/c;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v1, v2}, Lvw0/d;->a(Lvw0/a;Lay0/a;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lvw0/d;

    .line 42
    .line 43
    iget-object v1, p1, Lzv0/c;->o:Lzv0/e;

    .line 44
    .line 45
    iget-object v1, v1, Lzv0/e;->b:Ljava/util/LinkedHashMap;

    .line 46
    .line 47
    invoke-interface {p0}, Lfw0/t;->getKey()Lvw0/a;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    invoke-virtual {v1, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    check-cast v1, Lay0/k;

    .line 59
    .line 60
    invoke-interface {p0, v1}, Lfw0/t;->b(Lay0/k;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-interface {p0, v1, p1}, Lfw0/t;->d(Ljava/lang/Object;Lzv0/c;)V

    .line 65
    .line 66
    .line 67
    invoke-interface {p0}, Lfw0/t;->getKey()Lvw0/a;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {v0, p0, v1}, Lvw0/d;->e(Lvw0/a;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_1
    check-cast p0, Lxj0/m;

    .line 78
    .line 79
    check-cast p1, Ld4/l;

    .line 80
    .line 81
    const-string v0, "$this$semantics"

    .line 82
    .line 83
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-static {p0}, Lzj0/d;->k(Lxj0/r;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    return-object p0

    .line 96
    :pswitch_2
    check-cast p0, Lxj0/k;

    .line 97
    .line 98
    check-cast p1, Ld4/l;

    .line 99
    .line 100
    const-string v0, "$this$semantics"

    .line 101
    .line 102
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-static {p0}, Lzj0/d;->k(Lxj0/r;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    return-object p0

    .line 115
    :pswitch_3
    check-cast p0, Lxj0/p;

    .line 116
    .line 117
    check-cast p1, Ld4/l;

    .line 118
    .line 119
    const-string v0, "$this$semantics"

    .line 120
    .line 121
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p0}, Lzj0/d;->k(Lxj0/r;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_4
    check-cast p0, Lyj0/d;

    .line 135
    .line 136
    check-cast p1, Luu/g;

    .line 137
    .line 138
    const-string v0, "$this$rememberCameraPositionState"

    .line 139
    .line 140
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p0, Lyj0/d;->h:Lxj0/b;

    .line 144
    .line 145
    if-eqz p0, :cond_0

    .line 146
    .line 147
    iget-object v0, p0, Lxj0/b;->a:Lxj0/f;

    .line 148
    .line 149
    invoke-static {v0}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    iget p0, p0, Lxj0/b;->b:F

    .line 154
    .line 155
    new-instance v1, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 156
    .line 157
    const/4 v2, 0x0

    .line 158
    invoke-direct {v1, v0, p0, v2, v2}, Lcom/google/android/gms/maps/model/CameraPosition;-><init>(Lcom/google/android/gms/maps/model/LatLng;FFF)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {p1, v1}, Luu/g;->g(Lcom/google/android/gms/maps/model/CameraPosition;)V

    .line 162
    .line 163
    .line 164
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 165
    .line 166
    return-object p0

    .line 167
    :pswitch_5
    check-cast p0, Luc/g;

    .line 168
    .line 169
    check-cast p1, Ljava/lang/String;

    .line 170
    .line 171
    const-string v0, "it"

    .line 172
    .line 173
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-static {}, Ljp/hf;->a()I

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 185
    .line 186
    .line 187
    iget-object p0, p0, Luc/g;->a:Luc/h;

    .line 188
    .line 189
    invoke-interface {p0, p1, v0}, Luc/h;->d(Ljava/lang/String;Ljava/lang/Integer;)Lretrofit2/Call;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    invoke-interface {p0}, Lretrofit2/Call;->request()Ld01/k0;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    const-string p1, "request(...)"

    .line 198
    .line 199
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    invoke-static {p0}, Lkc/d;->f(Ld01/k0;)Lkc/e;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    return-object p0

    .line 207
    :pswitch_6
    check-cast p0, Lz9/j0;

    .line 208
    .line 209
    check-cast p1, Lz9/k;

    .line 210
    .line 211
    const-string v0, "backStackEntry"

    .line 212
    .line 213
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    iget-object v0, p1, Lz9/k;->k:Lca/c;

    .line 217
    .line 218
    iget-object v1, p1, Lz9/k;->e:Lz9/u;

    .line 219
    .line 220
    const/4 v2, 0x0

    .line 221
    if-eqz v1, :cond_1

    .line 222
    .line 223
    goto :goto_0

    .line 224
    :cond_1
    move-object v1, v2

    .line 225
    :goto_0
    if-nez v1, :cond_2

    .line 226
    .line 227
    goto :goto_1

    .line 228
    :cond_2
    invoke-virtual {v0}, Lca/c;->a()Landroid/os/Bundle;

    .line 229
    .line 230
    .line 231
    invoke-virtual {p0, v1}, Lz9/j0;->c(Lz9/u;)Lz9/u;

    .line 232
    .line 233
    .line 234
    move-result-object v3

    .line 235
    if-nez v3, :cond_3

    .line 236
    .line 237
    :goto_1
    move-object p1, v2

    .line 238
    goto :goto_2

    .line 239
    :cond_3
    invoke-virtual {v3, v1}, Lz9/u;->equals(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v1

    .line 243
    if-eqz v1, :cond_4

    .line 244
    .line 245
    goto :goto_2

    .line 246
    :cond_4
    invoke-virtual {p0}, Lz9/j0;->b()Lz9/m;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    invoke-virtual {v0}, Lca/c;->a()Landroid/os/Bundle;

    .line 251
    .line 252
    .line 253
    move-result-object p1

    .line 254
    invoke-virtual {v3, p1}, Lz9/u;->e(Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    invoke-virtual {p0, v3, p1}, Lz9/m;->b(Lz9/u;Landroid/os/Bundle;)Lz9/k;

    .line 259
    .line 260
    .line 261
    move-result-object p1

    .line 262
    :goto_2
    return-object p1

    .line 263
    :pswitch_7
    check-cast p0, Lyp0/d;

    .line 264
    .line 265
    check-cast p1, Lv3/c2;

    .line 266
    .line 267
    instance-of v0, p1, Lz1/a;

    .line 268
    .line 269
    if-eqz v0, :cond_5

    .line 270
    .line 271
    check-cast p1, Lz1/a;

    .line 272
    .line 273
    iget-object p1, p1, Lz1/a;->r:Lyp0/d;

    .line 274
    .line 275
    invoke-virtual {p0, p1}, Lyp0/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 279
    .line 280
    return-object p0

    .line 281
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 282
    .line 283
    const-string p1, "TextContextMenuDataNode.TraverseKey key must only be attached to instances of TextContextMenuDataNode."

    .line 284
    .line 285
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    throw p0

    .line 289
    :pswitch_8
    check-cast p0, Lv1/a;

    .line 290
    .line 291
    check-cast p1, Lay0/k;

    .line 292
    .line 293
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 297
    .line 298
    return-object p0

    .line 299
    :pswitch_9
    check-cast p0, Lz1/b;

    .line 300
    .line 301
    check-cast p1, Lv1/a;

    .line 302
    .line 303
    iget-object v0, p0, Lz1/b;->t:Ld90/m;

    .line 304
    .line 305
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 306
    .line 307
    invoke-static {p0, v1}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object p0

    .line 311
    invoke-virtual {v0, p1, p0}, Ld90/m;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 315
    .line 316
    return-object p0

    .line 317
    :pswitch_a
    check-cast p0, Lap0/e;

    .line 318
    .line 319
    check-cast p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 320
    .line 321
    const-string v0, "$this$registrationManagerEditor"

    .line 322
    .line 323
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    iget-object v0, p0, Lap0/e;->b:Lap0/d;

    .line 327
    .line 328
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 329
    .line 330
    .line 331
    move-result v0

    .line 332
    const-string v1, "SysNotifications"

    .line 333
    .line 334
    const/4 v2, 0x1

    .line 335
    if-eqz v0, :cond_7

    .line 336
    .line 337
    if-ne v0, v2, :cond_6

    .line 338
    .line 339
    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->removeTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 340
    .line 341
    .line 342
    goto :goto_3

    .line 343
    :cond_6
    new-instance p0, La8/r0;

    .line 344
    .line 345
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 346
    .line 347
    .line 348
    throw p0

    .line 349
    :cond_7
    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->addTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 350
    .line 351
    .line 352
    :goto_3
    iget-object p0, p0, Lap0/e;->a:Lap0/d;

    .line 353
    .line 354
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 355
    .line 356
    .line 357
    move-result p0

    .line 358
    const-string v0, "MktNotifications"

    .line 359
    .line 360
    if-eqz p0, :cond_9

    .line 361
    .line 362
    if-ne p0, v2, :cond_8

    .line 363
    .line 364
    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->removeTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 365
    .line 366
    .line 367
    goto :goto_4

    .line 368
    :cond_8
    new-instance p0, La8/r0;

    .line 369
    .line 370
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 371
    .line 372
    .line 373
    throw p0

    .line 374
    :cond_9
    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->addTag(Ljava/lang/String;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 375
    .line 376
    .line 377
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 378
    .line 379
    return-object p0

    .line 380
    :pswitch_b
    check-cast p0, Lyp0/h;

    .line 381
    .line 382
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationStatus;

    .line 383
    .line 384
    const-string v0, "it"

    .line 385
    .line 386
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 387
    .line 388
    .line 389
    new-instance v0, Ly1/i;

    .line 390
    .line 391
    const/16 v1, 0xb

    .line 392
    .line 393
    invoke-direct {v0, p1, v1}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 394
    .line 395
    .line 396
    const-string p1, "~$SFMCSdk"

    .line 397
    .line 398
    invoke-static {p1, p0, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 399
    .line 400
    .line 401
    invoke-static {}, Lcom/google/firebase/messaging/FirebaseMessaging;->c()Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 402
    .line 403
    .line 404
    move-result-object p1

    .line 405
    invoke-virtual {p1}, Lcom/google/firebase/messaging/FirebaseMessaging;->f()Laq/t;

    .line 406
    .line 407
    .line 408
    move-result-object p1

    .line 409
    new-instance v0, Lyp0/c;

    .line 410
    .line 411
    invoke-direct {v0, p0}, Lyp0/c;-><init>(Lyp0/h;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {p1, v0}, Laq/t;->k(Laq/e;)Laq/t;

    .line 415
    .line 416
    .line 417
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 418
    .line 419
    return-object p0

    .line 420
    :pswitch_c
    check-cast p0, Lcom/google/firebase/messaging/v;

    .line 421
    .line 422
    check-cast p1, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 423
    .line 424
    const-string v0, "$this$pushManager"

    .line 425
    .line 426
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->handleMessage(Lcom/google/firebase/messaging/v;)Z

    .line 430
    .line 431
    .line 432
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 433
    .line 434
    return-object p0

    .line 435
    :pswitch_data_0
    .packed-switch 0x0
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
