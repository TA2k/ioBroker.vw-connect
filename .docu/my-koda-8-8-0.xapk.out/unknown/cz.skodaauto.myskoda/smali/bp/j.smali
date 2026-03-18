.class public abstract Lbp/j;
.super Landroid/os/Binder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/IInterface;


# instance fields
.field public final synthetic c:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lbp/j;->c:I

    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0

    iput p2, p0, Lbp/j;->c:I

    packed-switch p2, :pswitch_data_0

    .line 2
    :pswitch_0
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 3
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    return-void

    .line 4
    :pswitch_1
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 5
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    return-void

    .line 6
    :pswitch_2
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 7
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    return-void

    .line 8
    :pswitch_3
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 9
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    return-void

    .line 10
    :pswitch_4
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 11
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    return-void

    .line 12
    :pswitch_5
    invoke-direct {p0}, Landroid/os/Binder;-><init>()V

    .line 13
    invoke-virtual {p0, p0, p1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_5
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_0
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method


# virtual methods
.method public abstract Q(ILandroid/os/Parcel;Landroid/os/Parcel;)Z
.end method

.method public R(ILandroid/os/Parcel;Landroid/os/Parcel;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public abstract S(Landroid/os/Parcel;I)Z
.end method

.method public asBinder()Landroid/os/IBinder;
    .locals 1

    .line 1
    iget v0, p0, Lbp/j;->c:I

    .line 2
    .line 3
    return-object p0
.end method

.method public onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    .locals 5

    .line 1
    iget v0, p0, Lbp/j;->c:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    const v3, 0xffffff

    .line 6
    .line 7
    .line 8
    const/4 v4, 0x1

    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    :pswitch_0
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0

    .line 17
    :pswitch_1
    if-le p1, v3, :cond_0

    .line 18
    .line 19
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 20
    .line 21
    .line 22
    move-result p4

    .line 23
    if-eqz p4, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p4

    .line 30
    invoke-virtual {p2, p4}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Lbp/j;->R(ILandroid/os/Parcel;Landroid/os/Parcel;)Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    :goto_0
    return v4

    .line 38
    :pswitch_2
    if-le p1, v3, :cond_2

    .line 39
    .line 40
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 41
    .line 42
    .line 43
    move-result p4

    .line 44
    if-eqz p4, :cond_3

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p4

    .line 51
    invoke-virtual {p2, p4}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_3
    invoke-virtual {p0, p1, p2, p3}, Lbp/j;->R(ILandroid/os/Parcel;Landroid/os/Parcel;)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    :goto_1
    return v4

    .line 59
    :pswitch_3
    if-le p1, v3, :cond_4

    .line 60
    .line 61
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 62
    .line 63
    .line 64
    move-result p3

    .line 65
    if-eqz p3, :cond_5

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_4
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p3

    .line 72
    invoke-virtual {p2, p3}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    :cond_5
    invoke-virtual {p0, p2, p1}, Lbp/j;->S(Landroid/os/Parcel;I)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    :goto_2
    return v4

    .line 80
    :pswitch_4
    if-le p1, v3, :cond_6

    .line 81
    .line 82
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 83
    .line 84
    .line 85
    move-result p3

    .line 86
    if-eqz p3, :cond_7

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_6
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p3

    .line 93
    invoke-virtual {p2, p3}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :cond_7
    invoke-virtual {p0, p2, p1}, Lbp/j;->S(Landroid/os/Parcel;I)Z

    .line 97
    .line 98
    .line 99
    move-result v4

    .line 100
    :goto_3
    return v4

    .line 101
    :pswitch_5
    if-le p1, v3, :cond_8

    .line 102
    .line 103
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 104
    .line 105
    .line 106
    move-result p3

    .line 107
    if-eqz p3, :cond_9

    .line 108
    .line 109
    :goto_4
    move v2, v4

    .line 110
    goto/16 :goto_7

    .line 111
    .line 112
    :cond_8
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p3

    .line 116
    invoke-virtual {p2, p3}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    :cond_9
    check-cast p0, Lcr/d;

    .line 120
    .line 121
    const/4 p3, 0x2

    .line 122
    if-ne p1, p3, :cond_f

    .line 123
    .line 124
    sget-object p1, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 125
    .line 126
    sget p3, Ler/k;->a:I

    .line 127
    .line 128
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 129
    .line 130
    .line 131
    move-result p3

    .line 132
    if-nez p3, :cond_a

    .line 133
    .line 134
    move-object p1, v1

    .line 135
    goto :goto_5

    .line 136
    :cond_a
    invoke-interface {p1, p2}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    check-cast p1, Landroid/os/Parcelable;

    .line 141
    .line 142
    :goto_5
    check-cast p1, Landroid/os/Bundle;

    .line 143
    .line 144
    invoke-virtual {p2}, Landroid/os/Parcel;->dataAvail()I

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    if-gtz p2, :cond_e

    .line 149
    .line 150
    iget-object p2, p0, Lcr/d;->f:Lcr/e;

    .line 151
    .line 152
    iget-object p2, p2, Lcr/e;->e:Ler/d;

    .line 153
    .line 154
    iget-object p3, p0, Lcr/d;->e:Laq/k;

    .line 155
    .line 156
    iget-object p4, p2, Ler/d;->f:Ljava/lang/Object;

    .line 157
    .line 158
    monitor-enter p4

    .line 159
    :try_start_0
    iget-object v0, p2, Ler/d;->e:Ljava/util/HashSet;

    .line 160
    .line 161
    invoke-virtual {v0, p3}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    monitor-exit p4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 165
    new-instance p3, Ler/b;

    .line 166
    .line 167
    invoke-direct {p3, p2, v4}, Ler/b;-><init>(Ljava/lang/Object;I)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {p2}, Ler/d;->a()Landroid/os/Handler;

    .line 171
    .line 172
    .line 173
    move-result-object p2

    .line 174
    invoke-virtual {p2, p3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 175
    .line 176
    .line 177
    iget-object p2, p0, Lcr/d;->d:Ler/p;

    .line 178
    .line 179
    const-string p3, "onRequestIntegrityToken"

    .line 180
    .line 181
    new-array p4, v2, [Ljava/lang/Object;

    .line 182
    .line 183
    invoke-virtual {p2, p3, p4}, Ler/p;->a(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    iget-object p2, p0, Lcr/d;->f:Lcr/e;

    .line 187
    .line 188
    iget-object p2, p2, Lcr/e;->d:Lmb/e;

    .line 189
    .line 190
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    const-string p2, "error"

    .line 194
    .line 195
    invoke-virtual {p1, p2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 196
    .line 197
    .line 198
    move-result p2

    .line 199
    if-nez p2, :cond_b

    .line 200
    .line 201
    move-object p3, v1

    .line 202
    goto :goto_6

    .line 203
    :cond_b
    new-instance p3, Lcr/a;

    .line 204
    .line 205
    invoke-direct {p3, p2, v1}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 206
    .line 207
    .line 208
    :goto_6
    if-eqz p3, :cond_c

    .line 209
    .line 210
    iget-object p0, p0, Lcr/d;->e:Laq/k;

    .line 211
    .line 212
    invoke-virtual {p0, p3}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 213
    .line 214
    .line 215
    goto :goto_4

    .line 216
    :cond_c
    const-string p2, "token"

    .line 217
    .line 218
    invoke-virtual {p1, p2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object p2

    .line 222
    if-nez p2, :cond_d

    .line 223
    .line 224
    iget-object p0, p0, Lcr/d;->e:Laq/k;

    .line 225
    .line 226
    new-instance p1, Lcr/a;

    .line 227
    .line 228
    const/16 p2, -0x64

    .line 229
    .line 230
    invoke-direct {p1, p2, v1}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 234
    .line 235
    .line 236
    goto :goto_4

    .line 237
    :cond_d
    const-string p3, "request.token.sid"

    .line 238
    .line 239
    invoke-virtual {p1, p3}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 240
    .line 241
    .line 242
    iget-object p1, p0, Lcr/d;->f:Lcr/e;

    .line 243
    .line 244
    iget-object p1, p1, Lcr/e;->b:Ljava/lang/String;

    .line 245
    .line 246
    const-string p1, "IntegrityDialogWrapper"

    .line 247
    .line 248
    invoke-static {}, Landroid/os/Process;->myUid()I

    .line 249
    .line 250
    .line 251
    move-result p3

    .line 252
    invoke-static {}, Landroid/os/Process;->myPid()I

    .line 253
    .line 254
    .line 255
    move-result p4

    .line 256
    const-string v0, "UID: ["

    .line 257
    .line 258
    const-string v1, "]  PID: ["

    .line 259
    .line 260
    const-string v2, "] "

    .line 261
    .line 262
    invoke-static {p3, p4, v0, v1, v2}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p3

    .line 266
    invoke-virtual {p3, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    iget-object p0, p0, Lcr/d;->e:Laq/k;

    .line 270
    .line 271
    new-instance p1, Lcr/h;

    .line 272
    .line 273
    invoke-direct {p1, p2}, Lcr/h;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {p0, p1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 277
    .line 278
    .line 279
    goto/16 :goto_4

    .line 280
    .line 281
    :catchall_0
    move-exception p0

    .line 282
    :try_start_1
    monitor-exit p4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 283
    throw p0

    .line 284
    :cond_e
    new-instance p0, Landroid/os/BadParcelableException;

    .line 285
    .line 286
    const-string p1, "Parcel data not fully consumed, unread size: "

    .line 287
    .line 288
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object p1

    .line 292
    invoke-direct {p0, p1}, Landroid/os/BadParcelableException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw p0

    .line 296
    :cond_f
    :goto_7
    return v2

    .line 297
    :pswitch_6
    if-le p1, v3, :cond_10

    .line 298
    .line 299
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 300
    .line 301
    .line 302
    move-result p4

    .line 303
    if-eqz p4, :cond_11

    .line 304
    .line 305
    goto :goto_8

    .line 306
    :cond_10
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object p4

    .line 310
    invoke-virtual {p2, p4}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    :cond_11
    invoke-virtual {p0, p1, p2, p3}, Lbp/j;->R(ILandroid/os/Parcel;Landroid/os/Parcel;)Z

    .line 314
    .line 315
    .line 316
    move-result v4

    .line 317
    :goto_8
    return v4

    .line 318
    :pswitch_7
    if-le p1, v3, :cond_12

    .line 319
    .line 320
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 321
    .line 322
    .line 323
    move-result p4

    .line 324
    if-eqz p4, :cond_13

    .line 325
    .line 326
    goto :goto_9

    .line 327
    :cond_12
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object p4

    .line 331
    invoke-virtual {p2, p4}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 332
    .line 333
    .line 334
    :cond_13
    invoke-virtual {p0, p1, p2, p3}, Lbp/j;->Q(ILandroid/os/Parcel;Landroid/os/Parcel;)Z

    .line 335
    .line 336
    .line 337
    move-result v4

    .line 338
    :goto_9
    return v4

    .line 339
    :pswitch_8
    if-le p1, v3, :cond_14

    .line 340
    .line 341
    invoke-super {p0, p1, p2, p3, p4}, Landroid/os/Binder;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 342
    .line 343
    .line 344
    move-result p3

    .line 345
    if-eqz p3, :cond_15

    .line 346
    .line 347
    :goto_a
    move v2, v4

    .line 348
    goto :goto_c

    .line 349
    :cond_14
    invoke-virtual {p0}, Landroid/os/Binder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object p3

    .line 353
    invoke-virtual {p2, p3}, Landroid/os/Parcel;->enforceInterface(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    :cond_15
    check-cast p0, Lbp/y;

    .line 357
    .line 358
    if-ne p1, v4, :cond_19

    .line 359
    .line 360
    sget-object p1, Lcom/google/android/gms/common/api/Status;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 361
    .line 362
    sget p3, Lbp/k;->a:I

    .line 363
    .line 364
    invoke-virtual {p2}, Landroid/os/Parcel;->readInt()I

    .line 365
    .line 366
    .line 367
    move-result p3

    .line 368
    if-nez p3, :cond_16

    .line 369
    .line 370
    move-object p1, v1

    .line 371
    goto :goto_b

    .line 372
    :cond_16
    invoke-interface {p1, p2}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object p1

    .line 376
    check-cast p1, Landroid/os/Parcelable;

    .line 377
    .line 378
    :goto_b
    check-cast p1, Lcom/google/android/gms/common/api/Status;

    .line 379
    .line 380
    invoke-virtual {p2}, Landroid/os/Parcel;->dataAvail()I

    .line 381
    .line 382
    .line 383
    move-result p2

    .line 384
    if-gtz p2, :cond_18

    .line 385
    .line 386
    iget-object p0, p0, Lbp/y;->d:Lbp/x;

    .line 387
    .line 388
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 389
    .line 390
    .line 391
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 392
    .line 393
    .line 394
    move-result p2

    .line 395
    if-eqz p2, :cond_17

    .line 396
    .line 397
    iget-object p0, p0, Lbp/x;->g:Laq/k;

    .line 398
    .line 399
    invoke-virtual {p0, v1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 400
    .line 401
    .line 402
    goto :goto_a

    .line 403
    :cond_17
    iget-object p0, p0, Lbp/x;->g:Laq/k;

    .line 404
    .line 405
    const-string p2, "User Action indexing error, please try again."

    .line 406
    .line 407
    invoke-static {p1, p2}, Lbp/m;->a(Lcom/google/android/gms/common/api/Status;Ljava/lang/String;)Lb0/l;

    .line 408
    .line 409
    .line 410
    move-result-object p1

    .line 411
    invoke-virtual {p0, p1}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 412
    .line 413
    .line 414
    goto :goto_a

    .line 415
    :cond_18
    new-instance p0, Landroid/os/BadParcelableException;

    .line 416
    .line 417
    const-string p1, "Parcel data not fully consumed, unread size: "

    .line 418
    .line 419
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object p1

    .line 423
    invoke-direct {p0, p1}, Landroid/os/BadParcelableException;-><init>(Ljava/lang/String;)V

    .line 424
    .line 425
    .line 426
    throw p0

    .line 427
    :cond_19
    :goto_c
    return v2

    .line 428
    nop

    .line 429
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_0
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method
