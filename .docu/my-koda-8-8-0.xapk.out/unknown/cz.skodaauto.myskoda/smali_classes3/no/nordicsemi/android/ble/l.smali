.class public final Lno/nordicsemi/android/ble/l;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lno/nordicsemi/android/ble/l;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/l;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 12

    .line 1
    iget p1, p0, Lno/nordicsemi/android/ble/l;->a:I

    .line 2
    .line 3
    const/16 v0, 0xa

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    const-string v3, ")"

    .line 8
    .line 9
    const-string v4, "UNKNOWN ("

    .line 10
    .line 11
    const/4 v5, -0x1

    .line 12
    const/4 v6, 0x0

    .line 13
    const-string v7, "android.bluetooth.device.extra.DEVICE"

    .line 14
    .line 15
    const/4 v8, 0x3

    .line 16
    iget-object p0, p0, Lno/nordicsemi/android/ble/l;->b:Ljava/lang/Object;

    .line 17
    .line 18
    packed-switch p1, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    invoke-virtual {p2, v7}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    check-cast p1, Landroid/bluetooth/BluetoothDevice;

    .line 26
    .line 27
    check-cast p0, Lno/nordicsemi/android/ble/e;

    .line 28
    .line 29
    iget-object v0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 30
    .line 31
    iget-object v0, v0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 32
    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-nez v0, :cond_0

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    const-string v0, "android.bluetooth.device.extra.PAIRING_VARIANT"

    .line 53
    .line 54
    invoke-virtual {p2, v0, v6}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    const-string v1, "android.bluetooth.device.extra.PAIRING_KEY"

    .line 59
    .line 60
    invoke-virtual {p2, v1, v5}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    new-instance v1, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v2, "[Broadcast] Action received: android.bluetooth.device.action.PAIRING_REQUEST, pairing variant: "

    .line 67
    .line 68
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    sget-object v2, Lc01/a;->a:[C

    .line 72
    .line 73
    packed-switch v0, :pswitch_data_1

    .line 74
    .line 75
    .line 76
    invoke-static {v4, v0, v3}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    goto :goto_0

    .line 81
    :pswitch_0
    const-string v2, "PAIRING_VARIANT_OOB_CONSENT"

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :pswitch_1
    const-string v2, "PAIRING_VARIANT_DISPLAY_PIN"

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :pswitch_2
    const-string v2, "PAIRING_VARIANT_DISPLAY_PASSKEY"

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :pswitch_3
    const-string v2, "PAIRING_VARIANT_CONSENT"

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :pswitch_4
    const-string v2, "PAIRING_VARIANT_PASSKEY_CONFIRMATION"

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :pswitch_5
    const-string v2, "PAIRING_VARIANT_PASSKEY"

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :pswitch_6
    const-string v2, "PAIRING_VARIANT_PIN"

    .line 100
    .line 101
    :goto_0
    const-string v3, " ("

    .line 102
    .line 103
    const-string v4, "); key: "

    .line 104
    .line 105
    invoke-static {v1, v2, v3, v0, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    invoke-virtual {p0, v8, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p0, p1, v0, p2}, Lno/nordicsemi/android/ble/e;->onPairingRequestReceived(Landroid/bluetooth/BluetoothDevice;II)V

    .line 119
    .line 120
    .line 121
    :cond_1
    :goto_1
    return-void

    .line 122
    :pswitch_7
    invoke-virtual {p2, v7}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    check-cast p1, Landroid/bluetooth/BluetoothDevice;

    .line 127
    .line 128
    const-string v3, "android.bluetooth.device.extra.BOND_STATE"

    .line 129
    .line 130
    invoke-virtual {p2, v3, v5}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    const-string v4, "android.bluetooth.device.extra.PREVIOUS_BOND_STATE"

    .line 135
    .line 136
    invoke-virtual {p2, v4, v5}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 137
    .line 138
    .line 139
    move-result p2

    .line 140
    check-cast p0, Lno/nordicsemi/android/ble/d;

    .line 141
    .line 142
    iget-object v4, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 143
    .line 144
    if-eqz v4, :cond_11

    .line 145
    .line 146
    if-eqz p1, :cond_11

    .line 147
    .line 148
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 153
    .line 154
    invoke-virtual {v5}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result v4

    .line 162
    if-nez v4, :cond_2

    .line 163
    .line 164
    goto/16 :goto_3

    .line 165
    .line 166
    :cond_2
    new-instance v4, La8/w;

    .line 167
    .line 168
    const/16 v5, 0x8

    .line 169
    .line 170
    invoke-direct {v4, v3, v5}, La8/w;-><init>(II)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0, v8, v4}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 174
    .line 175
    .line 176
    const/4 v4, 0x2

    .line 177
    const/4 v5, 0x5

    .line 178
    const/4 v6, 0x4

    .line 179
    const-string v7, "gatt.discoverServices()"

    .line 180
    .line 181
    const-string v9, "Discovering services..."

    .line 182
    .line 183
    packed-switch v3, :pswitch_data_2

    .line 184
    .line 185
    .line 186
    goto/16 :goto_2

    .line 187
    .line 188
    :pswitch_8
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 189
    .line 190
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 191
    .line 192
    .line 193
    move-result p2

    .line 194
    if-lt v6, p2, :cond_3

    .line 195
    .line 196
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 197
    .line 198
    const-string v0, "Device bonded"

    .line 199
    .line 200
    invoke-virtual {p2, v6, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 201
    .line 202
    .line 203
    :cond_3
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 204
    .line 205
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 209
    .line 210
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 214
    .line 215
    if-eqz p2, :cond_5

    .line 216
    .line 217
    iget v0, p2, Lno/nordicsemi/android/ble/i0;->c:I

    .line 218
    .line 219
    if-eq v0, v6, :cond_4

    .line 220
    .line 221
    if-ne v0, v5, :cond_5

    .line 222
    .line 223
    :cond_4
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 224
    .line 225
    .line 226
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 227
    .line 228
    goto/16 :goto_2

    .line 229
    .line 230
    :cond_5
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 231
    .line 232
    if-nez p1, :cond_11

    .line 233
    .line 234
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 235
    .line 236
    if-nez p1, :cond_11

    .line 237
    .line 238
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 239
    .line 240
    if-eqz p1, :cond_11

    .line 241
    .line 242
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 243
    .line 244
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 245
    .line 246
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 247
    .line 248
    .line 249
    move-result p2

    .line 250
    if-lt v4, p2, :cond_6

    .line 251
    .line 252
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 253
    .line 254
    invoke-virtual {p2, v4, v9}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 255
    .line 256
    .line 257
    :cond_6
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 258
    .line 259
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 260
    .line 261
    .line 262
    move-result p2

    .line 263
    if-lt v8, p2, :cond_7

    .line 264
    .line 265
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 266
    .line 267
    invoke-virtual {p0, v8, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 268
    .line 269
    .line 270
    :cond_7
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->discoverServices()Z

    .line 271
    .line 272
    .line 273
    goto/16 :goto_3

    .line 274
    .line 275
    :pswitch_9
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 276
    .line 277
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 278
    .line 279
    .line 280
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 281
    .line 282
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 283
    .line 284
    .line 285
    goto/16 :goto_3

    .line 286
    .line 287
    :pswitch_a
    const/16 v3, 0xc

    .line 288
    .line 289
    const/16 v10, 0xb

    .line 290
    .line 291
    if-ne p2, v10, :cond_d

    .line 292
    .line 293
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 294
    .line 295
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 296
    .line 297
    .line 298
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 299
    .line 300
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 301
    .line 302
    .line 303
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 304
    .line 305
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 306
    .line 307
    .line 308
    move-result p2

    .line 309
    if-lt v5, p2, :cond_8

    .line 310
    .line 311
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 312
    .line 313
    const-string v11, "Bonding failed"

    .line 314
    .line 315
    invoke-virtual {p2, v5, v11}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 316
    .line 317
    .line 318
    :cond_8
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 319
    .line 320
    if-eqz p2, :cond_a

    .line 321
    .line 322
    iget v11, p2, Lno/nordicsemi/android/ble/i0;->c:I

    .line 323
    .line 324
    if-eq v11, v6, :cond_9

    .line 325
    .line 326
    if-eq v11, v5, :cond_9

    .line 327
    .line 328
    const/4 v5, 0x7

    .line 329
    if-eq v11, v5, :cond_9

    .line 330
    .line 331
    if-eq v11, v10, :cond_9

    .line 332
    .line 333
    if-eq v11, v0, :cond_9

    .line 334
    .line 335
    if-ne v11, v3, :cond_a

    .line 336
    .line 337
    :cond_9
    const/4 v0, -0x4

    .line 338
    invoke-virtual {p2, v0, p1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 339
    .line 340
    .line 341
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 342
    .line 343
    :cond_a
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 344
    .line 345
    if-nez p1, :cond_10

    .line 346
    .line 347
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 348
    .line 349
    if-nez p1, :cond_10

    .line 350
    .line 351
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 352
    .line 353
    if-eqz p1, :cond_11

    .line 354
    .line 355
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 356
    .line 357
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 358
    .line 359
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 360
    .line 361
    .line 362
    move-result p2

    .line 363
    if-lt v4, p2, :cond_b

    .line 364
    .line 365
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 366
    .line 367
    invoke-virtual {p2, v4, v9}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 368
    .line 369
    .line 370
    :cond_b
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 371
    .line 372
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 373
    .line 374
    .line 375
    move-result p2

    .line 376
    if-lt v8, p2, :cond_c

    .line 377
    .line 378
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 379
    .line 380
    invoke-virtual {p0, v8, v7}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 381
    .line 382
    .line 383
    :cond_c
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->discoverServices()Z

    .line 384
    .line 385
    .line 386
    goto :goto_3

    .line 387
    :cond_d
    if-ne p2, v3, :cond_10

    .line 388
    .line 389
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->q:Z

    .line 390
    .line 391
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 392
    .line 393
    if-eqz p2, :cond_f

    .line 394
    .line 395
    iget p2, p2, Lno/nordicsemi/android/ble/i0;->c:I

    .line 396
    .line 397
    const/4 v0, 0x6

    .line 398
    if-ne p2, v0, :cond_f

    .line 399
    .line 400
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 401
    .line 402
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 403
    .line 404
    .line 405
    move-result p2

    .line 406
    if-lt v6, p2, :cond_e

    .line 407
    .line 408
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 409
    .line 410
    const-string v0, "Bond information removed"

    .line 411
    .line 412
    invoke-virtual {p2, v6, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 413
    .line 414
    .line 415
    :cond_e
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 416
    .line 417
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 418
    .line 419
    .line 420
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 421
    .line 422
    :cond_f
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 423
    .line 424
    if-nez p1, :cond_10

    .line 425
    .line 426
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->c()V

    .line 427
    .line 428
    .line 429
    :cond_10
    :goto_2
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 430
    .line 431
    .line 432
    :cond_11
    :goto_3
    return-void

    .line 433
    :pswitch_b
    const-string p1, "android.bluetooth.adapter.extra.STATE"

    .line 434
    .line 435
    invoke-virtual {p2, p1, v0}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 436
    .line 437
    .line 438
    move-result p1

    .line 439
    const-string v5, "android.bluetooth.adapter.extra.PREVIOUS_STATE"

    .line 440
    .line 441
    invoke-virtual {p2, v5, v0}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 442
    .line 443
    .line 444
    move-result p2

    .line 445
    check-cast p0, Lno/nordicsemi/android/ble/d;

    .line 446
    .line 447
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 448
    .line 449
    invoke-virtual {v5}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 450
    .line 451
    .line 452
    move-result v5

    .line 453
    if-lt v8, v5, :cond_12

    .line 454
    .line 455
    iget-object v5, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 456
    .line 457
    new-instance v7, Ljava/lang/StringBuilder;

    .line 458
    .line 459
    const-string v9, "[Broadcast] Action received: android.bluetooth.adapter.action.STATE_CHANGED, state changed to "

    .line 460
    .line 461
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 462
    .line 463
    .line 464
    packed-switch p1, :pswitch_data_3

    .line 465
    .line 466
    .line 467
    invoke-static {v4, p1, v3}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    goto :goto_4

    .line 472
    :pswitch_c
    const-string v3, "TURNING OFF"

    .line 473
    .line 474
    goto :goto_4

    .line 475
    :pswitch_d
    const-string v3, "ON"

    .line 476
    .line 477
    goto :goto_4

    .line 478
    :pswitch_e
    const-string v3, "TURNING ON"

    .line 479
    .line 480
    goto :goto_4

    .line 481
    :pswitch_f
    const-string v3, "OFF"

    .line 482
    .line 483
    :goto_4
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 484
    .line 485
    .line 486
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 487
    .line 488
    .line 489
    move-result-object v3

    .line 490
    invoke-virtual {v5, v8, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 491
    .line 492
    .line 493
    :cond_12
    const/16 v3, 0xd

    .line 494
    .line 495
    if-eq p1, v0, :cond_13

    .line 496
    .line 497
    if-eq p1, v3, :cond_13

    .line 498
    .line 499
    goto :goto_5

    .line 500
    :cond_13
    if-eq p2, v3, :cond_18

    .line 501
    .line 502
    if-eq p2, v0, :cond_18

    .line 503
    .line 504
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 505
    .line 506
    const/16 p1, -0x64

    .line 507
    .line 508
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 509
    .line 510
    .line 511
    iput-boolean v6, p0, Lno/nordicsemi/android/ble/d;->o:Z

    .line 512
    .line 513
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 514
    .line 515
    if-eqz p2, :cond_16

    .line 516
    .line 517
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 518
    .line 519
    if-eqz v0, :cond_14

    .line 520
    .line 521
    iget v3, v0, Lno/nordicsemi/android/ble/i0;->c:I

    .line 522
    .line 523
    if-eq v3, v8, :cond_14

    .line 524
    .line 525
    invoke-virtual {v0, p1, p2}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 526
    .line 527
    .line 528
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 529
    .line 530
    :cond_14
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 531
    .line 532
    if-eqz v0, :cond_15

    .line 533
    .line 534
    invoke-virtual {v0, p1, p2}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 535
    .line 536
    .line 537
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 538
    .line 539
    :cond_15
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 540
    .line 541
    if-eqz v0, :cond_16

    .line 542
    .line 543
    invoke-virtual {v0, p1, p2}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 544
    .line 545
    .line 546
    iput-object v2, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 547
    .line 548
    :cond_16
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->q:Z

    .line 549
    .line 550
    iput-boolean v6, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 551
    .line 552
    if-eqz p2, :cond_17

    .line 553
    .line 554
    invoke-virtual {p0, v1, p2}, Lno/nordicsemi/android/ble/d;->B(ILandroid/bluetooth/BluetoothDevice;)V

    .line 555
    .line 556
    .line 557
    :cond_17
    iput-boolean v6, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 558
    .line 559
    iput v6, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 560
    .line 561
    goto :goto_5

    .line 562
    :cond_18
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->c()V

    .line 563
    .line 564
    .line 565
    :goto_5
    return-void

    .line 566
    nop

    .line 567
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_7
    .end packed-switch

    .line 568
    .line 569
    .line 570
    .line 571
    .line 572
    .line 573
    .line 574
    .line 575
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 576
    .line 577
    .line 578
    .line 579
    .line 580
    .line 581
    .line 582
    .line 583
    .line 584
    .line 585
    .line 586
    .line 587
    .line 588
    .line 589
    .line 590
    .line 591
    .line 592
    .line 593
    :pswitch_data_2
    .packed-switch 0xa
        :pswitch_a
        :pswitch_9
        :pswitch_8
    .end packed-switch

    .line 594
    .line 595
    .line 596
    .line 597
    .line 598
    .line 599
    .line 600
    .line 601
    .line 602
    .line 603
    :pswitch_data_3
    .packed-switch 0xa
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
    .end packed-switch
.end method
