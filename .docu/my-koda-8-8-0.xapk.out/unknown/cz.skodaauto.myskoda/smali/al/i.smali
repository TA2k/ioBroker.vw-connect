.class public final synthetic Lal/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lwk0/r0;Lwk0/s0;Ljava/lang/String;)V
    .locals 1

    .line 1
    const/16 v0, 0x10

    iput v0, p0, Lal/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lal/i;->g:Ljava/lang/Object;

    iput-object p2, p0, Lal/i;->e:Ljava/lang/Object;

    iput-object p3, p0, Lal/i;->f:Ljava/lang/Object;

    iput-object p4, p0, Lal/i;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p5, p0, Lal/i;->d:I

    iput-object p1, p0, Lal/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lal/i;->f:Ljava/lang/Object;

    iput-object p3, p0, Lal/i;->g:Ljava/lang/Object;

    iput-object p4, p0, Lal/i;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 3
    iput p5, p0, Lal/i;->d:I

    iput-object p1, p0, Lal/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lal/i;->h:Ljava/lang/Object;

    iput-object p3, p0, Lal/i;->f:Ljava/lang/Object;

    iput-object p4, p0, Lal/i;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)V
    .locals 1

    .line 4
    const/16 v0, 0xb

    iput v0, p0, Lal/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lal/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lal/i;->f:Ljava/lang/Object;

    iput-object p3, p0, Lal/i;->h:Ljava/lang/Object;

    iput-object p4, p0, Lal/i;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/b0;Lay0/k;Ld20/c;Lxf0/d2;)V
    .locals 1

    .line 5
    const/4 v0, 0x2

    iput v0, p0, Lal/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lal/i;->e:Ljava/lang/Object;

    iput-object p2, p0, Lal/i;->g:Ljava/lang/Object;

    iput-object p3, p0, Lal/i;->f:Ljava/lang/Object;

    iput-object p4, p0, Lal/i;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lal/i;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x3

    .line 5
    const/4 v3, 0x1

    .line 6
    const/4 v4, 0x0

    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lal/i;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lay0/k;

    .line 13
    .line 14
    iget-object v1, p0, Lal/i;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lwk0/r0;

    .line 17
    .line 18
    iget-object v2, p0, Lal/i;->f:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Lwk0/s0;

    .line 21
    .line 22
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Ljava/lang/String;

    .line 25
    .line 26
    new-instance v3, Lwk0/q0;

    .line 27
    .line 28
    iget-object v1, v1, Lwk0/r0;->a:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v4, v2, Lwk0/s0;->a:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v2, v2, Lwk0/s0;->c:Ljava/util/List;

    .line 33
    .line 34
    invoke-direct {v3, v1, v2, v4, p0}, Lwk0/q0;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_0
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v0, Ljava/util/List;

    .line 46
    .line 47
    iget-object v1, p0, Lal/i;->h:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v1, Ljava/lang/String;

    .line 50
    .line 51
    iget-object v2, p0, Lal/i;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v2, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 54
    .line 55
    iget-object p0, p0, Lal/i;->g:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Landroid/net/nsd/NsdServiceInfo;

    .line 58
    .line 59
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->M(Ljava/util/List;Ljava/lang/String;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    :pswitch_1
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 67
    .line 68
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v1, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 71
    .line 72
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v2, Ljava/util/List;

    .line 75
    .line 76
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 79
    .line 80
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->b0(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/InternalVehicle;Ljava/util/List;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;)Llx0/b0;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :pswitch_2
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 88
    .line 89
    iget-object v1, p0, Lal/i;->h:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v1, Ljava/lang/String;

    .line 92
    .line 93
    iget-object v2, p0, Lal/i;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v2, Ltechnology/cariad/cat/genx/Antenna;

    .line 96
    .line 97
    iget-object p0, p0, Lal/i;->g:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 100
    .line 101
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->m(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;)Llx0/b0;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    :pswitch_3
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Ltechnology/cariad/cat/genx/Channel;

    .line 109
    .line 110
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v1, Landroid/bluetooth/BluetoothGattService;

    .line 113
    .line 114
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v2, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 117
    .line 118
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast p0, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 121
    .line 122
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;->a(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;Landroid/bluetooth/BluetoothGattCharacteristic;Landroid/bluetooth/BluetoothGattCharacteristic;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0

    .line 127
    :pswitch_4
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 130
    .line 131
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v1, Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 134
    .line 135
    iget-object v2, p0, Lal/i;->h:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v2, Ljava/lang/String;

    .line 138
    .line 139
    iget-object p0, p0, Lal/i;->g:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 142
    .line 143
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->l0(Ltechnology/cariad/cat/genx/ClientManagerDelegate;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;)Llx0/b0;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_5
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 151
    .line 152
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v1, [B

    .line 155
    .line 156
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v2, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 159
    .line 160
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 163
    .line 164
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->h0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)I

    .line 165
    .line 166
    .line 167
    move-result p0

    .line 168
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0

    .line 173
    :pswitch_6
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 176
    .line 177
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v1, [B

    .line 180
    .line 181
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v2, [B

    .line 184
    .line 185
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 188
    .line 189
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->M0(Ltechnology/cariad/cat/genx/Car2PhoneMode;[B[BLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    return-object p0

    .line 194
    :pswitch_7
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;

    .line 197
    .line 198
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v1, Ltechnology/cariad/cat/genx/Client;

    .line 201
    .line 202
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast v2, [B

    .line 205
    .line 206
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast p0, Lkotlin/jvm/internal/b0;

    .line 209
    .line 210
    invoke-static {v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;->j(Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;Ltechnology/cariad/cat/genx/Client;[BLkotlin/jvm/internal/b0;)I

    .line 211
    .line 212
    .line 213
    move-result p0

    .line 214
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    return-object p0

    .line 219
    :pswitch_8
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v0, [B

    .line 222
    .line 223
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v1, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 226
    .line 227
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 230
    .line 231
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast p0, Ljava/lang/Throwable;

    .line 234
    .line 235
    invoke-static {v0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    invoke-static {v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 240
    .line 241
    .line 242
    move-result-object v2

    .line 243
    invoke-static {v2}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    new-instance v3, Ljava/lang/StringBuilder;

    .line 248
    .line 249
    const-string v4, "sendData(): Failed to send \'0x"

    .line 250
    .line 251
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    const-string v0, "\' at \'"

    .line 258
    .line 259
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    const-string v0, "\' to \'"

    .line 266
    .line 267
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 268
    .line 269
    .line 270
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    const-string v0, "\' - error = "

    .line 274
    .line 275
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    return-object p0

    .line 286
    :pswitch_9
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v0, Lnb/l;

    .line 289
    .line 290
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v1, Ljava/util/UUID;

    .line 293
    .line 294
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v2, Leb/n;

    .line 297
    .line 298
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast p0, Landroid/content/Context;

    .line 301
    .line 302
    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v1

    .line 306
    iget-object v3, v0, Lnb/l;->c:Lmb/s;

    .line 307
    .line 308
    invoke-virtual {v3, v1}, Lmb/s;->e(Ljava/lang/String;)Lmb/o;

    .line 309
    .line 310
    .line 311
    move-result-object v3

    .line 312
    if-eqz v3, :cond_2

    .line 313
    .line 314
    iget-object v5, v3, Lmb/o;->b:Leb/h0;

    .line 315
    .line 316
    invoke-virtual {v5}, Leb/h0;->a()Z

    .line 317
    .line 318
    .line 319
    move-result v5

    .line 320
    if-nez v5, :cond_2

    .line 321
    .line 322
    iget-object v0, v0, Lnb/l;->b:Llb/a;

    .line 323
    .line 324
    check-cast v0, Lfb/e;

    .line 325
    .line 326
    const-string v5, "Moving WorkSpec ("

    .line 327
    .line 328
    iget-object v6, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 329
    .line 330
    monitor-enter v6

    .line 331
    :try_start_0
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 332
    .line 333
    .line 334
    move-result-object v7

    .line 335
    sget-object v8, Lfb/e;->l:Ljava/lang/String;

    .line 336
    .line 337
    new-instance v9, Ljava/lang/StringBuilder;

    .line 338
    .line 339
    invoke-direct {v9, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    invoke-virtual {v9, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 343
    .line 344
    .line 345
    const-string v5, ") to the foreground"

    .line 346
    .line 347
    invoke-virtual {v9, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 348
    .line 349
    .line 350
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 351
    .line 352
    .line 353
    move-result-object v5

    .line 354
    invoke-virtual {v7, v8, v5}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    iget-object v5, v0, Lfb/e;->g:Ljava/util/HashMap;

    .line 358
    .line 359
    invoke-virtual {v5, v1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v5

    .line 363
    check-cast v5, Lfb/f0;

    .line 364
    .line 365
    if-eqz v5, :cond_1

    .line 366
    .line 367
    iget-object v7, v0, Lfb/e;->a:Landroid/os/PowerManager$WakeLock;

    .line 368
    .line 369
    if-nez v7, :cond_0

    .line 370
    .line 371
    iget-object v7, v0, Lfb/e;->b:Landroid/content/Context;

    .line 372
    .line 373
    invoke-static {v7}, Lnb/i;->a(Landroid/content/Context;)Landroid/os/PowerManager$WakeLock;

    .line 374
    .line 375
    .line 376
    move-result-object v7

    .line 377
    iput-object v7, v0, Lfb/e;->a:Landroid/os/PowerManager$WakeLock;

    .line 378
    .line 379
    invoke-virtual {v7}, Landroid/os/PowerManager$WakeLock;->acquire()V

    .line 380
    .line 381
    .line 382
    goto :goto_0

    .line 383
    :catchall_0
    move-exception v0

    .line 384
    move-object p0, v0

    .line 385
    goto :goto_1

    .line 386
    :cond_0
    :goto_0
    iget-object v7, v0, Lfb/e;->f:Ljava/util/HashMap;

    .line 387
    .line 388
    invoke-virtual {v7, v1, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    iget-object v1, v0, Lfb/e;->b:Landroid/content/Context;

    .line 392
    .line 393
    iget-object v5, v5, Lfb/f0;->a:Lmb/o;

    .line 394
    .line 395
    invoke-static {v5}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 396
    .line 397
    .line 398
    move-result-object v5

    .line 399
    invoke-static {v1, v5, v2}, Llb/b;->a(Landroid/content/Context;Lmb/i;Leb/n;)Landroid/content/Intent;

    .line 400
    .line 401
    .line 402
    move-result-object v1

    .line 403
    iget-object v0, v0, Lfb/e;->b:Landroid/content/Context;

    .line 404
    .line 405
    invoke-virtual {v0, v1}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 406
    .line 407
    .line 408
    :cond_1
    monitor-exit v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 409
    invoke-static {v3}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 410
    .line 411
    .line 412
    move-result-object v0

    .line 413
    sget-object v1, Llb/b;->m:Ljava/lang/String;

    .line 414
    .line 415
    new-instance v1, Landroid/content/Intent;

    .line 416
    .line 417
    const-class v3, Landroidx/work/impl/foreground/SystemForegroundService;

    .line 418
    .line 419
    invoke-direct {v1, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 420
    .line 421
    .line 422
    const-string v3, "ACTION_NOTIFY"

    .line 423
    .line 424
    invoke-virtual {v1, v3}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 425
    .line 426
    .line 427
    const-string v3, "KEY_NOTIFICATION_ID"

    .line 428
    .line 429
    iget v5, v2, Leb/n;->a:I

    .line 430
    .line 431
    invoke-virtual {v1, v3, v5}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 432
    .line 433
    .line 434
    const-string v3, "KEY_FOREGROUND_SERVICE_TYPE"

    .line 435
    .line 436
    iget v5, v2, Leb/n;->b:I

    .line 437
    .line 438
    invoke-virtual {v1, v3, v5}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 439
    .line 440
    .line 441
    const-string v3, "KEY_NOTIFICATION"

    .line 442
    .line 443
    iget-object v2, v2, Leb/n;->c:Landroid/app/Notification;

    .line 444
    .line 445
    invoke-virtual {v1, v3, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 446
    .line 447
    .line 448
    const-string v2, "KEY_WORKSPEC_ID"

    .line 449
    .line 450
    iget-object v3, v0, Lmb/i;->a:Ljava/lang/String;

    .line 451
    .line 452
    invoke-virtual {v1, v2, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 453
    .line 454
    .line 455
    const-string v2, "KEY_GENERATION"

    .line 456
    .line 457
    iget v0, v0, Lmb/i;->b:I

    .line 458
    .line 459
    invoke-virtual {v1, v2, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 460
    .line 461
    .line 462
    invoke-virtual {p0, v1}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 463
    .line 464
    .line 465
    return-object v4

    .line 466
    :goto_1
    :try_start_1
    monitor-exit v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 467
    throw p0

    .line 468
    :cond_2
    const-string p0, "Calls to setForegroundAsync() must complete before a ListenableWorker signals completion of work by returning an instance of Result."

    .line 469
    .line 470
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 471
    .line 472
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 473
    .line 474
    .line 475
    throw v0

    .line 476
    :pswitch_a
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 477
    .line 478
    check-cast v0, Luu/g;

    .line 479
    .line 480
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 481
    .line 482
    check-cast v1, Ljava/util/List;

    .line 483
    .line 484
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 485
    .line 486
    check-cast v2, Lt4/c;

    .line 487
    .line 488
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 489
    .line 490
    check-cast p0, Ll2/b1;

    .line 491
    .line 492
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 493
    .line 494
    invoke-interface {p0, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 495
    .line 496
    .line 497
    check-cast v1, Ljava/lang/Iterable;

    .line 498
    .line 499
    new-instance p0, Ljava/util/ArrayList;

    .line 500
    .line 501
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 502
    .line 503
    .line 504
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 505
    .line 506
    .line 507
    move-result-object v1

    .line 508
    :cond_3
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 509
    .line 510
    .line 511
    move-result v4

    .line 512
    if-eqz v4, :cond_4

    .line 513
    .line 514
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    move-result-object v4

    .line 518
    check-cast v4, Lm70/r;

    .line 519
    .line 520
    iget-object v4, v4, Lm70/r;->c:Lxj0/f;

    .line 521
    .line 522
    if-eqz v4, :cond_3

    .line 523
    .line 524
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 525
    .line 526
    .line 527
    goto :goto_2

    .line 528
    :cond_4
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 529
    .line 530
    .line 531
    move-result v1

    .line 532
    if-eqz v1, :cond_5

    .line 533
    .line 534
    sget-object p0, Ln70/o;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 535
    .line 536
    const v1, 0x404ccccd    # 3.2f

    .line 537
    .line 538
    .line 539
    invoke-static {p0, v1}, Ljp/wf;->e(Lcom/google/android/gms/maps/model/LatLng;F)Lpv/g;

    .line 540
    .line 541
    .line 542
    move-result-object p0

    .line 543
    goto :goto_3

    .line 544
    :cond_5
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 545
    .line 546
    .line 547
    move-result v1

    .line 548
    if-ne v1, v3, :cond_6

    .line 549
    .line 550
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 551
    .line 552
    .line 553
    move-result-object p0

    .line 554
    check-cast p0, Lxj0/f;

    .line 555
    .line 556
    invoke-static {p0}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 557
    .line 558
    .line 559
    move-result-object p0

    .line 560
    const/high16 v1, 0x41700000    # 15.0f

    .line 561
    .line 562
    invoke-static {p0, v1}, Ljp/wf;->e(Lcom/google/android/gms/maps/model/LatLng;F)Lpv/g;

    .line 563
    .line 564
    .line 565
    move-result-object p0

    .line 566
    goto :goto_3

    .line 567
    :cond_6
    invoke-static {p0}, Llp/pe;->c(Ljava/util/Collection;)Lxj0/v;

    .line 568
    .line 569
    .line 570
    move-result-object p0

    .line 571
    new-instance v1, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 572
    .line 573
    iget-object v3, p0, Lxj0/v;->a:Lxj0/f;

    .line 574
    .line 575
    invoke-static {v3}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 576
    .line 577
    .line 578
    move-result-object v3

    .line 579
    iget-object p0, p0, Lxj0/v;->b:Lxj0/f;

    .line 580
    .line 581
    invoke-static {p0}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 582
    .line 583
    .line 584
    move-result-object p0

    .line 585
    invoke-direct {v1, v3, p0}, Lcom/google/android/gms/maps/model/LatLngBounds;-><init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 586
    .line 587
    .line 588
    sget p0, Ln70/o;->a:F

    .line 589
    .line 590
    invoke-interface {v2, p0}, Lt4/c;->Q(F)I

    .line 591
    .line 592
    .line 593
    move-result p0

    .line 594
    invoke-static {v1, p0}, Ljp/wf;->d(Lcom/google/android/gms/maps/model/LatLngBounds;I)Lpv/g;

    .line 595
    .line 596
    .line 597
    move-result-object p0

    .line 598
    :goto_3
    invoke-virtual {v0, p0}, Luu/g;->e(Lpv/g;)V

    .line 599
    .line 600
    .line 601
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 602
    .line 603
    return-object p0

    .line 604
    :pswitch_b
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 605
    .line 606
    check-cast v0, Lqr0/q;

    .line 607
    .line 608
    iget-object v1, p0, Lal/i;->h:Ljava/lang/Object;

    .line 609
    .line 610
    check-cast v1, Ljava/lang/String;

    .line 611
    .line 612
    iget-object v2, p0, Lal/i;->f:Ljava/lang/Object;

    .line 613
    .line 614
    check-cast v2, Lmb0/i;

    .line 615
    .line 616
    iget-object p0, p0, Lal/i;->g:Ljava/lang/Object;

    .line 617
    .line 618
    check-cast p0, Ljava/lang/Boolean;

    .line 619
    .line 620
    new-instance v5, Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;

    .line 621
    .line 622
    invoke-static {v0}, Ljb0/k;->a(Lqr0/q;)Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 623
    .line 624
    .line 625
    move-result-object v0

    .line 626
    if-nez v1, :cond_7

    .line 627
    .line 628
    move-object v1, v4

    .line 629
    :cond_7
    const-string v6, "<this>"

    .line 630
    .line 631
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 632
    .line 633
    .line 634
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 635
    .line 636
    .line 637
    move-result v2

    .line 638
    if-eqz v2, :cond_9

    .line 639
    .line 640
    if-eq v2, v3, :cond_8

    .line 641
    .line 642
    goto :goto_4

    .line 643
    :cond_8
    const-string v4, "AUTOMATIC"

    .line 644
    .line 645
    goto :goto_4

    .line 646
    :cond_9
    const-string v4, "ELECTRIC"

    .line 647
    .line 648
    :goto_4
    invoke-direct {v5, v0, v1, v4, p0}, Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;-><init>(Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 649
    .line 650
    .line 651
    return-object v5

    .line 652
    :pswitch_c
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 653
    .line 654
    check-cast v0, Lh2/r8;

    .line 655
    .line 656
    iget-object v3, p0, Lal/i;->f:Ljava/lang/Object;

    .line 657
    .line 658
    check-cast v3, Lvy0/b0;

    .line 659
    .line 660
    iget-object v5, p0, Lal/i;->g:Ljava/lang/Object;

    .line 661
    .line 662
    check-cast v5, Lc1/c;

    .line 663
    .line 664
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 665
    .line 666
    check-cast p0, Lay0/a;

    .line 667
    .line 668
    invoke-virtual {v0}, Lh2/r8;->c()Lh2/s8;

    .line 669
    .line 670
    .line 671
    move-result-object v6

    .line 672
    sget-object v7, Lh2/s8;->e:Lh2/s8;

    .line 673
    .line 674
    if-ne v6, v7, :cond_a

    .line 675
    .line 676
    iget-object v6, v0, Lh2/r8;->e:Li2/p;

    .line 677
    .line 678
    invoke-virtual {v6}, Li2/p;->d()Li2/u0;

    .line 679
    .line 680
    .line 681
    move-result-object v6

    .line 682
    sget-object v7, Lh2/s8;->f:Lh2/s8;

    .line 683
    .line 684
    iget-object v6, v6, Li2/u0;->a:Ljava/util/Map;

    .line 685
    .line 686
    invoke-interface {v6, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 687
    .line 688
    .line 689
    move-result v6

    .line 690
    if-eqz v6, :cond_a

    .line 691
    .line 692
    new-instance p0, Lh2/e6;

    .line 693
    .line 694
    invoke-direct {p0, v5, v4, v1}, Lh2/e6;-><init>(Lc1/c;Lkotlin/coroutines/Continuation;I)V

    .line 695
    .line 696
    .line 697
    invoke-static {v3, v4, v4, p0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 698
    .line 699
    .line 700
    new-instance p0, Lh2/i0;

    .line 701
    .line 702
    const/4 v1, 0x6

    .line 703
    invoke-direct {p0, v0, v4, v1}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 704
    .line 705
    .line 706
    invoke-static {v3, v4, v4, p0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 707
    .line 708
    .line 709
    goto :goto_5

    .line 710
    :cond_a
    new-instance v1, Lh2/i0;

    .line 711
    .line 712
    const/4 v5, 0x7

    .line 713
    invoke-direct {v1, v0, v4, v5}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 714
    .line 715
    .line 716
    invoke-static {v3, v4, v4, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 717
    .line 718
    .line 719
    move-result-object v0

    .line 720
    new-instance v1, Laj0/c;

    .line 721
    .line 722
    const/16 v2, 0x1a

    .line 723
    .line 724
    invoke-direct {v1, p0, v2}, Laj0/c;-><init>(Lay0/a;I)V

    .line 725
    .line 726
    .line 727
    invoke-virtual {v0, v1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 728
    .line 729
    .line 730
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 731
    .line 732
    return-object p0

    .line 733
    :pswitch_d
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 734
    .line 735
    check-cast v0, Lvy0/b0;

    .line 736
    .line 737
    iget-object v1, p0, Lal/i;->g:Ljava/lang/Object;

    .line 738
    .line 739
    check-cast v1, Lay0/k;

    .line 740
    .line 741
    iget-object v3, p0, Lal/i;->f:Ljava/lang/Object;

    .line 742
    .line 743
    check-cast v3, Ld20/c;

    .line 744
    .line 745
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 746
    .line 747
    check-cast p0, Lxf0/d2;

    .line 748
    .line 749
    new-instance v5, Ldm0/h;

    .line 750
    .line 751
    const/16 v6, 0xb

    .line 752
    .line 753
    invoke-direct {v5, p0, v4, v6}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 754
    .line 755
    .line 756
    invoke-static {v0, v4, v4, v5, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 757
    .line 758
    .line 759
    iget-object p0, v3, Ld20/c;->b:Ljava/lang/String;

    .line 760
    .line 761
    invoke-interface {v1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 762
    .line 763
    .line 764
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 765
    .line 766
    return-object p0

    .line 767
    :pswitch_e
    iget-object v7, p0, Lal/i;->e:Ljava/lang/Object;

    .line 768
    .line 769
    iget-object v0, p0, Lal/i;->f:Ljava/lang/Object;

    .line 770
    .line 771
    check-cast v0, Lc1/g0;

    .line 772
    .line 773
    iget-object v8, p0, Lal/i;->g:Ljava/lang/Object;

    .line 774
    .line 775
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 776
    .line 777
    move-object v5, p0

    .line 778
    check-cast v5, Lc1/f0;

    .line 779
    .line 780
    iget-object p0, v0, Lc1/g0;->d:Ljava/lang/Object;

    .line 781
    .line 782
    invoke-virtual {v7, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 783
    .line 784
    .line 785
    move-result p0

    .line 786
    if-eqz p0, :cond_b

    .line 787
    .line 788
    iget-object p0, v0, Lc1/g0;->e:Ljava/lang/Object;

    .line 789
    .line 790
    invoke-virtual {v8, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 791
    .line 792
    .line 793
    move-result p0

    .line 794
    if-nez p0, :cond_c

    .line 795
    .line 796
    :cond_b
    iput-object v7, v0, Lc1/g0;->d:Ljava/lang/Object;

    .line 797
    .line 798
    iput-object v8, v0, Lc1/g0;->e:Ljava/lang/Object;

    .line 799
    .line 800
    new-instance v4, Lc1/n1;

    .line 801
    .line 802
    iget-object v6, v0, Lc1/g0;->f:Lc1/b2;

    .line 803
    .line 804
    const/4 v9, 0x0

    .line 805
    invoke-direct/range {v4 .. v9}, Lc1/n1;-><init>(Lc1/j;Lc1/b2;Ljava/lang/Object;Ljava/lang/Object;Lc1/p;)V

    .line 806
    .line 807
    .line 808
    iput-object v4, v0, Lc1/g0;->h:Lc1/n1;

    .line 809
    .line 810
    iget-object p0, v0, Lc1/g0;->l:Lc1/i0;

    .line 811
    .line 812
    iget-object p0, p0, Lc1/i0;->b:Ll2/j1;

    .line 813
    .line 814
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 815
    .line 816
    invoke-virtual {p0, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 817
    .line 818
    .line 819
    iput-boolean v1, v0, Lc1/g0;->i:Z

    .line 820
    .line 821
    iput-boolean v3, v0, Lc1/g0;->j:Z

    .line 822
    .line 823
    :cond_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 824
    .line 825
    return-object p0

    .line 826
    :pswitch_f
    iget-object v0, p0, Lal/i;->e:Ljava/lang/Object;

    .line 827
    .line 828
    check-cast v0, Lc3/j;

    .line 829
    .line 830
    iget-object v1, p0, Lal/i;->f:Ljava/lang/Object;

    .line 831
    .line 832
    check-cast v1, Llh/g;

    .line 833
    .line 834
    iget-object v2, p0, Lal/i;->g:Ljava/lang/Object;

    .line 835
    .line 836
    check-cast v2, Lay0/k;

    .line 837
    .line 838
    iget-object p0, p0, Lal/i;->h:Ljava/lang/Object;

    .line 839
    .line 840
    check-cast p0, Ljava/lang/String;

    .line 841
    .line 842
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 843
    .line 844
    .line 845
    iget-object v0, v1, Llh/g;->a:Ljava/lang/String;

    .line 846
    .line 847
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 848
    .line 849
    .line 850
    move-result v0

    .line 851
    if-nez v0, :cond_d

    .line 852
    .line 853
    goto :goto_6

    .line 854
    :cond_d
    iget-object v0, v1, Llh/g;->a:Ljava/lang/String;

    .line 855
    .line 856
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 857
    .line 858
    .line 859
    move-result v0

    .line 860
    if-eqz v0, :cond_e

    .line 861
    .line 862
    :goto_6
    new-instance v0, Llh/d;

    .line 863
    .line 864
    invoke-direct {v0, p0}, Llh/d;-><init>(Ljava/lang/String;)V

    .line 865
    .line 866
    .line 867
    invoke-interface {v2, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 868
    .line 869
    .line 870
    :cond_e
    sget-object p0, Llh/c;->a:Llh/c;

    .line 871
    .line 872
    invoke-interface {v2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 873
    .line 874
    .line 875
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 876
    .line 877
    return-object p0

    .line 878
    nop

    .line 879
    :pswitch_data_0
    .packed-switch 0x0
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
