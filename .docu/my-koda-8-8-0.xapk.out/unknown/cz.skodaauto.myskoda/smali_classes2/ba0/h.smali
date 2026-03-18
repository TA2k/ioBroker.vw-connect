.class public final synthetic Lba0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p3, p0, Lba0/h;->d:I

    iput p1, p0, Lba0/h;->e:I

    iput-object p2, p0, Lba0/h;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 2
    iput p3, p0, Lba0/h;->d:I

    iput-object p1, p0, Lba0/h;->f:Ljava/lang/Object;

    iput p2, p0, Lba0/h;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lk01/p;ILk01/b;)V
    .locals 0

    .line 3
    const/4 p3, 0x4

    iput p3, p0, Lba0/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lba0/h;->f:Ljava/lang/Object;

    iput p2, p0, Lba0/h;->e:I

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lba0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lfd/d;

    .line 9
    .line 10
    iget p0, p0, Lba0/h;->e:I

    .line 11
    .line 12
    iget-object v0, v0, Lfd/d;->c:Lay0/k;

    .line 13
    .line 14
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;

    .line 27
    .line 28
    iget p0, p0, Lba0/h;->e:I

    .line 29
    .line 30
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;->d(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/communication/ServiceCommunicationFacade;I)Llx0/b0;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_1
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Ll2/b1;

    .line 38
    .line 39
    iget p0, p0, Lba0/h;->e:I

    .line 40
    .line 41
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-interface {v0, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_2
    iget v0, p0, Lba0/h;->e:I

    .line 52
    .line 53
    iget-object p0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Landroid/content/Intent;

    .line 56
    .line 57
    new-instance v1, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    const-string v2, "(MDK) Pairing result, code="

    .line 60
    .line 61
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v0, ". Intent="

    .line 68
    .line 69
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    :pswitch_3
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Ljava/lang/String;

    .line 83
    .line 84
    iget p0, p0, Lba0/h;->e:I

    .line 85
    .line 86
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->L(ILjava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_4
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 94
    .line 95
    iget p0, p0, Lba0/h;->e:I

    .line 96
    .line 97
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->i1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)Llx0/b0;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :pswitch_5
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;

    .line 105
    .line 106
    iget p0, p0, Lba0/h;->e:I

    .line 107
    .line 108
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;->i(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/communication/PPEServiceCommunication;I)Llx0/b0;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0

    .line 113
    :pswitch_6
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Lorg/altbeacon/beacon/Region;

    .line 116
    .line 117
    iget p0, p0, Lba0/h;->e:I

    .line 118
    .line 119
    new-instance v1, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    const-string v2, "didDetermineStateForRegion(): region = "

    .line 122
    .line 123
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    const-string v0, ", state = "

    .line 130
    .line 131
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    return-object p0

    .line 142
    :pswitch_7
    iget v0, p0, Lba0/h;->e:I

    .line 143
    .line 144
    iget-object p0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast p0, Lay0/a;

    .line 147
    .line 148
    new-instance v1, Lp1/b;

    .line 149
    .line 150
    const/4 v2, 0x0

    .line 151
    invoke-direct {v1, v0, v2, p0}, Lp1/b;-><init>(IFLay0/a;)V

    .line 152
    .line 153
    .line 154
    return-object v1

    .line 155
    :pswitch_8
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Lmy/t;

    .line 158
    .line 159
    iget p0, p0, Lba0/h;->e:I

    .line 160
    .line 161
    new-instance v1, Llj0/a;

    .line 162
    .line 163
    iget-object v0, v0, Lmy/t;->v:Lij0/a;

    .line 164
    .line 165
    check-cast v0, Ljj0/f;

    .line 166
    .line 167
    invoke-virtual {v0, p0}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    invoke-direct {v1, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    return-object v1

    .line 175
    :pswitch_9
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Lk01/p;

    .line 178
    .line 179
    iget p0, p0, Lba0/h;->e:I

    .line 180
    .line 181
    iget-object v1, v0, Lk01/p;->n:Lk01/a0;

    .line 182
    .line 183
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 184
    .line 185
    .line 186
    monitor-enter v0

    .line 187
    :try_start_0
    iget-object v1, v0, Lk01/p;->B:Ljava/util/LinkedHashSet;

    .line 188
    .line 189
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    invoke-interface {v1, p0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 194
    .line 195
    .line 196
    monitor-exit v0

    .line 197
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    return-object p0

    .line 200
    :catchall_0
    move-exception p0

    .line 201
    monitor-exit v0

    .line 202
    throw p0

    .line 203
    :pswitch_a
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Lh50/s0;

    .line 206
    .line 207
    iget p0, p0, Lba0/h;->e:I

    .line 208
    .line 209
    new-instance v1, Llj0/a;

    .line 210
    .line 211
    iget-object v0, v0, Lh50/s0;->t:Lij0/a;

    .line 212
    .line 213
    check-cast v0, Ljj0/f;

    .line 214
    .line 215
    invoke-virtual {v0, p0}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    invoke-direct {v1, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    return-object v1

    .line 223
    :pswitch_b
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v0, Lh50/d0;

    .line 226
    .line 227
    iget p0, p0, Lba0/h;->e:I

    .line 228
    .line 229
    new-instance v1, Llj0/a;

    .line 230
    .line 231
    iget-object v0, v0, Lh50/d0;->I:Lij0/a;

    .line 232
    .line 233
    check-cast v0, Ljj0/f;

    .line 234
    .line 235
    invoke-virtual {v0, p0}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    invoke-direct {v1, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 240
    .line 241
    .line 242
    return-object v1

    .line 243
    :pswitch_c
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 244
    .line 245
    check-cast v0, Landroidx/collection/h;

    .line 246
    .line 247
    iget p0, p0, Lba0/h;->e:I

    .line 248
    .line 249
    iget-object v0, v0, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 250
    .line 251
    check-cast v0, Lg4/l0;

    .line 252
    .line 253
    iget-object v0, v0, Lg4/l0;->b:Lg4/o;

    .line 254
    .line 255
    invoke-virtual {v0, p0}, Lg4/o;->d(I)I

    .line 256
    .line 257
    .line 258
    move-result p0

    .line 259
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    return-object p0

    .line 264
    :pswitch_d
    iget-object v0, p0, Lba0/h;->f:Ljava/lang/Object;

    .line 265
    .line 266
    check-cast v0, Lba0/q;

    .line 267
    .line 268
    iget p0, p0, Lba0/h;->e:I

    .line 269
    .line 270
    new-instance v1, Llj0/a;

    .line 271
    .line 272
    iget-object v0, v0, Lba0/q;->m:Lij0/a;

    .line 273
    .line 274
    check-cast v0, Ljj0/f;

    .line 275
    .line 276
    invoke-virtual {v0, p0}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    invoke-direct {v1, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    return-object v1

    .line 284
    nop

    .line 285
    :pswitch_data_0
    .packed-switch 0x0
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
