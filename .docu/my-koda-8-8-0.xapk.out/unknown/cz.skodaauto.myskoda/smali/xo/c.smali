.class public final Lxo/c;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lis/b;


# direct methods
.method public constructor <init>(Lxo/g;Lis/b;I)V
    .locals 0

    .line 1
    iput p3, p0, Lxo/c;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lxo/c;->e:Lis/b;

    .line 7
    .line 8
    const-string p1, "com.google.android.gms.dck.internal.IDigitalKeyRkeCallback"

    .line 9
    .line 10
    const/4 p2, 0x4

    .line 11
    invoke-direct {p0, p1, p2}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    iput-object p2, p0, Lxo/c;->e:Lis/b;

    .line 16
    .line 17
    const-string p1, "com.google.android.gms.dck.internal.IDigitalKeyConnectionStatusCallback"

    .line 18
    .line 19
    const/4 p2, 0x4

    .line 20
    invoke-direct {p0, p1, p2}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final S(Landroid/os/Parcel;I)Z
    .locals 10

    .line 1
    iget v0, p0, Lxo/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    if-ne p2, v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    sget-object v2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 18
    .line 19
    invoke-static {p1, v2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lko/f;

    .line 24
    .line 25
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 26
    .line 27
    .line 28
    new-instance p1, Lrs/a;

    .line 29
    .line 30
    invoke-direct {p1, p0, p2, v1}, Lrs/a;-><init>(Lxo/c;Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lxo/c;->e:Lis/b;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v0, 0x0

    .line 40
    :goto_0
    return v0

    .line 41
    :pswitch_0
    iget-object p0, p0, Lxo/c;->e:Lis/b;

    .line 42
    .line 43
    const/4 v0, 0x1

    .line 44
    if-eq p2, v0, :cond_5

    .line 45
    .line 46
    const/4 v1, 0x2

    .line 47
    if-eq p2, v1, :cond_4

    .line 48
    .line 49
    const/4 v1, 0x3

    .line 50
    if-eq p2, v1, :cond_3

    .line 51
    .line 52
    const/4 v1, 0x4

    .line 53
    if-eq p2, v1, :cond_2

    .line 54
    .line 55
    const/4 v1, 0x5

    .line 56
    if-eq p2, v1, :cond_1

    .line 57
    .line 58
    const/4 v0, 0x0

    .line 59
    goto/16 :goto_1

    .line 60
    .line 61
    :cond_1
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    sget-object v1, Landroid/os/Bundle;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 66
    .line 67
    invoke-static {p1, v1}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    check-cast v1, Landroid/os/Bundle;

    .line 72
    .line 73
    sget-object v2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 74
    .line 75
    invoke-static {p1, v2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Lko/f;

    .line 80
    .line 81
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 82
    .line 83
    .line 84
    new-instance p1, Lro/f;

    .line 85
    .line 86
    new-instance v2, Lb81/b;

    .line 87
    .line 88
    const/16 v3, 0x1d

    .line 89
    .line 90
    invoke-direct {v2, v3, v1, p2}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    const/16 p2, 0x10

    .line 94
    .line 95
    invoke-direct {p1, v2, p2}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 99
    .line 100
    .line 101
    goto/16 :goto_1

    .line 102
    .line 103
    :cond_2
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    sget-object v2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 112
    .line 113
    invoke-static {p1, v2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    check-cast v2, Lko/f;

    .line 118
    .line 119
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 120
    .line 121
    .line 122
    new-instance p1, Lro/f;

    .line 123
    .line 124
    new-instance v2, Lrs/a;

    .line 125
    .line 126
    invoke-direct {v2, p2, v1}, Lrs/a;-><init>(Ljava/lang/String;I)V

    .line 127
    .line 128
    .line 129
    const/16 p2, 0x10

    .line 130
    .line 131
    invoke-direct {p1, v2, p2}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 135
    .line 136
    .line 137
    goto/16 :goto_1

    .line 138
    .line 139
    :cond_3
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    invoke-virtual {p1}, Landroid/os/Parcel;->createByteArray()[B

    .line 152
    .line 153
    .line 154
    move-result-object v7

    .line 155
    sget-object p2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 156
    .line 157
    invoke-static {p1, p2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 158
    .line 159
    .line 160
    move-result-object p2

    .line 161
    check-cast p2, Lko/f;

    .line 162
    .line 163
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 164
    .line 165
    .line 166
    new-instance p1, Lro/f;

    .line 167
    .line 168
    new-instance v3, Lxo/b;

    .line 169
    .line 170
    const/4 v8, 0x0

    .line 171
    invoke-direct/range {v3 .. v8}, Lxo/b;-><init>(Ljava/lang/String;II[BI)V

    .line 172
    .line 173
    .line 174
    const/16 p2, 0x10

    .line 175
    .line 176
    invoke-direct {p1, v3, p2}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 180
    .line 181
    .line 182
    goto :goto_1

    .line 183
    :cond_4
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v5

    .line 187
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 188
    .line 189
    .line 190
    move-result v6

    .line 191
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 192
    .line 193
    .line 194
    move-result v7

    .line 195
    invoke-virtual {p1}, Landroid/os/Parcel;->createByteArray()[B

    .line 196
    .line 197
    .line 198
    move-result-object v8

    .line 199
    sget-object p2, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 200
    .line 201
    invoke-static {p1, p2}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 202
    .line 203
    .line 204
    move-result-object p2

    .line 205
    check-cast p2, Lko/f;

    .line 206
    .line 207
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 208
    .line 209
    .line 210
    new-instance p1, Lro/f;

    .line 211
    .line 212
    new-instance v4, Lxo/b;

    .line 213
    .line 214
    const/4 v9, 0x1

    .line 215
    invoke-direct/range {v4 .. v9}, Lxo/b;-><init>(Ljava/lang/String;II[BI)V

    .line 216
    .line 217
    .line 218
    const/16 p2, 0x10

    .line 219
    .line 220
    invoke-direct {p1, v4, p2}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 224
    .line 225
    .line 226
    goto :goto_1

    .line 227
    :cond_5
    invoke-virtual {p1}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object p2

    .line 231
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 232
    .line 233
    .line 234
    move-result v1

    .line 235
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 236
    .line 237
    .line 238
    move-result v2

    .line 239
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 240
    .line 241
    .line 242
    move-result v3

    .line 243
    sget-object v4, Lko/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 244
    .line 245
    invoke-static {p1, v4}, Lfp/a;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 246
    .line 247
    .line 248
    move-result-object v4

    .line 249
    check-cast v4, Lko/f;

    .line 250
    .line 251
    invoke-static {p1}, Lfp/a;->b(Landroid/os/Parcel;)V

    .line 252
    .line 253
    .line 254
    new-instance p1, Lro/f;

    .line 255
    .line 256
    new-instance v4, Landroidx/collection/h;

    .line 257
    .line 258
    invoke-direct {v4, p2, v1, v2, v3}, Landroidx/collection/h;-><init>(Ljava/lang/String;III)V

    .line 259
    .line 260
    .line 261
    const/16 p2, 0x10

    .line 262
    .line 263
    invoke-direct {p1, v4, p2}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 267
    .line 268
    .line 269
    :goto_1
    return v0

    .line 270
    nop

    .line 271
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
