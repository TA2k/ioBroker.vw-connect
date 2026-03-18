.class public final Lfs/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lfs/b;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget p0, p0, Lfs/b;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x0

    .line 11
    const/4 v1, 0x0

    .line 12
    move v3, v0

    .line 13
    move-object v4, v1

    .line 14
    move-object v5, v4

    .line 15
    move-object v6, v5

    .line 16
    move-object v7, v6

    .line 17
    :goto_0
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-ge v0, p0, :cond_5

    .line 22
    .line 23
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    int-to-char v1, v0

    .line 28
    const/4 v2, 0x1

    .line 29
    if-eq v1, v2, :cond_4

    .line 30
    .line 31
    const/4 v2, 0x2

    .line 32
    if-eq v1, v2, :cond_3

    .line 33
    .line 34
    const/4 v2, 0x3

    .line 35
    if-eq v1, v2, :cond_2

    .line 36
    .line 37
    const/4 v2, 0x4

    .line 38
    if-eq v1, v2, :cond_1

    .line 39
    .line 40
    const/16 v2, 0x3e8

    .line 41
    .line 42
    if-eq v1, v2, :cond_0

    .line 43
    .line 44
    invoke-static {p1, v0}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    invoke-static {p1, v0}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    move v3, v0

    .line 53
    goto :goto_0

    .line 54
    :cond_1
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    move-object v7, v0

    .line 59
    goto :goto_0

    .line 60
    :cond_2
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    move-object v6, v0

    .line 65
    goto :goto_0

    .line 66
    :cond_3
    sget-object v1, Lfs/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 67
    .line 68
    invoke-static {p1, v0, v1}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    check-cast v0, Lfs/h;

    .line 73
    .line 74
    move-object v5, v0

    .line 75
    goto :goto_0

    .line 76
    :cond_4
    invoke-static {p1, v0}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    move-object v4, v0

    .line 81
    goto :goto_0

    .line 82
    :cond_5
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 83
    .line 84
    .line 85
    new-instance v2, Lcom/google/firebase/appindexing/internal/Thing;

    .line 86
    .line 87
    invoke-direct/range {v2 .. v7}, Lcom/google/firebase/appindexing/internal/Thing;-><init>(ILandroid/os/Bundle;Lfs/h;Ljava/lang/String;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    return-object v2

    .line 91
    :pswitch_0
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    const/4 v0, 0x0

    .line 96
    const/4 v1, 0x0

    .line 97
    move v3, v0

    .line 98
    move-object v4, v1

    .line 99
    move-object v5, v4

    .line 100
    move-object v6, v5

    .line 101
    move-object v7, v6

    .line 102
    move-object v8, v7

    .line 103
    move-object v9, v8

    .line 104
    :goto_1
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    if-ge v0, p0, :cond_6

    .line 109
    .line 110
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    int-to-char v1, v0

    .line 115
    packed-switch v1, :pswitch_data_1

    .line 116
    .line 117
    .line 118
    :pswitch_1
    invoke-static {p1, v0}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 119
    .line 120
    .line 121
    goto :goto_1

    .line 122
    :pswitch_2
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    move-object v9, v0

    .line 127
    goto :goto_1

    .line 128
    :pswitch_3
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    move-object v8, v0

    .line 133
    goto :goto_1

    .line 134
    :pswitch_4
    sget-object v1, Lbp/p;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 135
    .line 136
    invoke-static {p1, v0, v1}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    check-cast v0, Lbp/p;

    .line 141
    .line 142
    move-object v7, v0

    .line 143
    goto :goto_1

    .line 144
    :pswitch_5
    invoke-static {p1, v0}, Ljp/xb;->g(Landroid/os/Parcel;I)[Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    move-object v6, v0

    .line 149
    goto :goto_1

    .line 150
    :pswitch_6
    invoke-static {p1, v0}, Ljp/xb;->g(Landroid/os/Parcel;I)[Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    move-object v5, v0

    .line 155
    goto :goto_1

    .line 156
    :pswitch_7
    sget-object v1, Lcom/google/firebase/appindexing/internal/Thing;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 157
    .line 158
    invoke-static {p1, v0, v1}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    check-cast v0, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 163
    .line 164
    move-object v4, v0

    .line 165
    goto :goto_1

    .line 166
    :pswitch_8
    invoke-static {p1, v0}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    move v3, v0

    .line 171
    goto :goto_1

    .line 172
    :cond_6
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 173
    .line 174
    .line 175
    new-instance v2, Lfs/f;

    .line 176
    .line 177
    invoke-direct/range {v2 .. v9}, Lfs/f;-><init>(I[Lcom/google/firebase/appindexing/internal/Thing;[Ljava/lang/String;[Ljava/lang/String;Lbp/p;Ljava/lang/String;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    return-object v2

    .line 181
    :pswitch_9
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 182
    .line 183
    .line 184
    move-result p0

    .line 185
    const/4 v0, 0x0

    .line 186
    const/4 v1, 0x0

    .line 187
    move v3, v0

    .line 188
    move v4, v3

    .line 189
    move-object v5, v1

    .line 190
    move-object v6, v5

    .line 191
    move-object v7, v6

    .line 192
    :goto_2
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-ge v0, p0, :cond_c

    .line 197
    .line 198
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    int-to-char v1, v0

    .line 203
    const/4 v2, 0x1

    .line 204
    if-eq v1, v2, :cond_b

    .line 205
    .line 206
    const/4 v2, 0x2

    .line 207
    if-eq v1, v2, :cond_a

    .line 208
    .line 209
    const/4 v2, 0x3

    .line 210
    if-eq v1, v2, :cond_9

    .line 211
    .line 212
    const/4 v2, 0x4

    .line 213
    if-eq v1, v2, :cond_8

    .line 214
    .line 215
    const/4 v2, 0x5

    .line 216
    if-eq v1, v2, :cond_7

    .line 217
    .line 218
    invoke-static {p1, v0}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 219
    .line 220
    .line 221
    goto :goto_2

    .line 222
    :cond_7
    invoke-static {p1, v0}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    move-object v7, v0

    .line 227
    goto :goto_2

    .line 228
    :cond_8
    invoke-static {p1, v0}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    move-object v6, v0

    .line 233
    goto :goto_2

    .line 234
    :cond_9
    invoke-static {p1, v0}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    move-object v5, v0

    .line 239
    goto :goto_2

    .line 240
    :cond_a
    invoke-static {p1, v0}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 241
    .line 242
    .line 243
    move-result v0

    .line 244
    move v4, v0

    .line 245
    goto :goto_2

    .line 246
    :cond_b
    invoke-static {p1, v0}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 247
    .line 248
    .line 249
    move-result v0

    .line 250
    move v3, v0

    .line 251
    goto :goto_2

    .line 252
    :cond_c
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 253
    .line 254
    .line 255
    new-instance v2, Lfs/h;

    .line 256
    .line 257
    invoke-direct/range {v2 .. v7}, Lfs/h;-><init>(ZILjava/lang/String;Landroid/os/Bundle;Landroid/os/Bundle;)V

    .line 258
    .line 259
    .line 260
    return-object v2

    .line 261
    :pswitch_a
    invoke-static {p1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 262
    .line 263
    .line 264
    move-result p0

    .line 265
    const/4 v0, 0x0

    .line 266
    :goto_3
    invoke-virtual {p1}, Landroid/os/Parcel;->dataPosition()I

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    if-ge v1, p0, :cond_e

    .line 271
    .line 272
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    .line 273
    .line 274
    .line 275
    move-result v1

    .line 276
    int-to-char v2, v1

    .line 277
    const/4 v3, 0x1

    .line 278
    if-eq v2, v3, :cond_d

    .line 279
    .line 280
    invoke-static {p1, v1}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 281
    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_d
    invoke-static {p1, v1}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 285
    .line 286
    .line 287
    move-result v0

    .line 288
    goto :goto_3

    .line 289
    :cond_e
    invoke-static {p1, p0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 290
    .line 291
    .line 292
    new-instance p0, Lfs/a;

    .line 293
    .line 294
    invoke-direct {p0, v0}, Lfs/a;-><init>(I)V

    .line 295
    .line 296
    .line 297
    return-object p0

    .line 298
    nop

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_0
    .end packed-switch

    .line 300
    .line 301
    .line 302
    .line 303
    .line 304
    .line 305
    .line 306
    .line 307
    .line 308
    .line 309
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
    .end packed-switch
.end method

.method public final synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lfs/b;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lcom/google/firebase/appindexing/internal/Thing;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lfs/f;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lfs/h;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lfs/a;

    .line 16
    .line 17
    return-object p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
