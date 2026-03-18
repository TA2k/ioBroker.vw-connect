.class public final Lbp/s;
.super Lhr/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lbp/t;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lbp/s;->g:I

    .line 1
    iput-object p1, p0, Lbp/s;->h:Ljava/lang/Object;

    const/4 p1, 0x0

    const/16 v0, 0x70e5

    const/4 v1, 0x0

    invoke-direct {p0, v1, p1, v0}, Lhr/b0;-><init>([Ljo/d;ZI)V

    return-void
.end method

.method public constructor <init>(Lh6/i;[Ljo/d;ZI)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lbp/s;->g:I

    .line 2
    iput-object p1, p0, Lbp/s;->h:Ljava/lang/Object;

    invoke-direct {p0, p2, p3, p4}, Lhr/b0;-><init>([Ljo/d;ZI)V

    return-void
.end method


# virtual methods
.method public final f(Lko/c;Laq/k;)V
    .locals 6

    .line 1
    iget v0, p0, Lbp/s;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh6/i;

    .line 9
    .line 10
    iget-object p0, p0, Lh6/i;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Llo/n;

    .line 13
    .line 14
    invoke-interface {p0, p1, p2}, Llo/n;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    check-cast p1, Lbp/w;

    .line 19
    .line 20
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Lfs/e;

    .line 25
    .line 26
    new-instance v0, Lbp/r;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-direct {v0, p0, p2, v1}, Lbp/r;-><init>(Ljava/lang/Object;Laq/k;I)V

    .line 30
    .line 31
    .line 32
    iget-object v2, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v2, Lbp/t;

    .line 35
    .line 36
    iget-object v2, v2, Lbp/t;->a:Lfs/f;

    .line 37
    .line 38
    check-cast p1, Lfs/c;

    .line 39
    .line 40
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    iget-object v4, p1, Lbp/a;->e:Ljava/lang/String;

    .line 45
    .line 46
    invoke-virtual {v3, v4}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    sget v4, Lbp/k;->a:I

    .line 50
    .line 51
    invoke-virtual {v3, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 52
    .line 53
    .line 54
    const/4 v0, 0x1

    .line 55
    invoke-virtual {v3, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2, v3, v1}, Lfs/f;->writeToParcel(Landroid/os/Parcel;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    :try_start_0
    iget-object p1, p1, Lbp/a;->d:Landroid/os/IBinder;

    .line 66
    .line 67
    const/16 v4, 0x8

    .line 68
    .line 69
    invoke-interface {p1, v4, v3, v2, v1}, Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2}, Landroid/os/Parcel;->readException()V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3}, Landroid/os/Parcel;->recycle()V

    .line 76
    .line 77
    .line 78
    sget-object p1, Lfs/a;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 79
    .line 80
    invoke-virtual {v2}, Landroid/os/Parcel;->readInt()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    const/4 v4, 0x0

    .line 85
    if-nez v3, :cond_0

    .line 86
    .line 87
    move-object p1, v4

    .line 88
    goto :goto_0

    .line 89
    :cond_0
    invoke-interface {p1, v2}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    check-cast p1, Landroid/os/Parcelable;

    .line 94
    .line 95
    :goto_0
    check-cast p1, Lfs/a;

    .line 96
    .line 97
    invoke-virtual {v2}, Landroid/os/Parcel;->recycle()V

    .line 98
    .line 99
    .line 100
    const/4 v2, 0x2

    .line 101
    if-nez p1, :cond_1

    .line 102
    .line 103
    move p1, v2

    .line 104
    goto :goto_1

    .line 105
    :cond_1
    iget p1, p1, Lfs/a;->d:I

    .line 106
    .line 107
    :goto_1
    const/4 v3, 0x3

    .line 108
    if-ne p1, v3, :cond_6

    .line 109
    .line 110
    const-string p1, "AppIndex"

    .line 111
    .line 112
    const/4 v3, 0x4

    .line 113
    invoke-static {p1, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_2

    .line 118
    .line 119
    move p1, v0

    .line 120
    goto :goto_2

    .line 121
    :cond_2
    invoke-static {p1, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    :goto_2
    if-eqz p1, :cond_3

    .line 126
    .line 127
    const-string p1, "AppIndex"

    .line 128
    .line 129
    const-string v3, "Queue was full. API call will be retried."

    .line 130
    .line 131
    invoke-static {p1, v3}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 132
    .line 133
    .line 134
    :cond_3
    iget-object p1, p2, Laq/k;->a:Laq/t;

    .line 135
    .line 136
    invoke-virtual {p1, v4}, Laq/t;->q(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result p1

    .line 140
    if-eqz p1, :cond_b

    .line 141
    .line 142
    iget-object p1, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast p1, Lbp/t;

    .line 145
    .line 146
    iget-object p1, p1, Lbp/t;->c:Lbp/u;

    .line 147
    .line 148
    iget-object p1, p1, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 149
    .line 150
    monitor-enter p1

    .line 151
    :try_start_1
    iget-object p2, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast p2, Lbp/t;

    .line 154
    .line 155
    iget-object p2, p2, Lbp/t;->c:Lbp/u;

    .line 156
    .line 157
    iget v3, p2, Lbp/u;->g:I

    .line 158
    .line 159
    if-nez v3, :cond_5

    .line 160
    .line 161
    iget-object p2, p2, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 162
    .line 163
    invoke-virtual {p2}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p2

    .line 167
    move-object v4, p2

    .line 168
    check-cast v4, Lbp/t;

    .line 169
    .line 170
    iget-object p0, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast p0, Lbp/t;

    .line 173
    .line 174
    if-ne v4, p0, :cond_4

    .line 175
    .line 176
    move v1, v0

    .line 177
    :cond_4
    invoke-static {v1}, Lno/c0;->k(Z)V

    .line 178
    .line 179
    .line 180
    goto :goto_3

    .line 181
    :catchall_0
    move-exception p0

    .line 182
    goto :goto_4

    .line 183
    :cond_5
    iput v2, p2, Lbp/u;->g:I

    .line 184
    .line 185
    :goto_3
    monitor-exit p1

    .line 186
    goto/16 :goto_7

    .line 187
    .line 188
    :goto_4
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 189
    throw p0

    .line 190
    :cond_6
    if-eq p1, v0, :cond_9

    .line 191
    .line 192
    const-string v2, "API call failed. Status code: "

    .line 193
    .line 194
    invoke-static {p1, v2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    const-string v2, "AppIndex"

    .line 199
    .line 200
    const/4 v3, 0x6

    .line 201
    invoke-static {v2, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 202
    .line 203
    .line 204
    move-result v5

    .line 205
    if-eqz v5, :cond_7

    .line 206
    .line 207
    move v2, v0

    .line 208
    goto :goto_5

    .line 209
    :cond_7
    invoke-static {v2, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 210
    .line 211
    .line 212
    move-result v2

    .line 213
    :goto_5
    if-eqz v2, :cond_8

    .line 214
    .line 215
    const-string v2, "AppIndex"

    .line 216
    .line 217
    invoke-static {v2, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 218
    .line 219
    .line 220
    :cond_8
    iget-object p1, p2, Laq/k;->a:Laq/t;

    .line 221
    .line 222
    invoke-virtual {p1, v4}, Laq/t;->q(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result p1

    .line 226
    if-eqz p1, :cond_9

    .line 227
    .line 228
    iget-object p1, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p1, Lbp/t;

    .line 231
    .line 232
    iget-object p1, p1, Lbp/t;->b:Laq/k;

    .line 233
    .line 234
    new-instance p2, Lb0/l;

    .line 235
    .line 236
    const-string v2, "Indexing error."

    .line 237
    .line 238
    invoke-direct {p2, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {p1, p2}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 242
    .line 243
    .line 244
    :cond_9
    iget-object p1, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast p1, Lbp/t;

    .line 247
    .line 248
    iget-object p1, p1, Lbp/t;->c:Lbp/u;

    .line 249
    .line 250
    iget-object p1, p1, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 251
    .line 252
    monitor-enter p1

    .line 253
    :try_start_2
    iget-object p2, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 254
    .line 255
    check-cast p2, Lbp/t;

    .line 256
    .line 257
    iget-object p2, p2, Lbp/t;->c:Lbp/u;

    .line 258
    .line 259
    iget-object p2, p2, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 260
    .line 261
    invoke-virtual {p2}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object p2

    .line 265
    check-cast p2, Lbp/t;

    .line 266
    .line 267
    iget-object v2, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 268
    .line 269
    check-cast v2, Lbp/t;

    .line 270
    .line 271
    if-ne p2, v2, :cond_a

    .line 272
    .line 273
    goto :goto_6

    .line 274
    :cond_a
    move v0, v1

    .line 275
    :goto_6
    invoke-static {v0}, Lno/c0;->k(Z)V

    .line 276
    .line 277
    .line 278
    iget-object p2, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 279
    .line 280
    check-cast p2, Lbp/t;

    .line 281
    .line 282
    iget-object p2, p2, Lbp/t;->c:Lbp/u;

    .line 283
    .line 284
    iget-object p2, p2, Lbp/u;->f:Ljava/util/ArrayDeque;

    .line 285
    .line 286
    invoke-virtual {p2}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object p2

    .line 290
    move-object v4, p2

    .line 291
    check-cast v4, Lbp/t;

    .line 292
    .line 293
    iget-object p0, p0, Lbp/s;->h:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast p0, Lbp/t;

    .line 296
    .line 297
    iget-object p0, p0, Lbp/t;->c:Lbp/u;

    .line 298
    .line 299
    iput v1, p0, Lbp/u;->g:I

    .line 300
    .line 301
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 302
    :cond_b
    :goto_7
    if-eqz v4, :cond_c

    .line 303
    .line 304
    invoke-virtual {v4}, Lbp/t;->a()V

    .line 305
    .line 306
    .line 307
    :cond_c
    return-void

    .line 308
    :catchall_1
    move-exception p0

    .line 309
    :try_start_3
    monitor-exit p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 310
    throw p0

    .line 311
    :catchall_2
    move-exception p0

    .line 312
    goto :goto_8

    .line 313
    :catch_0
    move-exception p0

    .line 314
    :try_start_4
    invoke-virtual {v2}, Landroid/os/Parcel;->recycle()V

    .line 315
    .line 316
    .line 317
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 318
    :goto_8
    invoke-virtual {v3}, Landroid/os/Parcel;->recycle()V

    .line 319
    .line 320
    .line 321
    throw p0

    .line 322
    nop

    .line 323
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
