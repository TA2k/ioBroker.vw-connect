.class public final Lkg/l0;
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
    iput p1, p0, Lkg/l0;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static a(Lno/h;Landroid/os/Parcel;I)V
    .locals 4

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lno/h;->d:I

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    const/4 v3, 0x4

    .line 11
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    iget v1, p0, Lno/h;->e:I

    .line 18
    .line 19
    const/4 v2, 0x2

    .line 20
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 24
    .line 25
    .line 26
    iget v1, p0, Lno/h;->f:I

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lno/h;->g:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {p1, v1, v3}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    const/4 v1, 0x5

    .line 41
    iget-object v2, p0, Lno/h;->h:Landroid/os/IBinder;

    .line 42
    .line 43
    invoke-static {p1, v1, v2}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 44
    .line 45
    .line 46
    const/4 v1, 0x6

    .line 47
    iget-object v2, p0, Lno/h;->i:[Lcom/google/android/gms/common/api/Scope;

    .line 48
    .line 49
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 50
    .line 51
    .line 52
    const/4 v1, 0x7

    .line 53
    iget-object v2, p0, Lno/h;->j:Landroid/os/Bundle;

    .line 54
    .line 55
    invoke-static {p1, v1, v2}, Ljp/dc;->f(Landroid/os/Parcel;ILandroid/os/Bundle;)V

    .line 56
    .line 57
    .line 58
    const/16 v1, 0x8

    .line 59
    .line 60
    iget-object v2, p0, Lno/h;->k:Landroid/accounts/Account;

    .line 61
    .line 62
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 63
    .line 64
    .line 65
    const/16 v1, 0xa

    .line 66
    .line 67
    iget-object v2, p0, Lno/h;->l:[Ljo/d;

    .line 68
    .line 69
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 70
    .line 71
    .line 72
    const/16 v1, 0xb

    .line 73
    .line 74
    iget-object v2, p0, Lno/h;->m:[Ljo/d;

    .line 75
    .line 76
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 77
    .line 78
    .line 79
    iget-boolean p2, p0, Lno/h;->n:Z

    .line 80
    .line 81
    const/16 v1, 0xc

    .line 82
    .line 83
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 87
    .line 88
    .line 89
    iget p2, p0, Lno/h;->o:I

    .line 90
    .line 91
    const/16 v1, 0xd

    .line 92
    .line 93
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 97
    .line 98
    .line 99
    iget-boolean p2, p0, Lno/h;->p:Z

    .line 100
    .line 101
    const/16 v1, 0xe

    .line 102
    .line 103
    invoke-static {p1, v1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 107
    .line 108
    .line 109
    const/16 p2, 0xf

    .line 110
    .line 111
    iget-object p0, p0, Lno/h;->q:Ljava/lang/String;

    .line 112
    .line 113
    invoke-static {p1, p0, p2}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 114
    .line 115
    .line 116
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 117
    .line 118
    .line 119
    return-void
.end method


# virtual methods
.method public final createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 41

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v0, v0, Lkg/l0;->a:I

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    move-object v4, v3

    .line 17
    move v3, v2

    .line 18
    :goto_0
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    if-ge v5, v0, :cond_3

    .line 23
    .line 24
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    int-to-char v6, v5

    .line 29
    const/4 v7, 0x1

    .line 30
    if-eq v6, v7, :cond_2

    .line 31
    .line 32
    const/4 v7, 0x2

    .line 33
    if-eq v6, v7, :cond_1

    .line 34
    .line 35
    const/4 v7, 0x3

    .line 36
    if-eq v6, v7, :cond_0

    .line 37
    .line 38
    invoke-static {v1, v5}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-static {v1, v5}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    invoke-static {v1, v5}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    sget-object v4, Lcom/google/android/gms/location/LocationRequest;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 53
    .line 54
    invoke-static {v1, v5, v4}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    goto :goto_0

    .line 59
    :cond_3
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 60
    .line 61
    .line 62
    new-instance v0, Lpp/e;

    .line 63
    .line 64
    invoke-direct {v0, v4, v2, v3}, Lpp/e;-><init>(Ljava/util/ArrayList;ZZ)V

    .line 65
    .line 66
    .line 67
    return-object v0

    .line 68
    :pswitch_0
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    sget-object v2, Lcom/google/android/gms/location/LocationResult;->e:Ljava/util/List;

    .line 73
    .line 74
    :goto_1
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-ge v3, v0, :cond_5

    .line 79
    .line 80
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    int-to-char v4, v3

    .line 85
    const/4 v5, 0x1

    .line 86
    if-eq v4, v5, :cond_4

    .line 87
    .line 88
    invoke-static {v1, v3}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_4
    sget-object v2, Landroid/location/Location;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 93
    .line 94
    invoke-static {v1, v3, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    goto :goto_1

    .line 99
    :cond_5
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 100
    .line 101
    .line 102
    new-instance v0, Lcom/google/android/gms/location/LocationResult;

    .line 103
    .line 104
    invoke-direct {v0, v2}, Lcom/google/android/gms/location/LocationResult;-><init>(Ljava/util/List;)V

    .line 105
    .line 106
    .line 107
    return-object v0

    .line 108
    :pswitch_1
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    new-instance v2, Landroid/os/WorkSource;

    .line 113
    .line 114
    invoke-direct {v2}, Landroid/os/WorkSource;-><init>()V

    .line 115
    .line 116
    .line 117
    const/4 v3, 0x0

    .line 118
    const/4 v4, 0x0

    .line 119
    const-wide/16 v5, -0x1

    .line 120
    .line 121
    const/4 v7, 0x0

    .line 122
    const v8, 0x7fffffff

    .line 123
    .line 124
    .line 125
    const-wide v9, 0x7fffffffffffffffL

    .line 126
    .line 127
    .line 128
    .line 129
    .line 130
    const-wide/16 v11, 0x0

    .line 131
    .line 132
    const-wide/32 v13, 0x927c0

    .line 133
    .line 134
    .line 135
    const-wide/32 v15, 0x36ee80

    .line 136
    .line 137
    .line 138
    const/16 v17, 0x66

    .line 139
    .line 140
    move-object/from16 v38, v2

    .line 141
    .line 142
    move-object/from16 v39, v3

    .line 143
    .line 144
    move/from16 v32, v4

    .line 145
    .line 146
    move/from16 v35, v32

    .line 147
    .line 148
    move/from16 v36, v35

    .line 149
    .line 150
    move/from16 v37, v36

    .line 151
    .line 152
    move-wide/from16 v33, v5

    .line 153
    .line 154
    move/from16 v31, v7

    .line 155
    .line 156
    move/from16 v30, v8

    .line 157
    .line 158
    move-wide/from16 v26, v9

    .line 159
    .line 160
    move-wide/from16 v28, v26

    .line 161
    .line 162
    move-wide/from16 v24, v11

    .line 163
    .line 164
    move-wide/from16 v22, v13

    .line 165
    .line 166
    move-wide/from16 v20, v15

    .line 167
    .line 168
    move/from16 v19, v17

    .line 169
    .line 170
    :goto_2
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 171
    .line 172
    .line 173
    move-result v2

    .line 174
    if-ge v2, v0, :cond_6

    .line 175
    .line 176
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    int-to-char v3, v2

    .line 181
    packed-switch v3, :pswitch_data_1

    .line 182
    .line 183
    .line 184
    :pswitch_2
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 185
    .line 186
    .line 187
    goto :goto_2

    .line 188
    :pswitch_3
    sget-object v3, Lgp/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 189
    .line 190
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    check-cast v2, Lgp/g;

    .line 195
    .line 196
    move-object/from16 v39, v2

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :pswitch_4
    sget-object v3, Landroid/os/WorkSource;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 200
    .line 201
    invoke-static {v1, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    check-cast v2, Landroid/os/WorkSource;

    .line 206
    .line 207
    move-object/from16 v38, v2

    .line 208
    .line 209
    goto :goto_2

    .line 210
    :pswitch_5
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 211
    .line 212
    .line 213
    move-result v2

    .line 214
    move/from16 v37, v2

    .line 215
    .line 216
    goto :goto_2

    .line 217
    :pswitch_6
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 218
    .line 219
    .line 220
    move-result v2

    .line 221
    move/from16 v36, v2

    .line 222
    .line 223
    goto :goto_2

    .line 224
    :pswitch_7
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 225
    .line 226
    .line 227
    move-result v2

    .line 228
    move/from16 v35, v2

    .line 229
    .line 230
    goto :goto_2

    .line 231
    :pswitch_8
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 232
    .line 233
    .line 234
    move-result-wide v2

    .line 235
    move-wide/from16 v33, v2

    .line 236
    .line 237
    goto :goto_2

    .line 238
    :pswitch_9
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 239
    .line 240
    .line 241
    move-result-wide v2

    .line 242
    move-wide/from16 v28, v2

    .line 243
    .line 244
    goto :goto_2

    .line 245
    :pswitch_a
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 246
    .line 247
    .line 248
    move-result v2

    .line 249
    move/from16 v32, v2

    .line 250
    .line 251
    goto :goto_2

    .line 252
    :pswitch_b
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 253
    .line 254
    .line 255
    move-result-wide v2

    .line 256
    move-wide/from16 v24, v2

    .line 257
    .line 258
    goto :goto_2

    .line 259
    :pswitch_c
    invoke-static {v1, v2}, Ljp/xb;->o(Landroid/os/Parcel;I)F

    .line 260
    .line 261
    .line 262
    move-result v2

    .line 263
    move/from16 v31, v2

    .line 264
    .line 265
    goto :goto_2

    .line 266
    :pswitch_d
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    move/from16 v30, v2

    .line 271
    .line 272
    goto :goto_2

    .line 273
    :pswitch_e
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 274
    .line 275
    .line 276
    move-result-wide v2

    .line 277
    move-wide/from16 v26, v2

    .line 278
    .line 279
    goto :goto_2

    .line 280
    :pswitch_f
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 281
    .line 282
    .line 283
    move-result-wide v2

    .line 284
    move-wide/from16 v22, v2

    .line 285
    .line 286
    goto :goto_2

    .line 287
    :pswitch_10
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 288
    .line 289
    .line 290
    move-result-wide v2

    .line 291
    move-wide/from16 v20, v2

    .line 292
    .line 293
    goto :goto_2

    .line 294
    :pswitch_11
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 295
    .line 296
    .line 297
    move-result v2

    .line 298
    move/from16 v19, v2

    .line 299
    .line 300
    goto/16 :goto_2

    .line 301
    .line 302
    :cond_6
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 303
    .line 304
    .line 305
    new-instance v18, Lcom/google/android/gms/location/LocationRequest;

    .line 306
    .line 307
    invoke-direct/range {v18 .. v39}, Lcom/google/android/gms/location/LocationRequest;-><init>(IJJJJJIFZJIIZLandroid/os/WorkSource;Lgp/g;)V

    .line 308
    .line 309
    .line 310
    return-object v18

    .line 311
    :pswitch_12
    invoke-static {v1}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 312
    .line 313
    .line 314
    move-result v0

    .line 315
    const/4 v2, 0x0

    .line 316
    const-wide/16 v3, 0x0

    .line 317
    .line 318
    const/4 v5, 0x1

    .line 319
    const/16 v6, 0x3e8

    .line 320
    .line 321
    move-object v13, v2

    .line 322
    move-wide v11, v3

    .line 323
    move v9, v5

    .line 324
    move v10, v9

    .line 325
    move v8, v6

    .line 326
    :goto_3
    invoke-virtual {v1}, Landroid/os/Parcel;->dataPosition()I

    .line 327
    .line 328
    .line 329
    move-result v2

    .line 330
    if-ge v2, v0, :cond_7

    .line 331
    .line 332
    invoke-virtual {v1}, Landroid/os/Parcel;->readInt()I

    .line 333
    .line 334
    .line 335
    move-result v2

    .line 336
    int-to-char v3, v2

    .line 337
    packed-switch v3, :pswitch_data_2

    .line 338
    .line 339
    .line 340
    invoke-static {v1, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 341
    .line 342
    .line 343
    goto :goto_3

    .line 344
    :pswitch_13
    invoke-static {v1, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 345
    .line 346
    .line 347
    goto :goto_3

    .line 348
    :pswitch_14
    sget-object v3, Lpp/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 349
    .line 350
    invoke-static {v1, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v2

    .line 354
    check-cast v2, [Lpp/j;

    .line 355
    .line 356
    move-object v13, v2

    .line 357
    goto :goto_3

    .line 358
    :pswitch_15
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 359
    .line 360
    .line 361
    move-result v2

    .line 362
    move v8, v2

    .line 363
    goto :goto_3

    .line 364
    :pswitch_16
    invoke-static {v1, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 365
    .line 366
    .line 367
    move-result-wide v2

    .line 368
    move-wide v11, v2

    .line 369
    goto :goto_3

    .line 370
    :pswitch_17
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 371
    .line 372
    .line 373
    move-result v2

    .line 374
    move v10, v2

    .line 375
    goto :goto_3

    .line 376
    :pswitch_18
    invoke-static {v1, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 377
    .line 378
    .line 379
    move-result v2

    .line 380
    move v9, v2

    .line 381
    goto :goto_3

    .line 382
    :cond_7
    invoke-static {v1, v0}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 383
    .line 384
    .line 385
    new-instance v7, Lcom/google/android/gms/location/LocationAvailability;

    .line 386
    .line 387
    invoke-direct/range {v7 .. v13}, Lcom/google/android/gms/location/LocationAvailability;-><init>(IIIJ[Lpp/j;)V

    .line 388
    .line 389
    .line 390
    return-object v7

    .line 391
    :pswitch_19
    const-string v0, "parcel"

    .line 392
    .line 393
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    new-instance v0, Lpd/u0;

    .line 397
    .line 398
    invoke-virtual {v1}, Landroid/os/Parcel;->readDouble()D

    .line 399
    .line 400
    .line 401
    move-result-wide v2

    .line 402
    invoke-virtual {v1}, Landroid/os/Parcel;->readDouble()D

    .line 403
    .line 404
    .line 405
    move-result-wide v4

    .line 406
    invoke-direct {v0, v2, v3, v4, v5}, Lpd/u0;-><init>(DD)V

    .line 407
    .line 408
    .line 409
    return-object v0

    .line 410
    :pswitch_1a
    const-string v0, "parcel"

    .line 411
    .line 412
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 413
    .line 414
    .line 415
    move-object v0, v1

    .line 416
    new-instance v1, Lpd/r0;

    .line 417
    .line 418
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 419
    .line 420
    .line 421
    move-result v2

    .line 422
    const/4 v3, 0x0

    .line 423
    if-nez v2, :cond_8

    .line 424
    .line 425
    move-object v2, v3

    .line 426
    goto :goto_4

    .line 427
    :cond_8
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 428
    .line 429
    .line 430
    move-result-wide v4

    .line 431
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 432
    .line 433
    .line 434
    move-result-object v2

    .line 435
    :goto_4
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 436
    .line 437
    .line 438
    move-result v4

    .line 439
    if-nez v4, :cond_9

    .line 440
    .line 441
    move-object v4, v3

    .line 442
    goto :goto_5

    .line 443
    :cond_9
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 444
    .line 445
    .line 446
    move-result-wide v4

    .line 447
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 448
    .line 449
    .line 450
    move-result-object v4

    .line 451
    :goto_5
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v5

    .line 455
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 456
    .line 457
    .line 458
    move-result v6

    .line 459
    if-nez v6, :cond_a

    .line 460
    .line 461
    move-object v6, v3

    .line 462
    goto :goto_6

    .line 463
    :cond_a
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 464
    .line 465
    .line 466
    move-result-wide v6

    .line 467
    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 468
    .line 469
    .line 470
    move-result-object v6

    .line 471
    :goto_6
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 472
    .line 473
    .line 474
    move-result v7

    .line 475
    if-nez v7, :cond_b

    .line 476
    .line 477
    move-object v7, v3

    .line 478
    goto :goto_7

    .line 479
    :cond_b
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 480
    .line 481
    .line 482
    move-result-wide v7

    .line 483
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 484
    .line 485
    .line 486
    move-result-object v7

    .line 487
    :goto_7
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 488
    .line 489
    .line 490
    move-result v8

    .line 491
    if-nez v8, :cond_c

    .line 492
    .line 493
    move-object v8, v3

    .line 494
    goto :goto_8

    .line 495
    :cond_c
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 496
    .line 497
    .line 498
    move-result-wide v8

    .line 499
    invoke-static {v8, v9}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 500
    .line 501
    .line 502
    move-result-object v8

    .line 503
    :goto_8
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 504
    .line 505
    .line 506
    move-result-object v9

    .line 507
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 508
    .line 509
    .line 510
    move-result v10

    .line 511
    if-nez v10, :cond_d

    .line 512
    .line 513
    :goto_9
    move-object/from16 v40, v9

    .line 514
    .line 515
    move-object v9, v3

    .line 516
    move-object v3, v4

    .line 517
    move-object v4, v5

    .line 518
    move-object v5, v6

    .line 519
    move-object v6, v7

    .line 520
    move-object v7, v8

    .line 521
    move-object/from16 v8, v40

    .line 522
    .line 523
    goto :goto_a

    .line 524
    :cond_d
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 525
    .line 526
    .line 527
    move-result-wide v10

    .line 528
    invoke-static {v10, v11}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 529
    .line 530
    .line 531
    move-result-object v3

    .line 532
    goto :goto_9

    .line 533
    :goto_a
    invoke-direct/range {v1 .. v9}, Lpd/r0;-><init>(Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/lang/Double;)V

    .line 534
    .line 535
    .line 536
    return-object v1

    .line 537
    :pswitch_1b
    move-object v0, v1

    .line 538
    const-string v1, "parcel"

    .line 539
    .line 540
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 541
    .line 542
    .line 543
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 544
    .line 545
    .line 546
    move-result-object v1

    .line 547
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 548
    .line 549
    .line 550
    move-result-object v2

    .line 551
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 552
    .line 553
    .line 554
    move-result v3

    .line 555
    new-instance v4, Ljava/util/ArrayList;

    .line 556
    .line 557
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 558
    .line 559
    .line 560
    const/4 v5, 0x0

    .line 561
    :goto_b
    if-eq v5, v3, :cond_e

    .line 562
    .line 563
    sget-object v6, Lpd/e0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 564
    .line 565
    const/4 v7, 0x1

    .line 566
    invoke-static {v6, v0, v4, v5, v7}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 567
    .line 568
    .line 569
    move-result v5

    .line 570
    goto :goto_b

    .line 571
    :cond_e
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 572
    .line 573
    .line 574
    move-result-object v0

    .line 575
    new-instance v3, Lpd/o0;

    .line 576
    .line 577
    invoke-direct {v3, v1, v2, v0, v4}, Lpd/o0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 578
    .line 579
    .line 580
    return-object v3

    .line 581
    :pswitch_1c
    move-object v0, v1

    .line 582
    const-string v1, "parcel"

    .line 583
    .line 584
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 585
    .line 586
    .line 587
    new-instance v1, Lpd/l0;

    .line 588
    .line 589
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 590
    .line 591
    .line 592
    move-result-wide v2

    .line 593
    invoke-virtual {v0}, Landroid/os/Parcel;->readDouble()D

    .line 594
    .line 595
    .line 596
    move-result-wide v4

    .line 597
    invoke-direct {v1, v2, v3, v4, v5}, Lpd/l0;-><init>(DD)V

    .line 598
    .line 599
    .line 600
    return-object v1

    .line 601
    :pswitch_1d
    move-object v0, v1

    .line 602
    const-string v1, "parcel"

    .line 603
    .line 604
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 605
    .line 606
    .line 607
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 608
    .line 609
    .line 610
    move-result v1

    .line 611
    new-instance v3, Ljava/util/ArrayList;

    .line 612
    .line 613
    invoke-direct {v3, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 614
    .line 615
    .line 616
    const/4 v2, 0x0

    .line 617
    move v4, v2

    .line 618
    :goto_c
    const/4 v5, 0x1

    .line 619
    if-eq v4, v1, :cond_f

    .line 620
    .line 621
    sget-object v6, Lpd/l0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 622
    .line 623
    invoke-static {v6, v0, v3, v4, v5}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 624
    .line 625
    .line 626
    move-result v4

    .line 627
    goto :goto_c

    .line 628
    :cond_f
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 629
    .line 630
    .line 631
    move-result v1

    .line 632
    new-instance v4, Ljava/util/ArrayList;

    .line 633
    .line 634
    invoke-direct {v4, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 635
    .line 636
    .line 637
    move v6, v2

    .line 638
    :goto_d
    if-eq v6, v1, :cond_10

    .line 639
    .line 640
    sget-object v7, Lpd/u0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 641
    .line 642
    invoke-static {v7, v0, v4, v6, v5}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 643
    .line 644
    .line 645
    move-result v6

    .line 646
    goto :goto_d

    .line 647
    :cond_10
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 648
    .line 649
    .line 650
    move-result v1

    .line 651
    new-instance v6, Ljava/util/ArrayList;

    .line 652
    .line 653
    invoke-direct {v6, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 654
    .line 655
    .line 656
    :goto_e
    if-eq v2, v1, :cond_11

    .line 657
    .line 658
    sget-object v7, Lpd/r0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 659
    .line 660
    invoke-static {v7, v0, v6, v2, v5}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 661
    .line 662
    .line 663
    move-result v2

    .line 664
    goto :goto_e

    .line 665
    :cond_11
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 666
    .line 667
    .line 668
    move-result-object v1

    .line 669
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 670
    .line 671
    .line 672
    move-result-object v7

    .line 673
    new-instance v2, Lpd/i0;

    .line 674
    .line 675
    move-object v5, v6

    .line 676
    move-object v6, v1

    .line 677
    invoke-direct/range {v2 .. v7}, Lpd/i0;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;)V

    .line 678
    .line 679
    .line 680
    return-object v2

    .line 681
    :pswitch_1e
    move-object v0, v1

    .line 682
    const-string v1, "parcel"

    .line 683
    .line 684
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 685
    .line 686
    .line 687
    new-instance v1, Lpd/e0;

    .line 688
    .line 689
    const-class v2, Lpd/e0;

    .line 690
    .line 691
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 692
    .line 693
    .line 694
    move-result-object v2

    .line 695
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    .line 696
    .line 697
    .line 698
    move-result-object v2

    .line 699
    check-cast v2, Lgz0/p;

    .line 700
    .line 701
    invoke-virtual {v0}, Landroid/os/Parcel;->readFloat()F

    .line 702
    .line 703
    .line 704
    move-result v3

    .line 705
    invoke-virtual {v0}, Landroid/os/Parcel;->readFloat()F

    .line 706
    .line 707
    .line 708
    move-result v0

    .line 709
    invoke-direct {v1, v2, v3, v0}, Lpd/e0;-><init>(Lgz0/p;FF)V

    .line 710
    .line 711
    .line 712
    return-object v1

    .line 713
    :pswitch_1f
    move-object v0, v1

    .line 714
    const-string v1, "parcel"

    .line 715
    .line 716
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 720
    .line 721
    .line 722
    move-result-object v3

    .line 723
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 724
    .line 725
    .line 726
    move-result-object v4

    .line 727
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 728
    .line 729
    .line 730
    move-result-object v5

    .line 731
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 732
    .line 733
    .line 734
    move-result-object v6

    .line 735
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 736
    .line 737
    .line 738
    move-result-object v7

    .line 739
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 740
    .line 741
    .line 742
    move-result-object v8

    .line 743
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 744
    .line 745
    .line 746
    move-result-object v9

    .line 747
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 748
    .line 749
    .line 750
    move-result-object v10

    .line 751
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 752
    .line 753
    .line 754
    move-result-object v11

    .line 755
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 756
    .line 757
    .line 758
    move-result-object v12

    .line 759
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 760
    .line 761
    .line 762
    move-result-object v13

    .line 763
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 764
    .line 765
    .line 766
    move-result-object v14

    .line 767
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 768
    .line 769
    .line 770
    move-result-object v15

    .line 771
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 772
    .line 773
    .line 774
    move-result-object v16

    .line 775
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 776
    .line 777
    .line 778
    move-result-object v17

    .line 779
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 780
    .line 781
    .line 782
    move-result-object v18

    .line 783
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 784
    .line 785
    .line 786
    move-result-object v19

    .line 787
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 788
    .line 789
    .line 790
    move-result-object v20

    .line 791
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 792
    .line 793
    .line 794
    move-result-object v21

    .line 795
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 796
    .line 797
    .line 798
    move-result-object v22

    .line 799
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 800
    .line 801
    .line 802
    move-result-object v23

    .line 803
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 804
    .line 805
    .line 806
    move-result v1

    .line 807
    const/16 v24, 0x0

    .line 808
    .line 809
    if-nez v1, :cond_12

    .line 810
    .line 811
    move-object/from16 v1, v24

    .line 812
    .line 813
    goto :goto_10

    .line 814
    :cond_12
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 815
    .line 816
    .line 817
    move-result v1

    .line 818
    if-eqz v1, :cond_13

    .line 819
    .line 820
    const/4 v1, 0x1

    .line 821
    goto :goto_f

    .line 822
    :cond_13
    const/4 v1, 0x0

    .line 823
    :goto_f
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 824
    .line 825
    .line 826
    move-result-object v1

    .line 827
    :goto_10
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 828
    .line 829
    .line 830
    move-result-object v25

    .line 831
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 832
    .line 833
    .line 834
    move-result-object v26

    .line 835
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 836
    .line 837
    .line 838
    move-result-object v27

    .line 839
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 840
    .line 841
    .line 842
    move-result v28

    .line 843
    if-nez v28, :cond_14

    .line 844
    .line 845
    move-object/from16 v28, v24

    .line 846
    .line 847
    goto :goto_12

    .line 848
    :cond_14
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 849
    .line 850
    .line 851
    move-result v28

    .line 852
    if-eqz v28, :cond_15

    .line 853
    .line 854
    const/16 v28, 0x1

    .line 855
    .line 856
    goto :goto_11

    .line 857
    :cond_15
    const/16 v28, 0x0

    .line 858
    .line 859
    :goto_11
    invoke-static/range {v28 .. v28}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 860
    .line 861
    .line 862
    move-result-object v28

    .line 863
    :goto_12
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 864
    .line 865
    .line 866
    move-result v29

    .line 867
    if-nez v29, :cond_16

    .line 868
    .line 869
    move-object/from16 v30, v1

    .line 870
    .line 871
    move-object/from16 v31, v3

    .line 872
    .line 873
    move-object/from16 v29, v24

    .line 874
    .line 875
    :goto_13
    move-object/from16 v32, v4

    .line 876
    .line 877
    goto :goto_15

    .line 878
    :cond_16
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 879
    .line 880
    .line 881
    move-result v2

    .line 882
    move-object/from16 v30, v1

    .line 883
    .line 884
    new-instance v1, Ljava/util/ArrayList;

    .line 885
    .line 886
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 887
    .line 888
    .line 889
    move-object/from16 v31, v3

    .line 890
    .line 891
    const/4 v3, 0x0

    .line 892
    :goto_14
    if-eq v3, v2, :cond_17

    .line 893
    .line 894
    move/from16 p0, v2

    .line 895
    .line 896
    sget-object v2, Lpd/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 897
    .line 898
    move-object/from16 v32, v4

    .line 899
    .line 900
    const/4 v4, 0x1

    .line 901
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 902
    .line 903
    .line 904
    move-result v3

    .line 905
    move/from16 v2, p0

    .line 906
    .line 907
    move-object/from16 v4, v32

    .line 908
    .line 909
    goto :goto_14

    .line 910
    :cond_17
    move-object/from16 v29, v1

    .line 911
    .line 912
    goto :goto_13

    .line 913
    :goto_15
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 914
    .line 915
    .line 916
    move-result v1

    .line 917
    if-nez v1, :cond_18

    .line 918
    .line 919
    move-object/from16 v1, v24

    .line 920
    .line 921
    goto :goto_16

    .line 922
    :cond_18
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 923
    .line 924
    .line 925
    move-result-object v1

    .line 926
    invoke-static {v1}, Lpd/l;->valueOf(Ljava/lang/String;)Lpd/l;

    .line 927
    .line 928
    .line 929
    move-result-object v1

    .line 930
    :goto_16
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 931
    .line 932
    .line 933
    move-result v2

    .line 934
    if-nez v2, :cond_19

    .line 935
    .line 936
    goto :goto_17

    .line 937
    :cond_19
    sget-object v2, Lpd/i0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 938
    .line 939
    invoke-interface {v2, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 940
    .line 941
    .line 942
    move-result-object v24

    .line 943
    :goto_17
    check-cast v24, Lpd/i0;

    .line 944
    .line 945
    new-instance v2, Lpd/m;

    .line 946
    .line 947
    move-object/from16 v3, v31

    .line 948
    .line 949
    move-object/from16 v4, v32

    .line 950
    .line 951
    move-object/from16 v31, v24

    .line 952
    .line 953
    move-object/from16 v24, v30

    .line 954
    .line 955
    move-object/from16 v30, v1

    .line 956
    .line 957
    invoke-direct/range {v2 .. v31}, Lpd/m;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/util/ArrayList;Lpd/l;Lpd/i0;)V

    .line 958
    .line 959
    .line 960
    return-object v2

    .line 961
    :pswitch_20
    move-object v0, v1

    .line 962
    const-string v1, "parcel"

    .line 963
    .line 964
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 965
    .line 966
    .line 967
    new-instance v1, Lpd/c;

    .line 968
    .line 969
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 970
    .line 971
    .line 972
    move-result-object v2

    .line 973
    sget-object v3, Lgz0/p;->Companion:Lgz0/o;

    .line 974
    .line 975
    invoke-virtual {v0}, Landroid/os/Parcel;->readLong()J

    .line 976
    .line 977
    .line 978
    move-result-wide v4

    .line 979
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 980
    .line 981
    .line 982
    invoke-static {v4, v5}, Lgz0/o;->a(J)Lgz0/p;

    .line 983
    .line 984
    .line 985
    move-result-object v3

    .line 986
    invoke-virtual {v0}, Landroid/os/Parcel;->readFloat()F

    .line 987
    .line 988
    .line 989
    move-result v4

    .line 990
    invoke-virtual {v0}, Landroid/os/Parcel;->readFloat()F

    .line 991
    .line 992
    .line 993
    move-result v0

    .line 994
    invoke-direct {v1, v2, v3, v4, v0}, Lpd/c;-><init>(Ljava/lang/String;Lgz0/p;FF)V

    .line 995
    .line 996
    .line 997
    return-object v1

    .line 998
    :pswitch_21
    move-object v0, v1

    .line 999
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1000
    .line 1001
    .line 1002
    move-result v1

    .line 1003
    new-instance v2, Landroid/os/Bundle;

    .line 1004
    .line 1005
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 1006
    .line 1007
    .line 1008
    sget-object v3, Lno/h;->r:[Lcom/google/android/gms/common/api/Scope;

    .line 1009
    .line 1010
    const/4 v4, 0x0

    .line 1011
    const/4 v5, 0x0

    .line 1012
    sget-object v6, Lno/h;->s:[Ljo/d;

    .line 1013
    .line 1014
    move-object v14, v2

    .line 1015
    move-object v13, v3

    .line 1016
    move-object v11, v4

    .line 1017
    move-object v12, v11

    .line 1018
    move-object v15, v12

    .line 1019
    move-object/from16 v21, v15

    .line 1020
    .line 1021
    move v8, v5

    .line 1022
    move v9, v8

    .line 1023
    move v10, v9

    .line 1024
    move/from16 v18, v10

    .line 1025
    .line 1026
    move/from16 v19, v18

    .line 1027
    .line 1028
    move/from16 v20, v19

    .line 1029
    .line 1030
    move-object/from16 v16, v6

    .line 1031
    .line 1032
    move-object/from16 v17, v16

    .line 1033
    .line 1034
    :goto_18
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1035
    .line 1036
    .line 1037
    move-result v2

    .line 1038
    if-ge v2, v1, :cond_1a

    .line 1039
    .line 1040
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1041
    .line 1042
    .line 1043
    move-result v2

    .line 1044
    int-to-char v3, v2

    .line 1045
    packed-switch v3, :pswitch_data_3

    .line 1046
    .line 1047
    .line 1048
    :pswitch_22
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1049
    .line 1050
    .line 1051
    goto :goto_18

    .line 1052
    :pswitch_23
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v21

    .line 1056
    goto :goto_18

    .line 1057
    :pswitch_24
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1058
    .line 1059
    .line 1060
    move-result v20

    .line 1061
    goto :goto_18

    .line 1062
    :pswitch_25
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1063
    .line 1064
    .line 1065
    move-result v19

    .line 1066
    goto :goto_18

    .line 1067
    :pswitch_26
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1068
    .line 1069
    .line 1070
    move-result v18

    .line 1071
    goto :goto_18

    .line 1072
    :pswitch_27
    sget-object v3, Ljo/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1073
    .line 1074
    invoke-static {v0, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v2

    .line 1078
    move-object/from16 v17, v2

    .line 1079
    .line 1080
    check-cast v17, [Ljo/d;

    .line 1081
    .line 1082
    goto :goto_18

    .line 1083
    :pswitch_28
    sget-object v3, Ljo/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1084
    .line 1085
    invoke-static {v0, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1086
    .line 1087
    .line 1088
    move-result-object v2

    .line 1089
    move-object/from16 v16, v2

    .line 1090
    .line 1091
    check-cast v16, [Ljo/d;

    .line 1092
    .line 1093
    goto :goto_18

    .line 1094
    :pswitch_29
    sget-object v3, Landroid/accounts/Account;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1095
    .line 1096
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1097
    .line 1098
    .line 1099
    move-result-object v2

    .line 1100
    move-object v15, v2

    .line 1101
    check-cast v15, Landroid/accounts/Account;

    .line 1102
    .line 1103
    goto :goto_18

    .line 1104
    :pswitch_2a
    invoke-static {v0, v2}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v14

    .line 1108
    goto :goto_18

    .line 1109
    :pswitch_2b
    sget-object v3, Lcom/google/android/gms/common/api/Scope;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1110
    .line 1111
    invoke-static {v0, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v2

    .line 1115
    move-object v13, v2

    .line 1116
    check-cast v13, [Lcom/google/android/gms/common/api/Scope;

    .line 1117
    .line 1118
    goto :goto_18

    .line 1119
    :pswitch_2c
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v12

    .line 1123
    goto :goto_18

    .line 1124
    :pswitch_2d
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v11

    .line 1128
    goto :goto_18

    .line 1129
    :pswitch_2e
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1130
    .line 1131
    .line 1132
    move-result v10

    .line 1133
    goto :goto_18

    .line 1134
    :pswitch_2f
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1135
    .line 1136
    .line 1137
    move-result v9

    .line 1138
    goto :goto_18

    .line 1139
    :pswitch_30
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1140
    .line 1141
    .line 1142
    move-result v8

    .line 1143
    goto :goto_18

    .line 1144
    :cond_1a
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1145
    .line 1146
    .line 1147
    new-instance v7, Lno/h;

    .line 1148
    .line 1149
    invoke-direct/range {v7 .. v21}, Lno/h;-><init>(IIILjava/lang/String;Landroid/os/IBinder;[Lcom/google/android/gms/common/api/Scope;Landroid/os/Bundle;Landroid/accounts/Account;[Ljo/d;[Ljo/d;ZIZLjava/lang/String;)V

    .line 1150
    .line 1151
    .line 1152
    return-object v7

    .line 1153
    :pswitch_31
    move-object v0, v1

    .line 1154
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1155
    .line 1156
    .line 1157
    move-result v1

    .line 1158
    const/4 v2, 0x0

    .line 1159
    const/4 v3, 0x0

    .line 1160
    move-object v5, v2

    .line 1161
    move-object v8, v5

    .line 1162
    move-object v10, v8

    .line 1163
    move v6, v3

    .line 1164
    move v7, v6

    .line 1165
    move v9, v7

    .line 1166
    :goto_19
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1167
    .line 1168
    .line 1169
    move-result v2

    .line 1170
    if-ge v2, v1, :cond_1b

    .line 1171
    .line 1172
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1173
    .line 1174
    .line 1175
    move-result v2

    .line 1176
    int-to-char v3, v2

    .line 1177
    packed-switch v3, :pswitch_data_4

    .line 1178
    .line 1179
    .line 1180
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1181
    .line 1182
    .line 1183
    goto :goto_19

    .line 1184
    :pswitch_32
    invoke-static {v0, v2}, Ljp/xb;->c(Landroid/os/Parcel;I)[I

    .line 1185
    .line 1186
    .line 1187
    move-result-object v10

    .line 1188
    goto :goto_19

    .line 1189
    :pswitch_33
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1190
    .line 1191
    .line 1192
    move-result v9

    .line 1193
    goto :goto_19

    .line 1194
    :pswitch_34
    invoke-static {v0, v2}, Ljp/xb;->c(Landroid/os/Parcel;I)[I

    .line 1195
    .line 1196
    .line 1197
    move-result-object v8

    .line 1198
    goto :goto_19

    .line 1199
    :pswitch_35
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1200
    .line 1201
    .line 1202
    move-result v7

    .line 1203
    goto :goto_19

    .line 1204
    :pswitch_36
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1205
    .line 1206
    .line 1207
    move-result v6

    .line 1208
    goto :goto_19

    .line 1209
    :pswitch_37
    sget-object v3, Lno/o;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1210
    .line 1211
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1212
    .line 1213
    .line 1214
    move-result-object v2

    .line 1215
    move-object v5, v2

    .line 1216
    check-cast v5, Lno/o;

    .line 1217
    .line 1218
    goto :goto_19

    .line 1219
    :cond_1b
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1220
    .line 1221
    .line 1222
    new-instance v4, Lno/g;

    .line 1223
    .line 1224
    invoke-direct/range {v4 .. v10}, Lno/g;-><init>(Lno/o;ZZ[II[I)V

    .line 1225
    .line 1226
    .line 1227
    return-object v4

    .line 1228
    :pswitch_38
    move-object v0, v1

    .line 1229
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1230
    .line 1231
    .line 1232
    move-result v1

    .line 1233
    const/4 v2, 0x0

    .line 1234
    const/4 v3, 0x0

    .line 1235
    move-object v4, v2

    .line 1236
    move v5, v3

    .line 1237
    move-object v3, v4

    .line 1238
    :goto_1a
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1239
    .line 1240
    .line 1241
    move-result v6

    .line 1242
    if-ge v6, v1, :cond_20

    .line 1243
    .line 1244
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1245
    .line 1246
    .line 1247
    move-result v6

    .line 1248
    int-to-char v7, v6

    .line 1249
    const/4 v8, 0x1

    .line 1250
    if-eq v7, v8, :cond_1f

    .line 1251
    .line 1252
    const/4 v8, 0x2

    .line 1253
    if-eq v7, v8, :cond_1e

    .line 1254
    .line 1255
    const/4 v8, 0x3

    .line 1256
    if-eq v7, v8, :cond_1d

    .line 1257
    .line 1258
    const/4 v8, 0x4

    .line 1259
    if-eq v7, v8, :cond_1c

    .line 1260
    .line 1261
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1262
    .line 1263
    .line 1264
    goto :goto_1a

    .line 1265
    :cond_1c
    sget-object v4, Lno/g;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1266
    .line 1267
    invoke-static {v0, v6, v4}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v4

    .line 1271
    check-cast v4, Lno/g;

    .line 1272
    .line 1273
    goto :goto_1a

    .line 1274
    :cond_1d
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1275
    .line 1276
    .line 1277
    move-result v5

    .line 1278
    goto :goto_1a

    .line 1279
    :cond_1e
    sget-object v3, Ljo/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1280
    .line 1281
    invoke-static {v0, v6, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v3

    .line 1285
    check-cast v3, [Ljo/d;

    .line 1286
    .line 1287
    goto :goto_1a

    .line 1288
    :cond_1f
    invoke-static {v0, v6}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v2

    .line 1292
    goto :goto_1a

    .line 1293
    :cond_20
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1294
    .line 1295
    .line 1296
    new-instance v0, Lno/j0;

    .line 1297
    .line 1298
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 1299
    .line 1300
    .line 1301
    iput-object v2, v0, Lno/j0;->d:Landroid/os/Bundle;

    .line 1302
    .line 1303
    iput-object v3, v0, Lno/j0;->e:[Ljo/d;

    .line 1304
    .line 1305
    iput v5, v0, Lno/j0;->f:I

    .line 1306
    .line 1307
    iput-object v4, v0, Lno/j0;->g:Lno/g;

    .line 1308
    .line 1309
    return-object v0

    .line 1310
    :pswitch_39
    move-object v0, v1

    .line 1311
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1312
    .line 1313
    .line 1314
    move-result v1

    .line 1315
    const/4 v2, 0x0

    .line 1316
    move v4, v2

    .line 1317
    move v5, v4

    .line 1318
    move v6, v5

    .line 1319
    move v7, v6

    .line 1320
    move v8, v7

    .line 1321
    :goto_1b
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1322
    .line 1323
    .line 1324
    move-result v2

    .line 1325
    if-ge v2, v1, :cond_26

    .line 1326
    .line 1327
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1328
    .line 1329
    .line 1330
    move-result v2

    .line 1331
    int-to-char v3, v2

    .line 1332
    const/4 v9, 0x1

    .line 1333
    if-eq v3, v9, :cond_25

    .line 1334
    .line 1335
    const/4 v9, 0x2

    .line 1336
    if-eq v3, v9, :cond_24

    .line 1337
    .line 1338
    const/4 v9, 0x3

    .line 1339
    if-eq v3, v9, :cond_23

    .line 1340
    .line 1341
    const/4 v9, 0x4

    .line 1342
    if-eq v3, v9, :cond_22

    .line 1343
    .line 1344
    const/4 v9, 0x5

    .line 1345
    if-eq v3, v9, :cond_21

    .line 1346
    .line 1347
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1348
    .line 1349
    .line 1350
    goto :goto_1b

    .line 1351
    :cond_21
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1352
    .line 1353
    .line 1354
    move-result v8

    .line 1355
    goto :goto_1b

    .line 1356
    :cond_22
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1357
    .line 1358
    .line 1359
    move-result v7

    .line 1360
    goto :goto_1b

    .line 1361
    :cond_23
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1362
    .line 1363
    .line 1364
    move-result v6

    .line 1365
    goto :goto_1b

    .line 1366
    :cond_24
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1367
    .line 1368
    .line 1369
    move-result v5

    .line 1370
    goto :goto_1b

    .line 1371
    :cond_25
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1372
    .line 1373
    .line 1374
    move-result v4

    .line 1375
    goto :goto_1b

    .line 1376
    :cond_26
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1377
    .line 1378
    .line 1379
    new-instance v3, Lno/o;

    .line 1380
    .line 1381
    invoke-direct/range {v3 .. v8}, Lno/o;-><init>(IZZII)V

    .line 1382
    .line 1383
    .line 1384
    return-object v3

    .line 1385
    :pswitch_3a
    move-object v0, v1

    .line 1386
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1387
    .line 1388
    .line 1389
    move-result v1

    .line 1390
    const/4 v2, 0x0

    .line 1391
    const/4 v3, 0x0

    .line 1392
    move v5, v2

    .line 1393
    move v8, v5

    .line 1394
    move v9, v8

    .line 1395
    move-object v6, v3

    .line 1396
    move-object v7, v6

    .line 1397
    :goto_1c
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1398
    .line 1399
    .line 1400
    move-result v2

    .line 1401
    if-ge v2, v1, :cond_2c

    .line 1402
    .line 1403
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1404
    .line 1405
    .line 1406
    move-result v2

    .line 1407
    int-to-char v3, v2

    .line 1408
    const/4 v4, 0x1

    .line 1409
    if-eq v3, v4, :cond_2b

    .line 1410
    .line 1411
    const/4 v4, 0x2

    .line 1412
    if-eq v3, v4, :cond_2a

    .line 1413
    .line 1414
    const/4 v4, 0x3

    .line 1415
    if-eq v3, v4, :cond_29

    .line 1416
    .line 1417
    const/4 v4, 0x4

    .line 1418
    if-eq v3, v4, :cond_28

    .line 1419
    .line 1420
    const/4 v4, 0x5

    .line 1421
    if-eq v3, v4, :cond_27

    .line 1422
    .line 1423
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1424
    .line 1425
    .line 1426
    goto :goto_1c

    .line 1427
    :cond_27
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1428
    .line 1429
    .line 1430
    move-result v9

    .line 1431
    goto :goto_1c

    .line 1432
    :cond_28
    invoke-static {v0, v2}, Ljp/xb;->l(Landroid/os/Parcel;I)Z

    .line 1433
    .line 1434
    .line 1435
    move-result v8

    .line 1436
    goto :goto_1c

    .line 1437
    :cond_29
    sget-object v3, Ljo/b;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1438
    .line 1439
    invoke-static {v0, v2, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1440
    .line 1441
    .line 1442
    move-result-object v2

    .line 1443
    move-object v7, v2

    .line 1444
    check-cast v7, Ljo/b;

    .line 1445
    .line 1446
    goto :goto_1c

    .line 1447
    :cond_2a
    invoke-static {v0, v2}, Ljp/xb;->q(Landroid/os/Parcel;I)Landroid/os/IBinder;

    .line 1448
    .line 1449
    .line 1450
    move-result-object v6

    .line 1451
    goto :goto_1c

    .line 1452
    :cond_2b
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1453
    .line 1454
    .line 1455
    move-result v5

    .line 1456
    goto :goto_1c

    .line 1457
    :cond_2c
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1458
    .line 1459
    .line 1460
    new-instance v4, Lno/v;

    .line 1461
    .line 1462
    invoke-direct/range {v4 .. v9}, Lno/v;-><init>(ILandroid/os/IBinder;Ljo/b;ZZ)V

    .line 1463
    .line 1464
    .line 1465
    return-object v4

    .line 1466
    :pswitch_3b
    move-object v0, v1

    .line 1467
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1468
    .line 1469
    .line 1470
    move-result v1

    .line 1471
    const/4 v2, 0x0

    .line 1472
    const/4 v3, 0x0

    .line 1473
    move v4, v3

    .line 1474
    move v5, v4

    .line 1475
    move-object v3, v2

    .line 1476
    :goto_1d
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1477
    .line 1478
    .line 1479
    move-result v6

    .line 1480
    if-ge v6, v1, :cond_31

    .line 1481
    .line 1482
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1483
    .line 1484
    .line 1485
    move-result v6

    .line 1486
    int-to-char v7, v6

    .line 1487
    const/4 v8, 0x1

    .line 1488
    if-eq v7, v8, :cond_30

    .line 1489
    .line 1490
    const/4 v8, 0x2

    .line 1491
    if-eq v7, v8, :cond_2f

    .line 1492
    .line 1493
    const/4 v8, 0x3

    .line 1494
    if-eq v7, v8, :cond_2e

    .line 1495
    .line 1496
    const/4 v8, 0x4

    .line 1497
    if-eq v7, v8, :cond_2d

    .line 1498
    .line 1499
    invoke-static {v0, v6}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1500
    .line 1501
    .line 1502
    goto :goto_1d

    .line 1503
    :cond_2d
    sget-object v3, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1504
    .line 1505
    invoke-static {v0, v6, v3}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v3

    .line 1509
    check-cast v3, Lcom/google/android/gms/auth/api/signin/GoogleSignInAccount;

    .line 1510
    .line 1511
    goto :goto_1d

    .line 1512
    :cond_2e
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1513
    .line 1514
    .line 1515
    move-result v5

    .line 1516
    goto :goto_1d

    .line 1517
    :cond_2f
    sget-object v2, Landroid/accounts/Account;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1518
    .line 1519
    invoke-static {v0, v6, v2}, Ljp/xb;->e(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v2

    .line 1523
    check-cast v2, Landroid/accounts/Account;

    .line 1524
    .line 1525
    goto :goto_1d

    .line 1526
    :cond_30
    invoke-static {v0, v6}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1527
    .line 1528
    .line 1529
    move-result v4

    .line 1530
    goto :goto_1d

    .line 1531
    :cond_31
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1532
    .line 1533
    .line 1534
    new-instance v0, Lno/u;

    .line 1535
    .line 1536
    invoke-direct {v0, v4, v2, v5, v3}, Lno/u;-><init>(ILandroid/accounts/Account;ILcom/google/android/gms/auth/api/signin/GoogleSignInAccount;)V

    .line 1537
    .line 1538
    .line 1539
    return-object v0

    .line 1540
    :pswitch_3c
    move-object v0, v1

    .line 1541
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1542
    .line 1543
    .line 1544
    move-result v1

    .line 1545
    const/4 v2, -0x1

    .line 1546
    const/4 v3, 0x0

    .line 1547
    const/4 v4, 0x0

    .line 1548
    const-wide/16 v5, 0x0

    .line 1549
    .line 1550
    move/from16 v18, v2

    .line 1551
    .line 1552
    move v8, v3

    .line 1553
    move v9, v8

    .line 1554
    move v10, v9

    .line 1555
    move/from16 v17, v10

    .line 1556
    .line 1557
    move-object v15, v4

    .line 1558
    move-object/from16 v16, v15

    .line 1559
    .line 1560
    move-wide v11, v5

    .line 1561
    move-wide v13, v11

    .line 1562
    :goto_1e
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1563
    .line 1564
    .line 1565
    move-result v2

    .line 1566
    if-ge v2, v1, :cond_32

    .line 1567
    .line 1568
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1569
    .line 1570
    .line 1571
    move-result v2

    .line 1572
    int-to-char v3, v2

    .line 1573
    packed-switch v3, :pswitch_data_5

    .line 1574
    .line 1575
    .line 1576
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1577
    .line 1578
    .line 1579
    goto :goto_1e

    .line 1580
    :pswitch_3d
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1581
    .line 1582
    .line 1583
    move-result v2

    .line 1584
    move/from16 v18, v2

    .line 1585
    .line 1586
    goto :goto_1e

    .line 1587
    :pswitch_3e
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1588
    .line 1589
    .line 1590
    move-result v2

    .line 1591
    move/from16 v17, v2

    .line 1592
    .line 1593
    goto :goto_1e

    .line 1594
    :pswitch_3f
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1595
    .line 1596
    .line 1597
    move-result-object v2

    .line 1598
    move-object/from16 v16, v2

    .line 1599
    .line 1600
    goto :goto_1e

    .line 1601
    :pswitch_40
    invoke-static {v0, v2}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v2

    .line 1605
    move-object v15, v2

    .line 1606
    goto :goto_1e

    .line 1607
    :pswitch_41
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 1608
    .line 1609
    .line 1610
    move-result-wide v2

    .line 1611
    move-wide v13, v2

    .line 1612
    goto :goto_1e

    .line 1613
    :pswitch_42
    invoke-static {v0, v2}, Ljp/xb;->s(Landroid/os/Parcel;I)J

    .line 1614
    .line 1615
    .line 1616
    move-result-wide v2

    .line 1617
    move-wide v11, v2

    .line 1618
    goto :goto_1e

    .line 1619
    :pswitch_43
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1620
    .line 1621
    .line 1622
    move-result v2

    .line 1623
    move v10, v2

    .line 1624
    goto :goto_1e

    .line 1625
    :pswitch_44
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1626
    .line 1627
    .line 1628
    move-result v2

    .line 1629
    move v9, v2

    .line 1630
    goto :goto_1e

    .line 1631
    :pswitch_45
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1632
    .line 1633
    .line 1634
    move-result v2

    .line 1635
    move v8, v2

    .line 1636
    goto :goto_1e

    .line 1637
    :cond_32
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1638
    .line 1639
    .line 1640
    new-instance v7, Lno/l;

    .line 1641
    .line 1642
    invoke-direct/range {v7 .. v18}, Lno/l;-><init>(IIIJJLjava/lang/String;Ljava/lang/String;II)V

    .line 1643
    .line 1644
    .line 1645
    return-object v7

    .line 1646
    :pswitch_46
    move-object v0, v1

    .line 1647
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1648
    .line 1649
    .line 1650
    move-result v1

    .line 1651
    const/4 v2, 0x0

    .line 1652
    const/4 v3, 0x0

    .line 1653
    :goto_1f
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1654
    .line 1655
    .line 1656
    move-result v4

    .line 1657
    if-ge v4, v1, :cond_35

    .line 1658
    .line 1659
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1660
    .line 1661
    .line 1662
    move-result v4

    .line 1663
    int-to-char v5, v4

    .line 1664
    const/4 v6, 0x1

    .line 1665
    if-eq v5, v6, :cond_34

    .line 1666
    .line 1667
    const/4 v6, 0x2

    .line 1668
    if-eq v5, v6, :cond_33

    .line 1669
    .line 1670
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1671
    .line 1672
    .line 1673
    goto :goto_1f

    .line 1674
    :cond_33
    sget-object v2, Lno/l;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1675
    .line 1676
    invoke-static {v0, v4, v2}, Ljp/xb;->j(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 1677
    .line 1678
    .line 1679
    move-result-object v2

    .line 1680
    goto :goto_1f

    .line 1681
    :cond_34
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1682
    .line 1683
    .line 1684
    move-result v3

    .line 1685
    goto :goto_1f

    .line 1686
    :cond_35
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1687
    .line 1688
    .line 1689
    new-instance v0, Lno/p;

    .line 1690
    .line 1691
    invoke-direct {v0, v3, v2}, Lno/p;-><init>(ILjava/util/List;)V

    .line 1692
    .line 1693
    .line 1694
    return-object v0

    .line 1695
    :pswitch_47
    move-object v0, v1

    .line 1696
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1697
    .line 1698
    .line 1699
    move-result v1

    .line 1700
    const/4 v2, 0x0

    .line 1701
    const/4 v3, 0x0

    .line 1702
    :goto_20
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1703
    .line 1704
    .line 1705
    move-result v4

    .line 1706
    if-ge v4, v1, :cond_38

    .line 1707
    .line 1708
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1709
    .line 1710
    .line 1711
    move-result v4

    .line 1712
    int-to-char v5, v4

    .line 1713
    const/4 v6, 0x1

    .line 1714
    if-eq v5, v6, :cond_37

    .line 1715
    .line 1716
    const/4 v6, 0x2

    .line 1717
    if-eq v5, v6, :cond_36

    .line 1718
    .line 1719
    invoke-static {v0, v4}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1720
    .line 1721
    .line 1722
    goto :goto_20

    .line 1723
    :cond_36
    invoke-static {v0, v4}, Ljp/xb;->f(Landroid/os/Parcel;I)Ljava/lang/String;

    .line 1724
    .line 1725
    .line 1726
    move-result-object v2

    .line 1727
    goto :goto_20

    .line 1728
    :cond_37
    invoke-static {v0, v4}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1729
    .line 1730
    .line 1731
    move-result v3

    .line 1732
    goto :goto_20

    .line 1733
    :cond_38
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1734
    .line 1735
    .line 1736
    new-instance v0, Lno/f;

    .line 1737
    .line 1738
    invoke-direct {v0, v3, v2}, Lno/f;-><init>(ILjava/lang/String;)V

    .line 1739
    .line 1740
    .line 1741
    return-object v0

    .line 1742
    :pswitch_48
    move-object v0, v1

    .line 1743
    const-string v1, "parcel"

    .line 1744
    .line 1745
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1746
    .line 1747
    .line 1748
    new-instance v1, Lnc/c0;

    .line 1749
    .line 1750
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1751
    .line 1752
    .line 1753
    move-result-object v2

    .line 1754
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1755
    .line 1756
    .line 1757
    move-result-object v0

    .line 1758
    invoke-direct {v1, v2, v0}, Lnc/c0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1759
    .line 1760
    .line 1761
    return-object v1

    .line 1762
    :pswitch_49
    move-object v0, v1

    .line 1763
    const-string v1, "parcel"

    .line 1764
    .line 1765
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1766
    .line 1767
    .line 1768
    new-instance v2, Lnc/z;

    .line 1769
    .line 1770
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1771
    .line 1772
    .line 1773
    move-result-object v3

    .line 1774
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1775
    .line 1776
    .line 1777
    move-result-object v4

    .line 1778
    sget-object v1, Lnc/c0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1779
    .line 1780
    invoke-interface {v1, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 1781
    .line 1782
    .line 1783
    move-result-object v5

    .line 1784
    check-cast v5, Lnc/c0;

    .line 1785
    .line 1786
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1787
    .line 1788
    .line 1789
    move-result-object v6

    .line 1790
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1791
    .line 1792
    .line 1793
    move-result-object v7

    .line 1794
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1795
    .line 1796
    .line 1797
    move-result v8

    .line 1798
    if-nez v8, :cond_39

    .line 1799
    .line 1800
    const/4 v0, 0x0

    .line 1801
    goto :goto_21

    .line 1802
    :cond_39
    invoke-interface {v1, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 1803
    .line 1804
    .line 1805
    move-result-object v0

    .line 1806
    :goto_21
    move-object v8, v0

    .line 1807
    check-cast v8, Lnc/c0;

    .line 1808
    .line 1809
    invoke-direct/range {v2 .. v8}, Lnc/z;-><init>(Ljava/lang/String;Ljava/lang/String;Lnc/c0;Ljava/lang/String;Ljava/lang/String;Lnc/c0;)V

    .line 1810
    .line 1811
    .line 1812
    return-object v2

    .line 1813
    :pswitch_4a
    move-object v0, v1

    .line 1814
    invoke-static {v0}, Ljp/xb;->y(Landroid/os/Parcel;)I

    .line 1815
    .line 1816
    .line 1817
    move-result v1

    .line 1818
    const/4 v2, 0x0

    .line 1819
    const/4 v3, 0x0

    .line 1820
    move-object v6, v2

    .line 1821
    move-object v7, v6

    .line 1822
    move-object v9, v7

    .line 1823
    move v5, v3

    .line 1824
    move v8, v5

    .line 1825
    :goto_22
    invoke-virtual {v0}, Landroid/os/Parcel;->dataPosition()I

    .line 1826
    .line 1827
    .line 1828
    move-result v2

    .line 1829
    if-ge v2, v1, :cond_3f

    .line 1830
    .line 1831
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1832
    .line 1833
    .line 1834
    move-result v2

    .line 1835
    int-to-char v3, v2

    .line 1836
    const/4 v4, 0x1

    .line 1837
    if-eq v3, v4, :cond_3e

    .line 1838
    .line 1839
    const/4 v4, 0x2

    .line 1840
    if-eq v3, v4, :cond_3d

    .line 1841
    .line 1842
    const/4 v4, 0x3

    .line 1843
    if-eq v3, v4, :cond_3c

    .line 1844
    .line 1845
    const/4 v4, 0x4

    .line 1846
    if-eq v3, v4, :cond_3b

    .line 1847
    .line 1848
    const/16 v4, 0x3e8

    .line 1849
    .line 1850
    if-eq v3, v4, :cond_3a

    .line 1851
    .line 1852
    invoke-static {v0, v2}, Ljp/xb;->v(Landroid/os/Parcel;I)V

    .line 1853
    .line 1854
    .line 1855
    goto :goto_22

    .line 1856
    :cond_3a
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1857
    .line 1858
    .line 1859
    move-result v5

    .line 1860
    goto :goto_22

    .line 1861
    :cond_3b
    invoke-static {v0, v2}, Ljp/xb;->a(Landroid/os/Parcel;I)Landroid/os/Bundle;

    .line 1862
    .line 1863
    .line 1864
    move-result-object v9

    .line 1865
    goto :goto_22

    .line 1866
    :cond_3c
    invoke-static {v0, v2}, Ljp/xb;->r(Landroid/os/Parcel;I)I

    .line 1867
    .line 1868
    .line 1869
    move-result v8

    .line 1870
    goto :goto_22

    .line 1871
    :cond_3d
    sget-object v3, Landroid/database/CursorWindow;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1872
    .line 1873
    invoke-static {v0, v2, v3}, Ljp/xb;->i(Landroid/os/Parcel;ILandroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v2

    .line 1877
    move-object v7, v2

    .line 1878
    check-cast v7, [Landroid/database/CursorWindow;

    .line 1879
    .line 1880
    goto :goto_22

    .line 1881
    :cond_3e
    invoke-static {v0, v2}, Ljp/xb;->g(Landroid/os/Parcel;I)[Ljava/lang/String;

    .line 1882
    .line 1883
    .line 1884
    move-result-object v6

    .line 1885
    goto :goto_22

    .line 1886
    :cond_3f
    invoke-static {v0, v1}, Ljp/xb;->k(Landroid/os/Parcel;I)V

    .line 1887
    .line 1888
    .line 1889
    new-instance v4, Lcom/google/android/gms/common/data/DataHolder;

    .line 1890
    .line 1891
    invoke-direct/range {v4 .. v9}, Lcom/google/android/gms/common/data/DataHolder;-><init>(I[Ljava/lang/String;[Landroid/database/CursorWindow;ILandroid/os/Bundle;)V

    .line 1892
    .line 1893
    .line 1894
    invoke-virtual {v4}, Lcom/google/android/gms/common/data/DataHolder;->y0()V

    .line 1895
    .line 1896
    .line 1897
    return-object v4

    .line 1898
    :pswitch_4b
    move-object v0, v1

    .line 1899
    const-string v1, "parcel"

    .line 1900
    .line 1901
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1902
    .line 1903
    .line 1904
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1905
    .line 1906
    .line 1907
    move-result v1

    .line 1908
    const/4 v2, 0x0

    .line 1909
    const/4 v3, 0x0

    .line 1910
    const-class v4, Lmg/c;

    .line 1911
    .line 1912
    if-nez v1, :cond_40

    .line 1913
    .line 1914
    move-object v8, v3

    .line 1915
    goto :goto_24

    .line 1916
    :cond_40
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1917
    .line 1918
    .line 1919
    move-result v1

    .line 1920
    new-instance v5, Ljava/util/ArrayList;

    .line 1921
    .line 1922
    invoke-direct {v5, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 1923
    .line 1924
    .line 1925
    move v6, v2

    .line 1926
    :goto_23
    if-eq v6, v1, :cond_41

    .line 1927
    .line 1928
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 1929
    .line 1930
    .line 1931
    move-result-object v7

    .line 1932
    invoke-virtual {v0, v7}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 1933
    .line 1934
    .line 1935
    move-result-object v7

    .line 1936
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1937
    .line 1938
    .line 1939
    add-int/lit8 v6, v6, 0x1

    .line 1940
    .line 1941
    goto :goto_23

    .line 1942
    :cond_41
    move-object v8, v5

    .line 1943
    :goto_24
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1944
    .line 1945
    .line 1946
    move-result v1

    .line 1947
    if-nez v1, :cond_42

    .line 1948
    .line 1949
    move-object v1, v3

    .line 1950
    goto :goto_25

    .line 1951
    :cond_42
    sget-object v1, Lkg/p0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 1952
    .line 1953
    invoke-interface {v1, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 1954
    .line 1955
    .line 1956
    move-result-object v1

    .line 1957
    :goto_25
    move-object v9, v1

    .line 1958
    check-cast v9, Lkg/p0;

    .line 1959
    .line 1960
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 1961
    .line 1962
    .line 1963
    move-result-object v1

    .line 1964
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 1965
    .line 1966
    .line 1967
    move-result-object v1

    .line 1968
    move-object v10, v1

    .line 1969
    check-cast v10, Lac/e;

    .line 1970
    .line 1971
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 1972
    .line 1973
    .line 1974
    move-result v1

    .line 1975
    if-nez v1, :cond_43

    .line 1976
    .line 1977
    move-object v11, v3

    .line 1978
    goto :goto_26

    .line 1979
    :cond_43
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 1980
    .line 1981
    .line 1982
    move-result-object v1

    .line 1983
    invoke-static {v1}, Log/i;->valueOf(Ljava/lang/String;)Log/i;

    .line 1984
    .line 1985
    .line 1986
    move-result-object v1

    .line 1987
    move-object v11, v1

    .line 1988
    :goto_26
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 1989
    .line 1990
    .line 1991
    move-result-object v1

    .line 1992
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 1993
    .line 1994
    .line 1995
    move-result-object v1

    .line 1996
    move-object v12, v1

    .line 1997
    check-cast v12, Lac/e;

    .line 1998
    .line 1999
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 2000
    .line 2001
    .line 2002
    move-result-object v1

    .line 2003
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 2004
    .line 2005
    .line 2006
    move-result-object v1

    .line 2007
    move-object v13, v1

    .line 2008
    check-cast v13, Lnc/z;

    .line 2009
    .line 2010
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2011
    .line 2012
    .line 2013
    move-result v1

    .line 2014
    if-nez v1, :cond_44

    .line 2015
    .line 2016
    move-object v14, v3

    .line 2017
    goto :goto_28

    .line 2018
    :cond_44
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2019
    .line 2020
    .line 2021
    move-result v1

    .line 2022
    if-eqz v1, :cond_45

    .line 2023
    .line 2024
    const/4 v1, 0x1

    .line 2025
    goto :goto_27

    .line 2026
    :cond_45
    move v1, v2

    .line 2027
    :goto_27
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2028
    .line 2029
    .line 2030
    move-result-object v1

    .line 2031
    move-object v14, v1

    .line 2032
    :goto_28
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2033
    .line 2034
    .line 2035
    move-result v1

    .line 2036
    if-nez v1, :cond_47

    .line 2037
    .line 2038
    :cond_46
    move-object v15, v3

    .line 2039
    goto :goto_2a

    .line 2040
    :cond_47
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2041
    .line 2042
    .line 2043
    move-result v1

    .line 2044
    new-instance v3, Ljava/util/ArrayList;

    .line 2045
    .line 2046
    invoke-direct {v3, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 2047
    .line 2048
    .line 2049
    :goto_29
    if-eq v2, v1, :cond_46

    .line 2050
    .line 2051
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 2052
    .line 2053
    .line 2054
    move-result-object v5

    .line 2055
    invoke-virtual {v0, v5}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 2056
    .line 2057
    .line 2058
    move-result-object v5

    .line 2059
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2060
    .line 2061
    .line 2062
    add-int/lit8 v2, v2, 0x1

    .line 2063
    .line 2064
    goto :goto_29

    .line 2065
    :goto_2a
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 2066
    .line 2067
    .line 2068
    move-result-object v1

    .line 2069
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    .line 2070
    .line 2071
    .line 2072
    move-result-object v1

    .line 2073
    move-object/from16 v16, v1

    .line 2074
    .line 2075
    check-cast v16, Lac/a0;

    .line 2076
    .line 2077
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2078
    .line 2079
    .line 2080
    move-result-object v17

    .line 2081
    new-instance v7, Lmg/c;

    .line 2082
    .line 2083
    invoke-direct/range {v7 .. v17}, Lmg/c;-><init>(Ljava/util/List;Lkg/p0;Lac/e;Log/i;Lac/e;Lnc/z;Ljava/lang/Boolean;Ljava/util/List;Lac/a0;Ljava/lang/String;)V

    .line 2084
    .line 2085
    .line 2086
    return-object v7

    .line 2087
    :pswitch_4c
    move-object v0, v1

    .line 2088
    new-instance v1, Lm/n0;

    .line 2089
    .line 2090
    invoke-direct {v1, v0}, Landroid/view/View$BaseSavedState;-><init>(Landroid/os/Parcel;)V

    .line 2091
    .line 2092
    .line 2093
    invoke-virtual {v0}, Landroid/os/Parcel;->readByte()B

    .line 2094
    .line 2095
    .line 2096
    move-result v0

    .line 2097
    if-eqz v0, :cond_48

    .line 2098
    .line 2099
    const/4 v0, 0x1

    .line 2100
    goto :goto_2b

    .line 2101
    :cond_48
    const/4 v0, 0x0

    .line 2102
    :goto_2b
    iput-boolean v0, v1, Lm/n0;->d:Z

    .line 2103
    .line 2104
    return-object v1

    .line 2105
    :pswitch_4d
    move-object v0, v1

    .line 2106
    new-instance v1, Llq/b;

    .line 2107
    .line 2108
    invoke-direct {v1, v0}, Landroid/view/View$BaseSavedState;-><init>(Landroid/os/Parcel;)V

    .line 2109
    .line 2110
    .line 2111
    const-class v2, Llq/b;

    .line 2112
    .line 2113
    invoke-virtual {v2}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 2114
    .line 2115
    .line 2116
    move-result-object v2

    .line 2117
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->readValue(Ljava/lang/ClassLoader;)Ljava/lang/Object;

    .line 2118
    .line 2119
    .line 2120
    move-result-object v0

    .line 2121
    check-cast v0, Ljava/lang/Integer;

    .line 2122
    .line 2123
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 2124
    .line 2125
    .line 2126
    move-result v0

    .line 2127
    iput v0, v1, Llq/b;->d:I

    .line 2128
    .line 2129
    return-object v1

    .line 2130
    :pswitch_4e
    move-object v0, v1

    .line 2131
    const-string v1, "parcel"

    .line 2132
    .line 2133
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2134
    .line 2135
    .line 2136
    new-instance v1, Lki/n;

    .line 2137
    .line 2138
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2139
    .line 2140
    .line 2141
    move-result v0

    .line 2142
    if-eqz v0, :cond_49

    .line 2143
    .line 2144
    const/4 v0, 0x1

    .line 2145
    goto :goto_2c

    .line 2146
    :cond_49
    const/4 v0, 0x0

    .line 2147
    :goto_2c
    invoke-direct {v1, v0}, Lki/n;-><init>(Z)V

    .line 2148
    .line 2149
    .line 2150
    return-object v1

    .line 2151
    :pswitch_4f
    move-object v0, v1

    .line 2152
    const-string v1, "parcel"

    .line 2153
    .line 2154
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2155
    .line 2156
    .line 2157
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2158
    .line 2159
    .line 2160
    move-result-object v3

    .line 2161
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2162
    .line 2163
    .line 2164
    move-result-object v4

    .line 2165
    invoke-virtual {v0}, Landroid/os/Parcel;->createStringArrayList()Ljava/util/ArrayList;

    .line 2166
    .line 2167
    .line 2168
    move-result-object v5

    .line 2169
    sget-object v1, Lkg/o;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 2170
    .line 2171
    invoke-interface {v1, v0}, Landroid/os/Parcelable$Creator;->createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;

    .line 2172
    .line 2173
    .line 2174
    move-result-object v1

    .line 2175
    move-object v6, v1

    .line 2176
    check-cast v6, Lkg/o;

    .line 2177
    .line 2178
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2179
    .line 2180
    .line 2181
    move-result v1

    .line 2182
    new-instance v7, Ljava/util/ArrayList;

    .line 2183
    .line 2184
    invoke-direct {v7, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 2185
    .line 2186
    .line 2187
    const/4 v2, 0x0

    .line 2188
    move v8, v2

    .line 2189
    :goto_2d
    const/4 v9, 0x1

    .line 2190
    if-eq v8, v1, :cond_4a

    .line 2191
    .line 2192
    sget-object v10, Lkg/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 2193
    .line 2194
    invoke-static {v10, v0, v7, v8, v9}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 2195
    .line 2196
    .line 2197
    move-result v8

    .line 2198
    goto :goto_2d

    .line 2199
    :cond_4a
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2200
    .line 2201
    .line 2202
    move-result v1

    .line 2203
    new-instance v8, Ljava/util/ArrayList;

    .line 2204
    .line 2205
    invoke-direct {v8, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 2206
    .line 2207
    .line 2208
    move v10, v2

    .line 2209
    :goto_2e
    if-eq v10, v1, :cond_4b

    .line 2210
    .line 2211
    sget-object v11, Lkg/i;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 2212
    .line 2213
    invoke-static {v11, v0, v8, v10, v9}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 2214
    .line 2215
    .line 2216
    move-result v10

    .line 2217
    goto :goto_2e

    .line 2218
    :cond_4b
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2219
    .line 2220
    .line 2221
    move-result v1

    .line 2222
    if-eqz v1, :cond_4c

    .line 2223
    .line 2224
    move v1, v9

    .line 2225
    goto :goto_2f

    .line 2226
    :cond_4c
    move v1, v9

    .line 2227
    move v9, v2

    .line 2228
    :goto_2f
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2229
    .line 2230
    .line 2231
    move-result v10

    .line 2232
    if-eqz v10, :cond_4d

    .line 2233
    .line 2234
    move v10, v1

    .line 2235
    goto :goto_30

    .line 2236
    :cond_4d
    move v10, v2

    .line 2237
    :goto_30
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2238
    .line 2239
    .line 2240
    move-result-object v11

    .line 2241
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2242
    .line 2243
    .line 2244
    move-result-object v12

    .line 2245
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2246
    .line 2247
    .line 2248
    move-result-object v13

    .line 2249
    new-instance v2, Lkg/p0;

    .line 2250
    .line 2251
    invoke-direct/range {v2 .. v13}, Lkg/p0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Lkg/o;Ljava/util/ArrayList;Ljava/util/ArrayList;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 2252
    .line 2253
    .line 2254
    return-object v2

    .line 2255
    :pswitch_50
    move-object v0, v1

    .line 2256
    const-string v1, "parcel"

    .line 2257
    .line 2258
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2259
    .line 2260
    .line 2261
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2262
    .line 2263
    .line 2264
    move-result-object v1

    .line 2265
    invoke-virtual {v0}, Landroid/os/Parcel;->readInt()I

    .line 2266
    .line 2267
    .line 2268
    move-result v2

    .line 2269
    new-instance v3, Ljava/util/ArrayList;

    .line 2270
    .line 2271
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2272
    .line 2273
    .line 2274
    const/4 v4, 0x0

    .line 2275
    :goto_31
    if-eq v4, v2, :cond_4e

    .line 2276
    .line 2277
    sget-object v5, Lkg/x;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 2278
    .line 2279
    const/4 v6, 0x1

    .line 2280
    invoke-static {v5, v0, v3, v4, v6}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    .line 2281
    .line 2282
    .line 2283
    move-result v4

    .line 2284
    goto :goto_31

    .line 2285
    :cond_4e
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2286
    .line 2287
    .line 2288
    move-result-object v2

    .line 2289
    invoke-static {v2}, Lkg/j0;->valueOf(Ljava/lang/String;)Lkg/j0;

    .line 2290
    .line 2291
    .line 2292
    move-result-object v2

    .line 2293
    invoke-virtual {v0}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    .line 2294
    .line 2295
    .line 2296
    move-result-object v0

    .line 2297
    new-instance v4, Lkg/m0;

    .line 2298
    .line 2299
    invoke-direct {v4, v1, v3, v2, v0}, Lkg/m0;-><init>(Ljava/lang/String;Ljava/util/ArrayList;Lkg/j0;Ljava/lang/String;)V

    .line 2300
    .line 2301
    .line 2302
    return-object v4

    .line 2303
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_50
        :pswitch_4f
        :pswitch_4e
        :pswitch_4d
        :pswitch_4c
        :pswitch_4b
        :pswitch_4a
        :pswitch_49
        :pswitch_48
        :pswitch_47
        :pswitch_46
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_31
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_12
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 2304
    .line 2305
    .line 2306
    .line 2307
    .line 2308
    .line 2309
    .line 2310
    .line 2311
    .line 2312
    .line 2313
    .line 2314
    .line 2315
    .line 2316
    .line 2317
    .line 2318
    .line 2319
    .line 2320
    .line 2321
    .line 2322
    .line 2323
    .line 2324
    .line 2325
    .line 2326
    .line 2327
    .line 2328
    .line 2329
    .line 2330
    .line 2331
    .line 2332
    .line 2333
    .line 2334
    .line 2335
    .line 2336
    .line 2337
    .line 2338
    .line 2339
    .line 2340
    .line 2341
    .line 2342
    .line 2343
    .line 2344
    .line 2345
    .line 2346
    .line 2347
    .line 2348
    .line 2349
    .line 2350
    .line 2351
    .line 2352
    .line 2353
    .line 2354
    .line 2355
    .line 2356
    .line 2357
    .line 2358
    .line 2359
    .line 2360
    .line 2361
    .line 2362
    .line 2363
    .line 2364
    .line 2365
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_2
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_2
        :pswitch_5
        :pswitch_4
        :pswitch_3
    .end packed-switch

    .line 2366
    .line 2367
    .line 2368
    .line 2369
    .line 2370
    .line 2371
    .line 2372
    .line 2373
    .line 2374
    .line 2375
    .line 2376
    .line 2377
    .line 2378
    .line 2379
    .line 2380
    .line 2381
    .line 2382
    .line 2383
    .line 2384
    .line 2385
    .line 2386
    .line 2387
    .line 2388
    .line 2389
    .line 2390
    .line 2391
    .line 2392
    .line 2393
    .line 2394
    .line 2395
    .line 2396
    .line 2397
    .line 2398
    .line 2399
    .line 2400
    .line 2401
    .line 2402
    .line 2403
    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
    .end packed-switch

    .line 2404
    .line 2405
    .line 2406
    .line 2407
    .line 2408
    .line 2409
    .line 2410
    .line 2411
    .line 2412
    .line 2413
    .line 2414
    .line 2415
    .line 2416
    .line 2417
    .line 2418
    .line 2419
    :pswitch_data_3
    .packed-switch 0x1
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_22
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
    .end packed-switch

    .line 2420
    .line 2421
    .line 2422
    .line 2423
    .line 2424
    .line 2425
    .line 2426
    .line 2427
    .line 2428
    .line 2429
    .line 2430
    .line 2431
    .line 2432
    .line 2433
    .line 2434
    .line 2435
    .line 2436
    .line 2437
    .line 2438
    .line 2439
    .line 2440
    .line 2441
    .line 2442
    .line 2443
    .line 2444
    .line 2445
    .line 2446
    .line 2447
    .line 2448
    .line 2449
    .line 2450
    .line 2451
    .line 2452
    .line 2453
    :pswitch_data_4
    .packed-switch 0x1
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
    .end packed-switch

    .line 2454
    .line 2455
    .line 2456
    .line 2457
    .line 2458
    .line 2459
    .line 2460
    .line 2461
    .line 2462
    .line 2463
    .line 2464
    .line 2465
    .line 2466
    .line 2467
    .line 2468
    .line 2469
    :pswitch_data_5
    .packed-switch 0x1
        :pswitch_45
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
    .end packed-switch
.end method

.method public final newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lkg/l0;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-array p0, p1, [Lpp/e;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    new-array p0, p1, [Lcom/google/android/gms/location/LocationResult;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    new-array p0, p1, [Lcom/google/android/gms/location/LocationRequest;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_2
    new-array p0, p1, [Lcom/google/android/gms/location/LocationAvailability;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_3
    new-array p0, p1, [Lpd/u0;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_4
    new-array p0, p1, [Lpd/r0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_5
    new-array p0, p1, [Lpd/o0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_6
    new-array p0, p1, [Lpd/l0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_7
    new-array p0, p1, [Lpd/i0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_8
    new-array p0, p1, [Lpd/e0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_9
    new-array p0, p1, [Lpd/m;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_a
    new-array p0, p1, [Lpd/c;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_b
    new-array p0, p1, [Lno/h;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_c
    new-array p0, p1, [Lno/g;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_d
    new-array p0, p1, [Lno/j0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_e
    new-array p0, p1, [Lno/o;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_f
    new-array p0, p1, [Lno/v;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_10
    new-array p0, p1, [Lno/u;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_11
    new-array p0, p1, [Lno/l;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_12
    new-array p0, p1, [Lno/p;

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_13
    new-array p0, p1, [Lno/f;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_14
    new-array p0, p1, [Lnc/c0;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_15
    new-array p0, p1, [Lnc/z;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_16
    new-array p0, p1, [Lcom/google/android/gms/common/data/DataHolder;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_17
    new-array p0, p1, [Lmg/c;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_18
    new-array p0, p1, [Lm/n0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_19
    new-array p0, p1, [Llq/b;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_1a
    new-array p0, p1, [Lki/n;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1b
    new-array p0, p1, [Lkg/p0;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_1c
    new-array p0, p1, [Lkg/m0;

    .line 94
    .line 95
    return-object p0

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
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
