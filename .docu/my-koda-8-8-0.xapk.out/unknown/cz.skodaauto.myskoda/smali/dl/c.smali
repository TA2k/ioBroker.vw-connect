.class public final synthetic Ldl/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(JIF)V
    .locals 0

    .line 1
    iput p3, p0, Ldl/c;->d:I

    .line 2
    .line 3
    iput p4, p0, Ldl/c;->e:F

    .line 4
    .line 5
    iput-wide p1, p0, Ldl/c;->f:J

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Ldl/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Lg3/d;

    .line 8
    .line 9
    iget p1, p0, Ldl/c;->e:F

    .line 10
    .line 11
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 12
    .line 13
    .line 14
    move-result v8

    .line 15
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v2, 0x2

    .line 20
    int-to-float v2, v2

    .line 21
    div-float/2addr v0, v2

    .line 22
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    int-to-long v3, v0

    .line 27
    const/4 v0, 0x0

    .line 28
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    int-to-long v5, v0

    .line 33
    const/16 v0, 0x20

    .line 34
    .line 35
    shl-long/2addr v3, v0

    .line 36
    const-wide v9, 0xffffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    and-long/2addr v5, v9

    .line 42
    or-long v4, v3, v5

    .line 43
    .line 44
    invoke-interface {v1, p1}, Lt4/c;->w0(F)F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    div-float/2addr p1, v2

    .line 49
    invoke-interface {v1}, Lg3/d;->e()J

    .line 50
    .line 51
    .line 52
    move-result-wide v2

    .line 53
    and-long/2addr v2, v9

    .line 54
    long-to-int v2, v2

    .line 55
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    int-to-long v6, p1

    .line 64
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    int-to-long v2, p1

    .line 69
    shl-long/2addr v6, v0

    .line 70
    and-long/2addr v2, v9

    .line 71
    or-long/2addr v6, v2

    .line 72
    const/4 v10, 0x0

    .line 73
    const/16 v11, 0x1f0

    .line 74
    .line 75
    iget-wide v2, p0, Ldl/c;->f:J

    .line 76
    .line 77
    const/4 v9, 0x0

    .line 78
    invoke-static/range {v1 .. v11}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 79
    .line 80
    .line 81
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0

    .line 84
    :pswitch_0
    move-object v0, p1

    .line 85
    check-cast v0, Lg3/d;

    .line 86
    .line 87
    iget p1, p0, Ldl/c;->e:F

    .line 88
    .line 89
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 90
    .line 91
    .line 92
    move-result v7

    .line 93
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    const/4 v2, 0x2

    .line 98
    int-to-float v2, v2

    .line 99
    div-float/2addr v1, v2

    .line 100
    const/4 v3, 0x0

    .line 101
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    int-to-long v3, v3

    .line 106
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    int-to-long v5, v1

    .line 111
    const/16 v1, 0x20

    .line 112
    .line 113
    shl-long/2addr v3, v1

    .line 114
    const-wide v8, 0xffffffffL

    .line 115
    .line 116
    .line 117
    .line 118
    .line 119
    and-long/2addr v5, v8

    .line 120
    or-long/2addr v3, v5

    .line 121
    invoke-interface {v0}, Lg3/d;->e()J

    .line 122
    .line 123
    .line 124
    move-result-wide v5

    .line 125
    shr-long/2addr v5, v1

    .line 126
    long-to-int v5, v5

    .line 127
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 128
    .line 129
    .line 130
    move-result v5

    .line 131
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 132
    .line 133
    .line 134
    move-result p1

    .line 135
    div-float/2addr p1, v2

    .line 136
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    int-to-long v5, v2

    .line 141
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    int-to-long v10, p1

    .line 146
    shl-long v1, v5, v1

    .line 147
    .line 148
    and-long v5, v10, v8

    .line 149
    .line 150
    or-long/2addr v5, v1

    .line 151
    const/4 v9, 0x0

    .line 152
    const/16 v10, 0x1f0

    .line 153
    .line 154
    iget-wide v1, p0, Ldl/c;->f:J

    .line 155
    .line 156
    const/4 v8, 0x0

    .line 157
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 158
    .line 159
    .line 160
    goto :goto_0

    .line 161
    :pswitch_1
    check-cast p1, Lg3/d;

    .line 162
    .line 163
    const-string v0, "$this$drawBehind"

    .line 164
    .line 165
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    iget v0, p0, Ldl/c;->e:F

    .line 169
    .line 170
    invoke-interface {p1, v0}, Lt4/c;->w0(F)F

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    sget v2, Ldl/d;->b:F

    .line 175
    .line 176
    invoke-interface {p1, v2}, Lt4/c;->w0(F)F

    .line 177
    .line 178
    .line 179
    move-result v3

    .line 180
    iget-wide v4, p0, Ldl/c;->f:J

    .line 181
    .line 182
    invoke-static {p1, v1, v3, v4, v5}, Ldl/d;->e(Lg3/d;FFJ)V

    .line 183
    .line 184
    .line 185
    invoke-interface {p1}, Lg3/d;->D0()J

    .line 186
    .line 187
    .line 188
    move-result-wide v6

    .line 189
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    invoke-virtual {p0}, Lgw0/c;->o()J

    .line 194
    .line 195
    .line 196
    move-result-wide v8

    .line 197
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    invoke-interface {v1}, Le3/r;->o()V

    .line 202
    .line 203
    .line 204
    :try_start_0
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v1, Lbu/c;

    .line 207
    .line 208
    const/high16 v3, 0x42b40000    # 90.0f

    .line 209
    .line 210
    invoke-virtual {v1, v6, v7, v3}, Lbu/c;->z(JF)V

    .line 211
    .line 212
    .line 213
    invoke-interface {p1, v0}, Lt4/c;->w0(F)F

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    invoke-interface {p1, v2}, Lt4/c;->w0(F)F

    .line 218
    .line 219
    .line 220
    move-result v3

    .line 221
    invoke-static {p1, v1, v3, v4, v5}, Ldl/d;->e(Lg3/d;FFJ)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 222
    .line 223
    .line 224
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 225
    .line 226
    .line 227
    move-result-object v1

    .line 228
    invoke-interface {v1}, Le3/r;->i()V

    .line 229
    .line 230
    .line 231
    invoke-virtual {p0, v8, v9}, Lgw0/c;->B(J)V

    .line 232
    .line 233
    .line 234
    invoke-interface {p1}, Lg3/d;->D0()J

    .line 235
    .line 236
    .line 237
    move-result-wide v6

    .line 238
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    invoke-virtual {p0}, Lgw0/c;->o()J

    .line 243
    .line 244
    .line 245
    move-result-wide v8

    .line 246
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    invoke-interface {v1}, Le3/r;->o()V

    .line 251
    .line 252
    .line 253
    :try_start_1
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 254
    .line 255
    check-cast v1, Lbu/c;

    .line 256
    .line 257
    const/high16 v3, 0x43340000    # 180.0f

    .line 258
    .line 259
    invoke-virtual {v1, v6, v7, v3}, Lbu/c;->z(JF)V

    .line 260
    .line 261
    .line 262
    invoke-interface {p1, v0}, Lt4/c;->w0(F)F

    .line 263
    .line 264
    .line 265
    move-result v1

    .line 266
    invoke-interface {p1, v2}, Lt4/c;->w0(F)F

    .line 267
    .line 268
    .line 269
    move-result v3

    .line 270
    invoke-static {p1, v1, v3, v4, v5}, Ldl/d;->e(Lg3/d;FFJ)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 271
    .line 272
    .line 273
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    invoke-interface {v1}, Le3/r;->i()V

    .line 278
    .line 279
    .line 280
    invoke-virtual {p0, v8, v9}, Lgw0/c;->B(J)V

    .line 281
    .line 282
    .line 283
    invoke-interface {p1}, Lg3/d;->D0()J

    .line 284
    .line 285
    .line 286
    move-result-wide v6

    .line 287
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    invoke-virtual {p0}, Lgw0/c;->o()J

    .line 292
    .line 293
    .line 294
    move-result-wide v8

    .line 295
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 296
    .line 297
    .line 298
    move-result-object v1

    .line 299
    invoke-interface {v1}, Le3/r;->o()V

    .line 300
    .line 301
    .line 302
    :try_start_2
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 303
    .line 304
    check-cast v1, Lbu/c;

    .line 305
    .line 306
    const/high16 v3, 0x43870000    # 270.0f

    .line 307
    .line 308
    invoke-virtual {v1, v6, v7, v3}, Lbu/c;->z(JF)V

    .line 309
    .line 310
    .line 311
    invoke-interface {p1, v0}, Lt4/c;->w0(F)F

    .line 312
    .line 313
    .line 314
    move-result v0

    .line 315
    invoke-interface {p1, v2}, Lt4/c;->w0(F)F

    .line 316
    .line 317
    .line 318
    move-result v1

    .line 319
    invoke-static {p1, v0, v1, v4, v5}, Ldl/d;->e(Lg3/d;FFJ)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 320
    .line 321
    .line 322
    invoke-static {p0, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 323
    .line 324
    .line 325
    goto/16 :goto_0

    .line 326
    .line 327
    :catchall_0
    move-exception v0

    .line 328
    move-object p1, v0

    .line 329
    invoke-static {p0, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 330
    .line 331
    .line 332
    throw p1

    .line 333
    :catchall_1
    move-exception v0

    .line 334
    move-object p1, v0

    .line 335
    invoke-static {p0, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 336
    .line 337
    .line 338
    throw p1

    .line 339
    :catchall_2
    move-exception v0

    .line 340
    move-object p1, v0

    .line 341
    invoke-static {p0, v8, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 342
    .line 343
    .line 344
    throw p1

    .line 345
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
