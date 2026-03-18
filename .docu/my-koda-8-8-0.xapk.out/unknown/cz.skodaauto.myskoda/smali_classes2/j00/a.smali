.class public final synthetic Lj00/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lj00/a;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 13

    .line 1
    iget p0, p0, Lj00/a;->d:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    const/4 v1, 0x0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object p0, Lje/i;->Companion:Lje/a;

    .line 9
    .line 10
    invoke-virtual {p0}, Lje/a;->serializer()Lqz0/a;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    sget-object p0, Lje/i;->Companion:Lje/a;

    .line 16
    .line 17
    invoke-virtual {p0}, Lje/a;->serializer()Lqz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :pswitch_1
    new-instance p0, Luz0/d;

    .line 23
    .line 24
    sget-object v0, Lje/a0;->a:Lje/a0;

    .line 25
    .line 26
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_2
    new-instance p0, Luz0/d;

    .line 31
    .line 32
    sget-object v0, Lje/j0;->a:Lje/j0;

    .line 33
    .line 34
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_3
    invoke-static {}, Lje/m0;->values()[Lje/m0;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    const-string v10, "Nov"

    .line 43
    .line 44
    const-string v11, "Dec"

    .line 45
    .line 46
    const-string v0, "Jan"

    .line 47
    .line 48
    const-string v1, "Feb"

    .line 49
    .line 50
    const-string v2, "Mar"

    .line 51
    .line 52
    const-string v3, "Apr"

    .line 53
    .line 54
    const-string v4, "May"

    .line 55
    .line 56
    const-string v5, "Jun"

    .line 57
    .line 58
    const-string v6, "Jul"

    .line 59
    .line 60
    const-string v7, "Aug"

    .line 61
    .line 62
    const-string v8, "Sep"

    .line 63
    .line 64
    const-string v9, "Oct"

    .line 65
    .line 66
    filled-new-array/range {v0 .. v11}, [Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    const/4 v11, 0x0

    .line 71
    const/4 v12, 0x0

    .line 72
    const/4 v1, 0x0

    .line 73
    const/4 v2, 0x0

    .line 74
    const/4 v3, 0x0

    .line 75
    const/4 v4, 0x0

    .line 76
    const/4 v5, 0x0

    .line 77
    const/4 v6, 0x0

    .line 78
    const/4 v7, 0x0

    .line 79
    const/4 v8, 0x0

    .line 80
    const/4 v9, 0x0

    .line 81
    const/4 v10, 0x0

    .line 82
    filled-new-array/range {v1 .. v12}, [[Ljava/lang/annotation/Annotation;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    const-string v2, "cariad.charging.multicharge.kitten.kola.models.KolaMonth.Month"

    .line 87
    .line 88
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :pswitch_4
    sget-object p0, Lje/m0;->Companion:Lje/l0;

    .line 94
    .line 95
    invoke-virtual {p0}, Lje/l0;->serializer()Lqz0/a;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :pswitch_5
    new-instance p0, Luz0/d;

    .line 101
    .line 102
    sget-object v0, Lje/g0;->a:Lje/g0;

    .line 103
    .line 104
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 105
    .line 106
    .line 107
    return-object p0

    .line 108
    :pswitch_6
    new-instance p0, Luz0/d;

    .line 109
    .line 110
    sget-object v0, Lje/v;->a:Lje/v;

    .line 111
    .line 112
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 113
    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_7
    invoke-static {}, Lje/y;->values()[Lje/y;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    const-string v5, "Sat"

    .line 121
    .line 122
    const-string v6, "Sun"

    .line 123
    .line 124
    const-string v0, "Mon"

    .line 125
    .line 126
    const-string v1, "Tue"

    .line 127
    .line 128
    const-string v2, "Wed"

    .line 129
    .line 130
    const-string v3, "Thu"

    .line 131
    .line 132
    const-string v4, "Fri"

    .line 133
    .line 134
    filled-new-array/range {v0 .. v6}, [Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    const/4 v6, 0x0

    .line 139
    const/4 v7, 0x0

    .line 140
    const/4 v1, 0x0

    .line 141
    const/4 v2, 0x0

    .line 142
    const/4 v3, 0x0

    .line 143
    const/4 v4, 0x0

    .line 144
    const/4 v5, 0x0

    .line 145
    filled-new-array/range {v1 .. v7}, [[Ljava/lang/annotation/Annotation;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    const-string v2, "cariad.charging.multicharge.kitten.kola.models.KolaDay.Day"

    .line 150
    .line 151
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    return-object p0

    .line 156
    :pswitch_8
    sget-object p0, Lje/y;->Companion:Lje/x;

    .line 157
    .line 158
    invoke-virtual {p0}, Lje/x;->serializer()Lqz0/a;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0

    .line 163
    :pswitch_9
    new-instance p0, Luz0/d;

    .line 164
    .line 165
    sget-object v0, Lje/p;->a:Lje/p;

    .line 166
    .line 167
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 168
    .line 169
    .line 170
    return-object p0

    .line 171
    :pswitch_a
    new-instance p0, Luz0/d;

    .line 172
    .line 173
    sget-object v0, Lje/o0;->a:Lje/o0;

    .line 174
    .line 175
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 176
    .line 177
    .line 178
    return-object p0

    .line 179
    :pswitch_b
    new-instance p0, Luz0/d;

    .line 180
    .line 181
    sget-object v0, Lje/m;->a:Lje/m;

    .line 182
    .line 183
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 184
    .line 185
    .line 186
    return-object p0

    .line 187
    :pswitch_c
    new-instance p0, Luz0/d;

    .line 188
    .line 189
    sget-object v0, Lje/r0;->a:Lje/r0;

    .line 190
    .line 191
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 192
    .line 193
    .line 194
    return-object p0

    .line 195
    :pswitch_d
    new-instance v2, Lqz0/f;

    .line 196
    .line 197
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 198
    .line 199
    const-class v3, Lje/i;

    .line 200
    .line 201
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    const-class v3, Lje/d;

    .line 206
    .line 207
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    const-class v5, Lje/h;

    .line 212
    .line 213
    invoke-virtual {p0, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    const/4 v5, 0x2

    .line 218
    move v6, v5

    .line 219
    new-array v5, v6, [Lhy0/d;

    .line 220
    .line 221
    aput-object v3, v5, v1

    .line 222
    .line 223
    aput-object p0, v5, v0

    .line 224
    .line 225
    new-array v6, v6, [Lqz0/a;

    .line 226
    .line 227
    sget-object p0, Lje/b;->a:Lje/b;

    .line 228
    .line 229
    aput-object p0, v6, v1

    .line 230
    .line 231
    sget-object p0, Lje/f;->a:Lje/f;

    .line 232
    .line 233
    aput-object p0, v6, v0

    .line 234
    .line 235
    new-instance p0, Lje/e;

    .line 236
    .line 237
    invoke-direct {p0, v1}, Lje/e;-><init>(I)V

    .line 238
    .line 239
    .line 240
    new-array v7, v0, [Ljava/lang/annotation/Annotation;

    .line 241
    .line 242
    aput-object p0, v7, v1

    .line 243
    .line 244
    const-string v3, "cariad.charging.multicharge.kitten.kola.models.KolaConfig"

    .line 245
    .line 246
    invoke-direct/range {v2 .. v7}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 247
    .line 248
    .line 249
    return-object v2

    .line 250
    :pswitch_e
    invoke-static {}, Lj91/j;->a()Lj91/f;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    return-object p0

    .line 255
    :pswitch_f
    invoke-static {}, Lj91/h;->a()Lj91/e;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    return-object p0

    .line 260
    :pswitch_10
    new-instance p0, Lj91/d;

    .line 261
    .line 262
    int-to-float v0, v0

    .line 263
    const/4 v1, 0x3

    .line 264
    int-to-float v1, v1

    .line 265
    const/4 v2, 0x4

    .line 266
    int-to-float v2, v2

    .line 267
    const/4 v3, 0x6

    .line 268
    int-to-float v3, v3

    .line 269
    invoke-direct {p0, v0, v1, v2, v3}, Lj91/d;-><init>(FFFF)V

    .line 270
    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_11
    new-instance p0, Lj91/c;

    .line 274
    .line 275
    invoke-direct {p0}, Lj91/c;-><init>()V

    .line 276
    .line 277
    .line 278
    return-object p0

    .line 279
    :pswitch_12
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->b()Ljava/lang/String;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    return-object p0

    .line 284
    :pswitch_13
    const-string p0, "Successfully unregistered RKE event callback."

    .line 285
    .line 286
    return-object p0

    .line 287
    :pswitch_14
    const-string p0, "Unregistering RKE event callback..."

    .line 288
    .line 289
    return-object p0

    .line 290
    :pswitch_15
    const-string p0, "Successfully registered RKE event callback."

    .line 291
    .line 292
    return-object p0

    .line 293
    :pswitch_16
    const-string p0, "Registering RKE event callback..."

    .line 294
    .line 295
    return-object p0

    .line 296
    :pswitch_17
    const-string p0, "Successfully unregistered connection status callback."

    .line 297
    .line 298
    return-object p0

    .line 299
    :pswitch_18
    const-string p0, "Unregistering connection status callback..."

    .line 300
    .line 301
    return-object p0

    .line 302
    :pswitch_19
    const-string p0, "Successfully registered connection status callback."

    .line 303
    .line 304
    return-object p0

    .line 305
    :pswitch_1a
    const-string p0, "Registering connection status callback..."

    .line 306
    .line 307
    return-object p0

    .line 308
    :pswitch_1b
    new-instance p0, Lj2/p;

    .line 309
    .line 310
    new-instance v0, Lc1/c;

    .line 311
    .line 312
    const/4 v1, 0x0

    .line 313
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    sget-object v2, Lc1/d;->j:Lc1/b2;

    .line 318
    .line 319
    const/4 v3, 0x0

    .line 320
    const/16 v4, 0xc

    .line 321
    .line 322
    invoke-direct {v0, v1, v2, v3, v4}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 323
    .line 324
    .line 325
    invoke-direct {p0, v0}, Lj2/p;-><init>(Lc1/c;)V

    .line 326
    .line 327
    .line 328
    return-object p0

    .line 329
    :pswitch_1c
    new-instance p0, Lcom/squareup/moshi/Moshi$Builder;

    .line 330
    .line 331
    invoke-direct {p0}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 332
    .line 333
    .line 334
    new-instance v0, Lbx/d;

    .line 335
    .line 336
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 337
    .line 338
    .line 339
    iget-object v1, p0, Lcom/squareup/moshi/Moshi$Builder;->a:Ljava/util/ArrayList;

    .line 340
    .line 341
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    new-instance v0, Lcom/squareup/moshi/Moshi;

    .line 345
    .line 346
    invoke-direct {v0, p0}, Lcom/squareup/moshi/Moshi;-><init>(Lcom/squareup/moshi/Moshi$Builder;)V

    .line 347
    .line 348
    .line 349
    return-object v0

    .line 350
    nop

    .line 351
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
