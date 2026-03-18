.class public final Lis0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lis0/e;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget p0, p0, Lis0/e;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    packed-switch p0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    check-cast p1, Ll2/b1;

    .line 8
    .line 9
    instance-of p0, p1, Lv2/m;

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    check-cast p1, Lv2/m;

    .line 14
    .line 15
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sget-object v0, Ll4/v;->d:Lu2/l;

    .line 29
    .line 30
    iget-object v0, v0, Lu2/l;->b:Lay0/k;

    .line 31
    .line 32
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :cond_0
    invoke-interface {p1}, Lv2/m;->l()Ll2/n2;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const-string p1, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutationPolicy<T of androidx.compose.runtime.saveable.RememberSaveableKt.mutableStateSaver?>"

    .line 41
    .line 42
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    new-instance p1, Ll2/j1;

    .line 46
    .line 47
    invoke-direct {p1, v0, p0}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    const-string p1, "Failed requirement."

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :pswitch_0
    check-cast p1, Lzb0/a;

    .line 60
    .line 61
    if-eqz p1, :cond_6

    .line 62
    .line 63
    invoke-static {}, Lwb0/c;->a()Lcom/squareup/moshi/Moshi;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-class v1, Lcz/skodaauto/myskoda/library/asyncevent/data/VehicleConnectionStatusEventDataDto;

    .line 68
    .line 69
    sget-object v2, Lax/b;->a:Ljava/util/Set;

    .line 70
    .line 71
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    iget-object v2, p1, Lzb0/a;->a:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v3, p1, Lzb0/a;->b:Ljava/time/OffsetDateTime;

    .line 78
    .line 79
    iget-object v4, p1, Lzb0/a;->c:Ljava/lang/String;

    .line 80
    .line 81
    iget-object v5, p1, Lzb0/a;->d:Ljava/lang/String;

    .line 82
    .line 83
    iget-object p1, p1, Lzb0/a;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p1, Lzb0/b;

    .line 86
    .line 87
    if-eqz p1, :cond_2

    .line 88
    .line 89
    iget-object p1, p1, Lzb0/b;->a:Ljava/lang/String;

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_2
    move-object p1, v0

    .line 93
    :goto_0
    if-eqz p1, :cond_5

    .line 94
    .line 95
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;

    .line 100
    .line 101
    if-eqz p0, :cond_5

    .line 102
    .line 103
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VehicleConnectionStatusEventDataDto;

    .line 104
    .line 105
    new-instance v0, Ltu0/f;

    .line 106
    .line 107
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/asyncevent/data/VehicleConnectionStatusEventDataDto;->getWakeupProgress()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    const-string p1, "WAKING_UP"

    .line 112
    .line 113
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-eqz p1, :cond_3

    .line 118
    .line 119
    sget-object p0, Ltu0/h;->e:Ltu0/h;

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_3
    const-string p1, "WOKE"

    .line 123
    .line 124
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    if-eqz p0, :cond_4

    .line 129
    .line 130
    sget-object p0, Ltu0/h;->f:Ltu0/h;

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_4
    sget-object p0, Ltu0/h;->d:Ltu0/h;

    .line 134
    .line 135
    :goto_1
    invoke-direct {v0, p0}, Ltu0/f;-><init>(Ltu0/h;)V

    .line 136
    .line 137
    .line 138
    :cond_5
    move-object v6, v0

    .line 139
    new-instance v1, Lzb0/a;

    .line 140
    .line 141
    invoke-direct/range {v1 .. v6}, Lzb0/a;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    move-object v0, v1

    .line 145
    :cond_6
    return-object v0

    .line 146
    :pswitch_1
    check-cast p1, Lzb0/a;

    .line 147
    .line 148
    if-eqz p1, :cond_c

    .line 149
    .line 150
    invoke-static {}, Lwb0/c;->a()Lcom/squareup/moshi/Moshi;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    const-class v1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;

    .line 155
    .line 156
    sget-object v2, Lax/b;->a:Ljava/util/Set;

    .line 157
    .line 158
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    iget-object v2, p1, Lzb0/a;->a:Ljava/lang/String;

    .line 163
    .line 164
    iget-object v3, p1, Lzb0/a;->b:Ljava/time/OffsetDateTime;

    .line 165
    .line 166
    iget-object v4, p1, Lzb0/a;->c:Ljava/lang/String;

    .line 167
    .line 168
    iget-object v5, p1, Lzb0/a;->d:Ljava/lang/String;

    .line 169
    .line 170
    iget-object p1, p1, Lzb0/a;->e:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast p1, Lzb0/b;

    .line 173
    .line 174
    if-eqz p1, :cond_7

    .line 175
    .line 176
    iget-object p1, p1, Lzb0/b;->a:Ljava/lang/String;

    .line 177
    .line 178
    goto :goto_2

    .line 179
    :cond_7
    move-object p1, v0

    .line 180
    :goto_2
    if-eqz p1, :cond_b

    .line 181
    .line 182
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;

    .line 187
    .line 188
    if-eqz p0, :cond_b

    .line 189
    .line 190
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;

    .line 191
    .line 192
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->getChargingState()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    const-string v1, "charging"

    .line 197
    .line 198
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result p1

    .line 202
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->getStateOfChargeInPercent()Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    if-eqz v1, :cond_8

    .line 207
    .line 208
    invoke-static {v1}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    if-eqz v1, :cond_8

    .line 213
    .line 214
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 215
    .line 216
    .line 217
    move-result v1

    .line 218
    new-instance v6, Lqr0/l;

    .line 219
    .line 220
    invoke-direct {v6, v1}, Lqr0/l;-><init>(I)V

    .line 221
    .line 222
    .line 223
    goto :goto_3

    .line 224
    :cond_8
    move-object v6, v0

    .line 225
    :goto_3
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->getCruisingRangeInKm()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    if-eqz v1, :cond_9

    .line 230
    .line 231
    invoke-static {v1}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    if-eqz v1, :cond_9

    .line 236
    .line 237
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 238
    .line 239
    .line 240
    move-result v1

    .line 241
    int-to-double v7, v1

    .line 242
    const-wide v9, 0x408f400000000000L    # 1000.0

    .line 243
    .line 244
    .line 245
    .line 246
    .line 247
    mul-double/2addr v7, v9

    .line 248
    new-instance v1, Lqr0/d;

    .line 249
    .line 250
    invoke-direct {v1, v7, v8}, Lqr0/d;-><init>(D)V

    .line 251
    .line 252
    .line 253
    goto :goto_4

    .line 254
    :cond_9
    move-object v1, v0

    .line 255
    :goto_4
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->getRemainingChargingTimeInMinutes()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    if-eqz p0, :cond_a

    .line 260
    .line 261
    invoke-static {p0}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 262
    .line 263
    .line 264
    move-result-object p0

    .line 265
    if-eqz p0, :cond_a

    .line 266
    .line 267
    sget v0, Lmy0/c;->g:I

    .line 268
    .line 269
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 270
    .line 271
    .line 272
    move-result p0

    .line 273
    sget-object v0, Lmy0/e;->i:Lmy0/e;

    .line 274
    .line 275
    invoke-static {p0, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 276
    .line 277
    .line 278
    move-result-wide v7

    .line 279
    new-instance v0, Lmy0/c;

    .line 280
    .line 281
    invoke-direct {v0, v7, v8}, Lmy0/c;-><init>(J)V

    .line 282
    .line 283
    .line 284
    :cond_a
    new-instance p0, Lrd0/l;

    .line 285
    .line 286
    invoke-direct {p0, p1, v6, v1, v0}, Lrd0/l;-><init>(ZLqr0/l;Lqr0/d;Lmy0/c;)V

    .line 287
    .line 288
    .line 289
    move-object v0, p0

    .line 290
    :cond_b
    move-object v6, v0

    .line 291
    new-instance v1, Lzb0/a;

    .line 292
    .line 293
    invoke-direct/range {v1 .. v6}, Lzb0/a;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    move-object v0, v1

    .line 297
    :cond_c
    return-object v0

    .line 298
    :pswitch_2
    check-cast p1, Lzb0/a;

    .line 299
    .line 300
    if-eqz p1, :cond_f

    .line 301
    .line 302
    invoke-static {}, Lwb0/c;->a()Lcom/squareup/moshi/Moshi;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    const-class v1, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;

    .line 307
    .line 308
    sget-object v2, Lax/b;->a:Ljava/util/Set;

    .line 309
    .line 310
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    iget-object v2, p1, Lzb0/a;->a:Ljava/lang/String;

    .line 315
    .line 316
    iget-object v3, p1, Lzb0/a;->b:Ljava/time/OffsetDateTime;

    .line 317
    .line 318
    iget-object v4, p1, Lzb0/a;->c:Ljava/lang/String;

    .line 319
    .line 320
    iget-object v5, p1, Lzb0/a;->d:Ljava/lang/String;

    .line 321
    .line 322
    iget-object p1, p1, Lzb0/a;->e:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast p1, Lzb0/b;

    .line 325
    .line 326
    if-eqz p1, :cond_d

    .line 327
    .line 328
    iget-object p1, p1, Lzb0/b;->a:Ljava/lang/String;

    .line 329
    .line 330
    goto :goto_5

    .line 331
    :cond_d
    move-object p1, v0

    .line 332
    :goto_5
    if-eqz p1, :cond_e

    .line 333
    .line 334
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object p0

    .line 338
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;

    .line 339
    .line 340
    if-eqz p0, :cond_e

    .line 341
    .line 342
    check-cast p0, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;

    .line 343
    .line 344
    new-instance v0, Lms0/e;

    .line 345
    .line 346
    invoke-virtual {p0}, Lcz/skodaauto/myskoda/library/asyncevent/data/UserNominationEventDataDto;->getVin()Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    invoke-direct {v0, p0}, Lms0/e;-><init>(Ljava/lang/String;)V

    .line 351
    .line 352
    .line 353
    :cond_e
    move-object v6, v0

    .line 354
    new-instance v1, Lzb0/a;

    .line 355
    .line 356
    invoke-direct/range {v1 .. v6}, Lzb0/a;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 357
    .line 358
    .line 359
    move-object v0, v1

    .line 360
    :cond_f
    return-object v0

    .line 361
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
