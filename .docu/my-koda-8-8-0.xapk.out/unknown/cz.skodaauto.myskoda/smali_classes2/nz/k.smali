.class public final synthetic Lnz/k;
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
    iput p1, p0, Lnz/k;->d:I

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
    .locals 4

    .line 1
    iget p0, p0, Lnz/k;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Luz0/d;

    .line 7
    .line 8
    sget-object v0, Lpd/q;->a:Lpd/q;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 12
    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_0
    new-instance p0, Luz0/d;

    .line 16
    .line 17
    sget-object v0, Lpd/n;->a:Lpd/n;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_1
    new-instance p0, Luz0/d;

    .line 25
    .line 26
    sget-object v0, Lpd/w;->a:Lpd/w;

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_2
    new-instance p0, Luz0/d;

    .line 34
    .line 35
    sget-object v0, Lpd/d;->a:Lpd/d;

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_3
    invoke-static {}, Lpd/l;->values()[Lpd/l;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const-string v0, "PRICE_DETAILS"

    .line 47
    .line 48
    const-string v1, "PRICE_EDIT"

    .line 49
    .line 50
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    const/4 v1, 0x0

    .line 55
    filled-new-array {v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.ChargingStatisticsEntryDetails.TotalCostCta"

    .line 60
    .line 61
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :pswitch_4
    sget-object p0, Lpd/l;->Companion:Lpd/k;

    .line 67
    .line 68
    invoke-virtual {p0}, Lpd/k;->serializer()Lqz0/a;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_5
    new-instance p0, Luz0/d;

    .line 74
    .line 75
    sget-object v0, Lpd/a;->a:Lpd/a;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_6
    invoke-static {}, Lpd/f;->values()[Lpd/f;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    const-string v0, "HOME"

    .line 87
    .line 88
    const-string v1, "UNKNOWN"

    .line 89
    .line 90
    const-string v2, "PUBLIC"

    .line 91
    .line 92
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    const/4 v1, 0x0

    .line 97
    filled-new-array {v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.ChargingStatisticsEntry.ChargingType"

    .line 102
    .line 103
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_7
    sget-object p0, Lpd/f;->Companion:Lpd/e;

    .line 109
    .line 110
    invoke-virtual {p0}, Lpd/e;->serializer()Lqz0/a;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :pswitch_8
    new-instance p0, Lx11/a;

    .line 116
    .line 117
    invoke-direct {p0}, Lx11/a;-><init>()V

    .line 118
    .line 119
    .line 120
    iget-object v0, p0, Lx11/a;->a:Landroidx/lifecycle/c1;

    .line 121
    .line 122
    invoke-virtual {v0}, Landroidx/lifecycle/c1;->n()V

    .line 123
    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_9
    invoke-static {}, Lcz/myskoda/api/bff_car_configurator/v3/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0

    .line 131
    :pswitch_a
    invoke-static {}, Lcz/myskoda/api/bff_car_configurator/v3/infrastructure/ApiClient;->c()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0

    .line 136
    :pswitch_b
    new-instance p0, Ljava/util/ArrayList;

    .line 137
    .line 138
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 139
    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_c
    new-instance p0, Ljava/util/ArrayList;

    .line 143
    .line 144
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 145
    .line 146
    .line 147
    return-object p0

    .line 148
    :pswitch_d
    invoke-static {}, Lof/o;->values()[Lof/o;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    const-string v0, "SHOW_INSTALLATION_SCREEN"

    .line 153
    .line 154
    const-string v1, "SHOW_UNINSTALLATION_SCREEN"

    .line 155
    .line 156
    const-string v2, "SHOW_OVERVIEW_SCREEN"

    .line 157
    .line 158
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    const/4 v1, 0x0

    .line 163
    filled-new-array {v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    const-string v2, "cariad.charging.multicharge.kitten.plugandcharge.models.PlugAndChargeOverviewGetResponse.ScreenToShow"

    .line 168
    .line 169
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    return-object p0

    .line 174
    :pswitch_e
    invoke-static {}, Lof/m;->values()[Lof/m;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    const-string v0, "SHOW_SUBSCRIBE_CTA"

    .line 179
    .line 180
    const-string v1, "SHOW_UPGRADE_CTA"

    .line 181
    .line 182
    const-string v2, "NONE"

    .line 183
    .line 184
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    const/4 v1, 0x0

    .line 189
    filled-new-array {v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    const-string v2, "cariad.charging.multicharge.kitten.plugandcharge.models.PlugAndChargeOverviewGetResponse.LinkOutCta"

    .line 194
    .line 195
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    return-object p0

    .line 200
    :pswitch_f
    invoke-static {}, Lof/j;->values()[Lof/j;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    const-string v0, "INACTIVE"

    .line 205
    .line 206
    const-string v1, "HIDDEN"

    .line 207
    .line 208
    const-string v2, "ACTIVE"

    .line 209
    .line 210
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    const/4 v1, 0x0

    .line 215
    filled-new-array {v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    const-string v2, "cariad.charging.multicharge.kitten.plugandcharge.models.PlugAndChargeOverviewGetResponse.ActivationStatus"

    .line 220
    .line 221
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    return-object p0

    .line 226
    :pswitch_10
    sget-object p0, Lof/j;->Companion:Lof/i;

    .line 227
    .line 228
    invoke-virtual {p0}, Lof/i;->serializer()Lqz0/a;

    .line 229
    .line 230
    .line 231
    move-result-object p0

    .line 232
    return-object p0

    .line 233
    :pswitch_11
    new-instance p0, Luz0/d;

    .line 234
    .line 235
    sget-object v0, Lof/a;->a:Lof/a;

    .line 236
    .line 237
    const/4 v1, 0x0

    .line 238
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 239
    .line 240
    .line 241
    return-object p0

    .line 242
    :pswitch_12
    sget-object p0, Lof/o;->Companion:Lof/n;

    .line 243
    .line 244
    invoke-virtual {p0}, Lof/n;->serializer()Lqz0/a;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    return-object p0

    .line 249
    :pswitch_13
    sget-object p0, Lof/m;->Companion:Lof/l;

    .line 250
    .line 251
    invoke-virtual {p0}, Lof/l;->serializer()Lqz0/a;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    return-object p0

    .line 256
    :pswitch_14
    invoke-static {}, Lof/f;->values()[Lof/f;

    .line 257
    .line 258
    .line 259
    move-result-object p0

    .line 260
    const-string v0, "SHOW_DEFAULT_POPUP"

    .line 261
    .line 262
    const-string v1, "SHOW_VEHICLE_POPUP"

    .line 263
    .line 264
    const-string v2, "DONT_SHOW_POPUP"

    .line 265
    .line 266
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    const/4 v1, 0x0

    .line 271
    filled-new-array {v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    const-string v2, "cariad.charging.multicharge.kitten.plugandcharge.models.Contract.PopUpToShow"

    .line 276
    .line 277
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 278
    .line 279
    .line 280
    move-result-object p0

    .line 281
    return-object p0

    .line 282
    :pswitch_15
    invoke-static {}, Lof/d;->values()[Lof/d;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    const-string v0, "ERROR"

    .line 287
    .line 288
    const-string v1, "UPDATE_REQUIRED"

    .line 289
    .line 290
    const-string v2, "ACTIVE"

    .line 291
    .line 292
    const-string v3, "NOT_ACTIVE"

    .line 293
    .line 294
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    const/4 v1, 0x0

    .line 299
    filled-new-array {v1, v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    const-string v2, "cariad.charging.multicharge.kitten.plugandcharge.models.Contract.ContractStatus"

    .line 304
    .line 305
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    return-object p0

    .line 310
    :pswitch_16
    sget-object p0, Lof/f;->Companion:Lof/e;

    .line 311
    .line 312
    invoke-virtual {p0}, Lof/e;->serializer()Lqz0/a;

    .line 313
    .line 314
    .line 315
    move-result-object p0

    .line 316
    return-object p0

    .line 317
    :pswitch_17
    sget-object p0, Lof/d;->Companion:Lof/c;

    .line 318
    .line 319
    invoke-virtual {p0}, Lof/c;->serializer()Lqz0/a;

    .line 320
    .line 321
    .line 322
    move-result-object p0

    .line 323
    return-object p0

    .line 324
    :pswitch_18
    sget-object p0, Ll90/a;->a:Ll90/a;

    .line 325
    .line 326
    return-object p0

    .line 327
    :pswitch_19
    new-instance p0, Llj0/a;

    .line 328
    .line 329
    const-string v0, "auxiliary_heating_gauge_temperature_button_plus"

    .line 330
    .line 331
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 332
    .line 333
    .line 334
    return-object p0

    .line 335
    :pswitch_1a
    new-instance p0, Llj0/a;

    .line 336
    .line 337
    const-string v0, "auxiliary_heating_set_duration_button_minus"

    .line 338
    .line 339
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    return-object p0

    .line 343
    :pswitch_1b
    new-instance p0, Llj0/a;

    .line 344
    .line 345
    const-string v0, "auxiliary_heating_gauge_temperature_button_minus"

    .line 346
    .line 347
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 348
    .line 349
    .line 350
    return-object p0

    .line 351
    :pswitch_1c
    new-instance p0, Llj0/a;

    .line 352
    .line 353
    const-string v0, "auxiliary_heating_set_duration_button_plus"

    .line 354
    .line 355
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    return-object p0

    .line 359
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
