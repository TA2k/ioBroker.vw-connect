.class public final synthetic Lfl/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr1/b;


# direct methods
.method public synthetic constructor <init>(Lr1/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfl/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfl/h;->e:Lr1/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lfl/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lhi/a;

    .line 7
    .line 8
    const-string v0, "$this$single"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    const-class v1, Lretrofit2/Retrofit;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast p1, Lii/a;

    .line 22
    .line 23
    invoke-virtual {p1, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Lretrofit2/Retrofit;

    .line 28
    .line 29
    const-class v2, Lni/c;

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Lretrofit2/Retrofit;->b(Ljava/lang/Class;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Lni/c;

    .line 36
    .line 37
    new-instance v4, Lni/b;

    .line 38
    .line 39
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-direct {v4, v1}, Lni/b;-><init>(Lni/c;)V

    .line 43
    .line 44
    .line 45
    const-class v1, Lqi/a;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p1, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Lqi/a;

    .line 56
    .line 57
    new-instance v13, Lpi/b;

    .line 58
    .line 59
    const-class v2, Lvy0/b0;

    .line 60
    .line 61
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    check-cast p1, Lvy0/b0;

    .line 70
    .line 71
    new-instance v2, Ljd/b;

    .line 72
    .line 73
    const/4 v8, 0x0

    .line 74
    const/4 v9, 0x4

    .line 75
    const/4 v3, 0x2

    .line 76
    const-class v5, Lni/b;

    .line 77
    .line 78
    const-string v6, "getChargingServiceProvider"

    .line 79
    .line 80
    const-string v7, "getChargingServiceProvider-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 81
    .line 82
    invoke-direct/range {v2 .. v9}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 83
    .line 84
    .line 85
    new-instance v5, Ljd/b;

    .line 86
    .line 87
    const/4 v11, 0x0

    .line 88
    const/4 v12, 0x5

    .line 89
    const/4 v6, 0x2

    .line 90
    const-class v8, Lqi/a;

    .line 91
    .line 92
    const-string v9, "setServiceProviders"

    .line 93
    .line 94
    const-string v10, "setServiceProviders$common_charging_service_provider_release(Lcariad/charging/multicharge/sdk/common/provider/models/HeadlessChargingServiceProviderGetResponse;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 95
    .line 96
    move-object v7, v1

    .line 97
    invoke-direct/range {v5 .. v12}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 98
    .line 99
    .line 100
    move-object v0, v5

    .line 101
    new-instance v5, Ll20/c;

    .line 102
    .line 103
    const/16 v12, 0x16

    .line 104
    .line 105
    const/4 v6, 0x0

    .line 106
    const-class v8, Lqi/a;

    .line 107
    .line 108
    const-string v9, "getServiceProviders"

    .line 109
    .line 110
    const-string v10, "getServiceProviders$common_charging_service_provider_release()Lcariad/charging/multicharge/sdk/common/provider/models/HeadlessChargingServiceProviderGetResponse;"

    .line 111
    .line 112
    invoke-direct/range {v5 .. v12}, Ll20/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 113
    .line 114
    .line 115
    iget-object v7, p0, Lfl/h;->e:Lr1/b;

    .line 116
    .line 117
    move-object v6, p1

    .line 118
    move-object v9, v0

    .line 119
    move-object v8, v2

    .line 120
    move-object v10, v5

    .line 121
    move-object v5, v13

    .line 122
    invoke-direct/range {v5 .. v10}, Lpi/b;-><init>(Lvy0/b0;Lr1/b;Ljd/b;Ljd/b;Ll20/c;)V

    .line 123
    .line 124
    .line 125
    return-object v5

    .line 126
    :pswitch_0
    check-cast p1, Lhi/c;

    .line 127
    .line 128
    const-string v0, "$this$module"

    .line 129
    .line 130
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    new-instance v0, Lfl/h;

    .line 134
    .line 135
    const/4 v1, 0x2

    .line 136
    iget-object p0, p0, Lfl/h;->e:Lr1/b;

    .line 137
    .line 138
    invoke-direct {v0, p0, v1}, Lfl/h;-><init>(Lr1/b;I)V

    .line 139
    .line 140
    .line 141
    new-instance p0, Lii/b;

    .line 142
    .line 143
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 144
    .line 145
    const-class v2, Lpi/b;

    .line 146
    .line 147
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    const/4 v3, 0x0

    .line 152
    invoke-direct {p0, v3, v0, v2}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 153
    .line 154
    .line 155
    iget-object p1, p1, Lhi/c;->a:Ljava/util/ArrayList;

    .line 156
    .line 157
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    new-instance p0, Lkq0/a;

    .line 161
    .line 162
    const/16 v0, 0x11

    .line 163
    .line 164
    invoke-direct {p0, v0}, Lkq0/a;-><init>(I)V

    .line 165
    .line 166
    .line 167
    new-instance v0, Lii/b;

    .line 168
    .line 169
    const-class v2, Lqi/a;

    .line 170
    .line 171
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    invoke-direct {v0, v3, p0, v1}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 182
    .line 183
    return-object p0

    .line 184
    :pswitch_1
    check-cast p1, Ld01/j0;

    .line 185
    .line 186
    const-string v0, "$this$addHeaders"

    .line 187
    .line 188
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    const-string v0, "Content-Type"

    .line 192
    .line 193
    const-string v1, "application/json"

    .line 194
    .line 195
    invoke-virtual {p1, v0, v1}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    iget-object p0, p0, Lfl/h;->e:Lr1/b;

    .line 199
    .line 200
    iget-object p0, p0, Lr1/b;->e:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast p0, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 203
    .line 204
    invoke-static {p0}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->B(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;)Ljava/util/Locale;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    invoke-virtual {p0}, Ljava/util/Locale;->toLanguageTag()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    const-string v0, "toLanguageTag(...)"

    .line 213
    .line 214
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    const-string v0, "Accept-Language"

    .line 218
    .line 219
    invoke-virtual {p1, v0, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    const-string p0, "X-Brand"

    .line 223
    .line 224
    const-string v0, "skoda"

    .line 225
    .line 226
    invoke-virtual {p1, p0, v0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    const-string p0, "X-Platform"

    .line 230
    .line 231
    const-string v0, "android"

    .line 232
    .line 233
    invoke-virtual {p1, p0, v0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    invoke-virtual {p0}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    const-string v0, "getId(...)"

    .line 245
    .line 246
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    const-string v0, "X-Device-Timezone"

    .line 250
    .line 251
    invoke-virtual {p1, v0, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    const-string p0, "X-Sdk-Version"

    .line 255
    .line 256
    const-string v0, "4.12.3"

    .line 257
    .line 258
    invoke-virtual {p1, p0, v0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    const-string p0, "X-Use-BffError-V2"

    .line 262
    .line 263
    const-string v0, "true"

    .line 264
    .line 265
    invoke-virtual {p1, p0, v0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    sget-object p0, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 269
    .line 270
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    invoke-static {p0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 274
    .line 275
    .line 276
    move-result v0

    .line 277
    const/4 v1, 0x0

    .line 278
    if-nez v0, :cond_0

    .line 279
    .line 280
    goto :goto_1

    .line 281
    :cond_0
    move-object p0, v1

    .line 282
    :goto_1
    if-nez p0, :cond_1

    .line 283
    .line 284
    sget-object p0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 285
    .line 286
    :cond_1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 287
    .line 288
    .line 289
    const-string v0, "X-Device-Manufacturer"

    .line 290
    .line 291
    invoke-virtual {p1, v0, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    sget-object p0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 295
    .line 296
    const-string v0, "MODEL"

    .line 297
    .line 298
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    const-string v0, "X-Device-Name"

    .line 302
    .line 303
    invoke-virtual {p1, v0, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    sget-object p0, Landroid/os/Build$VERSION;->CODENAME:Ljava/lang/String;

    .line 307
    .line 308
    const-string v0, "REL"

    .line 309
    .line 310
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 311
    .line 312
    .line 313
    move-result v0

    .line 314
    if-nez v0, :cond_2

    .line 315
    .line 316
    move-object v1, p0

    .line 317
    :cond_2
    if-nez v1, :cond_3

    .line 318
    .line 319
    sget-object v1, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 320
    .line 321
    :cond_3
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    const-string p0, "X-Device-OS-Name"

    .line 325
    .line 326
    invoke-virtual {p1, p0, v1}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 330
    .line 331
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object p0

    .line 335
    const-string v0, "X-Device-OS-Version"

    .line 336
    .line 337
    invoke-virtual {p1, v0, p0}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    goto/16 :goto_0

    .line 341
    .line 342
    nop

    .line 343
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
