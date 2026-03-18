.class public final synthetic Lvd/i;
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
    iput p1, p0, Lvd/i;->d:I

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
    .locals 5

    .line 1
    iget p0, p0, Lvd/i;->d:I

    .line 2
    .line 3
    const-string v0, "ACTIVE"

    .line 4
    .line 5
    const-string v1, "KoinApplication has not been started"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    packed-switch p0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lcz/myskoda/api/bff_loyalty_program/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_0
    invoke-static {}, Lcz/myskoda/api/bff_loyalty_program/v2/infrastructure/ApiClient;->b()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_1
    new-instance p0, Lwu/b;

    .line 22
    .line 23
    invoke-direct {p0}, Lwu/b;-><init>()V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_2
    new-instance p0, Lkj0/h;

    .line 28
    .line 29
    const-string v0, "SPIN - Enter SPIN - biometrics"

    .line 30
    .line 31
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_3
    new-instance p0, Lly0/n;

    .line 36
    .line 37
    const-string v0, "^[A-Z]+-[A-Z\\d]{8}-[A-Z\\d]{4}-[A-Z\\d]+$"

    .line 38
    .line 39
    invoke-direct {p0, v0}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_4
    new-instance p0, Lcom/squareup/moshi/Moshi$Builder;

    .line 44
    .line 45
    invoke-direct {p0}, Lcom/squareup/moshi/Moshi$Builder;-><init>()V

    .line 46
    .line 47
    .line 48
    new-instance v0, Lbx/d;

    .line 49
    .line 50
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/Moshi$Builder;->a(Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 54
    .line 55
    .line 56
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/JsonToStringAdapter;

    .line 57
    .line 58
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    new-instance v0, Lcz/skodaauto/myskoda/library/serialization/infrastructure/OffsetDateTimeAdapter;

    .line 65
    .line 66
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/Moshi$Builder;->b(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    new-instance v0, Lcom/squareup/moshi/Moshi;

    .line 73
    .line 74
    invoke-direct {v0, p0}, Lcom/squareup/moshi/Moshi;-><init>(Lcom/squareup/moshi/Moshi$Builder;)V

    .line 75
    .line 76
    .line 77
    return-object v0

    .line 78
    :pswitch_5
    new-instance p0, Luz0/d;

    .line 79
    .line 80
    sget-object v0, Lwb/a;->a:Lwb/a;

    .line 81
    .line 82
    const/4 v1, 0x0

    .line 83
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 84
    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_6
    invoke-static {}, Lwb/d;->values()[Lwb/d;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    const-string v1, "INACTIVE"

    .line 92
    .line 93
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    filled-new-array {v2, v2}, [[Ljava/lang/annotation/Annotation;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    const-string v2, "cariad.charging.multicharge.common.api.chargingcard.models.ChargingCard.Status"

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
    sget-object p0, Lwb/d;->Companion:Lwb/c;

    .line 109
    .line 110
    invoke-virtual {p0}, Lwb/c;->serializer()Lqz0/a;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :pswitch_8
    :try_start_0
    sget-object p0, Lwa/b;->g:Ljava/lang/Object;

    .line 116
    .line 117
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Ljava/lang/reflect/Method;

    .line 122
    .line 123
    if-eqz p0, :cond_0

    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-eqz p0, :cond_0

    .line 130
    .line 131
    const-string v0, "beginTransaction"

    .line 132
    .line 133
    sget-object v1, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 134
    .line 135
    const-class v3, Landroid/database/sqlite/SQLiteTransactionListener;

    .line 136
    .line 137
    const-class v4, Landroid/os/CancellationSignal;

    .line 138
    .line 139
    filled-new-array {v1, v3, v1, v4}, [Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    invoke-virtual {p0, v0, v1}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 144
    .line 145
    .line 146
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 147
    :catchall_0
    :cond_0
    return-object v2

    .line 148
    :pswitch_9
    :try_start_1
    const-class p0, Landroid/database/sqlite/SQLiteDatabase;

    .line 149
    .line 150
    const-string v0, "getThreadSession"

    .line 151
    .line 152
    invoke-virtual {p0, v0, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    const/4 v0, 0x1

    .line 157
    invoke-virtual {p0, v0}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 158
    .line 159
    .line 160
    move-object v2, p0

    .line 161
    :catchall_1
    return-object v2

    .line 162
    :pswitch_a
    sget-object p0, Lw2/e;->a:Ll2/u2;

    .line 163
    .line 164
    return-object v2

    .line 165
    :pswitch_b
    sget-object p0, Lw2/c;->a:Ll2/u2;

    .line 166
    .line 167
    return-object v2

    .line 168
    :pswitch_c
    sget-object p0, Lz11/a;->b:Landroidx/lifecycle/c1;

    .line 169
    .line 170
    if-eqz p0, :cond_1

    .line 171
    .line 172
    return-object p0

    .line 173
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 174
    .line 175
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    throw p0

    .line 179
    :pswitch_d
    sget-object p0, Lz11/a;->b:Landroidx/lifecycle/c1;

    .line 180
    .line 181
    if-eqz p0, :cond_2

    .line 182
    .line 183
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast p0, Li21/b;

    .line 186
    .line 187
    iget-object p0, p0, Li21/b;->d:Lk21/a;

    .line 188
    .line 189
    return-object p0

    .line 190
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 191
    .line 192
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 193
    .line 194
    .line 195
    throw p0

    .line 196
    :pswitch_e
    new-instance p0, Lw11/a;

    .line 197
    .line 198
    sget-object v0, Lz11/a;->b:Landroidx/lifecycle/c1;

    .line 199
    .line 200
    if-eqz v0, :cond_3

    .line 201
    .line 202
    iget-object v0, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast v0, Li21/b;

    .line 205
    .line 206
    iget-object v0, v0, Li21/b;->d:Lk21/a;

    .line 207
    .line 208
    new-instance v1, Lvd/i;

    .line 209
    .line 210
    const/16 v2, 0xf

    .line 211
    .line 212
    invoke-direct {v1, v2}, Lvd/i;-><init>(I)V

    .line 213
    .line 214
    .line 215
    invoke-direct {p0, v0, v1}, Lw11/a;-><init>(Ljava/lang/Object;Lay0/a;)V

    .line 216
    .line 217
    .line 218
    return-object p0

    .line 219
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 220
    .line 221
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p0

    .line 225
    :pswitch_f
    new-instance p0, Lw11/a;

    .line 226
    .line 227
    sget-object v0, Lz11/a;->b:Landroidx/lifecycle/c1;

    .line 228
    .line 229
    if-eqz v0, :cond_4

    .line 230
    .line 231
    new-instance v1, Lvd/i;

    .line 232
    .line 233
    const/16 v2, 0x10

    .line 234
    .line 235
    invoke-direct {v1, v2}, Lvd/i;-><init>(I)V

    .line 236
    .line 237
    .line 238
    invoke-direct {p0, v0, v1}, Lw11/a;-><init>(Ljava/lang/Object;Lay0/a;)V

    .line 239
    .line 240
    .line 241
    return-object p0

    .line 242
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 243
    .line 244
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw p0

    .line 248
    :pswitch_10
    sget-object p0, Lvz0/h;->b:Lvz0/g;

    .line 249
    .line 250
    return-object p0

    .line 251
    :pswitch_11
    sget-object p0, Lvz0/c0;->b:Lvz0/b0;

    .line 252
    .line 253
    return-object p0

    .line 254
    :pswitch_12
    sget-object p0, Lvz0/v;->b:Luz0/h1;

    .line 255
    .line 256
    return-object p0

    .line 257
    :pswitch_13
    sget-object p0, Lvz0/y;->b:Lsz0/h;

    .line 258
    .line 259
    return-object p0

    .line 260
    :pswitch_14
    sget-object p0, Lvz0/f0;->b:Lsz0/h;

    .line 261
    .line 262
    return-object p0

    .line 263
    :pswitch_15
    invoke-static {}, Lcz/myskoda/api/bff_garage/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 264
    .line 265
    .line 266
    move-result-object p0

    .line 267
    return-object p0

    .line 268
    :pswitch_16
    invoke-static {}, Lcz/myskoda/api/bff_garage/v2/infrastructure/ApiClient;->d()Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    return-object p0

    .line 273
    :pswitch_17
    sget p0, Lvu0/g;->a:F

    .line 274
    .line 275
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 276
    .line 277
    return-object p0

    .line 278
    :pswitch_18
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 279
    .line 280
    const-string v0, "PowerpassSDK not available"

    .line 281
    .line 282
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    throw p0

    .line 286
    :pswitch_19
    const-string p0, "Clear data and close MultiChargeSdk"

    .line 287
    .line 288
    return-object p0

    .line 289
    :pswitch_1a
    const-string p0, "MultiChargeSdk instance successfully created"

    .line 290
    .line 291
    return-object p0

    .line 292
    :pswitch_1b
    const-string p0, "Init multiChargeSdk"

    .line 293
    .line 294
    return-object p0

    .line 295
    :pswitch_1c
    invoke-static {}, Lvd/k;->values()[Lvd/k;

    .line 296
    .line 297
    .line 298
    move-result-object p0

    .line 299
    const-string v1, "EXPIRED_SUBSCRIPTION"

    .line 300
    .line 301
    const-string v3, "EXPIRED_SUBSCRIPTION_NO_COUPONS_USED"

    .line 302
    .line 303
    const-string v4, "NO_COUPONS_USED"

    .line 304
    .line 305
    filled-new-array {v4, v0, v1, v3}, [Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    filled-new-array {v2, v2, v2, v2}, [[Ljava/lang/annotation/Annotation;

    .line 310
    .line 311
    .line 312
    move-result-object v1

    .line 313
    const-string v2, "cariad.charging.multicharge.kitten.coupons.models.CouponsResponse.Status"

    .line 314
    .line 315
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 316
    .line 317
    .line 318
    move-result-object p0

    .line 319
    return-object p0

    .line 320
    nop

    .line 321
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
