.class public final synthetic Lqf0/d;
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
    iput p1, p0, Lqf0/d;->d:I

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
    iget p0, p0, Lqf0/d;->d:I

    .line 2
    .line 3
    const-string v0, "AndroidKeyStore"

    .line 4
    .line 5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->f()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :pswitch_0
    const-string p0, "removeRegionForRangingBeacons(): App not active. -> Send \'BEACON_LOST\' broadcast."

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_1
    const-string p0, "addRegionForRangingBeacons(): App not active. -> Send \'BEACON_FOUND\' broadcast."

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_2
    const-string p0, "startScanning()"

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_3
    const-string p0, "stopScanning(): Scanning was not active, found values will be reset"

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_4
    const-string p0, "close()"

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_5
    new-instance p0, Lt4/j;

    .line 34
    .line 35
    invoke-direct {p0, v2, v3}, Lt4/j;-><init>(J)V

    .line 36
    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_6
    new-instance p0, Lt4/j;

    .line 40
    .line 41
    invoke-direct {p0, v2, v3}, Lt4/j;-><init>(J)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_7
    sget-object p0, Lt1/o;->a:Ll2/u2;

    .line 46
    .line 47
    return-object v4

    .line 48
    :pswitch_8
    const-string p0, "Shake is not enabled"

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_9
    invoke-static {}, Lcz/myskoda/api/bff_dealers/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_a
    invoke-static {}, Lcz/myskoda/api/bff_dealers/v2/infrastructure/ApiClient;->d()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_b
    :try_start_0
    new-instance p0, Lpm/b;

    .line 62
    .line 63
    invoke-direct {p0}, Lpm/b;-><init>()V

    .line 64
    .line 65
    .line 66
    filled-new-array {p0}, [Lpm/b;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    invoke-static {p0}, Lky0/l;->b(Ljava/util/Iterator;)Lky0/j;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-static {p0}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-static {p0}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :catchall_0
    move-exception p0

    .line 92
    new-instance v0, Ljava/util/ServiceConfigurationError;

    .line 93
    .line 94
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-direct {v0, v1, p0}, Ljava/util/ServiceConfigurationError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 99
    .line 100
    .line 101
    throw v0

    .line 102
    :pswitch_c
    :try_start_1
    new-instance p0, Llm/d;

    .line 103
    .line 104
    invoke-direct {p0}, Llm/d;-><init>()V

    .line 105
    .line 106
    .line 107
    filled-new-array {p0}, [Llm/d;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 119
    invoke-static {p0}, Lky0/l;->b(Ljava/util/Iterator;)Lky0/j;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-static {p0}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-static {p0}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0

    .line 132
    :catchall_1
    move-exception p0

    .line 133
    new-instance v0, Ljava/util/ServiceConfigurationError;

    .line 134
    .line 135
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    invoke-direct {v0, v1, p0}, Ljava/util/ServiceConfigurationError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    throw v0

    .line 143
    :pswitch_d
    invoke-static {}, Lsi/d;->values()[Lsi/d;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    const-string v0, "ACTIVE"

    .line 148
    .line 149
    const-string v1, "PENDING"

    .line 150
    .line 151
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    filled-new-array {v4, v4}, [[Ljava/lang/annotation/Annotation;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    const-string v2, "cariad.charging.multicharge.sdk.headless.chargingsession.ChargingSession.Status"

    .line 160
    .line 161
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    :pswitch_e
    sget-object p0, Lsi/d;->Companion:Lsi/c;

    .line 167
    .line 168
    invoke-virtual {p0}, Lsi/c;->serializer()Lqz0/a;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0

    .line 173
    :pswitch_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 174
    .line 175
    const-string v0, "CompositionLocal LocalSavedStateRegistryOwner not present"

    .line 176
    .line 177
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    throw p0

    .line 181
    :pswitch_10
    sget-object p0, Lr70/a;->a:Lr70/a;

    .line 182
    .line 183
    return-object p0

    .line 184
    :pswitch_11
    invoke-static {}, Lcz/myskoda/api/bff_data_plan/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    return-object p0

    .line 189
    :pswitch_12
    invoke-static {}, Lcz/myskoda/api/bff_data_plan/v2/infrastructure/ApiClient;->b()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    return-object p0

    .line 194
    :pswitch_13
    sget p0, Lri0/a;->a:F

    .line 195
    .line 196
    return-object v1

    .line 197
    :pswitch_14
    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-virtual {p0, v4}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 202
    .line 203
    .line 204
    return-object p0

    .line 205
    :pswitch_15
    invoke-static {v4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    return-object p0

    .line 210
    :pswitch_16
    sget-object p0, Lr61/c;->a:Ljava/util/Set;

    .line 211
    .line 212
    return-object v1

    .line 213
    :pswitch_17
    const-string p0, "AES/GCM/NoPadding"

    .line 214
    .line 215
    invoke-static {p0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    return-object p0

    .line 220
    :pswitch_18
    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    invoke-virtual {p0, v4}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 225
    .line 226
    .line 227
    return-object p0

    .line 228
    :pswitch_19
    invoke-static {}, Lcz/myskoda/api/bff_consents/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 229
    .line 230
    .line 231
    move-result-object p0

    .line 232
    return-object p0

    .line 233
    :pswitch_1a
    invoke-static {}, Lcz/myskoda/api/bff_consents/v2/infrastructure/ApiClient;->d()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    return-object p0

    .line 238
    :pswitch_1b
    new-instance p0, Lrf0/b;

    .line 239
    .line 240
    const-string v0, "false"

    .line 241
    .line 242
    invoke-direct {p0, v0}, Lrf0/b;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    return-object p0

    .line 246
    :pswitch_1c
    sget-object p0, Lrf0/a;->b:Lrf0/a;

    .line 247
    .line 248
    return-object p0

    .line 249
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
