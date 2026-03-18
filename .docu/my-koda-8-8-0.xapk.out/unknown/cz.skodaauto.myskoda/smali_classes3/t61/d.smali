.class public final synthetic Lt61/d;
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
    iput p1, p0, Lt61/d;->d:I

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
    .locals 6

    .line 1
    iget p0, p0, Lt61/d;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string p0, "technology.cariad.cat.capabilities.UserRole"

    .line 9
    .line 10
    invoke-static {}, Lu41/t;->values()[Lu41/t;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    new-instance p0, Luz0/d;

    .line 20
    .line 21
    sget-object v0, Lu41/p;->a:Lu41/p;

    .line 22
    .line 23
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_1
    sget-object p0, Lu41/t;->Companion:Lu41/s;

    .line 28
    .line 29
    invoke-virtual {p0}, Lu41/s;->serializer()Lqz0/a;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_2
    new-instance p0, Luz0/d;

    .line 35
    .line 36
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 37
    .line 38
    const/4 v1, 0x2

    .line 39
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_3
    new-instance p0, Luz0/d;

    .line 44
    .line 45
    sget-object v0, Lu41/p;->a:Lu41/p;

    .line 46
    .line 47
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_4
    new-instance p0, Luz0/e0;

    .line 52
    .line 53
    sget-object v0, Lu41/i;->a:Lu41/i;

    .line 54
    .line 55
    sget-object v1, Lu41/g;->a:Lu41/g;

    .line 56
    .line 57
    const/4 v2, 0x1

    .line 58
    invoke-direct {p0, v0, v1, v2}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 59
    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_5
    sget-object p0, Lu2/i;->a:Ll2/u2;

    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_6
    new-instance p0, Lu2/e;

    .line 66
    .line 67
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 68
    .line 69
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 70
    .line 71
    .line 72
    invoke-direct {p0, v0}, Lu2/e;-><init>(Ljava/util/Map;)V

    .line 73
    .line 74
    .line 75
    return-object p0

    .line 76
    :pswitch_7
    sget-object p0, Llj0/c;->a:Llj0/c;

    .line 77
    .line 78
    return-object p0

    .line 79
    :pswitch_8
    invoke-static {}, Lcz/myskoda/api/bff_feedbacks/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :pswitch_9
    invoke-static {}, Lcz/myskoda/api/bff_feedbacks/v2/infrastructure/ApiClient;->a()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :pswitch_a
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 90
    .line 91
    .line 92
    move-result-wide v0

    .line 93
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    :pswitch_b
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->a()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0

    .line 103
    :pswitch_c
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->b()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :pswitch_d
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->a()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    return-object p0

    .line 113
    :pswitch_e
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->c()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    return-object p0

    .line 118
    :pswitch_f
    new-instance p0, Luz0/d;

    .line 119
    .line 120
    sget-object v0, Ltc/a;->a:Ltc/a;

    .line 121
    .line 122
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 123
    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_10
    new-instance p0, Luz0/d;

    .line 127
    .line 128
    sget-object v0, Lac/y;->a:Lac/y;

    .line 129
    .line 130
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 131
    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_11
    invoke-static {}, Ltc/d;->values()[Ltc/d;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    const-string v1, "ACTIVE"

    .line 139
    .line 140
    const-string v2, "INACTIVE"

    .line 141
    .line 142
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    filled-new-array {v0, v0}, [[Ljava/lang/annotation/Annotation;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    const-string v2, "cariad.charging.multicharge.kitten.chargingcard.models.ChargingCard.Status"

    .line 151
    .line 152
    invoke-static {v2, p0, v1, v0}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 153
    .line 154
    .line 155
    move-result-object p0

    .line 156
    return-object p0

    .line 157
    :pswitch_12
    sget-object p0, Ltc/d;->Companion:Ltc/c;

    .line 158
    .line 159
    invoke-virtual {p0}, Ltc/c;->serializer()Lqz0/a;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_13
    new-instance p0, Luz0/d;

    .line 165
    .line 166
    sget-object v0, Ltb/m;->a:Ltb/m;

    .line 167
    .line 168
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 169
    .line 170
    .line 171
    return-object p0

    .line 172
    :pswitch_14
    invoke-static {}, Ltb/s;->values()[Ltb/s;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    const-string v1, "POSTPONED_BY_USER"

    .line 177
    .line 178
    const-string v2, "UNCERTAIN"

    .line 179
    .line 180
    const-string v3, "REQUIRED_WITH_GRACE_PERIOD"

    .line 181
    .line 182
    const-string v4, "REQUIRED_IMMEDIATELY"

    .line 183
    .line 184
    const-string v5, "NOT_REQUIRED"

    .line 185
    .line 186
    filled-new-array {v3, v4, v5, v1, v2}, [Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    filled-new-array {v0, v0, v0, v0, v0}, [[Ljava/lang/annotation/Annotation;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    const-string v2, "cariad.charging.multicharge.bff.api.models.HeadlessConsentHeader.Status"

    .line 195
    .line 196
    invoke-static {v2, p0, v1, v0}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    return-object p0

    .line 201
    :pswitch_15
    sget-object p0, Ltb/s;->Companion:Ltb/r;

    .line 202
    .line 203
    invoke-virtual {p0}, Ltb/r;->serializer()Lqz0/a;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    return-object p0

    .line 208
    :pswitch_16
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->f()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    return-object p0

    .line 213
    :pswitch_17
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->h()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    return-object p0

    .line 218
    :pswitch_18
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->q()Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    return-object p0

    .line 223
    :pswitch_19
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->E()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    return-object p0

    .line 228
    :pswitch_1a
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->k()Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object p0

    .line 232
    return-object p0

    .line 233
    :pswitch_1b
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->l()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    return-object p0

    .line 238
    :pswitch_1c
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->q()Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    return-object p0

    .line 243
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
