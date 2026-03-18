.class public final synthetic Ljv0/c;
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
    iput p1, p0, Ljv0/c;->d:I

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
    .locals 7

    .line 1
    iget p0, p0, Ljv0/c;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Luz0/y;

    .line 7
    .line 8
    sget-object v0, Ll31/a;->INSTANCE:Ll31/a;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    new-array v1, v1, [Ljava/lang/annotation/Annotation;

    .line 12
    .line 13
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.ACFRoute"

    .line 14
    .line 15
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 16
    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_0
    const-string p0, "No screen is associated with this component"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    const-string p0, "Unexpected call to default provider"

    .line 23
    .line 24
    invoke-static {p0}, Ll2/v;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 25
    .line 26
    .line 27
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :pswitch_2
    const-string p0, "user is not logged in"

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_3
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_4
    const-string p0, "Non Vehicle Activation Service intent come while Vehicle Activation Service component is running"

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_5
    new-instance p0, Ld01/h0;

    .line 46
    .line 47
    invoke-direct {p0}, Ld01/h0;-><init>()V

    .line 48
    .line 49
    .line 50
    new-instance v0, Llm/b;

    .line 51
    .line 52
    invoke-direct {v0, p0}, Llm/b;-><init>(Ld01/i;)V

    .line 53
    .line 54
    .line 55
    return-object v0

    .line 56
    :pswitch_6
    new-instance v1, Lqz0/f;

    .line 57
    .line 58
    const-class p0, Lki/i;

    .line 59
    .line 60
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    const/4 p0, 0x0

    .line 67
    new-array v4, p0, [Lhy0/d;

    .line 68
    .line 69
    new-array v5, p0, [Lqz0/a;

    .line 70
    .line 71
    new-array v6, p0, [Ljava/lang/annotation/Annotation;

    .line 72
    .line 73
    const-string v2, "cariad.charging.multicharge.sdk.ChargingStatisticsParameters.Include"

    .line 74
    .line 75
    invoke-direct/range {v1 .. v6}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 76
    .line 77
    .line 78
    return-object v1

    .line 79
    :pswitch_7
    new-instance p0, Luz0/d;

    .line 80
    .line 81
    sget-object v0, Lki/i;->Companion:Lki/g;

    .line 82
    .line 83
    invoke-virtual {v0}, Lki/g;->serializer()Lqz0/a;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    const/4 v1, 0x0

    .line 88
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 89
    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_8
    new-instance p0, Luz0/d;

    .line 93
    .line 94
    sget-object v0, Lu41/v;->a:Lu41/v;

    .line 95
    .line 96
    const/4 v1, 0x0

    .line 97
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 98
    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_9
    new-instance p0, Luz0/d;

    .line 102
    .line 103
    sget-object v0, Lkg/g;->a:Lkg/g;

    .line 104
    .line 105
    const/4 v1, 0x0

    .line 106
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 107
    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_a
    new-instance p0, Luz0/d;

    .line 111
    .line 112
    sget-object v0, Lkg/d;->a:Lkg/d;

    .line 113
    .line 114
    const/4 v1, 0x0

    .line 115
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 116
    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_b
    new-instance p0, Luz0/d;

    .line 120
    .line 121
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 122
    .line 123
    const/4 v1, 0x0

    .line 124
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 125
    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_c
    invoke-static {}, Lkg/j0;->values()[Lkg/j0;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    const-string v0, "UPGRADE"

    .line 133
    .line 134
    const-string v1, "FOLLOW_UP"

    .line 135
    .line 136
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    const/4 v1, 0x0

    .line 141
    filled-new-array {v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    const-string v2, "cariad.charging.multicharge.kitten.subscription.models.SubscriptionUpgradeOrFollowUpCompleteRequest.Action"

    .line 146
    .line 147
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :pswitch_d
    sget-object p0, Lkg/j0;->Companion:Lkg/i0;

    .line 153
    .line 154
    invoke-virtual {p0}, Lkg/i0;->serializer()Lqz0/a;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0

    .line 159
    :pswitch_e
    new-instance p0, Luz0/d;

    .line 160
    .line 161
    sget-object v0, Lkg/v;->a:Lkg/v;

    .line 162
    .line 163
    const/4 v1, 0x0

    .line 164
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 165
    .line 166
    .line 167
    return-object p0

    .line 168
    :pswitch_f
    new-instance p0, Luz0/d;

    .line 169
    .line 170
    sget-object v0, Ldc/u;->a:Ldc/u;

    .line 171
    .line 172
    const/4 v1, 0x0

    .line 173
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 174
    .line 175
    .line 176
    return-object p0

    .line 177
    :pswitch_10
    new-instance p0, Luz0/d;

    .line 178
    .line 179
    sget-object v0, Lkg/n0;->a:Lkg/n0;

    .line 180
    .line 181
    const/4 v1, 0x0

    .line 182
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 183
    .line 184
    .line 185
    return-object p0

    .line 186
    :pswitch_11
    new-instance p0, Luz0/d;

    .line 187
    .line 188
    sget-object v0, Lkg/n0;->a:Lkg/n0;

    .line 189
    .line 190
    const/4 v1, 0x0

    .line 191
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 192
    .line 193
    .line 194
    return-object p0

    .line 195
    :pswitch_12
    new-instance p0, Luz0/d;

    .line 196
    .line 197
    sget-object v0, Ldc/u;->a:Ldc/u;

    .line 198
    .line 199
    const/4 v1, 0x0

    .line 200
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 201
    .line 202
    .line 203
    return-object p0

    .line 204
    :pswitch_13
    new-instance p0, Luz0/d;

    .line 205
    .line 206
    sget-object v0, Lac/y;->a:Lac/y;

    .line 207
    .line 208
    const/4 v1, 0x0

    .line 209
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 210
    .line 211
    .line 212
    return-object p0

    .line 213
    :pswitch_14
    new-instance p0, Luz0/d;

    .line 214
    .line 215
    sget-object v0, Lkg/v;->a:Lkg/v;

    .line 216
    .line 217
    const/4 v1, 0x0

    .line 218
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 219
    .line 220
    .line 221
    return-object p0

    .line 222
    :pswitch_15
    new-instance p0, Luz0/d;

    .line 223
    .line 224
    sget-object v0, Lkg/d;->a:Lkg/d;

    .line 225
    .line 226
    const/4 v1, 0x0

    .line 227
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 228
    .line 229
    .line 230
    return-object p0

    .line 231
    :pswitch_16
    const-string p0, "App started after crash"

    .line 232
    .line 233
    return-object p0

    .line 234
    :pswitch_17
    const-string p0, "Opening initial"

    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_18
    const-string p0, "User is signed in."

    .line 238
    .line 239
    return-object p0

    .line 240
    :pswitch_19
    const-string p0, "unregisterBluetoothStateBroadcastReceiver()"

    .line 241
    .line 242
    return-object p0

    .line 243
    :pswitch_1a
    new-instance p0, Lk1/b0;

    .line 244
    .line 245
    const/4 v0, 0x0

    .line 246
    invoke-direct {p0, v0}, Lk1/b0;-><init>(I)V

    .line 247
    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_1b
    new-instance p0, Llj0/a;

    .line 251
    .line 252
    const-string v0, "ai_trip_map_entry_point"

    .line 253
    .line 254
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    return-object p0

    .line 258
    :pswitch_1c
    new-instance p0, Llj0/a;

    .line 259
    .line 260
    const-string v0, "clear_search"

    .line 261
    .line 262
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    return-object p0

    .line 266
    nop

    .line 267
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
