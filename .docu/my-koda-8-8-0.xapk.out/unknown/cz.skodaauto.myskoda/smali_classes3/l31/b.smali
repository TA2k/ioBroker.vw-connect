.class public final synthetic Ll31/b;
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
    iput p1, p0, Ll31/b;->d:I

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
    iget p0, p0, Ll31/b;->d:I

    .line 2
    .line 3
    sget-object v0, Lmg/c;->n:Lmg/c;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x0

    .line 7
    packed-switch p0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance p0, Lqz0/f;

    .line 11
    .line 12
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 13
    .line 14
    const-class v1, Lgz0/d;

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const-class v3, Lgz0/f;

    .line 21
    .line 22
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    const-class v4, Lgz0/h;

    .line 27
    .line 28
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const/4 v4, 0x2

    .line 33
    new-array v5, v4, [Lhy0/d;

    .line 34
    .line 35
    aput-object v3, v5, v2

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    aput-object v0, v5, v3

    .line 39
    .line 40
    new-array v0, v4, [Lqz0/a;

    .line 41
    .line 42
    sget-object v4, Lmz0/d;->a:Lmz0/d;

    .line 43
    .line 44
    aput-object v4, v0, v2

    .line 45
    .line 46
    sget-object v2, Lmz0/j;->a:Lmz0/j;

    .line 47
    .line 48
    aput-object v2, v0, v3

    .line 49
    .line 50
    const-string v2, "kotlinx.datetime.DateTimeUnit.DateBased"

    .line 51
    .line 52
    invoke-direct {p0, v2, v1, v5, v0}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;)V

    .line 53
    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_0
    sget-object p0, Lly/a;->c:Lly/a;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_1
    sget-object p0, Lly/a;->b:Lly/a;

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_2
    invoke-static {}, Lcz/myskoda/api/bff_ai_assistant/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_3
    invoke-static {}, Lcz/myskoda/api/bff_ai_assistant/v2/infrastructure/ApiClient;->c()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_4
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 73
    .line 74
    .line 75
    move-result-wide v0

    .line 76
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_5
    const-string p0, ""

    .line 82
    .line 83
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_6
    new-instance p0, Lmg0/f;

    .line 89
    .line 90
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 91
    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_7
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :pswitch_8
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    :pswitch_9
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :pswitch_a
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    :pswitch_b
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_c
    const-string p0, "No success message provided"

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_d
    invoke-static {}, Lcz/myskoda/api/bff/v1/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0

    .line 127
    :pswitch_e
    invoke-static {}, Lcz/myskoda/api/bff/v1/infrastructure/ApiClient;->b()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0

    .line 132
    :pswitch_f
    new-instance p0, Landroid/os/Handler;

    .line 133
    .line 134
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    invoke-direct {p0, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 139
    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_10
    invoke-static {}, Llj/d;->values()[Llj/d;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    const-string v4, "PENDING_DISABLE"

    .line 147
    .line 148
    const-string v5, "PENDING_ENABLE"

    .line 149
    .line 150
    const-string v0, "DISABLED"

    .line 151
    .line 152
    const-string v1, "ENABLED"

    .line 153
    .line 154
    const-string v2, "ERROR"

    .line 155
    .line 156
    const-string v3, "ERROR_INVALID_PCID"

    .line 157
    .line 158
    filled-new-array/range {v0 .. v5}, [Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    const/4 v5, 0x0

    .line 163
    const/4 v6, 0x0

    .line 164
    const/4 v1, 0x0

    .line 165
    const/4 v2, 0x0

    .line 166
    const/4 v3, 0x0

    .line 167
    const/4 v4, 0x0

    .line 168
    filled-new-array/range {v1 .. v6}, [[Ljava/lang/annotation/Annotation;

    .line 169
    .line 170
    .line 171
    move-result-object v1

    .line 172
    const-string v2, "cariad.charging.multicharge.sdk.headless.subscription.PlugAndCharge.State"

    .line 173
    .line 174
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    return-object p0

    .line 179
    :pswitch_11
    sget-object p0, Llj/d;->Companion:Llj/c;

    .line 180
    .line 181
    invoke-virtual {p0}, Llj/c;->serializer()Lqz0/a;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    return-object p0

    .line 186
    :pswitch_12
    sget-object p0, Lpe/b;->d:Lpe/b;

    .line 187
    .line 188
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    return-object p0

    .line 193
    :pswitch_13
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    return-object p0

    .line 198
    :pswitch_14
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 199
    .line 200
    return-object p0

    .line 201
    :pswitch_15
    new-instance p0, Luz0/y;

    .line 202
    .line 203
    sget-object v0, Ll31/y;->INSTANCE:Ll31/y;

    .line 204
    .line 205
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 206
    .line 207
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.SBOSummaryRoute"

    .line 208
    .line 209
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 210
    .line 211
    .line 212
    return-object p0

    .line 213
    :pswitch_16
    new-instance p0, Luz0/y;

    .line 214
    .line 215
    sget-object v0, Ll31/x;->INSTANCE:Ll31/x;

    .line 216
    .line 217
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 218
    .line 219
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.SBONewRequestRoute"

    .line 220
    .line 221
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 222
    .line 223
    .line 224
    return-object p0

    .line 225
    :pswitch_17
    new-instance p0, Luz0/y;

    .line 226
    .line 227
    sget-object v0, Ll31/w;->INSTANCE:Ll31/w;

    .line 228
    .line 229
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 230
    .line 231
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.SBOAppointmentScheduleRoute"

    .line 232
    .line 233
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 234
    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_18
    new-instance p0, Luz0/y;

    .line 238
    .line 239
    sget-object v0, Ll31/v;->INSTANCE:Ll31/v;

    .line 240
    .line 241
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 242
    .line 243
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.SBO21SummaryRoute"

    .line 244
    .line 245
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 246
    .line 247
    .line 248
    return-object p0

    .line 249
    :pswitch_19
    new-instance p0, Luz0/y;

    .line 250
    .line 251
    sget-object v0, Ll31/u;->INSTANCE:Ll31/u;

    .line 252
    .line 253
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 254
    .line 255
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.SBO21ReplacementMobilityRoute"

    .line 256
    .line 257
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 258
    .line 259
    .line 260
    return-object p0

    .line 261
    :pswitch_1a
    new-instance p0, Luz0/y;

    .line 262
    .line 263
    sget-object v0, Ll31/n;->INSTANCE:Ll31/n;

    .line 264
    .line 265
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 266
    .line 267
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.MSLSummaryRoute"

    .line 268
    .line 269
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 270
    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_1b
    new-instance p0, Luz0/y;

    .line 274
    .line 275
    sget-object v0, Ll31/g;->INSTANCE:Ll31/g;

    .line 276
    .line 277
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 278
    .line 279
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.MSL16SummaryRoute"

    .line 280
    .line 281
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 282
    .line 283
    .line 284
    return-object p0

    .line 285
    :pswitch_1c
    new-instance p0, Luz0/y;

    .line 286
    .line 287
    sget-object v0, Ll31/c;->INSTANCE:Ll31/c;

    .line 288
    .line 289
    new-array v1, v2, [Ljava/lang/annotation/Annotation;

    .line 290
    .line 291
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.DropOffTypeRoute"

    .line 292
    .line 293
    invoke-direct {p0, v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;Ljava/lang/Object;[Ljava/lang/annotation/Annotation;)V

    .line 294
    .line 295
    .line 296
    return-object p0

    .line 297
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
