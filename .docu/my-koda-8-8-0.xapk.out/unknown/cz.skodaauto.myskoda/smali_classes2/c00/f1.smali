.class public final synthetic Lc00/f1;
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
    iput p1, p0, Lc00/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Connection;)V
    .locals 0

    .line 2
    const/16 p1, 0x9

    iput p1, p0, Lc00/f1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget p0, p0, Lc00/f1;->d:I

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    const/4 v1, 0x1

    .line 5
    const/4 v2, 0x0

    .line 6
    packed-switch p0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    new-instance p0, Lc91/e;

    .line 10
    .line 11
    invoke-direct {p0, v2}, Lc91/e;-><init>(I)V

    .line 12
    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_0
    new-instance p0, Lc91/e;

    .line 16
    .line 17
    invoke-direct {p0, v2}, Lc91/e;-><init>(I)V

    .line 18
    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_1
    new-instance p0, Lc91/e;

    .line 22
    .line 23
    invoke-direct {p0, v2}, Lc91/e;-><init>(I)V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_2
    new-instance p0, Lc91/f;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_3
    const-string p0, "io.opentelemetry.api.logs.Severity"

    .line 34
    .line 35
    invoke-static {}, Lio/opentelemetry/api/logs/Severity;->values()[Lio/opentelemetry/api/logs/Severity;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_4
    new-instance p0, Lc91/e;

    .line 45
    .line 46
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 47
    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_5
    new-instance p0, Lc91/e;

    .line 51
    .line 52
    invoke-direct {p0, v2}, Lc91/e;-><init>(I)V

    .line 53
    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_6
    new-instance p0, Lc91/e;

    .line 57
    .line 58
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 59
    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_7
    new-instance p0, Lc91/e;

    .line 63
    .line 64
    invoke-direct {p0, v2}, Lc91/e;-><init>(I)V

    .line 65
    .line 66
    .line 67
    return-object p0

    .line 68
    :pswitch_8
    new-instance p0, Luz0/e0;

    .line 69
    .line 70
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 71
    .line 72
    new-instance v3, Luz0/d;

    .line 73
    .line 74
    sget-object v4, Luz0/u;->a:Luz0/u;

    .line 75
    .line 76
    invoke-direct {v3, v4, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 77
    .line 78
    .line 79
    invoke-direct {p0, v0, v3, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 80
    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_9
    new-instance p0, Luz0/e0;

    .line 84
    .line 85
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 86
    .line 87
    new-instance v3, Luz0/d;

    .line 88
    .line 89
    sget-object v4, Luz0/q0;->a:Luz0/q0;

    .line 90
    .line 91
    invoke-direct {v3, v4, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 92
    .line 93
    .line 94
    invoke-direct {p0, v0, v3, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 95
    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_a
    new-instance p0, Luz0/e0;

    .line 99
    .line 100
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 101
    .line 102
    new-instance v3, Luz0/d;

    .line 103
    .line 104
    sget-object v4, Luz0/g;->a:Luz0/g;

    .line 105
    .line 106
    invoke-direct {v3, v4, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 107
    .line 108
    .line 109
    invoke-direct {p0, v0, v3, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 110
    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_b
    new-instance p0, Luz0/e0;

    .line 114
    .line 115
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 116
    .line 117
    new-instance v3, Luz0/d;

    .line 118
    .line 119
    invoke-direct {v3, v0, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 120
    .line 121
    .line 122
    invoke-direct {p0, v0, v3, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 123
    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_c
    new-instance p0, Luz0/e0;

    .line 127
    .line 128
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 129
    .line 130
    sget-object v2, Luz0/u;->a:Luz0/u;

    .line 131
    .line 132
    invoke-direct {p0, v0, v2, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 133
    .line 134
    .line 135
    return-object p0

    .line 136
    :pswitch_d
    new-instance p0, Luz0/e0;

    .line 137
    .line 138
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 139
    .line 140
    sget-object v2, Luz0/q0;->a:Luz0/q0;

    .line 141
    .line 142
    invoke-direct {p0, v0, v2, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 143
    .line 144
    .line 145
    return-object p0

    .line 146
    :pswitch_e
    new-instance p0, Luz0/e0;

    .line 147
    .line 148
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 149
    .line 150
    sget-object v2, Luz0/g;->a:Luz0/g;

    .line 151
    .line 152
    invoke-direct {p0, v0, v2, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 153
    .line 154
    .line 155
    return-object p0

    .line 156
    :pswitch_f
    new-instance p0, Luz0/e0;

    .line 157
    .line 158
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 159
    .line 160
    invoke-direct {p0, v0, v0, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 161
    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_10
    new-instance p0, Lkj0/h;

    .line 165
    .line 166
    const-string v0, "SPIN - Enter SPIN - SPIN blocked"

    .line 167
    .line 168
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    return-object p0

    .line 172
    :pswitch_11
    new-instance p0, Lkj0/h;

    .line 173
    .line 174
    const-string v0, "SPIN - Activate biometrics - Error"

    .line 175
    .line 176
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    return-object p0

    .line 180
    :pswitch_12
    new-instance p0, Lkj0/h;

    .line 181
    .line 182
    const-string v0, "SPIN - Activate biometrics - Success"

    .line 183
    .line 184
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_13
    const-class p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError$Connection;

    .line 189
    .line 190
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 191
    .line 192
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    const-string v0, "connectionErrorInfixIdPair: creating errorText of VehicleStatusError.ParkingFailed.Connection of value = "

    .line 201
    .line 202
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    return-object p0

    .line 207
    :pswitch_14
    sget-object p0, Lc71/e;->a:Ll2/e0;

    .line 208
    .line 209
    sget-object p0, Lc71/b;->a:Lc71/b;

    .line 210
    .line 211
    return-object p0

    .line 212
    :pswitch_15
    const-string p0, "technology.cariad.cat.network.tracing.OpenTelemetryLogLevel"

    .line 213
    .line 214
    invoke-static {}, Lz51/c;->values()[Lz51/c;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    return-object p0

    .line 223
    :pswitch_16
    new-instance p0, Luz0/e0;

    .line 224
    .line 225
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 226
    .line 227
    invoke-direct {p0, v0, v0, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 228
    .line 229
    .line 230
    return-object p0

    .line 231
    :pswitch_17
    const-string p0, "Wallet app successfully started, waiting for result..."

    .line 232
    .line 233
    return-object p0

    .line 234
    :pswitch_18
    const-string p0, "Starting Wallet app..."

    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_19
    const-string p0, "Got pairing password."

    .line 238
    .line 239
    return-object p0

    .line 240
    :pswitch_1a
    const-string p0, "No pairing password provided to performPairing, fetching it..."

    .line 241
    .line 242
    return-object p0

    .line 243
    :pswitch_1b
    new-instance p0, Lv2/r;

    .line 244
    .line 245
    new-instance v0, Lb30/a;

    .line 246
    .line 247
    const/16 v1, 0x1a

    .line 248
    .line 249
    invoke-direct {v0, v1}, Lb30/a;-><init>(I)V

    .line 250
    .line 251
    .line 252
    invoke-direct {p0, v0}, Lv2/r;-><init>(Lay0/k;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {p0}, Lv2/r;->e()V

    .line 256
    .line 257
    .line 258
    return-object p0

    .line 259
    :pswitch_1c
    new-instance p0, Llj0/a;

    .line 260
    .line 261
    const-string v0, "air_conditioning_gauge_windows_heating_button_start"

    .line 262
    .line 263
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    return-object p0

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
