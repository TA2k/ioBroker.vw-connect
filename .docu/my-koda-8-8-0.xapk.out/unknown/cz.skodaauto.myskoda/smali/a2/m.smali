.class public final synthetic La2/m;
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
    iput p1, p0, La2/m;->d:I

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
    iget p0, p0, La2/m;->d:I

    .line 2
    .line 3
    const-string v0, "UNKNOWN"

    .line 4
    .line 5
    const-string v1, "UNAVAILABLE"

    .line 6
    .line 7
    const-string v2, "AVAILABLE"

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    invoke-static {}, Lcz/myskoda/api/bff_shop/v2/infrastructure/ApiClient;->d()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_0
    new-instance p0, Lal/u;

    .line 20
    .line 21
    const/4 v0, 0x1

    .line 22
    invoke-direct {p0, v0}, Lal/u;-><init>(Z)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_1
    invoke-static {}, Lah/w;->values()[Lah/w;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const-string v0, "IN_PROGRESS"

    .line 35
    .line 36
    const-string v1, "FAILED"

    .line 37
    .line 38
    const-string v2, "INSTALLED"

    .line 39
    .line 40
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    filled-new-array {v4, v4, v4}, [[Ljava/lang/annotation/Annotation;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.firmware.LatestUpdateProcess.Status"

    .line 49
    .line 50
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_2
    sget-object p0, Lah/w;->Companion:Lah/v;

    .line 56
    .line 57
    invoke-virtual {p0}, Lah/v;->serializer()Lqz0/a;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-static {}, Lah/s;->values()[Lah/s;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    const-string v0, "POSTPONED"

    .line 67
    .line 68
    const-string v1, "DECLINED"

    .line 69
    .line 70
    const-string v2, "ACCEPTED"

    .line 71
    .line 72
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    filled-new-array {v4, v4, v4}, [[Ljava/lang/annotation/Annotation;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.firmware.FirmwareUpdateDecision"

    .line 81
    .line 82
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
    :pswitch_4
    sget-object p0, Lah/s;->Companion:Lah/r;

    .line 88
    .line 89
    invoke-virtual {p0}, Lah/r;->serializer()Lqz0/a;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0

    .line 94
    :pswitch_5
    invoke-static {}, Lah/g;->values()[Lah/g;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    const-string v0, "UPDATE_AVAILABLE"

    .line 99
    .line 100
    const-string v1, "UPDATING"

    .line 101
    .line 102
    const-string v2, "NO_UPDATE"

    .line 103
    .line 104
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    filled-new-array {v4, v4, v4}, [[Ljava/lang/annotation/Annotation;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.firmware.ChargingStationFirmwareResponse.Status"

    .line 113
    .line 114
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_6
    sget-object p0, Lah/g;->Companion:Lah/f;

    .line 120
    .line 121
    invoke-virtual {p0}, Lah/f;->serializer()Lqz0/a;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    return-object p0

    .line 126
    :pswitch_7
    new-instance p0, Luz0/d;

    .line 127
    .line 128
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 129
    .line 130
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 131
    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_8
    new-instance p0, Luz0/d;

    .line 135
    .line 136
    sget-object v0, Lae/i0;->a:Lae/i0;

    .line 137
    .line 138
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 139
    .line 140
    .line 141
    return-object p0

    .line 142
    :pswitch_9
    invoke-static {}, Lae/q;->values()[Lae/q;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    filled-new-array {v2, v1, v0}, [Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    filled-new-array {v4, v4, v4}, [[Ljava/lang/annotation/Annotation;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    const-string v2, "cariad.charging.multicharge.kitten.cpoi.models.ChargingPointAvailability.AvailabilityStatus"

    .line 155
    .line 156
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    return-object p0

    .line 161
    :pswitch_a
    sget-object p0, Lae/q;->Companion:Lae/p;

    .line 162
    .line 163
    invoke-virtual {p0}, Lae/p;->serializer()Lqz0/a;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0

    .line 168
    :pswitch_b
    invoke-static {}, Lae/l;->values()[Lae/l;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    filled-new-array {v2, v1, v0}, [Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    filled-new-array {v4, v4, v4}, [[Ljava/lang/annotation/Annotation;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    const-string v2, "cariad.charging.multicharge.kitten.cpoi.models.ChargingPoint.AvailabilityStatus"

    .line 181
    .line 182
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    return-object p0

    .line 187
    :pswitch_c
    sget-object p0, Lae/l;->Companion:Lae/k;

    .line 188
    .line 189
    invoke-virtual {p0}, Lae/k;->serializer()Lqz0/a;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    return-object p0

    .line 194
    :pswitch_d
    new-instance p0, Luz0/d;

    .line 195
    .line 196
    sget-object v0, Lae/j;->a:Lae/j;

    .line 197
    .line 198
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 199
    .line 200
    .line 201
    return-object p0

    .line 202
    :pswitch_e
    new-instance p0, Luz0/d;

    .line 203
    .line 204
    sget-object v0, Lae/a;->a:Lae/a;

    .line 205
    .line 206
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 207
    .line 208
    .line 209
    return-object p0

    .line 210
    :pswitch_f
    new-instance p0, Luz0/d;

    .line 211
    .line 212
    sget-object v0, Lae/g;->a:Lae/g;

    .line 213
    .line 214
    invoke-direct {p0, v0, v3}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 215
    .line 216
    .line 217
    return-object p0

    .line 218
    :pswitch_10
    const-string p0, "Manual reconnection to MQTT skipped because no subscribers exist."

    .line 219
    .line 220
    return-object p0

    .line 221
    :pswitch_11
    const-string p0, "Manually reconnecting to MQTT broker..."

    .line 222
    .line 223
    return-object p0

    .line 224
    :pswitch_12
    const-string p0, "Unsubscribe action queued."

    .line 225
    .line 226
    return-object p0

    .line 227
    :pswitch_13
    const-string p0, "Disconnected"

    .line 228
    .line 229
    return-object p0

    .line 230
    :pswitch_14
    const-string p0, "Disconnecting from MQTT broker..."

    .line 231
    .line 232
    return-object p0

    .line 233
    :pswitch_15
    const-string p0, "Error occurred in MQTT client"

    .line 234
    .line 235
    return-object p0

    .line 236
    :pswitch_16
    const-string p0, "Some MQTT message was received on null topic. Skipped."

    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_17
    sget-object p0, Lac0/w;->u:Lcm0/b;

    .line 240
    .line 241
    const-string p0, "Refreshing token"

    .line 242
    .line 243
    return-object p0

    .line 244
    :pswitch_18
    sget-object p0, Lac0/w;->u:Lcm0/b;

    .line 245
    .line 246
    const-string p0, "Connecting to MQTT broker..."

    .line 247
    .line 248
    return-object p0

    .line 249
    :pswitch_19
    sget-object p0, Lac0/w;->u:Lcm0/b;

    .line 250
    .line 251
    const-string p0, "Disconnecting job is cancelled or completed."

    .line 252
    .line 253
    return-object p0

    .line 254
    :pswitch_1a
    sget-object p0, Lac0/w;->u:Lcm0/b;

    .line 255
    .line 256
    const-string p0, "Disconnecting job planned."

    .line 257
    .line 258
    return-object p0

    .line 259
    :pswitch_1b
    sget-object p0, Lac0/w;->u:Lcm0/b;

    .line 260
    .line 261
    const-string p0, "Disconnecting job is already planned."

    .line 262
    .line 263
    return-object p0

    .line 264
    :pswitch_1c
    sget-object p0, La2/n;->a:Ll2/e0;

    .line 265
    .line 266
    return-object v4

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
