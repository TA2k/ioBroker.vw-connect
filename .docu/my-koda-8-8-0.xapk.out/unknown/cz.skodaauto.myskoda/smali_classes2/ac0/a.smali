.class public final synthetic Lac0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lac0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lac0/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lac0/a;->d:I

    .line 2
    .line 3
    const-string v1, "Subscribing to \'"

    .line 4
    .line 5
    const-string v2, "Topic `"

    .line 6
    .line 7
    const-string v3, "\'"

    .line 8
    .line 9
    const-string v4, "Unsubscribing from the topic \'"

    .line 10
    .line 11
    const-string v5, "\' not found."

    .line 12
    .line 13
    iget-object p0, p0, Lac0/a;->e:Ljava/lang/String;

    .line 14
    .line 15
    packed-switch v0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_0
    const-string v0, "decryptionMasterKey(): Failed to nuke already destroyed key alias "

    .line 20
    .line 21
    const-string v1, "."

    .line 22
    .line 23
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_1
    new-instance v0, Llj0/a;

    .line 29
    .line 30
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_2
    new-instance v0, Lkj0/h;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-object v0

    .line 40
    :pswitch_3
    const-string v0, "Handling of deeplink: "

    .line 41
    .line 42
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_4
    new-instance v0, Llj0/a;

    .line 48
    .line 49
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    return-object v0

    .line 53
    :pswitch_5
    const-string v0, "Playing URL: "

    .line 54
    .line 55
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_6
    const-string v0, "removeRPAStarterIfNotPairedAnymore(): remove and close "

    .line 61
    .line 62
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_7
    const-string v0, "rpaStarterFor(): OuterAntenna for vehicle with VIN = \'"

    .line 68
    .line 69
    invoke-static {v0, p0, v5}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_8
    const-string v0, "rpaStarterFor(): Vehicle with VIN = \'"

    .line 75
    .line 76
    invoke-static {v0, p0, v5}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :pswitch_9
    const-string v0, "showPairingSucceededScreen(): vin = "

    .line 82
    .line 83
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_a
    const-string v0, "isAllowedToPairWith(): vin = "

    .line 89
    .line 90
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :pswitch_b
    const-string v0, "Getting MQTT with clientId: "

    .line 96
    .line 97
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :pswitch_c
    new-instance v0, Lz9/r;

    .line 103
    .line 104
    invoke-direct {v0, p0}, Lz9/r;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    return-object v0

    .line 108
    :pswitch_d
    new-instance v0, Lkj0/h;

    .line 109
    .line 110
    invoke-direct {v0, p0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    return-object v0

    .line 114
    :pswitch_e
    const-string v0, "openLink("

    .line 115
    .line 116
    const-string v1, "): no OpenLinkProvider provided!"

    .line 117
    .line 118
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    return-object p0

    .line 123
    :pswitch_f
    new-instance v0, Llj0/a;

    .line 124
    .line 125
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    return-object v0

    .line 129
    :pswitch_10
    sget v0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->j:I

    .line 130
    .line 131
    const-string v0, "onNewToken: "

    .line 132
    .line 133
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0

    .line 138
    :pswitch_11
    invoke-static {v4, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    return-object p0

    .line 143
    :pswitch_12
    const-string v0, "Subscription action with id "

    .line 144
    .line 145
    const-string v1, " removed from queue."

    .line 146
    .line 147
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :pswitch_13
    const-string v0, "` cleared."

    .line 153
    .line 154
    invoke-static {v2, p0, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0

    .line 159
    :pswitch_14
    const-string v0, "` was not cleared because contains wild card"

    .line 160
    .line 161
    invoke-static {v2, p0, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    :pswitch_15
    const-string v0, "Clearing the topic `"

    .line 167
    .line 168
    const-string v1, "`"

    .line 169
    .line 170
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    return-object p0

    .line 175
    :pswitch_16
    const-string v0, "Unable to process MQTT message. No subscribers of \'"

    .line 176
    .line 177
    const-string v1, "\' found."

    .line 178
    .line 179
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    return-object p0

    .line 184
    :pswitch_17
    const-string v0, "\' topic..."

    .line 185
    .line 186
    invoke-static {v1, p0, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    return-object p0

    .line 191
    :pswitch_18
    const-string v0, "Unsubscribe from \'"

    .line 192
    .line 193
    const-string v1, "\' topic planned"

    .line 194
    .line 195
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    return-object p0

    .line 200
    :pswitch_19
    const-string v0, "Unsubscribe from the topic "

    .line 201
    .line 202
    const-string v1, " job is already planned."

    .line 203
    .line 204
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    return-object p0

    .line 209
    :pswitch_1a
    const-string v0, "Unsubscribe from the topic \'"

    .line 210
    .line 211
    const-string v1, "\' job is cancelled or completed."

    .line 212
    .line 213
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    return-object p0

    .line 218
    :pswitch_1b
    invoke-static {v4, p0, v3}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    return-object p0

    .line 223
    :pswitch_1c
    const-string v0, "\' is completed."

    .line 224
    .line 225
    invoke-static {v1, p0, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    return-object p0

    .line 230
    nop

    .line 231
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
