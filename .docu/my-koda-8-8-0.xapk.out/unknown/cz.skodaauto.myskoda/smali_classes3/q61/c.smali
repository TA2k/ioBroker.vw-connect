.class public final synthetic Lq61/c;
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
    iput p2, p0, Lq61/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq61/c;->e:Ljava/lang/String;

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
    .locals 2

    .line 1
    iget v0, p0, Lq61/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "message ["

    .line 7
    .line 8
    const-string v1, "] emitted as an event"

    .line 9
    .line 10
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    const-string v0, "ContactChannel for remote name "

    .line 18
    .line 19
    const-string v1, " not founded"

    .line 20
    .line 21
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

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
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 29
    .line 30
    const-string v0, "Set FCM token: "

    .line 31
    .line 32
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_2
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_3
    new-instance v0, Lx20/a;

    .line 41
    .line 42
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 43
    .line 44
    invoke-direct {v0, p0}, Lx20/a;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    return-object v0

    .line 48
    :pswitch_4
    new-instance v0, Llj0/a;

    .line 49
    .line 50
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 51
    .line 52
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    return-object v0

    .line 56
    :pswitch_5
    new-instance v0, Llj0/a;

    .line 57
    .line 58
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return-object v0

    .line 67
    :pswitch_6
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 68
    .line 69
    const-string v0, "migrate(): No pairings of PairingV0 format found for key = "

    .line 70
    .line 71
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :pswitch_7
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 77
    .line 78
    const-string v0, "onKeyExchangeFailed(): vin = "

    .line 79
    .line 80
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :pswitch_8
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 86
    .line 87
    const-string v0, "vehicleWith(): vin = "

    .line 88
    .line 89
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0

    .line 94
    :pswitch_9
    const-string v0, "removeQRCodePairing(): Pairing for \'"

    .line 95
    .line 96
    const-string v1, "\' not found"

    .line 97
    .line 98
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0

    .line 105
    :pswitch_a
    new-instance v0, Llj0/a;

    .line 106
    .line 107
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 108
    .line 109
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_b
    new-instance v0, Llj0/a;

    .line 117
    .line 118
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    return-object v0

    .line 127
    :pswitch_c
    new-instance v0, Llj0/a;

    .line 128
    .line 129
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 130
    .line 131
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    return-object v0

    .line 138
    :pswitch_d
    const-string v0, "(MDK) Vehicle "

    .line 139
    .line 140
    const-string v1, " paired."

    .line 141
    .line 142
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 143
    .line 144
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0

    .line 149
    :pswitch_e
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 150
    .line 151
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->S(Ljava/lang/String;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    return-object p0

    .line 156
    :pswitch_f
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 157
    .line 158
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->T(Ljava/lang/String;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0

    .line 163
    :pswitch_10
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 164
    .line 165
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->h0(Ljava/lang/String;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    return-object p0

    .line 170
    :pswitch_11
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 171
    .line 172
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->k(Ljava/lang/String;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0

    .line 177
    :pswitch_12
    new-instance v0, Llj0/a;

    .line 178
    .line 179
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 180
    .line 181
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    return-object v0

    .line 185
    :pswitch_13
    const-string v0, "stopRPAImmediately(): for vin = "

    .line 186
    .line 187
    const-string v1, " skipped! No RPA instance is currently running for this vin!"

    .line 188
    .line 189
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 190
    .line 191
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    return-object p0

    .line 196
    :pswitch_14
    const-string v0, "stopRPAImmediately(): for vin = "

    .line 197
    .line 198
    const-string v1, " skipped! No RPA instance is currently running for this vin!"

    .line 199
    .line 200
    iget-object p0, p0, Lq61/c;->e:Ljava/lang/String;

    .line 201
    .line 202
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    return-object p0

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
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
