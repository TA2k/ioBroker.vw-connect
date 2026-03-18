.class public final synthetic Ltechnology/cariad/cat/genx/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Ltechnology/cariad/cat/genx/u0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/u0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 9
    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleImpl;

    .line 13
    .line 14
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->F0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleImpl;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 26
    .line 27
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 30
    .line 31
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->j(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/InternalVehicle;)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Ljava/util/Set;

    .line 43
    .line 44
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 47
    .line 48
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->K0(Ljava/util/Set;Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 56
    .line 57
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 60
    .line 61
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->L0(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/protocol/Address;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :pswitch_3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Ltechnology/cariad/cat/genx/TransportState;

    .line 73
    .line 74
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 77
    .line 78
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->k(Ltechnology/cariad/cat/genx/TransportState;Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_4
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 86
    .line 87
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 90
    .line 91
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->l(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)Llx0/b0;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    :pswitch_5
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, [J

    .line 99
    .line 100
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 103
    .line 104
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->M([JLtechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :pswitch_6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 112
    .line 113
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p0, [B

    .line 116
    .line 117
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->l(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;[B)[B

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    return-object p0

    .line 122
    :pswitch_7
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;

    .line 125
    .line 126
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast p0, Ltechnology/cariad/cat/genx/TransportType;

    .line 129
    .line 130
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaImpl;->a(Ltechnology/cariad/cat/genx/VehicleAntennaImpl;Ltechnology/cariad/cat/genx/TransportType;)Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :pswitch_8
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v0, Ljava/lang/String;

    .line 138
    .line 139
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast p0, Ljava/lang/String;

    .line 142
    .line 143
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/Logging;->c(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_9
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v0, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;

    .line 151
    .line 152
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p0, Ltechnology/cariad/cat/genx/Client;

    .line 155
    .line 156
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;->g(Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;Ltechnology/cariad/cat/genx/Client;)I

    .line 157
    .line 158
    .line 159
    move-result p0

    .line 160
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    return-object p0

    .line 165
    :pswitch_a
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast v0, Ltechnology/cariad/cat/genx/Client;

    .line 168
    .line 169
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast p0, [B

    .line 172
    .line 173
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/ClientManagerCrossDelegate;->l(Ltechnology/cariad/cat/genx/Client;[B)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :pswitch_b
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast v0, Ltechnology/cariad/cat/genx/ClientCrossDelegate;

    .line 181
    .line 182
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast p0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 185
    .line 186
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/ClientCrossDelegate;->j(Ltechnology/cariad/cat/genx/ClientCrossDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)I

    .line 187
    .line 188
    .line 189
    move-result p0

    .line 190
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    return-object p0

    .line 195
    :pswitch_c
    iget-object v0, p0, Ltechnology/cariad/cat/genx/u0;->e:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 198
    .line 199
    iget-object p0, p0, Ltechnology/cariad/cat/genx/u0;->f:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast p0, Lvy0/b0;

    .line 202
    .line 203
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->b(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lvy0/b0;)Llx0/b0;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    return-object p0

    .line 208
    nop

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
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
