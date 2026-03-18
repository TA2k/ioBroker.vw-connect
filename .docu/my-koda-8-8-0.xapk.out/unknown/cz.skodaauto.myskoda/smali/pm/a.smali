.class public abstract Lpm/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ls71/j;Ls71/g;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;
    .locals 4

    .line 1
    const-string v0, "parkingManeuverType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->TPA:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 7
    .line 8
    if-ne p2, v0, :cond_0

    .line 9
    .line 10
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->TRAINED_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance v0, Llx0/l;

    .line 14
    .line 15
    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    new-instance p0, Llx0/l;

    .line 19
    .line 20
    sget-object p1, Ls71/j;->e:Ls71/j;

    .line 21
    .line 22
    sget-object v1, Ls71/g;->e:Ls71/g;

    .line 23
    .line 24
    invoke-direct {p0, p1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 34
    .line 35
    if-ne p2, p0, :cond_1

    .line 36
    .line 37
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_2
    new-instance p0, Llx0/l;

    .line 44
    .line 45
    sget-object v2, Ls71/j;->g:Ls71/j;

    .line 46
    .line 47
    invoke-direct {p0, v2, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-eqz p0, :cond_3

    .line 55
    .line 56
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->STRAIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_3
    new-instance p0, Llx0/l;

    .line 60
    .line 61
    sget-object v3, Ls71/j;->f:Ls71/j;

    .line 62
    .line 63
    invoke-direct {p0, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-eqz p0, :cond_5

    .line 71
    .line 72
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;->PARALLEL:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 73
    .line 74
    if-ne p2, p0, :cond_4

    .line 75
    .line 76
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 77
    .line 78
    return-object p0

    .line 79
    :cond_4
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_FORWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 80
    .line 81
    return-object p0

    .line 82
    :cond_5
    new-instance p0, Llx0/l;

    .line 83
    .line 84
    sget-object p2, Ls71/g;->f:Ls71/g;

    .line 85
    .line 86
    invoke-direct {p0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-eqz p0, :cond_6

    .line 94
    .line 95
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_6
    new-instance p0, Llx0/l;

    .line 99
    .line 100
    invoke-direct {p0, v2, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    if-eqz p0, :cond_7

    .line 108
    .line 109
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->STRAIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 110
    .line 111
    return-object p0

    .line 112
    :cond_7
    new-instance p0, Llx0/l;

    .line 113
    .line 114
    invoke-direct {p0, v3, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    if-eqz p0, :cond_8

    .line 122
    .line 123
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_BACKWARD_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 124
    .line 125
    return-object p0

    .line 126
    :cond_8
    new-instance p0, Llx0/l;

    .line 127
    .line 128
    sget-object p2, Ls71/g;->d:Ls71/g;

    .line 129
    .line 130
    invoke-direct {p0, p1, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    if-eqz p0, :cond_9

    .line 138
    .line 139
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->LEFT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 140
    .line 141
    return-object p0

    .line 142
    :cond_9
    new-instance p0, Llx0/l;

    .line 143
    .line 144
    invoke-direct {p0, v3, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0, p0}, Llx0/l;->equals(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result p0

    .line 151
    if-eqz p0, :cond_a

    .line 152
    .line 153
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->RIGHT_PARALLEL_PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 154
    .line 155
    return-object p0

    .line 156
    :cond_a
    sget-object p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 157
    .line 158
    return-object p0
.end method

.method public static final b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ls71/k;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v1, Ls71/k;->d:Lwe0/b;

    .line 7
    .line 8
    invoke-static {p0}, Lps/t1;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-static {v2}, Lpm/a;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/j;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-static {p0}, Lps/t1;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverType()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-static {v3}, Lpm/a;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ls71/i;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-static {p0}, Lps/t1;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/C2PNormalPrioManeuverInfoMessagePPE;->getParkingManeuverDirectionSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    sget-object v0, Ly81/a;->d:[I

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    aget p0, v0, p0

    .line 50
    .line 51
    packed-switch p0, :pswitch_data_0

    .line 52
    .line 53
    .line 54
    new-instance p0, La8/r0;

    .line 55
    .line 56
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :pswitch_0
    sget-object p0, Ls71/g;->f:Ls71/g;

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_1
    sget-object p0, Ls71/g;->e:Ls71/g;

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :pswitch_2
    sget-object p0, Ls71/g;->d:Ls71/g;

    .line 67
    .line 68
    :goto_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    invoke-static {p0, v2, v3}, Lwe0/b;->s(Ls71/g;Ls71/j;Ls71/i;)Ls71/k;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public static c(Llx0/j;Lay0/a;)Llx0/i;
    .locals 2

    .line 1
    sget-object v0, Llx0/y;->a:Llx0/y;

    .line 2
    .line 3
    const-string v1, "initializer"

    .line 4
    .line 5
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-eqz p0, :cond_2

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-eq p0, v1, :cond_1

    .line 16
    .line 17
    const/4 v1, 0x2

    .line 18
    if-ne p0, v1, :cond_0

    .line 19
    .line 20
    new-instance p0, Llx0/c0;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Llx0/c0;->d:Lay0/a;

    .line 26
    .line 27
    iput-object v0, p0, Llx0/c0;->e:Ljava/lang/Object;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_0
    new-instance p0, La8/r0;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_1
    new-instance p0, Llx0/p;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Llx0/p;->d:Lay0/a;

    .line 42
    .line 43
    iput-object v0, p0, Llx0/p;->e:Ljava/lang/Object;

    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_2
    new-instance p0, Llx0/q;

    .line 47
    .line 48
    invoke-direct {p0, p1}, Llx0/q;-><init>(Lay0/a;)V

    .line 49
    .line 50
    .line 51
    return-object p0
.end method

.method public static d(Lay0/a;)Llx0/q;
    .locals 1

    .line 1
    const-string v0, "initializer"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Llx0/q;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Llx0/q;-><init>(Lay0/a;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static final e(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/h;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ly81/a;->d:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    sget-object p0, Ls71/h;->e:Ls71/h;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_1
    sget-object p0, Ls71/h;->f:Ls71/h;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_2
    sget-object p0, Ls71/h;->h:Ls71/h;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_3
    sget-object p0, Ls71/h;->g:Ls71/h;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_4
    sget-object p0, Ls71/h;->d:Ls71/h;

    .line 36
    .line 37
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final f(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverTypePPE;)Ls71/i;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ly81/a;->c:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    sget-object p0, Ls71/i;->l:Ls71/i;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_1
    sget-object p0, Ls71/i;->k:Ls71/i;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_2
    sget-object p0, Ls71/i;->i:Ls71/i;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_3
    sget-object p0, Ls71/i;->h:Ls71/i;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_4
    sget-object p0, Ls71/i;->g:Ls71/i;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_5
    sget-object p0, Ls71/i;->f:Ls71/i;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_6
    sget-object p0, Ls71/i;->e:Ls71/i;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_7
    sget-object p0, Ls71/i;->d:Ls71/i;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x1
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

.method public static final g(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ParkingManeuverDirectionSideStatusPPE;)Ls71/j;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ly81/a;->d:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    sget-object p0, Ls71/j;->f:Ls71/j;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_1
    sget-object p0, Ls71/j;->g:Ls71/j;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_2
    sget-object p0, Ls71/j;->e:Ls71/j;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_3
    sget-object p0, Ls71/j;->d:Ls71/j;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final h(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;)Ls71/n;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ly81/a;->a:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    packed-switch p0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :pswitch_0
    sget-object p0, Ls71/n;->L:Ls71/n;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_1
    sget-object p0, Ls71/n;->K:Ls71/n;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_2
    sget-object p0, Ls71/n;->J:Ls71/n;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_3
    sget-object p0, Ls71/n;->I:Ls71/n;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_4
    sget-object p0, Ls71/n;->H:Ls71/n;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_5
    sget-object p0, Ls71/n;->G:Ls71/n;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_6
    sget-object p0, Ls71/n;->F:Ls71/n;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_7
    sget-object p0, Ls71/n;->E:Ls71/n;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_8
    sget-object p0, Ls71/n;->D:Ls71/n;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_9
    sget-object p0, Ls71/n;->C:Ls71/n;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_a
    sget-object p0, Ls71/n;->B:Ls71/n;

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_b
    sget-object p0, Ls71/n;->A:Ls71/n;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_c
    sget-object p0, Ls71/n;->z:Ls71/n;

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_d
    sget-object p0, Ls71/n;->y:Ls71/n;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_e
    sget-object p0, Ls71/n;->x:Ls71/n;

    .line 66
    .line 67
    return-object p0

    .line 68
    :pswitch_f
    sget-object p0, Ls71/n;->w:Ls71/n;

    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_10
    sget-object p0, Ls71/n;->v:Ls71/n;

    .line 72
    .line 73
    return-object p0

    .line 74
    :pswitch_11
    sget-object p0, Ls71/n;->u:Ls71/n;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_12
    sget-object p0, Ls71/n;->t:Ls71/n;

    .line 78
    .line 79
    return-object p0

    .line 80
    :pswitch_13
    sget-object p0, Ls71/n;->s:Ls71/n;

    .line 81
    .line 82
    return-object p0

    .line 83
    :pswitch_14
    sget-object p0, Ls71/n;->r:Ls71/n;

    .line 84
    .line 85
    return-object p0

    .line 86
    :pswitch_15
    sget-object p0, Ls71/n;->q:Ls71/n;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_16
    sget-object p0, Ls71/n;->p:Ls71/n;

    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_17
    sget-object p0, Ls71/n;->o:Ls71/n;

    .line 93
    .line 94
    return-object p0

    .line 95
    :pswitch_18
    sget-object p0, Ls71/n;->n:Ls71/n;

    .line 96
    .line 97
    return-object p0

    .line 98
    :pswitch_19
    sget-object p0, Ls71/n;->m:Ls71/n;

    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_1a
    sget-object p0, Ls71/n;->l:Ls71/n;

    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_1b
    sget-object p0, Ls71/n;->k:Ls71/n;

    .line 105
    .line 106
    return-object p0

    .line 107
    :pswitch_1c
    sget-object p0, Ls71/n;->j:Ls71/n;

    .line 108
    .line 109
    return-object p0

    .line 110
    :pswitch_1d
    sget-object p0, Ls71/n;->i:Ls71/n;

    .line 111
    .line 112
    return-object p0

    .line 113
    :pswitch_1e
    sget-object p0, Ls71/n;->h:Ls71/n;

    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_1f
    sget-object p0, Ls71/n;->g:Ls71/n;

    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_20
    sget-object p0, Ls71/n;->f:Ls71/n;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_21
    sget-object p0, Ls71/n;->e:Ls71/n;

    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_22
    sget-object p0, Ls71/n;->d:Ls71/n;

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_23
    const/4 p0, 0x0

    .line 129
    return-object p0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
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
