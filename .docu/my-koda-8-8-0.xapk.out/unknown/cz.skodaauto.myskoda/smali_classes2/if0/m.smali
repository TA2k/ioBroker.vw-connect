.class public final Lif0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Las0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lif0/m;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/16 v0, 0xb

    .line 9
    .line 10
    invoke-direct {p1, p0, v0}, Las0/h;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lif0/m;->b:Las0/h;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Ljava/lang/String;)Lss0/d;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :sswitch_0
    const-string v0, "UnknownCapabilityState"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lss0/d;->f:Lss0/d;

    .line 18
    .line 19
    return-object p0

    .line 20
    :sswitch_1
    const-string v0, "UnavailableCapability"

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lss0/d;->j:Lss0/d;

    .line 29
    .line 30
    return-object p0

    .line 31
    :sswitch_2
    const-string v0, "Unknown"

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-object p0, Lss0/d;->l:Lss0/d;

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_3
    const-string v0, "UnavailableTrunkDelivery"

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object p0, Lss0/d;->i:Lss0/d;

    .line 51
    .line 52
    return-object p0

    .line 53
    :sswitch_4
    const-string v0, "UnavailableOnlineSpeechGps"

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_0

    .line 60
    .line 61
    sget-object p0, Lss0/d;->g:Lss0/d;

    .line 62
    .line 63
    return-object p0

    .line 64
    :sswitch_5
    const-string v0, "UnavailableCarFeedback"

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_0

    .line 71
    .line 72
    sget-object p0, Lss0/d;->e:Lss0/d;

    .line 73
    .line 74
    return-object p0

    .line 75
    :sswitch_6
    const-string v0, "UnavailableFleet"

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_0

    .line 82
    .line 83
    sget-object p0, Lss0/d;->d:Lss0/d;

    .line 84
    .line 85
    return-object p0

    .line 86
    :sswitch_7
    const-string v0, "UnavailableDcs"

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_0

    .line 93
    .line 94
    sget-object p0, Lss0/d;->h:Lss0/d;

    .line 95
    .line 96
    return-object p0

    .line 97
    :sswitch_8
    const-string v0, "UnavailableServicePlatformCapabilities"

    .line 98
    .line 99
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    if-eqz v0, :cond_0

    .line 104
    .line 105
    sget-object p0, Lss0/d;->k:Lss0/d;

    .line 106
    .line 107
    return-object p0

    .line 108
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 109
    .line 110
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 111
    .line 112
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw v0

    .line 120
    nop

    .line 121
    :sswitch_data_0
    .sparse-switch
        -0x54f2f032 -> :sswitch_8
        -0xdd8a27c -> :sswitch_7
        0x5e62afe -> :sswitch_6
        0x1177e529 -> :sswitch_5
        0x28947505 -> :sswitch_4
        0x32be4778 -> :sswitch_3
        0x523e442a -> :sswitch_2
        0x655d0568 -> :sswitch_1
        0x6d7378cf -> :sswitch_0
    .end sparse-switch
.end method

.method public static b(Ljava/lang/String;)Lss0/m;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :sswitch_0
    const-string v0, "Preregistration"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lss0/m;->h:Lss0/m;

    .line 18
    .line 19
    return-object p0

    .line 20
    :sswitch_1
    const-string v0, "Unknown"

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lss0/m;->l:Lss0/m;

    .line 29
    .line 30
    return-object p0

    .line 31
    :sswitch_2
    const-string v0, "GuestUser"

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-object p0, Lss0/m;->g:Lss0/m;

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_3
    const-string v0, "NotActivated"

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object p0, Lss0/m;->e:Lss0/m;

    .line 51
    .line 52
    return-object p0

    .line 53
    :sswitch_4
    const-string v0, "GuestUserUnknownToVehicle"

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_0

    .line 60
    .line 61
    sget-object p0, Lss0/m;->j:Lss0/m;

    .line 62
    .line 63
    return-object p0

    .line 64
    :sswitch_5
    const-string v0, "PrimaryUserUnknownToVehicle"

    .line 65
    .line 66
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_0

    .line 71
    .line 72
    sget-object p0, Lss0/m;->i:Lss0/m;

    .line 73
    .line 74
    return-object p0

    .line 75
    :sswitch_6
    const-string v0, "GuestUserWaiting"

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_0

    .line 82
    .line 83
    sget-object p0, Lss0/m;->k:Lss0/m;

    .line 84
    .line 85
    return-object p0

    .line 86
    :sswitch_7
    const-string v0, "ResetSpin"

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_0

    .line 93
    .line 94
    sget-object p0, Lss0/m;->f:Lss0/m;

    .line 95
    .line 96
    return-object p0

    .line 97
    :sswitch_8
    const-string v0, "Activated"

    .line 98
    .line 99
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    if-eqz v0, :cond_0

    .line 104
    .line 105
    sget-object p0, Lss0/m;->d:Lss0/m;

    .line 106
    .line 107
    return-object p0

    .line 108
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 109
    .line 110
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 111
    .line 112
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw v0

    .line 120
    nop

    .line 121
    :sswitch_data_0
    .sparse-switch
        -0x7c5f164f -> :sswitch_8
        -0xfed95ef -> :sswitch_7
        -0xd7360d6 -> :sswitch_6
        0x1100ddf4 -> :sswitch_5
        0x16d62eca -> :sswitch_4
        0x1c32105e -> :sswitch_3
        0x428201a3 -> :sswitch_2
        0x523e442a -> :sswitch_1
        0x728a76bc -> :sswitch_0
    .end sparse-switch
.end method

.method public static c(Ljava/lang/String;)Lss0/n;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :sswitch_0
    const-string v0, "Unknown"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lss0/n;->h:Lss0/n;

    .line 18
    .line 19
    return-object p0

    .line 20
    :sswitch_1
    const-string v0, "Ordered"

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lss0/n;->g:Lss0/n;

    .line 29
    .line 30
    return-object p0

    .line 31
    :sswitch_2
    const-string v0, "Wcar"

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-object p0, Lss0/n;->f:Lss0/n;

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_3
    const-string v0, "Mbb"

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object p0, Lss0/n;->d:Lss0/n;

    .line 51
    .line 52
    return-object p0

    .line 53
    :sswitch_4
    const-string v0, "MbbOdp"

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_0

    .line 60
    .line 61
    sget-object p0, Lss0/n;->e:Lss0/n;

    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 65
    .line 66
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 67
    .line 68
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v0

    .line 76
    nop

    .line 77
    :sswitch_data_0
    .sparse-switch
        -0x77081752 -> :sswitch_4
        0x12d4d -> :sswitch_3
        0x290c1d -> :sswitch_2
        0x1b45904d -> :sswitch_1
        0x523e442a -> :sswitch_0
    .end sparse-switch
.end method

.method public static d(Ljava/lang/String;)Lss0/p;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto/16 :goto_0

    .line 9
    .line 10
    :sswitch_0
    const-string v0, "Unknown"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    sget-object p0, Lss0/p;->t:Lss0/p;

    .line 19
    .line 20
    return-object p0

    .line 21
    :sswitch_1
    const-string v0, "M6f"

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    sget-object p0, Lss0/p;->r:Lss0/p;

    .line 30
    .line 31
    return-object p0

    .line 32
    :sswitch_2
    const-string v0, "M6a"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    sget-object p0, Lss0/p;->q:Lss0/p;

    .line 41
    .line 42
    return-object p0

    .line 43
    :sswitch_3
    const-string v0, "M5f"

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_0

    .line 50
    .line 51
    sget-object p0, Lss0/p;->p:Lss0/p;

    .line 52
    .line 53
    return-object p0

    .line 54
    :sswitch_4
    const-string v0, "M5a"

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-eqz v0, :cond_0

    .line 61
    .line 62
    sget-object p0, Lss0/p;->o:Lss0/p;

    .line 63
    .line 64
    return-object p0

    .line 65
    :sswitch_5
    const-string v0, "E1h"

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-eqz v0, :cond_0

    .line 72
    .line 73
    sget-object p0, Lss0/p;->n:Lss0/p;

    .line 74
    .line 75
    return-object p0

    .line 76
    :sswitch_6
    const-string v0, "E1f"

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_0

    .line 83
    .line 84
    sget-object p0, Lss0/p;->s:Lss0/p;

    .line 85
    .line 86
    return-object p0

    .line 87
    :sswitch_7
    const-string v0, "E1a"

    .line 88
    .line 89
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    if-eqz v0, :cond_0

    .line 94
    .line 95
    sget-object p0, Lss0/p;->m:Lss0/p;

    .line 96
    .line 97
    return-object p0

    .line 98
    :sswitch_8
    const-string v0, "A8f"

    .line 99
    .line 100
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-eqz v0, :cond_0

    .line 105
    .line 106
    sget-object p0, Lss0/p;->l:Lss0/p;

    .line 107
    .line 108
    return-object p0

    .line 109
    :sswitch_9
    const-string v0, "A8a"

    .line 110
    .line 111
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-eqz v0, :cond_0

    .line 116
    .line 117
    sget-object p0, Lss0/p;->k:Lss0/p;

    .line 118
    .line 119
    return-object p0

    .line 120
    :sswitch_a
    const-string v0, "A7f"

    .line 121
    .line 122
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-eqz v0, :cond_0

    .line 127
    .line 128
    sget-object p0, Lss0/p;->j:Lss0/p;

    .line 129
    .line 130
    return-object p0

    .line 131
    :sswitch_b
    const-string v0, "A7a"

    .line 132
    .line 133
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    if-eqz v0, :cond_0

    .line 138
    .line 139
    sget-object p0, Lss0/p;->i:Lss0/p;

    .line 140
    .line 141
    return-object p0

    .line 142
    :sswitch_c
    const-string v0, "A6f"

    .line 143
    .line 144
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    if-eqz v0, :cond_0

    .line 149
    .line 150
    sget-object p0, Lss0/p;->h:Lss0/p;

    .line 151
    .line 152
    return-object p0

    .line 153
    :sswitch_d
    const-string v0, "A6a"

    .line 154
    .line 155
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    if-eqz v0, :cond_0

    .line 160
    .line 161
    sget-object p0, Lss0/p;->g:Lss0/p;

    .line 162
    .line 163
    return-object p0

    .line 164
    :sswitch_e
    const-string v0, "A5f"

    .line 165
    .line 166
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    if-eqz v0, :cond_0

    .line 171
    .line 172
    sget-object p0, Lss0/p;->f:Lss0/p;

    .line 173
    .line 174
    return-object p0

    .line 175
    :sswitch_f
    const-string v0, "A5a"

    .line 176
    .line 177
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    if-eqz v0, :cond_0

    .line 182
    .line 183
    sget-object p0, Lss0/p;->e:Lss0/p;

    .line 184
    .line 185
    return-object p0

    .line 186
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 187
    .line 188
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 189
    .line 190
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    throw v0

    .line 198
    nop

    .line 199
    :sswitch_data_0
    .sparse-switch
        0xfacd -> :sswitch_f
        0xfad2 -> :sswitch_e
        0xfaec -> :sswitch_d
        0xfaf1 -> :sswitch_c
        0xfb0b -> :sswitch_b
        0xfb10 -> :sswitch_a
        0xfb2a -> :sswitch_9
        0xfb2f -> :sswitch_8
        0x10955 -> :sswitch_7
        0x1095a -> :sswitch_6
        0x1095c -> :sswitch_5
        0x127d9 -> :sswitch_4
        0x127de -> :sswitch_3
        0x127f8 -> :sswitch_2
        0x127fd -> :sswitch_1
        0x523e442a -> :sswitch_0
    .end sparse-switch
.end method


# virtual methods
.method public final e(Lua/a;Landroidx/collection/f;)V
    .locals 7

    .line 1
    invoke-virtual {p2}, Landroidx/collection/f;->keySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/Set;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {p2}, Landroidx/collection/a1;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/16 v2, 0x3e7

    .line 17
    .line 18
    if-le v1, v2, :cond_1

    .line 19
    .line 20
    new-instance v0, Lif0/l;

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    invoke-direct {v0, p0, p1, v1}, Lif0/l;-><init>(Lif0/m;Lua/a;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {p2, v0}, Ljp/ye;->b(Landroidx/collection/f;Lay0/k;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    const-string p0, "SELECT `id`,`serviceExpiration`,`statuses`,`vin` FROM `capability` WHERE `vin` IN ("

    .line 31
    .line 32
    invoke-static {p0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-static {v1, p0}, Ljp/cf;->d(ILjava/lang/StringBuilder;)V

    .line 41
    .line 42
    .line 43
    const-string v1, ")"

    .line 44
    .line 45
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const-string v1, "toString(...)"

    .line 53
    .line 54
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-interface {p1, p0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    const/4 v0, 0x1

    .line 66
    move v1, v0

    .line 67
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_2

    .line 72
    .line 73
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Ljava/lang/String;

    .line 78
    .line 79
    invoke-interface {p0, v1, v2}, Lua/c;->w(ILjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    add-int/2addr v1, v0

    .line 83
    goto :goto_0

    .line 84
    :cond_2
    :try_start_0
    const-string p1, "vin"

    .line 85
    .line 86
    invoke-static {p0, p1}, Ljp/af;->c(Lua/c;Ljava/lang/String;)I

    .line 87
    .line 88
    .line 89
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 90
    const/4 v1, -0x1

    .line 91
    if-ne p1, v1, :cond_3

    .line 92
    .line 93
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {p0}, Lua/c;->s0()Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-eqz v1, :cond_6

    .line 102
    .line 103
    invoke-interface {p0, p1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-virtual {p2, v1}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    check-cast v1, Ljava/util/List;

    .line 112
    .line 113
    if-eqz v1, :cond_3

    .line 114
    .line 115
    const/4 v2, 0x0

    .line 116
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-interface {p0, v0}, Lua/c;->isNull(I)Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    const/4 v4, 0x0

    .line 125
    if-eqz v3, :cond_4

    .line 126
    .line 127
    move-object v3, v4

    .line 128
    goto :goto_2

    .line 129
    :cond_4
    invoke-interface {p0, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    :goto_2
    invoke-static {v3}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    const/4 v5, 0x2

    .line 138
    invoke-interface {p0, v5}, Lua/c;->isNull(I)Z

    .line 139
    .line 140
    .line 141
    move-result v6

    .line 142
    if-eqz v6, :cond_5

    .line 143
    .line 144
    goto :goto_3

    .line 145
    :cond_5
    invoke-interface {p0, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    :goto_3
    const/4 v5, 0x3

    .line 150
    invoke-interface {p0, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    new-instance v6, Lif0/f;

    .line 155
    .line 156
    invoke-direct {v6, v2, v3, v4, v5}, Lif0/f;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    invoke-interface {v1, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 160
    .line 161
    .line 162
    goto :goto_1

    .line 163
    :catchall_0
    move-exception p1

    .line 164
    goto :goto_4

    .line 165
    :cond_6
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 166
    .line 167
    .line 168
    return-void

    .line 169
    :goto_4
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 170
    .line 171
    .line 172
    throw p1
.end method

.method public final f(Lua/a;Landroidx/collection/f;)V
    .locals 6

    .line 1
    invoke-virtual {p2}, Landroidx/collection/f;->keySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/Set;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {p2}, Landroidx/collection/a1;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/16 v2, 0x3e7

    .line 17
    .line 18
    if-le v1, v2, :cond_1

    .line 19
    .line 20
    new-instance v0, Lif0/l;

    .line 21
    .line 22
    const/4 v1, 0x1

    .line 23
    invoke-direct {v0, p0, p1, v1}, Lif0/l;-><init>(Lif0/m;Lua/a;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {p2, v0}, Ljp/ye;->b(Landroidx/collection/f;Lay0/k;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    const-string p0, "SELECT `type`,`description`,`vin` FROM `capability_error` WHERE `vin` IN ("

    .line 31
    .line 32
    invoke-static {p0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-static {v1, p0}, Ljp/cf;->d(ILjava/lang/StringBuilder;)V

    .line 41
    .line 42
    .line 43
    const-string v1, ")"

    .line 44
    .line 45
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const-string v1, "toString(...)"

    .line 53
    .line 54
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-interface {p1, p0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    const/4 v0, 0x1

    .line 66
    move v1, v0

    .line 67
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_2

    .line 72
    .line 73
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Ljava/lang/String;

    .line 78
    .line 79
    invoke-interface {p0, v1, v2}, Lua/c;->w(ILjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    add-int/2addr v1, v0

    .line 83
    goto :goto_0

    .line 84
    :cond_2
    :try_start_0
    const-string p1, "vin"

    .line 85
    .line 86
    invoke-static {p0, p1}, Ljp/af;->c(Lua/c;Ljava/lang/String;)I

    .line 87
    .line 88
    .line 89
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 90
    const/4 v1, -0x1

    .line 91
    if-ne p1, v1, :cond_3

    .line 92
    .line 93
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {p0}, Lua/c;->s0()Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-eqz v1, :cond_5

    .line 102
    .line 103
    invoke-interface {p0, p1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-virtual {p2, v1}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    check-cast v1, Ljava/util/List;

    .line 112
    .line 113
    if-eqz v1, :cond_3

    .line 114
    .line 115
    const/4 v2, 0x0

    .line 116
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-static {v2}, Lif0/m;->a(Ljava/lang/String;)Lss0/d;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    invoke-interface {p0, v0}, Lua/c;->isNull(I)Z

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    if-eqz v3, :cond_4

    .line 129
    .line 130
    const/4 v3, 0x0

    .line 131
    goto :goto_2

    .line 132
    :cond_4
    invoke-interface {p0, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    :goto_2
    const/4 v4, 0x2

    .line 137
    invoke-interface {p0, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    new-instance v5, Lif0/i;

    .line 142
    .line 143
    invoke-direct {v5, v2, v3, v4}, Lif0/i;-><init>(Lss0/d;Ljava/lang/String;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    invoke-interface {v1, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 147
    .line 148
    .line 149
    goto :goto_1

    .line 150
    :catchall_0
    move-exception p1

    .line 151
    goto :goto_3

    .line 152
    :cond_5
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 153
    .line 154
    .line 155
    return-void

    .line 156
    :goto_3
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 157
    .line 158
    .line 159
    throw p1
.end method
