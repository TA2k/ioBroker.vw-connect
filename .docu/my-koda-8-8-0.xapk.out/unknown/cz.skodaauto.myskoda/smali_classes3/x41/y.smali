.class public final synthetic Lx41/y;
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
    iput p1, p0, Lx41/y;->d:I

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
    iget p0, p0, Lx41/y;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lqz0/f;

    .line 7
    .line 8
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 9
    .line 10
    const-class v1, Lxf/p;

    .line 11
    .line 12
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    const-class v1, Lxf/g;

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const-class v3, Lxf/l;

    .line 23
    .line 24
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    const-class v4, Lxf/o;

    .line 29
    .line 30
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const/4 v4, 0x3

    .line 35
    move-object v5, v3

    .line 36
    new-array v3, v4, [Lhy0/d;

    .line 37
    .line 38
    const/4 v6, 0x0

    .line 39
    aput-object v1, v3, v6

    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    aput-object v5, v3, v1

    .line 43
    .line 44
    const/4 v5, 0x2

    .line 45
    aput-object p0, v3, v5

    .line 46
    .line 47
    new-array v4, v4, [Lqz0/a;

    .line 48
    .line 49
    sget-object p0, Lxf/c;->a:Lxf/c;

    .line 50
    .line 51
    aput-object p0, v4, v6

    .line 52
    .line 53
    sget-object p0, Lxf/h;->a:Lxf/h;

    .line 54
    .line 55
    aput-object p0, v4, v1

    .line 56
    .line 57
    sget-object p0, Lxf/m;->a:Lxf/m;

    .line 58
    .line 59
    aput-object p0, v4, v5

    .line 60
    .line 61
    new-instance p0, Lje/e;

    .line 62
    .line 63
    invoke-direct {p0, v1}, Lje/e;-><init>(I)V

    .line 64
    .line 65
    .line 66
    new-array v5, v1, [Ljava/lang/annotation/Annotation;

    .line 67
    .line 68
    aput-object p0, v5, v6

    .line 69
    .line 70
    const-string v1, "cariad.charging.multicharge.kitten.plugandchargeoffline.models.PNCOfflineGetResponse"

    .line 71
    .line 72
    invoke-direct/range {v0 .. v5}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 73
    .line 74
    .line 75
    return-object v0

    .line 76
    :pswitch_0
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 77
    .line 78
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_1
    sget-object p0, Lgf/a;->d:Lgf/a;

    .line 84
    .line 85
    invoke-static {p0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_2
    sget-object p0, Lw60/b;->a:Lw60/b;

    .line 91
    .line 92
    return-object p0

    .line 93
    :pswitch_3
    const-string p0, "storeProviderPairingsInSecureStorage(): Failed to store provider pairings"

    .line 94
    .line 95
    return-object p0

    .line 96
    :pswitch_4
    const-string p0, "storeLocalPairingsInSecureStorage(): Failed to store local pairings"

    .line 97
    .line 98
    return-object p0

    .line 99
    :pswitch_5
    const-string p0, "storeLocalKeyPairInSecureStorage(): Failed to store local keypair"

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_6
    const-string p0, "restoreProviderPairingsFromSecureStorage()"

    .line 103
    .line 104
    return-object p0

    .line 105
    :pswitch_7
    const-string p0, "restoreLocalPairingsFromSecureStorage(): Failed to restore local pairings"

    .line 106
    .line 107
    return-object p0

    .line 108
    :pswitch_8
    const-string p0, "restoreLocalPairingsFromSecureStorage(): Old Key is still in use -> Migrate old pairings to new version"

    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_9
    const-string p0, "restoreLocalPairingsFromSecureStorage()"

    .line 112
    .line 113
    return-object p0

    .line 114
    :pswitch_a
    const-string p0, "restoreLocalKeyPairFromSecureStorageOrGenerateNewAndStore(): Failed to restore local keypair -> Generate new local keypair"

    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_b
    const-string p0, "restoreLocalKeyPairFromSecureStorageOrGenerateNewAndStore(): Restored local keypair was \'null\' -> Generate new local keypair"

    .line 118
    .line 119
    return-object p0

    .line 120
    :pswitch_c
    const-string p0, "restoreLocalKeyPairFromSecureStorageOrGenerateNewAndStore(): Successfully restored local keypair"

    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_d
    const-string p0, "restoreProviderPairingsFromSecureStorage(): Failed to restore provider pairings"

    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_e
    const-string p0, "storeLocalKeyPairInSecureStorage(): Storing local keypair"

    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_f
    const-string p0, "onKeyExchangeSucceeded(): No QRCodePairingDelegate set"

    .line 130
    .line 131
    return-object p0

    .line 132
    :pswitch_10
    const-string p0, "onKeyExchangeStarted(): Successfully started key exchange"

    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_11
    const-string p0, "onVehicleManagerEncounteredError()"

    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_12
    const-string p0, "startQRCodePairing(): Another pairing is still in progress"

    .line 139
    .line 140
    return-object p0

    .line 141
    :pswitch_13
    const-string p0, "startQRCodePairing()"

    .line 142
    .line 143
    return-object p0

    .line 144
    :pswitch_14
    const-string p0, "checkAllRequiredPermissionsAndRequestPermissionIfRequired()"

    .line 145
    .line 146
    return-object p0

    .line 147
    :pswitch_15
    const-string p0, "stopScanningForVehicles()"

    .line 148
    .line 149
    return-object p0

    .line 150
    :pswitch_16
    const-string p0, "startScanningForVehicles(): Failed to start scanning"

    .line 151
    .line 152
    return-object p0

    .line 153
    :pswitch_17
    const-string p0, "updateRegisteredPairings(): Start to collect VehicleAntenna updates"

    .line 154
    .line 155
    return-object p0

    .line 156
    :pswitch_18
    const-string p0, "updateRegisteredPairings(): Failed to register vehicles"

    .line 157
    .line 158
    return-object p0

    .line 159
    :pswitch_19
    const-string p0, "cancelQRCodePairing(): Failed cancel key exchange"

    .line 160
    .line 161
    return-object p0

    .line 162
    :pswitch_1a
    const-string p0, "cancelQRCodePairing()"

    .line 163
    .line 164
    return-object p0

    .line 165
    :pswitch_1b
    const-string p0, "restoreProviderPairings(): Provider pairings are available but \'Pairing Provider\' set to null -> Remove provider pairings"

    .line 166
    .line 167
    return-object p0

    .line 168
    :pswitch_1c
    const-string p0, "startScanningForVehicles()"

    .line 169
    .line 170
    return-object p0

    .line 171
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
