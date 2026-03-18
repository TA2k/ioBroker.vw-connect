.class public final Ltechnology/cariad/cat/genx/GenXErrorKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u001a\u001f\u0010\u0004\u001a\u0004\u0018\u00010\u00032\u000c\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00010\u0000H\u0000\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\" \u0010\u000b\u001a\u0004\u0018\u00010\u0001*\u00020\u00068@X\u0080\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\u000c"
    }
    d2 = {
        "Lkotlin/Function0;",
        "",
        "statusCall",
        "Ltechnology/cariad/cat/genx/GenXError$CoreGenX;",
        "checkStatus",
        "(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "getCgxStatusValue",
        "(Ltechnology/cariad/cat/genx/GenXError;)Ljava/lang/Integer;",
        "getCgxStatusValue$annotations",
        "(Ltechnology/cariad/cat/genx/GenXError;)V",
        "cgxStatusValue",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")",
            "Ltechnology/cariad/cat/genx/GenXError$CoreGenX;"
        }
    .end annotation

    .line 1
    const-string v0, "statusCall"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-static {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatusKt;->getCoreGenXStatus(I)Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object v0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 21
    .line 22
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getSuccess()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    return-object p0

    .line 34
    :cond_0
    invoke-static {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatusExtensionsKt;->loadLastStatusMessage(Ltechnology/cariad/cat/genx/CoreGenXStatus;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    new-instance v1, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 39
    .line 40
    invoke-direct {v1, p0, v0}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;-><init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-object v1
.end method

.method public static final getCgxStatusValue(Ltechnology/cariad/cat/genx/GenXError;)Ljava/lang/Integer;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 11
    .line 12
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->getStatus()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    instance-of v0, p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 26
    .line 27
    if-eqz v0, :cond_5

    .line 28
    .line 29
    check-cast p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 30
    .line 31
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;->getBluetoothError()Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    instance-of v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$ChannelNotFound;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getWrongChannel()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    instance-of v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$Disabled;

    .line 51
    .line 52
    if-eqz v0, :cond_2

    .line 53
    .line 54
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 55
    .line 56
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getClientDisabled()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    goto :goto_1

    .line 65
    :cond_2
    instance-of v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$LocationPermissionRequiredButMissing;

    .line 66
    .line 67
    if-nez v0, :cond_4

    .line 68
    .line 69
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothScanPermissionRequiredButMissing;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothScanPermissionRequiredButMissing;

    .line 70
    .line 71
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-nez v0, :cond_4

    .line 76
    .line 77
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothConnectPermissionRequiredButMissing;->INSTANCE:Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$BluetoothConnectPermissionRequiredButMissing;

    .line 78
    .line 79
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-eqz p0, :cond_3

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_3
    new-instance p0, La8/r0;

    .line 87
    .line 88
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_4
    :goto_0
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 93
    .line 94
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getRequiredPermissionsMissing()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    :goto_1
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :cond_5
    instance-of v0, p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;

    .line 108
    .line 109
    const/4 v1, 0x0

    .line 110
    if-eqz v0, :cond_7

    .line 111
    .line 112
    check-cast p0, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;

    .line 113
    .line 114
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/GenXError$BeaconScanner;->getBeaconScannerError()Lt41/k;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    instance-of v0, p0, Lt41/j;

    .line 119
    .line 120
    if-eqz v0, :cond_6

    .line 121
    .line 122
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 123
    .line 124
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getRequiredPermissionsMissing()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    return-object p0

    .line 137
    :cond_6
    instance-of p0, p0, Lt41/h;

    .line 138
    .line 139
    if-eqz p0, :cond_7

    .line 140
    .line 141
    sget-object p0, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 142
    .line 143
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getRequiredPermissionsMissing()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->getRawValue()I

    .line 148
    .line 149
    .line 150
    move-result p0

    .line 151
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    return-object p0

    .line 156
    :cond_7
    return-object v1
.end method

.method public static synthetic getCgxStatusValue$annotations(Ltechnology/cariad/cat/genx/GenXError;)V
    .locals 0

    .line 1
    return-void
.end method
