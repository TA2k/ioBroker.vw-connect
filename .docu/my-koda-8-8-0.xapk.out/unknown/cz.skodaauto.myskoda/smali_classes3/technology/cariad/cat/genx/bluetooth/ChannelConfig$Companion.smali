.class public final Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\u0080\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u001d\u0010\u0004\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0008\u0010\u0008\u001a\u0004\u0018\u00010\tH\u0086\u0002\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;",
        "",
        "<init>",
        "()V",
        "invoke",
        "Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;",
        "channel",
        "Ltechnology/cariad/cat/genx/Channel;",
        "service",
        "Landroid/bluetooth/BluetoothGattService;",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;-><init>()V

    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;Landroid/bluetooth/BluetoothGattCharacteristic;Landroid/bluetooth/BluetoothGattCharacteristic;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;->invoke$lambda$2(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;Landroid/bluetooth/BluetoothGattCharacteristic;Landroid/bluetooth/BluetoothGattCharacteristic;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invoke$lambda$2(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;Landroid/bluetooth/BluetoothGattCharacteristic;Landroid/bluetooth/BluetoothGattCharacteristic;)Ljava/lang/String;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    move v2, v1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v2, v0

    .line 8
    :goto_0
    if-eqz p1, :cond_1

    .line 9
    .line 10
    if-nez p2, :cond_1

    .line 11
    .line 12
    move p2, v1

    .line 13
    goto :goto_1

    .line 14
    :cond_1
    move p2, v0

    .line 15
    :goto_1
    if-eqz p1, :cond_2

    .line 16
    .line 17
    if-nez p3, :cond_2

    .line 18
    .line 19
    move v0, v1

    .line 20
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string p3, "ChannelConfig("

    .line 23
    .line 24
    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, "): Either service ("

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p0, "), notifyCharacteristic ("

    .line 39
    .line 40
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ") or writeCharacteristic ("

    .line 44
    .line 45
    const-string p3, ") is null -> Return \'null\'."

    .line 46
    .line 47
    invoke-static {p1, p2, p0, v0, p3}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method


# virtual methods
.method public final invoke(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;
    .locals 10

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    if-eqz p2, :cond_2

    .line 8
    .line 9
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattService;->getCharacteristics()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    check-cast v1, Ljava/lang/Iterable;

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    move-object v3, v2

    .line 32
    check-cast v3, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 33
    .line 34
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfigKt;->notifyCharacteristicUUID(Ltechnology/cariad/cat/genx/Channel;)Ljava/util/UUID;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    move-object v2, v0

    .line 50
    :goto_0
    check-cast v2, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 51
    .line 52
    move-object v5, v2

    .line 53
    goto :goto_1

    .line 54
    :cond_2
    move-object v5, v0

    .line 55
    :goto_1
    if-eqz p2, :cond_5

    .line 56
    .line 57
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattService;->getCharacteristics()Ljava/util/List;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    if-eqz v1, :cond_5

    .line 62
    .line 63
    check-cast v1, Ljava/lang/Iterable;

    .line 64
    .line 65
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    :cond_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_4

    .line 74
    .line 75
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    move-object v3, v2

    .line 80
    check-cast v3, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 81
    .line 82
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfigKt;->writeCharacteristicUUID(Ltechnology/cariad/cat/genx/Channel;)Ljava/util/UUID;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    if-eqz v3, :cond_3

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_4
    move-object v2, v0

    .line 98
    :goto_2
    check-cast v2, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 99
    .line 100
    move-object v6, v2

    .line 101
    goto :goto_3

    .line 102
    :cond_5
    move-object v6, v0

    .line 103
    :goto_3
    if-eqz v5, :cond_6

    .line 104
    .line 105
    if-eqz v6, :cond_6

    .line 106
    .line 107
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 108
    .line 109
    const/16 v8, 0x8

    .line 110
    .line 111
    const/4 v9, 0x0

    .line 112
    const/4 v7, 0x0

    .line 113
    move-object v4, p1

    .line 114
    invoke-direct/range {v3 .. v9}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;-><init>(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattCharacteristic;Landroid/bluetooth/BluetoothGattCharacteristic;ZILkotlin/jvm/internal/g;)V

    .line 115
    .line 116
    .line 117
    return-object v3

    .line 118
    :cond_6
    move-object v4, p1

    .line 119
    new-instance v3, Lal/i;

    .line 120
    .line 121
    const/16 v8, 0xc

    .line 122
    .line 123
    move-object v7, v6

    .line 124
    move-object v6, v5

    .line 125
    move-object v5, p2

    .line 126
    invoke-direct/range {v3 .. v8}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 127
    .line 128
    .line 129
    const-string p1, "GenX"

    .line 130
    .line 131
    invoke-static {p0, p1, v0, v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 132
    .line 133
    .line 134
    return-object v0
.end method
