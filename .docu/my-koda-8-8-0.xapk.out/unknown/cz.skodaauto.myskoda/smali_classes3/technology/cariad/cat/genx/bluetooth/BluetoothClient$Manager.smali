.class final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;
.super Lno/nordicsemi/android/ble/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "Manager"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000j\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0082\u0004\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u0015\u0010\u000b\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\u0008\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0019\u0010\u000f\u001a\u0004\u0018\u00010\u000e2\u0008\u0010\r\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0011H\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u001f\u0010\u0017\u001a\u00020\n2\u0006\u0010\u0014\u001a\u00020\u00112\u0006\u0010\u0016\u001a\u00020\u0015H\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u0015\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u000f\u001a\u00020\u000e\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ\u001d\u0010\u001e\u001a\u00020\u00192\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u001d\u001a\u00020\u001c\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u0017\u0010#\u001a\u00020\"2\u0006\u0010!\u001a\u00020 H\u0014\u00a2\u0006\u0004\u0008#\u0010$J\u000f\u0010%\u001a\u00020\nH\u0014\u00a2\u0006\u0004\u0008%\u0010&J\u000f\u0010\'\u001a\u00020\nH\u0014\u00a2\u0006\u0004\u0008\'\u0010&J\u000f\u0010(\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008(\u0010&J\u0017\u0010)\u001a\u00020\"2\u0006\u0010\t\u001a\u00020\u0008H\u0002\u00a2\u0006\u0004\u0008)\u0010*J\u0017\u0010-\u001a\u00020\n2\u0006\u0010,\u001a\u00020+H\u0002\u00a2\u0006\u0004\u0008-\u0010.J\u0017\u0010/\u001a\u00020\n2\u0006\u0010,\u001a\u00020+H\u0002\u00a2\u0006\u0004\u0008/\u0010.R$\u00100\u001a\u0004\u0018\u00010\u000e8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u00080\u00101\u001a\u0004\u00082\u00103\"\u0004\u00084\u00105R$\u00106\u001a\u0004\u0018\u00010\u000e8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u00086\u00101\u001a\u0004\u00087\u00103\"\u0004\u00088\u00105R\u001a\u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u0008098\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008:\u0010;\u00a8\u0006<"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;",
        "Lno/nordicsemi/android/ble/e;",
        "Landroid/content/Context;",
        "context",
        "Landroid/os/Handler;",
        "handler",
        "<init>",
        "(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/content/Context;Landroid/os/Handler;)V",
        "Ltechnology/cariad/cat/genx/Channel;",
        "channel",
        "Llx0/b0;",
        "discoverChannel",
        "(Ltechnology/cariad/cat/genx/Channel;)V",
        "forChannel",
        "Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;",
        "channelConfig",
        "(Ltechnology/cariad/cat/genx/Channel;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;",
        "",
        "getMinLogPriority",
        "()I",
        "priority",
        "",
        "message",
        "log",
        "(ILjava/lang/String;)V",
        "Lno/nordicsemi/android/ble/v0;",
        "enableNotifications",
        "(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Lno/nordicsemi/android/ble/v0;",
        "",
        "data",
        "sendData",
        "(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;[B)Lno/nordicsemi/android/ble/v0;",
        "Landroid/bluetooth/BluetoothGatt;",
        "gatt",
        "",
        "isRequiredServiceSupported",
        "(Landroid/bluetooth/BluetoothGatt;)Z",
        "onServicesInvalidated",
        "()V",
        "initialize",
        "close",
        "shouldDiscoverChannel",
        "(Ltechnology/cariad/cat/genx/Channel;)Z",
        "Landroid/bluetooth/BluetoothGattService;",
        "service",
        "checkIfHandshakeChannelIsAvailable",
        "(Landroid/bluetooth/BluetoothGattService;)V",
        "checkIfDataChannelIsAvailable",
        "handshakeConfig",
        "Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;",
        "getHandshakeConfig",
        "()Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;",
        "setHandshakeConfig",
        "(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V",
        "dataConfig",
        "getDataConfig",
        "setDataConfig",
        "Ljava/util/concurrent/CopyOnWriteArraySet;",
        "channelToDiscover",
        "Ljava/util/concurrent/CopyOnWriteArraySet;",
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


# instance fields
.field private final channelToDiscover:Ljava/util/concurrent/CopyOnWriteArraySet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/CopyOnWriteArraySet<",
            "Ltechnology/cariad/cat/genx/Channel;",
            ">;"
        }
    .end annotation
.end field

.field private dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

.field private handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/content/Context;Landroid/os/Handler;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Landroid/os/Handler;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "handler"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 12
    .line 13
    invoke-direct {p0, p2, p3}, Lno/nordicsemi/android/ble/e;-><init>(Landroid/content/Context;Landroid/os/Handler;)V

    .line 14
    .line 15
    .line 16
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 17
    .line 18
    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->channelToDiscover:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 22
    .line 23
    return-void
.end method

.method public static synthetic A(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfDataChannelIsAvailable$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic B(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$4(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfHandshakeChannelIsAvailable$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->isRequiredServiceSupported$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->log$lambda$0(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final checkIfDataChannelIsAvailable(Landroid/bluetooth/BluetoothGattService;)V
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 2
    .line 3
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 4
    .line 5
    const-string v1, "getName(...)"

    .line 6
    .line 7
    if-nez v0, :cond_2

    .line 8
    .line 9
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->Companion:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;

    .line 10
    .line 11
    sget-object v2, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 12
    .line 13
    invoke-virtual {v0, v2, p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;->invoke(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 20
    .line 21
    new-instance v7, Ltechnology/cariad/cat/genx/bluetooth/k;

    .line 22
    .line 23
    const/4 v4, 0x2

    .line 24
    invoke-direct {v7, p1, v4}, Ltechnology/cariad/cat/genx/bluetooth/k;-><init>(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;I)V

    .line 25
    .line 26
    .line 27
    new-instance v4, Lt51/j;

    .line 28
    .line 29
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v9

    .line 33
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v10

    .line 37
    const-string v5, "GenX"

    .line 38
    .line 39
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 40
    .line 41
    const/4 v8, 0x0

    .line 42
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    invoke-virtual {p0, v4}, Lno/nordicsemi/android/ble/e;->setNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/r0;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/o;

    .line 57
    .line 58
    const/4 v6, 0x0

    .line 59
    invoke-direct {v5, v0, v6}, Ltechnology/cariad/cat/genx/bluetooth/o;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 60
    .line 61
    .line 62
    iput-object v5, v4, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    .line 63
    .line 64
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 65
    .line 66
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    if-eqz v2, :cond_3

    .line 71
    .line 72
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/k;

    .line 73
    .line 74
    const/4 v2, 0x3

    .line 75
    invoke-direct {v4, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/k;-><init>(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;I)V

    .line 76
    .line 77
    .line 78
    move-object v2, v1

    .line 79
    new-instance v1, Lt51/j;

    .line 80
    .line 81
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    const-string v2, "GenX"

    .line 90
    .line 91
    const/4 v5, 0x0

    .line 92
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$genx_release(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    :cond_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 103
    .line 104
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 105
    .line 106
    const/4 v1, 0x2

    .line 107
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 108
    .line 109
    .line 110
    const-string v1, "GenX"

    .line 111
    .line 112
    const/4 v3, 0x0

    .line 113
    invoke-static {p0, v1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 114
    .line 115
    .line 116
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-eqz v0, :cond_1

    .line 121
    .line 122
    const/4 v0, 0x0

    .line 123
    invoke-virtual {p1, v2, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscoveryFailed$genx_release(Ltechnology/cariad/cat/genx/Channel;I)V

    .line 124
    .line 125
    .line 126
    :cond_1
    iput-object v3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 127
    .line 128
    return-void

    .line 129
    :cond_2
    move-object v2, v1

    .line 130
    sget-object p1, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 131
    .line 132
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    if-eqz p1, :cond_3

    .line 137
    .line 138
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 139
    .line 140
    const/4 p1, 0x3

    .line 141
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 142
    .line 143
    .line 144
    new-instance v1, Lt51/j;

    .line 145
    .line 146
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v7

    .line 154
    const-string v2, "GenX"

    .line 155
    .line 156
    const/4 v5, 0x0

    .line 157
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 161
    .line 162
    .line 163
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 164
    .line 165
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$genx_release(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V

    .line 166
    .line 167
    .line 168
    :cond_3
    return-void
.end method

.method private static final checkIfDataChannelIsAvailable$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "checkIfDataCharacteristicIsAvailable(): \'"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, "\' channel found -> Setting \'NotificationCallback\'"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final checkIfDataChannelIsAvailable$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    .locals 1

    .line 1
    const-string v0, "<unused var>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "data"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object p1, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 12
    .line 13
    iget-object p2, p2, Lzz0/a;->d:[B

    .line 14
    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    new-array p2, p2, [B

    .line 19
    .line 20
    :cond_0
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDataReceived$genx_release(Ltechnology/cariad/cat/genx/Channel;[B)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method private static final checkIfDataChannelIsAvailable$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "checkIfHandshakeChannelIsAvailable(): Channel \'"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, "\' should be discovered -> Enabling notifications if not enabled"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final checkIfDataChannelIsAvailable$lambda$1$0()Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "checkIfDataCharacteristicIsAvailable(): \'"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v0, "\' channel not found"

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    return-object v0
.end method

.method private static final checkIfDataChannelIsAvailable$lambda$2()Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Channel;->DATA:Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "checkIfHandshakeChannelIsAvailable(): Channel \'"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v0, "\' already found -> Enabling notifications if not enabled"

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    return-object v0
.end method

.method private final checkIfHandshakeChannelIsAvailable(Landroid/bluetooth/BluetoothGattService;)V
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 2
    .line 3
    sget-object v3, Lt51/d;->a:Lt51/d;

    .line 4
    .line 5
    const-string v1, "getName(...)"

    .line 6
    .line 7
    if-nez v0, :cond_2

    .line 8
    .line 9
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->Companion:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;

    .line 10
    .line 11
    sget-object v2, Ltechnology/cariad/cat/genx/Channel;->HANDSHAKE:Ltechnology/cariad/cat/genx/Channel;

    .line 12
    .line 13
    invoke-virtual {v0, v2, p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig$Companion;->invoke(Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothGattService;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 20
    .line 21
    new-instance v7, Ltechnology/cariad/cat/genx/bluetooth/k;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    invoke-direct {v7, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/k;-><init>(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;I)V

    .line 25
    .line 26
    .line 27
    new-instance v4, Lt51/j;

    .line 28
    .line 29
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v9

    .line 33
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v10

    .line 37
    const-string v5, "GenX"

    .line 38
    .line 39
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 40
    .line 41
    const/4 v8, 0x0

    .line 42
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {p0, v2}, Lno/nordicsemi/android/ble/e;->setNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/r0;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/l;

    .line 57
    .line 58
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/l;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object v4, v2, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    .line 62
    .line 63
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 64
    .line 65
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_3

    .line 74
    .line 75
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/k;

    .line 76
    .line 77
    const/4 v2, 0x1

    .line 78
    invoke-direct {v4, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/k;-><init>(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;I)V

    .line 79
    .line 80
    .line 81
    move-object v2, v1

    .line 82
    new-instance v1, Lt51/j;

    .line 83
    .line 84
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v6

    .line 88
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v7

    .line 92
    const-string v2, "GenX"

    .line 93
    .line 94
    const/4 v5, 0x0

    .line 95
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$genx_release(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :cond_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 106
    .line 107
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 108
    .line 109
    const/4 v1, 0x0

    .line 110
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 111
    .line 112
    .line 113
    const-string v1, "GenX"

    .line 114
    .line 115
    const/4 v3, 0x0

    .line 116
    invoke-static {p0, v1, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 117
    .line 118
    .line 119
    invoke-direct {p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    if-eqz v0, :cond_1

    .line 124
    .line 125
    const/4 v0, 0x0

    .line 126
    invoke-virtual {p1, v2, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscoveryFailed$genx_release(Ltechnology/cariad/cat/genx/Channel;I)V

    .line 127
    .line 128
    .line 129
    :cond_1
    iput-object v3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 130
    .line 131
    return-void

    .line 132
    :cond_2
    move-object v2, v1

    .line 133
    sget-object p1, Ltechnology/cariad/cat/genx/Channel;->HANDSHAKE:Ltechnology/cariad/cat/genx/Channel;

    .line 134
    .line 135
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z

    .line 136
    .line 137
    .line 138
    move-result p1

    .line 139
    if-eqz p1, :cond_3

    .line 140
    .line 141
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 142
    .line 143
    const/4 p1, 0x1

    .line 144
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 145
    .line 146
    .line 147
    new-instance v1, Lt51/j;

    .line 148
    .line 149
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v6

    .line 153
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    const-string v2, "GenX"

    .line 158
    .line 159
    const/4 v5, 0x0

    .line 160
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 164
    .line 165
    .line 166
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 167
    .line 168
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$genx_release(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V

    .line 169
    .line 170
    .line 171
    :cond_3
    return-void
.end method

.method private static final checkIfHandshakeChannelIsAvailable$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "checkIfHandshakeChannelIsAvailable(): \'"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, "\' channel found -> Setting \'NotificationCallback\'"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final checkIfHandshakeChannelIsAvailable$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    .locals 1

    .line 1
    const-string v0, "<unused var>"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p2, "data"

    .line 7
    .line 8
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-object p2, p3, Lzz0/a;->d:[B

    .line 16
    .line 17
    if-nez p2, :cond_0

    .line 18
    .line 19
    const/4 p2, 0x0

    .line 20
    new-array p2, p2, [B

    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDataReceived$genx_release(Ltechnology/cariad/cat/genx/Channel;[B)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method private static final checkIfHandshakeChannelIsAvailable$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "checkIfHandshakeChannelIsAvailable(): Channel \'"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string p0, "\' should be discovered -> Enabling notifications if not enabled"

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method private static final checkIfHandshakeChannelIsAvailable$lambda$1$0()Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Channel;->HANDSHAKE:Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "checkIfHandshakeChannelIsAvailable(): \'"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v0, "\' channel not found"

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    return-object v0
.end method

.method private static final checkIfHandshakeChannelIsAvailable$lambda$2()Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Channel;->HANDSHAKE:Ltechnology/cariad/cat/genx/Channel;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "checkIfHandshakeChannelIsAvailable(): Channel \'"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v0, "\' already found -> Enabling notifications if not enabled"

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    return-object v0
.end method

.method private static final close$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "close() - device = "

    .line 10
    .line 11
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->close$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfHandshakeChannelIsAvailable$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->log$lambda$5(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfDataChannelIsAvailable$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic i(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->log$lambda$1(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final initialize$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "initialize() - device = "

    .line 10
    .line 11
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final initialize$lambda$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 7
    .line 8
    const/4 p1, 0x4

    .line 9
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method private static final initialize$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onConnectionPriorityRequested(): Successfully requested high connection priority"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final initialize$lambda$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 2

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p2, p1, v1}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(ILandroid/os/Parcelable;I)V

    .line 10
    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    const-string p2, "GenX"

    .line 14
    .line 15
    invoke-static {p0, p2, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method private static final initialize$lambda$2$0(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getFailReasonDescription(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "onMtuChanged(): Failed to request high connection priority with status = "

    .line 13
    .line 14
    const-string v1, " - device = "

    .line 15
    .line 16
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final initialize$lambda$3(ILtechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 7

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p4, p0}, Ljava/lang/Math;->min(II)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    add-int/lit8 p0, p0, -0x5

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->setCurrentUsableMtu(I)V

    .line 13
    .line 14
    .line 15
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/r;

    .line 16
    .line 17
    invoke-direct {v3, p4, p0, p3}, Ltechnology/cariad/cat/genx/bluetooth/r;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lt51/j;

    .line 21
    .line 22
    invoke-static {p2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    const-string p0, "getName(...)"

    .line 27
    .line 28
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    const-string v1, "GenX"

    .line 33
    .line 34
    sget-object v2, Lt51/f;->a:Lt51/f;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method private static final initialize$lambda$3$0(IILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p2

    .line 8
    const-string v0, " - Used MTU = "

    .line 9
    .line 10
    const-string v1, "  - device = "

    .line 11
    .line 12
    const-string v2, "onMtuChanged(): Received MTU = "

    .line 13
    .line 14
    invoke-static {p0, p1, v2, v0, v1}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method private static final initialize$lambda$4(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {v4, p2, p1, v0}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(ILandroid/os/Parcelable;I)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p1, "getName(...)"

    .line 19
    .line 20
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->disconnect()Lno/nordicsemi/android/ble/a0;

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method private static final initialize$lambda$4$0(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getFailReasonDescription(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "onMtuChanged(): Failed with status = "

    .line 13
    .line 14
    const-string v1, ". -> Disconnect - device = "

    .line 15
    .line 16
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final isRequiredServiceSupported$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "isRequiredServiceSupported() - device = "

    .line 10
    .line 11
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic j(IILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$3$0(IILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->log$lambda$2(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->onServicesInvalidated$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final log$lambda$0(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, " - device = "

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final log$lambda$1(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, " - device = "

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final log$lambda$2(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, " - device = "

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final log$lambda$3(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, " - device = "

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final log$lambda$4(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, " - device = "

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final log$lambda$5(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, " - device = "

    .line 10
    .line 11
    invoke-static {p0, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic m()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfDataChannelIsAvailable$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic n()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfDataChannelIsAvailable$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic o(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$2$0(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onServicesInvalidated$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "onServicesInvalidated() - device = "

    .line 10
    .line 11
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic p(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfHandshakeChannelIsAvailable$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic q(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfDataChannelIsAvailable$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfHandshakeChannelIsAvailable$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic s()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final shouldDiscoverChannel(Ltechnology/cariad/cat/genx/Channel;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->channelToDiscover:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public static synthetic t(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic u(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$4$0(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic v(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->log$lambda$3(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic w(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfHandshakeChannelIsAvailable$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic x(ILtechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$3(ILtechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic y(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->log$lambda$4(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic z(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->initialize$lambda$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;Landroid/bluetooth/BluetoothDevice;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final channelConfig(Ltechnology/cariad/cat/genx/Channel;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p1, -0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    sget-object v0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    aget p1, v0, p1

    .line 12
    .line 13
    :goto_0
    const/4 v0, 0x1

    .line 14
    if-eq p1, v0, :cond_2

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-eq p1, v0, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    return-object p0

    .line 21
    :cond_1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 25
    .line 26
    return-object p0
.end method

.method public close()V
    .locals 8

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-direct {v4, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lt51/j;

    .line 10
    .line 11
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    const-string v0, "getName(...)"

    .line 16
    .line 17
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v7

    .line 21
    const-string v2, "GenX"

    .line 22
    .line 23
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move-object v0, v1

    .line 43
    :goto_0
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/e;->removeNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    move-object v0, v1

    .line 56
    :goto_1
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/e;->removeNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 57
    .line 58
    .line 59
    iput-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 60
    .line 61
    iput-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 62
    .line 63
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->channelToDiscover:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->clear()V

    .line 66
    .line 67
    .line 68
    invoke-super {p0}, Lno/nordicsemi/android/ble/e;->close()V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final discoverChannel(Ltechnology/cariad/cat/genx/Channel;)V
    .locals 1

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->channelToDiscover:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final enableNotifications(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Lno/nordicsemi/android/ble/v0;
    .locals 1

    .line 1
    const-string v0, "channelConfig"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/e;->enableNotifications(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/v0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string p1, "enableNotifications(...)"

    .line 15
    .line 16
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object p0
.end method

.method public final getDataConfig()Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getHandshakeConfig()Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMinLogPriority()I
    .locals 0

    .line 1
    const/4 p0, 0x2

    .line 2
    return p0
.end method

.method public initialize()V
    .locals 8

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v4, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lt51/j;

    .line 10
    .line 11
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    const-string v0, "getName(...)"

    .line 16
    .line 17
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v7

    .line 21
    const-string v2, "GenX"

    .line 22
    .line 23
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x1

    .line 33
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/e;->requestConnectionPriority(I)Lno/nordicsemi/android/ble/z;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/p;

    .line 38
    .line 39
    const/4 v3, 0x0

    .line 40
    invoke-direct {v2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/p;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;I)V

    .line 41
    .line 42
    .line 43
    iput-object v2, v1, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 44
    .line 45
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/p;

    .line 46
    .line 47
    const/4 v3, 0x1

    .line 48
    invoke-direct {v2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/p;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;I)V

    .line 49
    .line 50
    .line 51
    iput-object v2, v1, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 52
    .line 53
    iget-object v2, v1, Lno/nordicsemi/android/ble/i0;->a:Lno/nordicsemi/android/ble/d;

    .line 54
    .line 55
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    iget-boolean v3, v1, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 59
    .line 60
    if-nez v3, :cond_1

    .line 61
    .line 62
    iget-boolean v3, v2, Lno/nordicsemi/android/ble/d;->h:Z

    .line 63
    .line 64
    if-eqz v3, :cond_0

    .line 65
    .line 66
    iget-object v3, v2, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 67
    .line 68
    if-eqz v3, :cond_0

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    iget-object v3, v2, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 72
    .line 73
    :goto_0
    invoke-interface {v3, v1}, Ljava/util/Deque;->add(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    iput-boolean v0, v1, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 77
    .line 78
    :cond_1
    const/4 v1, 0x0

    .line 79
    invoke-virtual {v2, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 80
    .line 81
    .line 82
    sget-object v2, Ltechnology/cariad/cat/genx/Client;->Companion:Ltechnology/cariad/cat/genx/Client$Companion;

    .line 83
    .line 84
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/Client$Companion;->getMaximumMTUInBytes()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    add-int/lit8 v2, v2, 0x5

    .line 89
    .line 90
    invoke-virtual {p0, v2}, Lno/nordicsemi/android/ble/e;->requestMtu(I)Lno/nordicsemi/android/ble/b0;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    iget-object v4, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 95
    .line 96
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/q;

    .line 97
    .line 98
    invoke-direct {v5, v2, v4, p0}, Ltechnology/cariad/cat/genx/bluetooth/q;-><init>(ILtechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;)V

    .line 99
    .line 100
    .line 101
    iput-object v5, v3, Lno/nordicsemi/android/ble/m0;->m:Ltechnology/cariad/cat/genx/bluetooth/q;

    .line 102
    .line 103
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/p;

    .line 104
    .line 105
    const/4 v4, 0x2

    .line 106
    invoke-direct {v2, p0, v4}, Ltechnology/cariad/cat/genx/bluetooth/p;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;I)V

    .line 107
    .line 108
    .line 109
    iput-object v2, v3, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 110
    .line 111
    iget-object p0, v3, Lno/nordicsemi/android/ble/i0;->a:Lno/nordicsemi/android/ble/d;

    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    iget-boolean v2, v3, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 117
    .line 118
    if-nez v2, :cond_3

    .line 119
    .line 120
    iget-boolean v2, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 121
    .line 122
    if-eqz v2, :cond_2

    .line 123
    .line 124
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 125
    .line 126
    if-eqz v2, :cond_2

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_2
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 130
    .line 131
    :goto_1
    invoke-interface {v2, v3}, Ljava/util/Deque;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    iput-boolean v0, v3, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 135
    .line 136
    :cond_3
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 137
    .line 138
    .line 139
    return-void
.end method

.method public isRequiredServiceSupported(Landroid/bluetooth/BluetoothGatt;)Z
    .locals 8

    .line 1
    const-string v0, "gatt"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 7
    .line 8
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    invoke-direct {v4, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Lt51/j;

    .line 15
    .line 16
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v0, "getName(...)"

    .line 21
    .line 22
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    const-string v2, "GenX"

    .line 27
    .line 28
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 38
    .line 39
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getServiceID$genx_release()Ljava/util/UUID;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {p1, v0}, Landroid/bluetooth/BluetoothGatt;->getService(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattService;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-eqz p1, :cond_0

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfHandshakeChannelIsAvailable(Landroid/bluetooth/BluetoothGattService;)V

    .line 50
    .line 51
    .line 52
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->checkIfDataChannelIsAvailable(Landroid/bluetooth/BluetoothGattService;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 56
    .line 57
    if-nez p1, :cond_2

    .line 58
    .line 59
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 60
    .line 61
    if-eqz p0, :cond_1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    const/4 p0, 0x0

    .line 65
    return p0

    .line 66
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 67
    return p0
.end method

.method public log(ILjava/lang/String;)V
    .locals 4

    .line 1
    const-string v0, "message"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "GenX_Nordic"

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq p1, v2, :cond_4

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    if-eq p1, v3, :cond_3

    .line 14
    .line 15
    const/4 v3, 0x4

    .line 16
    if-eq p1, v3, :cond_2

    .line 17
    .line 18
    const/4 v3, 0x5

    .line 19
    if-eq p1, v3, :cond_1

    .line 20
    .line 21
    const/4 v3, 0x6

    .line 22
    if-eq p1, v3, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 25
    .line 26
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/j;

    .line 27
    .line 28
    const/4 v3, 0x5

    .line 29
    invoke-direct {p1, p2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/j;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 30
    .line 31
    .line 32
    invoke-static {v0, v1, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn$default(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 37
    .line 38
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/j;

    .line 39
    .line 40
    const/4 v3, 0x4

    .line 41
    invoke-direct {p1, p2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/j;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v0, v1, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logError$default(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 49
    .line 50
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/j;

    .line 51
    .line 52
    const/4 v3, 0x3

    .line 53
    invoke-direct {p1, p2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/j;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, v1, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn$default(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 61
    .line 62
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/j;

    .line 63
    .line 64
    const/4 v3, 0x2

    .line 65
    invoke-direct {p1, p2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/j;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 66
    .line 67
    .line 68
    invoke-static {v0, v1, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logDebug$default(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 73
    .line 74
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/j;

    .line 75
    .line 76
    const/4 v3, 0x1

    .line 77
    invoke-direct {p1, p2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/j;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 78
    .line 79
    .line 80
    invoke-static {v0, v1, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logDebug$default(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_4
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 85
    .line 86
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/j;

    .line 87
    .line 88
    const/4 v3, 0x0

    .line 89
    invoke-direct {p1, p2, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/j;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 90
    .line 91
    .line 92
    invoke-static {v0, v1, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logVerbose$default(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method public onServicesInvalidated()V
    .locals 8

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->this$0:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;

    .line 2
    .line 3
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    invoke-direct {v4, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lt51/j;

    .line 10
    .line 11
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    const-string v0, "getName(...)"

    .line 16
    .line 17
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v7

    .line 21
    const-string v2, "GenX"

    .line 22
    .line 23
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move-object v0, v1

    .line 43
    :goto_0
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/e;->removeNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    move-object v0, v1

    .line 56
    :goto_1
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/e;->removeNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 57
    .line 58
    .line 59
    iput-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 60
    .line 61
    iput-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 62
    .line 63
    return-void
.end method

.method public final sendData(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;[B)Lno/nordicsemi/android/ble/v0;
    .locals 1

    .line 1
    const-string v0, "channelConfig"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "data"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getWriteCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const/4 v0, 0x1

    .line 16
    invoke-virtual {p0, p1, p2, v0}, Lno/nordicsemi/android/ble/e;->writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;[BI)Lno/nordicsemi/android/ble/v0;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const-string p1, "writeCharacteristic(...)"

    .line 21
    .line 22
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object p0
.end method

.method public final setDataConfig(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->dataConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 2
    .line 3
    return-void
.end method

.method public final setHandshakeConfig(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->handshakeConfig:Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 2
    .line 3
    return-void
.end method
