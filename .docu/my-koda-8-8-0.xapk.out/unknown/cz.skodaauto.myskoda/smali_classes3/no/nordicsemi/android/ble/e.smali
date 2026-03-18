.class public abstract Lno/nordicsemi/android/ble/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final BATTERY_LEVEL_CHARACTERISTIC:Ljava/util/UUID;

.field static final BATTERY_SERVICE:Ljava/util/UUID;

.field static final CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

.field static final GENERIC_ATTRIBUTE_SERVICE:Ljava/util/UUID;

.field public static final PAIRING_VARIANT_CONSENT:I = 0x3

.field public static final PAIRING_VARIANT_DISPLAY_PASSKEY:I = 0x4

.field public static final PAIRING_VARIANT_DISPLAY_PIN:I = 0x5

.field public static final PAIRING_VARIANT_OOB_CONSENT:I = 0x6

.field public static final PAIRING_VARIANT_PASSKEY:I = 0x1

.field public static final PAIRING_VARIANT_PASSKEY_CONFIRMATION:I = 0x2

.field public static final PAIRING_VARIANT_PIN:I

.field static final SERVICE_CHANGED_CHARACTERISTIC:Ljava/util/UUID;


# instance fields
.field bondingObserver:Lb01/a;

.field protected callbacks:Lno/nordicsemi/android/ble/f;
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end field

.field connectionObserver:Lb01/b;

.field private final context:Landroid/content/Context;

.field private final mPairingRequestBroadcastReceiver:Landroid/content/BroadcastReceiver;

.field final requestHandler:Lno/nordicsemi/android/ble/d;

.field private serverManager:Lno/nordicsemi/android/ble/u;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "00002902-0000-1000-8000-00805f9b34fb"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lno/nordicsemi/android/ble/e;->CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

    .line 8
    .line 9
    const-string v0, "0000180F-0000-1000-8000-00805f9b34fb"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lno/nordicsemi/android/ble/e;->BATTERY_SERVICE:Ljava/util/UUID;

    .line 16
    .line 17
    const-string v0, "00002A19-0000-1000-8000-00805f9b34fb"

    .line 18
    .line 19
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lno/nordicsemi/android/ble/e;->BATTERY_LEVEL_CHARACTERISTIC:Ljava/util/UUID;

    .line 24
    .line 25
    const-string v0, "00001801-0000-1000-8000-00805f9b34fb"

    .line 26
    .line 27
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lno/nordicsemi/android/ble/e;->GENERIC_ATTRIBUTE_SERVICE:Ljava/util/UUID;

    .line 32
    .line 33
    const-string v0, "00002A05-0000-1000-8000-00805f9b34fb"

    .line 34
    .line 35
    invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sput-object v0, Lno/nordicsemi/android/ble/e;->SERVICE_CHANGED_CHARACTERISTIC:Ljava/util/UUID;

    .line 40
    .line 41
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Handler;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lno/nordicsemi/android/ble/l;

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    invoke-direct {v0, p0, v1}, Lno/nordicsemi/android/ble/l;-><init>(Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lno/nordicsemi/android/ble/e;->mPairingRequestBroadcastReceiver:Landroid/content/BroadcastReceiver;

    .line 11
    .line 12
    iput-object p1, p0, Lno/nordicsemi/android/ble/e;->context:Landroid/content/Context;

    .line 13
    .line 14
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->getGattCallback()Lno/nordicsemi/android/ble/d;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iput-object v1, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 19
    .line 20
    iput-object p0, v1, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 21
    .line 22
    iput-object p2, v1, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 23
    .line 24
    new-instance p0, Landroid/content/IntentFilter;

    .line 25
    .line 26
    const-string p2, "android.bluetooth.device.action.PAIRING_REQUEST"

    .line 27
    .line 28
    invoke-direct {p0, p2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const/4 p2, 0x2

    .line 32
    invoke-static {p1, v0, p0, p2}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    .line 33
    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public attachClientConnection(Landroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 4
    .line 5
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v0, 0x6

    .line 10
    if-lt v0, p1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 13
    .line 14
    const-string p1, "Server not bound to the manager"

    .line 15
    .line 16
    invoke-virtual {p0, v0, p1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public beginAtomicRequestQueue()Lno/nordicsemi/android/ble/j0;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/j0;

    .line 2
    .line 3
    invoke-direct {v0}, Lno/nordicsemi/android/ble/j0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public beginReliableWrite()Lno/nordicsemi/android/ble/g0;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/g0;

    .line 2
    .line 3
    invoke-direct {v0}, Lno/nordicsemi/android/ble/j0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public final cancelQueue()V
    .locals 7

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    const/4 v0, -0x7

    .line 4
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 9
    .line 10
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    iget-boolean v3, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 16
    .line 17
    const/4 v4, 0x5

    .line 18
    const/4 v5, 0x0

    .line 19
    if-eqz v3, :cond_8

    .line 20
    .line 21
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 22
    .line 23
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-lt v4, v3, :cond_1

    .line 28
    .line 29
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 30
    .line 31
    const-string v6, "Request cancelled"

    .line 32
    .line 33
    invoke-virtual {v3, v4, v6}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 37
    .line 38
    instance-of v6, v3, Lno/nordicsemi/android/ble/p0;

    .line 39
    .line 40
    if-eqz v6, :cond_2

    .line 41
    .line 42
    check-cast v3, Lno/nordicsemi/android/ble/p0;

    .line 43
    .line 44
    invoke-virtual {v3, v0, v2}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 48
    .line 49
    if-eqz v3, :cond_3

    .line 50
    .line 51
    invoke-virtual {v3, v0, v2}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 52
    .line 53
    .line 54
    iput-object v5, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 55
    .line 56
    :cond_3
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 57
    .line 58
    instance-of v6, v3, Lno/nordicsemi/android/ble/g0;

    .line 59
    .line 60
    if-eqz v6, :cond_4

    .line 61
    .line 62
    check-cast v3, Lno/nordicsemi/android/ble/g0;

    .line 63
    .line 64
    invoke-virtual {v3, v2}, Lno/nordicsemi/android/ble/j0;->k(Landroid/bluetooth/BluetoothDevice;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_4
    if-eqz v3, :cond_5

    .line 69
    .line 70
    invoke-virtual {v3, v0, v2}, Lno/nordicsemi/android/ble/j0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 71
    .line 72
    .line 73
    iput-object v5, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 74
    .line 75
    :cond_5
    :goto_0
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 76
    .line 77
    if-eqz v3, :cond_6

    .line 78
    .line 79
    iget-boolean v3, v3, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 80
    .line 81
    if-eqz v3, :cond_7

    .line 82
    .line 83
    :cond_6
    const/4 v1, 0x1

    .line 84
    :cond_7
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 85
    .line 86
    .line 87
    :cond_8
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 88
    .line 89
    if-eqz v1, :cond_9

    .line 90
    .line 91
    invoke-virtual {v1, v0, v2}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 92
    .line 93
    .line 94
    iput-object v5, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 95
    .line 96
    invoke-virtual {p0, v4}, Lno/nordicsemi/android/ble/d;->o(I)V

    .line 97
    .line 98
    .line 99
    :cond_9
    :goto_1
    return-void
.end method

.method public close()V
    .locals 2

    .line 1
    :try_start_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/e;->context:Landroid/content/Context;

    .line 2
    .line 3
    iget-object v1, p0, Lno/nordicsemi/android/ble/e;->mPairingRequestBroadcastReceiver:Landroid/content/BroadcastReceiver;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    .line 8
    :catch_0
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->c()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final closeServer()V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final connect(Landroid/bluetooth/BluetoothDevice;)Lno/nordicsemi/android/ble/x;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/x;

    invoke-direct {v0, p1}, Lno/nordicsemi/android/ble/x;-><init>(Landroid/bluetooth/BluetoothDevice;)V

    .line 2
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->shouldAutoConnect()Z

    move-result p1

    .line 3
    iput-boolean p1, v0, Lno/nordicsemi/android/ble/x;->u:Z

    .line 4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 5
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public final connect(Landroid/bluetooth/BluetoothDevice;I)Lno/nordicsemi/android/ble/x;
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 6
    new-instance v0, Lno/nordicsemi/android/ble/x;

    invoke-direct {v0, p1}, Lno/nordicsemi/android/ble/x;-><init>(Landroid/bluetooth/BluetoothDevice;)V

    .line 7
    iput p2, v0, Lno/nordicsemi/android/ble/x;->q:I

    .line 8
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->shouldAutoConnect()Z

    move-result p1

    .line 9
    iput-boolean p1, v0, Lno/nordicsemi/android/ble/x;->u:Z

    .line 10
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 11
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public createBond()Lno/nordicsemi/android/ble/i0;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->createBondInsecure()Lno/nordicsemi/android/ble/i0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public createBondInsecure()Lno/nordicsemi/android/ble/i0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/l0;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public disableBatteryLevelNotifications()V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    .line 2
    .line 3
    const/16 v1, 0x1d

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Lno/nordicsemi/android/ble/b;

    .line 15
    .line 16
    const/4 v2, 0x4

    .line 17
    invoke-direct {v1, p0, v2}, Lno/nordicsemi/android/ble/b;-><init>(Lno/nordicsemi/android/ble/e;I)V

    .line 18
    .line 19
    .line 20
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 21
    .line 22
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public disableIndications(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/v0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public disableNotifications(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/v0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final disconnect()Lno/nordicsemi/android/ble/a0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/a0;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public enableBatteryLevelNotifications()V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Lno/nordicsemi/android/ble/b;

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    invoke-direct {v1, p0, v2}, Lno/nordicsemi/android/ble/b;-><init>(Lno/nordicsemi/android/ble/e;I)V

    .line 18
    .line 19
    .line 20
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->f:Lno/nordicsemi/android/ble/b;

    .line 21
    .line 22
    new-instance v1, Lno/nordicsemi/android/ble/b;

    .line 23
    .line 24
    const/4 v2, 0x3

    .line 25
    invoke-direct {v1, p0, v2}, Lno/nordicsemi/android/ble/b;-><init>(Lno/nordicsemi/android/ble/e;I)V

    .line 26
    .line 27
    .line 28
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 29
    .line 30
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public enableIndications(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/v0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public enableNotifications(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/v0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final enqueue(Lno/nordicsemi/android/ble/i0;)V
    .locals 1
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p1, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 20
    .line 21
    :goto_0
    invoke-interface {v0, p1}, Ljava/util/Deque;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    iput-boolean v0, p1, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 26
    .line 27
    :cond_1
    const/4 p1, 0x0

    .line 28
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public ensureBond()Lno/nordicsemi/android/ble/i0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/l0;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final getBatteryValue()I
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget p0, p0, Lno/nordicsemi/android/ble/d;->x:I

    .line 4
    .line 5
    return p0
.end method

.method public getBluetoothDevice()Landroid/bluetooth/BluetoothDevice;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 4
    .line 5
    return-object p0
.end method

.method public final getBondingObserver()Lb01/a;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final getConnectionObserver()Lb01/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->connectionObserver:Lb01/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConnectionState()I
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget p0, p0, Lno/nordicsemi/android/ble/d;->s:I

    .line 4
    .line 5
    return p0
.end method

.method public final getContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGattCallback()Lno/nordicsemi/android/ble/d;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance p0, Lno/nordicsemi/android/ble/c;

    .line 2
    .line 3
    invoke-direct {p0}, Lno/nordicsemi/android/ble/d;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public abstract getMinLogPriority()I
.end method

.method public getMtu()I
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget p0, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 4
    .line 5
    return p0
.end method

.method public getServiceDiscoveryDelay(Z)I
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const/16 p0, 0x640

    .line 4
    .line 5
    return p0

    .line 6
    :cond_0
    const/16 p0, 0x12c

    .line 7
    .line 8
    return p0
.end method

.method public abstract initialize()V
.end method

.method public final isBonded()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    const/16 v0, 0xc

    .line 12
    .line 13
    if-ne p0, v0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final isConnected()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 4
    .line 5
    return p0
.end method

.method public isOptionalServiceSupported(Landroid/bluetooth/BluetoothGatt;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0
.end method

.method public final isReady()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/d;->o:Z

    .line 4
    .line 5
    return p0
.end method

.method public final isReliableWriteInProgress()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/d;->u:Z

    .line 4
    .line 5
    return p0
.end method

.method public abstract isRequiredServiceSupported(Landroid/bluetooth/BluetoothGatt;)Z
.end method

.method public varargs log(II[Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/e;->context:Landroid/content/Context;

    invoke-virtual {v0, p2, p3}, Landroid/content/Context;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    .line 2
    invoke-virtual {p0, p1, p2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    return-void
.end method

.method public abstract log(ILjava/lang/String;)V
.end method

.method public onDeviceReady()V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onManagerReady()V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onPairingRequestReceived(Landroid/bluetooth/BluetoothDevice;II)V
    .locals 0

    .line 1
    return-void
.end method

.method public onServerReady(Landroid/bluetooth/BluetoothGattServer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public abstract onServicesInvalidated()V
.end method

.method public overrideMtu(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x203

    .line 7
    .line 8
    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iput p1, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 13
    .line 14
    return-void
.end method

.method public readBatteryLevel()V
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/e0;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iput-boolean v1, v0, Lno/nordicsemi/android/ble/e0;->q:Z

    .line 10
    .line 11
    iget-object v1, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    new-instance v1, Lno/nordicsemi/android/ble/j;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-direct {v1, p0, v2}, Lno/nordicsemi/android/ble/j;-><init>(Lno/nordicsemi/android/ble/d;I)V

    .line 25
    .line 26
    .line 27
    iput-object v1, v0, Lno/nordicsemi/android/ble/q0;->p:Lno/nordicsemi/android/ble/j;

    .line 28
    .line 29
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public readCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/e0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/e0;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-boolean p1, v0, Lno/nordicsemi/android/ble/e0;->q:Z

    .line 10
    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public readDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;)Lno/nordicsemi/android/ble/e0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/e0;

    .line 2
    .line 3
    const/16 v1, 0xc

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V

    .line 6
    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-boolean p1, v0, Lno/nordicsemi/android/ble/e0;->q:Z

    .line 10
    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public readPhy()Lno/nordicsemi/android/ble/c0;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/c0;

    .line 2
    .line 3
    invoke-direct {v0}, Lno/nordicsemi/android/ble/c0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/c0;->f(Lno/nordicsemi/android/ble/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public readRssi()Lno/nordicsemi/android/ble/f0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/f0;

    .line 2
    .line 3
    const/16 v1, 0x23

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/f0;->f(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public refreshDeviceCache()Lno/nordicsemi/android/ble/i0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/l0;

    .line 2
    .line 3
    const/16 v1, 0x24

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public removeBond()Lno/nordicsemi/android/ble/i0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/l0;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public removeIndicationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/e;->removeNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public removeNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->F(Landroid/os/Parcelable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public removeWriteCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->F(Landroid/os/Parcelable;)V

    return-void
.end method

.method public removeWriteCallback(Landroid/bluetooth/BluetoothGattDescriptor;)V
    .locals 0

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->F(Landroid/os/Parcelable;)V

    return-void
.end method

.method public requestConnectionPriority(I)Lno/nordicsemi/android/ble/z;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/z;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lno/nordicsemi/android/ble/z;-><init>(I)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/z;->f(Lno/nordicsemi/android/ble/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public requestMtu(I)Lno/nordicsemi/android/ble/b0;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/b0;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lno/nordicsemi/android/ble/b0;-><init>(I)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/b0;->f(Lno/nordicsemi/android/ble/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public runOnCallbackThread(Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public sendIndication(Landroid/bluetooth/BluetoothGattCharacteristic;Lzz0/a;)Lno/nordicsemi/android/ble/v0;
    .locals 6

    if-eqz p2, :cond_0

    .line 1
    iget-object p2, p2, Lzz0/a;->d:[B

    :goto_0
    move-object v3, p2

    goto :goto_1

    :cond_0
    const/4 p2, 0x0

    goto :goto_0

    .line 2
    :goto_1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz v3, :cond_1

    .line 3
    array-length p2, v3

    :goto_2
    move v5, p2

    goto :goto_3

    :cond_1
    const/4 p2, 0x0

    goto :goto_2

    :goto_3
    const/16 v1, 0x9

    const/4 v4, 0x0

    move-object v2, p1

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 5
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public sendIndication(Landroid/bluetooth/BluetoothGattCharacteristic;[B)Lno/nordicsemi/android/ble/v0;
    .locals 6

    .line 6
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz p2, :cond_0

    .line 7
    array-length v1, p2

    :goto_0
    move v5, v1

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    goto :goto_0

    :goto_1
    const/16 v1, 0x9

    const/4 v4, 0x0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public sendIndication(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)Lno/nordicsemi/android/ble/v0;
    .locals 6

    .line 10
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    const/16 v1, 0x9

    move-object v2, p1

    move-object v3, p2

    move v4, p3

    move v5, p4

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public sendNotification(Landroid/bluetooth/BluetoothGattCharacteristic;Lzz0/a;)Lno/nordicsemi/android/ble/v0;
    .locals 6

    if-eqz p2, :cond_0

    .line 1
    iget-object p2, p2, Lzz0/a;->d:[B

    :goto_0
    move-object v3, p2

    goto :goto_1

    :cond_0
    const/4 p2, 0x0

    goto :goto_0

    .line 2
    :goto_1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz v3, :cond_1

    .line 3
    array-length p2, v3

    :goto_2
    move v5, p2

    goto :goto_3

    :cond_1
    const/4 p2, 0x0

    goto :goto_2

    :goto_3
    const/16 v1, 0x8

    const/4 v4, 0x0

    move-object v2, p1

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 5
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public sendNotification(Landroid/bluetooth/BluetoothGattCharacteristic;[B)Lno/nordicsemi/android/ble/v0;
    .locals 6

    .line 6
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz p2, :cond_0

    .line 7
    array-length v1, p2

    :goto_0
    move v5, v1

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    goto :goto_0

    :goto_1
    const/16 v1, 0x8

    const/4 v4, 0x0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public sendNotification(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)Lno/nordicsemi/android/ble/v0;
    .locals 6

    .line 10
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    const/16 v1, 0x8

    move-object v2, p1

    move-object v3, p2

    move v4, p3

    move v5, p4

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public final setBondingObserver(Lb01/a;)V
    .locals 0

    .line 1
    return-void
.end method

.method public setCharacteristicValue(Landroid/bluetooth/BluetoothGattCharacteristic;Lzz0/a;)Lno/nordicsemi/android/ble/k0;
    .locals 3

    if-eqz p2, :cond_0

    .line 1
    iget-object p2, p2, Lzz0/a;->d:[B

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    .line 2
    :goto_0
    new-instance v0, Lno/nordicsemi/android/ble/k0;

    const/4 v1, 0x0

    if-eqz p2, :cond_1

    .line 3
    array-length v2, p2

    goto :goto_1

    :cond_1
    move v2, v1

    :goto_1
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/k0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 5
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/k0;->f(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public setCharacteristicValue(Landroid/bluetooth/BluetoothGattCharacteristic;[B)Lno/nordicsemi/android/ble/k0;
    .locals 3

    .line 6
    new-instance v0, Lno/nordicsemi/android/ble/k0;

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    .line 7
    array-length v2, p2

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/k0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/k0;->f(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public setCharacteristicValue(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)Lno/nordicsemi/android/ble/k0;
    .locals 1

    .line 10
    new-instance v0, Lno/nordicsemi/android/ble/k0;

    invoke-direct {v0, p1, p2, p3, p4}, Lno/nordicsemi/android/ble/k0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/k0;->f(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public setCharacteristicValue(Landroid/bluetooth/BluetoothGattCharacteristic;Lzz0/b;)V
    .locals 0

    .line 13
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 14
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->C:Ljava/util/HashMap;

    if-nez p1, :cond_0

    return-void

    :cond_0
    if-nez p2, :cond_1

    .line 15
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    .line 16
    :cond_1
    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final setConnectionObserver(Lb01/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/nordicsemi/android/ble/e;->connectionObserver:Lb01/b;

    .line 2
    .line 3
    return-void
.end method

.method public setConnectionParametersListener(Lyz0/a;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-eqz p1, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget p0, p0, Lno/nordicsemi/android/ble/d;->w:I

    .line 10
    .line 11
    if-lez p0, :cond_0

    .line 12
    .line 13
    invoke-interface {p1}, Lyz0/a;->a()V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void

    .line 17
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public setDescriptorValue(Landroid/bluetooth/BluetoothGattDescriptor;Lzz0/a;)Lno/nordicsemi/android/ble/k0;
    .locals 3

    if-eqz p2, :cond_0

    .line 1
    iget-object p2, p2, Lzz0/a;->d:[B

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    .line 2
    :goto_0
    new-instance v0, Lno/nordicsemi/android/ble/k0;

    const/4 v1, 0x0

    if-eqz p2, :cond_1

    .line 3
    array-length v2, p2

    goto :goto_1

    :cond_1
    move v2, v1

    :goto_1
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/k0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 5
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/k0;->f(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public setDescriptorValue(Landroid/bluetooth/BluetoothGattDescriptor;[B)Lno/nordicsemi/android/ble/k0;
    .locals 3

    .line 6
    new-instance v0, Lno/nordicsemi/android/ble/k0;

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    .line 7
    array-length v2, p2

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/k0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/k0;->f(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public setDescriptorValue(Landroid/bluetooth/BluetoothGattDescriptor;[BII)Lno/nordicsemi/android/ble/k0;
    .locals 1

    .line 10
    new-instance v0, Lno/nordicsemi/android/ble/k0;

    invoke-direct {v0, p1, p2, p3, p4}, Lno/nordicsemi/android/ble/k0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/k0;->f(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public setDescriptorValue(Landroid/bluetooth/BluetoothGattDescriptor;Lzz0/b;)V
    .locals 0

    .line 13
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 14
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->C:Ljava/util/HashMap;

    if-nez p1, :cond_0

    return-void

    :cond_0
    if-nez p2, :cond_1

    .line 15
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    .line 16
    :cond_1
    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public setGattCallbacks(Lno/nordicsemi/android/ble/f;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public setIndicationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/r0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/e;->setNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/r0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public setNotificationCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->i(Landroid/os/Parcelable;)Lno/nordicsemi/android/ble/r0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public setPreferredPhy(III)Lno/nordicsemi/android/ble/c0;
    .locals 1

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/c0;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2, p3}, Lno/nordicsemi/android/ble/c0;-><init>(III)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/c0;->f(Lno/nordicsemi/android/ble/d;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public setWriteCallback(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->i(Landroid/os/Parcelable;)Lno/nordicsemi/android/ble/r0;

    move-result-object p0

    return-object p0
.end method

.method public setWriteCallback(Landroid/bluetooth/BluetoothGattDescriptor;)Lno/nordicsemi/android/ble/r0;
    .locals 0

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->i(Landroid/os/Parcelable;)Lno/nordicsemi/android/ble/r0;

    move-result-object p0

    return-object p0
.end method

.method public shouldAutoConnect()Z
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public shouldClearCacheWhenDisconnected()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public sleep(J)Lno/nordicsemi/android/ble/n0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/n0;

    .line 2
    .line 3
    const/16 v1, 0x25

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    iput-wide p1, v0, Lno/nordicsemi/android/ble/p0;->o:J

    .line 9
    .line 10
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public final useServer(Lno/nordicsemi/android/ble/u;)V
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3
    .line 4
    .line 5
    throw p0
.end method

.method public waitForIndication(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/t0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/t0;

    .line 2
    .line 3
    const/16 v1, 0x15

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/t0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public waitForNotification(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/t0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/t0;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/t0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public waitForRead(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/s0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/s0;

    const/16 v1, 0x16

    .line 2
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 4
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForRead(Landroid/bluetooth/BluetoothGattCharacteristic;[B)Lno/nordicsemi/android/ble/s0;
    .locals 3

    .line 5
    new-instance v0, Lno/nordicsemi/android/ble/s0;

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    .line 6
    array-length v2, p2

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/s0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForRead(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)Lno/nordicsemi/android/ble/s0;
    .locals 1

    .line 9
    new-instance v0, Lno/nordicsemi/android/ble/s0;

    invoke-direct {v0, p1, p2, p3, p4}, Lno/nordicsemi/android/ble/s0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V

    .line 10
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 11
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForRead(Landroid/bluetooth/BluetoothGattDescriptor;)Lno/nordicsemi/android/ble/s0;
    .locals 2

    .line 12
    new-instance v0, Lno/nordicsemi/android/ble/s0;

    const/16 v1, 0x16

    .line 13
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V

    .line 14
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 15
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForRead(Landroid/bluetooth/BluetoothGattDescriptor;[B)Lno/nordicsemi/android/ble/s0;
    .locals 3

    .line 16
    new-instance v0, Lno/nordicsemi/android/ble/s0;

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    .line 17
    array-length v2, p2

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/s0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 18
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 19
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForRead(Landroid/bluetooth/BluetoothGattDescriptor;[BII)Lno/nordicsemi/android/ble/s0;
    .locals 1

    .line 20
    new-instance v0, Lno/nordicsemi/android/ble/s0;

    invoke-direct {v0, p1, p2, p3, p4}, Lno/nordicsemi/android/ble/s0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 21
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 22
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForWrite(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/t0;
    .locals 2

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/t0;

    const/16 v1, 0x17

    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/t0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 3
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitForWrite(Landroid/bluetooth/BluetoothGattDescriptor;)Lno/nordicsemi/android/ble/t0;
    .locals 2

    .line 4
    new-instance v0, Lno/nordicsemi/android/ble/t0;

    const/16 v1, 0x17

    .line 5
    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V

    const/4 p1, 0x0

    .line 6
    iput-boolean p1, v0, Lno/nordicsemi/android/ble/t0;->q:Z

    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 8
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitIf(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(TT;",
            "Lno/nordicsemi/android/ble/v;",
            ")",
            "Lno/nordicsemi/android/ble/w;"
        }
    .end annotation

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/w;

    invoke-direct {v0, p1, p2}, Lno/nordicsemi/android/ble/w;-><init>(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)V

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 3
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitIf(Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lno/nordicsemi/android/ble/v;",
            ")",
            "Lno/nordicsemi/android/ble/w;"
        }
    .end annotation

    .line 4
    new-instance v0, Lno/nordicsemi/android/ble/w;

    const/4 v1, 0x0

    invoke-direct {v0, v1, p1}, Lno/nordicsemi/android/ble/w;-><init>(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)V

    .line 5
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 6
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public waitUntil(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(TT;",
            "Lno/nordicsemi/android/ble/v;",
            ")",
            "Lno/nordicsemi/android/ble/w;"
        }
    .end annotation

    .line 3
    invoke-virtual {p0, p1, p2}, Lno/nordicsemi/android/ble/e;->waitIf(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;

    move-result-object p0

    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/w;->s:Z

    return-object p0
.end method

.method public waitUntil(Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lno/nordicsemi/android/ble/v;",
            ")",
            "Lno/nordicsemi/android/ble/w;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/e;->waitIf(Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;

    move-result-object p0

    const/4 p1, 0x1

    .line 2
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/w;->s:Z

    return-object p0
.end method

.method public waitUntilIndicationsEnabled(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/w;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/bluetooth/BluetoothGattCharacteristic;",
            ")",
            "Lno/nordicsemi/android/ble/w;"
        }
    .end annotation

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/b;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Lno/nordicsemi/android/ble/b;-><init>(Lno/nordicsemi/android/ble/e;I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p1, v0}, Lno/nordicsemi/android/ble/e;->waitUntil(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public waitUntilNotificationsEnabled(Landroid/bluetooth/BluetoothGattCharacteristic;)Lno/nordicsemi/android/ble/w;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/bluetooth/BluetoothGattCharacteristic;",
            ")",
            "Lno/nordicsemi/android/ble/w;"
        }
    .end annotation

    .line 1
    new-instance v0, Lno/nordicsemi/android/ble/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lno/nordicsemi/android/ble/b;-><init>(Lno/nordicsemi/android/ble/e;I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, p1, v0}, Lno/nordicsemi/android/ble/e;->waitUntil(Ljava/lang/Object;Lno/nordicsemi/android/ble/v;)Lno/nordicsemi/android/ble/w;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;Lzz0/a;)Lno/nordicsemi/android/ble/v0;
    .locals 6
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    if-eqz p2, :cond_0

    .line 1
    iget-object p2, p2, Lzz0/a;->d:[B

    :goto_0
    move-object v2, p2

    goto :goto_1

    :cond_0
    const/4 p2, 0x0

    goto :goto_0

    .line 2
    :goto_1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz v2, :cond_1

    .line 3
    array-length p2, v2

    :goto_2
    move v4, p2

    goto :goto_3

    :cond_1
    const/4 p2, 0x0

    goto :goto_2

    :goto_3
    if-eqz p1, :cond_2

    .line 4
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getWriteType()I

    move-result p2

    :goto_4
    move v5, p2

    goto :goto_5

    :cond_2
    const/4 p2, 0x2

    goto :goto_4

    :goto_5
    const/4 v3, 0x0

    move-object v1, p1

    .line 5
    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V

    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 7
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;Lzz0/a;I)Lno/nordicsemi/android/ble/v0;
    .locals 6

    if-eqz p2, :cond_0

    .line 8
    iget-object p2, p2, Lzz0/a;->d:[B

    :goto_0
    move-object v2, p2

    goto :goto_1

    :cond_0
    const/4 p2, 0x0

    goto :goto_0

    .line 9
    :goto_1
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz v2, :cond_1

    .line 10
    array-length p2, v2

    :goto_2
    move v4, p2

    goto :goto_3

    :cond_1
    const/4 p2, 0x0

    goto :goto_2

    :goto_3
    const/4 v3, 0x0

    move-object v1, p1

    move v5, p3

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V

    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;[B)Lno/nordicsemi/android/ble/v0;
    .locals 6
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 13
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz p2, :cond_0

    .line 14
    array-length v1, p2

    :goto_0
    move v4, v1

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    goto :goto_0

    :goto_1
    if-eqz p1, :cond_1

    .line 15
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getWriteType()I

    move-result v1

    :goto_2
    move v5, v1

    goto :goto_3

    :cond_1
    const/4 v1, 0x2

    goto :goto_2

    :goto_3
    const/4 v3, 0x0

    move-object v1, p1

    move-object v2, p2

    .line 16
    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V

    .line 17
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 18
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;[BI)Lno/nordicsemi/android/ble/v0;
    .locals 6

    .line 19
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz p2, :cond_0

    .line 20
    array-length v1, p2

    :goto_0
    move v4, v1

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    goto :goto_0

    :goto_1
    const/4 v3, 0x0

    move-object v1, p1

    move-object v2, p2

    move v5, p3

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V

    .line 21
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 22
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)Lno/nordicsemi/android/ble/v0;
    .locals 6
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 23
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    if-eqz p1, :cond_0

    .line 24
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getWriteType()I

    move-result v1

    :goto_0
    move-object v2, p2

    move v3, p3

    move v4, p4

    move v5, v1

    move-object v1, p1

    goto :goto_1

    :cond_0
    const/4 v1, 0x2

    goto :goto_0

    .line 25
    :goto_1
    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V

    .line 26
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 27
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeCharacteristic(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)Lno/nordicsemi/android/ble/v0;
    .locals 6

    .line 28
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move v4, p4

    move v5, p5

    invoke-direct/range {v0 .. v5}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V

    .line 29
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 30
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;Lzz0/a;)Lno/nordicsemi/android/ble/v0;
    .locals 3

    if-eqz p2, :cond_0

    .line 1
    iget-object p2, p2, Lzz0/a;->d:[B

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    .line 2
    :goto_0
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    const/4 v1, 0x0

    if-eqz p2, :cond_1

    .line 3
    array-length v2, p2

    goto :goto_1

    :cond_1
    move v2, v1

    :goto_1
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 5
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;[B)Lno/nordicsemi/android/ble/v0;
    .locals 3

    .line 6
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    const/4 v1, 0x0

    if-eqz p2, :cond_0

    .line 7
    array-length v2, p2

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    invoke-direct {v0, p1, p2, v1, v2}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 9
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method

.method public writeDescriptor(Landroid/bluetooth/BluetoothGattDescriptor;[BII)Lno/nordicsemi/android/ble/v0;
    .locals 1

    .line 10
    new-instance v0, Lno/nordicsemi/android/ble/v0;

    invoke-direct {v0, p1, p2, p3, p4}, Lno/nordicsemi/android/ble/v0;-><init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V

    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 12
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    return-object v0
.end method
