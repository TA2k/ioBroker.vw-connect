.class public final Lno/nordicsemi/android/ble/s0;
.super Lno/nordicsemi/android/ble/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V
    .locals 1

    const/16 v0, 0x16

    .line 1
    invoke-direct {p0, v0, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    .line 2
    invoke-static {p2, p3, p4}, Ljp/ta;->a([BII)[B

    return-void
.end method

.method public constructor <init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V
    .locals 1

    const/16 v0, 0x16

    .line 3
    invoke-direct {p0, v0, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V

    .line 4
    invoke-static {p2, p3, p4}, Ljp/ta;->a([BII)[B

    return-void
.end method


# virtual methods
.method public final d(Landroid/bluetooth/BluetoothDevice;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    new-instance v1, Lno/nordicsemi/android/ble/y;

    .line 4
    .line 5
    invoke-direct {v1, p0, p1}, Lno/nordicsemi/android/ble/y;-><init>(Lno/nordicsemi/android/ble/s0;Landroid/bluetooth/BluetoothDevice;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 9
    .line 10
    .line 11
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public final e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 2
    .line 3
    .line 4
    return-object p0
.end method
