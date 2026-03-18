.class public final Lno/nordicsemi/android/ble/k0;
.super Lno/nordicsemi/android/ble/l0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final m:[B

.field public final n:Z


# direct methods
.method public constructor <init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BII)V
    .locals 1

    const/16 v0, 0x19

    .line 1
    invoke-direct {p0, v0, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    const/4 p1, 0x1

    .line 2
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/k0;->n:Z

    .line 3
    invoke-static {p2, p3, p4}, Ljp/ta;->a([BII)[B

    move-result-object p1

    iput-object p1, p0, Lno/nordicsemi/android/ble/k0;->m:[B

    return-void
.end method

.method public constructor <init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V
    .locals 1

    const/16 v0, 0x1a

    .line 4
    invoke-direct {p0, v0, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V

    const/4 p1, 0x1

    .line 5
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/k0;->n:Z

    .line 6
    invoke-static {p2, p3, p4}, Ljp/ta;->a([BII)[B

    move-result-object p1

    iput-object p1, p0, Lno/nordicsemi/android/ble/k0;->m:[B

    return-void
.end method


# virtual methods
.method public final e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final f(Lno/nordicsemi/android/ble/d;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 2
    .line 3
    .line 4
    return-void
.end method
