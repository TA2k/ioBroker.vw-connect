.class public final Lno/nordicsemi/android/ble/v0;
.super Lno/nordicsemi/android/ble/q0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final q:[B

.field public final r:I

.field public s:[B

.field public t:I

.field public u:Z


# direct methods
.method public constructor <init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    const/4 p1, 0x0

    .line 2
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->t:I

    const/4 p2, 0x0

    .line 3
    iput-object p2, p0, Lno/nordicsemi/android/ble/v0;->q:[B

    .line 4
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->r:I

    const/4 p1, 0x1

    .line 5
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/v0;->u:Z

    return-void
.end method

.method public constructor <init>(ILandroid/bluetooth/BluetoothGattCharacteristic;[BII)V
    .locals 0

    .line 6
    invoke-direct {p0, p1, p2}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->t:I

    .line 8
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 9
    invoke-static {p3, p4, p5}, Ljp/ta;->a([BII)[B

    move-result-object p2

    iput-object p2, p0, Lno/nordicsemi/android/ble/v0;->q:[B

    .line 10
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->r:I

    return-void
.end method

.method public constructor <init>(Landroid/bluetooth/BluetoothGattCharacteristic;[BIII)V
    .locals 1

    const/4 v0, 0x7

    .line 11
    invoke-direct {p0, v0, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattCharacteristic;)V

    const/4 p1, 0x0

    .line 12
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->t:I

    .line 13
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 14
    invoke-static {p2, p3, p4}, Ljp/ta;->a([BII)[B

    move-result-object p1

    iput-object p1, p0, Lno/nordicsemi/android/ble/v0;->q:[B

    .line 15
    iput p5, p0, Lno/nordicsemi/android/ble/v0;->r:I

    return-void
.end method

.method public constructor <init>(Landroid/bluetooth/BluetoothGattDescriptor;[BII)V
    .locals 1

    const/16 v0, 0xb

    .line 16
    invoke-direct {p0, v0, p1}, Lno/nordicsemi/android/ble/i0;-><init>(ILandroid/bluetooth/BluetoothGattDescriptor;)V

    const/4 p1, 0x0

    .line 17
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->t:I

    .line 18
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 19
    invoke-static {p2, p3, p4}, Ljp/ta;->a([BII)[B

    move-result-object p1

    iput-object p1, p0, Lno/nordicsemi/android/ble/v0;->q:[B

    const/4 p1, 0x2

    .line 20
    iput p1, p0, Lno/nordicsemi/android/ble/v0;->r:I

    return-void
.end method


# virtual methods
.method public final e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final h(Landroid/bluetooth/BluetoothDevice;[B)Z
    .locals 4

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/v0;->t:I

    .line 2
    .line 3
    iget-object v1, p0, Lno/nordicsemi/android/ble/v0;->s:[B

    .line 4
    .line 5
    iget-object v2, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 6
    .line 7
    new-instance v3, Lno/nordicsemi/android/ble/u0;

    .line 8
    .line 9
    invoke-direct {v3, p0, p1, v1, v0}, Lno/nordicsemi/android/ble/u0;-><init>(Lno/nordicsemi/android/ble/v0;Landroid/bluetooth/BluetoothDevice;[BI)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 13
    .line 14
    .line 15
    iget v0, p0, Lno/nordicsemi/android/ble/v0;->t:I

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    add-int/2addr v0, v2

    .line 19
    iput v0, p0, Lno/nordicsemi/android/ble/v0;->t:I

    .line 20
    .line 21
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 26
    .line 27
    new-instance v3, Lno/nordicsemi/android/ble/u0;

    .line 28
    .line 29
    invoke-direct {v3, p0, p1}, Lno/nordicsemi/android/ble/u0;-><init>(Lno/nordicsemi/android/ble/v0;Landroid/bluetooth/BluetoothDevice;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v3}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    :cond_0
    iget p0, p0, Lno/nordicsemi/android/ble/v0;->r:I

    .line 36
    .line 37
    const/4 p1, 0x2

    .line 38
    if-ne p0, p1, :cond_1

    .line 39
    .line 40
    invoke-static {p2, v1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0

    .line 45
    :cond_1
    return v2
.end method
