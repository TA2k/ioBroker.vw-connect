.class Lno/nordicsemi/android/ble/BleManagerHandler$4;
.super Landroid/bluetooth/BluetoothGattCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic b:I


# instance fields
.field public final synthetic a:Lno/nordicsemi/android/ble/d;


# direct methods
.method public constructor <init>(Lno/nordicsemi/android/ble/d;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/bluetooth/BluetoothGattCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onCharacteristicChanged(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getValue()[B

    move-result-object v0

    invoke-virtual {p0, p1, p2, v0}, Lno/nordicsemi/android/ble/BleManagerHandler$4;->onCharacteristicChanged(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;[B)V

    return-void
.end method

.method public final onCharacteristicChanged(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;[B)V
    .locals 8

    const/4 v0, 0x2

    const/4 v1, 0x4

    const/4 v2, 0x1

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    if-eqz p2, :cond_3

    sget-object v3, Lno/nordicsemi/android/ble/e;->SERVICE_CHANGED_CHARACTERISTIC:Ljava/util/UUID;

    .line 3
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    .line 4
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 p3, 0x1e

    if-gt p2, p3, :cond_e

    .line 5
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result p2

    if-lt v1, p2, :cond_0

    .line 7
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    const-string p3, "Service Changed indication received"

    invoke-virtual {p2, v1, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 8
    :cond_0
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 9
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->onServicesInvalidated()V

    const/4 p2, -0x3

    .line 10
    invoke-virtual {p0, p2}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 11
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 12
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 13
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result p2

    if-lt v0, p2, :cond_1

    .line 14
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    const-string p3, "Discovering Services..."

    invoke-virtual {p2, v0, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 15
    :cond_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 16
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result p2

    const/4 p3, 0x3

    if-lt p3, p2, :cond_2

    .line 17
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    const-string p2, "gatt.discoverServices()"

    invoke-virtual {p0, p3, p2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 18
    :cond_2
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->discoverServices()Z

    return-void

    .line 19
    :cond_3
    sget-object v3, Lno/nordicsemi/android/ble/e;->CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

    .line 20
    invoke-virtual {p2, v3}, Landroid/bluetooth/BluetoothGattCharacteristic;->getDescriptor(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattDescriptor;

    move-result-object v3

    .line 21
    const-string v4, ", value: "

    if-eqz v3, :cond_5

    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    move-result-object v5

    if-eqz v5, :cond_5

    .line 22
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    move-result-object v5

    array-length v5, v5

    if-ne v5, v0, :cond_5

    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    move-result-object v0

    const/4 v3, 0x0

    aget-byte v0, v0, v3

    if-ne v0, v2, :cond_4

    goto :goto_0

    .line 23
    :cond_4
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 24
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result v0

    if-lt v1, v0, :cond_6

    .line 25
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 26
    new-instance v3, Ljava/lang/StringBuilder;

    const-string v5, "Indication received from "

    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p3}, Lc01/a;->a([B)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    .line 28
    invoke-virtual {v0, v1, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    goto :goto_1

    .line 29
    :cond_5
    :goto_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 30
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result v0

    if-lt v1, v0, :cond_6

    .line 31
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 32
    new-instance v3, Ljava/lang/StringBuilder;

    const-string v5, "Notification received from "

    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p3}, Lc01/a;->a([B)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    .line 34
    invoke-virtual {v0, v1, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 35
    :cond_6
    :goto_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->D:Lno/nordicsemi/android/ble/r0;

    if-eqz v0, :cond_8

    .line 36
    sget-object v0, Lno/nordicsemi/android/ble/e;->BATTERY_LEVEL_CHARACTERISTIC:Ljava/util/UUID;

    .line 37
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    move-result-object v3

    invoke-virtual {v0, v3}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_8

    .line 38
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->D:Lno/nordicsemi/android/ble/r0;

    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object v3

    .line 39
    iget-object v4, v0, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    if-nez v4, :cond_7

    goto :goto_2

    .line 40
    :cond_7
    new-instance v5, Lzz0/a;

    invoke-direct {v5, p3}, Lzz0/a;-><init>([B)V

    .line 41
    iget-object v0, v0, Lno/nordicsemi/android/ble/r0;->b:Lno/nordicsemi/android/ble/d;

    new-instance v6, Lno/nordicsemi/android/ble/d0;

    const/4 v7, 0x1

    invoke-direct {v6, v4, v3, v5, v7}, Lno/nordicsemi/android/ble/d0;-><init>(Lyz0/b;Landroid/bluetooth/BluetoothDevice;Lzz0/a;I)V

    invoke-virtual {v0, v6}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 42
    :cond_8
    :goto_2
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->B:Ljava/util/HashMap;

    invoke-virtual {v0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lno/nordicsemi/android/ble/r0;

    if-eqz v0, :cond_a

    .line 43
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object v3

    .line 44
    iget-object v4, v0, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    if-nez v4, :cond_9

    goto :goto_3

    .line 45
    :cond_9
    new-instance v5, Lzz0/a;

    invoke-direct {v5, p3}, Lzz0/a;-><init>([B)V

    .line 46
    iget-object v0, v0, Lno/nordicsemi/android/ble/r0;->b:Lno/nordicsemi/android/ble/d;

    new-instance v6, Lno/nordicsemi/android/ble/d0;

    const/4 v7, 0x1

    invoke-direct {v6, v4, v3, v5, v7}, Lno/nordicsemi/android/ble/d0;-><init>(Lyz0/b;Landroid/bluetooth/BluetoothDevice;Lzz0/a;I)V

    invoke-virtual {v0, v6}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 47
    :cond_a
    :goto_3
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    instance-of v3, v0, Lno/nordicsemi/android/ble/t0;

    if-eqz v3, :cond_d

    move-object v3, v0

    check-cast v3, Lno/nordicsemi/android/ble/t0;

    iget-object v0, v0, Lno/nordicsemi/android/ble/i0;->d:Landroid/bluetooth/BluetoothGattCharacteristic;

    if-ne v0, p2, :cond_d

    .line 48
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p2

    .line 49
    iget-object v0, v3, Lno/nordicsemi/android/ble/q0;->p:Lno/nordicsemi/android/ble/j;

    if-nez v0, :cond_b

    .line 50
    iput-boolean v2, v3, Lno/nordicsemi/android/ble/t0;->q:Z

    goto :goto_4

    .line 51
    :cond_b
    iput-boolean v2, v3, Lno/nordicsemi/android/ble/t0;->q:Z

    .line 52
    new-instance v4, Lzz0/a;

    invoke-direct {v4, p3}, Lzz0/a;-><init>([B)V

    .line 53
    iget-object p3, v3, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    new-instance v5, Lno/nordicsemi/android/ble/d0;

    const/4 v6, 0x2

    invoke-direct {v5, v0, p2, v4, v6}, Lno/nordicsemi/android/ble/d0;-><init>(Lyz0/b;Landroid/bluetooth/BluetoothDevice;Lzz0/a;I)V

    invoke-virtual {p3, v5}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 54
    :goto_4
    iget-boolean p2, v3, Lno/nordicsemi/android/ble/t0;->q:Z

    if-eqz p2, :cond_d

    .line 55
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 56
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result p2

    if-lt v1, p2, :cond_c

    .line 57
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    const-string p3, "Wait for value changed complete"

    invoke-virtual {p2, v1, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 58
    :cond_c
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p1

    invoke-virtual {v3, p1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    const/4 p1, 0x0

    .line 59
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 60
    invoke-virtual {p0, v2}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 61
    :cond_d
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    move-result p1

    if-eqz p1, :cond_e

    .line 62
    invoke-virtual {p0, v2}, Lno/nordicsemi/android/ble/d;->A(Z)V

    :cond_e
    return-void
.end method

.method public final onCharacteristicRead(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;I)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getValue()[B

    move-result-object v0

    invoke-virtual {p0, p1, p2, v0, p3}, Lno/nordicsemi/android/ble/BleManagerHandler$4;->onCharacteristicRead(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;[BI)V

    return-void
.end method

.method public final onCharacteristicRead(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;[BI)V
    .locals 5

    const/4 v0, 0x1

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    if-nez p4, :cond_3

    .line 3
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 4
    invoke-virtual {p4}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result p4

    const/4 v1, 0x4

    if-lt v1, p4, :cond_0

    .line 5
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Read Response received from "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    move-result-object p2

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, ", value: "

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    invoke-static {p3}, Lc01/a;->a([B)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    .line 8
    invoke-virtual {p4, v1, p2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 9
    :cond_0
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    instance-of p4, p2, Lno/nordicsemi/android/ble/e0;

    if-eqz p4, :cond_a

    check-cast p2, Lno/nordicsemi/android/ble/e0;

    .line 10
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p4

    .line 11
    iget-object v1, p2, Lno/nordicsemi/android/ble/q0;->p:Lno/nordicsemi/android/ble/j;

    if-nez v1, :cond_1

    .line 12
    iput-boolean v0, p2, Lno/nordicsemi/android/ble/e0;->q:Z

    goto :goto_0

    .line 13
    :cond_1
    iput-boolean v0, p2, Lno/nordicsemi/android/ble/e0;->q:Z

    .line 14
    new-instance v2, Lzz0/a;

    invoke-direct {v2, p3}, Lzz0/a;-><init>([B)V

    .line 15
    iget-object p3, p2, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    new-instance v3, Lno/nordicsemi/android/ble/d0;

    const/4 v4, 0x0

    invoke-direct {v3, v1, p4, v2, v4}, Lno/nordicsemi/android/ble/d0;-><init>(Lyz0/b;Landroid/bluetooth/BluetoothDevice;Lzz0/a;I)V

    invoke-virtual {p3, v3}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 16
    :goto_0
    iget-boolean p3, p2, Lno/nordicsemi/android/ble/e0;->q:Z

    if-nez p3, :cond_2

    iget-boolean p3, p2, Lno/nordicsemi/android/ble/p0;->n:Z

    if-nez p3, :cond_2

    iget-boolean p3, p2, Lno/nordicsemi/android/ble/i0;->k:Z

    if-nez p3, :cond_2

    .line 17
    invoke-virtual {p0, p2}, Lno/nordicsemi/android/ble/d;->g(Lno/nordicsemi/android/ble/i0;)V

    goto/16 :goto_2

    .line 18
    :cond_2
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p1

    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    goto/16 :goto_2

    :cond_3
    const/16 p2, 0x89

    .line 19
    const-string p3, "BleManager"

    if-ne p4, p2, :cond_4

    .line 20
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "Reading failed with status "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p3, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_4
    const/4 p2, 0x5

    if-eq p4, p2, :cond_7

    const/16 v1, 0x8

    if-ne p4, v1, :cond_5

    goto :goto_1

    .line 21
    :cond_5
    const-string p2, "onCharacteristicRead error "

    const-string v1, ", bond state: "

    .line 22
    invoke-static {p2, p4, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    .line 23
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object v1

    invoke-virtual {v1}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    move-result v1

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {p3, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 24
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    instance-of p3, p2, Lno/nordicsemi/android/ble/e0;

    if-eqz p3, :cond_6

    check-cast p2, Lno/nordicsemi/android/ble/e0;

    .line 25
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p3

    invoke-virtual {p2, p4, p3}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    :cond_6
    const/4 p2, 0x0

    .line 26
    iput-object p2, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 27
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    invoke-static {p0, p4}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    goto :goto_2

    .line 28
    :cond_7
    :goto_1
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 29
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result v1

    if-lt p2, v1, :cond_8

    .line 30
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 31
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Authentication required ("

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, ")"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 32
    invoke-virtual {v1, p2, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 33
    :cond_8
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p2

    invoke-virtual {p2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    move-result p2

    const/16 v1, 0xc

    if-ne p2, v1, :cond_9

    .line 34
    const-string p2, "Phone has lost bonding information"

    invoke-static {p3, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 35
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 36
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    :cond_9
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    instance-of p3, p2, Lno/nordicsemi/android/ble/e0;

    if-eqz p3, :cond_a

    check-cast p2, Lno/nordicsemi/android/ble/e0;

    .line 38
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p1

    invoke-virtual {p2, p4, p1}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 39
    :cond_a
    :goto_2
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 40
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->A(Z)V

    return-void
.end method

.method public final onCharacteristicWrite(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattCharacteristic;I)V
    .locals 4

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-nez p3, :cond_3

    .line 4
    .line 5
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    .line 7
    invoke-virtual {p3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    const/4 v0, 0x4

    .line 12
    if-lt v0, p3, :cond_0

    .line 13
    .line 14
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "Data written to "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {p3, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 38
    .line 39
    instance-of v0, p3, Lno/nordicsemi/android/ble/v0;

    .line 40
    .line 41
    if-eqz v0, :cond_a

    .line 42
    .line 43
    check-cast p3, Lno/nordicsemi/android/ble/v0;

    .line 44
    .line 45
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattCharacteristic;->getValue()[B

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-virtual {p3, v0, p2}, Lno/nordicsemi/android/ble/v0;->h(Landroid/bluetooth/BluetoothDevice;[B)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-nez p2, :cond_1

    .line 58
    .line 59
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 60
    .line 61
    instance-of v0, p2, Lno/nordicsemi/android/ble/g0;

    .line 62
    .line 63
    if-eqz v0, :cond_1

    .line 64
    .line 65
    check-cast p2, Lno/nordicsemi/android/ble/g0;

    .line 66
    .line 67
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    const/4 v1, -0x6

    .line 72
    invoke-virtual {p3, v1, v0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/j0;->k(Landroid/bluetooth/BluetoothDevice;)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_1

    .line 83
    .line 84
    :cond_1
    iget-boolean p2, p3, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 85
    .line 86
    if-nez p2, :cond_2

    .line 87
    .line 88
    iget-boolean p2, p3, Lno/nordicsemi/android/ble/p0;->n:Z

    .line 89
    .line 90
    if-nez p2, :cond_2

    .line 91
    .line 92
    iget-boolean p2, p3, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 93
    .line 94
    if-nez p2, :cond_2

    .line 95
    .line 96
    invoke-virtual {p0, p3}, Lno/nordicsemi/android/ble/d;->g(Lno/nordicsemi/android/ble/i0;)V

    .line 97
    .line 98
    .line 99
    goto/16 :goto_1

    .line 100
    .line 101
    :cond_2
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-virtual {p3, p1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 106
    .line 107
    .line 108
    goto/16 :goto_1

    .line 109
    .line 110
    :cond_3
    const/16 p2, 0x89

    .line 111
    .line 112
    const-string v0, "BleManager"

    .line 113
    .line 114
    if-ne p3, p2, :cond_4

    .line 115
    .line 116
    new-instance p0, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    const-string p1, "Writing failed with status "

    .line 119
    .line 120
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 131
    .line 132
    .line 133
    return-void

    .line 134
    :cond_4
    const/4 p2, 0x5

    .line 135
    if-eq p3, p2, :cond_7

    .line 136
    .line 137
    const/16 v1, 0x8

    .line 138
    .line 139
    if-ne p3, v1, :cond_5

    .line 140
    .line 141
    goto :goto_0

    .line 142
    :cond_5
    const-string p2, "onCharacteristicWrite error "

    .line 143
    .line 144
    const-string v1, ", bond state: "

    .line 145
    .line 146
    invoke-static {p2, p3, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p2

    .line 165
    invoke-static {v0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 166
    .line 167
    .line 168
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 169
    .line 170
    instance-of v0, p2, Lno/nordicsemi/android/ble/v0;

    .line 171
    .line 172
    if-eqz v0, :cond_6

    .line 173
    .line 174
    check-cast p2, Lno/nordicsemi/android/ble/v0;

    .line 175
    .line 176
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    invoke-virtual {p2, p3, v0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 181
    .line 182
    .line 183
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 184
    .line 185
    instance-of v0, p2, Lno/nordicsemi/android/ble/g0;

    .line 186
    .line 187
    if-eqz v0, :cond_6

    .line 188
    .line 189
    check-cast p2, Lno/nordicsemi/android/ble/g0;

    .line 190
    .line 191
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    invoke-virtual {p2, v0}, Lno/nordicsemi/android/ble/j0;->k(Landroid/bluetooth/BluetoothDevice;)V

    .line 196
    .line 197
    .line 198
    :cond_6
    const/4 p2, 0x0

    .line 199
    iput-object p2, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 200
    .line 201
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 202
    .line 203
    .line 204
    invoke-static {p0, p3}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    .line 205
    .line 206
    .line 207
    goto :goto_1

    .line 208
    :cond_7
    :goto_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 209
    .line 210
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 211
    .line 212
    .line 213
    move-result v1

    .line 214
    if-lt p2, v1, :cond_8

    .line 215
    .line 216
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 217
    .line 218
    new-instance v2, Ljava/lang/StringBuilder;

    .line 219
    .line 220
    const-string v3, "Authentication required ("

    .line 221
    .line 222
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v2, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 226
    .line 227
    .line 228
    const-string v3, ")"

    .line 229
    .line 230
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 231
    .line 232
    .line 233
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    invoke-virtual {v1, p2, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 238
    .line 239
    .line 240
    :cond_8
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 241
    .line 242
    .line 243
    move-result-object p2

    .line 244
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 245
    .line 246
    .line 247
    move-result p2

    .line 248
    const/16 v1, 0xc

    .line 249
    .line 250
    if-ne p2, v1, :cond_9

    .line 251
    .line 252
    const-string p2, "Phone has lost bonding information"

    .line 253
    .line 254
    invoke-static {v0, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 255
    .line 256
    .line 257
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 258
    .line 259
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 260
    .line 261
    .line 262
    :cond_9
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 263
    .line 264
    instance-of v0, p2, Lno/nordicsemi/android/ble/v0;

    .line 265
    .line 266
    if-eqz v0, :cond_a

    .line 267
    .line 268
    check-cast p2, Lno/nordicsemi/android/ble/v0;

    .line 269
    .line 270
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 271
    .line 272
    .line 273
    move-result-object p1

    .line 274
    invoke-virtual {p2, p3, p1}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 275
    .line 276
    .line 277
    :cond_a
    :goto_1
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 278
    .line 279
    .line 280
    const/4 p1, 0x1

    .line 281
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 282
    .line 283
    .line 284
    return-void
.end method

.method public final onConnectionStateChange(Landroid/bluetooth/BluetoothGatt;II)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    new-instance v4, Lno/nordicsemi/android/ble/m;

    .line 10
    .line 11
    invoke-direct {v4, v2, v3}, Lno/nordicsemi/android/ble/m;-><init>(II)V

    .line 12
    .line 13
    .line 14
    iget-object v5, v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 15
    .line 16
    const/4 v6, 0x3

    .line 17
    invoke-virtual {v5, v6, v4}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 18
    .line 19
    .line 20
    const-string v4, ")"

    .line 21
    .line 22
    const-string v7, "wait("

    .line 23
    .line 24
    const-wide/16 v8, 0x0

    .line 25
    .line 26
    const/4 v10, 0x4

    .line 27
    const/4 v11, 0x2

    .line 28
    const/4 v12, 0x1

    .line 29
    if-nez v2, :cond_5

    .line 30
    .line 31
    if-ne v3, v11, :cond_5

    .line 32
    .line 33
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->b:Landroid/bluetooth/BluetoothDevice;

    .line 34
    .line 35
    if-nez v2, :cond_1

    .line 36
    .line 37
    const-string v0, "BleManager"

    .line 38
    .line 39
    const-string v2, "Device received notification after disconnection."

    .line 40
    .line 41
    invoke-static {v0, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    iget-object v0, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 45
    .line 46
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-lt v6, v0, :cond_0

    .line 51
    .line 52
    iget-object v0, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 53
    .line 54
    const-string v2, "gatt.close()"

    .line 55
    .line 56
    invoke-virtual {v0, v6, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    :cond_0
    :try_start_0
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->close()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    :catchall_0
    return-void

    .line 63
    :cond_1
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 64
    .line 65
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-lt v10, v2, :cond_2

    .line 70
    .line 71
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 72
    .line 73
    new-instance v3, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    const-string v14, "Connected to "

    .line 76
    .line 77
    invoke-direct {v3, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 81
    .line 82
    .line 83
    move-result-object v14

    .line 84
    invoke-virtual {v14}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v14

    .line 88
    invoke-virtual {v3, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-virtual {v2, v10, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 96
    .line 97
    .line 98
    :cond_2
    iput-boolean v12, v5, Lno/nordicsemi/android/ble/d;->n:Z

    .line 99
    .line 100
    iput-wide v8, v5, Lno/nordicsemi/android/ble/d;->l:J

    .line 101
    .line 102
    iput v11, v5, Lno/nordicsemi/android/ble/d;->s:I

    .line 103
    .line 104
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 105
    .line 106
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    new-instance v2, Lno/nordicsemi/android/ble/o;

    .line 110
    .line 111
    const/4 v3, 0x0

    .line 112
    invoke-direct {v2, v1, v3}, Lno/nordicsemi/android/ble/o;-><init>(Landroid/bluetooth/BluetoothGatt;I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v5, v2}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 116
    .line 117
    .line 118
    iget-boolean v2, v5, Lno/nordicsemi/android/ble/d;->k:Z

    .line 119
    .line 120
    if-nez v2, :cond_1f

    .line 121
    .line 122
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    const/16 v3, 0xc

    .line 131
    .line 132
    if-ne v2, v3, :cond_3

    .line 133
    .line 134
    move v13, v12

    .line 135
    goto :goto_0

    .line 136
    :cond_3
    const/4 v13, 0x0

    .line 137
    :goto_0
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 138
    .line 139
    invoke-virtual {v2, v13}, Lno/nordicsemi/android/ble/e;->getServiceDiscoveryDelay(Z)I

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-lez v2, :cond_4

    .line 144
    .line 145
    iget-object v3, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 146
    .line 147
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    if-lt v6, v3, :cond_4

    .line 152
    .line 153
    iget-object v3, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 154
    .line 155
    new-instance v8, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    invoke-direct {v8, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    invoke-virtual {v3, v6, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 171
    .line 172
    .line 173
    :cond_4
    iget v3, v5, Lno/nordicsemi/android/ble/d;->m:I

    .line 174
    .line 175
    add-int/2addr v3, v12

    .line 176
    iput v3, v5, Lno/nordicsemi/android/ble/d;->m:I

    .line 177
    .line 178
    new-instance v4, Lno/nordicsemi/android/ble/p;

    .line 179
    .line 180
    invoke-direct {v4, v0, v3, v1}, Lno/nordicsemi/android/ble/p;-><init>(Lno/nordicsemi/android/ble/BleManagerHandler$4;ILandroid/bluetooth/BluetoothGatt;)V

    .line 181
    .line 182
    .line 183
    int-to-long v0, v2

    .line 184
    invoke-virtual {v5, v4, v0, v1}, Lno/nordicsemi/android/ble/d;->E(Ljava/lang/Runnable;J)V

    .line 185
    .line 186
    .line 187
    return-void

    .line 188
    :cond_5
    const-string v15, "): "

    .line 189
    .line 190
    if-nez v3, :cond_20

    .line 191
    .line 192
    iget-object v3, v5, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 193
    .line 194
    move-wide/from16 v16, v8

    .line 195
    .line 196
    iget-object v8, v5, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 197
    .line 198
    iget-object v9, v5, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 199
    .line 200
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 201
    .line 202
    .line 203
    move-result-wide v18

    .line 204
    iget-wide v10, v5, Lno/nordicsemi/android/ble/d;->l:J

    .line 205
    .line 206
    cmp-long v16, v10, v16

    .line 207
    .line 208
    if-lez v16, :cond_6

    .line 209
    .line 210
    move/from16 v16, v12

    .line 211
    .line 212
    goto :goto_1

    .line 213
    :cond_6
    const/16 v16, 0x0

    .line 214
    .line 215
    :goto_1
    if-eqz v16, :cond_7

    .line 216
    .line 217
    const-wide/16 v20, 0x4e20

    .line 218
    .line 219
    add-long v10, v10, v20

    .line 220
    .line 221
    cmp-long v10, v18, v10

    .line 222
    .line 223
    if-lez v10, :cond_7

    .line 224
    .line 225
    move v10, v12

    .line 226
    goto :goto_2

    .line 227
    :cond_7
    const/4 v10, 0x0

    .line 228
    :goto_2
    if-eqz v2, :cond_8

    .line 229
    .line 230
    iget-object v11, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 231
    .line 232
    invoke-virtual {v11}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 233
    .line 234
    .line 235
    move-result v11

    .line 236
    const/4 v14, 0x5

    .line 237
    if-lt v14, v11, :cond_8

    .line 238
    .line 239
    iget-object v11, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 240
    .line 241
    move/from16 v18, v12

    .line 242
    .line 243
    new-instance v12, Ljava/lang/StringBuilder;

    .line 244
    .line 245
    const-string v13, "Error: (0x"

    .line 246
    .line 247
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v13

    .line 254
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    invoke-virtual {v12, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 258
    .line 259
    .line 260
    invoke-static {v2}, La/a;->d(I)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v13

    .line 264
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v12

    .line 271
    invoke-virtual {v11, v14, v12}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 272
    .line 273
    .line 274
    goto :goto_3

    .line 275
    :cond_8
    move/from16 v18, v12

    .line 276
    .line 277
    :goto_3
    if-eqz v2, :cond_a

    .line 278
    .line 279
    if-eqz v16, :cond_a

    .line 280
    .line 281
    if-nez v10, :cond_a

    .line 282
    .line 283
    if-eqz v8, :cond_a

    .line 284
    .line 285
    iget v11, v8, Lno/nordicsemi/android/ble/x;->s:I

    .line 286
    .line 287
    if-lez v11, :cond_a

    .line 288
    .line 289
    add-int/lit8 v11, v11, -0x1

    .line 290
    .line 291
    iput v11, v8, Lno/nordicsemi/android/ble/x;->s:I

    .line 292
    .line 293
    iget v2, v8, Lno/nordicsemi/android/ble/x;->t:I

    .line 294
    .line 295
    if-lez v2, :cond_9

    .line 296
    .line 297
    iget-object v3, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 298
    .line 299
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 300
    .line 301
    .line 302
    move-result v3

    .line 303
    if-lt v6, v3, :cond_9

    .line 304
    .line 305
    iget-object v3, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 306
    .line 307
    new-instance v9, Ljava/lang/StringBuilder;

    .line 308
    .line 309
    invoke-direct {v9, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    invoke-virtual {v9, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 313
    .line 314
    .line 315
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 316
    .line 317
    .line 318
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 319
    .line 320
    .line 321
    move-result-object v4

    .line 322
    invoke-virtual {v3, v6, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 323
    .line 324
    .line 325
    :cond_9
    new-instance v3, Lno/nordicsemi/android/ble/n;

    .line 326
    .line 327
    const/4 v4, 0x1

    .line 328
    invoke-direct {v3, v0, v1, v8, v4}, Lno/nordicsemi/android/ble/n;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 329
    .line 330
    .line 331
    int-to-long v0, v2

    .line 332
    invoke-virtual {v5, v3, v0, v1}, Lno/nordicsemi/android/ble/d;->E(Ljava/lang/Runnable;J)V

    .line 333
    .line 334
    .line 335
    return-void

    .line 336
    :cond_a
    if-eqz v8, :cond_e

    .line 337
    .line 338
    iget-boolean v4, v8, Lno/nordicsemi/android/ble/x;->u:Z

    .line 339
    .line 340
    if-eqz v4, :cond_e

    .line 341
    .line 342
    iget-boolean v4, v5, Lno/nordicsemi/android/ble/d;->r:Z

    .line 343
    .line 344
    if-eqz v4, :cond_e

    .line 345
    .line 346
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 347
    .line 348
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 349
    .line 350
    .line 351
    move-result v2

    .line 352
    if-lt v6, v2, :cond_c

    .line 353
    .line 354
    iget-object v2, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 355
    .line 356
    iget-boolean v3, v5, Lno/nordicsemi/android/ble/d;->n:Z

    .line 357
    .line 358
    if-eqz v3, :cond_b

    .line 359
    .line 360
    const-string v3, "; reset connected to false"

    .line 361
    .line 362
    goto :goto_4

    .line 363
    :cond_b
    const-string v3, ""

    .line 364
    .line 365
    :goto_4
    const-string v4, "autoConnect = false called failed; retrying with autoConnect = true"

    .line 366
    .line 367
    invoke-virtual {v4, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object v3

    .line 371
    invoke-virtual {v2, v6, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 372
    .line 373
    .line 374
    :cond_c
    iget-boolean v2, v5, Lno/nordicsemi/android/ble/d;->n:Z

    .line 375
    .line 376
    if-eqz v2, :cond_d

    .line 377
    .line 378
    const/4 v2, 0x0

    .line 379
    iput-boolean v2, v5, Lno/nordicsemi/android/ble/d;->n:Z

    .line 380
    .line 381
    iput v2, v5, Lno/nordicsemi/android/ble/d;->s:I

    .line 382
    .line 383
    :cond_d
    new-instance v2, Lno/nordicsemi/android/ble/n;

    .line 384
    .line 385
    const/4 v3, 0x0

    .line 386
    invoke-direct {v2, v0, v1, v8, v3}, Lno/nordicsemi/android/ble/n;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {v5, v2}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 390
    .line 391
    .line 392
    return-void

    .line 393
    :cond_e
    move/from16 v0, v18

    .line 394
    .line 395
    iput-boolean v0, v5, Lno/nordicsemi/android/ble/d;->p:Z

    .line 396
    .line 397
    const/4 v4, -0x1

    .line 398
    invoke-virtual {v5, v4}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 399
    .line 400
    .line 401
    const/4 v7, 0x0

    .line 402
    iput-boolean v7, v5, Lno/nordicsemi/android/ble/d;->o:Z

    .line 403
    .line 404
    iget-boolean v7, v5, Lno/nordicsemi/android/ble/d;->n:Z

    .line 405
    .line 406
    iget-boolean v11, v5, Lno/nordicsemi/android/ble/d;->j:Z

    .line 407
    .line 408
    const/16 v12, 0xa

    .line 409
    .line 410
    if-eqz v10, :cond_f

    .line 411
    .line 412
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    invoke-virtual {v5, v12, v0}, Lno/nordicsemi/android/ble/d;->B(ILandroid/bluetooth/BluetoothDevice;)V

    .line 417
    .line 418
    .line 419
    goto :goto_6

    .line 420
    :cond_f
    if-eqz v11, :cond_10

    .line 421
    .line 422
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    const/4 v12, 0x4

    .line 427
    invoke-virtual {v5, v12, v0}, Lno/nordicsemi/android/ble/d;->B(ILandroid/bluetooth/BluetoothDevice;)V

    .line 428
    .line 429
    .line 430
    goto :goto_6

    .line 431
    :cond_10
    if-eqz v3, :cond_11

    .line 432
    .line 433
    iget v13, v3, Lno/nordicsemi/android/ble/i0;->c:I

    .line 434
    .line 435
    if-ne v13, v6, :cond_11

    .line 436
    .line 437
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    const/4 v12, 0x0

    .line 442
    invoke-virtual {v5, v12, v0}, Lno/nordicsemi/android/ble/d;->B(ILandroid/bluetooth/BluetoothDevice;)V

    .line 443
    .line 444
    .line 445
    goto :goto_6

    .line 446
    :cond_11
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 447
    .line 448
    .line 449
    move-result-object v13

    .line 450
    if-eqz v2, :cond_14

    .line 451
    .line 452
    const/16 v14, 0x8

    .line 453
    .line 454
    if-eq v2, v14, :cond_14

    .line 455
    .line 456
    const/16 v12, 0x13

    .line 457
    .line 458
    if-eq v2, v12, :cond_13

    .line 459
    .line 460
    const/16 v12, 0x16

    .line 461
    .line 462
    if-eq v2, v12, :cond_12

    .line 463
    .line 464
    move v12, v4

    .line 465
    goto :goto_5

    .line 466
    :cond_12
    move v12, v0

    .line 467
    goto :goto_5

    .line 468
    :cond_13
    const/4 v12, 0x2

    .line 469
    :cond_14
    :goto_5
    invoke-virtual {v5, v12, v13}, Lno/nordicsemi/android/ble/d;->B(ILandroid/bluetooth/BluetoothDevice;)V

    .line 470
    .line 471
    .line 472
    :goto_6
    const/4 v0, 0x0

    .line 473
    if-eqz v3, :cond_16

    .line 474
    .line 475
    iget v12, v3, Lno/nordicsemi/android/ble/i0;->c:I

    .line 476
    .line 477
    if-eq v12, v6, :cond_16

    .line 478
    .line 479
    const/4 v6, 0x6

    .line 480
    if-eq v12, v6, :cond_16

    .line 481
    .line 482
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 483
    .line 484
    .line 485
    move-result-object v6

    .line 486
    if-nez v2, :cond_15

    .line 487
    .line 488
    move v12, v4

    .line 489
    goto :goto_7

    .line 490
    :cond_15
    move v12, v2

    .line 491
    :goto_7
    invoke-virtual {v3, v12, v6}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 492
    .line 493
    .line 494
    iput-object v0, v5, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 495
    .line 496
    :cond_16
    if-eqz v9, :cond_17

    .line 497
    .line 498
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 499
    .line 500
    .line 501
    move-result-object v6

    .line 502
    invoke-virtual {v9, v4, v6}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 503
    .line 504
    .line 505
    iput-object v0, v5, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 506
    .line 507
    :cond_17
    if-eqz v8, :cond_1c

    .line 508
    .line 509
    if-eqz v11, :cond_18

    .line 510
    .line 511
    const/4 v4, -0x2

    .line 512
    goto :goto_8

    .line 513
    :cond_18
    if-nez v2, :cond_19

    .line 514
    .line 515
    goto :goto_8

    .line 516
    :cond_19
    const/16 v4, 0x85

    .line 517
    .line 518
    if-eq v2, v4, :cond_1a

    .line 519
    .line 520
    const/16 v4, 0x93

    .line 521
    .line 522
    if-ne v2, v4, :cond_1b

    .line 523
    .line 524
    :cond_1a
    if-eqz v10, :cond_1b

    .line 525
    .line 526
    const/4 v4, -0x5

    .line 527
    goto :goto_8

    .line 528
    :cond_1b
    move v4, v2

    .line 529
    :goto_8
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 530
    .line 531
    .line 532
    move-result-object v6

    .line 533
    invoke-virtual {v8, v4, v6}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 534
    .line 535
    .line 536
    iput-object v0, v5, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 537
    .line 538
    :cond_1c
    const/4 v12, 0x0

    .line 539
    iput-boolean v12, v5, Lno/nordicsemi/android/ble/d;->p:Z

    .line 540
    .line 541
    if-eqz v3, :cond_1d

    .line 542
    .line 543
    iget v3, v3, Lno/nordicsemi/android/ble/i0;->c:I

    .line 544
    .line 545
    const/4 v6, 0x6

    .line 546
    if-ne v3, v6, :cond_1d

    .line 547
    .line 548
    goto :goto_a

    .line 549
    :cond_1d
    if-eqz v7, :cond_1e

    .line 550
    .line 551
    iget-boolean v3, v5, Lno/nordicsemi/android/ble/d;->r:Z

    .line 552
    .line 553
    if-eqz v3, :cond_1e

    .line 554
    .line 555
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 556
    .line 557
    .line 558
    move-result-object v1

    .line 559
    invoke-virtual {v5, v1, v0}, Lno/nordicsemi/android/ble/d;->l(Landroid/bluetooth/BluetoothDevice;Lno/nordicsemi/android/ble/x;)Z

    .line 560
    .line 561
    .line 562
    goto :goto_9

    .line 563
    :cond_1e
    const/4 v12, 0x0

    .line 564
    iput-boolean v12, v5, Lno/nordicsemi/android/ble/d;->r:Z

    .line 565
    .line 566
    invoke-virtual {v5, v12}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 567
    .line 568
    .line 569
    :goto_9
    if-nez v7, :cond_1f

    .line 570
    .line 571
    if-nez v2, :cond_21

    .line 572
    .line 573
    :cond_1f
    :goto_a
    return-void

    .line 574
    :cond_20
    if-eqz v2, :cond_21

    .line 575
    .line 576
    iget-object v0, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 577
    .line 578
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 579
    .line 580
    .line 581
    move-result v0

    .line 582
    const/4 v6, 0x6

    .line 583
    if-lt v6, v0, :cond_21

    .line 584
    .line 585
    iget-object v0, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 586
    .line 587
    new-instance v1, Ljava/lang/StringBuilder;

    .line 588
    .line 589
    const-string v3, "Error (0x"

    .line 590
    .line 591
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 595
    .line 596
    .line 597
    move-result-object v3

    .line 598
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 599
    .line 600
    .line 601
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 602
    .line 603
    .line 604
    invoke-static {v2}, La/a;->d(I)Ljava/lang/String;

    .line 605
    .line 606
    .line 607
    move-result-object v2

    .line 608
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 609
    .line 610
    .line 611
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 612
    .line 613
    .line 614
    move-result-object v1

    .line 615
    invoke-virtual {v0, v6, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 616
    .line 617
    .line 618
    :cond_21
    iget-object v0, v5, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 619
    .line 620
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 621
    .line 622
    .line 623
    return-void
.end method

.method public onConnectionUpdated(Landroid/bluetooth/BluetoothGatt;IIII)V
    .locals 7
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-nez p5, :cond_0

    .line 4
    .line 5
    new-instance p5, Lno/nordicsemi/android/ble/q;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-direct {p5, p2, p3, p4, v0}, Lno/nordicsemi/android/ble/q;-><init>(IIII)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x4

    .line 12
    invoke-virtual {p0, v0, p5}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 13
    .line 14
    .line 15
    iput p2, p0, Lno/nordicsemi/android/ble/d;->w:I

    .line 16
    .line 17
    iget-object p5, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 18
    .line 19
    instance-of v0, p5, Lno/nordicsemi/android/ble/z;

    .line 20
    .line 21
    if-eqz v0, :cond_3

    .line 22
    .line 23
    move-object v2, p5

    .line 24
    check-cast v2, Lno/nordicsemi/android/ble/z;

    .line 25
    .line 26
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    iget-object p5, v2, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 31
    .line 32
    new-instance v1, Lno/nordicsemi/android/ble/y;

    .line 33
    .line 34
    move v4, p2

    .line 35
    move v5, p3

    .line 36
    move v6, p4

    .line 37
    invoke-direct/range {v1 .. v6}, Lno/nordicsemi/android/ble/y;-><init>(Lno/nordicsemi/android/ble/z;Landroid/bluetooth/BluetoothDevice;III)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p5, v1}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-virtual {v2, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    move v4, p2

    .line 52
    move v5, p3

    .line 53
    move v6, p4

    .line 54
    const/16 p2, 0x3b

    .line 55
    .line 56
    const/4 p3, 0x0

    .line 57
    const/4 p4, 0x5

    .line 58
    const-string v0, ", timeout: "

    .line 59
    .line 60
    const-string v1, ", latency: "

    .line 61
    .line 62
    const-string v2, "BleManager"

    .line 63
    .line 64
    if-ne p5, p2, :cond_1

    .line 65
    .line 66
    const-string p2, "onConnectionUpdated received status: Unacceptable connection interval, interval: "

    .line 67
    .line 68
    invoke-static {v4, v5, p2, v1, v0}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    invoke-virtual {p2, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    invoke-static {v2, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    new-instance p2, Lno/nordicsemi/android/ble/q;

    .line 83
    .line 84
    const/4 v0, 0x1

    .line 85
    invoke-direct {p2, v4, v5, v6, v0}, Lno/nordicsemi/android/ble/q;-><init>(IIII)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p0, p4, p2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 89
    .line 90
    .line 91
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 92
    .line 93
    instance-of p4, p2, Lno/nordicsemi/android/ble/z;

    .line 94
    .line 95
    if-eqz p4, :cond_3

    .line 96
    .line 97
    check-cast p2, Lno/nordicsemi/android/ble/z;

    .line 98
    .line 99
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-virtual {p2, p5, p1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 104
    .line 105
    .line 106
    iput-object p3, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_1
    const-string p2, "onConnectionUpdated received status: "

    .line 110
    .line 111
    const-string v3, ", interval: "

    .line 112
    .line 113
    invoke-static {p5, v4, p2, v3, v1}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    invoke-virtual {p2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {p2, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p2

    .line 130
    invoke-static {v2, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 131
    .line 132
    .line 133
    new-instance p2, Lno/nordicsemi/android/ble/r;

    .line 134
    .line 135
    invoke-direct {p2, p5, v4, v5, v6}, Lno/nordicsemi/android/ble/r;-><init>(IIII)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0, p4, p2}, Lno/nordicsemi/android/ble/d;->z(ILno/nordicsemi/android/ble/t;)V

    .line 139
    .line 140
    .line 141
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 142
    .line 143
    instance-of p4, p2, Lno/nordicsemi/android/ble/z;

    .line 144
    .line 145
    if-eqz p4, :cond_2

    .line 146
    .line 147
    check-cast p2, Lno/nordicsemi/android/ble/z;

    .line 148
    .line 149
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-virtual {p2, p5, p1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 154
    .line 155
    .line 156
    iput-object p3, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 157
    .line 158
    :cond_2
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 159
    .line 160
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    :cond_3
    :goto_0
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->t:Z

    .line 164
    .line 165
    if-eqz p1, :cond_4

    .line 166
    .line 167
    const/4 p1, 0x0

    .line 168
    iput-boolean p1, p0, Lno/nordicsemi/android/ble/d;->t:Z

    .line 169
    .line 170
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 171
    .line 172
    .line 173
    const/4 p1, 0x1

    .line 174
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 175
    .line 176
    .line 177
    :cond_4
    return-void
.end method

.method public final onDescriptorRead(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;I)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    move-result-object v0

    invoke-virtual {p0, p1, p2, p3, v0}, Lno/nordicsemi/android/ble/BleManagerHandler$4;->onDescriptorRead(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;I[B)V

    return-void
.end method

.method public final onDescriptorRead(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;I[B)V
    .locals 5

    const/4 v0, 0x1

    .line 2
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    if-nez p3, :cond_3

    .line 3
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 4
    invoke-virtual {p3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result p3

    const/4 v1, 0x4

    if-lt v1, p3, :cond_0

    .line 5
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Read Response received from descr. "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    move-result-object p2

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, ", value: "

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    invoke-static {p4}, Lc01/a;->a([B)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    .line 8
    invoke-virtual {p3, v1, p2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 9
    :cond_0
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    instance-of p3, p2, Lno/nordicsemi/android/ble/e0;

    if-eqz p3, :cond_a

    check-cast p2, Lno/nordicsemi/android/ble/e0;

    .line 10
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p3

    .line 11
    iget-object v1, p2, Lno/nordicsemi/android/ble/q0;->p:Lno/nordicsemi/android/ble/j;

    if-nez v1, :cond_1

    .line 12
    iput-boolean v0, p2, Lno/nordicsemi/android/ble/e0;->q:Z

    goto :goto_0

    .line 13
    :cond_1
    iput-boolean v0, p2, Lno/nordicsemi/android/ble/e0;->q:Z

    .line 14
    new-instance v2, Lzz0/a;

    invoke-direct {v2, p4}, Lzz0/a;-><init>([B)V

    .line 15
    iget-object p4, p2, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    new-instance v3, Lno/nordicsemi/android/ble/d0;

    const/4 v4, 0x0

    invoke-direct {v3, v1, p3, v2, v4}, Lno/nordicsemi/android/ble/d0;-><init>(Lyz0/b;Landroid/bluetooth/BluetoothDevice;Lzz0/a;I)V

    invoke-virtual {p4, v3}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 16
    :goto_0
    iget-boolean p3, p2, Lno/nordicsemi/android/ble/e0;->q:Z

    if-nez p3, :cond_2

    iget-boolean p3, p2, Lno/nordicsemi/android/ble/p0;->n:Z

    if-nez p3, :cond_2

    iget-boolean p3, p2, Lno/nordicsemi/android/ble/i0;->k:Z

    if-nez p3, :cond_2

    .line 17
    invoke-virtual {p0, p2}, Lno/nordicsemi/android/ble/d;->g(Lno/nordicsemi/android/ble/i0;)V

    goto/16 :goto_2

    .line 18
    :cond_2
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p1

    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    goto/16 :goto_2

    :cond_3
    const/16 p2, 0x89

    .line 19
    const-string p4, "BleManager"

    if-ne p3, p2, :cond_4

    .line 20
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "Reading descriptor failed with status "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p4, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    return-void

    :cond_4
    const/4 p2, 0x5

    if-eq p3, p2, :cond_7

    const/16 v1, 0x8

    if-ne p3, v1, :cond_5

    goto :goto_1

    .line 21
    :cond_5
    const-string p2, "onDescriptorRead error "

    const-string v1, ", bond state: "

    .line 22
    invoke-static {p2, p3, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    .line 23
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object v1

    invoke-virtual {v1}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    move-result v1

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {p4, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 24
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    instance-of p4, p2, Lno/nordicsemi/android/ble/e0;

    if-eqz p4, :cond_6

    check-cast p2, Lno/nordicsemi/android/ble/e0;

    .line 25
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p4

    invoke-virtual {p2, p3, p4}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    :cond_6
    const/4 p2, 0x0

    .line 26
    iput-object p2, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 27
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    invoke-static {p0, p3}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    goto :goto_2

    .line 28
    :cond_7
    :goto_1
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 29
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    move-result v1

    if-lt p2, v1, :cond_8

    .line 30
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 31
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Authentication required ("

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, ")"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    .line 32
    invoke-virtual {v1, p2, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 33
    :cond_8
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p2

    invoke-virtual {p2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    move-result p2

    const/16 v1, 0xc

    if-ne p2, v1, :cond_9

    .line 34
    const-string p2, "Phone has lost bonding information"

    invoke-static {p4, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 35
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 36
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    :cond_9
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    instance-of p4, p2, Lno/nordicsemi/android/ble/e0;

    if-eqz p4, :cond_a

    check-cast p2, Lno/nordicsemi/android/ble/e0;

    .line 38
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    move-result-object p1

    invoke-virtual {p2, p3, p1}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 39
    :cond_a
    :goto_2
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 40
    invoke-virtual {p0, v0}, Lno/nordicsemi/android/ble/d;->A(Z)V

    return-void
.end method

.method public final onDescriptorWrite(Landroid/bluetooth/BluetoothGatt;Landroid/bluetooth/BluetoothGattDescriptor;I)V
    .locals 5

    .line 1
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x1

    .line 6
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    if-nez p3, :cond_8

    .line 9
    .line 10
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 11
    .line 12
    invoke-virtual {p3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    const/4 v2, 0x4

    .line 17
    if-lt v2, p3, :cond_0

    .line 18
    .line 19
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 20
    .line 21
    new-instance v3, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v4, "Data written to descr. "

    .line 24
    .line 25
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {p3, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    sget-object p3, Lno/nordicsemi/android/ble/e;->SERVICE_CHANGED_CHARACTERISTIC:Ljava/util/UUID;

    .line 43
    .line 44
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattDescriptor;->getCharacteristic()Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGattCharacteristic;->getUuid()Ljava/util/UUID;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-virtual {p3, v3}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p3

    .line 56
    if-eqz p3, :cond_1

    .line 57
    .line 58
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 59
    .line 60
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-lt v2, p2, :cond_5

    .line 65
    .line 66
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 67
    .line 68
    const-string p3, "Service Changed notifications enabled"

    .line 69
    .line 70
    invoke-virtual {p2, v2, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    sget-object p3, Lno/nordicsemi/android/ble/e;->CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

    .line 75
    .line 76
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothGattDescriptor;->getUuid()Ljava/util/UUID;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    invoke-virtual {p3, p2}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    if-eqz p2, :cond_5

    .line 85
    .line 86
    if-eqz v0, :cond_5

    .line 87
    .line 88
    array-length p2, v0

    .line 89
    const/4 p3, 0x2

    .line 90
    if-ne p2, p3, :cond_5

    .line 91
    .line 92
    aget-byte p2, v0, v1

    .line 93
    .line 94
    if-nez p2, :cond_5

    .line 95
    .line 96
    const/4 p2, 0x0

    .line 97
    aget-byte p2, v0, p2

    .line 98
    .line 99
    if-eqz p2, :cond_4

    .line 100
    .line 101
    if-eq p2, v1, :cond_3

    .line 102
    .line 103
    if-eq p2, p3, :cond_2

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_2
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 107
    .line 108
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 109
    .line 110
    .line 111
    move-result p2

    .line 112
    if-lt v2, p2, :cond_5

    .line 113
    .line 114
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 115
    .line 116
    const-string p3, "Indications enabled"

    .line 117
    .line 118
    invoke-virtual {p2, v2, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 119
    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_3
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 123
    .line 124
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 125
    .line 126
    .line 127
    move-result p2

    .line 128
    if-lt v2, p2, :cond_5

    .line 129
    .line 130
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 131
    .line 132
    const-string p3, "Notifications enabled"

    .line 133
    .line 134
    invoke-virtual {p2, v2, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :cond_4
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 139
    .line 140
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 141
    .line 142
    .line 143
    move-result p2

    .line 144
    if-lt v2, p2, :cond_5

    .line 145
    .line 146
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 147
    .line 148
    const-string p3, "Notifications and indications disabled"

    .line 149
    .line 150
    invoke-virtual {p2, v2, p3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 151
    .line 152
    .line 153
    :cond_5
    :goto_0
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 154
    .line 155
    instance-of p3, p2, Lno/nordicsemi/android/ble/v0;

    .line 156
    .line 157
    if-eqz p3, :cond_f

    .line 158
    .line 159
    check-cast p2, Lno/nordicsemi/android/ble/v0;

    .line 160
    .line 161
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 162
    .line 163
    .line 164
    move-result-object p3

    .line 165
    invoke-virtual {p2, p3, v0}, Lno/nordicsemi/android/ble/v0;->h(Landroid/bluetooth/BluetoothDevice;[B)Z

    .line 166
    .line 167
    .line 168
    move-result p3

    .line 169
    if-nez p3, :cond_6

    .line 170
    .line 171
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 172
    .line 173
    instance-of v0, p3, Lno/nordicsemi/android/ble/g0;

    .line 174
    .line 175
    if-eqz v0, :cond_6

    .line 176
    .line 177
    check-cast p3, Lno/nordicsemi/android/ble/g0;

    .line 178
    .line 179
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    const/4 v2, -0x6

    .line 184
    invoke-virtual {p2, v2, v0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    invoke-virtual {p3, p1}, Lno/nordicsemi/android/ble/j0;->k(Landroid/bluetooth/BluetoothDevice;)V

    .line 192
    .line 193
    .line 194
    goto/16 :goto_2

    .line 195
    .line 196
    :cond_6
    iget-boolean p3, p2, Lno/nordicsemi/android/ble/v0;->u:Z

    .line 197
    .line 198
    if-nez p3, :cond_7

    .line 199
    .line 200
    iget-boolean p3, p2, Lno/nordicsemi/android/ble/p0;->n:Z

    .line 201
    .line 202
    if-nez p3, :cond_7

    .line 203
    .line 204
    iget-boolean p3, p2, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 205
    .line 206
    if-nez p3, :cond_7

    .line 207
    .line 208
    invoke-virtual {p0, p2}, Lno/nordicsemi/android/ble/d;->g(Lno/nordicsemi/android/ble/i0;)V

    .line 209
    .line 210
    .line 211
    goto/16 :goto_2

    .line 212
    .line 213
    :cond_7
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 214
    .line 215
    .line 216
    move-result-object p1

    .line 217
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 218
    .line 219
    .line 220
    goto/16 :goto_2

    .line 221
    .line 222
    :cond_8
    const/16 p2, 0x89

    .line 223
    .line 224
    const-string v0, "BleManager"

    .line 225
    .line 226
    if-ne p3, p2, :cond_9

    .line 227
    .line 228
    new-instance p0, Ljava/lang/StringBuilder;

    .line 229
    .line 230
    const-string p1, "Writing descriptor failed with status "

    .line 231
    .line 232
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 243
    .line 244
    .line 245
    return-void

    .line 246
    :cond_9
    const/4 p2, 0x5

    .line 247
    if-eq p3, p2, :cond_c

    .line 248
    .line 249
    const/16 v2, 0x8

    .line 250
    .line 251
    if-ne p3, v2, :cond_a

    .line 252
    .line 253
    goto :goto_1

    .line 254
    :cond_a
    const-string p2, "onDescriptorWrite error "

    .line 255
    .line 256
    const-string v2, ", bond state: "

    .line 257
    .line 258
    invoke-static {p2, p3, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    move-result-object p2

    .line 262
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    invoke-virtual {v2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object p2

    .line 277
    invoke-static {v0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 278
    .line 279
    .line 280
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 281
    .line 282
    instance-of v0, p2, Lno/nordicsemi/android/ble/v0;

    .line 283
    .line 284
    if-eqz v0, :cond_b

    .line 285
    .line 286
    check-cast p2, Lno/nordicsemi/android/ble/v0;

    .line 287
    .line 288
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 289
    .line 290
    .line 291
    move-result-object v0

    .line 292
    invoke-virtual {p2, p3, v0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 293
    .line 294
    .line 295
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 296
    .line 297
    instance-of v0, p2, Lno/nordicsemi/android/ble/g0;

    .line 298
    .line 299
    if-eqz v0, :cond_b

    .line 300
    .line 301
    check-cast p2, Lno/nordicsemi/android/ble/g0;

    .line 302
    .line 303
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    invoke-virtual {p2, v0}, Lno/nordicsemi/android/ble/j0;->k(Landroid/bluetooth/BluetoothDevice;)V

    .line 308
    .line 309
    .line 310
    :cond_b
    const/4 p2, 0x0

    .line 311
    iput-object p2, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 312
    .line 313
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 314
    .line 315
    .line 316
    invoke-static {p0, p3}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    .line 317
    .line 318
    .line 319
    goto :goto_2

    .line 320
    :cond_c
    :goto_1
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 321
    .line 322
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 323
    .line 324
    .line 325
    move-result v2

    .line 326
    if-lt p2, v2, :cond_d

    .line 327
    .line 328
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 329
    .line 330
    new-instance v3, Ljava/lang/StringBuilder;

    .line 331
    .line 332
    const-string v4, "Authentication required ("

    .line 333
    .line 334
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v3, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 338
    .line 339
    .line 340
    const-string v4, ")"

    .line 341
    .line 342
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 343
    .line 344
    .line 345
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v3

    .line 349
    invoke-virtual {v2, p2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 350
    .line 351
    .line 352
    :cond_d
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 353
    .line 354
    .line 355
    move-result-object p2

    .line 356
    invoke-virtual {p2}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 357
    .line 358
    .line 359
    move-result p2

    .line 360
    const/16 v2, 0xc

    .line 361
    .line 362
    if-ne p2, v2, :cond_e

    .line 363
    .line 364
    const-string p2, "Phone has lost bonding information"

    .line 365
    .line 366
    invoke-static {v0, p2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 367
    .line 368
    .line 369
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 370
    .line 371
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 372
    .line 373
    .line 374
    :cond_e
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 375
    .line 376
    instance-of v0, p2, Lno/nordicsemi/android/ble/v0;

    .line 377
    .line 378
    if-eqz v0, :cond_f

    .line 379
    .line 380
    check-cast p2, Lno/nordicsemi/android/ble/v0;

    .line 381
    .line 382
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 383
    .line 384
    .line 385
    move-result-object p1

    .line 386
    invoke-virtual {p2, p3, p1}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 387
    .line 388
    .line 389
    :cond_f
    :goto_2
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 390
    .line 391
    .line 392
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 393
    .line 394
    .line 395
    return-void
.end method

.method public final onMtuChanged(Landroid/bluetooth/BluetoothGatt;II)V
    .locals 4

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-nez p3, :cond_1

    .line 4
    .line 5
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    .line 7
    invoke-virtual {p3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    const/4 v0, 0x4

    .line 12
    if-lt v0, p3, :cond_0

    .line 13
    .line 14
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "MTU changed to: "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {p3, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    const/16 p3, 0x203

    .line 34
    .line 35
    invoke-static {p3, p2}, Ljava/lang/Math;->min(II)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iput p2, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 40
    .line 41
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 42
    .line 43
    instance-of p3, p2, Lno/nordicsemi/android/ble/b0;

    .line 44
    .line 45
    if-eqz p3, :cond_3

    .line 46
    .line 47
    check-cast p2, Lno/nordicsemi/android/ble/b0;

    .line 48
    .line 49
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 50
    .line 51
    .line 52
    move-result-object p3

    .line 53
    iget v0, p0, Lno/nordicsemi/android/ble/d;->v:I

    .line 54
    .line 55
    iget-object v1, p2, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 56
    .line 57
    new-instance v2, Lno/nordicsemi/android/ble/p;

    .line 58
    .line 59
    const/4 v3, 0x1

    .line 60
    invoke-direct {v2, p2, p3, v0, v3}, Lno/nordicsemi/android/ble/p;-><init>(Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;II)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v1, "onMtuChanged error: "

    .line 77
    .line 78
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", mtu: "

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    const-string v0, "BleManager"

    .line 97
    .line 98
    invoke-static {v0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 99
    .line 100
    .line 101
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 102
    .line 103
    instance-of v0, p2, Lno/nordicsemi/android/ble/b0;

    .line 104
    .line 105
    if-eqz v0, :cond_2

    .line 106
    .line 107
    check-cast p2, Lno/nordicsemi/android/ble/b0;

    .line 108
    .line 109
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {p2, p3, v0}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 114
    .line 115
    .line 116
    const/4 p2, 0x0

    .line 117
    iput-object p2, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 118
    .line 119
    :cond_2
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 120
    .line 121
    .line 122
    invoke-static {p0, p3}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    .line 123
    .line 124
    .line 125
    :cond_3
    :goto_0
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 126
    .line 127
    .line 128
    iget-boolean p1, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 129
    .line 130
    if-eqz p1, :cond_4

    .line 131
    .line 132
    const/4 p1, 0x1

    .line 133
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 134
    .line 135
    .line 136
    :cond_4
    return-void
.end method

.method public final onPhyRead(Landroid/bluetooth/BluetoothGatt;III)V
    .locals 3

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-nez p4, :cond_1

    .line 4
    .line 5
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    .line 7
    invoke-virtual {p4}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 8
    .line 9
    .line 10
    move-result p4

    .line 11
    const/4 v0, 0x4

    .line 12
    if-lt v0, p4, :cond_0

    .line 13
    .line 14
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "PHY read (TX: "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p2}, Lc01/a;->d(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v2, ", RX: "

    .line 31
    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-static {p3}, Lc01/a;->d(I)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v2, ")"

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p4, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_0
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 55
    .line 56
    instance-of v0, p4, Lno/nordicsemi/android/ble/c0;

    .line 57
    .line 58
    if-eqz v0, :cond_4

    .line 59
    .line 60
    check-cast p4, Lno/nordicsemi/android/ble/c0;

    .line 61
    .line 62
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    iget-object v1, p4, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 67
    .line 68
    new-instance v2, Lno/nordicsemi/android/ble/y;

    .line 69
    .line 70
    invoke-direct {v2, p4, v0, p2, p3}, Lno/nordicsemi/android/ble/y;-><init>(Lno/nordicsemi/android/ble/c0;Landroid/bluetooth/BluetoothDevice;II)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 74
    .line 75
    .line 76
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 77
    .line 78
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 87
    .line 88
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    const/4 p3, 0x5

    .line 93
    if-lt p3, p2, :cond_2

    .line 94
    .line 95
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 96
    .line 97
    new-instance v0, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v1, "PHY read failed with status "

    .line 100
    .line 101
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-virtual {p2, p3, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 112
    .line 113
    .line 114
    :cond_2
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 115
    .line 116
    instance-of p3, p2, Lno/nordicsemi/android/ble/c0;

    .line 117
    .line 118
    if-eqz p3, :cond_3

    .line 119
    .line 120
    check-cast p2, Lno/nordicsemi/android/ble/c0;

    .line 121
    .line 122
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-virtual {p2, p4, p1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 127
    .line 128
    .line 129
    :cond_3
    const/4 p1, 0x0

    .line 130
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 131
    .line 132
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 133
    .line 134
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    :cond_4
    :goto_0
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 138
    .line 139
    .line 140
    const/4 p1, 0x1

    .line 141
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 142
    .line 143
    .line 144
    return-void
.end method

.method public final onPhyUpdate(Landroid/bluetooth/BluetoothGatt;III)V
    .locals 3

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-nez p4, :cond_1

    .line 4
    .line 5
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    .line 7
    invoke-virtual {p4}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 8
    .line 9
    .line 10
    move-result p4

    .line 11
    const/4 v0, 0x4

    .line 12
    if-lt v0, p4, :cond_0

    .line 13
    .line 14
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "PHY updated (TX: "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p2}, Lc01/a;->d(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v2, ", RX: "

    .line 31
    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-static {p3}, Lc01/a;->d(I)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v2, ")"

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p4, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_0
    iget-object p4, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 55
    .line 56
    instance-of v0, p4, Lno/nordicsemi/android/ble/c0;

    .line 57
    .line 58
    if-eqz v0, :cond_4

    .line 59
    .line 60
    check-cast p4, Lno/nordicsemi/android/ble/c0;

    .line 61
    .line 62
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    iget-object v1, p4, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 67
    .line 68
    new-instance v2, Lno/nordicsemi/android/ble/y;

    .line 69
    .line 70
    invoke-direct {v2, p4, v0, p2, p3}, Lno/nordicsemi/android/ble/y;-><init>(Lno/nordicsemi/android/ble/c0;Landroid/bluetooth/BluetoothDevice;II)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-virtual {p4, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 85
    .line 86
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    const/4 p3, 0x5

    .line 91
    if-lt p3, p2, :cond_2

    .line 92
    .line 93
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 94
    .line 95
    new-instance v0, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    const-string v1, "PHY updated failed with status "

    .line 98
    .line 99
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    invoke-virtual {p2, p3, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 110
    .line 111
    .line 112
    :cond_2
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 113
    .line 114
    instance-of p3, p2, Lno/nordicsemi/android/ble/c0;

    .line 115
    .line 116
    if-eqz p3, :cond_3

    .line 117
    .line 118
    check-cast p2, Lno/nordicsemi/android/ble/c0;

    .line 119
    .line 120
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-virtual {p2, p4, p1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 125
    .line 126
    .line 127
    const/4 p1, 0x0

    .line 128
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 129
    .line 130
    :cond_3
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 131
    .line 132
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    :cond_4
    :goto_0
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 136
    .line 137
    .line 138
    move-result p1

    .line 139
    if-nez p1, :cond_6

    .line 140
    .line 141
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 142
    .line 143
    instance-of p1, p1, Lno/nordicsemi/android/ble/c0;

    .line 144
    .line 145
    if-eqz p1, :cond_5

    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_5
    return-void

    .line 149
    :cond_6
    :goto_1
    const/4 p1, 0x1

    .line 150
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 151
    .line 152
    .line 153
    return-void
.end method

.method public final onReadRemoteRssi(Landroid/bluetooth/BluetoothGatt;II)V
    .locals 3

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    if-nez p3, :cond_1

    .line 4
    .line 5
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 6
    .line 7
    invoke-virtual {p3}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    const/4 v0, 0x4

    .line 12
    if-lt v0, p3, :cond_0

    .line 13
    .line 14
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "Remote RSSI received: "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v2, " dBm"

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {p3, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    iget-object p3, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 39
    .line 40
    instance-of v0, p3, Lno/nordicsemi/android/ble/f0;

    .line 41
    .line 42
    if-eqz v0, :cond_4

    .line 43
    .line 44
    check-cast p3, Lno/nordicsemi/android/ble/f0;

    .line 45
    .line 46
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iget-object v1, p3, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 51
    .line 52
    new-instance v2, Lno/nordicsemi/android/ble/y;

    .line 53
    .line 54
    invoke-direct {v2, p3, v0, p2}, Lno/nordicsemi/android/ble/y;-><init>(Lno/nordicsemi/android/ble/f0;Landroid/bluetooth/BluetoothDevice;I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1, v2}, Lno/nordicsemi/android/ble/d;->C(Ljava/lang/Runnable;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-virtual {p3, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 69
    .line 70
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 71
    .line 72
    .line 73
    move-result p2

    .line 74
    const/4 v0, 0x5

    .line 75
    if-lt v0, p2, :cond_2

    .line 76
    .line 77
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 78
    .line 79
    new-instance v1, Ljava/lang/StringBuilder;

    .line 80
    .line 81
    const-string v2, "Reading remote RSSI failed with status "

    .line 82
    .line 83
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {p2, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :cond_2
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 97
    .line 98
    instance-of v0, p2, Lno/nordicsemi/android/ble/f0;

    .line 99
    .line 100
    if-eqz v0, :cond_3

    .line 101
    .line 102
    check-cast p2, Lno/nordicsemi/android/ble/f0;

    .line 103
    .line 104
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    invoke-virtual {p2, p3, p1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 109
    .line 110
    .line 111
    :cond_3
    const/4 p1, 0x0

    .line 112
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 113
    .line 114
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    :cond_4
    :goto_0
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 120
    .line 121
    .line 122
    const/4 p1, 0x1

    .line 123
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 124
    .line 125
    .line 126
    return-void
.end method

.method public final onReliableWriteCompleted(Landroid/bluetooth/BluetoothGatt;I)V
    .locals 4

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 4
    .line 5
    iget v0, v0, Lno/nordicsemi/android/ble/i0;->c:I

    .line 6
    .line 7
    const/16 v1, 0xe

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x1

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    move v0, v3

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v0, v2

    .line 16
    :goto_0
    iput-boolean v2, p0, Lno/nordicsemi/android/ble/d;->u:Z

    .line 17
    .line 18
    if-nez p2, :cond_4

    .line 19
    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 23
    .line 24
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    const/4 v0, 0x4

    .line 29
    if-lt v0, p2, :cond_1

    .line 30
    .line 31
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 32
    .line 33
    const-string v1, "Reliable Write executed"

    .line 34
    .line 35
    invoke-virtual {p2, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 49
    .line 50
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    const/4 v0, 0x5

    .line 55
    if-lt v0, p2, :cond_3

    .line 56
    .line 57
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 58
    .line 59
    const-string v1, "Reliable Write aborted"

    .line 60
    .line 61
    invoke-virtual {p2, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 62
    .line 63
    .line 64
    :cond_3
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-virtual {p2, v0}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 71
    .line 72
    .line 73
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->A:Lno/nordicsemi/android/ble/j0;

    .line 74
    .line 75
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    const/4 v0, -0x4

    .line 80
    invoke-virtual {p2, v0, p1}, Lno/nordicsemi/android/ble/j0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    new-instance v1, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    const-string v2, "onReliableWriteCompleted execute "

    .line 87
    .line 88
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v0, ", error "

    .line 95
    .line 96
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    const-string v1, "BleManager"

    .line 107
    .line 108
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 112
    .line 113
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    invoke-virtual {v0, p2, v1}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 121
    .line 122
    .line 123
    invoke-static {p0, p2}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    .line 124
    .line 125
    .line 126
    :goto_1
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/d;->b()Z

    .line 127
    .line 128
    .line 129
    invoke-virtual {p0, v3}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 130
    .line 131
    .line 132
    return-void
.end method

.method public onServiceChanged(Landroid/bluetooth/BluetoothGatt;)V
    .locals 3
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 4
    .line 5
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x4

    .line 10
    if-lt v1, v0, :cond_0

    .line 11
    .line 12
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 13
    .line 14
    const-string v2, "Service changed, invalidating services"

    .line 15
    .line 16
    invoke-virtual {v0, v1, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 21
    .line 22
    iget-object v1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 23
    .line 24
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->onServicesInvalidated()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    const/4 v1, -0x3

    .line 31
    invoke-virtual {p0, v1}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 32
    .line 33
    .line 34
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 38
    .line 39
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 40
    .line 41
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    const/4 v1, 0x2

    .line 46
    if-lt v1, v0, :cond_1

    .line 47
    .line 48
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 49
    .line 50
    const-string v2, "Discovering Services..."

    .line 51
    .line 52
    invoke-virtual {v0, v1, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 56
    .line 57
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    const/4 v1, 0x3

    .line 62
    if-lt v1, v0, :cond_2

    .line 63
    .line 64
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 65
    .line 66
    const-string v0, "gatt.discoverServices()"

    .line 67
    .line 68
    invoke-virtual {p0, v1, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    :cond_2
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->discoverServices()Z

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public final onServicesDiscovered(Landroid/bluetooth/BluetoothGatt;I)V
    .locals 5

    .line 1
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-nez p2, :cond_7

    .line 13
    .line 14
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 15
    .line 16
    invoke-virtual {p2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    const/4 v2, 0x4

    .line 21
    if-lt v2, p2, :cond_1

    .line 22
    .line 23
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 24
    .line 25
    const-string v3, "Services discovered"

    .line 26
    .line 27
    invoke-virtual {p2, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    const/4 p2, 0x1

    .line 31
    iput-boolean p2, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 32
    .line 33
    iget-object v3, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 34
    .line 35
    invoke-virtual {v3, p1}, Lno/nordicsemi/android/ble/e;->isRequiredServiceSupported(Landroid/bluetooth/BluetoothGatt;)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_5

    .line 40
    .line 41
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 42
    .line 43
    invoke-virtual {v2}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    const/4 v3, 0x2

    .line 48
    if-lt v3, v2, :cond_2

    .line 49
    .line 50
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 51
    .line 52
    const-string v4, "Primary service found"

    .line 53
    .line 54
    invoke-virtual {v2, v3, v4}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    :cond_2
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->j:Z

    .line 58
    .line 59
    iget-object v2, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 60
    .line 61
    invoke-virtual {v2, p1}, Lno/nordicsemi/android/ble/e;->isOptionalServiceSupported(Landroid/bluetooth/BluetoothGatt;)Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-eqz p1, :cond_3

    .line 66
    .line 67
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 68
    .line 69
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-lt v3, p1, :cond_3

    .line 74
    .line 75
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 76
    .line 77
    const-string v2, "Secondary service found"

    .line 78
    .line 79
    invoke-virtual {p1, v3, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    :cond_3
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    iput-boolean p2, p0, Lno/nordicsemi/android/ble/d;->p:Z

    .line 88
    .line 89
    iput-boolean p2, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 90
    .line 91
    iput-object v1, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 92
    .line 93
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 94
    .line 95
    if-nez p1, :cond_4

    .line 96
    .line 97
    new-instance p1, Ljava/util/concurrent/LinkedBlockingDeque;

    .line 98
    .line 99
    invoke-direct {p1}, Ljava/util/concurrent/LinkedBlockingDeque;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object p1, p0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 103
    .line 104
    :cond_4
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 105
    .line 106
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->initialize()V

    .line 107
    .line 108
    .line 109
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 110
    .line 111
    invoke-virtual {p0, p2}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_5
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 116
    .line 117
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 118
    .line 119
    .line 120
    move-result p1

    .line 121
    const/4 v0, 0x5

    .line 122
    if-lt v0, p1, :cond_6

    .line 123
    .line 124
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 125
    .line 126
    const-string v1, "Device is not supported"

    .line 127
    .line 128
    invoke-virtual {p1, v0, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 129
    .line 130
    .line 131
    :cond_6
    iput-boolean p2, p0, Lno/nordicsemi/android/ble/d;->j:Z

    .line 132
    .line 133
    iget-object p1, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 134
    .line 135
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p0, v2}, Lno/nordicsemi/android/ble/d;->o(I)V

    .line 139
    .line 140
    .line 141
    return-void

    .line 142
    :cond_7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 143
    .line 144
    const-string v2, "onServicesDiscovered error "

    .line 145
    .line 146
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    const-string v2, "BleManager"

    .line 157
    .line 158
    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 159
    .line 160
    .line 161
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 162
    .line 163
    .line 164
    invoke-static {p0, p2}, Lno/nordicsemi/android/ble/d;->a(Lno/nordicsemi/android/ble/d;I)V

    .line 165
    .line 166
    .line 167
    iget-object p2, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 168
    .line 169
    if-eqz p2, :cond_8

    .line 170
    .line 171
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    const/4 v0, -0x4

    .line 176
    invoke-virtual {p2, v0, p1}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 177
    .line 178
    .line 179
    iput-object v1, p0, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 180
    .line 181
    :cond_8
    const/4 p1, -0x1

    .line 182
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/d;->o(I)V

    .line 183
    .line 184
    .line 185
    return-void
.end method
