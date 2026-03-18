.class public final synthetic Lno/nordicsemi/android/ble/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/nordicsemi/android/ble/v;
.implements Lyz0/d;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno/nordicsemi/android/ble/e;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lno/nordicsemi/android/ble/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/b;->e:Lno/nordicsemi/android/ble/e;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/b;->d:I

    .line 2
    .line 3
    check-cast p1, Landroid/bluetooth/BluetoothGattCharacteristic;

    .line 4
    .line 5
    iget-object p0, p0, Lno/nordicsemi/android/ble/b;->e:Lno/nordicsemi/android/ble/e;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    sget-object v1, Lno/nordicsemi/android/ble/e;->CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

    .line 18
    .line 19
    invoke-virtual {p1, v1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getDescriptor(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattDescriptor;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    if-nez p1, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    if-eqz p0, :cond_2

    .line 36
    .line 37
    array-length p1, p0

    .line 38
    const/4 v1, 0x2

    .line 39
    if-ne p1, v1, :cond_2

    .line 40
    .line 41
    aget-byte p0, p0, v0

    .line 42
    .line 43
    and-int/2addr p0, v1

    .line 44
    if-ne p0, v1, :cond_2

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    :cond_2
    :goto_0
    return v0

    .line 48
    :pswitch_0
    const/4 v0, 0x0

    .line 49
    if-nez p1, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    sget-object v1, Lno/nordicsemi/android/ble/e;->CLIENT_CHARACTERISTIC_CONFIG_DESCRIPTOR_UUID:Ljava/util/UUID;

    .line 53
    .line 54
    invoke-virtual {p1, v1}, Landroid/bluetooth/BluetoothGattCharacteristic;->getDescriptor(Ljava/util/UUID;)Landroid/bluetooth/BluetoothGattDescriptor;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-nez p1, :cond_4

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_4
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 62
    .line 63
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothGattDescriptor;->getValue()[B

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-eqz p0, :cond_5

    .line 71
    .line 72
    array-length p1, p0

    .line 73
    const/4 v1, 0x2

    .line 74
    if-ne p1, v1, :cond_5

    .line 75
    .line 76
    aget-byte p0, p0, v0

    .line 77
    .line 78
    const/4 p1, 0x1

    .line 79
    and-int/2addr p0, p1

    .line 80
    if-ne p0, p1, :cond_5

    .line 81
    .line 82
    move v0, p1

    .line 83
    :cond_5
    :goto_1
    return v0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public e(Landroid/bluetooth/BluetoothDevice;)V
    .locals 1

    .line 1
    iget p1, p0, Lno/nordicsemi/android/ble/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x4

    .line 7
    const-string v0, "Battery Level notifications disabled"

    .line 8
    .line 9
    iget-object p0, p0, Lno/nordicsemi/android/ble/b;->e:Lno/nordicsemi/android/ble/e;

    .line 10
    .line 11
    invoke-virtual {p0, p1, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    const/4 p1, 0x4

    .line 16
    const-string v0, "Battery Level notifications enabled"

    .line 17
    .line 18
    iget-object p0, p0, Lno/nordicsemi/android/ble/b;->e:Lno/nordicsemi/android/ble/e;

    .line 19
    .line 20
    invoke-virtual {p0, p1, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method
