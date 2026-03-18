.class public final synthetic Lno/nordicsemi/android/ble/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/nordicsemi/android/ble/s;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Landroid/bluetooth/BluetoothGatt;


# direct methods
.method public synthetic constructor <init>(Landroid/bluetooth/BluetoothGatt;I)V
    .locals 0

    .line 1
    iput p2, p0, Lno/nordicsemi/android/ble/o;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/o;->b:Landroid/bluetooth/BluetoothGatt;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lb01/b;)V
    .locals 1

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/o;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/o;->b:Landroid/bluetooth/BluetoothGatt;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->b:I

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 v0, 0x5

    .line 15
    invoke-interface {p1, p0, v0}, Lb01/b;->onDeviceFailedToConnect(Landroid/bluetooth/BluetoothDevice;I)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    sget v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->b:I

    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p1, p0}, Lb01/b;->onDeviceConnected(Landroid/bluetooth/BluetoothDevice;)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
