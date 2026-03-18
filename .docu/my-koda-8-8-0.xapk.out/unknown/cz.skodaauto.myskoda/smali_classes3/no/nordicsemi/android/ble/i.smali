.class public final synthetic Lno/nordicsemi/android/ble/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/nordicsemi/android/ble/s;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Landroid/bluetooth/BluetoothDevice;

.field public final synthetic c:I


# direct methods
.method public synthetic constructor <init>(IILandroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    iput p2, p0, Lno/nordicsemi/android/ble/i;->a:I

    .line 2
    .line 3
    iput-object p3, p0, Lno/nordicsemi/android/ble/i;->b:Landroid/bluetooth/BluetoothDevice;

    .line 4
    .line 5
    iput p1, p0, Lno/nordicsemi/android/ble/i;->c:I

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lb01/b;)V
    .locals 1

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/i;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lno/nordicsemi/android/ble/i;->b:Landroid/bluetooth/BluetoothDevice;

    .line 7
    .line 8
    iget p0, p0, Lno/nordicsemi/android/ble/i;->c:I

    .line 9
    .line 10
    invoke-interface {p1, v0, p0}, Lb01/b;->onDeviceDisconnected(Landroid/bluetooth/BluetoothDevice;I)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/i;->b:Landroid/bluetooth/BluetoothDevice;

    .line 15
    .line 16
    iget p0, p0, Lno/nordicsemi/android/ble/i;->c:I

    .line 17
    .line 18
    invoke-interface {p1, v0, p0}, Lb01/b;->onDeviceDisconnected(Landroid/bluetooth/BluetoothDevice;I)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/i;->b:Landroid/bluetooth/BluetoothDevice;

    .line 23
    .line 24
    iget p0, p0, Lno/nordicsemi/android/ble/i;->c:I

    .line 25
    .line 26
    invoke-interface {p1, v0, p0}, Lb01/b;->onDeviceDisconnected(Landroid/bluetooth/BluetoothDevice;I)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_2
    iget-object v0, p0, Lno/nordicsemi/android/ble/i;->b:Landroid/bluetooth/BluetoothDevice;

    .line 31
    .line 32
    iget p0, p0, Lno/nordicsemi/android/ble/i;->c:I

    .line 33
    .line 34
    invoke-interface {p1, v0, p0}, Lb01/b;->onDeviceFailedToConnect(Landroid/bluetooth/BluetoothDevice;I)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
