.class public final synthetic Lno/nordicsemi/android/ble/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/nordicsemi/android/ble/s;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Landroid/bluetooth/BluetoothDevice;


# direct methods
.method public synthetic constructor <init>(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    iput p1, p0, Lno/nordicsemi/android/ble/g;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lno/nordicsemi/android/ble/g;->b:Landroid/bluetooth/BluetoothDevice;

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
    iget v0, p0, Lno/nordicsemi/android/ble/g;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/g;->b:Landroid/bluetooth/BluetoothDevice;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-interface {p1, p0}, Lb01/b;->onDeviceReady(Landroid/bluetooth/BluetoothDevice;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    invoke-interface {p1, p0}, Lb01/b;->onDeviceDisconnecting(Landroid/bluetooth/BluetoothDevice;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_1
    const/4 v0, 0x0

    .line 17
    invoke-interface {p1, p0, v0}, Lb01/b;->onDeviceDisconnected(Landroid/bluetooth/BluetoothDevice;I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_2
    invoke-interface {p1, p0}, Lb01/b;->onDeviceConnecting(Landroid/bluetooth/BluetoothDevice;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_3
    invoke-interface {p1, p0}, Lb01/b;->onDeviceConnecting(Landroid/bluetooth/BluetoothDevice;)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
