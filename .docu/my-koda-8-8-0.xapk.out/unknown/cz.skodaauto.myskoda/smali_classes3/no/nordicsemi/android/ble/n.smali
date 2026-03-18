.class public final synthetic Lno/nordicsemi/android/ble/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lno/nordicsemi/android/ble/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/n;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lno/nordicsemi/android/ble/n;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lno/nordicsemi/android/ble/n;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lno/nordicsemi/android/ble/n;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lno/nordicsemi/android/ble/d;

    .line 9
    .line 10
    iget-object v1, p0, Lno/nordicsemi/android/ble/n;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lno/nordicsemi/android/ble/z;

    .line 13
    .line 14
    iget-object p0, p0, Lno/nordicsemi/android/ble/n;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Landroid/bluetooth/BluetoothDevice;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, p0}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    iput-boolean p0, v0, Lno/nordicsemi/android/ble/d;->t:Z

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 32
    .line 33
    .line 34
    :cond_0
    return-void

    .line 35
    :pswitch_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/n;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;

    .line 38
    .line 39
    iget-object v1, p0, Lno/nordicsemi/android/ble/n;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Landroid/bluetooth/BluetoothGatt;

    .line 42
    .line 43
    iget-object p0, p0, Lno/nordicsemi/android/ble/n;->g:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lno/nordicsemi/android/ble/x;

    .line 46
    .line 47
    iget-object v0, v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 48
    .line 49
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    invoke-virtual {v0, v2, p0}, Lno/nordicsemi/android/ble/d;->l(Landroid/bluetooth/BluetoothDevice;Lno/nordicsemi/android/ble/x;)Z

    .line 54
    .line 55
    .line 56
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 57
    .line 58
    if-nez p0, :cond_2

    .line 59
    .line 60
    const/4 p0, 0x0

    .line 61
    iput p0, v0, Lno/nordicsemi/android/ble/d;->s:I

    .line 62
    .line 63
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 64
    .line 65
    invoke-virtual {p0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    const/4 v2, 0x4

    .line 70
    if-lt v2, p0, :cond_1

    .line 71
    .line 72
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 73
    .line 74
    const-string v3, "Disconnected"

    .line 75
    .line 76
    invoke-virtual {p0, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    :cond_1
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    new-instance p0, Lno/nordicsemi/android/ble/o;

    .line 85
    .line 86
    const/4 v2, 0x1

    .line 87
    invoke-direct {p0, v1, v2}, Lno/nordicsemi/android/ble/o;-><init>(Landroid/bluetooth/BluetoothGatt;I)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/d;->D(Lno/nordicsemi/android/ble/s;)V

    .line 91
    .line 92
    .line 93
    :cond_2
    return-void

    .line 94
    :pswitch_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/n;->e:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;

    .line 97
    .line 98
    iget-object v1, p0, Lno/nordicsemi/android/ble/n;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v1, Landroid/bluetooth/BluetoothGatt;

    .line 101
    .line 102
    iget-object p0, p0, Lno/nordicsemi/android/ble/n;->g:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p0, Lno/nordicsemi/android/ble/x;

    .line 105
    .line 106
    iget-object v0, v0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 107
    .line 108
    invoke-virtual {v1}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-virtual {v0, v1, p0}, Lno/nordicsemi/android/ble/d;->l(Landroid/bluetooth/BluetoothDevice;Lno/nordicsemi/android/ble/x;)Z

    .line 113
    .line 114
    .line 115
    return-void

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
