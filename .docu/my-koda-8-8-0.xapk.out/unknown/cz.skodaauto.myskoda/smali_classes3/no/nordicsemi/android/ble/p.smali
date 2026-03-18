.class public final synthetic Lno/nordicsemi/android/ble/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/BleManagerHandler$4;ILandroid/bluetooth/BluetoothGatt;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lno/nordicsemi/android/ble/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/p;->f:Ljava/lang/Object;

    iput p2, p0, Lno/nordicsemi/android/ble/p;->e:I

    iput-object p3, p0, Lno/nordicsemi/android/ble/p;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;II)V
    .locals 0

    .line 2
    iput p4, p0, Lno/nordicsemi/android/ble/p;->d:I

    iput-object p1, p0, Lno/nordicsemi/android/ble/p;->f:Ljava/lang/Object;

    iput-object p2, p0, Lno/nordicsemi/android/ble/p;->g:Ljava/lang/Object;

    iput p3, p0, Lno/nordicsemi/android/ble/p;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/p;->d:I

    .line 2
    .line 3
    const-string v1, "i0"

    .line 4
    .line 5
    iget v2, p0, Lno/nordicsemi/android/ble/p;->e:I

    .line 6
    .line 7
    iget-object v3, p0, Lno/nordicsemi/android/ble/p;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object p0, p0, Lno/nordicsemi/android/ble/p;->f:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast p0, Lno/nordicsemi/android/ble/i0;

    .line 15
    .line 16
    check-cast v3, Landroid/bluetooth/BluetoothDevice;

    .line 17
    .line 18
    iget-object p0, p0, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    :try_start_0
    invoke-interface {p0, v2, v3}, Lyz0/c;->b(ILandroid/bluetooth/BluetoothDevice;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    const-string v0, "Exception in Fail callback"

    .line 28
    .line 29
    invoke-static {v1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 30
    .line 31
    .line 32
    :cond_0
    :goto_0
    return-void

    .line 33
    :pswitch_0
    check-cast p0, Lno/nordicsemi/android/ble/b0;

    .line 34
    .line 35
    check-cast v3, Landroid/bluetooth/BluetoothDevice;

    .line 36
    .line 37
    iget-object p0, p0, Lno/nordicsemi/android/ble/m0;->m:Ltechnology/cariad/cat/genx/bluetooth/q;

    .line 38
    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    :try_start_1
    invoke-virtual {p0, v2, v3}, Ltechnology/cariad/cat/genx/bluetooth/q;->a(ILandroid/bluetooth/BluetoothDevice;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :catchall_1
    move-exception p0

    .line 46
    const-string v0, "Exception in Value callback"

    .line 47
    .line 48
    invoke-static {v1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 49
    .line 50
    .line 51
    :cond_1
    :goto_1
    return-void

    .line 52
    :pswitch_1
    check-cast p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;

    .line 53
    .line 54
    check-cast v3, Landroid/bluetooth/BluetoothGatt;

    .line 55
    .line 56
    iget-object p0, p0, Lno/nordicsemi/android/ble/BleManagerHandler$4;->a:Lno/nordicsemi/android/ble/d;

    .line 57
    .line 58
    iget v0, p0, Lno/nordicsemi/android/ble/d;->m:I

    .line 59
    .line 60
    if-eq v2, v0, :cond_2

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 64
    .line 65
    if-eqz v0, :cond_5

    .line 66
    .line 67
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 68
    .line 69
    if-nez v0, :cond_5

    .line 70
    .line 71
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 72
    .line 73
    if-nez v0, :cond_5

    .line 74
    .line 75
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGatt;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothDevice;->getBondState()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    const/16 v1, 0xb

    .line 84
    .line 85
    if-eq v0, v1, :cond_5

    .line 86
    .line 87
    const/4 v0, 0x1

    .line 88
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 89
    .line 90
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 91
    .line 92
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    const/4 v1, 0x2

    .line 97
    if-lt v1, v0, :cond_3

    .line 98
    .line 99
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 100
    .line 101
    const-string v2, "Discovering services..."

    .line 102
    .line 103
    invoke-virtual {v0, v1, v2}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 104
    .line 105
    .line 106
    :cond_3
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 107
    .line 108
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    const/4 v1, 0x3

    .line 113
    if-lt v1, v0, :cond_4

    .line 114
    .line 115
    iget-object p0, p0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 116
    .line 117
    const-string v0, "gatt.discoverServices()"

    .line 118
    .line 119
    invoke-virtual {p0, v1, v0}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 120
    .line 121
    .line 122
    :cond_4
    invoke-virtual {v3}, Landroid/bluetooth/BluetoothGatt;->discoverServices()Z

    .line 123
    .line 124
    .line 125
    :cond_5
    :goto_2
    return-void

    .line 126
    nop

    .line 127
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
