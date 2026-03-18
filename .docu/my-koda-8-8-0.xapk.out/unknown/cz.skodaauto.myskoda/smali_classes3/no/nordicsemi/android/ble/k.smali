.class public final synthetic Lno/nordicsemi/android/ble/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno/nordicsemi/android/ble/d;

.field public final synthetic f:Lno/nordicsemi/android/ble/i0;

.field public final synthetic g:Landroid/bluetooth/BluetoothDevice;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/d;Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    iput p4, p0, Lno/nordicsemi/android/ble/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/k;->e:Lno/nordicsemi/android/ble/d;

    .line 4
    .line 5
    iput-object p2, p0, Lno/nordicsemi/android/ble/k;->f:Lno/nordicsemi/android/ble/i0;

    .line 6
    .line 7
    iput-object p3, p0, Lno/nordicsemi/android/ble/k;->g:Landroid/bluetooth/BluetoothDevice;

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
    iget v0, p0, Lno/nordicsemi/android/ble/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lno/nordicsemi/android/ble/k;->e:Lno/nordicsemi/android/ble/d;

    .line 7
    .line 8
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 9
    .line 10
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x4

    .line 15
    if-lt v2, v1, :cond_0

    .line 16
    .line 17
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 18
    .line 19
    const-string v3, "Cache refreshed"

    .line 20
    .line 21
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    iget-object v1, p0, Lno/nordicsemi/android/ble/k;->f:Lno/nordicsemi/android/ble/i0;

    .line 25
    .line 26
    iget-object p0, p0, Lno/nordicsemi/android/ble/k;->g:Landroid/bluetooth/BluetoothDevice;

    .line 27
    .line 28
    invoke-virtual {v1, p0}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    iput-object v1, v0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 33
    .line 34
    iget-object v2, v0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 35
    .line 36
    const/4 v3, -0x3

    .line 37
    if-eqz v2, :cond_1

    .line 38
    .line 39
    invoke-virtual {v2, v3, p0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 40
    .line 41
    .line 42
    iput-object v1, v0, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 43
    .line 44
    :cond_1
    invoke-virtual {v0, v3}, Lno/nordicsemi/android/ble/d;->f(I)V

    .line 45
    .line 46
    .line 47
    iget-object p0, v0, Lno/nordicsemi/android/ble/d;->c:Landroid/bluetooth/BluetoothGatt;

    .line 48
    .line 49
    iget-boolean v1, v0, Lno/nordicsemi/android/ble/d;->n:Z

    .line 50
    .line 51
    if-eqz v1, :cond_4

    .line 52
    .line 53
    if-eqz p0, :cond_4

    .line 54
    .line 55
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 56
    .line 57
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->onServicesInvalidated()V

    .line 58
    .line 59
    .line 60
    const/4 v1, 0x1

    .line 61
    iput-boolean v1, v0, Lno/nordicsemi/android/ble/d;->k:Z

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    iput-boolean v1, v0, Lno/nordicsemi/android/ble/d;->i:Z

    .line 65
    .line 66
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 67
    .line 68
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    const/4 v2, 0x2

    .line 73
    if-lt v2, v1, :cond_2

    .line 74
    .line 75
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 76
    .line 77
    const-string v3, "Discovering Services..."

    .line 78
    .line 79
    invoke-virtual {v1, v2, v3}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    :cond_2
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 83
    .line 84
    invoke-virtual {v1}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    const/4 v2, 0x3

    .line 89
    if-lt v2, v1, :cond_3

    .line 90
    .line 91
    iget-object v0, v0, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 92
    .line 93
    const-string v1, "gatt.discoverServices()"

    .line 94
    .line 95
    invoke-virtual {v0, v2, v1}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 96
    .line 97
    .line 98
    :cond_3
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothGatt;->discoverServices()Z

    .line 99
    .line 100
    .line 101
    :cond_4
    return-void

    .line 102
    :pswitch_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/k;->e:Lno/nordicsemi/android/ble/d;

    .line 103
    .line 104
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 105
    .line 106
    iget-object v2, p0, Lno/nordicsemi/android/ble/k;->f:Lno/nordicsemi/android/ble/i0;

    .line 107
    .line 108
    if-ne v1, v2, :cond_5

    .line 109
    .line 110
    const/4 v1, -0x5

    .line 111
    iget-object p0, p0, Lno/nordicsemi/android/ble/k;->g:Landroid/bluetooth/BluetoothDevice;

    .line 112
    .line 113
    invoke-virtual {v2, v1, p0}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 114
    .line 115
    .line 116
    const/4 p0, 0x1

    .line 117
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 118
    .line 119
    .line 120
    :cond_5
    return-void

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
