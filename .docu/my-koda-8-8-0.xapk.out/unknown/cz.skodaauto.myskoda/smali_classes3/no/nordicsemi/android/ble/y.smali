.class public final synthetic Lno/nordicsemi/android/ble/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno/nordicsemi/android/ble/i0;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/c0;Landroid/bluetooth/BluetoothDevice;II)V
    .locals 0

    .line 2
    const/4 p2, 0x1

    iput p2, p0, Lno/nordicsemi/android/ble/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/y;->e:Lno/nordicsemi/android/ble/i0;

    return-void
.end method

.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/f0;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 3
    const/4 p2, 0x2

    iput p2, p0, Lno/nordicsemi/android/ble/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/y;->e:Lno/nordicsemi/android/ble/i0;

    return-void
.end method

.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/s0;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 4
    const/4 p2, 0x3

    iput p2, p0, Lno/nordicsemi/android/ble/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/y;->e:Lno/nordicsemi/android/ble/i0;

    return-void
.end method

.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/z;Landroid/bluetooth/BluetoothDevice;III)V
    .locals 0

    .line 1
    const/4 p2, 0x0

    iput p2, p0, Lno/nordicsemi/android/ble/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/y;->e:Lno/nordicsemi/android/ble/i0;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/y;->d:I

    .line 2
    .line 3
    const-string v1, "Exception in Value callback"

    .line 4
    .line 5
    const-string v2, "i0"

    .line 6
    .line 7
    iget-object p0, p0, Lno/nordicsemi/android/ble/y;->e:Lno/nordicsemi/android/ble/i0;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p0, Lno/nordicsemi/android/ble/s0;

    .line 13
    .line 14
    iget-object p0, p0, Lno/nordicsemi/android/ble/q0;->p:Lno/nordicsemi/android/ble/j;

    .line 15
    .line 16
    if-nez p0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    :try_start_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    invoke-static {v2, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 27
    .line 28
    .line 29
    :goto_0
    return-void

    .line 30
    :pswitch_0
    check-cast p0, Lno/nordicsemi/android/ble/f0;

    .line 31
    .line 32
    iget-object p0, p0, Lno/nordicsemi/android/ble/m0;->m:Ltechnology/cariad/cat/genx/bluetooth/q;

    .line 33
    .line 34
    if-nez p0, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    :try_start_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 38
    .line 39
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 40
    .line 41
    .line 42
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 43
    :catchall_1
    move-exception p0

    .line 44
    invoke-static {v2, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 45
    .line 46
    .line 47
    :goto_1
    return-void

    .line 48
    :pswitch_1
    check-cast p0, Lno/nordicsemi/android/ble/c0;

    .line 49
    .line 50
    iget-object p0, p0, Lno/nordicsemi/android/ble/m0;->m:Ltechnology/cariad/cat/genx/bluetooth/q;

    .line 51
    .line 52
    if-nez p0, :cond_2

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_2
    :try_start_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 61
    :catchall_2
    move-exception p0

    .line 62
    invoke-static {v2, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 63
    .line 64
    .line 65
    :goto_2
    return-void

    .line 66
    :pswitch_2
    check-cast p0, Lno/nordicsemi/android/ble/z;

    .line 67
    .line 68
    iget-object p0, p0, Lno/nordicsemi/android/ble/m0;->m:Ltechnology/cariad/cat/genx/bluetooth/q;

    .line 69
    .line 70
    if-nez p0, :cond_3

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    :try_start_3
    new-instance p0, Ljava/lang/ClassCastException;

    .line 74
    .line 75
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 76
    .line 77
    .line 78
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 79
    :catchall_3
    move-exception p0

    .line 80
    invoke-static {v2, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 81
    .line 82
    .line 83
    :goto_3
    return-void

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
