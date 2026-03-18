.class public final synthetic Lno/nordicsemi/android/ble/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyz0/b;

.field public final synthetic f:Landroid/bluetooth/BluetoothDevice;

.field public final synthetic g:Lzz0/a;


# direct methods
.method public synthetic constructor <init>(Lyz0/b;Landroid/bluetooth/BluetoothDevice;Lzz0/a;I)V
    .locals 0

    .line 1
    iput p4, p0, Lno/nordicsemi/android/ble/d0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lno/nordicsemi/android/ble/d0;->e:Lyz0/b;

    .line 4
    .line 5
    iput-object p2, p0, Lno/nordicsemi/android/ble/d0;->f:Landroid/bluetooth/BluetoothDevice;

    .line 6
    .line 7
    iput-object p3, p0, Lno/nordicsemi/android/ble/d0;->g:Lzz0/a;

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
    .locals 5

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/d0;->d:I

    .line 2
    .line 3
    const-string v1, "i0"

    .line 4
    .line 5
    const-string v2, "Exception in Value callback"

    .line 6
    .line 7
    iget-object v3, p0, Lno/nordicsemi/android/ble/d0;->g:Lzz0/a;

    .line 8
    .line 9
    iget-object v4, p0, Lno/nordicsemi/android/ble/d0;->f:Landroid/bluetooth/BluetoothDevice;

    .line 10
    .line 11
    iget-object p0, p0, Lno/nordicsemi/android/ble/d0;->e:Lyz0/b;

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    :try_start_0
    invoke-interface {p0, v4, v3}, Lyz0/b;->a(Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    invoke-static {v1, v2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 22
    .line 23
    .line 24
    :goto_0
    return-void

    .line 25
    :pswitch_0
    :try_start_1
    invoke-interface {p0, v4, v3}, Lyz0/b;->a(Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :catchall_1
    move-exception p0

    .line 30
    const-string v0, "r0"

    .line 31
    .line 32
    invoke-static {v0, v2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 33
    .line 34
    .line 35
    :goto_1
    return-void

    .line 36
    :pswitch_1
    :try_start_2
    invoke-interface {p0, v4, v3}, Lyz0/b;->a(Landroid/bluetooth/BluetoothDevice;Lzz0/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 37
    .line 38
    .line 39
    goto :goto_2

    .line 40
    :catchall_2
    move-exception p0

    .line 41
    invoke-static {v1, v2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 42
    .line 43
    .line 44
    :goto_2
    return-void

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
