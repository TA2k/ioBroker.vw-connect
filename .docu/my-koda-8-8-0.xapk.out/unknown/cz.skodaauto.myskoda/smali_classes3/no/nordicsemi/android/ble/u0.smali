.class public final synthetic Lno/nordicsemi/android/ble/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno/nordicsemi/android/ble/v0;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/v0;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    const/4 p2, 0x1

    iput p2, p0, Lno/nordicsemi/android/ble/u0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/u0;->e:Lno/nordicsemi/android/ble/v0;

    return-void
.end method

.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/v0;Landroid/bluetooth/BluetoothDevice;[BI)V
    .locals 0

    .line 2
    const/4 p2, 0x0

    iput p2, p0, Lno/nordicsemi/android/ble/u0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/u0;->e:Lno/nordicsemi/android/ble/v0;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/u0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/u0;->e:Lno/nordicsemi/android/ble/v0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lno/nordicsemi/android/ble/q0;->p:Lno/nordicsemi/android/ble/j;

    .line 9
    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    :try_start_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    const-string v0, "i0"

    .line 21
    .line 22
    const-string v1, "Exception in Value callback"

    .line 23
    .line 24
    invoke-static {v0, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 25
    .line 26
    .line 27
    :goto_0
    return-void

    .line 28
    :pswitch_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
