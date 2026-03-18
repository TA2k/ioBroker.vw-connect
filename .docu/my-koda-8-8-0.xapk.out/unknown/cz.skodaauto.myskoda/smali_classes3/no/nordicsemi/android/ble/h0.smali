.class public final synthetic Lno/nordicsemi/android/ble/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lno/nordicsemi/android/ble/i0;


# direct methods
.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/i0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lno/nordicsemi/android/ble/h0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/h0;->e:Lno/nordicsemi/android/ble/i0;

    return-void
.end method

.method public synthetic constructor <init>(Lno/nordicsemi/android/ble/i0;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 2
    const/4 p2, 0x0

    iput p2, p0, Lno/nordicsemi/android/ble/h0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lno/nordicsemi/android/ble/h0;->e:Lno/nordicsemi/android/ble/i0;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/h0;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lno/nordicsemi/android/ble/h0;->e:Lno/nordicsemi/android/ble/i0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Lno/nordicsemi/android/ble/i0;->f:Lno/nordicsemi/android/ble/b;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    :try_start_0
    iget-object p0, p0, Lno/nordicsemi/android/ble/b;->e:Lno/nordicsemi/android/ble/e;

    .line 17
    .line 18
    iget-object p0, p0, Lno/nordicsemi/android/ble/e;->requestHandler:Lno/nordicsemi/android/ble/d;

    .line 19
    .line 20
    iget-object v0, p0, Lno/nordicsemi/android/ble/d;->D:Lno/nordicsemi/android/ble/r0;

    .line 21
    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    new-instance v0, Lno/nordicsemi/android/ble/r0;

    .line 25
    .line 26
    invoke-direct {v0, p0}, Lno/nordicsemi/android/ble/r0;-><init>(Lno/nordicsemi/android/ble/d;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lno/nordicsemi/android/ble/j;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    invoke-direct {v1, p0, v2}, Lno/nordicsemi/android/ble/j;-><init>(Lno/nordicsemi/android/ble/d;I)V

    .line 33
    .line 34
    .line 35
    iput-object v1, v0, Lno/nordicsemi/android/ble/r0;->a:Lyz0/b;

    .line 36
    .line 37
    iput-object v0, p0, Lno/nordicsemi/android/ble/d;->D:Lno/nordicsemi/android/ble/r0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    const-string v0, "i0"

    .line 42
    .line 43
    const-string v1, "Exception in Before callback"

    .line 44
    .line 45
    invoke-static {v0, v1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 46
    .line 47
    .line 48
    :cond_0
    :goto_0
    return-void

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
