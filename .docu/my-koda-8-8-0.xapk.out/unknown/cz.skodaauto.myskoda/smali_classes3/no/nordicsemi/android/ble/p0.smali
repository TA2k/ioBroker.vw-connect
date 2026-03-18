.class public abstract Lno/nordicsemi/android/ble/p0;
.super Lno/nordicsemi/android/ble/i0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public m:Lno/nordicsemi/android/ble/o0;

.field public n:Z

.field public o:J


# virtual methods
.method public a(ILandroid/bluetooth/BluetoothDevice;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 6
    .line 7
    iget-object v1, v1, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 8
    .line 9
    invoke-virtual {v1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput-object v0, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 14
    .line 15
    :cond_0
    invoke-super {p0, p1, p2}, Lno/nordicsemi/android/ble/i0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 6
    .line 7
    iget-object v1, v1, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 8
    .line 9
    invoke-virtual {v1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput-object v0, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 14
    .line 15
    :cond_0
    invoke-super {p0}, Lno/nordicsemi/android/ble/i0;->b()V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final c(Landroid/bluetooth/BluetoothDevice;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lno/nordicsemi/android/ble/p0;->o:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v2, v0, v2

    .line 6
    .line 7
    if-lez v2, :cond_0

    .line 8
    .line 9
    new-instance v2, Lno/nordicsemi/android/ble/o0;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v2, v3, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 16
    .line 17
    iget-object v3, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 18
    .line 19
    invoke-virtual {v3, v2, v0, v1}, Lno/nordicsemi/android/ble/d;->E(Ljava/lang/Runnable;J)V

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->c(Landroid/bluetooth/BluetoothDevice;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public d(Landroid/bluetooth/BluetoothDevice;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lno/nordicsemi/android/ble/i0;->b:Lno/nordicsemi/android/ble/d;

    .line 6
    .line 7
    iget-object v1, v1, Lno/nordicsemi/android/ble/d;->e:Landroid/os/Handler;

    .line 8
    .line 9
    invoke-virtual {v1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput-object v0, p0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 14
    .line 15
    :cond_0
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public final f()V
    .locals 2

    .line 1
    iget-object v0, p0, Lno/nordicsemi/android/ble/i0;->a:Lno/nordicsemi/android/ble/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-boolean v1, p0, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    iget-boolean v1, v0, Lno/nordicsemi/android/ble/d;->h:Z

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->g:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v1, v0, Lno/nordicsemi/android/ble/d;->f:Ljava/util/concurrent/LinkedBlockingDeque;

    .line 20
    .line 21
    :goto_0
    invoke-interface {v1, p0}, Ljava/util/Deque;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/i0;->i:Z

    .line 26
    .line 27
    :cond_1
    const/4 p0, 0x0

    .line 28
    invoke-virtual {v0, p0}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final g(Lno/nordicsemi/android/ble/d;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lno/nordicsemi/android/ble/i0;->e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;

    .line 2
    .line 3
    .line 4
    return-void
.end method
