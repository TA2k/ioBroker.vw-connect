.class public final Lno/nordicsemi/android/ble/g0;
.super Lno/nordicsemi/android/ble/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public q:Z

.field public r:Z


# virtual methods
.method public final e(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/i0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final h()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lno/nordicsemi/android/ble/p0;->n:Z

    .line 3
    .line 4
    invoke-super {p0}, Lno/nordicsemi/android/ble/j0;->h()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final i()Lno/nordicsemi/android/ble/i0;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/g0;->q:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/g0;->q:Z

    .line 7
    .line 8
    new-instance p0, Lno/nordicsemi/android/ble/l0;

    .line 9
    .line 10
    const/16 v0, 0xd

    .line 11
    .line 12
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/j0;->p:Ljava/util/LinkedList;

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    iput-boolean v1, p0, Lno/nordicsemi/android/ble/g0;->r:Z

    .line 25
    .line 26
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/p0;->n:Z

    .line 27
    .line 28
    if-eqz p0, :cond_1

    .line 29
    .line 30
    new-instance p0, Lno/nordicsemi/android/ble/l0;

    .line 31
    .line 32
    const/16 v0, 0xf

    .line 33
    .line 34
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    new-instance p0, Lno/nordicsemi/android/ble/l0;

    .line 39
    .line 40
    const/16 v0, 0xe

    .line 41
    .line 42
    invoke-direct {p0, v0}, Lno/nordicsemi/android/ble/i0;-><init>(I)V

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_2
    invoke-super {p0}, Lno/nordicsemi/android/ble/j0;->i()Lno/nordicsemi/android/ble/i0;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public final j()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lno/nordicsemi/android/ble/g0;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0}, Lno/nordicsemi/android/ble/j0;->j()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/g0;->r:Z

    .line 11
    .line 12
    xor-int/lit8 p0, p0, 0x1

    .line 13
    .line 14
    return p0
.end method

.method public final l(Lno/nordicsemi/android/ble/d;)Lno/nordicsemi/android/ble/j0;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lno/nordicsemi/android/ble/p0;->g(Lno/nordicsemi/android/ble/d;)V

    .line 2
    .line 3
    .line 4
    return-object p0
.end method
