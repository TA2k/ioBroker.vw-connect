.class public final Lgp/f;
.super Lno/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Landroidx/collection/a1;

.field public final B:Landroidx/collection/a1;

.field public final z:Landroidx/collection/a1;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Llo/s;Llo/s;)V
    .locals 8

    .line 1
    const/16 v3, 0x17

    .line 2
    .line 3
    const/4 v7, 0x0

    .line 4
    move-object v0, p0

    .line 5
    move-object v1, p1

    .line 6
    move-object v2, p2

    .line 7
    move-object v4, p3

    .line 8
    move-object v5, p4

    .line 9
    move-object v6, p5

    .line 10
    invoke-direct/range {v0 .. v7}, Lno/i;-><init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Landroidx/collection/a1;

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    invoke-direct {p0, p1}, Landroidx/collection/a1;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object p0, v0, Lgp/f;->z:Landroidx/collection/a1;

    .line 20
    .line 21
    new-instance p0, Landroidx/collection/a1;

    .line 22
    .line 23
    invoke-direct {p0, p1}, Landroidx/collection/a1;-><init>(I)V

    .line 24
    .line 25
    .line 26
    iput-object p0, v0, Lgp/f;->A:Landroidx/collection/a1;

    .line 27
    .line 28
    new-instance p0, Landroidx/collection/a1;

    .line 29
    .line 30
    invoke-direct {p0, p1}, Landroidx/collection/a1;-><init>(I)V

    .line 31
    .line 32
    .line 33
    iput-object p0, v0, Lgp/f;->B:Landroidx/collection/a1;

    .line 34
    .line 35
    new-instance p0, Landroidx/collection/a1;

    .line 36
    .line 37
    invoke-direct {p0, p1}, Landroidx/collection/a1;-><init>(I)V

    .line 38
    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final C(Lgp/l;Laq/k;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lno/e;->k()[Ljo/d;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    array-length v2, v0

    .line 9
    const/4 v3, 0x0

    .line 10
    if-ge v1, v2, :cond_1

    .line 11
    .line 12
    aget-object v2, v0, v1

    .line 13
    .line 14
    const-string v4, "geofences_with_callback"

    .line 15
    .line 16
    iget-object v5, v2, Ljo/d;->d:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    if-eqz v4, :cond_0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move-object v2, v3

    .line 29
    :goto_1
    if-nez v2, :cond_2

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    invoke-virtual {v2}, Ljo/d;->x0()J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    const-wide/16 v4, 0x1

    .line 37
    .line 38
    cmp-long v0, v0, v4

    .line 39
    .line 40
    if-ltz v0, :cond_3

    .line 41
    .line 42
    invoke-virtual {p0}, Lno/e;->r()Landroid/os/IInterface;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lgp/v;

    .line 47
    .line 48
    new-instance v0, Lbp/r;

    .line 49
    .line 50
    const/4 v1, 0x1

    .line 51
    invoke-direct {v0, v3, p2, v1}, Lbp/r;-><init>(Ljava/lang/Object;Laq/k;I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    invoke-static {p2, p1}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 62
    .line 63
    .line 64
    const/16 p1, 0x62

    .line 65
    .line 66
    invoke-virtual {p0, p2, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :cond_3
    :goto_2
    invoke-virtual {p0}, Lno/e;->r()Landroid/os/IInterface;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    check-cast p0, Lgp/v;

    .line 75
    .line 76
    new-instance v0, Lgp/d;

    .line 77
    .line 78
    const/4 v1, 0x1

    .line 79
    invoke-direct {v0, v1, p2}, Lgp/d;-><init>(ILaq/k;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    invoke-static {p2, p1}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 90
    .line 91
    .line 92
    const/16 p1, 0x4a

    .line 93
    .line 94
    invoke-virtual {p0, p2, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 95
    .line 96
    .line 97
    return-void
.end method

.method public final j()I
    .locals 0

    .line 1
    const p0, 0xb2c988

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method public final m(Landroid/os/IBinder;)Landroid/os/IInterface;
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    const-string p0, "com.google.android.gms.location.internal.IGoogleLocationManagerService"

    .line 6
    .line 7
    invoke-interface {p1, p0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    instance-of v1, v0, Lgp/v;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    check-cast v0, Lgp/v;

    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_1
    new-instance v0, Lgp/v;

    .line 19
    .line 20
    const/4 v1, 0x4

    .line 21
    invoke-direct {v0, p1, p0, v1}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public final o()[Ljo/d;
    .locals 0

    .line 1
    sget-object p0, Lpp/k;->a:[Ljo/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "com.google.android.gms.location.internal.IGoogleLocationManagerService"

    .line 2
    .line 3
    return-object p0
.end method

.method public final t()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "com.google.android.location.internal.GoogleLocationManagerService.START"

    .line 2
    .line 3
    return-object p0
.end method

.method public final w()V
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lgp/f;->z:Landroidx/collection/a1;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object v1, p0, Lgp/f;->z:Landroidx/collection/a1;

    .line 8
    .line 9
    invoke-virtual {v1}, Landroidx/collection/a1;->clear()V

    .line 10
    .line 11
    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 13
    iget-object v1, p0, Lgp/f;->A:Landroidx/collection/a1;

    .line 14
    .line 15
    monitor-enter v1

    .line 16
    :try_start_1
    iget-object v0, p0, Lgp/f;->A:Landroidx/collection/a1;

    .line 17
    .line 18
    invoke-virtual {v0}, Landroidx/collection/a1;->clear()V

    .line 19
    .line 20
    .line 21
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 22
    iget-object v0, p0, Lgp/f;->B:Landroidx/collection/a1;

    .line 23
    .line 24
    monitor-enter v0

    .line 25
    :try_start_2
    iget-object p0, p0, Lgp/f;->B:Landroidx/collection/a1;

    .line 26
    .line 27
    invoke-virtual {p0}, Landroidx/collection/a1;->clear()V

    .line 28
    .line 29
    .line 30
    monitor-exit v0

    .line 31
    return-void

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 34
    throw p0

    .line 35
    :catchall_1
    move-exception p0

    .line 36
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 37
    throw p0

    .line 38
    :catchall_2
    move-exception p0

    .line 39
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 40
    throw p0
.end method

.method public final z()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
