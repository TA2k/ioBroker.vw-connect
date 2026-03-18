.class public final Lqp/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lrp/f;

.field public b:Lh6/e;


# direct methods
.method public constructor <init>(Lrp/f;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v0, Ljava/util/HashMap;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lqp/g;->a:Lrp/f;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lsp/l;)Lsp/k;
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0, p1}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 8
    .line 9
    .line 10
    const/16 v1, 0xb

    .line 11
    .line 12
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Lhp/b;->T(Landroid/os/IBinder;)Lhp/c;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 25
    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    iget p0, p1, Lsp/l;->t:I

    .line 30
    .line 31
    const/4 p1, 0x1

    .line 32
    if-ne p0, p1, :cond_0

    .line 33
    .line 34
    new-instance p0, Lsp/a;

    .line 35
    .line 36
    invoke-direct {p0, v0}, Lsp/k;-><init>(Lhp/c;)V

    .line 37
    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_0
    new-instance p0, Lsp/k;

    .line 41
    .line 42
    invoke-direct {p0, v0}, Lsp/k;-><init>(Lhp/c;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_1
    const/4 p0, 0x0

    .line 47
    return-object p0

    .line 48
    :catch_0
    move-exception p0

    .line 49
    new-instance p1, La8/r0;

    .line 50
    .line 51
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    throw p1
.end method

.method public final b()Lcom/google/android/gms/maps/model/CameraPosition;
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object v0, Lcom/google/android/gms/maps/model/CameraPosition;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 13
    .line 14
    invoke-static {p0, v0}, Lhp/j;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    .line 23
    return-object v0

    .line 24
    :catch_0
    move-exception p0

    .line 25
    new-instance v0, La8/r0;

    .line 26
    .line 27
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw v0
.end method

.method public final c()Lj1/a;
    .locals 5

    .line 1
    :try_start_0
    new-instance v0, Lj1/a;

    .line 2
    .line 3
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 4
    .line 5
    const-string v1, "com.google.android.gms.maps.internal.IProjectionDelegate"

    .line 6
    .line 7
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const/16 v3, 0x1a

    .line 12
    .line 13
    invoke-virtual {p0, v2, v3}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-interface {v2, v1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    instance-of v4, v3, Lrp/b;

    .line 30
    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    move-object v1, v3

    .line 34
    check-cast v1, Lrp/b;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    new-instance v3, Lrp/b;

    .line 38
    .line 39
    const/4 v4, 0x5

    .line 40
    invoke-direct {v3, v2, v1, v4}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    move-object v1, v3

    .line 44
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 45
    .line 46
    .line 47
    const/16 p0, 0x18

    .line 48
    .line 49
    invoke-direct {v0, v1, p0}, Lj1/a;-><init>(Ljava/lang/Object;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 50
    .line 51
    .line 52
    return-object v0

    .line 53
    :catch_0
    move-exception p0

    .line 54
    new-instance v0, La8/r0;

    .line 55
    .line 56
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 57
    .line 58
    .line 59
    throw v0
.end method

.method public final d()Lh6/e;
    .locals 6

    .line 1
    :try_start_0
    iget-object v0, p0, Lqp/g;->b:Lh6/e;

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    new-instance v0, Lh6/e;

    .line 6
    .line 7
    iget-object v1, p0, Lqp/g;->a:Lrp/f;

    .line 8
    .line 9
    const-string v2, "com.google.android.gms.maps.internal.IUiSettingsDelegate"

    .line 10
    .line 11
    invoke-virtual {v1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    const/16 v4, 0x19

    .line 16
    .line 17
    invoke-virtual {v1, v3, v4}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v1}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    if-nez v3, :cond_0

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    invoke-interface {v3, v2}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    instance-of v5, v4, Lrp/c;

    .line 34
    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    move-object v2, v4

    .line 38
    check-cast v2, Lrp/c;

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    new-instance v4, Lrp/c;

    .line 42
    .line 43
    const/4 v5, 0x5

    .line 44
    invoke-direct {v4, v3, v2, v5}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    move-object v2, v4

    .line 48
    :goto_0
    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    .line 49
    .line 50
    .line 51
    const/16 v1, 0x1c

    .line 52
    .line 53
    invoke-direct {v0, v2, v1}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    iput-object v0, p0, Lqp/g;->b:Lh6/e;

    .line 57
    .line 58
    :cond_2
    iget-object p0, p0, Lqp/g;->b:Lh6/e;
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 59
    .line 60
    return-object p0

    .line 61
    :catch_0
    move-exception p0

    .line 62
    new-instance v0, La8/r0;

    .line 63
    .line 64
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 65
    .line 66
    .line 67
    throw v0
.end method

.method public final e(Lpv/g;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    iget-object p1, p1, Lpv/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Lyo/a;

    .line 6
    .line 7
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0, p1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x4

    .line 15
    invoke-virtual {p0, v0, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catch_0
    move-exception p0

    .line 20
    new-instance p1, La8/r0;

    .line 21
    .line 22
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 23
    .line 24
    .line 25
    throw p1
.end method

.method public final f(Ljava/lang/String;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/16 p1, 0x3d

    .line 11
    .line 12
    invoke-virtual {p0, v0, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :catch_0
    move-exception p0

    .line 17
    new-instance p1, La8/r0;

    .line 18
    .line 19
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 20
    .line 21
    .line 22
    throw p1
.end method

.method public final g(Lqp/a;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    :try_start_0
    new-instance v0, Lqp/j;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lqp/j;-><init>(Lqp/a;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 13
    .line 14
    .line 15
    const/16 v0, 0x21

    .line 16
    .line 17
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    new-instance p1, La8/r0;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    throw p1
.end method

.method public final h(Lqp/c;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    :try_start_0
    new-instance v0, Lqp/j;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lqp/j;-><init>(Lqp/c;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 13
    .line 14
    .line 15
    const/16 v0, 0x20

    .line 16
    .line 17
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    new-instance p1, La8/r0;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    throw p1
.end method

.method public final i(Lqp/d;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    :try_start_0
    new-instance v0, Lqp/j;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lqp/j;-><init>(Lqp/d;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 13
    .line 14
    .line 15
    const/16 v0, 0x54

    .line 16
    .line 17
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    new-instance p1, La8/r0;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    throw p1
.end method

.method public final j(Lqp/e;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    :try_start_0
    new-instance v0, Lqp/j;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lqp/j;-><init>(Lqp/e;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 13
    .line 14
    .line 15
    const/16 v0, 0x1e

    .line 16
    .line 17
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    new-instance p1, La8/r0;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    throw p1
.end method

.method public final k(Lqp/f;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    :try_start_0
    new-instance v0, Lqp/j;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lqp/j;-><init>(Lqp/f;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 13
    .line 14
    .line 15
    const/16 v0, 0x1f

    .line 16
    .line 17
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    new-instance p1, La8/r0;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 25
    .line 26
    .line 27
    throw p1
.end method

.method public final l(IIII)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p3}, Landroid/os/Parcel;->writeInt(I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p4}, Landroid/os/Parcel;->writeInt(I)V

    .line 17
    .line 18
    .line 19
    const/16 p1, 0x27

    .line 20
    .line 21
    invoke-virtual {p0, v0, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :catch_0
    move-exception p0

    .line 26
    new-instance p1, La8/r0;

    .line 27
    .line 28
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 29
    .line 30
    .line 31
    throw p1
.end method

.method public final m()V
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lqp/g;->a:Lrp/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/16 v1, 0x8

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catch_0
    move-exception p0

    .line 14
    new-instance v0, La8/r0;

    .line 15
    .line 16
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    throw v0
.end method
