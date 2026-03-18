.class public Lsp/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhp/c;


# direct methods
.method public constructor <init>(Lhp/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lsp/k;->a:Lhp/c;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a()Lcom/google/android/gms/maps/model/LatLng;
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    check-cast p0, Lhp/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x4

    .line 10
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v0, Lcom/google/android/gms/maps/model/LatLng;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    invoke-static {p0, v0}, Lhp/j;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Lcom/google/android/gms/maps/model/LatLng;

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    .line 24
    .line 25
    return-object v0

    .line 26
    :catch_0
    move-exception p0

    .line 27
    new-instance v0, La8/r0;

    .line 28
    .line 29
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 30
    .line 31
    .line 32
    throw v0
.end method

.method public final b()Z
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    check-cast p0, Lhp/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/16 v1, 0xd

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget v0, Lhp/j;->a:I

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x0

    .line 26
    :goto_0
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    .line 29
    return v0

    .line 30
    :catch_0
    move-exception p0

    .line 31
    new-instance v0, La8/r0;

    .line 32
    .line 33
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 34
    .line 35
    .line 36
    throw v0
.end method

.method public final c()V
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    check-cast p0, Lhp/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-virtual {p0, v0, v1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :catch_0
    move-exception p0

    .line 15
    new-instance v0, La8/r0;

    .line 16
    .line 17
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 18
    .line 19
    .line 20
    throw v0
.end method

.method public final d(Lsp/b;)V
    .locals 2

    .line 1
    const/16 v0, 0x12

    .line 2
    .line 3
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 4
    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    :try_start_0
    check-cast p0, Lhp/a;

    .line 8
    .line 9
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-static {p1, v1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object p1, p1, Lsp/b;->a:Lyo/a;

    .line 22
    .line 23
    check-cast p0, Lhp/a;

    .line 24
    .line 25
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-static {v1, p1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :catch_0
    move-exception p0

    .line 37
    new-instance p1, La8/r0;

    .line 38
    .line 39
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 40
    .line 41
    .line 42
    throw p1
.end method

.method public final e(Lcom/google/android/gms/maps/model/LatLng;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 4
    .line 5
    check-cast p0, Lhp/a;

    .line 6
    .line 7
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0, p1}, Lhp/j;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x3

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

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 27
    .line 28
    const-string p1, "latlng cannot be null - a position is required."

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lsp/k;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 8
    .line 9
    check-cast p1, Lsp/k;

    .line 10
    .line 11
    iget-object p1, p1, Lsp/k;->a:Lhp/c;

    .line 12
    .line 13
    check-cast p0, Lhp/a;

    .line 14
    .line 15
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-static {v0, p1}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 20
    .line 21
    .line 22
    const/16 p1, 0x10

    .line 23
    .line 24
    invoke-virtual {p0, v0, p1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    const/4 v1, 0x1

    .line 35
    :cond_1
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 36
    .line 37
    .line 38
    return v1

    .line 39
    :catch_0
    move-exception p0

    .line 40
    new-instance p1, La8/r0;

    .line 41
    .line 42
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 43
    .line 44
    .line 45
    throw p1
.end method

.method public final f(Ljava/lang/Object;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    new-instance v0, Lyo/b;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lhp/a;

    .line 9
    .line 10
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-static {p1, v0}, Lhp/j;->d(Landroid/os/Parcel;Landroid/os/IInterface;)V

    .line 15
    .line 16
    .line 17
    const/16 v0, 0x1d

    .line 18
    .line 19
    invoke-virtual {p0, p1, v0}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :catch_0
    move-exception p0

    .line 24
    new-instance p1, La8/r0;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public final g(F)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    check-cast p0, Lhp/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeFloat(F)V

    .line 10
    .line 11
    .line 12
    const/16 p1, 0x1b

    .line 13
    .line 14
    invoke-virtual {p0, v0, p1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :catch_0
    move-exception p0

    .line 19
    new-instance p1, La8/r0;

    .line 20
    .line 21
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 22
    .line 23
    .line 24
    throw p1
.end method

.method public final h()V
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    check-cast p0, Lhp/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/16 v1, 0xb

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p0

    .line 16
    new-instance v0, La8/r0;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 19
    .line 20
    .line 21
    throw v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/k;->a:Lhp/c;

    .line 2
    .line 3
    check-cast p0, Lhp/a;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/16 v1, 0x11

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1}, Lbp/a;->c(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Landroid/os/Parcel;->readInt()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return v0

    .line 23
    :catch_0
    move-exception p0

    .line 24
    new-instance v0, La8/r0;

    .line 25
    .line 26
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw v0
.end method
