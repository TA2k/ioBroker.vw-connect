.class public final Lsp/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhp/f;


# direct methods
.method public constructor <init>(Lhp/f;)V
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
    iput-object p1, p0, Lsp/o;->a:Lhp/f;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 1

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/o;->a:Lhp/f;

    .line 2
    .line 3
    new-instance v0, Lyo/b;

    .line 4
    .line 5
    invoke-direct {v0, p1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    check-cast p0, Lhp/d;

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
    const/16 v0, 0x1b

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

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lsp/o;

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
    iget-object p0, p0, Lsp/o;->a:Lhp/f;

    .line 8
    .line 9
    check-cast p1, Lsp/o;

    .line 10
    .line 11
    iget-object p1, p1, Lsp/o;->a:Lhp/f;

    .line 12
    .line 13
    check-cast p0, Lhp/d;

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
    const/16 p1, 0x13

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

.method public final hashCode()I
    .locals 2

    .line 1
    :try_start_0
    iget-object p0, p0, Lsp/o;->a:Lhp/f;

    .line 2
    .line 3
    check-cast p0, Lhp/d;

    .line 4
    .line 5
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/16 v1, 0x14

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
