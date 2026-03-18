.class public final Lcr/c;
.super Ler/q;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:[B

.field public final synthetic f:Ljava/lang/Long;

.field public final synthetic g:Laq/k;

.field public final synthetic h:Lcr/g;

.field public final synthetic i:Lcr/e;


# direct methods
.method public constructor <init>(Lcr/e;Laq/k;[BLjava/lang/Long;Laq/k;Lcr/g;)V
    .locals 0

    .line 1
    iput-object p3, p0, Lcr/c;->e:[B

    .line 2
    .line 3
    iput-object p4, p0, Lcr/c;->f:Ljava/lang/Long;

    .line 4
    .line 5
    iput-object p5, p0, Lcr/c;->g:Laq/k;

    .line 6
    .line 7
    iput-object p6, p0, Lcr/c;->h:Lcr/g;

    .line 8
    .line 9
    iput-object p1, p0, Lcr/c;->i:Lcr/e;

    .line 10
    .line 11
    invoke-direct {p0, p2}, Ler/q;-><init>(Laq/k;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    instance-of v0, p1, Ler/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcr/a;

    .line 6
    .line 7
    const/16 v1, -0x9

    .line 8
    .line 9
    invoke-direct {v0, v1, p1}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 10
    .line 11
    .line 12
    invoke-super {p0, v0}, Ler/q;->a(Ljava/lang/Exception;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    invoke-super {p0, p1}, Ler/q;->a(Ljava/lang/Exception;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final b()V
    .locals 8

    .line 1
    iget-object v0, p0, Lcr/c;->g:Laq/k;

    .line 2
    .line 3
    iget-object v1, p0, Lcr/c;->i:Lcr/e;

    .line 4
    .line 5
    :try_start_0
    iget-object v2, v1, Lcr/e;->e:Ler/d;

    .line 6
    .line 7
    iget-object v2, v2, Ler/d;->n:Ler/o;

    .line 8
    .line 9
    iget-object v3, p0, Lcr/c;->e:[B

    .line 10
    .line 11
    iget-object v4, p0, Lcr/c;->f:Ljava/lang/Long;

    .line 12
    .line 13
    invoke-static {v1, v3, v4}, Lcr/e;->a(Lcr/e;[BLjava/lang/Long;)Landroid/os/Bundle;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    new-instance v4, Lcr/d;

    .line 18
    .line 19
    invoke-direct {v4, v1, v0}, Lcr/d;-><init>(Lcr/e;Laq/k;)V

    .line 20
    .line 21
    .line 22
    check-cast v2, Ler/m;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    const-string v6, "com.google.android.play.core.integrity.protocol.IIntegrityService"

    .line 32
    .line 33
    invoke-virtual {v5, v6}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    sget v6, Ler/k;->a:I

    .line 37
    .line 38
    const/4 v6, 0x1

    .line 39
    invoke-virtual {v5, v6}, Landroid/os/Parcel;->writeInt(I)V

    .line 40
    .line 41
    .line 42
    const/4 v7, 0x0

    .line 43
    invoke-virtual {v3, v5, v7}, Landroid/os/Bundle;->writeToParcel(Landroid/os/Parcel;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v5, v4}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    .line 48
    .line 49
    :try_start_1
    iget-object v2, v2, Ler/m;->c:Landroid/os/IBinder;

    .line 50
    .line 51
    const/4 v3, 0x0

    .line 52
    const/4 v4, 0x2

    .line 53
    invoke-interface {v2, v4, v5, v3, v6}, Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 54
    .line 55
    .line 56
    :try_start_2
    invoke-virtual {v5}, Landroid/os/Parcel;->recycle()V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :catchall_0
    move-exception v2

    .line 61
    invoke-virtual {v5}, Landroid/os/Parcel;->recycle()V

    .line 62
    .line 63
    .line 64
    throw v2
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_0

    .line 65
    :catch_0
    move-exception v2

    .line 66
    iget-object v1, v1, Lcr/e;->a:Ler/p;

    .line 67
    .line 68
    iget-object p0, p0, Lcr/c;->h:Lcr/g;

    .line 69
    .line 70
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    const/4 v3, 0x6

    .line 78
    const-string v4, "PlayCore"

    .line 79
    .line 80
    invoke-static {v4, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-eqz v3, :cond_0

    .line 85
    .line 86
    iget-object v1, v1, Ler/p;->a:Ljava/lang/String;

    .line 87
    .line 88
    const-string v3, "requestIntegrityToken(%s)"

    .line 89
    .line 90
    invoke-static {v1, v3, p0}, Ler/p;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-static {v4, p0, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 95
    .line 96
    .line 97
    :cond_0
    new-instance p0, Lcr/a;

    .line 98
    .line 99
    const/16 v1, -0x64

    .line 100
    .line 101
    invoke-direct {p0, v1, v2}, Lcr/a;-><init>(ILjava/lang/Exception;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v0, p0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 105
    .line 106
    .line 107
    return-void
.end method
