.class public final Lno/h0;
.super Lno/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Landroid/os/IBinder;

.field public final synthetic h:Lno/e;


# direct methods
.method public constructor <init>(Lno/e;ILandroid/os/IBinder;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lno/h0;->h:Lno/e;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p4}, Lno/w;-><init>(Lno/e;ILandroid/os/Bundle;)V

    .line 4
    .line 5
    .line 6
    iput-object p3, p0, Lno/h0;->g:Landroid/os/IBinder;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljo/b;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lno/h0;->h:Lno/e;

    .line 2
    .line 3
    iget-object p0, p0, Lno/e;->p:Lno/c;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0, p1}, Lno/c;->b(Ljo/b;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final b()Z
    .locals 5

    .line 1
    const-string v0, "GmsClient"

    .line 2
    .line 3
    iget-object v1, p0, Lno/h0;->g:Landroid/os/IBinder;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    :try_start_0
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    move-object v3, v1

    .line 10
    check-cast v3, Landroid/os/IBinder;

    .line 11
    .line 12
    invoke-interface {v3}, Landroid/os/IBinder;->getInterfaceDescriptor()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v3
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    iget-object p0, p0, Lno/h0;->h:Lno/e;

    .line 17
    .line 18
    invoke-virtual {p0}, Lno/e;->s()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-nez v4, :cond_0

    .line 27
    .line 28
    invoke-virtual {p0}, Lno/e;->s()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    new-instance v1, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v4, "service descriptor mismatch: "

    .line 35
    .line 36
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, " vs. "

    .line 43
    .line 44
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 55
    .line 56
    .line 57
    return v2

    .line 58
    :cond_0
    invoke-virtual {p0, v1}, Lno/e;->m(Landroid/os/IBinder;)Landroid/os/IInterface;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    if-eqz v0, :cond_3

    .line 63
    .line 64
    const/4 v1, 0x2

    .line 65
    const/4 v3, 0x4

    .line 66
    invoke-static {p0, v1, v3, v0}, Lno/e;->A(Lno/e;IILandroid/os/IInterface;)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-nez v1, :cond_1

    .line 71
    .line 72
    const/4 v1, 0x3

    .line 73
    invoke-static {p0, v1, v3, v0}, Lno/e;->A(Lno/e;IILandroid/os/IInterface;)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_3

    .line 78
    .line 79
    :cond_1
    const/4 v0, 0x0

    .line 80
    iput-object v0, p0, Lno/e;->t:Ljo/b;

    .line 81
    .line 82
    iget-object p0, p0, Lno/e;->o:Lno/b;

    .line 83
    .line 84
    if-eqz p0, :cond_2

    .line 85
    .line 86
    invoke-interface {p0}, Lno/b;->a()V

    .line 87
    .line 88
    .line 89
    :cond_2
    const/4 p0, 0x1

    .line 90
    return p0

    .line 91
    :cond_3
    return v2

    .line 92
    :catch_0
    const-string p0, "service probably died"

    .line 93
    .line 94
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 95
    .line 96
    .line 97
    return v2
.end method
