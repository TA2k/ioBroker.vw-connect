.class public final Ler/a;
.super Ler/q;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:Landroid/os/IBinder;

.field public final synthetic f:Ler/c;


# direct methods
.method public constructor <init>(Ler/c;Landroid/os/IBinder;)V
    .locals 0

    .line 1
    iput-object p2, p0, Ler/a;->e:Landroid/os/IBinder;

    .line 2
    .line 3
    iput-object p1, p0, Ler/a;->f:Ler/c;

    .line 4
    .line 5
    invoke-direct {p0}, Ler/q;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 6

    .line 1
    iget-object v0, p0, Ler/a;->f:Ler/c;

    .line 2
    .line 3
    iget-object v0, v0, Ler/c;->a:Ler/d;

    .line 4
    .line 5
    iget-object v1, v0, Ler/d;->i:Lfv/b;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    sget v1, Ler/n;->d:I

    .line 11
    .line 12
    iget-object p0, p0, Ler/a;->e:Landroid/os/IBinder;

    .line 13
    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string v1, "com.google.android.play.core.integrity.protocol.IIntegrityService"

    .line 19
    .line 20
    invoke-interface {p0, v1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    instance-of v2, v1, Ler/o;

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    move-object p0, v1

    .line 29
    check-cast p0, Ler/o;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    new-instance v1, Ler/m;

    .line 33
    .line 34
    invoke-direct {v1, p0}, Ler/m;-><init>(Landroid/os/IBinder;)V

    .line 35
    .line 36
    .line 37
    move-object p0, v1

    .line 38
    :goto_0
    iput-object p0, v0, Ler/d;->n:Ler/o;

    .line 39
    .line 40
    iget-object p0, v0, Ler/d;->b:Ler/p;

    .line 41
    .line 42
    const-string v1, "linkToDeath"

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    new-array v3, v2, [Ljava/lang/Object;

    .line 46
    .line 47
    invoke-virtual {p0, v1, v3}, Ler/p;->a(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :try_start_0
    iget-object v1, v0, Ler/d;->n:Ler/o;

    .line 51
    .line 52
    check-cast v1, Ler/m;

    .line 53
    .line 54
    iget-object v1, v1, Ler/m;->c:Landroid/os/IBinder;

    .line 55
    .line 56
    iget-object v3, v0, Ler/d;->k:Ler/r;

    .line 57
    .line 58
    invoke-interface {v1, v3, v2}, Landroid/os/IBinder;->linkToDeath(Landroid/os/IBinder$DeathRecipient;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :catch_0
    move-exception v1

    .line 63
    new-array v3, v2, [Ljava/lang/Object;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    const/4 v4, 0x6

    .line 69
    const-string v5, "PlayCore"

    .line 70
    .line 71
    invoke-static {v5, v4}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_2

    .line 76
    .line 77
    iget-object p0, p0, Ler/p;->a:Ljava/lang/String;

    .line 78
    .line 79
    const-string v4, "linkToDeath failed"

    .line 80
    .line 81
    invoke-static {p0, v4, v3}, Ler/p;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-static {v5, p0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 86
    .line 87
    .line 88
    :cond_2
    :goto_1
    iput-boolean v2, v0, Ler/d;->g:Z

    .line 89
    .line 90
    iget-object p0, v0, Ler/d;->d:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_3

    .line 101
    .line 102
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    check-cast v1, Ljava/lang/Runnable;

    .line 107
    .line 108
    invoke-interface {v1}, Ljava/lang/Runnable;->run()V

    .line 109
    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_3
    iget-object p0, v0, Ler/d;->d:Ljava/util/ArrayList;

    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 115
    .line 116
    .line 117
    return-void
.end method
