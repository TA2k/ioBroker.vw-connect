.class public final Lfv/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Ljava/lang/Object;

.field public static c:Lfv/f;


# instance fields
.field public a:Lgs/h;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lfv/f;->b:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public static c()Lfv/f;
    .locals 3

    .line 1
    sget-object v0, Lfv/f;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lfv/f;->c:Lfv/f;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v1, 0x0

    .line 11
    :goto_0
    const-string v2, "MlKitContext has not been initialized"

    .line 12
    .line 13
    invoke-static {v2, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 14
    .line 15
    .line 16
    sget-object v1, Lfv/f;->c:Lfv/f;

    .line 17
    .line 18
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-object v1

    .line 23
    :catchall_0
    move-exception v1

    .line 24
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw v1
.end method

.method public static d(Landroid/content/Context;Ljava/util/concurrent/Executor;)Lfv/f;
    .locals 9

    .line 1
    sget-object v0, Lfv/f;->b:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lfv/f;->c:Lfv/f;

    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    const/4 v3, 0x0

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    move v1, v2

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v1, v3

    .line 13
    :goto_0
    const-string v4, "MlKitContext is already initialized"

    .line 14
    .line 15
    invoke-static {v4, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Lfv/f;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    sput-object v1, Lfv/f;->c:Lfv/f;

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    if-eqz v4, :cond_1

    .line 30
    .line 31
    move-object p0, v4

    .line 32
    :cond_1
    const-class v4, Lcom/google/mlkit/common/internal/MlKitComponentDiscoveryService;

    .line 33
    .line 34
    new-instance v5, Lb81/a;

    .line 35
    .line 36
    new-instance v6, Laq/a;

    .line 37
    .line 38
    const/16 v7, 0x1a

    .line 39
    .line 40
    invoke-direct {v6, v4, v7}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    const/16 v4, 0x8

    .line 44
    .line 45
    invoke-direct {v5, v4, p0, v6}, Lb81/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5}, Lb81/a;->m()Ljava/util/ArrayList;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    new-instance v5, Ljava/util/ArrayList;

    .line 53
    .line 54
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 55
    .line 56
    .line 57
    new-instance v6, Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 60
    .line 61
    .line 62
    sget-object v7, Lgs/f;->w0:Lf3/d;

    .line 63
    .line 64
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 65
    .line 66
    .line 67
    const-class v4, Landroid/content/Context;

    .line 68
    .line 69
    new-array v8, v3, [Ljava/lang/Class;

    .line 70
    .line 71
    invoke-static {p0, v4, v8}, Lgs/b;->c(Ljava/lang/Object;Ljava/lang/Class;[Ljava/lang/Class;)Lgs/b;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-virtual {v6, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    const-class p0, Lfv/f;

    .line 79
    .line 80
    new-array v3, v3, [Ljava/lang/Class;

    .line 81
    .line 82
    invoke-static {v1, p0, v3}, Lgs/b;->c(Ljava/lang/Object;Ljava/lang/Class;[Ljava/lang/Class;)Lgs/b;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v6, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    new-instance p0, Lgs/h;

    .line 90
    .line 91
    invoke-direct {p0, p1, v5, v6, v7}, Lgs/h;-><init>(Ljava/util/concurrent/Executor;Ljava/util/ArrayList;Ljava/util/ArrayList;Lgs/f;)V

    .line 92
    .line 93
    .line 94
    iput-object p0, v1, Lfv/f;->a:Lgs/h;

    .line 95
    .line 96
    invoke-virtual {p0, v2}, Lgs/h;->i(Z)V

    .line 97
    .line 98
    .line 99
    sget-object p0, Lfv/f;->c:Lfv/f;

    .line 100
    .line 101
    monitor-exit v0

    .line 102
    return-object p0

    .line 103
    :catchall_0
    move-exception p0

    .line 104
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 105
    throw p0
.end method


# virtual methods
.method public final a(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lfv/f;->c:Lfv/f;

    .line 2
    .line 3
    if-ne v0, p0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    const-string v1, "MlKitContext has been deleted"

    .line 9
    .line 10
    invoke-static {v1, v0}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lfv/f;->a:Lgs/h;

    .line 14
    .line 15
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lfv/f;->a:Lgs/h;

    .line 19
    .line 20
    invoke-interface {p0, p1}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final b()Landroid/content/Context;
    .locals 1

    .line 1
    const-class v0, Landroid/content/Context;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lfv/f;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/content/Context;

    .line 8
    .line 9
    return-object p0
.end method
