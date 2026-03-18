.class public final Les/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lcr/b;

.field public final c:Landroidx/lifecycle/c1;

.field public final d:Ljava/util/concurrent/Executor;

.field public final e:Ljava/util/concurrent/Executor;

.field public final f:Las/e;


# direct methods
.method public constructor <init>(Lsr/f;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;)V
    .locals 4

    .line 1
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lsr/f;->c:Lsr/i;

    .line 5
    .line 6
    iget-object v0, v0, Lsr/i;->e:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 9
    .line 10
    .line 11
    iget-object v1, p1, Lsr/f;->a:Landroid/content/Context;

    .line 12
    .line 13
    const-class v2, Lcr/i;

    .line 14
    .line 15
    monitor-enter v2

    .line 16
    :try_start_0
    sget-object v3, Lcr/i;->a:Laq/a;

    .line 17
    .line 18
    if-nez v3, :cond_1

    .line 19
    .line 20
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    if-eqz v3, :cond_0

    .line 25
    .line 26
    move-object v1, v3

    .line 27
    :cond_0
    new-instance v3, Laq/a;

    .line 28
    .line 29
    invoke-direct {v3, v1}, Laq/a;-><init>(Landroid/content/Context;)V

    .line 30
    .line 31
    .line 32
    sput-object v3, Lcr/i;->a:Laq/a;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    :goto_0
    sget-object v1, Lcr/i;->a:Laq/a;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    .line 39
    monitor-exit v2

    .line 40
    iget-object v1, v1, Laq/a;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Ler/g;

    .line 43
    .line 44
    invoke-virtual {v1}, Ler/g;->a()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lcr/b;

    .line 49
    .line 50
    new-instance v2, Landroidx/lifecycle/c1;

    .line 51
    .line 52
    invoke-direct {v2, p1}, Landroidx/lifecycle/c1;-><init>(Lsr/f;)V

    .line 53
    .line 54
    .line 55
    new-instance p1, Las/e;

    .line 56
    .line 57
    const/4 v3, 0x0

    .line 58
    invoke-direct {p1, v3}, Las/e;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-object v0, p0, Les/d;->a:Ljava/lang/String;

    .line 65
    .line 66
    iput-object v1, p0, Les/d;->b:Lcr/b;

    .line 67
    .line 68
    iput-object v2, p0, Les/d;->c:Landroidx/lifecycle/c1;

    .line 69
    .line 70
    iput-object p2, p0, Les/d;->d:Ljava/util/concurrent/Executor;

    .line 71
    .line 72
    iput-object p3, p0, Les/d;->e:Ljava/util/concurrent/Executor;

    .line 73
    .line 74
    iput-object p1, p0, Les/d;->f:Las/e;

    .line 75
    .line 76
    return-void

    .line 77
    :goto_1
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 78
    throw p0
.end method
