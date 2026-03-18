.class public Lcom/google/firebase/remoteconfig/RemoteConfigRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# static fields
.field private static final LIBRARY_NAME:Ljava/lang/String; = "fire-rc"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lgs/s;Lin/z1;)Lcu/j;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/firebase/remoteconfig/RemoteConfigRegistrar;->lambda$getComponents$0(Lgs/s;Lgs/c;)Lcu/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static lambda$getComponents$0(Lgs/s;Lgs/c;)Lcu/j;
    .locals 9

    .line 1
    new-instance v0, Lcu/j;

    .line 2
    .line 3
    const-class v1, Landroid/content/Context;

    .line 4
    .line 5
    invoke-interface {p1, v1}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Landroid/content/Context;

    .line 10
    .line 11
    invoke-interface {p1, p0}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    move-object v2, p0

    .line 16
    check-cast v2, Ljava/util/concurrent/ScheduledExecutorService;

    .line 17
    .line 18
    const-class p0, Lsr/f;

    .line 19
    .line 20
    invoke-interface {p1, p0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    move-object v3, p0

    .line 25
    check-cast v3, Lsr/f;

    .line 26
    .line 27
    const-class p0, Lht/d;

    .line 28
    .line 29
    invoke-interface {p1, p0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    move-object v4, p0

    .line 34
    check-cast v4, Lht/d;

    .line 35
    .line 36
    const-class p0, Lur/a;

    .line 37
    .line 38
    invoke-interface {p1, p0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Lur/a;

    .line 43
    .line 44
    const-string v5, "frc"

    .line 45
    .line 46
    monitor-enter p0

    .line 47
    :try_start_0
    iget-object v6, p0, Lur/a;->a:Ljava/util/HashMap;

    .line 48
    .line 49
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-nez v6, :cond_0

    .line 54
    .line 55
    iget-object v6, p0, Lur/a;->a:Ljava/util/HashMap;

    .line 56
    .line 57
    new-instance v7, Ltr/c;

    .line 58
    .line 59
    iget-object v8, p0, Lur/a;->b:Lgt/b;

    .line 60
    .line 61
    invoke-direct {v7, v8}, Ltr/c;-><init>(Lgt/b;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v6, v5, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :catchall_0
    move-exception v0

    .line 69
    move-object p1, v0

    .line 70
    goto :goto_1

    .line 71
    :cond_0
    :goto_0
    iget-object v6, p0, Lur/a;->a:Ljava/util/HashMap;

    .line 72
    .line 73
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    check-cast v5, Ltr/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    .line 79
    monitor-exit p0

    .line 80
    const-class p0, Lwr/b;

    .line 81
    .line 82
    invoke-interface {p1, p0}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    invoke-direct/range {v0 .. v6}, Lcu/j;-><init>(Landroid/content/Context;Ljava/util/concurrent/ScheduledExecutorService;Lsr/f;Lht/d;Ltr/c;Lgt/b;)V

    .line 87
    .line 88
    .line 89
    return-object v0

    .line 90
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 91
    throw p1
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lgs/b;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Lgs/s;

    .line 2
    .line 3
    const-class v0, Lyr/b;

    .line 4
    .line 5
    const-class v1, Ljava/util/concurrent/ScheduledExecutorService;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    const-class v0, Lfu/a;

    .line 11
    .line 12
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    new-instance v1, Lgs/a;

    .line 17
    .line 18
    const-class v2, Lcu/j;

    .line 19
    .line 20
    invoke-direct {v1, v2, v0}, Lgs/a;-><init>(Ljava/lang/Class;[Ljava/lang/Class;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "fire-rc"

    .line 24
    .line 25
    iput-object v0, v1, Lgs/a;->a:Ljava/lang/String;

    .line 26
    .line 27
    const-class v2, Landroid/content/Context;

    .line 28
    .line 29
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 34
    .line 35
    .line 36
    new-instance v2, Lgs/k;

    .line 37
    .line 38
    const/4 v3, 0x1

    .line 39
    const/4 v4, 0x0

    .line 40
    invoke-direct {v2, p0, v3, v4}, Lgs/k;-><init>(Lgs/s;II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 44
    .line 45
    .line 46
    const-class v2, Lsr/f;

    .line 47
    .line 48
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 53
    .line 54
    .line 55
    const-class v2, Lht/d;

    .line 56
    .line 57
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 62
    .line 63
    .line 64
    const-class v2, Lur/a;

    .line 65
    .line 66
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 71
    .line 72
    .line 73
    const-class v2, Lwr/b;

    .line 74
    .line 75
    invoke-static {v2}, Lgs/k;->a(Ljava/lang/Class;)Lgs/k;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-virtual {v1, v2}, Lgs/a;->a(Lgs/k;)V

    .line 80
    .line 81
    .line 82
    new-instance v2, Lcom/google/firebase/messaging/p;

    .line 83
    .line 84
    invoke-direct {v2, p0, v3}, Lcom/google/firebase/messaging/p;-><init>(Lgs/s;I)V

    .line 85
    .line 86
    .line 87
    iput-object v2, v1, Lgs/a;->f:Lgs/e;

    .line 88
    .line 89
    const/4 p0, 0x2

    .line 90
    invoke-virtual {v1, p0}, Lgs/a;->c(I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const-string v1, "23.0.1"

    .line 98
    .line 99
    invoke-static {v0, v1}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    filled-new-array {p0, v0}, [Lgs/b;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0
.end method
