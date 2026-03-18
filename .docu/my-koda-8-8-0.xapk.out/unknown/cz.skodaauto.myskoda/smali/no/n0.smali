.class public final Lno/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Ljava/lang/Object;

.field public static h:Lno/n0;

.field public static i:Landroid/os/HandlerThread;


# instance fields
.field public final a:Ljava/util/HashMap;

.field public final b:Landroid/content/Context;

.field public volatile c:Lbp/c;

.field public final d:Lso/a;

.field public final e:J

.field public final f:J


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
    sput-object v0, Lno/n0;->g:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;)V
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
    iput-object v0, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 10
    .line 11
    new-instance v0, Lno/m0;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lno/m0;-><init>(Lno/n0;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lno/n0;->b:Landroid/content/Context;

    .line 21
    .line 22
    new-instance p1, Lbp/c;

    .line 23
    .line 24
    invoke-direct {p1, p2, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;Landroid/os/Handler$Callback;)V

    .line 25
    .line 26
    .line 27
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lno/n0;->c:Lbp/c;

    .line 31
    .line 32
    invoke-static {}, Lso/a;->b()Lso/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lno/n0;->d:Lso/a;

    .line 37
    .line 38
    const-wide/16 p1, 0x1388

    .line 39
    .line 40
    iput-wide p1, p0, Lno/n0;->e:J

    .line 41
    .line 42
    const-wide/32 p1, 0x493e0

    .line 43
    .line 44
    .line 45
    iput-wide p1, p0, Lno/n0;->f:J

    .line 46
    .line 47
    return-void
.end method

.method public static a(Landroid/content/Context;)Lno/n0;
    .locals 3

    .line 1
    sget-object v0, Lno/n0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lno/n0;->h:Lno/n0;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lno/n0;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {p0}, Landroid/content/Context;->getMainLooper()Landroid/os/Looper;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-direct {v1, v2, p0}, Lno/n0;-><init>(Landroid/content/Context;Landroid/os/Looper;)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Lno/n0;->h:Lno/n0;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    sget-object p0, Lno/n0;->h:Lno/n0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 31
    throw p0
.end method


# virtual methods
.method public final b(Lno/k0;Lno/g0;Ljava/lang/String;Ljava/util/concurrent/Executor;)Ljo/b;
    .locals 5

    .line 1
    const-string v0, "Trying to bind a GmsServiceConnection that was already connected before.  config="

    .line 2
    .line 3
    iget-object v1, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget-object v2, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 7
    .line 8
    invoke-virtual {v2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Lno/l0;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    if-nez p4, :cond_0

    .line 16
    .line 17
    move-object p4, v3

    .line 18
    :cond_0
    if-nez v2, :cond_1

    .line 19
    .line 20
    new-instance v2, Lno/l0;

    .line 21
    .line 22
    invoke-direct {v2, p0, p1}, Lno/l0;-><init>(Lno/n0;Lno/k0;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, v2, Lno/l0;->a:Ljava/util/HashMap;

    .line 26
    .line 27
    invoke-virtual {v0, p2, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    invoke-static {v2, p3, p4}, Lno/l0;->a(Lno/l0;Ljava/lang/String;Ljava/util/concurrent/Executor;)Ljo/b;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    iget-object p0, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 35
    .line 36
    invoke-virtual {p0, p1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    iget-object p0, p0, Lno/n0;->c:Lbp/c;

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    invoke-virtual {p0, v4, p1}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, v2, Lno/l0;->a:Ljava/util/HashMap;

    .line 49
    .line 50
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_6

    .line 55
    .line 56
    iget-object p0, v2, Lno/l0;->a:Ljava/util/HashMap;

    .line 57
    .line 58
    invoke-virtual {p0, p2, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    iget p0, v2, Lno/l0;->b:I

    .line 62
    .line 63
    const/4 p1, 0x1

    .line 64
    if-eq p0, p1, :cond_3

    .line 65
    .line 66
    const/4 p1, 0x2

    .line 67
    if-eq p0, p1, :cond_2

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    invoke-static {v2, p3, p4}, Lno/l0;->a(Lno/l0;Ljava/lang/String;Ljava/util/concurrent/Executor;)Ljo/b;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    goto :goto_0

    .line 75
    :cond_3
    iget-object p0, v2, Lno/l0;->f:Landroid/content/ComponentName;

    .line 76
    .line 77
    iget-object p1, v2, Lno/l0;->d:Landroid/os/IBinder;

    .line 78
    .line 79
    invoke-virtual {p2, p0, p1}, Lno/g0;->onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V

    .line 80
    .line 81
    .line 82
    :goto_0
    iget-boolean p0, v2, Lno/l0;->c:Z

    .line 83
    .line 84
    if-eqz p0, :cond_4

    .line 85
    .line 86
    sget-object p0, Ljo/b;->h:Ljo/b;

    .line 87
    .line 88
    monitor-exit v1

    .line 89
    return-object p0

    .line 90
    :cond_4
    if-nez v3, :cond_5

    .line 91
    .line 92
    new-instance v3, Ljo/b;

    .line 93
    .line 94
    const/4 p0, -0x1

    .line 95
    invoke-direct {v3, p0}, Ljo/b;-><init>(I)V

    .line 96
    .line 97
    .line 98
    :cond_5
    monitor-exit v1

    .line 99
    return-object v3

    .line 100
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 101
    .line 102
    invoke-virtual {p1}, Lno/k0;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 115
    throw p0
.end method

.method public final c(Ljava/lang/String;Ljava/lang/String;Landroid/content/ServiceConnection;Z)V
    .locals 2

    .line 1
    new-instance v0, Lno/k0;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2, p4}, Lno/k0;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 4
    .line 5
    .line 6
    const-string p1, "Trying to unbind a GmsServiceConnection  that was not bound before.  config="

    .line 7
    .line 8
    const-string p2, "Nonexistent connection status for service config: "

    .line 9
    .line 10
    const-string p4, "ServiceConnection must not be null"

    .line 11
    .line 12
    invoke-static {p3, p4}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p4, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 16
    .line 17
    monitor-enter p4

    .line 18
    :try_start_0
    iget-object v1, p0, Lno/n0;->a:Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-virtual {v1, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Lno/l0;

    .line 25
    .line 26
    if-eqz v1, :cond_2

    .line 27
    .line 28
    iget-object p2, v1, Lno/l0;->a:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {p2, p3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    if-eqz p2, :cond_1

    .line 35
    .line 36
    iget-object p1, v1, Lno/l0;->a:Ljava/util/HashMap;

    .line 37
    .line 38
    invoke-virtual {p1, p3}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    iget-object p1, v1, Lno/l0;->a:Ljava/util/HashMap;

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/util/HashMap;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-eqz p1, :cond_0

    .line 48
    .line 49
    iget-object p1, p0, Lno/n0;->c:Lbp/c;

    .line 50
    .line 51
    const/4 p2, 0x0

    .line 52
    invoke-virtual {p1, p2, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    iget-object p2, p0, Lno/n0;->c:Lbp/c;

    .line 57
    .line 58
    iget-wide v0, p0, Lno/n0;->e:J

    .line 59
    .line 60
    invoke-virtual {p2, p1, v0, v1}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto :goto_1

    .line 66
    :cond_0
    :goto_0
    monitor-exit p4

    .line 67
    return-void

    .line 68
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    invoke-virtual {v0}, Lno/k0;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    invoke-virtual {p1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    invoke-virtual {v0}, Lno/k0;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :goto_1
    monitor-exit p4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 97
    throw p0
.end method
