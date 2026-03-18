.class public final Llo/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Handler$Callback;


# static fields
.field public static final s:Lcom/google/android/gms/common/api/Status;

.field public static final t:Lcom/google/android/gms/common/api/Status;

.field public static final u:Ljava/lang/Object;

.field public static v:Llo/g;


# instance fields
.field public d:J

.field public e:Z

.field public f:Lno/p;

.field public g:Lpo/b;

.field public final h:Landroid/content/Context;

.field public final i:Ljo/e;

.field public final j:Lc2/k;

.field public final k:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final l:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final m:Ljava/util/concurrent/ConcurrentHashMap;

.field public n:Llo/p;

.field public final o:Landroidx/collection/g;

.field public final p:Landroidx/collection/g;

.field public final q:Lbp/c;

.field public volatile r:Z


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/gms/common/api/Status;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    const-string v2, "Sign-out occurred while this API call was in progress."

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v2, v3, v3}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Llo/g;->s:Lcom/google/android/gms/common/api/Status;

    .line 11
    .line 12
    new-instance v0, Lcom/google/android/gms/common/api/Status;

    .line 13
    .line 14
    const-string v2, "The user must be signed in to make this API call."

    .line 15
    .line 16
    invoke-direct {v0, v1, v2, v3, v3}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Llo/g;->t:Lcom/google/android/gms/common/api/Status;

    .line 20
    .line 21
    new-instance v0, Ljava/lang/Object;

    .line 22
    .line 23
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    sput-object v0, Llo/g;->u:Ljava/lang/Object;

    .line 27
    .line 28
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;)V
    .locals 6

    .line 1
    sget-object v0, Ljo/e;->d:Ljo/e;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const-wide/16 v1, 0x2710

    .line 7
    .line 8
    iput-wide v1, p0, Llo/g;->d:J

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput-boolean v1, p0, Llo/g;->e:Z

    .line 12
    .line 13
    new-instance v2, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v2, v3}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object v2, p0, Llo/g;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 20
    .line 21
    new-instance v2, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 22
    .line 23
    invoke-direct {v2, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 24
    .line 25
    .line 26
    iput-object v2, p0, Llo/g;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 27
    .line 28
    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    .line 29
    .line 30
    const/4 v4, 0x5

    .line 31
    const/high16 v5, 0x3f400000    # 0.75f

    .line 32
    .line 33
    invoke-direct {v2, v4, v5, v3}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(IFI)V

    .line 34
    .line 35
    .line 36
    iput-object v2, p0, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    iput-object v2, p0, Llo/g;->n:Llo/p;

    .line 40
    .line 41
    new-instance v4, Landroidx/collection/g;

    .line 42
    .line 43
    invoke-direct {v4, v2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iput-object v4, p0, Llo/g;->o:Landroidx/collection/g;

    .line 47
    .line 48
    new-instance v4, Landroidx/collection/g;

    .line 49
    .line 50
    invoke-direct {v4, v2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object v4, p0, Llo/g;->p:Landroidx/collection/g;

    .line 54
    .line 55
    iput-boolean v3, p0, Llo/g;->r:Z

    .line 56
    .line 57
    iput-object p1, p0, Llo/g;->h:Landroid/content/Context;

    .line 58
    .line 59
    new-instance v2, Lbp/c;

    .line 60
    .line 61
    invoke-direct {v2, p2, p0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;Landroid/os/Handler$Callback;)V

    .line 62
    .line 63
    .line 64
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 65
    .line 66
    .line 67
    iput-object v2, p0, Llo/g;->q:Lbp/c;

    .line 68
    .line 69
    iput-object v0, p0, Llo/g;->i:Ljo/e;

    .line 70
    .line 71
    new-instance p2, Lc2/k;

    .line 72
    .line 73
    const/16 v0, 0x13

    .line 74
    .line 75
    invoke-direct {p2, v0}, Lc2/k;-><init>(I)V

    .line 76
    .line 77
    .line 78
    iput-object p2, p0, Llo/g;->j:Lc2/k;

    .line 79
    .line 80
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    sget-object p2, Lto/b;->f:Ljava/lang/Boolean;

    .line 85
    .line 86
    if-nez p2, :cond_0

    .line 87
    .line 88
    const-string p2, "android.hardware.type.automotive"

    .line 89
    .line 90
    invoke-virtual {p1, p2}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 91
    .line 92
    .line 93
    move-result p1

    .line 94
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    sput-object p1, Lto/b;->f:Ljava/lang/Boolean;

    .line 99
    .line 100
    :cond_0
    sget-object p1, Lto/b;->f:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-eqz p1, :cond_1

    .line 107
    .line 108
    iput-boolean v1, p0, Llo/g;->r:Z

    .line 109
    .line 110
    :cond_1
    const/4 p0, 0x6

    .line 111
    invoke-virtual {v2, p0}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {v2, p0}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 116
    .line 117
    .line 118
    return-void
.end method

.method public static d(Llo/b;Ljo/b;)Lcom/google/android/gms/common/api/Status;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/gms/common/api/Status;

    .line 2
    .line 3
    iget-object p0, p0, Llo/b;->b:Lc2/k;

    .line 4
    .line 5
    iget-object p0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const-string v2, "API: "

    .line 14
    .line 15
    const-string v3, " is not available on this device. Connection failed with: "

    .line 16
    .line 17
    invoke-static {v2, p0, v3, v1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/16 v1, 0x11

    .line 22
    .line 23
    iget-object v2, p1, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 24
    .line 25
    invoke-direct {v0, v1, p0, v2, p1}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method

.method public static g(Landroid/content/Context;)Llo/g;
    .locals 5

    .line 1
    sget-object v0, Llo/g;->u:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Llo/g;->v:Llo/g;

    .line 5
    .line 6
    if-nez v1, :cond_1

    .line 7
    .line 8
    sget-object v1, Lno/n0;->g:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 11
    :try_start_1
    sget-object v2, Lno/n0;->i:Landroid/os/HandlerThread;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    monitor-exit v1

    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    new-instance v2, Landroid/os/HandlerThread;

    .line 20
    .line 21
    const-string v3, "GoogleApiHandler"

    .line 22
    .line 23
    const/16 v4, 0x9

    .line 24
    .line 25
    invoke-direct {v2, v3, v4}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    sput-object v2, Lno/n0;->i:Landroid/os/HandlerThread;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Thread;->start()V

    .line 31
    .line 32
    .line 33
    sget-object v2, Lno/n0;->i:Landroid/os/HandlerThread;

    .line 34
    .line 35
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 36
    :goto_0
    :try_start_2
    invoke-virtual {v2}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    new-instance v2, Llo/g;

    .line 41
    .line 42
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object v3, Ljo/e;->c:Ljava/lang/Object;

    .line 47
    .line 48
    invoke-direct {v2, p0, v1}, Llo/g;-><init>(Landroid/content/Context;Landroid/os/Looper;)V

    .line 49
    .line 50
    .line 51
    sput-object v2, Llo/g;->v:Llo/g;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :catchall_1
    move-exception p0

    .line 55
    goto :goto_3

    .line 56
    :goto_1
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 57
    :try_start_4
    throw p0

    .line 58
    :cond_1
    :goto_2
    sget-object p0, Llo/g;->v:Llo/g;

    .line 59
    .line 60
    monitor-exit v0

    .line 61
    return-object p0

    .line 62
    :goto_3
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 63
    throw p0
.end method


# virtual methods
.method public final a(Llo/p;)V
    .locals 2

    .line 1
    sget-object v0, Llo/g;->u:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Llo/g;->n:Llo/p;

    .line 5
    .line 6
    if-eq v1, p1, :cond_0

    .line 7
    .line 8
    iput-object p1, p0, Llo/g;->n:Llo/p;

    .line 9
    .line 10
    iget-object v1, p0, Llo/g;->o:Landroidx/collection/g;

    .line 11
    .line 12
    invoke-virtual {v1}, Landroidx/collection/g;->clear()V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    iget-object p0, p0, Llo/g;->o:Landroidx/collection/g;

    .line 19
    .line 20
    iget-object p1, p1, Llo/p;->i:Landroidx/collection/g;

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Landroidx/collection/g;->addAll(Ljava/util/Collection;)Z

    .line 23
    .line 24
    .line 25
    monitor-exit v0

    .line 26
    return-void

    .line 27
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    throw p0
.end method

.method public final b()Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Llo/g;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-static {}, Lno/n;->e()Lno/n;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object v0, v0, Lno/n;->a:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lno/o;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-boolean v0, v0, Lno/o;->e:Z

    .line 17
    .line 18
    if-eqz v0, :cond_2

    .line 19
    .line 20
    :cond_1
    iget-object p0, p0, Llo/g;->j:Lc2/k;

    .line 21
    .line 22
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Landroid/util/SparseIntArray;

    .line 25
    .line 26
    const v0, 0xc1fa340

    .line 27
    .line 28
    .line 29
    const/4 v1, -0x1

    .line 30
    invoke-virtual {p0, v0, v1}, Landroid/util/SparseIntArray;->get(II)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eq p0, v1, :cond_3

    .line 35
    .line 36
    if-nez p0, :cond_2

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 40
    return p0

    .line 41
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 42
    return p0
.end method

.method public final c(Ljo/b;I)Z
    .locals 6

    .line 1
    iget-object v0, p0, Llo/g;->i:Ljo/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llo/g;->h:Landroid/content/Context;

    .line 7
    .line 8
    invoke-static {p0}, Lvo/a;->f(Landroid/content/Context;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/4 v2, 0x0

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_0
    iget v1, p1, Ljo/b;->e:I

    .line 17
    .line 18
    iget-object p1, p1, Ljo/b;->f:Landroid/app/PendingIntent;

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    move v4, v3

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    move v4, v2

    .line 28
    :goto_0
    if-eqz v4, :cond_2

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_2
    const/4 p1, 0x0

    .line 32
    invoke-virtual {v0, p0, p1, v1}, Ljo/f;->b(Landroid/content/Context;Ljava/lang/String;I)Landroid/content/Intent;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    if-nez v4, :cond_3

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_3
    const/high16 p1, 0xc000000

    .line 40
    .line 41
    invoke-static {p0, v2, v4, p1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    :goto_1
    if-eqz p1, :cond_4

    .line 46
    .line 47
    sget v4, Lcom/google/android/gms/common/api/GoogleApiActivity;->e:I

    .line 48
    .line 49
    new-instance v4, Landroid/content/Intent;

    .line 50
    .line 51
    const-class v5, Lcom/google/android/gms/common/api/GoogleApiActivity;

    .line 52
    .line 53
    invoke-direct {v4, p0, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 54
    .line 55
    .line 56
    const-string v5, "pending_intent"

    .line 57
    .line 58
    invoke-virtual {v4, v5, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 59
    .line 60
    .line 61
    const-string p1, "failing_client_id"

    .line 62
    .line 63
    invoke-virtual {v4, p1, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 64
    .line 65
    .line 66
    const-string p1, "notify_manager"

    .line 67
    .line 68
    invoke-virtual {v4, p1, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 69
    .line 70
    .line 71
    sget p1, Lcp/c;->a:I

    .line 72
    .line 73
    const/high16 p2, 0x8000000

    .line 74
    .line 75
    or-int/2addr p1, p2

    .line 76
    invoke-static {p0, v2, v4, p1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-virtual {v0, p0, v1, p1}, Ljo/e;->g(Landroid/content/Context;ILandroid/app/PendingIntent;)V

    .line 81
    .line 82
    .line 83
    return v3

    .line 84
    :cond_4
    :goto_2
    return v2
.end method

.method public final e(Lko/i;)Llo/s;
    .locals 3

    .line 1
    iget-object v0, p1, Lko/i;->h:Llo/b;

    .line 2
    .line 3
    iget-object v1, p0, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    check-cast v2, Llo/s;

    .line 10
    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    new-instance v2, Llo/s;

    .line 14
    .line 15
    invoke-direct {v2, p0, p1}, Llo/s;-><init>(Llo/g;Lko/i;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    :cond_0
    iget-object p1, v2, Llo/s;->d:Lko/c;

    .line 22
    .line 23
    invoke-interface {p1}, Lko/c;->h()Z

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    iget-object p0, p0, Llo/g;->p:Landroidx/collection/g;

    .line 30
    .line 31
    invoke-virtual {p0, v0}, Landroidx/collection/g;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    :cond_1
    invoke-virtual {v2}, Llo/s;->n()V

    .line 35
    .line 36
    .line 37
    return-object v2
.end method

.method public final f(Laq/k;ILko/i;)V
    .locals 8

    .line 1
    if-eqz p2, :cond_6

    .line 2
    .line 3
    iget-object v3, p3, Lko/i;->h:Llo/b;

    .line 4
    .line 5
    invoke-virtual {p0}, Llo/g;->b()Z

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    if-nez p3, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-static {}, Lno/n;->e()Lno/n;

    .line 13
    .line 14
    .line 15
    move-result-object p3

    .line 16
    iget-object p3, p3, Lno/n;->a:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p3, Lno/o;

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    if-eqz p3, :cond_3

    .line 22
    .line 23
    iget-boolean v1, p3, Lno/o;->e:Z

    .line 24
    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    iget-boolean p3, p3, Lno/o;->f:Z

    .line 28
    .line 29
    iget-object v1, p0, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 30
    .line 31
    invoke-virtual {v1, v3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    check-cast v1, Llo/s;

    .line 36
    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    iget-object v2, v1, Llo/s;->d:Lko/c;

    .line 40
    .line 41
    instance-of v4, v2, Lno/e;

    .line 42
    .line 43
    if-eqz v4, :cond_2

    .line 44
    .line 45
    check-cast v2, Lno/e;

    .line 46
    .line 47
    iget-object v4, v2, Lno/e;->v:Lno/j0;

    .line 48
    .line 49
    if-eqz v4, :cond_1

    .line 50
    .line 51
    invoke-virtual {v2}, Lno/e;->b()Z

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    if-nez v4, :cond_1

    .line 56
    .line 57
    invoke-static {v1, v2, p2}, Llo/w;->a(Llo/s;Lno/e;I)Lno/g;

    .line 58
    .line 59
    .line 60
    move-result-object p3

    .line 61
    if-eqz p3, :cond_2

    .line 62
    .line 63
    iget v2, v1, Llo/s;->n:I

    .line 64
    .line 65
    add-int/2addr v2, v0

    .line 66
    iput v2, v1, Llo/s;->n:I

    .line 67
    .line 68
    iget-boolean v0, p3, Lno/g;->f:Z

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    move v0, p3

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    :goto_0
    const/4 p2, 0x0

    .line 74
    move-object v1, p0

    .line 75
    goto :goto_3

    .line 76
    :cond_3
    :goto_1
    new-instance p3, Llo/w;

    .line 77
    .line 78
    const-wide/16 v1, 0x0

    .line 79
    .line 80
    if-eqz v0, :cond_4

    .line 81
    .line 82
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 83
    .line 84
    .line 85
    move-result-wide v4

    .line 86
    goto :goto_2

    .line 87
    :cond_4
    move-wide v4, v1

    .line 88
    :goto_2
    if-eqz v0, :cond_5

    .line 89
    .line 90
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 91
    .line 92
    .line 93
    move-result-wide v1

    .line 94
    :cond_5
    move-object v0, p3

    .line 95
    move-wide v6, v1

    .line 96
    move-object v1, p0

    .line 97
    move v2, p2

    .line 98
    invoke-direct/range {v0 .. v7}, Llo/w;-><init>(Llo/g;ILlo/b;JJ)V

    .line 99
    .line 100
    .line 101
    move-object p2, v0

    .line 102
    :goto_3
    if-eqz p2, :cond_6

    .line 103
    .line 104
    iget-object p0, p1, Laq/k;->a:Laq/t;

    .line 105
    .line 106
    iget-object p1, v1, Llo/g;->q:Lbp/c;

    .line 107
    .line 108
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    new-instance p3, Llo/q;

    .line 112
    .line 113
    invoke-direct {p3, p1}, Llo/q;-><init>(Lbp/c;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0, p3, p2}, Laq/t;->b(Ljava/util/concurrent/Executor;Laq/e;)Laq/t;

    .line 117
    .line 118
    .line 119
    :cond_6
    return-void
.end method

.method public final h(Ljo/b;I)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Llo/g;->c(Ljo/b;I)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x5

    .line 8
    const/4 v1, 0x0

    .line 9
    iget-object p0, p0, Llo/g;->q:Lbp/c;

    .line 10
    .line 11
    invoke-virtual {p0, v0, p2, v1, p1}, Landroid/os/Handler;->obtainMessage(IIILjava/lang/Object;)Landroid/os/Message;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Landroid/os/Handler;->sendMessage(Landroid/os/Message;)Z

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final handleMessage(Landroid/os/Message;)Z
    .locals 13

    .line 1
    iget v0, p1, Landroid/os/Message;->what:I

    .line 2
    .line 3
    sget-object v5, Lno/q;->c:Lno/q;

    .line 4
    .line 5
    const-wide/32 v1, 0x493e0

    .line 6
    .line 7
    .line 8
    const-string v3, "GoogleApiManager"

    .line 9
    .line 10
    const/16 v7, 0x11

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    iget-object v8, p0, Llo/g;->q:Lbp/c;

    .line 14
    .line 15
    const/4 v9, 0x0

    .line 16
    const/4 v10, 0x1

    .line 17
    iget-object v6, p0, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 18
    .line 19
    packed-switch v0, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    new-instance p0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string p1, "Unknown message id: "

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v3, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 37
    .line 38
    .line 39
    return v4

    .line 40
    :pswitch_0
    iput-boolean v4, p0, Llo/g;->e:Z

    .line 41
    .line 42
    return v10

    .line 43
    :pswitch_1
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Llo/x;

    .line 46
    .line 47
    iget-wide v0, p1, Llo/x;->c:J

    .line 48
    .line 49
    iget-object v11, p1, Llo/x;->a:Lno/l;

    .line 50
    .line 51
    iget v12, p1, Llo/x;->b:I

    .line 52
    .line 53
    const-wide/16 v2, 0x0

    .line 54
    .line 55
    cmp-long v0, v0, v2

    .line 56
    .line 57
    if-nez v0, :cond_1

    .line 58
    .line 59
    new-instance p1, Lno/p;

    .line 60
    .line 61
    filled-new-array {v11}, [Lno/l;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-direct {p1, v12, v0}, Lno/p;-><init>(ILjava/util/List;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, p0, Llo/g;->g:Lpo/b;

    .line 73
    .line 74
    if-nez v0, :cond_0

    .line 75
    .line 76
    new-instance v1, Lpo/b;

    .line 77
    .line 78
    sget-object v6, Lko/h;->c:Lko/h;

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    iget-object v2, p0, Llo/g;->h:Landroid/content/Context;

    .line 82
    .line 83
    sget-object v4, Lpo/b;->n:Lc2/k;

    .line 84
    .line 85
    invoke-direct/range {v1 .. v6}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 86
    .line 87
    .line 88
    iput-object v1, p0, Llo/g;->g:Lpo/b;

    .line 89
    .line 90
    :cond_0
    iget-object p0, p0, Llo/g;->g:Lpo/b;

    .line 91
    .line 92
    invoke-virtual {p0, p1}, Lpo/b;->f(Lno/p;)Laq/t;

    .line 93
    .line 94
    .line 95
    return v10

    .line 96
    :cond_1
    iget-object v0, p0, Llo/g;->f:Lno/p;

    .line 97
    .line 98
    if-eqz v0, :cond_8

    .line 99
    .line 100
    iget-object v1, v0, Lno/p;->e:Ljava/util/List;

    .line 101
    .line 102
    iget v0, v0, Lno/p;->d:I

    .line 103
    .line 104
    if-ne v0, v12, :cond_4

    .line 105
    .line 106
    if-eqz v1, :cond_2

    .line 107
    .line 108
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    iget v1, p1, Llo/x;->d:I

    .line 113
    .line 114
    if-lt v0, v1, :cond_2

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_2
    iget-object v0, p0, Llo/g;->f:Lno/p;

    .line 118
    .line 119
    iget-object v1, v0, Lno/p;->e:Ljava/util/List;

    .line 120
    .line 121
    if-nez v1, :cond_3

    .line 122
    .line 123
    new-instance v1, Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 126
    .line 127
    .line 128
    iput-object v1, v0, Lno/p;->e:Ljava/util/List;

    .line 129
    .line 130
    :cond_3
    iget-object v0, v0, Lno/p;->e:Ljava/util/List;

    .line 131
    .line 132
    invoke-interface {v0, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_4
    :goto_0
    invoke-virtual {v8, v7}, Landroid/os/Handler;->removeMessages(I)V

    .line 137
    .line 138
    .line 139
    iget-object v0, p0, Llo/g;->f:Lno/p;

    .line 140
    .line 141
    if-eqz v0, :cond_8

    .line 142
    .line 143
    iget v1, v0, Lno/p;->d:I

    .line 144
    .line 145
    if-gtz v1, :cond_5

    .line 146
    .line 147
    invoke-virtual {p0}, Llo/g;->b()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-eqz v1, :cond_7

    .line 152
    .line 153
    :cond_5
    iget-object v1, p0, Llo/g;->g:Lpo/b;

    .line 154
    .line 155
    if-nez v1, :cond_6

    .line 156
    .line 157
    new-instance v1, Lpo/b;

    .line 158
    .line 159
    sget-object v6, Lko/h;->c:Lko/h;

    .line 160
    .line 161
    const/4 v3, 0x0

    .line 162
    iget-object v2, p0, Llo/g;->h:Landroid/content/Context;

    .line 163
    .line 164
    sget-object v4, Lpo/b;->n:Lc2/k;

    .line 165
    .line 166
    invoke-direct/range {v1 .. v6}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 167
    .line 168
    .line 169
    iput-object v1, p0, Llo/g;->g:Lpo/b;

    .line 170
    .line 171
    :cond_6
    iget-object v1, p0, Llo/g;->g:Lpo/b;

    .line 172
    .line 173
    invoke-virtual {v1, v0}, Lpo/b;->f(Lno/p;)Laq/t;

    .line 174
    .line 175
    .line 176
    :cond_7
    iput-object v9, p0, Llo/g;->f:Lno/p;

    .line 177
    .line 178
    :cond_8
    :goto_1
    iget-object v0, p0, Llo/g;->f:Lno/p;

    .line 179
    .line 180
    if-nez v0, :cond_22

    .line 181
    .line 182
    new-instance v0, Ljava/util/ArrayList;

    .line 183
    .line 184
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v0, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    new-instance v1, Lno/p;

    .line 191
    .line 192
    invoke-direct {v1, v12, v0}, Lno/p;-><init>(ILjava/util/List;)V

    .line 193
    .line 194
    .line 195
    iput-object v1, p0, Llo/g;->f:Lno/p;

    .line 196
    .line 197
    invoke-virtual {v8, v7}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    iget-wide v0, p1, Llo/x;->c:J

    .line 202
    .line 203
    invoke-virtual {v8, p0, v0, v1}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 204
    .line 205
    .line 206
    return v10

    .line 207
    :pswitch_2
    iget-object p1, p0, Llo/g;->f:Lno/p;

    .line 208
    .line 209
    if-eqz p1, :cond_22

    .line 210
    .line 211
    iget v0, p1, Lno/p;->d:I

    .line 212
    .line 213
    if-gtz v0, :cond_9

    .line 214
    .line 215
    invoke-virtual {p0}, Llo/g;->b()Z

    .line 216
    .line 217
    .line 218
    move-result v0

    .line 219
    if-eqz v0, :cond_b

    .line 220
    .line 221
    :cond_9
    iget-object v0, p0, Llo/g;->g:Lpo/b;

    .line 222
    .line 223
    if-nez v0, :cond_a

    .line 224
    .line 225
    new-instance v1, Lpo/b;

    .line 226
    .line 227
    sget-object v6, Lko/h;->c:Lko/h;

    .line 228
    .line 229
    const/4 v3, 0x0

    .line 230
    iget-object v2, p0, Llo/g;->h:Landroid/content/Context;

    .line 231
    .line 232
    sget-object v4, Lpo/b;->n:Lc2/k;

    .line 233
    .line 234
    invoke-direct/range {v1 .. v6}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 235
    .line 236
    .line 237
    iput-object v1, p0, Llo/g;->g:Lpo/b;

    .line 238
    .line 239
    :cond_a
    iget-object v0, p0, Llo/g;->g:Lpo/b;

    .line 240
    .line 241
    invoke-virtual {v0, p1}, Lpo/b;->f(Lno/p;)Laq/t;

    .line 242
    .line 243
    .line 244
    :cond_b
    iput-object v9, p0, Llo/g;->f:Lno/p;

    .line 245
    .line 246
    return v10

    .line 247
    :pswitch_3
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 248
    .line 249
    check-cast p0, Llo/t;

    .line 250
    .line 251
    iget-object p1, p0, Llo/t;->a:Llo/b;

    .line 252
    .line 253
    invoke-virtual {v6, p1}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result p1

    .line 257
    if-eqz p1, :cond_22

    .line 258
    .line 259
    iget-object p1, p0, Llo/t;->a:Llo/b;

    .line 260
    .line 261
    invoke-virtual {v6, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object p1

    .line 265
    check-cast p1, Llo/s;

    .line 266
    .line 267
    iget-object v0, p1, Llo/s;->l:Ljava/util/ArrayList;

    .line 268
    .line 269
    iget-object v1, p1, Llo/s;->o:Llo/g;

    .line 270
    .line 271
    iget-object v1, v1, Llo/g;->q:Lbp/c;

    .line 272
    .line 273
    iget-object v2, p1, Llo/s;->c:Ljava/util/LinkedList;

    .line 274
    .line 275
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v0

    .line 279
    if-eqz v0, :cond_22

    .line 280
    .line 281
    const/16 v0, 0xf

    .line 282
    .line 283
    invoke-virtual {v1, v0, p0}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    const/16 v0, 0x10

    .line 287
    .line 288
    invoke-virtual {v1, v0, p0}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    iget-object p0, p0, Llo/t;->b:Ljo/d;

    .line 292
    .line 293
    new-instance v0, Ljava/util/ArrayList;

    .line 294
    .line 295
    invoke-virtual {v2}, Ljava/util/LinkedList;->size()I

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 300
    .line 301
    .line 302
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 303
    .line 304
    .line 305
    move-result-object v1

    .line 306
    :cond_c
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 307
    .line 308
    .line 309
    move-result v3

    .line 310
    if-eqz v3, :cond_e

    .line 311
    .line 312
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v3

    .line 316
    check-cast v3, Llo/f0;

    .line 317
    .line 318
    instance-of v5, v3, Llo/v;

    .line 319
    .line 320
    if-eqz v5, :cond_c

    .line 321
    .line 322
    move-object v5, v3

    .line 323
    check-cast v5, Llo/v;

    .line 324
    .line 325
    invoke-virtual {v5, p1}, Llo/v;->g(Llo/s;)[Ljo/d;

    .line 326
    .line 327
    .line 328
    move-result-object v5

    .line 329
    if-eqz v5, :cond_c

    .line 330
    .line 331
    array-length v6, v5

    .line 332
    move v7, v4

    .line 333
    :goto_3
    if-ge v7, v6, :cond_c

    .line 334
    .line 335
    aget-object v8, v5, v7

    .line 336
    .line 337
    invoke-static {v8, p0}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v8

    .line 341
    if-eqz v8, :cond_d

    .line 342
    .line 343
    if-ltz v7, :cond_c

    .line 344
    .line 345
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 346
    .line 347
    .line 348
    goto :goto_2

    .line 349
    :cond_d
    add-int/lit8 v7, v7, 0x1

    .line 350
    .line 351
    goto :goto_3

    .line 352
    :cond_e
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 353
    .line 354
    .line 355
    move-result p1

    .line 356
    :goto_4
    if-ge v4, p1, :cond_22

    .line 357
    .line 358
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object v1

    .line 362
    check-cast v1, Llo/f0;

    .line 363
    .line 364
    invoke-virtual {v2, v1}, Ljava/util/LinkedList;->remove(Ljava/lang/Object;)Z

    .line 365
    .line 366
    .line 367
    new-instance v3, Law0/d;

    .line 368
    .line 369
    invoke-direct {v3, p0}, Law0/d;-><init>(Ljo/d;)V

    .line 370
    .line 371
    .line 372
    invoke-virtual {v1, v3}, Llo/f0;->b(Ljava/lang/Exception;)V

    .line 373
    .line 374
    .line 375
    add-int/lit8 v4, v4, 0x1

    .line 376
    .line 377
    goto :goto_4

    .line 378
    :pswitch_4
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 379
    .line 380
    check-cast p0, Llo/t;

    .line 381
    .line 382
    iget-object p1, p0, Llo/t;->a:Llo/b;

    .line 383
    .line 384
    invoke-virtual {v6, p1}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 385
    .line 386
    .line 387
    move-result p1

    .line 388
    if-eqz p1, :cond_22

    .line 389
    .line 390
    iget-object p1, p0, Llo/t;->a:Llo/b;

    .line 391
    .line 392
    invoke-virtual {v6, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object p1

    .line 396
    check-cast p1, Llo/s;

    .line 397
    .line 398
    iget-object v0, p1, Llo/s;->l:Ljava/util/ArrayList;

    .line 399
    .line 400
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 401
    .line 402
    .line 403
    move-result p0

    .line 404
    if-nez p0, :cond_f

    .line 405
    .line 406
    goto/16 :goto_e

    .line 407
    .line 408
    :cond_f
    iget-boolean p0, p1, Llo/s;->k:Z

    .line 409
    .line 410
    if-nez p0, :cond_22

    .line 411
    .line 412
    iget-object p0, p1, Llo/s;->d:Lko/c;

    .line 413
    .line 414
    invoke-interface {p0}, Lko/c;->isConnected()Z

    .line 415
    .line 416
    .line 417
    move-result p0

    .line 418
    if-nez p0, :cond_10

    .line 419
    .line 420
    invoke-virtual {p1}, Llo/s;->n()V

    .line 421
    .line 422
    .line 423
    return v10

    .line 424
    :cond_10
    invoke-virtual {p1}, Llo/s;->h()V

    .line 425
    .line 426
    .line 427
    return v10

    .line 428
    :pswitch_5
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 429
    .line 430
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 431
    .line 432
    .line 433
    move-result-object p0

    .line 434
    throw p0

    .line 435
    :pswitch_6
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 436
    .line 437
    invoke-virtual {v6, p0}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    move-result p0

    .line 441
    if-eqz p0, :cond_22

    .line 442
    .line 443
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 444
    .line 445
    invoke-virtual {v6, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 446
    .line 447
    .line 448
    move-result-object p0

    .line 449
    check-cast p0, Llo/s;

    .line 450
    .line 451
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 452
    .line 453
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 454
    .line 455
    invoke-static {p1}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 456
    .line 457
    .line 458
    iget-object p1, p0, Llo/s;->d:Lko/c;

    .line 459
    .line 460
    invoke-interface {p1}, Lko/c;->isConnected()Z

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    if-eqz v0, :cond_13

    .line 465
    .line 466
    iget-object v0, p0, Llo/s;->h:Ljava/util/HashMap;

    .line 467
    .line 468
    invoke-virtual {v0}, Ljava/util/HashMap;->isEmpty()Z

    .line 469
    .line 470
    .line 471
    move-result v0

    .line 472
    if-eqz v0, :cond_13

    .line 473
    .line 474
    iget-object v0, p0, Llo/s;->f:Lvp/y1;

    .line 475
    .line 476
    iget-object v1, v0, Lvp/y1;->e:Ljava/lang/Object;

    .line 477
    .line 478
    check-cast v1, Ljava/util/Map;

    .line 479
    .line 480
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 481
    .line 482
    .line 483
    move-result v1

    .line 484
    if-eqz v1, :cond_12

    .line 485
    .line 486
    iget-object v0, v0, Lvp/y1;->f:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v0, Ljava/util/Map;

    .line 489
    .line 490
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 491
    .line 492
    .line 493
    move-result v0

    .line 494
    if-nez v0, :cond_11

    .line 495
    .line 496
    goto :goto_5

    .line 497
    :cond_11
    const-string p0, "Timing out service connection."

    .line 498
    .line 499
    invoke-interface {p1, p0}, Lko/c;->a(Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    return v10

    .line 503
    :cond_12
    :goto_5
    invoke-virtual {p0}, Llo/s;->k()V

    .line 504
    .line 505
    .line 506
    :cond_13
    return v10

    .line 507
    :pswitch_7
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 508
    .line 509
    invoke-virtual {v6, p0}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 510
    .line 511
    .line 512
    move-result p0

    .line 513
    if-eqz p0, :cond_22

    .line 514
    .line 515
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 516
    .line 517
    invoke-virtual {v6, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object p0

    .line 521
    check-cast p0, Llo/s;

    .line 522
    .line 523
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 524
    .line 525
    iget-object v0, p1, Llo/g;->q:Lbp/c;

    .line 526
    .line 527
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 528
    .line 529
    .line 530
    iget-boolean v0, p0, Llo/s;->k:Z

    .line 531
    .line 532
    if-eqz v0, :cond_22

    .line 533
    .line 534
    iget-object v1, p0, Llo/s;->e:Llo/b;

    .line 535
    .line 536
    iget-object v2, p0, Llo/s;->o:Llo/g;

    .line 537
    .line 538
    iget-object v2, v2, Llo/g;->q:Lbp/c;

    .line 539
    .line 540
    if-eqz v0, :cond_14

    .line 541
    .line 542
    const/16 v0, 0xb

    .line 543
    .line 544
    invoke-virtual {v2, v0, v1}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 545
    .line 546
    .line 547
    const/16 v0, 0x9

    .line 548
    .line 549
    invoke-virtual {v2, v0, v1}, Landroid/os/Handler;->removeMessages(ILjava/lang/Object;)V

    .line 550
    .line 551
    .line 552
    iput-boolean v4, p0, Llo/s;->k:Z

    .line 553
    .line 554
    :cond_14
    iget-object v0, p1, Llo/g;->i:Ljo/e;

    .line 555
    .line 556
    iget-object p1, p1, Llo/g;->h:Landroid/content/Context;

    .line 557
    .line 558
    sget v1, Ljo/f;->a:I

    .line 559
    .line 560
    invoke-virtual {v0, p1, v1}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 561
    .line 562
    .line 563
    move-result p1

    .line 564
    const/16 v0, 0x12

    .line 565
    .line 566
    if-ne p1, v0, :cond_15

    .line 567
    .line 568
    new-instance p1, Lcom/google/android/gms/common/api/Status;

    .line 569
    .line 570
    const/16 v0, 0x15

    .line 571
    .line 572
    const-string v1, "Connection timed out waiting for Google Play services update to complete."

    .line 573
    .line 574
    invoke-direct {p1, v0, v1, v9, v9}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 575
    .line 576
    .line 577
    goto :goto_6

    .line 578
    :cond_15
    new-instance p1, Lcom/google/android/gms/common/api/Status;

    .line 579
    .line 580
    const/16 v0, 0x16

    .line 581
    .line 582
    const-string v1, "API failed to connect while resuming due to an unknown error."

    .line 583
    .line 584
    invoke-direct {p1, v0, v1, v9, v9}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 585
    .line 586
    .line 587
    :goto_6
    invoke-virtual {p0, p1}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 588
    .line 589
    .line 590
    iget-object p0, p0, Llo/s;->d:Lko/c;

    .line 591
    .line 592
    const-string p1, "Timing out connection while resuming."

    .line 593
    .line 594
    invoke-interface {p0, p1}, Lko/c;->a(Ljava/lang/String;)V

    .line 595
    .line 596
    .line 597
    return v10

    .line 598
    :pswitch_8
    iget-object p0, p0, Llo/g;->p:Landroidx/collection/g;

    .line 599
    .line 600
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 601
    .line 602
    .line 603
    new-instance p1, Landroidx/collection/b;

    .line 604
    .line 605
    invoke-direct {p1, p0}, Landroidx/collection/b;-><init>(Landroidx/collection/g;)V

    .line 606
    .line 607
    .line 608
    :cond_16
    :goto_7
    invoke-virtual {p1}, Landroidx/collection/b;->hasNext()Z

    .line 609
    .line 610
    .line 611
    move-result v0

    .line 612
    if-eqz v0, :cond_17

    .line 613
    .line 614
    invoke-virtual {p1}, Landroidx/collection/b;->next()Ljava/lang/Object;

    .line 615
    .line 616
    .line 617
    move-result-object v0

    .line 618
    check-cast v0, Llo/b;

    .line 619
    .line 620
    invoke-virtual {v6, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 621
    .line 622
    .line 623
    move-result-object v0

    .line 624
    check-cast v0, Llo/s;

    .line 625
    .line 626
    if-eqz v0, :cond_16

    .line 627
    .line 628
    invoke-virtual {v0}, Llo/s;->r()V

    .line 629
    .line 630
    .line 631
    goto :goto_7

    .line 632
    :cond_17
    invoke-virtual {p0}, Landroidx/collection/g;->clear()V

    .line 633
    .line 634
    .line 635
    return v10

    .line 636
    :pswitch_9
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 637
    .line 638
    invoke-virtual {v6, p0}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    move-result p0

    .line 642
    if-eqz p0, :cond_22

    .line 643
    .line 644
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 645
    .line 646
    invoke-virtual {v6, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 647
    .line 648
    .line 649
    move-result-object p0

    .line 650
    check-cast p0, Llo/s;

    .line 651
    .line 652
    iget-object p1, p0, Llo/s;->o:Llo/g;

    .line 653
    .line 654
    iget-object p1, p1, Llo/g;->q:Lbp/c;

    .line 655
    .line 656
    invoke-static {p1}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 657
    .line 658
    .line 659
    iget-boolean p1, p0, Llo/s;->k:Z

    .line 660
    .line 661
    if-eqz p1, :cond_22

    .line 662
    .line 663
    invoke-virtual {p0}, Llo/s;->n()V

    .line 664
    .line 665
    .line 666
    return v10

    .line 667
    :pswitch_a
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 668
    .line 669
    check-cast p1, Lko/i;

    .line 670
    .line 671
    invoke-virtual {p0, p1}, Llo/g;->e(Lko/i;)Llo/s;

    .line 672
    .line 673
    .line 674
    return v10

    .line 675
    :pswitch_b
    iget-object p1, p0, Llo/g;->h:Landroid/content/Context;

    .line 676
    .line 677
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 678
    .line 679
    .line 680
    move-result-object v0

    .line 681
    instance-of v0, v0, Landroid/app/Application;

    .line 682
    .line 683
    if-eqz v0, :cond_22

    .line 684
    .line 685
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 686
    .line 687
    .line 688
    move-result-object p1

    .line 689
    check-cast p1, Landroid/app/Application;

    .line 690
    .line 691
    invoke-static {p1}, Llo/d;->b(Landroid/app/Application;)V

    .line 692
    .line 693
    .line 694
    sget-object p1, Llo/d;->h:Llo/d;

    .line 695
    .line 696
    new-instance v0, Llo/r;

    .line 697
    .line 698
    invoke-direct {v0, p0}, Llo/r;-><init>(Llo/g;)V

    .line 699
    .line 700
    .line 701
    invoke-virtual {p1, v0}, Llo/d;->a(Llo/c;)V

    .line 702
    .line 703
    .line 704
    iget-object v0, p1, Llo/d;->d:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 705
    .line 706
    iget-object p1, p1, Llo/d;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 707
    .line 708
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 709
    .line 710
    .line 711
    move-result v3

    .line 712
    if-nez v3, :cond_1a

    .line 713
    .line 714
    sget-object v3, Lto/b;->h:Ljava/lang/Boolean;

    .line 715
    .line 716
    if-nez v3, :cond_18

    .line 717
    .line 718
    invoke-static {}, Landroid/os/Process;->isIsolated()Z

    .line 719
    .line 720
    .line 721
    move-result v3

    .line 722
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 723
    .line 724
    .line 725
    move-result-object v3

    .line 726
    sput-object v3, Lto/b;->h:Ljava/lang/Boolean;

    .line 727
    .line 728
    :cond_18
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 729
    .line 730
    .line 731
    move-result v3

    .line 732
    if-nez v3, :cond_19

    .line 733
    .line 734
    new-instance v3, Landroid/app/ActivityManager$RunningAppProcessInfo;

    .line 735
    .line 736
    invoke-direct {v3}, Landroid/app/ActivityManager$RunningAppProcessInfo;-><init>()V

    .line 737
    .line 738
    .line 739
    invoke-static {v3}, Landroid/app/ActivityManager;->getMyMemoryState(Landroid/app/ActivityManager$RunningAppProcessInfo;)V

    .line 740
    .line 741
    .line 742
    invoke-virtual {p1, v10}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    .line 743
    .line 744
    .line 745
    move-result p1

    .line 746
    if-nez p1, :cond_1a

    .line 747
    .line 748
    iget p1, v3, Landroid/app/ActivityManager$RunningAppProcessInfo;->importance:I

    .line 749
    .line 750
    const/16 v3, 0x64

    .line 751
    .line 752
    if-le p1, v3, :cond_1a

    .line 753
    .line 754
    invoke-virtual {v0, v10}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 755
    .line 756
    .line 757
    goto :goto_8

    .line 758
    :cond_19
    move p1, v10

    .line 759
    goto :goto_9

    .line 760
    :cond_1a
    :goto_8
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 761
    .line 762
    .line 763
    move-result p1

    .line 764
    :goto_9
    if-nez p1, :cond_22

    .line 765
    .line 766
    iput-wide v1, p0, Llo/g;->d:J

    .line 767
    .line 768
    return v10

    .line 769
    :pswitch_c
    iget v0, p1, Landroid/os/Message;->arg1:I

    .line 770
    .line 771
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 772
    .line 773
    check-cast p1, Ljo/b;

    .line 774
    .line 775
    invoke-virtual {v6}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 776
    .line 777
    .line 778
    move-result-object v1

    .line 779
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 780
    .line 781
    .line 782
    move-result-object v1

    .line 783
    :cond_1b
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 784
    .line 785
    .line 786
    move-result v2

    .line 787
    if-eqz v2, :cond_1c

    .line 788
    .line 789
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 790
    .line 791
    .line 792
    move-result-object v2

    .line 793
    check-cast v2, Llo/s;

    .line 794
    .line 795
    iget v4, v2, Llo/s;->i:I

    .line 796
    .line 797
    if-ne v4, v0, :cond_1b

    .line 798
    .line 799
    goto :goto_a

    .line 800
    :cond_1c
    move-object v2, v9

    .line 801
    :goto_a
    if-eqz v2, :cond_1e

    .line 802
    .line 803
    iget v0, p1, Ljo/b;->e:I

    .line 804
    .line 805
    const/16 v1, 0xd

    .line 806
    .line 807
    if-ne v0, v1, :cond_1d

    .line 808
    .line 809
    new-instance v1, Lcom/google/android/gms/common/api/Status;

    .line 810
    .line 811
    iget-object p0, p0, Llo/g;->i:Ljo/e;

    .line 812
    .line 813
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 814
    .line 815
    .line 816
    sget-object p0, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 817
    .line 818
    invoke-static {v0}, Ljo/b;->x0(I)Ljava/lang/String;

    .line 819
    .line 820
    .line 821
    move-result-object p0

    .line 822
    iget-object p1, p1, Ljo/b;->g:Ljava/lang/String;

    .line 823
    .line 824
    const-string v0, "Error resolution was canceled by the user, original error message: "

    .line 825
    .line 826
    const-string v3, ": "

    .line 827
    .line 828
    invoke-static {v0, p0, v3, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 829
    .line 830
    .line 831
    move-result-object p0

    .line 832
    invoke-direct {v1, v7, p0, v9, v9}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 833
    .line 834
    .line 835
    invoke-virtual {v2, v1}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 836
    .line 837
    .line 838
    return v10

    .line 839
    :cond_1d
    iget-object p0, v2, Llo/s;->e:Llo/b;

    .line 840
    .line 841
    invoke-static {p0, p1}, Llo/g;->d(Llo/b;Ljo/b;)Lcom/google/android/gms/common/api/Status;

    .line 842
    .line 843
    .line 844
    move-result-object p0

    .line 845
    invoke-virtual {v2, p0}, Llo/s;->f(Lcom/google/android/gms/common/api/Status;)V

    .line 846
    .line 847
    .line 848
    return v10

    .line 849
    :cond_1e
    const-string p0, "Could not find API instance "

    .line 850
    .line 851
    const-string p1, " while trying to fail enqueued calls."

    .line 852
    .line 853
    invoke-static {p0, v0, p1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 854
    .line 855
    .line 856
    move-result-object p0

    .line 857
    new-instance p1, Ljava/lang/Exception;

    .line 858
    .line 859
    invoke-direct {p1}, Ljava/lang/Exception;-><init>()V

    .line 860
    .line 861
    .line 862
    invoke-static {v3, p0, p1}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 863
    .line 864
    .line 865
    return v10

    .line 866
    :pswitch_d
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 867
    .line 868
    check-cast p1, Llo/y;

    .line 869
    .line 870
    iget-object v0, p1, Llo/y;->c:Lko/i;

    .line 871
    .line 872
    iget-object v1, p1, Llo/y;->a:Llo/f0;

    .line 873
    .line 874
    iget-object v0, v0, Lko/i;->h:Llo/b;

    .line 875
    .line 876
    invoke-virtual {v6, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 877
    .line 878
    .line 879
    move-result-object v0

    .line 880
    check-cast v0, Llo/s;

    .line 881
    .line 882
    if-nez v0, :cond_1f

    .line 883
    .line 884
    iget-object v0, p1, Llo/y;->c:Lko/i;

    .line 885
    .line 886
    invoke-virtual {p0, v0}, Llo/g;->e(Lko/i;)Llo/s;

    .line 887
    .line 888
    .line 889
    move-result-object v0

    .line 890
    :cond_1f
    iget-object v2, v0, Llo/s;->d:Lko/c;

    .line 891
    .line 892
    invoke-interface {v2}, Lko/c;->h()Z

    .line 893
    .line 894
    .line 895
    move-result v2

    .line 896
    if-eqz v2, :cond_20

    .line 897
    .line 898
    iget-object p0, p0, Llo/g;->l:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 899
    .line 900
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 901
    .line 902
    .line 903
    move-result p0

    .line 904
    iget p1, p1, Llo/y;->b:I

    .line 905
    .line 906
    if-eq p0, p1, :cond_20

    .line 907
    .line 908
    sget-object p0, Llo/g;->s:Lcom/google/android/gms/common/api/Status;

    .line 909
    .line 910
    invoke-virtual {v1, p0}, Llo/f0;->a(Lcom/google/android/gms/common/api/Status;)V

    .line 911
    .line 912
    .line 913
    invoke-virtual {v0}, Llo/s;->r()V

    .line 914
    .line 915
    .line 916
    return v10

    .line 917
    :cond_20
    invoke-virtual {v0, v1}, Llo/s;->o(Llo/f0;)V

    .line 918
    .line 919
    .line 920
    return v10

    .line 921
    :pswitch_e
    invoke-virtual {v6}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 922
    .line 923
    .line 924
    move-result-object p0

    .line 925
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 926
    .line 927
    .line 928
    move-result-object p0

    .line 929
    :goto_b
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 930
    .line 931
    .line 932
    move-result p1

    .line 933
    if-eqz p1, :cond_22

    .line 934
    .line 935
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move-result-object p1

    .line 939
    check-cast p1, Llo/s;

    .line 940
    .line 941
    iget-object v0, p1, Llo/s;->o:Llo/g;

    .line 942
    .line 943
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 944
    .line 945
    invoke-static {v0}, Lno/c0;->d(Landroid/os/Handler;)V

    .line 946
    .line 947
    .line 948
    iput-object v9, p1, Llo/s;->m:Ljo/b;

    .line 949
    .line 950
    invoke-virtual {p1}, Llo/s;->n()V

    .line 951
    .line 952
    .line 953
    goto :goto_b

    .line 954
    :pswitch_f
    iget-object p0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 955
    .line 956
    invoke-static {p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->i(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    .line 957
    .line 958
    .line 959
    move-result-object p0

    .line 960
    throw p0

    .line 961
    :pswitch_10
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 962
    .line 963
    check-cast p1, Ljava/lang/Boolean;

    .line 964
    .line 965
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 966
    .line 967
    .line 968
    move-result p1

    .line 969
    if-eq v10, p1, :cond_21

    .line 970
    .line 971
    goto :goto_c

    .line 972
    :cond_21
    const-wide/16 v1, 0x2710

    .line 973
    .line 974
    :goto_c
    iput-wide v1, p0, Llo/g;->d:J

    .line 975
    .line 976
    const/16 p1, 0xc

    .line 977
    .line 978
    invoke-virtual {v8, p1}, Landroid/os/Handler;->removeMessages(I)V

    .line 979
    .line 980
    .line 981
    invoke-virtual {v6}, Ljava/util/concurrent/ConcurrentHashMap;->keySet()Ljava/util/Set;

    .line 982
    .line 983
    .line 984
    move-result-object v0

    .line 985
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 986
    .line 987
    .line 988
    move-result-object v0

    .line 989
    :goto_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 990
    .line 991
    .line 992
    move-result v1

    .line 993
    if-eqz v1, :cond_22

    .line 994
    .line 995
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 996
    .line 997
    .line 998
    move-result-object v1

    .line 999
    check-cast v1, Llo/b;

    .line 1000
    .line 1001
    invoke-virtual {v8, p1, v1}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v1

    .line 1005
    iget-wide v2, p0, Llo/g;->d:J

    .line 1006
    .line 1007
    invoke-virtual {v8, v1, v2, v3}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    .line 1008
    .line 1009
    .line 1010
    goto :goto_d

    .line 1011
    :cond_22
    :goto_e
    return v10

    .line 1012
    nop

    .line 1013
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_d
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_d
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
