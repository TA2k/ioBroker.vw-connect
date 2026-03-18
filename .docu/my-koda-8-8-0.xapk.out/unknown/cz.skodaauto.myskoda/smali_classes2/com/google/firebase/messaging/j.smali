.class public final Lcom/google/firebase/messaging/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Ljava/lang/Object;

.field public static d:Lcom/google/firebase/messaging/j0;


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Object;


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
    sput-object v0, Lcom/google/firebase/messaging/j;->c:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lcom/google/firebase/messaging/j;->a:Ljava/lang/Object;

    .line 8
    new-instance p1, Lha/c;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Lha/c;-><init>(I)V

    iput-object p1, p0, Lcom/google/firebase/messaging/j;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Landroidx/collection/f;

    const/4 v1, 0x0

    .line 3
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 4
    iput-object v0, p0, Lcom/google/firebase/messaging/j;->b:Ljava/lang/Object;

    .line 5
    iput-object p1, p0, Lcom/google/firebase/messaging/j;->a:Ljava/lang/Object;

    return-void
.end method

.method public static a(Landroid/content/Context;Landroid/content/Intent;Z)Laq/t;
    .locals 4

    .line 1
    const-string v0, "FirebaseMessaging"

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const-string v0, "FirebaseMessaging"

    .line 11
    .line 12
    const-string v1, "Binding to service"

    .line 13
    .line 14
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 15
    .line 16
    .line 17
    :cond_0
    sget-object v0, Lcom/google/firebase/messaging/j;->c:Ljava/lang/Object;

    .line 18
    .line 19
    monitor-enter v0

    .line 20
    :try_start_0
    sget-object v1, Lcom/google/firebase/messaging/j;->d:Lcom/google/firebase/messaging/j0;

    .line 21
    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    new-instance v1, Lcom/google/firebase/messaging/j0;

    .line 25
    .line 26
    invoke-direct {v1, p0}, Lcom/google/firebase/messaging/j0;-><init>(Landroid/content/Context;)V

    .line 27
    .line 28
    .line 29
    sput-object v1, Lcom/google/firebase/messaging/j;->d:Lcom/google/firebase/messaging/j0;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    goto :goto_4

    .line 34
    :cond_1
    :goto_0
    sget-object v1, Lcom/google/firebase/messaging/j;->d:Lcom/google/firebase/messaging/j0;

    .line 35
    .line 36
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    if-eqz p2, :cond_4

    .line 38
    .line 39
    invoke-static {}, Lcom/google/firebase/messaging/w;->k()Lcom/google/firebase/messaging/w;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-virtual {p2, p0}, Lcom/google/firebase/messaging/w;->n(Landroid/content/Context;)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-eqz p2, :cond_3

    .line 48
    .line 49
    sget-object p2, Lcom/google/firebase/messaging/g0;->b:Ljava/lang/Object;

    .line 50
    .line 51
    monitor-enter p2

    .line 52
    :try_start_1
    invoke-static {p0}, Lcom/google/firebase/messaging/g0;->a(Landroid/content/Context;)V

    .line 53
    .line 54
    .line 55
    const-string p0, "com.google.firebase.iid.WakeLockHolder.wakefulintent"

    .line 56
    .line 57
    const/4 v0, 0x0

    .line 58
    invoke-virtual {p1, p0, v0}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    const-string v0, "com.google.firebase.iid.WakeLockHolder.wakefulintent"

    .line 63
    .line 64
    const/4 v2, 0x1

    .line 65
    invoke-virtual {p1, v0, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 66
    .line 67
    .line 68
    if-nez p0, :cond_2

    .line 69
    .line 70
    sget-object p0, Lcom/google/firebase/messaging/g0;->c:Lzp/a;

    .line 71
    .line 72
    sget-wide v2, Lcom/google/firebase/messaging/g0;->a:J

    .line 73
    .line 74
    invoke-virtual {p0, v2, v3}, Lzp/a;->a(J)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :catchall_1
    move-exception p0

    .line 79
    goto :goto_2

    .line 80
    :cond_2
    :goto_1
    invoke-virtual {v1, p1}, Lcom/google/firebase/messaging/j0;->b(Landroid/content/Intent;)Laq/t;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    new-instance v0, La8/t;

    .line 85
    .line 86
    const/16 v1, 0xd

    .line 87
    .line 88
    invoke-direct {v0, p1, v1}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0, v0}, Laq/t;->k(Laq/e;)Laq/t;

    .line 92
    .line 93
    .line 94
    monitor-exit p2

    .line 95
    goto :goto_3

    .line 96
    :goto_2
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 97
    throw p0

    .line 98
    :cond_3
    invoke-virtual {v1, p1}, Lcom/google/firebase/messaging/j0;->b(Landroid/content/Intent;)Laq/t;

    .line 99
    .line 100
    .line 101
    :goto_3
    const/4 p0, -0x1

    .line 102
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    return-object p0

    .line 111
    :cond_4
    invoke-virtual {v1, p1}, Lcom/google/firebase/messaging/j0;->b(Landroid/content/Intent;)Laq/t;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    new-instance p1, Lha/c;

    .line 116
    .line 117
    const/4 p2, 0x0

    .line 118
    invoke-direct {p1, p2}, Lha/c;-><init>(I)V

    .line 119
    .line 120
    .line 121
    new-instance p2, Lc1/y;

    .line 122
    .line 123
    const/4 v0, 0x3

    .line 124
    invoke-direct {p2, v0}, Lc1/y;-><init>(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0, p1, p2}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0

    .line 132
    :goto_4
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 133
    throw p0
.end method


# virtual methods
.method public b(Landroid/content/Intent;)Laq/t;
    .locals 6

    .line 1
    const-string v0, "gcm.rawData64"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    const-string v3, "rawData"

    .line 11
    .line 12
    invoke-static {v1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {p1, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[B)Landroid/content/Intent;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v0}, Landroid/content/Intent;->removeExtra(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    iget-object v0, p0, Lcom/google/firebase/messaging/j;->a:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Landroid/content/Context;

    .line 25
    .line 26
    iget-object p0, p0, Lcom/google/firebase/messaging/j;->b:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lha/c;

    .line 29
    .line 30
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget v1, v1, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I

    .line 35
    .line 36
    const/16 v3, 0x1a

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    if-lt v1, v3, :cond_1

    .line 40
    .line 41
    move v1, v4

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    move v1, v2

    .line 44
    :goto_0
    invoke-virtual {p1}, Landroid/content/Intent;->getFlags()I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    const/high16 v5, 0x10000000

    .line 49
    .line 50
    and-int/2addr v3, v5

    .line 51
    if-eqz v3, :cond_2

    .line 52
    .line 53
    move v2, v4

    .line 54
    :cond_2
    if-eqz v1, :cond_3

    .line 55
    .line 56
    if-nez v2, :cond_3

    .line 57
    .line 58
    invoke-static {v0, p1, v2}, Lcom/google/firebase/messaging/j;->a(Landroid/content/Context;Landroid/content/Intent;Z)Laq/t;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_3
    new-instance v1, Lcom/google/firebase/messaging/h;

    .line 64
    .line 65
    const/4 v3, 0x0

    .line 66
    invoke-direct {v1, v3, v0, p1}, Lcom/google/firebase/messaging/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    invoke-static {p0, v1}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    new-instance v3, Lcom/google/firebase/messaging/i;

    .line 74
    .line 75
    invoke-direct {v3, v0, p1, v2}, Lcom/google/firebase/messaging/i;-><init>(Landroid/content/Context;Landroid/content/Intent;Z)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1, p0, v3}, Laq/t;->e(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method
