.class public final Lcq/t1;
.super Lno/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Lev/c;

.field public final B:Lev/c;

.field public final C:Lev/c;

.field public final D:Lev/c;

.field public final E:Lev/c;

.field public final F:Lev/c;

.field public final G:Lev/c;

.field public final H:Lev/c;

.field public final I:Lev/c;

.field public final J:Lev/c;

.field public final K:Lcq/v1;

.field public final L:Lop/c;

.field public final z:Ljava/util/concurrent/ExecutorService;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Lin/z1;Llo/s;Llo/s;)V
    .locals 10

    .line 1
    invoke-static {}, Ljava/util/concurrent/Executors;->newCachedThreadPool()Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Ljava/util/concurrent/Executors;->unconfigurableExecutorService(Ljava/util/concurrent/ExecutorService;)Ljava/util/concurrent/ExecutorService;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Lcq/v1;->b:Lcq/v1;

    .line 10
    .line 11
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    const-class v1, Lcq/v1;

    .line 15
    .line 16
    monitor-enter v1

    .line 17
    :try_start_0
    sget-object v2, Lcq/v1;->b:Lcq/v1;

    .line 18
    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    new-instance v2, Lcq/v1;

    .line 22
    .line 23
    invoke-direct {v2, p1}, Lcq/v1;-><init>(Landroid/content/Context;)V

    .line 24
    .line 25
    .line 26
    sput-object v2, Lcq/v1;->b:Lcq/v1;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    move-object p0, v0

    .line 31
    goto/16 :goto_1

    .line 32
    .line 33
    :cond_0
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 34
    sget-object v1, Lcq/v1;->b:Lcq/v1;

    .line 35
    .line 36
    const/16 v5, 0xe

    .line 37
    .line 38
    const/4 v9, 0x0

    .line 39
    move-object v2, p0

    .line 40
    move-object v3, p1

    .line 41
    move-object v4, p2

    .line 42
    move-object v6, p3

    .line 43
    move-object v7, p4

    .line 44
    move-object v8, p5

    .line 45
    invoke-direct/range {v2 .. v9}, Lno/i;-><init>(Landroid/content/Context;Landroid/os/Looper;ILin/z1;Lko/j;Lko/k;I)V

    .line 46
    .line 47
    .line 48
    new-instance p0, Lev/c;

    .line 49
    .line 50
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 51
    .line 52
    .line 53
    iput-object p0, v2, Lcq/t1;->A:Lev/c;

    .line 54
    .line 55
    new-instance p0, Lev/c;

    .line 56
    .line 57
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object p0, v2, Lcq/t1;->B:Lev/c;

    .line 61
    .line 62
    new-instance p0, Lev/c;

    .line 63
    .line 64
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 65
    .line 66
    .line 67
    iput-object p0, v2, Lcq/t1;->C:Lev/c;

    .line 68
    .line 69
    new-instance p0, Lev/c;

    .line 70
    .line 71
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 72
    .line 73
    .line 74
    iput-object p0, v2, Lcq/t1;->D:Lev/c;

    .line 75
    .line 76
    new-instance p0, Lev/c;

    .line 77
    .line 78
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 79
    .line 80
    .line 81
    iput-object p0, v2, Lcq/t1;->E:Lev/c;

    .line 82
    .line 83
    new-instance p0, Lev/c;

    .line 84
    .line 85
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object p0, v2, Lcq/t1;->F:Lev/c;

    .line 89
    .line 90
    new-instance p0, Lev/c;

    .line 91
    .line 92
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 93
    .line 94
    .line 95
    iput-object p0, v2, Lcq/t1;->G:Lev/c;

    .line 96
    .line 97
    new-instance p0, Lev/c;

    .line 98
    .line 99
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 100
    .line 101
    .line 102
    iput-object p0, v2, Lcq/t1;->H:Lev/c;

    .line 103
    .line 104
    new-instance p0, Lev/c;

    .line 105
    .line 106
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 107
    .line 108
    .line 109
    iput-object p0, v2, Lcq/t1;->I:Lev/c;

    .line 110
    .line 111
    new-instance p0, Lev/c;

    .line 112
    .line 113
    invoke-direct {p0}, Lev/c;-><init>()V

    .line 114
    .line 115
    .line 116
    iput-object p0, v2, Lcq/t1;->J:Lev/c;

    .line 117
    .line 118
    new-instance p0, Ljava/util/HashMap;

    .line 119
    .line 120
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 121
    .line 122
    .line 123
    new-instance p0, Ljava/util/HashMap;

    .line 124
    .line 125
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 126
    .line 127
    .line 128
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iput-object v0, v2, Lcq/t1;->z:Ljava/util/concurrent/ExecutorService;

    .line 132
    .line 133
    iput-object v1, v2, Lcq/t1;->K:Lcq/v1;

    .line 134
    .line 135
    new-instance p0, Lcq/r1;

    .line 136
    .line 137
    const/4 p1, 0x0

    .line 138
    invoke-direct {p0, v3, p1}, Lcq/r1;-><init>(Landroid/content/Context;Z)V

    .line 139
    .line 140
    .line 141
    new-instance p1, Lop/c;

    .line 142
    .line 143
    invoke-direct {p1, p0}, Lop/c;-><init>(Lcq/r1;)V

    .line 144
    .line 145
    .line 146
    iput-object p1, v2, Lcq/t1;->L:Lop/c;

    .line 147
    .line 148
    return-void

    .line 149
    :goto_1
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 150
    throw p0
.end method


# virtual methods
.method public final e(Lno/d;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lno/e;->c:Landroid/content/Context;

    .line 2
    .line 3
    const-string v1, "com.google.android.wearable.app.cn"

    .line 4
    .line 5
    const-string v2, "The Wear OS app is out of date. Requires API version 8600000 but found "

    .line 6
    .line 7
    invoke-virtual {p0}, Lcq/t1;->g()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    if-nez v3, :cond_2

    .line 12
    .line 13
    :try_start_0
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    const/16 v4, 0x80

    .line 18
    .line 19
    invoke-virtual {v3, v1, v4}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    iget-object v3, v3, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    const-string v5, "com.google.android.wearable.api.version"

    .line 29
    .line 30
    invoke-virtual {v3, v5, v4}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move v3, v4

    .line 36
    :goto_0
    const v5, 0x8339c0

    .line 37
    .line 38
    .line 39
    if-ge v3, v5, :cond_2

    .line 40
    .line 41
    const-string v5, "WearableClient"

    .line 42
    .line 43
    new-instance v6, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v6, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-static {v5, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    new-instance v2, Landroid/content/Intent;

    .line 59
    .line 60
    const-string v3, "com.google.android.wearable.app.cn.UPDATE_ANDROID_WEAR"

    .line 61
    .line 62
    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2, v1}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const/high16 v5, 0x10000

    .line 74
    .line 75
    invoke-virtual {v3, v2, v5}, Landroid/content/pm/PackageManager;->resolveActivity(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    if-eqz v3, :cond_1

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_1
    const-string v2, "market://details"

    .line 83
    .line 84
    invoke-static {v2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-virtual {v2}, Landroid/net/Uri;->buildUpon()Landroid/net/Uri$Builder;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    const-string v3, "id"

    .line 93
    .line 94
    invoke-virtual {v2, v3, v1}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-virtual {v1}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    new-instance v2, Landroid/content/Intent;

    .line 103
    .line 104
    const-string v3, "android.intent.action.VIEW"

    .line 105
    .line 106
    invoke-direct {v2, v3, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 107
    .line 108
    .line 109
    :goto_1
    sget v1, Lop/f;->a:I

    .line 110
    .line 111
    invoke-static {v0, v4, v2, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    const/4 v1, 0x6

    .line 116
    invoke-virtual {p0, p1, v1, v0}, Lno/e;->y(Lno/d;ILandroid/app/PendingIntent;)V
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 117
    .line 118
    .line 119
    return-void

    .line 120
    :catch_0
    const/16 v0, 0x10

    .line 121
    .line 122
    const/4 v1, 0x0

    .line 123
    invoke-virtual {p0, p1, v0, v1}, Lno/e;->y(Lno/d;ILandroid/app/PendingIntent;)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :cond_2
    invoke-super {p0, p1}, Lno/e;->e(Lno/d;)V

    .line 128
    .line 129
    .line 130
    return-void
.end method

.method public final g()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcq/t1;->K:Lcq/v1;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcq/v1;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final j()I
    .locals 0

    .line 1
    const p0, 0x8339c0

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method public final synthetic m(Landroid/os/IBinder;)Landroid/os/IInterface;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    const-string p0, "com.google.android.gms.wearable.internal.IWearableService"

    .line 6
    .line 7
    invoke-interface {p1, p0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    instance-of v0, p0, Lcq/w0;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    check-cast p0, Lcq/w0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_1
    new-instance p0, Lcq/w0;

    .line 19
    .line 20
    invoke-direct {p0, p1}, Lcq/w0;-><init>(Landroid/os/IBinder;)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public final o()[Ljo/d;
    .locals 0

    .line 1
    sget-object p0, Lbq/g;->b:[Ljo/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "com.google.android.gms.wearable.internal.IWearableService"

    .line 2
    .line 3
    return-object p0
.end method

.method public final t()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "com.google.android.gms.wearable.BIND"

    .line 2
    .line 3
    return-object p0
.end method

.method public final u()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcq/t1;->K:Lcq/v1;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcq/v1;->a()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const-string p0, "com.google.android.wearable.app.cn"

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const-string p0, "com.google.android.gms"

    .line 13
    .line 14
    return-object p0
.end method

.method public final x(ILandroid/os/IBinder;Landroid/os/Bundle;I)V
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    const-string v1, "WearableClient"

    .line 3
    .line 4
    invoke-static {v1, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "onPostInitHandler: statusCode "

    .line 13
    .line 14
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-static {v1, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    :cond_0
    if-nez p1, :cond_1

    .line 28
    .line 29
    iget-object p1, p0, Lcq/t1;->A:Lev/c;

    .line 30
    .line 31
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lcq/t1;->B:Lev/c;

    .line 35
    .line 36
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lcq/t1;->C:Lev/c;

    .line 40
    .line 41
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lcq/t1;->E:Lev/c;

    .line 45
    .line 46
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, p0, Lcq/t1;->F:Lev/c;

    .line 50
    .line 51
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lcq/t1;->G:Lev/c;

    .line 55
    .line 56
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 57
    .line 58
    .line 59
    iget-object p1, p0, Lcq/t1;->H:Lev/c;

    .line 60
    .line 61
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 62
    .line 63
    .line 64
    iget-object p1, p0, Lcq/t1;->I:Lev/c;

    .line 65
    .line 66
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 67
    .line 68
    .line 69
    iget-object p1, p0, Lcq/t1;->J:Lev/c;

    .line 70
    .line 71
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 72
    .line 73
    .line 74
    iget-object p1, p0, Lcq/t1;->D:Lev/c;

    .line 75
    .line 76
    invoke-virtual {p1, p2}, Lev/c;->a(Landroid/os/IBinder;)V

    .line 77
    .line 78
    .line 79
    const/4 p1, 0x0

    .line 80
    :cond_1
    invoke-super {p0, p1, p2, p3, p4}, Lno/e;->x(ILandroid/os/IBinder;Landroid/os/Bundle;I)V

    .line 81
    .line 82
    .line 83
    return-void
.end method

.method public final z()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
