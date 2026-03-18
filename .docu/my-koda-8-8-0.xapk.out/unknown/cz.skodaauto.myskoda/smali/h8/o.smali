.class public final Lh8/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lno/d;


# instance fields
.field public a:Z

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(IFLp1/v;)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p3, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 4
    new-instance p3, Ll2/g1;

    invoke-direct {p3, p1}, Ll2/g1;-><init>(I)V

    .line 5
    iput-object p3, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 6
    new-instance p3, Ll2/f1;

    invoke-direct {p3, p2}, Ll2/f1;-><init>(F)V

    .line 7
    iput-object p3, p0, Lh8/o;->d:Ljava/lang/Object;

    .line 8
    new-instance p2, Lo1/g0;

    const/16 p3, 0x1e

    const/16 v0, 0x64

    invoke-direct {p2, p1, p3, v0}, Lo1/g0;-><init>(III)V

    iput-object p2, p0, Lh8/o;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llo/g;Lko/c;Llo/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh8/o;->f:Ljava/lang/Object;

    const/4 p1, 0x0

    iput-object p1, p0, Lh8/o;->d:Ljava/lang/Object;

    iput-object p1, p0, Lh8/o;->e:Ljava/lang/Object;

    const/4 p1, 0x0

    iput-boolean p1, p0, Lh8/o;->a:Z

    iput-object p2, p0, Lh8/o;->b:Ljava/lang/Object;

    iput-object p3, p0, Lh8/o;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lo8/m;Lwe0/b;)V
    .locals 0

    .line 68
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 69
    iput-object p1, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 70
    iput-object p2, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 71
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 72
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lh8/o;->d:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 73
    iput-boolean p1, p0, Lh8/o;->a:Z

    return-void
.end method

.method public constructor <init>(Lsr/f;)V
    .locals 6

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 11
    new-instance v0, Laq/k;

    invoke-direct {v0}, Laq/k;-><init>()V

    iput-object v0, p0, Lh8/o;->d:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Lh8/o;->a:Z

    .line 13
    new-instance v1, Laq/k;

    invoke-direct {v1}, Laq/k;-><init>()V

    iput-object v1, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 14
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 15
    iget-object v1, p1, Lsr/f;->a:Landroid/content/Context;

    .line 16
    iput-object p1, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 17
    const-string p1, "com.google.firebase.crashlytics"

    invoke-virtual {v1, p1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object p1

    .line 18
    const-string v2, "firebase_crashlytics_collection_enabled"

    invoke-interface {p1, v2}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    move-result v3

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v3, :cond_0

    .line 19
    iput-boolean v0, p0, Lh8/o;->a:Z

    .line 20
    invoke-interface {p1, v2, v4}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v5

    :goto_0
    if-nez p1, :cond_3

    .line 21
    const-string p1, "firebase_crashlytics_collection_enabled"

    :try_start_0
    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v2

    if-eqz v2, :cond_1

    .line 22
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v1

    const/16 v3, 0x80

    .line 23
    invoke-virtual {v2, v1, v3}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    move-result-object v1

    if-eqz v1, :cond_1

    .line 24
    iget-object v2, v1, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    if-eqz v2, :cond_1

    .line 25
    invoke-virtual {v2, p1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_1

    .line 26
    iget-object v1, v1, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception p1

    .line 27
    const-string v1, "Could not read data collection permission from manifest"

    .line 28
    const-string v2, "FirebaseCrashlytics"

    invoke-static {v2, v1, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_1
    move-object p1, v5

    :goto_1
    if-nez p1, :cond_2

    .line 29
    iput-boolean v0, p0, Lh8/o;->a:Z

    move-object p1, v5

    goto :goto_2

    .line 30
    :cond_2
    iput-boolean v4, p0, Lh8/o;->a:Z

    .line 31
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {v0, p1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    .line 32
    :cond_3
    :goto_2
    iput-object p1, p0, Lh8/o;->e:Ljava/lang/Object;

    .line 33
    iget-object p1, p0, Lh8/o;->c:Ljava/lang/Object;

    monitor-enter p1

    .line 34
    :try_start_1
    invoke-virtual {p0}, Lh8/o;->a()Z

    move-result v0

    if-eqz v0, :cond_4

    .line 35
    iget-object p0, p0, Lh8/o;->d:Ljava/lang/Object;

    check-cast p0, Laq/k;

    invoke-virtual {p0, v5}, Laq/k;->d(Ljava/lang/Object;)V

    goto :goto_3

    :catchall_0
    move-exception p0

    goto :goto_4

    .line 36
    :cond_4
    :goto_3
    monitor-exit p1

    return-void

    :goto_4
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method

.method public constructor <init>(Lu/m;Lv/b;Lj0/h;)V
    .locals 5

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p3, 0x0

    .line 38
    iput-boolean p3, p0, Lh8/o;->a:Z

    .line 39
    new-instance p3, Lu/j1;

    invoke-direct {p3, p0}, Lu/j1;-><init>(Lh8/o;)V

    iput-object p3, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 40
    iput-object p1, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 41
    sget p3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1e

    if-lt p3, v0, :cond_2

    .line 42
    :try_start_0
    invoke-static {}, Lu/a;->a()Landroid/hardware/camera2/CameraCharacteristics$Key;

    move-result-object p3

    invoke-virtual {p2, p3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Landroid/util/Range;
    :try_end_0
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p3

    .line 43
    const-string v0, "ZoomControl"

    const-string v1, "AssertionError, fail to get camera characteristic."

    invoke-static {v0, v1, p3}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    const/4 p3, 0x0

    :goto_0
    if-eqz p3, :cond_2

    .line 44
    new-instance p3, Lb6/f;

    .line 45
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 46
    iput-boolean v0, p3, Lb6/f;->d:Z

    .line 47
    invoke-static {}, Lu/a;->a()Landroid/hardware/camera2/CameraCharacteristics$Key;

    move-result-object v1

    .line 48
    invoke-virtual {p2, v1}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/util/Range;

    iput-object v1, p3, Lb6/f;->e:Ljava/lang/Object;

    .line 49
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x22

    if-lt v1, v2, :cond_1

    .line 50
    iget-object p2, p2, Lv/b;->b:Lpv/g;

    .line 51
    invoke-static {}, Lt51/b;->e()Landroid/hardware/camera2/CameraCharacteristics$Key;

    move-result-object v1

    .line 52
    iget-object p2, p2, Lpv/g;->e:Ljava/lang/Object;

    check-cast p2, Landroid/hardware/camera2/CameraCharacteristics;

    .line 53
    invoke-virtual {p2, v1}, Landroid/hardware/camera2/CameraCharacteristics;->get(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    move-result-object p2

    .line 54
    check-cast p2, [I

    if-eqz p2, :cond_1

    .line 55
    array-length v1, p2

    move v2, v0

    :goto_1
    if-ge v2, v1, :cond_1

    aget v3, p2, v2

    const/4 v4, 0x1

    if-ne v3, v4, :cond_0

    move v0, v4

    goto :goto_2

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    .line 56
    :cond_1
    :goto_2
    iput-boolean v0, p3, Lb6/f;->d:Z

    goto :goto_3

    .line 57
    :cond_2
    new-instance p3, Lt1/j0;

    const/4 v0, 0x4

    invoke-direct {p3, p2, v0}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 58
    :goto_3
    iput-object p3, p0, Lh8/o;->e:Ljava/lang/Object;

    .line 59
    new-instance p2, Ld3/a;

    invoke-interface {p3}, Lu/k1;->g()F

    move-result v0

    invoke-interface {p3}, Lu/k1;->e()F

    move-result p3

    invoke-direct {p2, v0, p3}, Ld3/a;-><init>(FF)V

    iput-object p2, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 60
    invoke-virtual {p2}, Ld3/a;->j()V

    .line 61
    new-instance p3, Landroidx/lifecycle/i0;

    .line 62
    new-instance v0, Ll0/a;

    invoke-virtual {p2}, Ld3/a;->e()F

    move-result v1

    .line 63
    invoke-virtual {p2}, Ld3/a;->c()F

    move-result v2

    .line 64
    invoke-virtual {p2}, Ld3/a;->d()F

    move-result v3

    invoke-virtual {p2}, Ld3/a;->b()F

    move-result p2

    invoke-direct {v0, v1, v2, v3, p2}, Ll0/a;-><init>(FFFF)V

    .line 65
    invoke-direct {p3, v0}, Landroidx/lifecycle/g0;-><init>(Ljava/lang/Object;)V

    .line 66
    iput-object p3, p0, Lh8/o;->d:Ljava/lang/Object;

    .line 67
    iget-object p0, p0, Lh8/o;->f:Ljava/lang/Object;

    check-cast p0, Lu/j1;

    invoke-virtual {p1, p0}, Lu/m;->h(Lu/l;)V

    return-void
.end method


# virtual methods
.method public declared-synchronized a()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lh8/o;->e:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Ljava/lang/Boolean;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    goto :goto_0

    .line 13
    :catchall_0
    move-exception v0

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    :try_start_1
    iget-object v0, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lsr/f;

    .line 18
    .line 19
    invoke-virtual {v0}, Lsr/f;->h()Z

    .line 20
    .line 21
    .line 22
    move-result v0
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    goto :goto_0

    .line 24
    :catch_0
    const/4 v0, 0x0

    .line 25
    :goto_0
    :try_start_2
    invoke-virtual {p0, v0}, Lh8/o;->c(Z)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 26
    .line 27
    .line 28
    monitor-exit p0

    .line 29
    return v0

    .line 30
    :goto_1
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 31
    throw v0
.end method

.method public b(I)Lgr/m;
    .locals 4

    .line 1
    iget-object v0, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lgr/m;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    return-object v1

    .line 18
    :cond_0
    iget-object v1, p0, Lh8/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Ly7/k;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    const-class v2, Lh8/a0;

    .line 26
    .line 27
    if-eqz p1, :cond_5

    .line 28
    .line 29
    const/4 v3, 0x1

    .line 30
    if-eq p1, v3, :cond_4

    .line 31
    .line 32
    const/4 v3, 0x2

    .line 33
    if-eq p1, v3, :cond_3

    .line 34
    .line 35
    const/4 v3, 0x3

    .line 36
    if-eq p1, v3, :cond_2

    .line 37
    .line 38
    const/4 v2, 0x4

    .line 39
    if-ne p1, v2, :cond_1

    .line 40
    .line 41
    new-instance v2, Lh8/n;

    .line 42
    .line 43
    invoke-direct {v2, p0, v1, v3}, Lh8/n;-><init>(Ljava/lang/Object;Ly7/k;I)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 48
    .line 49
    const-string v0, "Unrecognized contentType: "

    .line 50
    .line 51
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    const-string p0, "androidx.media3.exoplayer.rtsp.RtspMediaSource$Factory"

    .line 60
    .line 61
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p0, v2}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    new-instance v2, La8/d;

    .line 70
    .line 71
    const/4 v1, 0x5

    .line 72
    invoke-direct {v2, p0, v1}, La8/d;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_3
    const-string p0, "androidx.media3.exoplayer.hls.HlsMediaSource$Factory"

    .line 77
    .line 78
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {p0, v2}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    new-instance v2, Lh8/n;

    .line 87
    .line 88
    invoke-direct {v2, p0, v1, v3}, Lh8/n;-><init>(Ljava/lang/Object;Ly7/k;I)V

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_4
    const-string p0, "androidx.media3.exoplayer.smoothstreaming.SsMediaSource$Factory"

    .line 93
    .line 94
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {p0, v2}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    new-instance v2, Lh8/n;

    .line 103
    .line 104
    invoke-direct {v2, p0, v1, v3}, Lh8/n;-><init>(Ljava/lang/Object;Ly7/k;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_5
    const-string p0, "androidx.media3.exoplayer.dash.DashMediaSource$Factory"

    .line 109
    .line 110
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    invoke-virtual {p0, v2}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    new-instance v2, Lh8/n;

    .line 119
    .line 120
    const/4 v3, 0x0

    .line 121
    invoke-direct {v2, p0, v1, v3}, Lh8/n;-><init>(Ljava/lang/Object;Ly7/k;I)V

    .line 122
    .line 123
    .line 124
    :goto_0
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-virtual {v0, p0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    return-object v2
.end method

.method public c(Z)V
    .locals 3

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const-string p1, "ENABLED"

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const-string p1, "DISABLED"

    .line 7
    .line 8
    :goto_0
    iget-object v0, p0, Lh8/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Ljava/lang/Boolean;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    const-string p0, "global Firebase setting"

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    iget-boolean p0, p0, Lh8/o;->a:Z

    .line 18
    .line 19
    if-eqz p0, :cond_2

    .line 20
    .line 21
    const-string p0, "firebase_crashlytics_collection_enabled manifest flag"

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_2
    const-string p0, "API"

    .line 25
    .line 26
    :goto_1
    const-string v0, " by "

    .line 27
    .line 28
    const-string v1, "."

    .line 29
    .line 30
    const-string v2, "Crashlytics automatic data collection "

    .line 31
    .line 32
    invoke-static {v2, p1, v0, p0, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    const/4 p1, 0x3

    .line 37
    const-string v0, "FirebaseCrashlytics"

    .line 38
    .line 39
    invoke-static {v0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-eqz p1, :cond_3

    .line 44
    .line 45
    const/4 p1, 0x0

    .line 46
    invoke-static {v0, p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 47
    .line 48
    .line 49
    :cond_3
    return-void
.end method

.method public d(Ljo/b;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llo/g;

    .line 4
    .line 5
    iget-object v0, v0, Llo/g;->q:Lbp/c;

    .line 6
    .line 7
    new-instance v1, Lk0/g;

    .line 8
    .line 9
    const/16 v2, 0xa

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v1, p0, p1, v3, v2}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public e(Ljo/b;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Llo/g;

    .line 4
    .line 5
    iget-object v0, v0, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 6
    .line 7
    iget-object p0, p0, Lh8/o;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Llo/b;

    .line 10
    .line 11
    invoke-virtual {v0, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Llo/s;

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Llo/s;->q(Ljo/b;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method
