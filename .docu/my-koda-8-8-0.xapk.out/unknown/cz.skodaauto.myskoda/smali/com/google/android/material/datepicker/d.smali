.class public final Lcom/google/android/material/datepicker/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public final d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 57
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 58
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 59
    sget-object v0, Lk0/j;->f:Lk0/j;

    .line 60
    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 61
    sget-object v0, Lv0/e;->f:Ljava/lang/Object;

    monitor-enter v0

    .line 62
    :try_start_0
    sget-object v1, Lv0/e;->g:Lv0/e;

    if-nez v1, :cond_0

    .line 63
    new-instance v1, Lv0/e;

    invoke-direct {v1}, Lv0/e;-><init>()V

    sput-object v1, Lv0/e;->g:Lv0/e;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 64
    :cond_0
    :goto_0
    sget-object v1, Lv0/e;->g:Lv0/e;

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 65
    const-string v0, "getInstance(...)"

    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 66
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 67
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    return-void

    .line 68
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0
.end method

.method public constructor <init>(Landroid/content/Context;I)V
    .locals 4

    packed-switch p2, :pswitch_data_0

    .line 1
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    const-class p2, Lcom/google/android/material/datepicker/u;

    .line 3
    invoke-virtual {p2}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object p2

    const v0, 0x7f040383

    .line 4
    invoke-static {p1, p2, v0}, Llp/w9;->e(Landroid/content/Context;Ljava/lang/String;I)Landroid/util/TypedValue;

    move-result-object p2

    iget p2, p2, Landroid/util/TypedValue;->data:I

    .line 5
    sget-object v0, Ldq/a;->m:[I

    .line 6
    invoke-virtual {p1, p2, v0}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object p2

    const/4 v0, 0x4

    const/4 v1, 0x0

    .line 7
    invoke-virtual {p2, v0, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v0

    .line 8
    invoke-static {p1, v0}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    const/4 v0, 0x2

    .line 9
    invoke-virtual {p2, v0, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v0

    .line 10
    invoke-static {p1, v0}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    const/4 v0, 0x3

    .line 11
    invoke-virtual {p2, v0, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v0

    .line 12
    invoke-static {p1, v0}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    const/4 v0, 0x5

    .line 13
    invoke-virtual {p2, v0, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v0

    .line 14
    invoke-static {p1, v0}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    const/4 v0, 0x7

    .line 15
    invoke-static {p1, p2, v0}, Llp/x9;->b(Landroid/content/Context;Landroid/content/res/TypedArray;I)Landroid/content/res/ColorStateList;

    move-result-object v0

    const/16 v2, 0x9

    .line 16
    invoke-virtual {p2, v2, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v2

    .line 17
    invoke-static {p1, v2}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object v2

    iput-object v2, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    const/16 v2, 0x8

    .line 18
    invoke-virtual {p2, v2, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v2

    .line 19
    invoke-static {p1, v2}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object v2

    iput-object v2, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    const/16 v2, 0xa

    .line 20
    invoke-virtual {p2, v2, v1}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result v1

    .line 21
    invoke-static {p1, v1}, Lca/j;->c(Landroid/content/Context;I)Lca/j;

    move-result-object p1

    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 22
    new-instance p1, Landroid/graphics/Paint;

    invoke-direct {p1}, Landroid/graphics/Paint;-><init>()V

    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 23
    invoke-virtual {v0}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    move-result p0

    invoke-virtual {p1, p0}, Landroid/graphics/Paint;->setColor(I)V

    .line 24
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    return-void

    .line 25
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    .line 27
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 28
    sget-object p1, Lmm/e;->o:Lmm/e;

    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 29
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 30
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 31
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 32
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 33
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 34
    new-instance p1, Lyl/h;

    invoke-direct {p1}, Lyl/h;-><init>()V

    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    return-void

    .line 35
    :pswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 36
    new-instance p2, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-direct {p2, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object p2, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 37
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    iput-object p2, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 38
    new-instance p2, Lww/e;

    invoke-direct {p2, p1}, Lww/e;-><init>(Landroid/content/Context;)V

    iput-object p2, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 39
    new-instance p2, Ljava/io/File;

    invoke-virtual {p1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    move-result-object v0

    const-string v1, ".phrase_cache"

    invoke-direct {p2, v0, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/io/File;->mkdirs()Z

    .line 40
    new-instance v0, Ljava/io/File;

    invoke-virtual {p1}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object v2

    invoke-direct {v0, v2, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->mkdirs()Z

    .line 41
    new-instance v1, Landroidx/lifecycle/c1;

    invoke-direct {v1, p2, v0}, Landroidx/lifecycle/c1;-><init>(Ljava/io/File;Ljava/io/File;)V

    .line 42
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 43
    new-instance p2, Lro/f;

    const/16 v0, 0xe

    invoke-direct {p2, v1, v0}, Lro/f;-><init>(Ljava/lang/Object;I)V

    iput-object p2, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    const/4 p2, 0x0

    .line 44
    :try_start_0
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object v0

    const-string v1, "context.packageManager.g\u2026o(context.packageName, 0)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    iget-object v1, v0, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;

    if-eqz v1, :cond_0

    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    move-result v1

    if-nez v1, :cond_0

    .line 46
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;

    goto :goto_0

    .line 47
    :cond_0
    new-instance v0, Landroid/content/pm/PackageManager$NameNotFoundException;

    invoke-direct {v0}, Landroid/content/pm/PackageManager$NameNotFoundException;-><init>()V

    throw v0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    :catch_0
    const-string v0, "Could not read app version"

    invoke-static {v0}, Let/d;->d(Ljava/lang/String;)V

    move-object v0, p2

    .line 49
    :goto_0
    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 50
    new-instance v0, Luw/b;

    .line 51
    invoke-static {p1}, Llp/na;->b(Landroid/content/Context;)Ljava/util/Locale;

    move-result-object v1

    .line 52
    const-string v2, "KvzCzoTw5T8rIrq-jiRiaYbeN0V3Djof2fzjjQaVnJc"

    const-string v3, "6ba09622c4ff51e59f80bfd9a2f2649a"

    invoke-direct {v0, v2, v3, p2, v1}, Luw/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Locale;)V

    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 53
    invoke-virtual {p0, v0}, Lcom/google/android/material/datepicker/d;->d(Luw/b;)V

    .line 54
    new-instance p2, Landroid/content/IntentFilter;

    invoke-direct {p2}, Landroid/content/IntentFilter;-><init>()V

    const-string v0, "android.intent.action.LOCALE_CHANGED"

    invoke-virtual {p2, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 55
    new-instance v0, Lc8/e;

    const/4 v1, 0x4

    invoke-direct {v0, p0, v1}, Lc8/e;-><init>(Ljava/lang/Object;I)V

    .line 56
    invoke-virtual {p1, v0, p2}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lb81/d;)V
    .locals 0

    .line 69
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 70
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 71
    iput-object p2, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 72
    iput-object p3, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 73
    iput-object p4, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 74
    iput-object p5, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 75
    iput-object p6, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 76
    iput-object p7, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 77
    iput-object p8, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lyl/o;)V
    .locals 2

    .line 78
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 79
    iget-object v0, p1, Lyl/o;->a:Landroid/content/Context;

    .line 80
    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 81
    iget-object v0, p1, Lyl/o;->b:Lmm/e;

    .line 82
    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 83
    iget-object v1, p1, Lyl/o;->c:Llx0/i;

    .line 84
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 85
    iget-object v1, p1, Lyl/o;->d:Llx0/i;

    .line 86
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 87
    iget-object v1, p1, Lyl/o;->e:Llx0/i;

    .line 88
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 89
    iget-object v1, p1, Lyl/o;->f:Lyl/g;

    .line 90
    iput-object v1, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 91
    iget-object p1, p1, Lyl/o;->g:Lyl/d;

    .line 92
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 93
    iget-object p1, v0, Lmm/e;->n:Lyl/i;

    .line 94
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    new-instance v0, Lyl/h;

    invoke-direct {v0, p1}, Lyl/h;-><init>(Lyl/i;)V

    .line 96
    iput-object v0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    return-void
.end method

.method public static final b(Lcom/google/android/material/datepicker/d;Lb0/r;)Lh0/v;
    .locals 3

    .line 1
    iget-object p1, p1, Lb0/r;->a:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "iterator(...)"

    .line 8
    .line 9
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "next(...)"

    .line 23
    .line 24
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    check-cast v0, Lb0/p;

    .line 28
    .line 29
    sget-object v0, Lb0/p;->a:Lh0/h;

    .line 30
    .line 31
    invoke-static {v0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_0

    .line 36
    .line 37
    sget-object v1, Lh0/v0;->a:Ljava/lang/Object;

    .line 38
    .line 39
    monitor-enter v1

    .line 40
    :try_start_0
    sget-object v2, Lh0/v0;->b:Ljava/util/HashMap;

    .line 41
    .line 42
    invoke-virtual {v2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Lh0/u;

    .line 47
    .line 48
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v0, Landroid/content/Context;

    .line 52
    .line 53
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :catchall_0
    move-exception p0

    .line 58
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 59
    throw p0

    .line 60
    :cond_1
    sget-object p0, Lh0/w;->a:Lh0/v;

    .line 61
    .line 62
    return-object p0
.end method

.method public static final c(Lcom/google/android/material/datepicker/d;I)V
    .locals 7

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb0/u;

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    goto :goto_4

    .line 8
    :cond_0
    iget-object p0, p0, Lb0/u;->g:Lu/n;

    .line 9
    .line 10
    if-eqz p0, :cond_9

    .line 11
    .line 12
    iget-object p0, p0, Lu/n;->b:Lz/a;

    .line 13
    .line 14
    iget-object v0, p0, Lz/a;->a:Ljava/lang/Object;

    .line 15
    .line 16
    monitor-enter v0

    .line 17
    :try_start_0
    iget v1, p0, Lz/a;->g:I

    .line 18
    .line 19
    if-ne p1, v1, :cond_1

    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    goto :goto_5

    .line 25
    :cond_1
    iput p1, p0, Lz/a;->g:I

    .line 26
    .line 27
    new-instance v2, Ljava/util/ArrayList;

    .line 28
    .line 29
    iget-object v3, p0, Lz/a;->c:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 32
    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    if-ne v1, v3, :cond_2

    .line 36
    .line 37
    if-eq p1, v3, :cond_2

    .line 38
    .line 39
    iget-object p0, p0, Lz/a;->f:Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 42
    .line 43
    .line 44
    :cond_2
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_8

    .line 54
    .line 55
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, Lh0/k0;

    .line 60
    .line 61
    iget-object v2, v0, Lh0/k0;->b:Ljava/lang/Object;

    .line 62
    .line 63
    monitor-enter v2

    .line 64
    const/4 v4, 0x1

    .line 65
    if-ne p1, v3, :cond_3

    .line 66
    .line 67
    move v5, v3

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    move v5, v4

    .line 70
    :goto_1
    :try_start_1
    iput v5, v0, Lh0/k0;->c:I

    .line 71
    .line 72
    const/4 v5, 0x0

    .line 73
    if-eq v1, v3, :cond_4

    .line 74
    .line 75
    if-ne p1, v3, :cond_4

    .line 76
    .line 77
    move v6, v4

    .line 78
    goto :goto_2

    .line 79
    :cond_4
    move v6, v5

    .line 80
    :goto_2
    if-ne v1, v3, :cond_5

    .line 81
    .line 82
    if-eq p1, v3, :cond_5

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_5
    move v4, v5

    .line 86
    :goto_3
    if-nez v6, :cond_6

    .line 87
    .line 88
    if-eqz v4, :cond_7

    .line 89
    .line 90
    :cond_6
    invoke-virtual {v0}, Lh0/k0;->b()V

    .line 91
    .line 92
    .line 93
    :cond_7
    monitor-exit v2

    .line 94
    goto :goto_0

    .line 95
    :catchall_1
    move-exception p0

    .line 96
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 97
    throw p0

    .line 98
    :cond_8
    :goto_4
    return-void

    .line 99
    :goto_5
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 100
    throw p0

    .line 101
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 102
    .line 103
    const-string p1, "CameraX not initialized yet."

    .line 104
    .line 105
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0
.end method

.method public static e(Lcom/google/android/material/datepicker/d;Landroidx/lifecycle/x;Lb0/r;Lb0/d1;)Lv0/b;
    .locals 12

    .line 1
    sget-object v5, Lb0/x;->g:Lb0/x;

    .line 2
    .line 3
    const-string v0, "CX:bindToLifecycle-internal"

    .line 4
    .line 5
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :try_start_0
    invoke-static {}, Llp/k1;->a()V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lb0/u;

    .line 18
    .line 19
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v0, v0, Lb0/u;->a:Lh0/i0;

    .line 23
    .line 24
    invoke-virtual {v0}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p2, v0}, Lb0/r;->c(Ljava/util/LinkedHashSet;)Lh0/b0;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    const-string v0, "select(...)"

    .line 33
    .line 34
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-interface {v1, v0}, Lh0/b0;->q(Z)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, p2}, Lcom/google/android/material/datepicker/d;->g(Lb0/r;)Lh0/c;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    iget-object p2, v3, Lh0/c;->c:Lh0/t;

    .line 46
    .line 47
    check-cast p2, Lh0/v;

    .line 48
    .line 49
    iget-object p2, p2, Lh0/v;->d:Lh0/h;

    .line 50
    .line 51
    const-string v2, "getCompatibilityId(...)"

    .line 52
    .line 53
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v2, v3, Lh0/w0;->a:Lh0/z;

    .line 57
    .line 58
    invoke-interface {v2}, Lh0/z;->f()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    const-string v4, "getCameraId(...)"

    .line 63
    .line 64
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    filled-new-array {v2}, [Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-static {v2}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    new-instance v10, Lb0/q;

    .line 76
    .line 77
    invoke-direct {v10, v2, p2}, Lb0/q;-><init>(Ljava/util/ArrayList;Lh0/h;)V

    .line 78
    .line 79
    .line 80
    iget-object p2, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast p2, Lv0/e;

    .line 83
    .line 84
    iget-object v2, p2, Lv0/e;->a:Ljava/lang/Object;

    .line 85
    .line 86
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 87
    :try_start_1
    iget-object p2, p2, Lv0/e;->b:Ljava/util/HashMap;

    .line 88
    .line 89
    new-instance v4, Lv0/a;

    .line 90
    .line 91
    invoke-static {p1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    invoke-direct {v4, v6, v10}, Lv0/a;-><init>(ILb0/q;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p2, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    check-cast p2, Lv0/b;

    .line 103
    .line 104
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 105
    :try_start_2
    iget-object v2, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v2, Lv0/e;

    .line 108
    .line 109
    iget-object v4, v2, Lv0/e;->a:Ljava/lang/Object;

    .line 110
    .line 111
    monitor-enter v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 112
    :try_start_3
    iget-object v2, v2, Lv0/e;->b:Ljava/util/HashMap;

    .line 113
    .line 114
    invoke-virtual {v2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    invoke-static {v2}, Ljava/util/Collections;->unmodifiableCollection(Ljava/util/Collection;)Ljava/util/Collection;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    monitor-exit v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 123
    :try_start_4
    iget-object v4, p3, Lb0/d1;->g:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v4, Ljava/util/List;

    .line 126
    .line 127
    check-cast v4, Ljava/lang/Iterable;

    .line 128
    .line 129
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    :cond_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v6

    .line 137
    if-eqz v6, :cond_3

    .line 138
    .line 139
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    check-cast v6, Lb0/z1;

    .line 144
    .line 145
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 146
    .line 147
    .line 148
    move-result-object v7

    .line 149
    :cond_1
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 150
    .line 151
    .line 152
    move-result v8

    .line 153
    if-eqz v8, :cond_0

    .line 154
    .line 155
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v8

    .line 159
    const-string v9, "next(...)"

    .line 160
    .line 161
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    check-cast v8, Lv0/b;

    .line 165
    .line 166
    iget-object v9, v8, Lv0/b;->d:Ljava/lang/Object;

    .line 167
    .line 168
    monitor-enter v9
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 169
    :try_start_5
    iget-object v11, v8, Lv0/b;->f:Ll0/g;

    .line 170
    .line 171
    invoke-virtual {v11}, Ll0/g;->z()Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object v11

    .line 175
    check-cast v11, Ljava/util/ArrayList;

    .line 176
    .line 177
    invoke-virtual {v11, v6}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v11

    .line 181
    monitor-exit v9
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 182
    if-eqz v11, :cond_1

    .line 183
    .line 184
    :try_start_6
    invoke-virtual {v8}, Lv0/b;->m()Landroidx/lifecycle/x;

    .line 185
    .line 186
    .line 187
    move-result-object v8

    .line 188
    invoke-static {v8, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    if-eqz v8, :cond_2

    .line 193
    .line 194
    goto :goto_0

    .line 195
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 196
    .line 197
    const-string p1, "Use case %s already bound to a different lifecycle."

    .line 198
    .line 199
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object p2

    .line 203
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p2

    .line 207
    invoke-static {p1, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 215
    :catchall_0
    move-exception v0

    .line 216
    move-object p0, v0

    .line 217
    :try_start_7
    monitor-exit v9
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 218
    :try_start_8
    throw p0

    .line 219
    :cond_3
    if-nez p2, :cond_5

    .line 220
    .line 221
    iget-object p2, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast p2, Lv0/e;

    .line 224
    .line 225
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v0, Lb0/u;

    .line 228
    .line 229
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    iget-object v0, v0, Lb0/u;->k:Lcom/google/firebase/messaging/w;

    .line 233
    .line 234
    if-eqz v0, :cond_4

    .line 235
    .line 236
    move-object v2, v0

    .line 237
    new-instance v0, Ll0/g;

    .line 238
    .line 239
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 240
    .line 241
    move-object v7, v4

    .line 242
    check-cast v7, Lz/a;

    .line 243
    .line 244
    iget-object v4, v2, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 245
    .line 246
    move-object v8, v4

    .line 247
    check-cast v8, Lc2/k;

    .line 248
    .line 249
    iget-object v2, v2, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 250
    .line 251
    move-object v9, v2

    .line 252
    check-cast v9, Lh0/r2;

    .line 253
    .line 254
    const/4 v2, 0x0

    .line 255
    move-object v4, v2

    .line 256
    move-object v6, v5

    .line 257
    invoke-direct/range {v0 .. v9}, Ll0/g;-><init>(Lh0/b0;Lh0/b0;Lh0/c;Lh0/c;Lb0/x;Lb0/x;Lz/a;Lc2/k;Lh0/r2;)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {p2, p1, v0}, Lv0/e;->b(Landroidx/lifecycle/x;Ll0/g;)Lv0/b;

    .line 261
    .line 262
    .line 263
    move-result-object p2

    .line 264
    goto :goto_1

    .line 265
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 266
    .line 267
    const-string p1, "CameraX not initialized yet."

    .line 268
    .line 269
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    throw p0

    .line 273
    :cond_5
    :goto_1
    iget-object v0, p3, Lb0/d1;->g:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v0, Ljava/util/List;

    .line 276
    .line 277
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 278
    .line 279
    .line 280
    move-result v0

    .line 281
    if-eqz v0, :cond_6

    .line 282
    .line 283
    goto :goto_2

    .line 284
    :cond_6
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v0, Lv0/e;

    .line 287
    .line 288
    iget-object v1, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 289
    .line 290
    check-cast v1, Lb0/u;

    .line 291
    .line 292
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    iget-object v1, v1, Lb0/u;->g:Lu/n;

    .line 296
    .line 297
    if-eqz v1, :cond_7

    .line 298
    .line 299
    iget-object v1, v1, Lu/n;->b:Lz/a;

    .line 300
    .line 301
    invoke-virtual {v0, p2, p3, v1}, Lv0/e;->a(Lv0/b;Lb0/d1;Lz/a;)V

    .line 302
    .line 303
    .line 304
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast p0, Ljava/util/HashSet;

    .line 307
    .line 308
    new-instance p3, Lv0/a;

    .line 309
    .line 310
    invoke-static {p1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 311
    .line 312
    .line 313
    move-result p1

    .line 314
    invoke-direct {p3, p1, v10}, Lv0/a;-><init>(ILb0/q;)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {p0, p3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 318
    .line 319
    .line 320
    :goto_2
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 321
    .line 322
    .line 323
    return-object p2

    .line 324
    :cond_7
    :try_start_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 325
    .line 326
    const-string p1, "CameraX not initialized yet."

    .line 327
    .line 328
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 329
    .line 330
    .line 331
    throw p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 332
    :catchall_1
    move-exception v0

    .line 333
    move-object p0, v0

    .line 334
    :try_start_a
    monitor-exit v4
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 335
    :try_start_b
    throw p0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_3

    .line 336
    :catchall_2
    move-exception v0

    .line 337
    move-object p0, v0

    .line 338
    :try_start_c
    monitor-exit v2
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_2

    .line 339
    :try_start_d
    throw p0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_3

    .line 340
    :catchall_3
    move-exception v0

    .line 341
    move-object p0, v0

    .line 342
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 343
    .line 344
    .line 345
    throw p0
.end method

.method public static i(Lcom/google/android/material/datepicker/d;Luw/b;Lhu/q;I)V
    .locals 2

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p1, Luw/b;

    .line 8
    .line 9
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 10
    .line 11
    if-eqz p3, :cond_1

    .line 12
    .line 13
    const/4 p2, 0x0

    .line 14
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const-string p3, "lBundle"

    .line 18
    .line 19
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p3, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p3, Ljava/util/concurrent/ExecutorService;

    .line 25
    .line 26
    new-instance v0, La8/y0;

    .line 27
    .line 28
    const/16 v1, 0x16

    .line 29
    .line 30
    invoke-direct {v0, p0, p1, p2, v1}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p3, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 34
    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public a(Luw/b;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Luw/b;

    .line 4
    .line 5
    iget-object v0, v0, Luw/b;->f:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v1, p1, Luw/b;->f:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v2, p1, Luw/b;->h:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iput-object p1, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    new-instance v0, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v1, "Locale changed: "

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-static {v0}, Let/d;->c(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/d;->d(Luw/b;)V

    .line 37
    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    const/4 v1, 0x2

    .line 41
    invoke-static {p0, p1, v0, v1}, Lcom/google/android/material/datepicker/d;->i(Lcom/google/android/material/datepicker/d;Luw/b;Lhu/q;I)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string p1, "Used Locale "

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p1, " did not change, skipping update"

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-static {p0}, Let/d;->c(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public d(Luw/b;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/lifecycle/c1;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    :try_start_0
    invoke-virtual {v0, p1}, Landroidx/lifecycle/c1;->u(Luw/b;)Lww/d;

    .line 10
    .line 11
    .line 12
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-object v0, v1

    .line 15
    :goto_0
    if-nez v0, :cond_0

    .line 16
    .line 17
    const-string v2, "Reset"

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_0
    const-string v2, "Set"

    .line 21
    .line 22
    :goto_1
    const-string v3, " TranslationRepository for: "

    .line 23
    .line 24
    invoke-static {v2, v3}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-static {p1}, Llp/td;->a(Luw/b;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-static {v2}, Let/d;->c(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    sget-object v2, Luw/c;->a:Lcom/google/android/material/datepicker/d;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    new-instance v2, Lb81/d;

    .line 47
    .line 48
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Lww/e;

    .line 51
    .line 52
    invoke-virtual {p1}, Luw/b;->b()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    const-string v4, "localeHash"

    .line 60
    .line 61
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 65
    .line 66
    invoke-interface {p0, v3, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-nez p0, :cond_1

    .line 71
    .line 72
    const-string p0, ""

    .line 73
    .line 74
    :cond_1
    iget-object p1, p1, Luw/b;->e:Ljava/util/Locale;

    .line 75
    .line 76
    invoke-direct {v2, p0, v0, p1}, Lb81/d;-><init>(Ljava/lang/String;Lww/d;Ljava/util/Locale;)V

    .line 77
    .line 78
    .line 79
    move-object v1, v2

    .line 80
    :cond_2
    sput-object v1, Luw/c;->b:Lb81/d;

    .line 81
    .line 82
    return-void
.end method

.method public f()Lyl/r;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lyl/o;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Landroid/content/Context;

    .line 8
    .line 9
    iget-object v3, v0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Lmm/e;

    .line 12
    .line 13
    iget-object v4, v0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v4, Lyl/h;

    .line 16
    .line 17
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    new-instance v5, Lyl/i;

    .line 21
    .line 22
    iget-object v4, v4, Lyl/h;->a:Ljava/util/LinkedHashMap;

    .line 23
    .line 24
    invoke-static {v4}, Lkp/g8;->d(Ljava/util/Map;)Ljava/util/Map;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-direct {v5, v4}, Lyl/i;-><init>(Ljava/util/Map;)V

    .line 29
    .line 30
    .line 31
    iget-object v6, v3, Lmm/e;->a:Lu01/k;

    .line 32
    .line 33
    iget-object v7, v3, Lmm/e;->b:Lpx0/g;

    .line 34
    .line 35
    iget-object v8, v3, Lmm/e;->c:Lpx0/g;

    .line 36
    .line 37
    iget-object v9, v3, Lmm/e;->d:Lpx0/g;

    .line 38
    .line 39
    iget-object v10, v3, Lmm/e;->e:Lmm/b;

    .line 40
    .line 41
    iget-object v11, v3, Lmm/e;->f:Lmm/b;

    .line 42
    .line 43
    iget-object v12, v3, Lmm/e;->g:Lmm/b;

    .line 44
    .line 45
    iget-object v13, v3, Lmm/e;->h:Lay0/k;

    .line 46
    .line 47
    iget-object v14, v3, Lmm/e;->i:Lay0/k;

    .line 48
    .line 49
    iget-object v15, v3, Lmm/e;->j:Lay0/k;

    .line 50
    .line 51
    iget-object v4, v3, Lmm/e;->k:Lnm/i;

    .line 52
    .line 53
    move-object/from16 v20, v1

    .line 54
    .line 55
    iget-object v1, v3, Lmm/e;->l:Lnm/g;

    .line 56
    .line 57
    iget-object v3, v3, Lmm/e;->m:Lnm/d;

    .line 58
    .line 59
    move-object/from16 v19, v5

    .line 60
    .line 61
    new-instance v5, Lmm/e;

    .line 62
    .line 63
    move-object/from16 v17, v1

    .line 64
    .line 65
    move-object/from16 v18, v3

    .line 66
    .line 67
    move-object/from16 v16, v4

    .line 68
    .line 69
    invoke-direct/range {v5 .. v19}, Lmm/e;-><init>(Lu01/k;Lpx0/g;Lpx0/g;Lpx0/g;Lmm/b;Lmm/b;Lmm/b;Lay0/k;Lay0/k;Lay0/k;Lnm/i;Lnm/g;Lnm/d;Lyl/i;)V

    .line 70
    .line 71
    .line 72
    iget-object v1, v0, Lcom/google/android/material/datepicker/d;->c:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v1, Llx0/i;

    .line 75
    .line 76
    if-nez v1, :cond_0

    .line 77
    .line 78
    new-instance v1, Lyl/k;

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    invoke-direct {v1, v3}, Lyl/k;-><init>(I)V

    .line 82
    .line 83
    .line 84
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    :cond_0
    move-object v3, v1

    .line 89
    iget-object v1, v0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v1, Llx0/i;

    .line 92
    .line 93
    if-nez v1, :cond_1

    .line 94
    .line 95
    new-instance v1, Ly1/i;

    .line 96
    .line 97
    const/16 v4, 0x9

    .line 98
    .line 99
    invoke-direct {v1, v0, v4}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    :cond_1
    move-object v4, v1

    .line 107
    iget-object v1, v0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v1, Llx0/i;

    .line 110
    .line 111
    if-nez v1, :cond_2

    .line 112
    .line 113
    new-instance v1, Lyl/k;

    .line 114
    .line 115
    const/4 v6, 0x1

    .line 116
    invoke-direct {v1, v6}, Lyl/k;-><init>(I)V

    .line 117
    .line 118
    .line 119
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    :cond_2
    iget-object v6, v0, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v6, Lyl/g;

    .line 126
    .line 127
    if-nez v6, :cond_3

    .line 128
    .line 129
    sget-object v6, Lyl/g;->a:Lyl/g;

    .line 130
    .line 131
    :cond_3
    iget-object v0, v0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v0, Lyl/d;

    .line 134
    .line 135
    if-nez v0, :cond_4

    .line 136
    .line 137
    new-instance v7, Lyl/d;

    .line 138
    .line 139
    sget-object v8, Lmx0/s;->d:Lmx0/s;

    .line 140
    .line 141
    move-object v9, v8

    .line 142
    move-object v10, v8

    .line 143
    move-object v11, v8

    .line 144
    move-object v12, v8

    .line 145
    invoke-direct/range {v7 .. v12}, Lyl/d;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 146
    .line 147
    .line 148
    move-object v0, v5

    .line 149
    move-object v5, v1

    .line 150
    move-object v1, v2

    .line 151
    move-object v2, v0

    .line 152
    :goto_0
    move-object/from16 v0, v20

    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_4
    move-object v7, v5

    .line 156
    move-object v5, v1

    .line 157
    move-object v1, v2

    .line 158
    move-object v2, v7

    .line 159
    move-object v7, v0

    .line 160
    goto :goto_0

    .line 161
    :goto_1
    invoke-direct/range {v0 .. v7}, Lyl/o;-><init>(Landroid/content/Context;Lmm/e;Llx0/i;Llx0/i;Llx0/i;Lyl/g;Lyl/d;)V

    .line 162
    .line 163
    .line 164
    new-instance v1, Lyl/r;

    .line 165
    .line 166
    invoke-direct {v1, v0}, Lyl/r;-><init>(Lyl/o;)V

    .line 167
    .line 168
    .line 169
    return-object v1
.end method

.method public g(Lb0/r;)Lh0/c;
    .locals 4

    .line 1
    const-string v0, "cameraSelector"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "CX:getCameraInfo"

    .line 7
    .line 8
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lb0/u;

    .line 18
    .line 19
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    iget-object v0, v0, Lb0/u;->a:Lh0/i0;

    .line 23
    .line 24
    invoke-virtual {v0}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p1, v0}, Lb0/r;->c(Ljava/util/LinkedHashSet;)Lh0/b0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v1, "getCameraInfoInternal(...)"

    .line 37
    .line 38
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {p0, p1}, Lcom/google/android/material/datepicker/d;->b(Lcom/google/android/material/datepicker/d;Lb0/r;)Lh0/v;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-interface {v0}, Lh0/z;->f()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    const-string v2, "getCameraId(...)"

    .line 50
    .line 51
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-object v2, p1, Lh0/v;->d:Lh0/h;

    .line 55
    .line 56
    filled-new-array {v1}, [Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-static {v1}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    new-instance v3, Lb0/q;

    .line 65
    .line 66
    invoke-direct {v3, v1, v2}, Lb0/q;-><init>(Ljava/util/ArrayList;Lh0/h;)V

    .line 67
    .line 68
    .line 69
    iget-object v1, p0, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 70
    .line 71
    monitor-enter v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 72
    :try_start_1
    iget-object v2, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v2, Ljava/util/HashMap;

    .line 75
    .line 76
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    if-nez v2, :cond_0

    .line 81
    .line 82
    new-instance v2, Lh0/c;

    .line 83
    .line 84
    invoke-direct {v2, v0, p1}, Lh0/c;-><init>(Lh0/z;Lh0/t;)V

    .line 85
    .line 86
    .line 87
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast p0, Ljava/util/HashMap;

    .line 90
    .line 91
    invoke-virtual {p0, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :catchall_0
    move-exception p0

    .line 96
    goto :goto_1

    .line 97
    :cond_0
    :goto_0
    :try_start_2
    monitor-exit v1

    .line 98
    check-cast v2, Lh0/c;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 99
    .line 100
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 101
    .line 102
    .line 103
    return-object v2

    .line 104
    :goto_1
    :try_start_3
    monitor-exit v1

    .line 105
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 106
    :catchall_1
    move-exception p0

    .line 107
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 108
    .line 109
    .line 110
    throw p0
.end method

.method public h()V
    .locals 1

    .line 1
    const-string v0, "CX:unbindAll"

    .line 2
    .line 3
    invoke-static {v0}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    invoke-static {}, Llp/k1;->a()V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-static {p0, v0}, Lcom/google/android/material/datepicker/d;->c(Lcom/google/android/material/datepicker/d;I)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lv0/e;

    .line 20
    .line 21
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Ljava/util/HashSet;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Lv0/e;->i(Ljava/util/HashSet;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    .line 28
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 34
    .line 35
    .line 36
    throw p0
.end method
