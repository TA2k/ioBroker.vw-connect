.class public abstract Lh/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lfv/o;

.field public static e:I

.field public static f:Ly5/c;

.field public static g:Ly5/c;

.field public static h:Ljava/lang/Boolean;

.field public static i:Z

.field public static final j:Landroidx/collection/g;

.field public static final k:Ljava/lang/Object;

.field public static final l:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lfv/o;

    .line 2
    .line 3
    new-instance v1, Lj0/a;

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    invoke-direct {v1, v2}, Lj0/a;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, v1}, Lfv/o;-><init>(Lj0/a;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lh/n;->d:Lfv/o;

    .line 13
    .line 14
    const/16 v0, -0x64

    .line 15
    .line 16
    sput v0, Lh/n;->e:I

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    sput-object v0, Lh/n;->f:Ly5/c;

    .line 20
    .line 21
    sput-object v0, Lh/n;->g:Ly5/c;

    .line 22
    .line 23
    sput-object v0, Lh/n;->h:Ljava/lang/Boolean;

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    sput-boolean v1, Lh/n;->i:Z

    .line 27
    .line 28
    new-instance v1, Landroidx/collection/g;

    .line 29
    .line 30
    invoke-direct {v1, v0}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Lh/n;->j:Landroidx/collection/g;

    .line 34
    .line 35
    new-instance v0, Ljava/lang/Object;

    .line 36
    .line 37
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lh/n;->k:Ljava/lang/Object;

    .line 41
    .line 42
    new-instance v0, Ljava/lang/Object;

    .line 43
    .line 44
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lh/n;->l:Ljava/lang/Object;

    .line 48
    .line 49
    return-void
.end method

.method public static a()V
    .locals 5

    .line 1
    sget-object v0, Lh/n;->j:Landroidx/collection/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v1, Landroidx/collection/b;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Landroidx/collection/b;-><init>(Landroidx/collection/g;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    :goto_0
    invoke-virtual {v1}, Landroidx/collection/b;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    invoke-virtual {v1}, Landroidx/collection/b;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Ljava/lang/ref/WeakReference;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lh/n;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    check-cast v0, Lh/z;

    .line 32
    .line 33
    iget-object v2, v0, Lh/z;->n:Landroid/content/Context;

    .line 34
    .line 35
    invoke-static {v2}, Lh/n;->f(Landroid/content/Context;)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_1

    .line 40
    .line 41
    sget-object v3, Lh/n;->f:Ly5/c;

    .line 42
    .line 43
    if-eqz v3, :cond_1

    .line 44
    .line 45
    sget-object v4, Lh/n;->g:Ly5/c;

    .line 46
    .line 47
    invoke-virtual {v3, v4}, Ly5/c;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-nez v3, :cond_1

    .line 52
    .line 53
    new-instance v3, Lh/k;

    .line 54
    .line 55
    const/4 v4, 0x1

    .line 56
    invoke-direct {v3, v2, v4}, Lh/k;-><init>(Landroid/content/Context;I)V

    .line 57
    .line 58
    .line 59
    sget-object v2, Lh/n;->d:Lfv/o;

    .line 60
    .line 61
    invoke-virtual {v2, v3}, Lfv/o;->execute(Ljava/lang/Runnable;)V

    .line 62
    .line 63
    .line 64
    :cond_1
    const/4 v2, 0x1

    .line 65
    invoke-virtual {v0, v2, v2}, Lh/z;->r(ZZ)Z

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    return-void
.end method

.method public static b()Ly5/c;
    .locals 3

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x21

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lh/n;->c()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-static {v0}, Lh/m;->a(Ljava/lang/Object;)Landroid/os/LocaleList;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    new-instance v1, Ly5/c;

    .line 18
    .line 19
    new-instance v2, Ly5/d;

    .line 20
    .line 21
    invoke-direct {v2, v0}, Ly5/d;-><init>(Landroid/os/LocaleList;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {v1, v2}, Ly5/c;-><init>(Ly5/d;)V

    .line 25
    .line 26
    .line 27
    return-object v1

    .line 28
    :cond_0
    sget-object v0, Lh/n;->f:Ly5/c;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    return-object v0

    .line 33
    :cond_1
    sget-object v0, Ly5/c;->b:Ly5/c;

    .line 34
    .line 35
    return-object v0
.end method

.method public static c()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Lh/n;->j:Landroidx/collection/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v1, Landroidx/collection/b;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Landroidx/collection/b;-><init>(Landroidx/collection/g;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    invoke-virtual {v1}, Landroidx/collection/b;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {v1}, Landroidx/collection/b;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Ljava/lang/ref/WeakReference;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lh/n;

    .line 28
    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    check-cast v0, Lh/z;

    .line 32
    .line 33
    iget-object v0, v0, Lh/z;->n:Landroid/content/Context;

    .line 34
    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    const-string v1, "locale"

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    return-object v0

    .line 44
    :cond_1
    const/4 v0, 0x0

    .line 45
    return-object v0
.end method

.method public static f(Landroid/content/Context;)Z
    .locals 4

    .line 1
    sget-object v0, Lh/n;->h:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    sget v0, Landroidx/appcompat/app/AppLocalesMetadataHolderService;->d:I

    .line 6
    .line 7
    invoke-static {}, Lh/d0;->a()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    or-int/lit16 v0, v0, 0x80

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v2, Landroid/content/ComponentName;

    .line 18
    .line 19
    const-class v3, Landroidx/appcompat/app/AppLocalesMetadataHolderService;

    .line 20
    .line 21
    invoke-direct {v2, p0, v3}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, v2, v0}, Landroid/content/pm/PackageManager;->getServiceInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ServiceInfo;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    iget-object p0, p0, Landroid/content/pm/ServiceInfo;->metaData:Landroid/os/Bundle;

    .line 29
    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    const-string v0, "autoStoreLocales"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    sput-object p0, Lh/n;->h:Ljava/lang/Boolean;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catch_0
    const-string p0, "AppCompatDelegate"

    .line 46
    .line 47
    const-string v0, "Checking for metadata for AppLocalesMetadataHolderService : Service not found"

    .line 48
    .line 49
    invoke-static {p0, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 53
    .line 54
    sput-object p0, Lh/n;->h:Ljava/lang/Boolean;

    .line 55
    .line 56
    :cond_0
    :goto_0
    sget-object p0, Lh/n;->h:Ljava/lang/Boolean;

    .line 57
    .line 58
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    return p0
.end method

.method public static i(Lh/z;)V
    .locals 3

    .line 1
    sget-object v0, Lh/n;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lh/n;->j:Landroidx/collection/g;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    new-instance v2, Landroidx/collection/b;

    .line 10
    .line 11
    invoke-direct {v2, v1}, Landroidx/collection/b;-><init>(Landroidx/collection/g;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    :goto_0
    invoke-virtual {v2}, Landroidx/collection/b;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_2

    .line 19
    .line 20
    invoke-virtual {v2}, Landroidx/collection/b;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Ljava/lang/ref/WeakReference;

    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lh/n;

    .line 31
    .line 32
    if-eq v1, p0, :cond_1

    .line 33
    .line 34
    if-nez v1, :cond_0

    .line 35
    .line 36
    :cond_1
    invoke-virtual {v2}, Landroidx/collection/b;->remove()V

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
    :cond_2
    monitor-exit v0

    .line 43
    return-void

    .line 44
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    throw p0
.end method

.method public static q(Landroid/content/Context;)V
    .locals 3

    .line 1
    invoke-static {p0}, Lh/n;->f(Landroid/content/Context;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v1, 0x21

    .line 11
    .line 12
    if-lt v0, v1, :cond_2

    .line 13
    .line 14
    sget-boolean v0, Lh/n;->i:Z

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    sget-object v0, Lh/n;->d:Lfv/o;

    .line 19
    .line 20
    new-instance v1, Lh/k;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-direct {v1, p0, v2}, Lh/k;-><init>(Landroid/content/Context;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lfv/o;->execute(Ljava/lang/Runnable;)V

    .line 27
    .line 28
    .line 29
    :cond_1
    :goto_0
    return-void

    .line 30
    :cond_2
    sget-object v0, Lh/n;->l:Ljava/lang/Object;

    .line 31
    .line 32
    monitor-enter v0

    .line 33
    :try_start_0
    sget-object v1, Lh/n;->f:Ly5/c;

    .line 34
    .line 35
    if-nez v1, :cond_5

    .line 36
    .line 37
    sget-object v1, Lh/n;->g:Ly5/c;

    .line 38
    .line 39
    if-nez v1, :cond_3

    .line 40
    .line 41
    invoke-static {p0}, Landroidx/core/app/c;->e(Landroid/content/Context;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0}, Ly5/c;->a(Ljava/lang/String;)Ly5/c;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    sput-object p0, Lh/n;->g:Ly5/c;

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto :goto_3

    .line 54
    :cond_3
    :goto_1
    sget-object p0, Lh/n;->g:Ly5/c;

    .line 55
    .line 56
    iget-object p0, p0, Ly5/c;->a:Ly5/d;

    .line 57
    .line 58
    iget-object p0, p0, Ly5/d;->a:Landroid/os/LocaleList;

    .line 59
    .line 60
    invoke-virtual {p0}, Landroid/os/LocaleList;->isEmpty()Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    if-eqz p0, :cond_4

    .line 65
    .line 66
    monitor-exit v0

    .line 67
    return-void

    .line 68
    :cond_4
    sget-object p0, Lh/n;->g:Ly5/c;

    .line 69
    .line 70
    sput-object p0, Lh/n;->f:Ly5/c;

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_5
    sget-object v2, Lh/n;->g:Ly5/c;

    .line 74
    .line 75
    invoke-virtual {v1, v2}, Ly5/c;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-nez v1, :cond_6

    .line 80
    .line 81
    sget-object v1, Lh/n;->f:Ly5/c;

    .line 82
    .line 83
    sput-object v1, Lh/n;->g:Ly5/c;

    .line 84
    .line 85
    iget-object v1, v1, Ly5/c;->a:Ly5/d;

    .line 86
    .line 87
    iget-object v1, v1, Ly5/d;->a:Landroid/os/LocaleList;

    .line 88
    .line 89
    invoke-virtual {v1}, Landroid/os/LocaleList;->toLanguageTags()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-static {p0, v1}, Landroidx/core/app/c;->d(Landroid/content/Context;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :cond_6
    :goto_2
    monitor-exit v0

    .line 97
    return-void

    .line 98
    :goto_3
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 99
    throw p0
.end method


# virtual methods
.method public abstract d()V
.end method

.method public abstract e()V
.end method

.method public abstract g()V
.end method

.method public abstract h()V
.end method

.method public abstract j(I)Z
.end method

.method public abstract k(I)V
.end method

.method public abstract n(Landroid/view/View;)V
.end method

.method public abstract o(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
.end method

.method public abstract p(Ljava/lang/CharSequence;)V
.end method
