.class public abstract Lkp/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Landroid/content/Intent;

    .line 2
    .line 3
    const-class v1, Landroidx/core/google/shortcuts/TrampolineActivity;

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "androidx.core.content.pm.SHORTCUT_LISTENER"

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 11
    .line 12
    .line 13
    const-string p0, "id"

    .line 14
    .line 15
    invoke-virtual {v0, p0, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    invoke-virtual {v0, p0}, Landroid/content/Intent;->toUri(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static b(Landroid/content/Context;)Lhu/q;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-static {}, Lor/d;->a()V

    .line 3
    .line 4
    .line 5
    new-instance v1, Lu/x0;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, v1, Lu/x0;->a:Ljava/lang/Object;

    .line 11
    .line 12
    iput-object v0, v1, Lu/x0;->b:Ljava/lang/Object;

    .line 13
    .line 14
    iput-object v0, v1, Lu/x0;->c:Ljava/lang/Object;

    .line 15
    .line 16
    iput-object v0, v1, Lu/x0;->d:Ljava/lang/Object;

    .line 17
    .line 18
    iput-object v0, v1, Lu/x0;->e:Ljava/lang/Object;

    .line 19
    .line 20
    new-instance v2, Lh6/e;

    .line 21
    .line 22
    invoke-direct {v2, p0}, Lh6/e;-><init>(Landroid/content/Context;)V

    .line 23
    .line 24
    .line 25
    iput-object v2, v1, Lu/x0;->a:Ljava/lang/Object;

    .line 26
    .line 27
    new-instance v2, Lhu/q;

    .line 28
    .line 29
    invoke-direct {v2, p0}, Lhu/q;-><init>(Landroid/content/Context;)V

    .line 30
    .line 31
    .line 32
    iput-object v2, v1, Lu/x0;->b:Ljava/lang/Object;

    .line 33
    .line 34
    invoke-static {}, Lor/c;->J()Lh6/e;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    iput-object p0, v1, Lu/x0;->e:Ljava/lang/Object;

    .line 39
    .line 40
    const-string p0, "android-keystore://core-google-shortcuts.MASTER_KEY"

    .line 41
    .line 42
    iput-object p0, v1, Lu/x0;->c:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-virtual {v1}, Lu/x0;->c()Lh6/e;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    monitor-enter p0
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 49
    :try_start_1
    iget-object v1, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Lj1/a;

    .line 52
    .line 53
    invoke-virtual {v1}, Lj1/a;->p()Lhu/q;

    .line 54
    .line 55
    .line 56
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catch Ljava/security/GeneralSecurityException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 58
    return-object v1

    .line 59
    :catchall_0
    move-exception v1

    .line 60
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 61
    :try_start_4
    throw v1
    :try_end_4
    .catch Ljava/security/GeneralSecurityException; {:try_start_4 .. :try_end_4} :catch_0
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 62
    :catch_0
    move-exception p0

    .line 63
    const-string v1, "ShortcutUtils"

    .line 64
    .line 65
    const-string v2, "could not get or create keyset handle."

    .line 66
    .line 67
    invoke-static {v1, v2, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 68
    .line 69
    .line 70
    return-object v0
.end method

.method public static final c(Ll2/o;)Z
    .locals 1

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Landroid/content/res/Configuration;

    .line 10
    .line 11
    iget p0, p0, Landroid/content/res/Configuration;->uiMode:I

    .line 12
    .line 13
    and-int/lit8 p0, p0, 0x30

    .line 14
    .line 15
    const/16 v0, 0x20

    .line 16
    .line 17
    if-ne p0, v0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method
