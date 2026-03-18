.class public abstract Lo5/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static volatile a:Lo5/b;

.field public static volatile b:Ljava/util/ArrayList;


# direct methods
.method public static final a(Law0/h;Ljava/nio/charset/Charset;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Llw0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Llw0/c;

    .line 7
    .line 8
    iget v1, v0, Llw0/c;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Llw0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llw0/c;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Llw0/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Llw0/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Llw0/c;->d:Ljava/nio/charset/CharsetDecoder;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_4

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    const-string p2, "<this>"

    .line 54
    .line 55
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p0}, Low0/r;->a()Low0/m;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    sget-object v2, Low0/q;->a:Ljava/util/List;

    .line 63
    .line 64
    const-string v2, "Content-Type"

    .line 65
    .line 66
    invoke-interface {p2, v2}, Lvw0/j;->get(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    const/4 v2, 0x0

    .line 71
    if-eqz p2, :cond_3

    .line 72
    .line 73
    sget-object v4, Low0/e;->f:Low0/e;

    .line 74
    .line 75
    invoke-static {p2}, Ljp/hc;->b(Ljava/lang/String;)Low0/e;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    goto :goto_1

    .line 80
    :cond_3
    move-object p2, v2

    .line 81
    :goto_1
    if-eqz p2, :cond_4

    .line 82
    .line 83
    invoke-static {p2}, Ljp/ic;->e(Low0/e;)Ljava/nio/charset/Charset;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    goto :goto_2

    .line 88
    :cond_4
    move-object p2, v2

    .line 89
    :goto_2
    if-nez p2, :cond_5

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_5
    move-object p1, p2

    .line 93
    :goto_3
    invoke-virtual {p1}, Ljava/nio/charset/Charset;->newDecoder()Ljava/nio/charset/CharsetDecoder;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-virtual {p0}, Law0/h;->M()Law0/c;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 102
    .line 103
    const-class v4, Lnz0/i;

    .line 104
    .line 105
    invoke-virtual {p2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 106
    .line 107
    .line 108
    move-result-object p2

    .line 109
    :try_start_0
    invoke-static {v4}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 110
    .line 111
    .line 112
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 113
    :catchall_0
    new-instance v4, Lzw0/a;

    .line 114
    .line 115
    invoke-direct {v4, p2, v2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 116
    .line 117
    .line 118
    iput-object p1, v0, Llw0/c;->d:Ljava/nio/charset/CharsetDecoder;

    .line 119
    .line 120
    iput v3, v0, Llw0/c;->f:I

    .line 121
    .line 122
    invoke-virtual {p0, v4, v0}, Law0/c;->a(Lzw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    if-ne p2, v1, :cond_6

    .line 127
    .line 128
    return-object v1

    .line 129
    :cond_6
    move-object p0, p1

    .line 130
    :goto_4
    if-eqz p2, :cond_7

    .line 131
    .line 132
    check-cast p2, Lnz0/i;

    .line 133
    .line 134
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    invoke-static {p0, p2}, Ljp/r1;->b(Ljava/nio/charset/CharsetDecoder;Lnz0/i;)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    return-object p0

    .line 142
    :cond_7
    new-instance p0, Ljava/lang/NullPointerException;

    .line 143
    .line 144
    const-string p1, "null cannot be cast to non-null type kotlinx.io.Source"

    .line 145
    .line 146
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    throw p0
.end method

.method public static final b(Ler0/g;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x1

    .line 11
    if-eq p0, v0, :cond_2

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    if-eq p0, v0, :cond_1

    .line 15
    .line 16
    const/4 v0, 0x3

    .line 17
    if-eq p0, v0, :cond_0

    .line 18
    .line 19
    const p0, 0x7f1201c9

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :cond_0
    const p0, 0x7f1201c2

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :cond_1
    const p0, 0x7f1201c0

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :cond_2
    const p0, 0x7f1201c1

    .line 32
    .line 33
    .line 34
    return p0
.end method

.method public static final c(Law0/h;)Lkw0/b;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Law0/h;->M()Law0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Law0/c;->c()Lkw0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static d(Landroid/content/Context;)Ljava/util/List;
    .locals 5

    .line 1
    sget-object v0, Lo5/c;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez v0, :cond_4

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    new-instance v2, Landroid/content/Intent;

    .line 15
    .line 16
    const-string v3, "androidx.core.content.pm.SHORTCUT_LISTENER"

    .line 17
    .line 18
    invoke-direct {v2, v3}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 26
    .line 27
    .line 28
    const/16 v3, 0x80

    .line 29
    .line 30
    invoke-virtual {v1, v2, v3}, Landroid/content/pm/PackageManager;->queryIntentActivities(Landroid/content/Intent;I)Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    :catch_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_3

    .line 43
    .line 44
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    check-cast v2, Landroid/content/pm/ResolveInfo;

    .line 49
    .line 50
    iget-object v2, v2, Landroid/content/pm/ResolveInfo;->activityInfo:Landroid/content/pm/ActivityInfo;

    .line 51
    .line 52
    if-nez v2, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    iget-object v2, v2, Landroid/content/pm/ActivityInfo;->metaData:Landroid/os/Bundle;

    .line 56
    .line 57
    if-nez v2, :cond_1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    const-string v3, "androidx.core.content.pm.shortcut_listener_impl"

    .line 61
    .line 62
    invoke-virtual {v2, v3}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    if-nez v2, :cond_2

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    :try_start_0
    const-class v3, Lo5/c;

    .line 70
    .line 71
    invoke-virtual {v3}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-static {v2, v4, v3}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    const-string v3, "getInstance"

    .line 81
    .line 82
    const-class v4, Landroid/content/Context;

    .line 83
    .line 84
    filled-new-array {v4}, [Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-virtual {v2, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    const/4 v4, 0x0

    .line 97
    invoke-virtual {v2, v4, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    check-cast v2, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 102
    .line 103
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_3
    sget-object p0, Lo5/c;->b:Ljava/util/ArrayList;

    .line 108
    .line 109
    if-nez p0, :cond_4

    .line 110
    .line 111
    sput-object v0, Lo5/c;->b:Ljava/util/ArrayList;

    .line 112
    .line 113
    :cond_4
    sget-object p0, Lo5/c;->b:Ljava/util/ArrayList;

    .line 114
    .line 115
    return-object p0
.end method

.method public static e(Landroid/content/Context;)Lo5/b;
    .locals 3

    .line 1
    sget-object v0, Lo5/c;->a:Lo5/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    const-class v0, Lo5/c;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-string v1, "androidx.sharetarget.ShortcutInfoCompatSaverImpl"

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-static {v1, v2, v0}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v1, "getInstance"

    .line 19
    .line 20
    const-class v2, Landroid/content/Context;

    .line 21
    .line 22
    filled-new-array {v2}, [Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-virtual {v0, v1, p0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lo5/b;

    .line 40
    .line 41
    sput-object p0, Lo5/c;->a:Lo5/b;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    :catch_0
    sget-object p0, Lo5/c;->a:Lo5/b;

    .line 44
    .line 45
    if-nez p0, :cond_0

    .line 46
    .line 47
    new-instance p0, Lo5/b;

    .line 48
    .line 49
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 50
    .line 51
    .line 52
    sput-object p0, Lo5/c;->a:Lo5/b;

    .line 53
    .line 54
    :cond_0
    sget-object p0, Lo5/c;->a:Lo5/b;

    .line 55
    .line 56
    return-object p0
.end method

.method public static f(Landroid/content/Context;Ljava/lang/String;)V
    .locals 12

    .line 1
    const-class v0, Landroid/content/pm/ShortcutManager;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/content/pm/ShortcutManager;

    .line 8
    .line 9
    invoke-virtual {v0, p1}, Landroid/content/pm/ShortcutManager;->reportShortcutUsed(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0}, Lo5/c;->d(Landroid/content/Context;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;

    .line 33
    .line 34
    invoke-static {p1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_0

    .line 50
    .line 51
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    check-cast v2, Ljava/lang/String;

    .line 56
    .line 57
    iget-object v3, v0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->c:Lbp/b;

    .line 58
    .line 59
    iget-object v4, v0, Landroidx/core/google/shortcuts/ShortcutInfoChangeListenerImpl;->a:Landroid/content/Context;

    .line 60
    .line 61
    invoke-static {v4, v2}, Lkp/k;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    new-instance v11, Landroid/os/Bundle;

    .line 66
    .line 67
    invoke-direct {v11}, Landroid/os/Bundle;-><init>()V

    .line 68
    .line 69
    .line 70
    invoke-static {v8}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    new-instance v5, Lbp/p;

    .line 74
    .line 75
    const/4 v9, 0x0

    .line 76
    const/4 v10, 0x0

    .line 77
    const-string v6, "ViewAction"

    .line 78
    .line 79
    const-string v7, ""

    .line 80
    .line 81
    invoke-direct/range {v5 .. v11}, Lbp/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 82
    .line 83
    .line 84
    filled-new-array {v5}, [Lbp/p;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    iget-object v3, v3, Lbp/b;->a:Lbp/q;

    .line 89
    .line 90
    new-instance v4, Lbp/x;

    .line 91
    .line 92
    invoke-direct {v4, v2}, Lbp/x;-><init>([Lbp/p;)V

    .line 93
    .line 94
    .line 95
    const/4 v2, 0x1

    .line 96
    invoke-virtual {v3, v2, v4}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_1
    return-void
.end method
