.class public final Lm/f2;
.super Lm/i2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Landroid/content/res/Resources;

.field public c:Landroid/content/res/Resources;


# direct methods
.method public constructor <init>(Landroid/content/res/Resources;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lm/i2;-><init>(Landroid/content/res/Resources;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm/f2;->b:Landroid/content/res/Resources;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Landroid/content/res/Resources;
    .locals 5

    .line 1
    sget-object v0, Luw/c;->a:Lcom/google/android/material/datepicker/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, v0, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Luw/b;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, v0, Luw/b;->d:Ljava/lang/String;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v1

    .line 16
    :goto_0
    iget-object v2, p0, Lm/f2;->b:Landroid/content/res/Resources;

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    iput-object v1, p0, Lm/f2;->c:Landroid/content/res/Resources;

    .line 21
    .line 22
    return-object v2

    .line 23
    :cond_1
    invoke-static {v0}, Llp/na;->c(Ljava/lang/String;)Ljava/util/Locale;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iget-object v1, p0, Lm/f2;->c:Landroid/content/res/Resources;

    .line 28
    .line 29
    if-nez v1, :cond_2

    .line 30
    .line 31
    move-object v1, v2

    .line 32
    :cond_2
    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    const-string v4, "currentResources.configuration"

    .line 37
    .line 38
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v3}, Landroid/content/res/Configuration;->getLocales()Landroid/os/LocaleList;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    const/4 v4, 0x0

    .line 46
    invoke-virtual {v3, v4}, Landroid/os/LocaleList;->get(I)Ljava/util/Locale;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-eqz v3, :cond_3

    .line 55
    .line 56
    return-object v1

    .line 57
    :cond_3
    new-instance v3, Landroid/content/res/Configuration;

    .line 58
    .line 59
    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-direct {v3, v1}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v3, v0}, Landroid/content/res/Configuration;->setLocale(Ljava/util/Locale;)V

    .line 67
    .line 68
    .line 69
    new-instance v0, Landroid/content/res/Resources;

    .line 70
    .line 71
    invoke-virtual {v2}, Landroid/content/res/Resources;->getAssets()Landroid/content/res/AssetManager;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    invoke-virtual {v2}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-direct {v0, v1, v2, v3}, Landroid/content/res/Resources;-><init>(Landroid/content/res/AssetManager;Landroid/util/DisplayMetrics;Landroid/content/res/Configuration;)V

    .line 80
    .line 81
    .line 82
    iput-object v0, p0, Lm/f2;->c:Landroid/content/res/Resources;

    .line 83
    .line 84
    return-object v0
.end method

.method public final getConfiguration()Landroid/content/res/Configuration;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lm/f2;->a()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "getFallbackResources().configuration"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public final getQuantityString(II)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lm/f2;->getQuantityText(II)Ljava/lang/CharSequence;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getQuantityText(II)Ljava/lang/CharSequence;
    .locals 5

    .line 1
    sget-object v0, Luw/c;->b:Lb81/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/Locale;

    .line 9
    .line 10
    invoke-static {v0}, Landroid/icu/text/PluralRules;->forLocale(Ljava/util/Locale;)Landroid/icu/text/PluralRules;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v1

    .line 16
    :goto_0
    if-eqz v0, :cond_1

    .line 17
    .line 18
    int-to-double v2, p2

    .line 19
    invoke-virtual {v0, v2, v3}, Landroid/icu/text/PluralRules;->select(D)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move-object v0, v1

    .line 25
    :goto_1
    if-eqz v0, :cond_4

    .line 26
    .line 27
    :try_start_0
    iget-object v2, p0, Lm/i2;->a:Landroid/content/res/Resources;

    .line 28
    .line 29
    invoke-virtual {v2, p1}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    sget-object v3, Luw/c;->b:Lb81/d;

    .line 34
    .line 35
    if-eqz v3, :cond_2

    .line 36
    .line 37
    const-string v4, "pluralKey"

    .line 38
    .line 39
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v3, v3, Lb81/d;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v3, Lww/d;

    .line 45
    .line 46
    iget-object v3, v3, Lww/d;->c:Ljava/util/Map;

    .line 47
    .line 48
    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Ljava/util/Map;

    .line 53
    .line 54
    if-eqz v2, :cond_2

    .line 55
    .line 56
    invoke-interface {v2, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    check-cast v0, Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    move-object v0, v1

    .line 64
    goto :goto_2

    .line 65
    :catchall_0
    move-exception v0

    .line 66
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    :goto_2
    instance-of v2, v0, Llx0/n;

    .line 71
    .line 72
    if-eqz v2, :cond_3

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_3
    move-object v1, v0

    .line 76
    :goto_3
    check-cast v1, Ljava/lang/String;

    .line 77
    .line 78
    :cond_4
    if-eqz v1, :cond_5

    .line 79
    .line 80
    invoke-static {v1}, Llp/na;->a(Ljava/lang/String;)Landroid/text/Spanned;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    goto :goto_4

    .line 85
    :cond_5
    invoke-virtual {p0}, Lm/f2;->a()Landroid/content/res/Resources;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {p0, p1, p2}, Landroid/content/res/Resources;->getQuantityText(II)Ljava/lang/CharSequence;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    const-string p1, "getFallbackResources().g\u2026uantityText(id, quantity)"

    .line 94
    .line 95
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    :goto_4
    return-object p0
.end method

.method public final getString(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lm/f2;->getText(I)Ljava/lang/CharSequence;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final varargs getString(I[Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    const-string v0, "formatArgs"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p0, p1}, Lm/f2;->getString(I)Ljava/lang/String;

    move-result-object p0

    .line 3
    array-length p1, p2

    invoke-static {p2, p1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    array-length p2, p1

    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public final getStringArray(I)[Ljava/lang/String;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget-object v1, p0, Lm/i2;->a:Landroid/content/res/Resources;

    .line 3
    .line 4
    invoke-virtual {v1, p1}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    sget-object v2, Luw/c;->b:Lb81/d;

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    const-string v3, "arrayKey"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v2, Lb81/d;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Lww/d;

    .line 20
    .line 21
    iget-object v2, v2, Lww/d;->b:Ljava/util/Map;

    .line 22
    .line 23
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Ljava/util/List;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :catchall_0
    move-exception v1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move-object v1, v0

    .line 33
    goto :goto_1

    .line 34
    :goto_0
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    :goto_1
    instance-of v2, v1, Llx0/n;

    .line 39
    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    move-object v1, v0

    .line 43
    :cond_1
    check-cast v1, Ljava/util/List;

    .line 44
    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    new-array v0, v0, [Ljava/lang/String;

    .line 49
    .line 50
    invoke-interface {v1, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    check-cast v0, [Ljava/lang/String;

    .line 55
    .line 56
    :cond_2
    if-nez v0, :cond_3

    .line 57
    .line 58
    invoke-virtual {p0}, Lm/f2;->a()Landroid/content/res/Resources;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    const-string p0, "getFallbackResources().getStringArray(id)"

    .line 67
    .line 68
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    :cond_3
    return-object v0
.end method

.method public final getText(I)Ljava/lang/CharSequence;
    .locals 4

    const/4 v0, 0x0

    .line 1
    :try_start_0
    iget-object v1, p0, Lm/i2;->a:Landroid/content/res/Resources;

    invoke-virtual {v1, p1}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    move-result-object v1

    .line 2
    sget-object v2, Luw/c;->b:Lb81/d;

    if-eqz v2, :cond_0

    .line 3
    const-string v3, "stringKey"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    iget-object v2, v2, Lb81/d;->e:Ljava/lang/Object;

    check-cast v2, Lww/d;

    .line 5
    iget-object v2, v2, Lww/d;->a:Ljava/util/Map;

    .line 6
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v1

    goto :goto_0

    :cond_0
    move-object v1, v0

    goto :goto_1

    .line 7
    :goto_0
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    move-result-object v1

    .line 8
    :goto_1
    instance-of v2, v1, Llx0/n;

    if-eqz v2, :cond_1

    goto :goto_2

    :cond_1
    move-object v0, v1

    .line 9
    :goto_2
    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_2

    .line 10
    invoke-static {v0}, Llp/na;->a(Ljava/lang/String;)Landroid/text/Spanned;

    move-result-object p0

    goto :goto_3

    :cond_2
    invoke-virtual {p0}, Lm/f2;->a()Landroid/content/res/Resources;

    move-result-object p0

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getText(I)Ljava/lang/CharSequence;

    move-result-object p0

    const-string p1, "getFallbackResources().getText(id)"

    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_3
    return-object p0
.end method

.method public final getText(ILjava/lang/CharSequence;)Ljava/lang/CharSequence;
    .locals 4

    const/4 v0, 0x0

    .line 11
    :try_start_0
    iget-object v1, p0, Lm/i2;->a:Landroid/content/res/Resources;

    invoke-virtual {v1, p1}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    move-result-object v1

    .line 12
    sget-object v2, Luw/c;->b:Lb81/d;

    if-eqz v2, :cond_0

    .line 13
    const-string v3, "stringKey"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    iget-object v2, v2, Lb81/d;->e:Ljava/lang/Object;

    check-cast v2, Lww/d;

    .line 15
    iget-object v2, v2, Lww/d;->a:Ljava/util/Map;

    .line 16
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v1

    goto :goto_0

    :cond_0
    move-object v1, v0

    goto :goto_1

    .line 17
    :goto_0
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    move-result-object v1

    .line 18
    :goto_1
    instance-of v2, v1, Llx0/n;

    if-eqz v2, :cond_1

    goto :goto_2

    :cond_1
    move-object v0, v1

    .line 19
    :goto_2
    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_2

    .line 20
    invoke-static {v0}, Llp/na;->a(Ljava/lang/String;)Landroid/text/Spanned;

    move-result-object p0

    goto :goto_3

    :cond_2
    invoke-virtual {p0}, Lm/f2;->a()Landroid/content/res/Resources;

    move-result-object p0

    invoke-virtual {p0, p1, p2}, Landroid/content/res/Resources;->getText(ILjava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p0

    :goto_3
    return-object p0
.end method

.method public final getTextArray(I)[Ljava/lang/CharSequence;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget-object v1, p0, Lm/i2;->a:Landroid/content/res/Resources;

    .line 3
    .line 4
    invoke-virtual {v1, p1}, Landroid/content/res/Resources;->getResourceEntryName(I)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    sget-object v2, Luw/c;->b:Lb81/d;

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    const-string v3, "arrayKey"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v2, Lb81/d;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Lww/d;

    .line 20
    .line 21
    iget-object v2, v2, Lww/d;->b:Ljava/util/Map;

    .line 22
    .line 23
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Ljava/util/List;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :catchall_0
    move-exception v1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move-object v1, v0

    .line 33
    goto :goto_1

    .line 34
    :goto_0
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    :goto_1
    instance-of v2, v1, Llx0/n;

    .line 39
    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    move-object v1, v0

    .line 43
    :cond_1
    check-cast v1, Ljava/util/List;

    .line 44
    .line 45
    if-eqz v1, :cond_3

    .line 46
    .line 47
    new-instance v0, Ljava/util/ArrayList;

    .line 48
    .line 49
    const/16 v2, 0xa

    .line 50
    .line 51
    invoke-static {v1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eqz v2, :cond_2

    .line 67
    .line 68
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Ljava/lang/String;

    .line 73
    .line 74
    invoke-static {v2}, Llp/na;->a(Ljava/lang/String;)Landroid/text/Spanned;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_2
    const/4 v1, 0x0

    .line 83
    new-array v1, v1, [Ljava/lang/CharSequence;

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    check-cast v0, [Ljava/lang/CharSequence;

    .line 90
    .line 91
    :cond_3
    if-nez v0, :cond_4

    .line 92
    .line 93
    invoke-virtual {p0}, Lm/f2;->a()Landroid/content/res/Resources;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getTextArray(I)[Ljava/lang/CharSequence;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    const-string p0, "getFallbackResources().getTextArray(id)"

    .line 102
    .line 103
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    :cond_4
    return-object v0
.end method
