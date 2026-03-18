.class public abstract Ljp/hd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lb90/g;)Z
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lb90/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x1

    .line 10
    if-eqz v0, :cond_5

    .line 11
    .line 12
    check-cast p0, Lb90/j;

    .line 13
    .line 14
    iget-object v0, p0, Lb90/j;->b:Lb90/p;

    .line 15
    .line 16
    iget-object p0, p0, Lb90/j;->c:Ljava/lang/String;

    .line 17
    .line 18
    iget-boolean v3, v0, Lb90/p;->c:Z

    .line 19
    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-lez v3, :cond_1

    .line 27
    .line 28
    :cond_0
    move v3, v2

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    move v3, v1

    .line 31
    :goto_0
    iget-object v4, v0, Lb90/p;->d:Ljava/lang/String;

    .line 32
    .line 33
    if-eqz v4, :cond_3

    .line 34
    .line 35
    iget-boolean v0, v0, Lb90/p;->c:Z

    .line 36
    .line 37
    if-nez v0, :cond_2

    .line 38
    .line 39
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    invoke-static {v4}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    const-string v4, "compile(...)"

    .line 51
    .line 52
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    const-string v4, "input"

    .line 56
    .line 57
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    goto :goto_2

    .line 69
    :cond_3
    :goto_1
    move p0, v2

    .line 70
    :goto_2
    if-eqz v3, :cond_4

    .line 71
    .line 72
    if-eqz p0, :cond_4

    .line 73
    .line 74
    return v2

    .line 75
    :cond_4
    return v1

    .line 76
    :cond_5
    instance-of v0, p0, Lb90/h;

    .line 77
    .line 78
    if-eqz v0, :cond_8

    .line 79
    .line 80
    check-cast p0, Lb90/h;

    .line 81
    .line 82
    iget-object v0, p0, Lb90/h;->b:Lb90/p;

    .line 83
    .line 84
    iget-boolean v0, v0, Lb90/p;->c:Z

    .line 85
    .line 86
    if-eqz v0, :cond_7

    .line 87
    .line 88
    iget-object p0, p0, Lb90/h;->c:Lb90/b;

    .line 89
    .line 90
    if-eqz p0, :cond_6

    .line 91
    .line 92
    return v2

    .line 93
    :cond_6
    return v1

    .line 94
    :cond_7
    return v2

    .line 95
    :cond_8
    instance-of v0, p0, Lb90/i;

    .line 96
    .line 97
    if-eqz v0, :cond_b

    .line 98
    .line 99
    check-cast p0, Lb90/i;

    .line 100
    .line 101
    iget-object v0, p0, Lb90/i;->b:Lb90/p;

    .line 102
    .line 103
    iget-boolean v0, v0, Lb90/p;->c:Z

    .line 104
    .line 105
    if-eqz v0, :cond_a

    .line 106
    .line 107
    iget-object p0, p0, Lb90/i;->c:Ljava/util/Set;

    .line 108
    .line 109
    check-cast p0, Ljava/util/Collection;

    .line 110
    .line 111
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-nez p0, :cond_9

    .line 116
    .line 117
    return v2

    .line 118
    :cond_9
    return v1

    .line 119
    :cond_a
    return v2

    .line 120
    :cond_b
    new-instance p0, La8/r0;

    .line 121
    .line 122
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 123
    .line 124
    .line 125
    throw p0
.end method

.method public static final b(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "name"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, ".preferences_pb"

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-static {p0, p1}, Llp/ye;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
