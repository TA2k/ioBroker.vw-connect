.class public final Lyd/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lyd/l;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lyd/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lyd/l;->a:Lyd/l;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Ljava/util/List;)Lry/a;
    .locals 12

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lyd/b;->a:Lyd/b;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v0, Lyd/c;

    .line 11
    .line 12
    check-cast p0, Ljava/lang/Iterable;

    .line 13
    .line 14
    new-instance v1, Ljava/util/ArrayList;

    .line 15
    .line 16
    const/16 v2, 0xa

    .line 17
    .line 18
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lvd/c;

    .line 40
    .line 41
    new-instance v3, Lyd/a;

    .line 42
    .line 43
    iget-object v4, v2, Lvd/c;->a:Ljava/lang/String;

    .line 44
    .line 45
    iget-object v5, v2, Lvd/c;->b:Ljava/lang/String;

    .line 46
    .line 47
    iget-object v6, v2, Lvd/c;->c:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v7, v2, Lvd/c;->d:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v8, v2, Lvd/c;->e:Ljava/lang/String;

    .line 52
    .line 53
    iget-object v9, v2, Lvd/c;->f:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v10, v2, Lvd/c;->g:Ljava/lang/String;

    .line 56
    .line 57
    iget-boolean v11, v2, Lvd/c;->h:Z

    .line 58
    .line 59
    invoke-direct/range {v3 .. v11}, Lyd/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    invoke-direct {v0, v1}, Lyd/c;-><init>(Ljava/util/ArrayList;)V

    .line 67
    .line 68
    .line 69
    return-object v0
.end method

.method public static b(Ljava/lang/String;Lvd/l;Ljava/lang/String;Z)Lyd/r;
    .locals 7

    .line 1
    new-instance v0, Lyd/n;

    .line 2
    .line 3
    iget-object v1, p1, Lvd/l;->b:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p1, Lvd/l;->e:Ljava/util/List;

    .line 6
    .line 7
    iget-object v3, p1, Lvd/l;->d:Ljava/util/List;

    .line 8
    .line 9
    iget-object v4, p1, Lvd/l;->a:Ljava/lang/String;

    .line 10
    .line 11
    const-string v5, "pattern"

    .line 12
    .line 13
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-static {v1}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const-string v5, "compile(...)"

    .line 21
    .line 22
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v5, "input"

    .line 26
    .line 27
    invoke-static {p2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1, p2}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v1}, Ljava/util/regex/Matcher;->matches()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    const/4 v5, 0x1

    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-nez v6, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 v6, 0x0

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    :goto_0
    move v6, v5

    .line 51
    :goto_1
    xor-int/2addr v6, v5

    .line 52
    invoke-direct {v0, p2, p0, v1, v6}, Lyd/n;-><init>(Ljava/lang/String;Ljava/lang/String;ZZ)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p1, Lvd/l;->c:Lvd/k;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p0, :cond_5

    .line 62
    .line 63
    if-eq p0, v5, :cond_4

    .line 64
    .line 65
    const/4 p1, 0x2

    .line 66
    if-eq p0, p1, :cond_3

    .line 67
    .line 68
    const/4 p1, 0x3

    .line 69
    if-ne p0, p1, :cond_2

    .line 70
    .line 71
    sget-object p0, Lyd/q;->a:Lyd/q;

    .line 72
    .line 73
    return-object p0

    .line 74
    :cond_2
    new-instance p0, La8/r0;

    .line 75
    .line 76
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_3
    new-instance p0, Lyd/o;

    .line 81
    .line 82
    invoke-static {v3}, Lyd/l;->a(Ljava/util/List;)Lry/a;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-static {v2}, Lyd/l;->a(Ljava/util/List;)Lry/a;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    invoke-direct {p0, v4, p1, p2}, Lyd/o;-><init>(Ljava/lang/String;Lry/a;Lry/a;)V

    .line 91
    .line 92
    .line 93
    return-object p0

    .line 94
    :cond_4
    new-instance p0, Lyd/m;

    .line 95
    .line 96
    invoke-static {v3}, Lyd/l;->a(Ljava/util/List;)Lry/a;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-static {v2}, Lyd/l;->a(Ljava/util/List;)Lry/a;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    invoke-direct {p0, v4, v0, p1, p2}, Lyd/m;-><init>(Ljava/lang/String;Lyd/n;Lry/a;Lry/a;)V

    .line 105
    .line 106
    .line 107
    return-object p0

    .line 108
    :cond_5
    new-instance p0, Lyd/p;

    .line 109
    .line 110
    invoke-direct {p0, v0, p3}, Lyd/p;-><init>(Lyd/n;Z)V

    .line 111
    .line 112
    .line 113
    return-object p0
.end method
