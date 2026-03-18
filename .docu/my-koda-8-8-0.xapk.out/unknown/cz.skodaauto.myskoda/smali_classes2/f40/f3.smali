.class public final Lf40/f3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/y0;


# direct methods
.method public constructor <init>(Lf40/y0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/f3;->a:Lf40/y0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Ljava/util/Map;

    .line 2
    .line 3
    const-string p2, "id"

    .line 4
    .line 5
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    check-cast p2, Ljava/lang/String;

    .line 10
    .line 11
    if-nez p2, :cond_0

    .line 12
    .line 13
    new-instance v0, Lne0/c;

    .line 14
    .line 15
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 16
    .line 17
    const-string p0, "Invalid identification param"

    .line 18
    .line 19
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    const/16 v5, 0x1e

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 28
    .line 29
    .line 30
    return-object v0

    .line 31
    :cond_0
    const-string v0, "badgeType"

    .line 32
    .line 33
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    check-cast p1, Ljava/lang/String;

    .line 38
    .line 39
    if-nez p1, :cond_1

    .line 40
    .line 41
    new-instance v0, Lne0/c;

    .line 42
    .line 43
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    const-string p0, "Invalid badge type param"

    .line 46
    .line 47
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const/4 v4, 0x0

    .line 51
    const/16 v5, 0x1e

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    const/4 v3, 0x0

    .line 55
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 56
    .line 57
    .line 58
    return-object v0

    .line 59
    :cond_1
    new-instance v0, Lg40/v0;

    .line 60
    .line 61
    sget-object v1, Lg40/n;->e:Lfv/b;

    .line 62
    .line 63
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 64
    .line 65
    invoke-virtual {p1, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    const-string v2, "toLowerCase(...)"

    .line 70
    .line 71
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    sget-object v1, Lg40/n;->h:Lsx0/b;

    .line 78
    .line 79
    invoke-virtual {v1}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    :cond_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_3

    .line 88
    .line 89
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    move-object v3, v2

    .line 94
    check-cast v3, Lg40/n;

    .line 95
    .line 96
    iget-object v3, v3, Lg40/n;->d:Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {v3, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 99
    .line 100
    .line 101
    move-result v3

    .line 102
    if-eqz v3, :cond_2

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_3
    const/4 v2, 0x0

    .line 106
    :goto_0
    check-cast v2, Lg40/n;

    .line 107
    .line 108
    if-nez v2, :cond_4

    .line 109
    .line 110
    sget-object v2, Lg40/n;->f:Lg40/n;

    .line 111
    .line 112
    :cond_4
    invoke-direct {v0, p2, v2}, Lg40/v0;-><init>(Ljava/lang/String;Lg40/n;)V

    .line 113
    .line 114
    .line 115
    iget-object p0, p0, Lf40/f3;->a:Lf40/y0;

    .line 116
    .line 117
    check-cast p0, Ld40/a;

    .line 118
    .line 119
    iput-object v0, p0, Ld40/a;->c:Lg40/v0;

    .line 120
    .line 121
    iget-object p0, p0, Ld40/a;->b:Lwe0/a;

    .line 122
    .line 123
    check-cast p0, Lwe0/c;

    .line 124
    .line 125
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 126
    .line 127
    .line 128
    new-instance p0, Lne0/e;

    .line 129
    .line 130
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    return-object p0
.end method
