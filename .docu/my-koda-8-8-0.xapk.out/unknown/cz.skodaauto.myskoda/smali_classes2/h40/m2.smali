.class public final Lh40/m2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbh0/j;

.field public final j:Lbh0/g;

.field public final k:Lbh0/c;


# direct methods
.method public constructor <init>(Lf40/g0;Ltr0/b;Lbh0/j;Lbh0/g;Lbh0/c;)V
    .locals 8

    .line 1
    new-instance v0, Lh40/k2;

    .line 2
    .line 3
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v7, 0x0

    .line 6
    const-string v1, ""

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x0

    .line 12
    invoke-direct/range {v0 .. v7}, Lh40/k2;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/util/List;Lh40/a;Lh40/j2;Z)V

    .line 13
    .line 14
    .line 15
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 16
    .line 17
    .line 18
    iput-object p2, p0, Lh40/m2;->h:Ltr0/b;

    .line 19
    .line 20
    iput-object p3, p0, Lh40/m2;->i:Lbh0/j;

    .line 21
    .line 22
    iput-object p4, p0, Lh40/m2;->j:Lbh0/g;

    .line 23
    .line 24
    iput-object p5, p0, Lh40/m2;->k:Lbh0/c;

    .line 25
    .line 26
    invoke-virtual {p1}, Lf40/g0;->invoke()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Lg40/a;

    .line 31
    .line 32
    if-eqz p1, :cond_4

    .line 33
    .line 34
    iget-object p2, p1, Lg40/a;->h:Lg40/b;

    .line 35
    .line 36
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 37
    .line 38
    .line 39
    move-result-object p3

    .line 40
    check-cast p3, Lh40/k2;

    .line 41
    .line 42
    iget-object v1, p1, Lg40/a;->b:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v2, p1, Lg40/a;->e:Ljava/time/OffsetDateTime;

    .line 45
    .line 46
    invoke-static {v2}, Lvo/a;->i(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iget-object p4, p1, Lg40/a;->i:Ljava/util/List;

    .line 51
    .line 52
    check-cast p4, Ljava/lang/Iterable;

    .line 53
    .line 54
    new-instance v4, Ljava/util/ArrayList;

    .line 55
    .line 56
    const/16 p5, 0xa

    .line 57
    .line 58
    invoke-static {p4, p5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 59
    .line 60
    .line 61
    move-result p5

    .line 62
    invoke-direct {v4, p5}, Ljava/util/ArrayList;-><init>(I)V

    .line 63
    .line 64
    .line 65
    invoke-interface {p4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 66
    .line 67
    .line 68
    move-result-object p4

    .line 69
    :goto_0
    invoke-interface {p4}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result p5

    .line 73
    if-eqz p5, :cond_0

    .line 74
    .line 75
    invoke-interface {p4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p5

    .line 79
    check-cast p5, Ljava/lang/String;

    .line 80
    .line 81
    invoke-static {p5}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 82
    .line 83
    .line 84
    move-result-object p5

    .line 85
    invoke-virtual {v4, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_0
    invoke-static {p2}, Llp/g0;->d(Lg40/b;)Lh40/a;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    iget-object p1, p1, Lg40/a;->g:Lg40/z;

    .line 94
    .line 95
    const/4 p4, 0x1

    .line 96
    const/4 p5, 0x0

    .line 97
    if-eqz p1, :cond_2

    .line 98
    .line 99
    new-instance v0, Lh40/j2;

    .line 100
    .line 101
    iget-object v6, p1, Lg40/z;->a:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v7, p1, Lg40/z;->d:Lcq0/h;

    .line 104
    .line 105
    if-eqz v7, :cond_1

    .line 106
    .line 107
    invoke-static {v7, p4}, Ljp/gg;->c(Lcq0/h;Z)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p5

    .line 111
    :cond_1
    iget-object v7, p1, Lg40/z;->b:Ljava/lang/String;

    .line 112
    .line 113
    iget-object p1, p1, Lg40/z;->c:Ljava/lang/String;

    .line 114
    .line 115
    invoke-direct {v0, v6, p5, v7, p1}, Lh40/j2;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    move-object v6, v0

    .line 119
    goto :goto_1

    .line 120
    :cond_2
    move-object v6, p5

    .line 121
    :goto_1
    sget-object p1, Lg40/b;->e:Lg40/b;

    .line 122
    .line 123
    if-ne p2, p1, :cond_3

    .line 124
    .line 125
    :goto_2
    move v7, p4

    .line 126
    goto :goto_3

    .line 127
    :cond_3
    const/4 p4, 0x0

    .line 128
    goto :goto_2

    .line 129
    :goto_3
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 130
    .line 131
    .line 132
    const-string p1, "name"

    .line 133
    .line 134
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    new-instance v0, Lh40/k2;

    .line 138
    .line 139
    invoke-direct/range {v0 .. v7}, Lh40/k2;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/util/List;Lh40/a;Lh40/j2;Z)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 143
    .line 144
    .line 145
    return-void

    .line 146
    :cond_4
    invoke-virtual {p2}, Ltr0/b;->invoke()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    return-void
.end method
