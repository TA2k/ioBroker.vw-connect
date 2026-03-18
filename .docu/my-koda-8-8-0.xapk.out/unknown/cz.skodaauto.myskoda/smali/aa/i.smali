.class public final Laa/i;
.super Lz9/j0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lz9/j0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "Laa/i;",
        "Lz9/j0;",
        "Laa/h;",
        "<init>",
        "()V",
        "navigation-compose_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation

.annotation runtime Lz9/i0;
    value = "composable"
.end annotation


# instance fields
.field public final c:Ll2/j1;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 5
    .line 6
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Laa/i;->c:Ll2/j1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a()Lz9/u;
    .locals 2

    .line 1
    new-instance v0, Laa/h;

    .line 2
    .line 3
    sget-object v1, Laa/c;->a:Lt2/b;

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Laa/h;-><init>(Laa/i;Lay0/p;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final d(Ljava/util/List;Lz9/b0;)V
    .locals 5

    .line 1
    check-cast p1, Ljava/lang/Iterable;

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    if-eqz p2, :cond_6

    .line 12
    .line 13
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    check-cast p2, Lz9/k;

    .line 18
    .line 19
    invoke-virtual {p0}, Lz9/j0;->b()Lz9/m;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget-object v1, v0, Lz9/m;->e:Lyy0/l1;

    .line 24
    .line 25
    const-string v2, "backStackEntry"

    .line 26
    .line 27
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v2, v0, Lz9/m;->c:Lyy0/c2;

    .line 31
    .line 32
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    check-cast v3, Ljava/lang/Iterable;

    .line 37
    .line 38
    instance-of v4, v3, Ljava/util/Collection;

    .line 39
    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    move-object v4, v3

    .line 43
    check-cast v4, Ljava/util/Collection;

    .line 44
    .line 45
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_0

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    :cond_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_4

    .line 61
    .line 62
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    check-cast v4, Lz9/k;

    .line 67
    .line 68
    if-ne v4, p2, :cond_1

    .line 69
    .line 70
    iget-object v3, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 71
    .line 72
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    check-cast v3, Ljava/lang/Iterable;

    .line 77
    .line 78
    instance-of v4, v3, Ljava/util/Collection;

    .line 79
    .line 80
    if-eqz v4, :cond_2

    .line 81
    .line 82
    move-object v4, v3

    .line 83
    check-cast v4, Ljava/util/Collection;

    .line 84
    .line 85
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-eqz v4, :cond_2

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_2
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    :cond_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v4

    .line 100
    if-eqz v4, :cond_4

    .line 101
    .line 102
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    check-cast v4, Lz9/k;

    .line 107
    .line 108
    if-ne v4, p2, :cond_3

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_4
    :goto_1
    iget-object v1, v1, Lyy0/l1;->d:Lyy0/a2;

    .line 112
    .line 113
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Ljava/util/List;

    .line 118
    .line 119
    invoke-static {v1}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    check-cast v1, Lz9/k;

    .line 124
    .line 125
    const/4 v3, 0x0

    .line 126
    if-eqz v1, :cond_5

    .line 127
    .line 128
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    check-cast v4, Ljava/util/Set;

    .line 133
    .line 134
    invoke-static {v4, v1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-virtual {v2, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    :cond_5
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    check-cast v1, Ljava/util/Set;

    .line 146
    .line 147
    invoke-static {v1, p2}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v2, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0, p2}, Lz9/m;->f(Lz9/k;)V

    .line 155
    .line 156
    .line 157
    goto/16 :goto_0

    .line 158
    .line 159
    :cond_6
    iget-object p0, p0, Laa/i;->c:Ll2/j1;

    .line 160
    .line 161
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 162
    .line 163
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    return-void
.end method

.method public final e(Lz9/k;Z)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lz9/j0;->b()Lz9/m;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p1, p2}, Lz9/m;->e(Lz9/k;Z)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Laa/i;->c:Ll2/j1;

    .line 9
    .line 10
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final g(Lz9/k;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lz9/j0;->b()Lz9/m;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "entry"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lz9/m;->c:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Ljava/util/Set;

    .line 17
    .line 18
    invoke-static {v1, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lz9/m;->h:Lz9/y;

    .line 27
    .line 28
    iget-object p0, p0, Lz9/y;->b:Lca/g;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lca/g;->f:Lmx0/l;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lmx0/l;->contains(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-eqz p0, :cond_0

    .line 40
    .line 41
    sget-object p0, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 42
    .line 43
    invoke-virtual {p1, p0}, Lz9/k;->a(Landroidx/lifecycle/q;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "Cannot transition entry that is not in the back stack"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0
.end method
