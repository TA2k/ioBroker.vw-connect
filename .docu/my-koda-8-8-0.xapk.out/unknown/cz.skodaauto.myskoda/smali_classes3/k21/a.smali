.class public final Lk21/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh21/a;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:Lh21/c;

.field public final e:Landroidx/lifecycle/c1;

.field public final f:Ljava/util/ArrayList;

.field public g:Ljava/lang/ThreadLocal;


# direct methods
.method public constructor <init>(Lh21/a;Ljava/lang/String;Lh21/c;Landroidx/lifecycle/c1;I)V
    .locals 1

    .line 1
    and-int/lit8 v0, p5, 0x4

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x1

    .line 8
    :goto_0
    and-int/lit8 p5, p5, 0x8

    .line 9
    .line 10
    if-eqz p5, :cond_1

    .line 11
    .line 12
    const/4 p3, 0x0

    .line 13
    :cond_1
    const-string p5, "scopeQualifier"

    .line 14
    .line 15
    invoke-static {p1, p5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lk21/a;->a:Lh21/a;

    .line 22
    .line 23
    iput-object p2, p0, Lk21/a;->b:Ljava/lang/String;

    .line 24
    .line 25
    iput-boolean v0, p0, Lk21/a;->c:Z

    .line 26
    .line 27
    iput-object p3, p0, Lk21/a;->d:Lh21/c;

    .line 28
    .line 29
    iput-object p4, p0, Lk21/a;->e:Landroidx/lifecycle/c1;

    .line 30
    .line 31
    new-instance p1, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lk21/a;->f:Ljava/util/ArrayList;

    .line 37
    .line 38
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 41
    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "clazz"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p3, :cond_0

    .line 7
    .line 8
    invoke-interface {p3}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p3

    .line 12
    check-cast p3, Lg21/a;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p3, 0x0

    .line 16
    :goto_0
    invoke-virtual {p0, p3, p2, p1}, Lk21/a;->c(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public final b(Lhy0/d;)Ljava/util/ArrayList;
    .locals 7

    .line 1
    const-string v0, "clazz"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lu/x0;

    .line 7
    .line 8
    iget-object v1, p0, Lk21/a;->e:Landroidx/lifecycle/c1;

    .line 9
    .line 10
    iget-object v2, v1, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v2, Lap0/o;

    .line 13
    .line 14
    invoke-direct {v0, v2, p0, p1}, Lu/x0;-><init>(Lap0/o;Lk21/a;Lhy0/d;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, v1, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lgw0/c;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget-object v1, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Ljava/lang/Iterable;

    .line 33
    .line 34
    new-instance v2, Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_2

    .line 48
    .line 49
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    move-object v4, v3

    .line 54
    check-cast v4, Lc21/b;

    .line 55
    .line 56
    iget-object v4, v4, Lc21/b;->a:La21/a;

    .line 57
    .line 58
    iget-object v5, v4, La21/a;->a:Lh21/a;

    .line 59
    .line 60
    iget-object v6, v0, Lu/x0;->b:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v6, Lk21/a;

    .line 63
    .line 64
    iget-object v6, v6, Lk21/a;->a:Lh21/a;

    .line 65
    .line 66
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    if-eqz v5, :cond_0

    .line 71
    .line 72
    iget-object v5, v4, La21/a;->b:Lhy0/d;

    .line 73
    .line 74
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    if-nez v5, :cond_1

    .line 79
    .line 80
    iget-object v4, v4, La21/a;->f:Ljava/lang/Object;

    .line 81
    .line 82
    invoke-interface {v4, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    if-eqz v4, :cond_0

    .line 87
    .line 88
    :cond_1
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_2
    invoke-static {v2}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    check-cast v1, Ljava/lang/Iterable;

    .line 97
    .line 98
    new-instance v2, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 101
    .line 102
    .line 103
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    :cond_3
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-eqz v3, :cond_5

    .line 112
    .line 113
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    check-cast v3, Lc21/b;

    .line 118
    .line 119
    invoke-virtual {v3, v0}, Lc21/b;->c(Lu/x0;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    if-nez v3, :cond_4

    .line 124
    .line 125
    const/4 v3, 0x0

    .line 126
    :cond_4
    if-eqz v3, :cond_3

    .line 127
    .line 128
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_5
    new-instance v0, Ljava/util/ArrayList;

    .line 133
    .line 134
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 135
    .line 136
    .line 137
    iget-object p0, p0, Lk21/a;->f:Ljava/util/ArrayList;

    .line 138
    .line 139
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 144
    .line 145
    .line 146
    move-result v1

    .line 147
    if-eqz v1, :cond_6

    .line 148
    .line 149
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    check-cast v1, Lk21/a;

    .line 154
    .line 155
    invoke-virtual {v1, p1}, Lk21/a;->b(Lhy0/d;)Ljava/util/ArrayList;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    invoke-static {v1, v0}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 160
    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_6
    invoke-static {v0, v2}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    return-object p0
.end method

.method public final c(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lk21/a;->e:Landroidx/lifecycle/c1;

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lap0/o;

    .line 6
    .line 7
    sget-object v2, Ld21/b;->d:Ld21/b;

    .line 8
    .line 9
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Ld21/b;

    .line 12
    .line 13
    invoke-virtual {v1, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-gtz v1, :cond_3

    .line 18
    .line 19
    const-string v1, ""

    .line 20
    .line 21
    const/16 v3, 0x27

    .line 22
    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    new-instance v4, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v5, " with qualifier \'"

    .line 28
    .line 29
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    if-nez v4, :cond_1

    .line 43
    .line 44
    :cond_0
    move-object v4, v1

    .line 45
    :cond_1
    iget-boolean v5, p0, Lk21/a;->c:Z

    .line 46
    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    new-instance v1, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v5, " - scope:\'"

    .line 53
    .line 54
    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v5, p0, Lk21/a;->b:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {v1, v5, v3}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    :goto_0
    iget-object v5, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v5, Lap0/o;

    .line 66
    .line 67
    new-instance v6, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v7, "|- \'"

    .line 70
    .line 71
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {p3}, Lm21/a;->a(Lhy0/d;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, "..."

    .line 91
    .line 92
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    invoke-virtual {v5, v2, v1}, Lap0/o;->v(Ld21/b;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-static {}, Lmy0/j;->b()J

    .line 103
    .line 104
    .line 105
    move-result-wide v3

    .line 106
    invoke-virtual {p0, p1, p2, p3}, Lk21/a;->e(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-static {v3, v4}, Lmy0/l;->a(J)J

    .line 111
    .line 112
    .line 113
    move-result-wide p1

    .line 114
    iget-object v0, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v0, Lap0/o;

    .line 117
    .line 118
    new-instance v1, Ljava/lang/StringBuilder;

    .line 119
    .line 120
    invoke-direct {v1, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-static {p3}, Lm21/a;->a(Lhy0/d;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p3

    .line 127
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    const-string p3, "\' in "

    .line 131
    .line 132
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    sget p3, Lmy0/c;->g:I

    .line 136
    .line 137
    sget-object p3, Lmy0/e;->f:Lmy0/e;

    .line 138
    .line 139
    invoke-static {p1, p2, p3}, Lmy0/c;->n(JLmy0/e;)J

    .line 140
    .line 141
    .line 142
    move-result-wide p1

    .line 143
    long-to-double p1, p1

    .line 144
    const-wide v3, 0x408f400000000000L    # 1000.0

    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    div-double/2addr p1, v3

    .line 150
    const-string p3, " ms"

    .line 151
    .line 152
    invoke-static {v1, p1, p2, p3}, Lp3/m;->n(Ljava/lang/StringBuilder;DLjava/lang/String;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    invoke-virtual {v0, v2, p1}, Lap0/o;->v(Ld21/b;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    return-object p0

    .line 160
    :cond_3
    invoke-virtual {p0, p1, p2, p3}, Lk21/a;->e(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    return-object p0
.end method

.method public final d(Lu/x0;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lk21/a;->e:Landroidx/lifecycle/c1;

    .line 2
    .line 3
    iget-object v0, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lb81/b;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-virtual {v0, p0, p1, v1}, Lb81/b;->v(Lk21/a;Lu/x0;Z)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    if-nez p0, :cond_2

    .line 16
    .line 17
    iget-object p0, p1, Lu/x0;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lh21/a;

    .line 20
    .line 21
    const/16 v0, 0x27

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    new-instance v1, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v2, " and qualifier \'"

    .line 28
    .line 29
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    if-nez p0, :cond_1

    .line 43
    .line 44
    :cond_0
    const-string p0, ""

    .line 45
    .line 46
    :cond_1
    new-instance v1, Lb21/a;

    .line 47
    .line 48
    new-instance v2, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v3, "No definition found for type \'"

    .line 51
    .line 52
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object p1, p1, Lu/x0;->c:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Lhy0/d;

    .line 58
    .line 59
    invoke-static {p1}, Lm21/a;->a(Lhy0/d;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string p0, ". Check your Modules configuration and add missing type and/or qualifier!"

    .line 73
    .line 74
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    const-string p1, "msg"

    .line 82
    .line 83
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-direct {v1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw v1

    .line 90
    :cond_2
    return-object p0
.end method

.method public final e(Lg21/a;Lh21/a;Lhy0/d;)Ljava/lang/Object;
    .locals 7

    .line 1
    new-instance v0, Lu/x0;

    .line 2
    .line 3
    iget-object v6, p0, Lk21/a;->e:Landroidx/lifecycle/c1;

    .line 4
    .line 5
    iget-object v1, v6, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lap0/o;

    .line 8
    .line 9
    move-object v2, p0

    .line 10
    move-object v5, p1

    .line 11
    move-object v4, p2

    .line 12
    move-object v3, p3

    .line 13
    invoke-direct/range {v0 .. v5}, Lu/x0;-><init>(Lap0/o;Lk21/a;Lhy0/d;Lh21/a;Lg21/a;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "| << parameters"

    .line 17
    .line 18
    if-nez v5, :cond_0

    .line 19
    .line 20
    invoke-virtual {v2, v0}, Lk21/a;->d(Lu/x0;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    iget-object p1, v6, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Lap0/o;

    .line 28
    .line 29
    sget-object p2, Ld21/b;->d:Ld21/b;

    .line 30
    .line 31
    iget-object p3, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p3, Ld21/b;

    .line 34
    .line 35
    invoke-virtual {p3, p2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 36
    .line 37
    .line 38
    move-result p3

    .line 39
    if-gtz p3, :cond_1

    .line 40
    .line 41
    new-instance p3, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string v1, "| >> parameters "

    .line 44
    .line 45
    invoke-direct {p3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p3

    .line 55
    invoke-virtual {p1, p2, p3}, Lap0/o;->v(Ld21/b;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    iget-object p1, v2, Lk21/a;->g:Ljava/lang/ThreadLocal;

    .line 59
    .line 60
    if-eqz p1, :cond_2

    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Lmx0/l;

    .line 67
    .line 68
    if-nez p1, :cond_3

    .line 69
    .line 70
    :cond_2
    new-instance p1, Lmx0/l;

    .line 71
    .line 72
    invoke-direct {p1}, Lmx0/l;-><init>()V

    .line 73
    .line 74
    .line 75
    new-instance p2, Ljava/lang/ThreadLocal;

    .line 76
    .line 77
    invoke-direct {p2}, Ljava/lang/ThreadLocal;-><init>()V

    .line 78
    .line 79
    .line 80
    iput-object p2, v2, Lk21/a;->g:Ljava/lang/ThreadLocal;

    .line 81
    .line 82
    invoke-virtual {p2, p1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_3
    invoke-virtual {p1, v5}, Lmx0/l;->addFirst(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    const/4 p2, 0x0

    .line 89
    :try_start_0
    invoke-virtual {v2, v0}, Lk21/a;->d(Lu/x0;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 93
    iget-object v0, v6, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lap0/o;

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Lap0/o;->u(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p1}, Lmx0/l;->isEmpty()Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    if-eqz p0, :cond_4

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_4
    invoke-virtual {p1}, Lmx0/l;->removeFirst()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    :goto_0
    invoke-virtual {p1}, Lmx0/l;->isEmpty()Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    if-eqz p0, :cond_6

    .line 115
    .line 116
    iget-object p0, v2, Lk21/a;->g:Ljava/lang/ThreadLocal;

    .line 117
    .line 118
    if-eqz p0, :cond_5

    .line 119
    .line 120
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->remove()V

    .line 121
    .line 122
    .line 123
    :cond_5
    iput-object p2, v2, Lk21/a;->g:Ljava/lang/ThreadLocal;

    .line 124
    .line 125
    :cond_6
    return-object p3

    .line 126
    :catchall_0
    move-exception v0

    .line 127
    move-object p3, v0

    .line 128
    iget-object v0, v6, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v0, Lap0/o;

    .line 131
    .line 132
    invoke-virtual {v0, p0}, Lap0/o;->u(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1}, Lmx0/l;->isEmpty()Z

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-eqz p0, :cond_7

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_7
    invoke-virtual {p1}, Lmx0/l;->removeFirst()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    :goto_1
    invoke-virtual {p1}, Lmx0/l;->isEmpty()Z

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    if-eqz p0, :cond_9

    .line 150
    .line 151
    iget-object p0, v2, Lk21/a;->g:Ljava/lang/ThreadLocal;

    .line 152
    .line 153
    if-eqz p0, :cond_8

    .line 154
    .line 155
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->remove()V

    .line 156
    .line 157
    .line 158
    :cond_8
    iput-object p2, v2, Lk21/a;->g:Ljava/lang/ThreadLocal;

    .line 159
    .line 160
    :cond_9
    throw p3
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "[\'"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lk21/a;->b:Ljava/lang/String;

    .line 9
    .line 10
    const-string v1, "\']"

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
