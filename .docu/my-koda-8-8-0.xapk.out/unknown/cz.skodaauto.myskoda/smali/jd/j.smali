.class public final Ljd/j;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljd/b;

.field public final e:Laa/y;

.field public final f:Lyj/b;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;

.field public final i:Llx0/q;

.field public j:Lcd/n;

.field public final k:Lyy0/c2;

.field public l:Z

.field public m:Lgz0/p;

.field public n:Lgz0/p;


# direct methods
.method public constructor <init>(Ljd/b;Laa/y;Lyj/b;Ljava/util/List;Lgz0/p;Lgz0/p;)V
    .locals 9

    .line 1
    const-string v0, "filters"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ljd/j;->d:Ljd/b;

    .line 10
    .line 11
    iput-object p2, p0, Ljd/j;->e:Laa/y;

    .line 12
    .line 13
    iput-object p3, p0, Ljd/j;->f:Lyj/b;

    .line 14
    .line 15
    new-instance p1, Llc/q;

    .line 16
    .line 17
    sget-object p2, Llc/a;->c:Llc/c;

    .line 18
    .line 19
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Ljd/j;->g:Lyy0/c2;

    .line 27
    .line 28
    iput-object p1, p0, Ljd/j;->h:Lyy0/c2;

    .line 29
    .line 30
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Ljd/j;->i:Llx0/q;

    .line 35
    .line 36
    new-instance p1, Lcd/n;

    .line 37
    .line 38
    invoke-direct {p1}, Lcd/n;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Ljd/j;->j:Lcd/n;

    .line 42
    .line 43
    invoke-static {p4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Ljd/j;->k:Lyy0/c2;

    .line 48
    .line 49
    const-string p2, "month"

    .line 50
    .line 51
    const-string p3, "getMonth(...)"

    .line 52
    .line 53
    if-nez p5, :cond_0

    .line 54
    .line 55
    sget-object p5, Lmy0/g;->a:Lmy0/b;

    .line 56
    .line 57
    invoke-interface {p5}, Lmy0/b;->now()Lmy0/f;

    .line 58
    .line 59
    .line 60
    move-result-object p5

    .line 61
    invoke-static {p5}, Lkp/t9;->d(Lmy0/f;)Lgz0/p;

    .line 62
    .line 63
    .line 64
    move-result-object p5

    .line 65
    sget-object v0, Lgz0/b0;->Companion:Lgz0/a0;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    sget-object v0, Lgz0/b0;->b:Lgz0/n;

    .line 71
    .line 72
    invoke-static {p5, v0}, Lkp/u9;->e(Lgz0/p;Lgz0/b0;)Lgz0/w;

    .line 73
    .line 74
    .line 75
    move-result-object p5

    .line 76
    iget-object p5, p5, Lgz0/w;->d:Ljava/time/LocalDateTime;

    .line 77
    .line 78
    invoke-virtual {p5}, Ljava/time/LocalDateTime;->getYear()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    invoke-virtual {p5}, Ljava/time/LocalDateTime;->getMonth()Ljava/time/Month;

    .line 83
    .line 84
    .line 85
    move-result-object p5

    .line 86
    invoke-static {p5, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-static {p5}, Lkp/s9;->e(Ljava/time/Month;)Lgz0/z;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    invoke-static {v3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    new-instance v1, Lgz0/w;

    .line 97
    .line 98
    const/4 v4, 0x1

    .line 99
    const/4 v5, 0x0

    .line 100
    const/4 v6, 0x0

    .line 101
    const/4 v7, 0x0

    .line 102
    const/4 v8, 0x0

    .line 103
    invoke-direct/range {v1 .. v8}, Lgz0/w;-><init>(ILgz0/z;IIIII)V

    .line 104
    .line 105
    .line 106
    invoke-static {v1, v0}, Lkp/u9;->d(Lgz0/w;Lgz0/b0;)Lmy0/f;

    .line 107
    .line 108
    .line 109
    move-result-object p5

    .line 110
    invoke-static {p5}, Lkp/t9;->d(Lmy0/f;)Lgz0/p;

    .line 111
    .line 112
    .line 113
    move-result-object p5

    .line 114
    :cond_0
    iput-object p5, p0, Ljd/j;->m:Lgz0/p;

    .line 115
    .line 116
    if-nez p6, :cond_1

    .line 117
    .line 118
    sget-object p5, Lmy0/g;->a:Lmy0/b;

    .line 119
    .line 120
    invoke-interface {p5}, Lmy0/b;->now()Lmy0/f;

    .line 121
    .line 122
    .line 123
    move-result-object p5

    .line 124
    invoke-static {p5}, Lkp/t9;->d(Lmy0/f;)Lgz0/p;

    .line 125
    .line 126
    .line 127
    move-result-object p5

    .line 128
    sget-object p6, Lgz0/b0;->Companion:Lgz0/a0;

    .line 129
    .line 130
    invoke-virtual {p6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    sget-object p6, Lgz0/b0;->b:Lgz0/n;

    .line 134
    .line 135
    invoke-static {p5, p6}, Lkp/u9;->e(Lgz0/p;Lgz0/b0;)Lgz0/w;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    iget-object v0, v0, Lgz0/w;->d:Ljava/time/LocalDateTime;

    .line 140
    .line 141
    invoke-virtual {v0}, Ljava/time/LocalDateTime;->getYear()I

    .line 142
    .line 143
    .line 144
    move-result v2

    .line 145
    invoke-virtual {v0}, Ljava/time/LocalDateTime;->getMonth()Ljava/time/Month;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    invoke-static {v0, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-static {v0}, Lkp/s9;->e(Ljava/time/Month;)Lgz0/z;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-static {p5, p6}, Lkp/u9;->e(Lgz0/p;Lgz0/b0;)Lgz0/w;

    .line 157
    .line 158
    .line 159
    move-result-object p3

    .line 160
    iget-object p3, p3, Lgz0/w;->d:Ljava/time/LocalDateTime;

    .line 161
    .line 162
    invoke-virtual {p3}, Ljava/time/LocalDateTime;->getDayOfMonth()I

    .line 163
    .line 164
    .line 165
    move-result v4

    .line 166
    invoke-static {v3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    new-instance v1, Lgz0/w;

    .line 170
    .line 171
    const/4 v5, 0x0

    .line 172
    const/4 v6, 0x0

    .line 173
    const/4 v7, 0x0

    .line 174
    const/4 v8, 0x0

    .line 175
    invoke-direct/range {v1 .. v8}, Lgz0/w;-><init>(ILgz0/z;IIIII)V

    .line 176
    .line 177
    .line 178
    invoke-static {v1, p6}, Lkp/u9;->d(Lgz0/w;Lgz0/b0;)Lmy0/f;

    .line 179
    .line 180
    .line 181
    move-result-object p2

    .line 182
    invoke-static {p2}, Lkp/t9;->d(Lmy0/f;)Lgz0/p;

    .line 183
    .line 184
    .line 185
    move-result-object p6

    .line 186
    :cond_1
    iput-object p6, p0, Ljd/j;->n:Lgz0/p;

    .line 187
    .line 188
    const/4 p2, 0x0

    .line 189
    invoke-virtual {p1, p2, p4}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    iget-object p1, p0, Ljd/j;->m:Lgz0/p;

    .line 193
    .line 194
    invoke-virtual {p1}, Lgz0/p;->a()J

    .line 195
    .line 196
    .line 197
    move-result-wide p1

    .line 198
    iget-object p3, p0, Ljd/j;->n:Lgz0/p;

    .line 199
    .line 200
    invoke-virtual {p3}, Lgz0/p;->a()J

    .line 201
    .line 202
    .line 203
    move-result-wide p3

    .line 204
    invoke-virtual {p0, p1, p2, p3, p4}, Ljd/j;->d(JJ)V

    .line 205
    .line 206
    .line 207
    return-void
.end method

.method public static a(Lyy0/j1;)Ljava/util/ArrayList;
    .locals 4

    .line 1
    check-cast p0, Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lkd/a;

    .line 29
    .line 30
    iget-object v2, v1, Lkd/a;->a:Lkd/q;

    .line 31
    .line 32
    sget-object v3, Lkd/q;->d:Lkd/q;

    .line 33
    .line 34
    if-ne v2, v3, :cond_0

    .line 35
    .line 36
    iget-boolean v2, v1, Lkd/a;->d:Z

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    iget-object v1, v1, Lkd/a;->b:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    return-object v0
.end method

.method public static b(Lyy0/j1;)Ljava/util/ArrayList;
    .locals 4

    .line 1
    check-cast p0, Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lkd/a;

    .line 29
    .line 30
    iget-object v2, v1, Lkd/a;->a:Lkd/q;

    .line 31
    .line 32
    sget-object v3, Lkd/q;->e:Lkd/q;

    .line 33
    .line 34
    if-ne v2, v3, :cond_0

    .line 35
    .line 36
    iget-boolean v2, v1, Lkd/a;->d:Z

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    iget-object v1, v1, Lkd/a;->b:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    return-object v0
.end method


# virtual methods
.method public final d(JJ)V
    .locals 11

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Ljd/j;->l:Z

    .line 3
    .line 4
    sget-object v1, Lmy0/e;->k:Lmy0/e;

    .line 5
    .line 6
    const/16 v2, 0x1e

    .line 7
    .line 8
    invoke-static {v2, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 9
    .line 10
    .line 11
    move-result-wide v3

    .line 12
    invoke-static {v3, v4}, Lmy0/c;->e(J)J

    .line 13
    .line 14
    .line 15
    move-result-wide v3

    .line 16
    sub-long v5, p1, p3

    .line 17
    .line 18
    invoke-static {v5, v6}, Ljava/lang/Math;->abs(J)J

    .line 19
    .line 20
    .line 21
    move-result-wide v5

    .line 22
    cmp-long v3, v5, v3

    .line 23
    .line 24
    if-lez v3, :cond_0

    .line 25
    .line 26
    const/4 v3, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v3, v0

    .line 29
    :goto_0
    if-eqz v3, :cond_1

    .line 30
    .line 31
    invoke-static {v2, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 32
    .line 33
    .line 34
    move-result-wide p3

    .line 35
    invoke-static {p3, p4}, Lmy0/c;->e(J)J

    .line 36
    .line 37
    .line 38
    move-result-wide p3

    .line 39
    add-long/2addr p3, p1

    .line 40
    :cond_1
    sget-object v1, Lgz0/p;->Companion:Lgz0/o;

    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-static {p1, p2}, Lgz0/o;->a(J)Lgz0/p;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iput-object p1, p0, Ljd/j;->m:Lgz0/p;

    .line 50
    .line 51
    invoke-static {p3, p4}, Lgz0/o;->a(J)Lgz0/p;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    iput-object p1, p0, Ljd/j;->n:Lgz0/p;

    .line 56
    .line 57
    iget-object p1, p0, Ljd/j;->k:Lyy0/c2;

    .line 58
    .line 59
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    check-cast p2, Ljava/lang/Iterable;

    .line 64
    .line 65
    new-instance p3, Ljava/util/ArrayList;

    .line 66
    .line 67
    const/16 p4, 0xa

    .line 68
    .line 69
    invoke-static {p2, p4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 70
    .line 71
    .line 72
    move-result p4

    .line 73
    invoke-direct {p3, p4}, Ljava/util/ArrayList;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result p4

    .line 84
    if-eqz p4, :cond_3

    .line 85
    .line 86
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p4

    .line 90
    check-cast p4, Lkd/a;

    .line 91
    .line 92
    iget-object v1, p4, Lkd/a;->a:Lkd/q;

    .line 93
    .line 94
    sget-object v2, Lkd/q;->g:Lkd/q;

    .line 95
    .line 96
    if-ne v1, v2, :cond_2

    .line 97
    .line 98
    iget-object v1, p0, Ljd/j;->m:Lgz0/p;

    .line 99
    .line 100
    const-string v2, "dd.MM."

    .line 101
    .line 102
    invoke-static {v1, v2}, Llp/t0;->b(Lgz0/p;Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    iget-object v4, p0, Ljd/j;->n:Lgz0/p;

    .line 107
    .line 108
    invoke-static {v4, v2}, Llp/t0;->b(Lgz0/p;Ljava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    const-string v4, " - "

    .line 113
    .line 114
    invoke-static {v1, v4, v2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    const/16 v2, 0x1b

    .line 119
    .line 120
    invoke-static {p4, v1, v0, v2}, Lkd/a;->a(Lkd/a;Ljava/lang/String;ZI)Lkd/a;

    .line 121
    .line 122
    .line 123
    move-result-object p4

    .line 124
    :cond_2
    invoke-virtual {p3, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    const/4 p2, 0x0

    .line 132
    invoke-virtual {p1, p2, p3}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    iget-object v4, p0, Ljd/j;->j:Lcd/n;

    .line 136
    .line 137
    iget-object v7, p0, Ljd/j;->m:Lgz0/p;

    .line 138
    .line 139
    iget-object v8, p0, Ljd/j;->n:Lgz0/p;

    .line 140
    .line 141
    const/4 v9, 0x0

    .line 142
    const/16 v10, 0x13

    .line 143
    .line 144
    const/4 v5, 0x0

    .line 145
    const/4 v6, 0x0

    .line 146
    invoke-static/range {v4 .. v10}, Lcd/n;->a(Lcd/n;Ljava/util/ArrayList;Ljava/util/ArrayList;Lgz0/p;Lgz0/p;ZI)Lcd/n;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    iput-object p1, p0, Ljd/j;->j:Lcd/n;

    .line 151
    .line 152
    invoke-virtual {p0, v3}, Ljd/j;->f(Z)V

    .line 153
    .line 154
    .line 155
    return-void
.end method

.method public final f(Z)V
    .locals 10

    .line 1
    iget-object v0, p0, Ljd/j;->k:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/util/List;

    .line 8
    .line 9
    iget-boolean v5, p0, Ljd/j;->l:Z

    .line 10
    .line 11
    iget-object v1, p0, Ljd/j;->m:Lgz0/p;

    .line 12
    .line 13
    iget-object v2, p0, Ljd/j;->n:Lgz0/p;

    .line 14
    .line 15
    const-string v3, "value"

    .line 16
    .line 17
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string v3, "startDate"

    .line 21
    .line 22
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v3, "endDate"

    .line 26
    .line 27
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    check-cast v0, Ljava/lang/Iterable;

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_5

    .line 41
    .line 42
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    check-cast v4, Lkd/a;

    .line 47
    .line 48
    iget-object v6, v4, Lkd/a;->a:Lkd/q;

    .line 49
    .line 50
    sget-object v7, Lkd/q;->g:Lkd/q;

    .line 51
    .line 52
    if-ne v6, v7, :cond_0

    .line 53
    .line 54
    new-instance v3, Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 57
    .line 58
    .line 59
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 60
    .line 61
    .line 62
    move-result-object v6

    .line 63
    :cond_1
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 64
    .line 65
    .line 66
    move-result v7

    .line 67
    if-eqz v7, :cond_2

    .line 68
    .line 69
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    move-object v8, v7

    .line 74
    check-cast v8, Lkd/a;

    .line 75
    .line 76
    iget-object v8, v8, Lkd/a;->a:Lkd/q;

    .line 77
    .line 78
    sget-object v9, Lkd/q;->d:Lkd/q;

    .line 79
    .line 80
    if-ne v8, v9, :cond_1

    .line 81
    .line 82
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_2
    new-instance v6, Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 89
    .line 90
    .line 91
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    if-eqz v7, :cond_4

    .line 100
    .line 101
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    move-object v8, v7

    .line 106
    check-cast v8, Lkd/a;

    .line 107
    .line 108
    iget-object v8, v8, Lkd/a;->a:Lkd/q;

    .line 109
    .line 110
    sget-object v9, Lkd/q;->e:Lkd/q;

    .line 111
    .line 112
    if-ne v8, v9, :cond_3

    .line 113
    .line 114
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_4
    new-instance v7, Ljd/k;

    .line 119
    .line 120
    invoke-virtual {v1}, Lgz0/p;->a()J

    .line 121
    .line 122
    .line 123
    move-result-wide v0

    .line 124
    invoke-virtual {v2}, Lgz0/p;->a()J

    .line 125
    .line 126
    .line 127
    move-result-wide v8

    .line 128
    invoke-direct {v7, v0, v1, v8, v9}, Ljd/k;-><init>(JJ)V

    .line 129
    .line 130
    .line 131
    new-instance v1, Ljd/i;

    .line 132
    .line 133
    move-object v2, v4

    .line 134
    move-object v4, v6

    .line 135
    move v6, p1

    .line 136
    invoke-direct/range {v1 .. v7}, Ljd/i;-><init>(Lkd/a;Ljava/util/ArrayList;Ljava/util/ArrayList;ZZLjd/k;)V

    .line 137
    .line 138
    .line 139
    new-instance p1, Llc/q;

    .line 140
    .line 141
    invoke-direct {p1, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    iget-object p0, p0, Ljd/j;->g:Lyy0/c2;

    .line 145
    .line 146
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    const/4 v0, 0x0

    .line 150
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    return-void

    .line 154
    :cond_5
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 155
    .line 156
    const-string p1, "Collection contains no element matching the predicate."

    .line 157
    .line 158
    invoke-direct {p0, p1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0
.end method
