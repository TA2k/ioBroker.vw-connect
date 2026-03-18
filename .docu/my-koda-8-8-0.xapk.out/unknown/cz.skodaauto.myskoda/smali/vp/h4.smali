.class public final Lvp/h4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Z

.field public final c:Lcom/google/android/gms/internal/measurement/m3;

.field public final d:Ljava/util/BitSet;

.field public final e:Ljava/util/BitSet;

.field public final f:Landroidx/collection/f;

.field public final g:Landroidx/collection/f;

.field public final synthetic h:Lvp/d;


# direct methods
.method public constructor <init>(Lvp/d;Ljava/lang/String;)V
    .locals 0

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvp/h4;->h:Lvp/d;

    iput-object p2, p0, Lvp/h4;->a:Ljava/lang/String;

    const/4 p1, 0x1

    iput-boolean p1, p0, Lvp/h4;->b:Z

    new-instance p1, Ljava/util/BitSet;

    .line 9
    invoke-direct {p1}, Ljava/util/BitSet;-><init>()V

    iput-object p1, p0, Lvp/h4;->d:Ljava/util/BitSet;

    new-instance p1, Ljava/util/BitSet;

    .line 10
    invoke-direct {p1}, Ljava/util/BitSet;-><init>()V

    iput-object p1, p0, Lvp/h4;->e:Ljava/util/BitSet;

    .line 11
    new-instance p1, Landroidx/collection/f;

    const/4 p2, 0x0

    .line 12
    invoke-direct {p1, p2}, Landroidx/collection/a1;-><init>(I)V

    .line 13
    iput-object p1, p0, Lvp/h4;->f:Landroidx/collection/f;

    new-instance p1, Landroidx/collection/f;

    .line 14
    invoke-direct {p1, p2}, Landroidx/collection/a1;-><init>(I)V

    .line 15
    iput-object p1, p0, Lvp/h4;->g:Landroidx/collection/f;

    return-void
.end method

.method public constructor <init>(Lvp/d;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m3;Ljava/util/BitSet;Ljava/util/BitSet;Landroidx/collection/f;Landroidx/collection/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvp/h4;->h:Lvp/d;

    iput-object p2, p0, Lvp/h4;->a:Ljava/lang/String;

    iput-object p4, p0, Lvp/h4;->d:Ljava/util/BitSet;

    iput-object p5, p0, Lvp/h4;->e:Ljava/util/BitSet;

    iput-object p6, p0, Lvp/h4;->f:Landroidx/collection/f;

    new-instance p1, Landroidx/collection/f;

    const/4 p2, 0x0

    .line 2
    invoke-direct {p1, p2}, Landroidx/collection/a1;-><init>(I)V

    .line 3
    iput-object p1, p0, Lvp/h4;->g:Landroidx/collection/f;

    .line 4
    invoke-interface {p7}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p4

    if-eqz p4, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Ljava/lang/Integer;

    new-instance p5, Ljava/util/ArrayList;

    .line 5
    invoke-direct {p5}, Ljava/util/ArrayList;-><init>()V

    .line 6
    invoke-interface {p7, p4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p6

    check-cast p6, Ljava/lang/Long;

    invoke-virtual {p5, p6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object p6, p0, Lvp/h4;->g:Landroidx/collection/f;

    .line 7
    invoke-interface {p6, p4, p5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_0
    iput-boolean p2, p0, Lvp/h4;->b:Z

    iput-object p3, p0, Lvp/h4;->c:Lcom/google/android/gms/internal/measurement/m3;

    return-void
.end method


# virtual methods
.method public final a(Lvp/c;)V
    .locals 10

    .line 1
    invoke-virtual {p1}, Lvp/c;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p1, Lvp/c;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/Boolean;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object v1, p0, Lvp/h4;->e:Ljava/util/BitSet;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    invoke-virtual {v1, v0, v2}, Ljava/util/BitSet;->set(IZ)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v1, p1, Lvp/c;->d:Ljava/io/Serializable;

    .line 18
    .line 19
    check-cast v1, Ljava/lang/Boolean;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    iget-object v2, p0, Lvp/h4;->d:Ljava/util/BitSet;

    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-virtual {v2, v0, v1}, Ljava/util/BitSet;->set(IZ)V

    .line 30
    .line 31
    .line 32
    :cond_1
    iget-object v1, p1, Lvp/c;->e:Ljava/io/Serializable;

    .line 33
    .line 34
    check-cast v1, Ljava/lang/Long;

    .line 35
    .line 36
    const-wide/16 v2, 0x3e8

    .line 37
    .line 38
    if-eqz v1, :cond_3

    .line 39
    .line 40
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    iget-object v4, p0, Lvp/h4;->f:Landroidx/collection/f;

    .line 45
    .line 46
    invoke-interface {v4, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    check-cast v5, Ljava/lang/Long;

    .line 51
    .line 52
    iget-object v6, p1, Lvp/c;->e:Ljava/io/Serializable;

    .line 53
    .line 54
    check-cast v6, Ljava/lang/Long;

    .line 55
    .line 56
    invoke-virtual {v6}, Ljava/lang/Long;->longValue()J

    .line 57
    .line 58
    .line 59
    move-result-wide v6

    .line 60
    div-long/2addr v6, v2

    .line 61
    if-eqz v5, :cond_2

    .line 62
    .line 63
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 64
    .line 65
    .line 66
    move-result-wide v8

    .line 67
    cmp-long v5, v6, v8

    .line 68
    .line 69
    if-lez v5, :cond_3

    .line 70
    .line 71
    :cond_2
    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    invoke-interface {v4, v1, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    :cond_3
    iget-object v1, p1, Lvp/c;->f:Ljava/io/Serializable;

    .line 79
    .line 80
    check-cast v1, Ljava/lang/Long;

    .line 81
    .line 82
    if-eqz v1, :cond_8

    .line 83
    .line 84
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    iget-object v1, p0, Lvp/h4;->g:Landroidx/collection/f;

    .line 89
    .line 90
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    check-cast v4, Ljava/util/List;

    .line 95
    .line 96
    if-nez v4, :cond_4

    .line 97
    .line 98
    new-instance v4, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 101
    .line 102
    .line 103
    invoke-interface {v1, v0, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    :cond_4
    invoke-virtual {p1}, Lvp/c;->d()Z

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    if-eqz v0, :cond_5

    .line 111
    .line 112
    invoke-interface {v4}, Ljava/util/List;->clear()V

    .line 113
    .line 114
    .line 115
    :cond_5
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z7;->a()V

    .line 116
    .line 117
    .line 118
    iget-object v0, p0, Lvp/h4;->h:Lvp/d;

    .line 119
    .line 120
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v0, Lvp/g1;

    .line 123
    .line 124
    iget-object v1, v0, Lvp/g1;->g:Lvp/h;

    .line 125
    .line 126
    sget-object v5, Lvp/z;->F0:Lvp/y;

    .line 127
    .line 128
    iget-object p0, p0, Lvp/h4;->a:Ljava/lang/String;

    .line 129
    .line 130
    invoke-virtual {v1, p0, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_6

    .line 135
    .line 136
    invoke-virtual {p1}, Lvp/c;->e()Z

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    if-eqz v1, :cond_6

    .line 141
    .line 142
    invoke-interface {v4}, Ljava/util/List;->clear()V

    .line 143
    .line 144
    .line 145
    :cond_6
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z7;->a()V

    .line 146
    .line 147
    .line 148
    iget-object v0, v0, Lvp/g1;->g:Lvp/h;

    .line 149
    .line 150
    invoke-virtual {v0, p0, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 151
    .line 152
    .line 153
    move-result p0

    .line 154
    if-eqz p0, :cond_7

    .line 155
    .line 156
    iget-object p0, p1, Lvp/c;->f:Ljava/io/Serializable;

    .line 157
    .line 158
    check-cast p0, Ljava/lang/Long;

    .line 159
    .line 160
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 161
    .line 162
    .line 163
    move-result-wide p0

    .line 164
    div-long/2addr p0, v2

    .line 165
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    invoke-interface {v4, p0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result p1

    .line 173
    if-nez p1, :cond_8

    .line 174
    .line 175
    invoke-interface {v4, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    return-void

    .line 179
    :cond_7
    iget-object p0, p1, Lvp/c;->f:Ljava/io/Serializable;

    .line 180
    .line 181
    check-cast p0, Ljava/lang/Long;

    .line 182
    .line 183
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 184
    .line 185
    .line 186
    move-result-wide p0

    .line 187
    div-long/2addr p0, v2

    .line 188
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    invoke-interface {v4, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    :cond_8
    return-void
.end method

.method public final b(I)Lcom/google/android/gms/internal/measurement/t2;
    .locals 8

    .line 1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/t2;->w()Lcom/google/android/gms/internal/measurement/s2;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 9
    .line 10
    check-cast v1, Lcom/google/android/gms/internal/measurement/t2;

    .line 11
    .line 12
    invoke-virtual {v1, p1}, Lcom/google/android/gms/internal/measurement/t2;->x(I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 16
    .line 17
    .line 18
    iget-object p1, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 19
    .line 20
    check-cast p1, Lcom/google/android/gms/internal/measurement/t2;

    .line 21
    .line 22
    iget-boolean v1, p0, Lvp/h4;->b:Z

    .line 23
    .line 24
    invoke-virtual {p1, v1}, Lcom/google/android/gms/internal/measurement/t2;->A(Z)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lvp/h4;->c:Lcom/google/android/gms/internal/measurement/m3;

    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 32
    .line 33
    .line 34
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 35
    .line 36
    check-cast v1, Lcom/google/android/gms/internal/measurement/t2;

    .line 37
    .line 38
    invoke-virtual {v1, p1}, Lcom/google/android/gms/internal/measurement/t2;->z(Lcom/google/android/gms/internal/measurement/m3;)V

    .line 39
    .line 40
    .line 41
    :cond_0
    invoke-static {}, Lcom/google/android/gms/internal/measurement/m3;->x()Lcom/google/android/gms/internal/measurement/l3;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object v1, p0, Lvp/h4;->d:Ljava/util/BitSet;

    .line 46
    .line 47
    invoke-static {v1}, Lvp/s0;->I0(Ljava/util/BitSet;)Ljava/util/ArrayList;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 52
    .line 53
    .line 54
    iget-object v2, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 55
    .line 56
    check-cast v2, Lcom/google/android/gms/internal/measurement/m3;

    .line 57
    .line 58
    invoke-virtual {v2, v1}, Lcom/google/android/gms/internal/measurement/m3;->B(Ljava/util/List;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, p0, Lvp/h4;->e:Ljava/util/BitSet;

    .line 62
    .line 63
    invoke-static {v1}, Lvp/s0;->I0(Ljava/util/BitSet;)Ljava/util/ArrayList;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 68
    .line 69
    .line 70
    iget-object v2, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 71
    .line 72
    check-cast v2, Lcom/google/android/gms/internal/measurement/m3;

    .line 73
    .line 74
    invoke-virtual {v2, v1}, Lcom/google/android/gms/internal/measurement/m3;->z(Ljava/lang/Iterable;)V

    .line 75
    .line 76
    .line 77
    iget-object v1, p0, Lvp/h4;->f:Landroidx/collection/f;

    .line 78
    .line 79
    if-nez v1, :cond_1

    .line 80
    .line 81
    const/4 v1, 0x0

    .line 82
    goto :goto_1

    .line 83
    :cond_1
    new-instance v2, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 90
    .line 91
    .line 92
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    :cond_2
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    if-eqz v4, :cond_3

    .line 105
    .line 106
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    check-cast v4, Ljava/lang/Integer;

    .line 111
    .line 112
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    invoke-interface {v1, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    check-cast v4, Ljava/lang/Long;

    .line 121
    .line 122
    if-eqz v4, :cond_2

    .line 123
    .line 124
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z2;->t()Lcom/google/android/gms/internal/measurement/y2;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 129
    .line 130
    .line 131
    iget-object v7, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 132
    .line 133
    check-cast v7, Lcom/google/android/gms/internal/measurement/z2;

    .line 134
    .line 135
    invoke-virtual {v7, v5}, Lcom/google/android/gms/internal/measurement/z2;->u(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 139
    .line 140
    .line 141
    move-result-wide v4

    .line 142
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 143
    .line 144
    .line 145
    iget-object v7, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 146
    .line 147
    check-cast v7, Lcom/google/android/gms/internal/measurement/z2;

    .line 148
    .line 149
    invoke-virtual {v7, v4, v5}, Lcom/google/android/gms/internal/measurement/z2;->v(J)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    check-cast v4, Lcom/google/android/gms/internal/measurement/z2;

    .line 157
    .line 158
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    goto :goto_0

    .line 162
    :cond_3
    move-object v1, v2

    .line 163
    :goto_1
    if-eqz v1, :cond_4

    .line 164
    .line 165
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 166
    .line 167
    .line 168
    iget-object v2, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 169
    .line 170
    check-cast v2, Lcom/google/android/gms/internal/measurement/m3;

    .line 171
    .line 172
    invoke-virtual {v2, v1}, Lcom/google/android/gms/internal/measurement/m3;->D(Ljava/util/ArrayList;)V

    .line 173
    .line 174
    .line 175
    :cond_4
    iget-object p0, p0, Lvp/h4;->g:Landroidx/collection/f;

    .line 176
    .line 177
    if-nez p0, :cond_5

    .line 178
    .line 179
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 180
    .line 181
    goto :goto_3

    .line 182
    :cond_5
    new-instance v1, Ljava/util/ArrayList;

    .line 183
    .line 184
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 185
    .line 186
    .line 187
    move-result v2

    .line 188
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 189
    .line 190
    .line 191
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 196
    .line 197
    .line 198
    move-result-object v2

    .line 199
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    if-eqz v3, :cond_7

    .line 204
    .line 205
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    check-cast v3, Ljava/lang/Integer;

    .line 210
    .line 211
    invoke-static {}, Lcom/google/android/gms/internal/measurement/o3;->u()Lcom/google/android/gms/internal/measurement/n3;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 216
    .line 217
    .line 218
    move-result v5

    .line 219
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 220
    .line 221
    .line 222
    iget-object v6, v4, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 223
    .line 224
    check-cast v6, Lcom/google/android/gms/internal/measurement/o3;

    .line 225
    .line 226
    invoke-virtual {v6, v5}, Lcom/google/android/gms/internal/measurement/o3;->v(I)V

    .line 227
    .line 228
    .line 229
    invoke-interface {p0, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v3

    .line 233
    check-cast v3, Ljava/util/List;

    .line 234
    .line 235
    if-eqz v3, :cond_6

    .line 236
    .line 237
    invoke-static {v3}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 241
    .line 242
    .line 243
    iget-object v5, v4, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 244
    .line 245
    check-cast v5, Lcom/google/android/gms/internal/measurement/o3;

    .line 246
    .line 247
    check-cast v3, Ljava/util/List;

    .line 248
    .line 249
    invoke-virtual {v5, v3}, Lcom/google/android/gms/internal/measurement/o3;->w(Ljava/util/List;)V

    .line 250
    .line 251
    .line 252
    :cond_6
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 253
    .line 254
    .line 255
    move-result-object v3

    .line 256
    check-cast v3, Lcom/google/android/gms/internal/measurement/o3;

    .line 257
    .line 258
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    goto :goto_2

    .line 262
    :cond_7
    move-object p0, v1

    .line 263
    :goto_3
    check-cast p0, Ljava/util/List;

    .line 264
    .line 265
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 266
    .line 267
    .line 268
    iget-object v1, p1, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 269
    .line 270
    check-cast v1, Lcom/google/android/gms/internal/measurement/m3;

    .line 271
    .line 272
    invoke-virtual {v1, p0}, Lcom/google/android/gms/internal/measurement/m3;->F(Ljava/lang/Iterable;)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 276
    .line 277
    .line 278
    iget-object p0, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 279
    .line 280
    check-cast p0, Lcom/google/android/gms/internal/measurement/t2;

    .line 281
    .line 282
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 283
    .line 284
    .line 285
    move-result-object p1

    .line 286
    check-cast p1, Lcom/google/android/gms/internal/measurement/m3;

    .line 287
    .line 288
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/t2;->y(Lcom/google/android/gms/internal/measurement/m3;)V

    .line 289
    .line 290
    .line 291
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 292
    .line 293
    .line 294
    move-result-object p0

    .line 295
    check-cast p0, Lcom/google/android/gms/internal/measurement/t2;

    .line 296
    .line 297
    return-object p0
.end method
