.class public abstract Ljp/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lz9/w;Lhy0/d;Lt2/b;)V
    .locals 3

    .line 1
    new-instance v0, Laa/j;

    .line 2
    .line 3
    iget-object v1, p0, Lz9/w;->g:Lz9/k0;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const-class v2, Laa/i;

    .line 9
    .line 10
    invoke-static {v2}, Ljp/s0;->a(Ljava/lang/Class;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v1, v2}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Laa/i;

    .line 19
    .line 20
    invoke-direct {v0, v1, p1, p2}, Laa/j;-><init>(Laa/i;Lhy0/d;Lt2/b;)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p1, Lmx0/r;->d:Lmx0/r;

    .line 24
    .line 25
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    if-eqz p2, :cond_0

    .line 30
    .line 31
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Lz9/r;

    .line 36
    .line 37
    const-string p2, "navDeepLink"

    .line 38
    .line 39
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object p2, v0, Lvp/c;->e:Ljava/io/Serializable;

    .line 43
    .line 44
    check-cast p2, Ljava/util/ArrayList;

    .line 45
    .line 46
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 p1, 0x0

    .line 51
    iput-object p1, v0, Laa/j;->i:Lay0/k;

    .line 52
    .line 53
    iput-object p1, v0, Laa/j;->j:Lay0/k;

    .line 54
    .line 55
    iput-object p1, v0, Laa/j;->k:Lay0/k;

    .line 56
    .line 57
    iput-object p1, v0, Laa/j;->l:Lay0/k;

    .line 58
    .line 59
    iget-object p0, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v0}, Laa/j;->a()Lz9/u;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    return-void
.end method

.method public static b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V
    .locals 3

    .line 1
    and-int/lit8 v0, p8, 0x2

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-object p2, v1

    .line 8
    :cond_0
    and-int/lit8 v0, p8, 0x8

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    move-object p3, v2

    .line 14
    :cond_1
    and-int/lit8 v0, p8, 0x10

    .line 15
    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    move-object p4, v2

    .line 19
    :cond_2
    and-int/lit8 v0, p8, 0x20

    .line 20
    .line 21
    if-eqz v0, :cond_3

    .line 22
    .line 23
    move-object p5, p3

    .line 24
    :cond_3
    and-int/lit8 p8, p8, 0x40

    .line 25
    .line 26
    if-eqz p8, :cond_4

    .line 27
    .line 28
    move-object p6, p4

    .line 29
    :cond_4
    new-instance p8, Laa/j;

    .line 30
    .line 31
    iget-object v0, p0, Lz9/w;->g:Lz9/k0;

    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    const-class v2, Laa/i;

    .line 37
    .line 38
    invoke-static {v2}, Ljp/s0;->a(Ljava/lang/Class;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-virtual {v0, v2}, Lz9/k0;->b(Ljava/lang/String;)Lz9/j0;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Laa/i;

    .line 47
    .line 48
    invoke-direct {p8, v0, p1, p7}, Laa/j;-><init>(Laa/i;Ljava/lang/String;Lay0/p;)V

    .line 49
    .line 50
    .line 51
    check-cast p2, Ljava/lang/Iterable;

    .line 52
    .line 53
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    if-eqz p2, :cond_5

    .line 62
    .line 63
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    check-cast p2, Lz9/h;

    .line 68
    .line 69
    iget-object p7, p2, Lz9/h;->a:Ljava/lang/String;

    .line 70
    .line 71
    iget-object p2, p2, Lz9/h;->b:Lz9/i;

    .line 72
    .line 73
    const-string v0, "name"

    .line 74
    .line 75
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget-object v0, p8, Lvp/c;->d:Ljava/io/Serializable;

    .line 79
    .line 80
    check-cast v0, Ljava/util/LinkedHashMap;

    .line 81
    .line 82
    invoke-interface {v0, p7, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_5
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    if-eqz p2, :cond_6

    .line 95
    .line 96
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    check-cast p2, Lz9/r;

    .line 101
    .line 102
    const-string p7, "navDeepLink"

    .line 103
    .line 104
    invoke-static {p2, p7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    iget-object p7, p8, Lvp/c;->e:Ljava/io/Serializable;

    .line 108
    .line 109
    check-cast p7, Ljava/util/ArrayList;

    .line 110
    .line 111
    invoke-virtual {p7, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_6
    iput-object p3, p8, Laa/j;->i:Lay0/k;

    .line 116
    .line 117
    iput-object p4, p8, Laa/j;->j:Lay0/k;

    .line 118
    .line 119
    iput-object p5, p8, Laa/j;->k:Lay0/k;

    .line 120
    .line 121
    iput-object p6, p8, Laa/j;->l:Lay0/k;

    .line 122
    .line 123
    iget-object p0, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-virtual {p8}, Laa/j;->a()Lz9/u;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    return-void
.end method

.method public static final c(Lm70/r;)Ljava/lang/String;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lm70/r;->f:Ljava/lang/String;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lm70/r;->g:Ljava/lang/String;

    .line 14
    .line 15
    if-eqz p0, :cond_2

    .line 16
    .line 17
    invoke-static {p0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    if-eqz v0, :cond_4

    .line 28
    .line 29
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    const-string v2, " - "

    .line 39
    .line 40
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    :goto_0
    if-eqz v0, :cond_4

    .line 55
    .line 56
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-eqz p0, :cond_3

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    :cond_4
    :goto_1
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0
.end method

.method public static final d(Lay0/k;)Lz9/b0;
    .locals 11

    .line 1
    new-instance v0, Lz9/c0;

    .line 2
    .line 3
    invoke-direct {v0}, Lz9/c0;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    iget-boolean p0, v0, Lz9/c0;->b:Z

    .line 10
    .line 11
    iget-object v1, v0, Lz9/c0;->a:Lz9/a0;

    .line 12
    .line 13
    iput-boolean p0, v1, Lz9/a0;->a:Z

    .line 14
    .line 15
    iget-boolean p0, v0, Lz9/c0;->c:Z

    .line 16
    .line 17
    iput-boolean p0, v1, Lz9/a0;->b:Z

    .line 18
    .line 19
    iget-object p0, v0, Lz9/c0;->e:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v2, -0x1

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    iget-boolean v3, v0, Lz9/c0;->f:Z

    .line 25
    .line 26
    iget-boolean v0, v0, Lz9/c0;->g:Z

    .line 27
    .line 28
    iput-object p0, v1, Lz9/a0;->d:Ljava/lang/String;

    .line 29
    .line 30
    iput v2, v1, Lz9/a0;->c:I

    .line 31
    .line 32
    iput-boolean v3, v1, Lz9/a0;->f:Z

    .line 33
    .line 34
    iput-boolean v0, v1, Lz9/a0;->g:Z

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iget-object p0, v0, Lz9/c0;->h:Lhy0/d;

    .line 38
    .line 39
    if-eqz p0, :cond_1

    .line 40
    .line 41
    iget-boolean v3, v0, Lz9/c0;->f:Z

    .line 42
    .line 43
    iget-boolean v0, v0, Lz9/c0;->g:Z

    .line 44
    .line 45
    iput-object p0, v1, Lz9/a0;->e:Lhy0/d;

    .line 46
    .line 47
    iput v2, v1, Lz9/a0;->c:I

    .line 48
    .line 49
    iput-boolean v3, v1, Lz9/a0;->f:Z

    .line 50
    .line 51
    iput-boolean v0, v1, Lz9/a0;->g:Z

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    iget p0, v0, Lz9/c0;->d:I

    .line 55
    .line 56
    iget-boolean v2, v0, Lz9/c0;->f:Z

    .line 57
    .line 58
    iget-boolean v0, v0, Lz9/c0;->g:Z

    .line 59
    .line 60
    iput p0, v1, Lz9/a0;->c:I

    .line 61
    .line 62
    const/4 p0, 0x0

    .line 63
    iput-object p0, v1, Lz9/a0;->d:Ljava/lang/String;

    .line 64
    .line 65
    iput-boolean v2, v1, Lz9/a0;->f:Z

    .line 66
    .line 67
    iput-boolean v0, v1, Lz9/a0;->g:Z

    .line 68
    .line 69
    :goto_0
    iget-object p0, v1, Lz9/a0;->d:Ljava/lang/String;

    .line 70
    .line 71
    if-eqz p0, :cond_2

    .line 72
    .line 73
    new-instance v2, Lz9/b0;

    .line 74
    .line 75
    iget-boolean v3, v1, Lz9/a0;->a:Z

    .line 76
    .line 77
    iget-boolean v4, v1, Lz9/a0;->b:Z

    .line 78
    .line 79
    iget-boolean v6, v1, Lz9/a0;->f:Z

    .line 80
    .line 81
    iget-boolean v7, v1, Lz9/a0;->g:Z

    .line 82
    .line 83
    iget v8, v1, Lz9/a0;->h:I

    .line 84
    .line 85
    iget v9, v1, Lz9/a0;->i:I

    .line 86
    .line 87
    sget v0, Lz9/u;->h:I

    .line 88
    .line 89
    const-string v0, "android-app://androidx.navigation/"

    .line 90
    .line 91
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    invoke-direct/range {v2 .. v9}, Lz9/b0;-><init>(ZZIZZII)V

    .line 100
    .line 101
    .line 102
    iput-object p0, v2, Lz9/b0;->h:Ljava/lang/String;

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_2
    iget-object p0, v1, Lz9/a0;->e:Lhy0/d;

    .line 106
    .line 107
    if-eqz p0, :cond_3

    .line 108
    .line 109
    new-instance v2, Lz9/b0;

    .line 110
    .line 111
    iget-boolean v3, v1, Lz9/a0;->a:Z

    .line 112
    .line 113
    iget-boolean v4, v1, Lz9/a0;->b:Z

    .line 114
    .line 115
    iget-boolean v6, v1, Lz9/a0;->f:Z

    .line 116
    .line 117
    iget-boolean v7, v1, Lz9/a0;->g:Z

    .line 118
    .line 119
    iget v8, v1, Lz9/a0;->h:I

    .line 120
    .line 121
    iget v9, v1, Lz9/a0;->i:I

    .line 122
    .line 123
    invoke-static {p0}, Ljp/mg;->c(Lhy0/d;)Lqz0/a;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    invoke-static {v0}, Lda/d;->b(Lqz0/a;)I

    .line 128
    .line 129
    .line 130
    move-result v5

    .line 131
    invoke-direct/range {v2 .. v9}, Lz9/b0;-><init>(ZZIZZII)V

    .line 132
    .line 133
    .line 134
    iput-object p0, v2, Lz9/b0;->i:Lhy0/d;

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_3
    new-instance v3, Lz9/b0;

    .line 138
    .line 139
    iget-boolean v4, v1, Lz9/a0;->a:Z

    .line 140
    .line 141
    iget-boolean v5, v1, Lz9/a0;->b:Z

    .line 142
    .line 143
    iget v6, v1, Lz9/a0;->c:I

    .line 144
    .line 145
    iget-boolean v7, v1, Lz9/a0;->f:Z

    .line 146
    .line 147
    iget-boolean v8, v1, Lz9/a0;->g:Z

    .line 148
    .line 149
    iget v9, v1, Lz9/a0;->h:I

    .line 150
    .line 151
    iget v10, v1, Lz9/a0;->i:I

    .line 152
    .line 153
    invoke-direct/range {v3 .. v10}, Lz9/b0;-><init>(ZZIZZII)V

    .line 154
    .line 155
    .line 156
    move-object v2, v3

    .line 157
    :goto_1
    return-object v2
.end method

.method public static e(Lz9/w;Ljava/lang/String;Ljava/lang/String;Lay0/k;)V
    .locals 2

    .line 1
    new-instance v0, Lz9/w;

    .line 2
    .line 3
    iget-object v1, p0, Lz9/w;->g:Lz9/k0;

    .line 4
    .line 5
    invoke-direct {v0, v1, p1, p2}, Lz9/w;-><init>(Lz9/k0;Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p3, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lz9/w;->i()Lz9/v;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    :goto_0
    sget-object p2, Lmx0/r;->d:Lmx0/r;

    .line 16
    .line 17
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result p3

    .line 21
    if-eqz p3, :cond_0

    .line 22
    .line 23
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    check-cast p2, Lz9/h;

    .line 28
    .line 29
    iget-object p3, p2, Lz9/h;->a:Ljava/lang/String;

    .line 30
    .line 31
    iget-object p2, p2, Lz9/h;->b:Lz9/i;

    .line 32
    .line 33
    const-string v0, "argumentName"

    .line 34
    .line 35
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, p1, Lz9/u;->e:Lca/j;

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    iget-object v0, v0, Lca/j;->d:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v0, Ljava/util/LinkedHashMap;

    .line 46
    .line 47
    invoke-interface {v0, p3, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    if-eqz p3, :cond_1

    .line 56
    .line 57
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p3

    .line 61
    check-cast p3, Lz9/r;

    .line 62
    .line 63
    invoke-virtual {p1, p3}, Lz9/u;->c(Lz9/r;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    iget-object p0, p0, Lz9/w;->k:Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    return-void
.end method
