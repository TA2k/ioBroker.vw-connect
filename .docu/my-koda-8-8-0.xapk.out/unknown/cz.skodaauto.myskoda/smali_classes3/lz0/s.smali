.class public final Llz0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llz0/m;


# instance fields
.field public final a:Lhu/q;

.field public final b:Ljava/lang/String;

.field public final c:Llz0/r;


# direct methods
.method public constructor <init>(Ljava/util/Collection;Lhu/q;Ljava/lang/String;)V
    .locals 10

    .line 1
    const-string v0, "whatThisExpects"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Llz0/s;->a:Lhu/q;

    .line 10
    .line 11
    iput-object p3, p0, Llz0/s;->b:Ljava/lang/String;

    .line 12
    .line 13
    new-instance p2, Llz0/r;

    .line 14
    .line 15
    invoke-direct {p2}, Llz0/r;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p2, p0, Llz0/s;->c:Llz0/r;

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    if-eqz p2, :cond_7

    .line 29
    .line 30
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    check-cast p2, Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result p3

    .line 40
    if-lez p3, :cond_6

    .line 41
    .line 42
    iget-object p3, p0, Llz0/s;->c:Llz0/r;

    .line 43
    .line 44
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    const/4 v1, 0x0

    .line 49
    move v2, v1

    .line 50
    :goto_1
    const/4 v3, 0x1

    .line 51
    if-ge v2, v0, :cond_4

    .line 52
    .line 53
    invoke-virtual {p2, v2}, Ljava/lang/String;->charAt(I)C

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    iget-object p3, p3, Llz0/r;->a:Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v4}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 68
    .line 69
    .line 70
    move-result v7

    .line 71
    invoke-static {v7, v6}, Ljp/k1;->n(II)V

    .line 72
    .line 73
    .line 74
    sub-int/2addr v6, v3

    .line 75
    move v7, v1

    .line 76
    :goto_2
    if-gt v7, v6, :cond_1

    .line 77
    .line 78
    add-int v8, v7, v6

    .line 79
    .line 80
    ushr-int/2addr v8, v3

    .line 81
    invoke-interface {p3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v9

    .line 85
    check-cast v9, Llx0/l;

    .line 86
    .line 87
    iget-object v9, v9, Llx0/l;->d:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v9, Ljava/lang/String;

    .line 90
    .line 91
    invoke-static {v9, v5}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 92
    .line 93
    .line 94
    move-result v9

    .line 95
    if-gez v9, :cond_0

    .line 96
    .line 97
    add-int/lit8 v7, v8, 0x1

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_0
    if-lez v9, :cond_2

    .line 101
    .line 102
    add-int/lit8 v6, v8, -0x1

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_1
    add-int/lit8 v7, v7, 0x1

    .line 106
    .line 107
    neg-int v8, v7

    .line 108
    :cond_2
    if-gez v8, :cond_3

    .line 109
    .line 110
    new-instance v5, Llz0/r;

    .line 111
    .line 112
    invoke-direct {v5}, Llz0/r;-><init>()V

    .line 113
    .line 114
    .line 115
    neg-int v6, v8

    .line 116
    sub-int/2addr v6, v3

    .line 117
    invoke-static {v4}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    new-instance v4, Llx0/l;

    .line 122
    .line 123
    invoke-direct {v4, v3, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    invoke-interface {p3, v6, v4}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    move-object p3, v5

    .line 130
    goto :goto_3

    .line 131
    :cond_3
    invoke-interface {p3, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p3

    .line 135
    check-cast p3, Llx0/l;

    .line 136
    .line 137
    iget-object p3, p3, Llx0/l;->e:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast p3, Llz0/r;

    .line 140
    .line 141
    :goto_3
    add-int/lit8 v2, v2, 0x1

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_4
    iget-boolean v0, p3, Llz0/r;->b:Z

    .line 145
    .line 146
    if-nez v0, :cond_5

    .line 147
    .line 148
    iput-boolean v3, p3, Llz0/r;->b:Z

    .line 149
    .line 150
    goto :goto_0

    .line 151
    :cond_5
    const-string p0, "The string \'"

    .line 152
    .line 153
    const-string p1, "\' was passed several times"

    .line 154
    .line 155
    invoke-static {p0, p2, p1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 160
    .line 161
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p1

    .line 169
    :cond_6
    new-instance p1, Ljava/lang/StringBuilder;

    .line 170
    .line 171
    const-string p2, "Found an empty string in "

    .line 172
    .line 173
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    iget-object p0, p0, Llz0/s;->b:Ljava/lang/String;

    .line 177
    .line 178
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 186
    .line 187
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    throw p1

    .line 195
    :cond_7
    iget-object p0, p0, Llz0/s;->c:Llz0/r;

    .line 196
    .line 197
    invoke-static {p0}, Llz0/s;->b(Llz0/r;)V

    .line 198
    .line 199
    .line 200
    return-void
.end method

.method public static final b(Llz0/r;)V
    .locals 7

    .line 1
    iget-object p0, p0, Llz0/r;->a:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Llx0/l;

    .line 18
    .line 19
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Llz0/r;

    .line 22
    .line 23
    invoke-static {v1}, Llz0/s;->b(Llz0/r;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_2

    .line 41
    .line 42
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    check-cast v2, Llx0/l;

    .line 47
    .line 48
    iget-object v3, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v3, Ljava/lang/String;

    .line 51
    .line 52
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v2, Llz0/r;

    .line 55
    .line 56
    iget-boolean v4, v2, Llz0/r;->b:Z

    .line 57
    .line 58
    iget-object v5, v2, Llz0/r;->a:Ljava/util/List;

    .line 59
    .line 60
    if-nez v4, :cond_1

    .line 61
    .line 62
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    const/4 v6, 0x1

    .line 67
    if-ne v4, v6, :cond_1

    .line 68
    .line 69
    invoke-static {v5}, Lmx0/q;->i0(Ljava/util/List;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    check-cast v2, Llx0/l;

    .line 74
    .line 75
    iget-object v4, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v4, Ljava/lang/String;

    .line 78
    .line 79
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v2, Llz0/r;

    .line 82
    .line 83
    invoke-static {v3, v4}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    new-instance v4, Llx0/l;

    .line 88
    .line 89
    invoke-direct {v4, v3, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_1
    new-instance v4, Llx0/l;

    .line 97
    .line 98
    invoke-direct {v4, v3, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_2
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 106
    .line 107
    .line 108
    new-instance v1, Llz0/k;

    .line 109
    .line 110
    const/4 v2, 0x1

    .line 111
    invoke-direct {v1, v2}, Llz0/k;-><init>(I)V

    .line 112
    .line 113
    .line 114
    invoke-static {v0, v1}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    check-cast v0, Ljava/util/Collection;

    .line 119
    .line 120
    invoke-interface {p0, v0}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 121
    .line 122
    .line 123
    return-void
.end method


# virtual methods
.method public final a(Llz0/c;Ljava/lang/CharSequence;I)Ljava/lang/Object;
    .locals 7

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v6, Lkotlin/jvm/internal/d0;

    .line 7
    .line 8
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput p3, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 12
    .line 13
    iget-object v0, p0, Llz0/s;->c:Llz0/r;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    :goto_0
    iget v2, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 17
    .line 18
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-gt v2, v3, :cond_2

    .line 23
    .line 24
    iget-boolean v2, v0, Llz0/r;->b:Z

    .line 25
    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    iget v1, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 29
    .line 30
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    :cond_0
    iget-object v0, v0, Llz0/r;->a:Ljava/util/List;

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    check-cast v2, Llx0/l;

    .line 51
    .line 52
    iget-object v3, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v3, Ljava/lang/String;

    .line 55
    .line 56
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v2, Llz0/r;

    .line 59
    .line 60
    iget v4, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    invoke-static {p2, v3, v4, v5}, Lly0/p;->a0(Ljava/lang/CharSequence;Ljava/lang/String;IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    if-eqz v4, :cond_1

    .line 68
    .line 69
    iget v0, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 70
    .line 71
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    add-int/2addr v3, v0

    .line 76
    iput v3, v6, Lkotlin/jvm/internal/d0;->d:I

    .line 77
    .line 78
    move-object v0, v2

    .line 79
    goto :goto_0

    .line 80
    :cond_2
    if-eqz v1, :cond_4

    .line 81
    .line 82
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    invoke-interface {p2, p3, v0}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 87
    .line 88
    .line 89
    move-result-object p2

    .line 90
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    iget-object p0, p0, Llz0/s;->a:Lhu/q;

    .line 95
    .line 96
    invoke-virtual {p0, p1, p2}, Lhu/q;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    if-nez p1, :cond_3

    .line 101
    .line 102
    return-object v1

    .line 103
    :cond_3
    new-instance v0, Lc41/b;

    .line 104
    .line 105
    const/16 v1, 0x10

    .line 106
    .line 107
    invoke-direct {v0, p1, p2, p0, v1}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 108
    .line 109
    .line 110
    new-instance p0, Llz0/h;

    .line 111
    .line 112
    invoke-direct {p0, p3, v0}, Llz0/h;-><init>(ILay0/a;)V

    .line 113
    .line 114
    .line 115
    return-object p0

    .line 116
    :cond_4
    new-instance v1, Lh2/w4;

    .line 117
    .line 118
    const/4 v3, 0x2

    .line 119
    move-object v4, p0

    .line 120
    move-object v5, p2

    .line 121
    move v2, p3

    .line 122
    invoke-direct/range {v1 .. v6}, Lh2/w4;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    new-instance p0, Llz0/h;

    .line 126
    .line 127
    invoke-direct {p0, v2, v1}, Llz0/h;-><init>(ILay0/a;)V

    .line 128
    .line 129
    .line 130
    return-object p0
.end method
