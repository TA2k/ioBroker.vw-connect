.class public final Li5/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static f:I


# instance fields
.field public a:Ljava/util/ArrayList;

.field public b:I

.field public c:I

.field public d:Ljava/util/ArrayList;

.field public e:I


# virtual methods
.method public final a(Ljava/util/ArrayList;)V
    .locals 5

    .line 1
    iget-object v0, p0, Li5/o;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Li5/o;->e:I

    .line 8
    .line 9
    const/4 v2, -0x1

    .line 10
    if-eq v1, v2, :cond_1

    .line 11
    .line 12
    if-lez v0, :cond_1

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    :goto_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-ge v1, v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Li5/o;

    .line 26
    .line 27
    iget v3, p0, Li5/o;->e:I

    .line 28
    .line 29
    iget v4, v2, Li5/o;->b:I

    .line 30
    .line 31
    if-ne v3, v4, :cond_0

    .line 32
    .line 33
    iget v3, p0, Li5/o;->c:I

    .line 34
    .line 35
    invoke-virtual {p0, v3, v2}, Li5/o;->c(ILi5/o;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    if-nez v0, :cond_2

    .line 42
    .line 43
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    :cond_2
    return-void
.end method

.method public final b(La5/c;I)I
    .locals 8

    .line 1
    iget-object v0, p0, Li5/o;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lh5/d;

    .line 16
    .line 17
    iget-object v1, v1, Lh5/d;->U:Lh5/e;

    .line 18
    .line 19
    invoke-virtual {p1}, La5/c;->t()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1, p1, v2}, Lh5/d;->c(La5/c;Z)V

    .line 23
    .line 24
    .line 25
    move v3, v2

    .line 26
    :goto_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-ge v3, v4, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Lh5/d;

    .line 37
    .line 38
    invoke-virtual {v4, p1, v2}, Lh5/d;->c(La5/c;Z)V

    .line 39
    .line 40
    .line 41
    add-int/lit8 v3, v3, 0x1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    if-nez p2, :cond_2

    .line 45
    .line 46
    iget v3, v1, Lh5/e;->A0:I

    .line 47
    .line 48
    if-lez v3, :cond_2

    .line 49
    .line 50
    invoke-static {v1, p1, v0, v2}, Lh5/j;->a(Lh5/e;La5/c;Ljava/util/ArrayList;I)V

    .line 51
    .line 52
    .line 53
    :cond_2
    const/4 v3, 0x1

    .line 54
    if-ne p2, v3, :cond_3

    .line 55
    .line 56
    iget v4, v1, Lh5/e;->B0:I

    .line 57
    .line 58
    if-lez v4, :cond_3

    .line 59
    .line 60
    invoke-static {v1, p1, v0, v3}, Lh5/j;->a(Lh5/e;La5/c;Ljava/util/ArrayList;I)V

    .line 61
    .line 62
    .line 63
    :cond_3
    :try_start_0
    invoke-virtual {p1}, La5/c;->p()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :catch_0
    move-exception v3

    .line 68
    sget-object v4, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 69
    .line 70
    new-instance v5, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v6, "\n"

    .line 83
    .line 84
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v3}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-static {v3}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    const-string v6, "["

    .line 96
    .line 97
    const-string v7, "   at "

    .line 98
    .line 99
    invoke-virtual {v3, v6, v7}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    const-string v6, ","

    .line 104
    .line 105
    const-string v7, "\n   at"

    .line 106
    .line 107
    invoke-virtual {v3, v6, v7}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v3

    .line 111
    const-string v6, "]"

    .line 112
    .line 113
    const-string v7, ""

    .line 114
    .line 115
    invoke-virtual {v3, v6, v7}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    invoke-virtual {v4, v3}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    :goto_1
    new-instance v3, Ljava/util/ArrayList;

    .line 130
    .line 131
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 132
    .line 133
    .line 134
    iput-object v3, p0, Li5/o;->d:Ljava/util/ArrayList;

    .line 135
    .line 136
    :goto_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    if-ge v2, v3, :cond_4

    .line 141
    .line 142
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    check-cast v3, Lh5/d;

    .line 147
    .line 148
    new-instance v4, Lfv/b;

    .line 149
    .line 150
    const/4 v5, 0x7

    .line 151
    invoke-direct {v4, v5}, Lfv/b;-><init>(I)V

    .line 152
    .line 153
    .line 154
    new-instance v5, Ljava/lang/ref/WeakReference;

    .line 155
    .line 156
    invoke-direct {v5, v3}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iget-object v5, v3, Lh5/d;->J:Lh5/c;

    .line 160
    .line 161
    invoke-static {v5}, La5/c;->n(Ljava/lang/Object;)I

    .line 162
    .line 163
    .line 164
    iget-object v5, v3, Lh5/d;->K:Lh5/c;

    .line 165
    .line 166
    invoke-static {v5}, La5/c;->n(Ljava/lang/Object;)I

    .line 167
    .line 168
    .line 169
    iget-object v5, v3, Lh5/d;->L:Lh5/c;

    .line 170
    .line 171
    invoke-static {v5}, La5/c;->n(Ljava/lang/Object;)I

    .line 172
    .line 173
    .line 174
    iget-object v5, v3, Lh5/d;->M:Lh5/c;

    .line 175
    .line 176
    invoke-static {v5}, La5/c;->n(Ljava/lang/Object;)I

    .line 177
    .line 178
    .line 179
    iget-object v3, v3, Lh5/d;->N:Lh5/c;

    .line 180
    .line 181
    invoke-static {v3}, La5/c;->n(Ljava/lang/Object;)I

    .line 182
    .line 183
    .line 184
    iget-object v3, p0, Li5/o;->d:Ljava/util/ArrayList;

    .line 185
    .line 186
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    add-int/lit8 v2, v2, 0x1

    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_4
    if-nez p2, :cond_5

    .line 193
    .line 194
    iget-object p0, v1, Lh5/d;->J:Lh5/c;

    .line 195
    .line 196
    invoke-static {p0}, La5/c;->n(Ljava/lang/Object;)I

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    iget-object p2, v1, Lh5/d;->L:Lh5/c;

    .line 201
    .line 202
    invoke-static {p2}, La5/c;->n(Ljava/lang/Object;)I

    .line 203
    .line 204
    .line 205
    move-result p2

    .line 206
    invoke-virtual {p1}, La5/c;->t()V

    .line 207
    .line 208
    .line 209
    :goto_3
    sub-int/2addr p2, p0

    .line 210
    goto :goto_4

    .line 211
    :cond_5
    iget-object p0, v1, Lh5/d;->K:Lh5/c;

    .line 212
    .line 213
    invoke-static {p0}, La5/c;->n(Ljava/lang/Object;)I

    .line 214
    .line 215
    .line 216
    move-result p0

    .line 217
    iget-object p2, v1, Lh5/d;->M:Lh5/c;

    .line 218
    .line 219
    invoke-static {p2}, La5/c;->n(Ljava/lang/Object;)I

    .line 220
    .line 221
    .line 222
    move-result p2

    .line 223
    invoke-virtual {p1}, La5/c;->t()V

    .line 224
    .line 225
    .line 226
    goto :goto_3

    .line 227
    :goto_4
    return p2
.end method

.method public final c(ILi5/o;)V
    .locals 5

    .line 1
    iget v0, p2, Li5/o;->b:I

    .line 2
    .line 3
    iget-object v1, p0, Li5/o;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-eqz v2, :cond_2

    .line 14
    .line 15
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Lh5/d;

    .line 20
    .line 21
    iget-object v3, p2, Li5/o;->a:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    :goto_1
    if-nez p1, :cond_1

    .line 34
    .line 35
    iput v0, v2, Lh5/d;->o0:I

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    iput v0, v2, Lh5/d;->p0:I

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    iput v0, p0, Li5/o;->e:I

    .line 42
    .line 43
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Li5/o;->c:I

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    const-string v1, "Horizontal"

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v2, 0x1

    .line 14
    if-ne v1, v2, :cond_1

    .line 15
    .line 16
    const-string v1, "Vertical"

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    const/4 v2, 0x2

    .line 20
    if-ne v1, v2, :cond_2

    .line 21
    .line 22
    const-string v1, "Both"

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_2
    const-string v1, "Unknown"

    .line 26
    .line 27
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, " ["

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget v1, p0, Li5/o;->b:I

    .line 36
    .line 37
    const-string v2, "] <"

    .line 38
    .line 39
    invoke-static {v1, v2, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iget-object p0, p0, Li5/o;->a:Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_3

    .line 54
    .line 55
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    check-cast v1, Lh5/d;

    .line 60
    .line 61
    const-string v2, " "

    .line 62
    .line 63
    invoke-static {v0, v2}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    iget-object v1, v1, Lh5/d;->i0:Ljava/lang/String;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    goto :goto_1

    .line 77
    :cond_3
    const-string p0, " >"

    .line 78
    .line 79
    invoke-static {v0, p0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method
