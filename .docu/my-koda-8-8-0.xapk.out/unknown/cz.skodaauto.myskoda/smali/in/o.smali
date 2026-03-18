.class public final Lin/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/x0;


# instance fields
.field public a:I

.field public b:Z

.field public c:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x4

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    iput-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    const/4 v0, 0x0

    iput v0, p0, Lin/o;->a:I

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 4
    iput-boolean v0, p0, Lin/o;->b:Z

    .line 5
    sget-object v0, Lin/d;->e:Lin/d;

    iput-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 6
    iput p1, p0, Lin/o;->a:I

    return-void
.end method

.method public static final d(Lin/o;Llx0/b;Lrx0/a;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/j;

    .line 4
    .line 5
    instance-of v1, p2, Lwz0/y;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p2

    .line 10
    check-cast v1, Lwz0/y;

    .line 11
    .line 12
    iget v2, v1, Lwz0/y;->k:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lwz0/y;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lwz0/y;

    .line 25
    .line 26
    invoke-direct {v1, p0, p2}, Lwz0/y;-><init>(Lin/o;Lrx0/a;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p2, v1, Lwz0/y;->i:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lwz0/y;->k:I

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    const/4 v5, 0x6

    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x7

    .line 39
    const/4 v8, 0x4

    .line 40
    const/4 v9, 0x1

    .line 41
    if-eqz v3, :cond_4

    .line 42
    .line 43
    if-ne v3, v9, :cond_3

    .line 44
    .line 45
    iget p0, v1, Lwz0/y;->h:I

    .line 46
    .line 47
    iget-object p1, v1, Lwz0/y;->g:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v0, v1, Lwz0/y;->f:Ljava/util/LinkedHashMap;

    .line 50
    .line 51
    iget-object v3, v1, Lwz0/y;->e:Lin/o;

    .line 52
    .line 53
    iget-object v10, v1, Lwz0/y;->d:Llx0/b;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    check-cast p2, Lvz0/n;

    .line 59
    .line 60
    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    iget-object p1, v3, Lin/o;->c:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p1, Lo8/j;

    .line 66
    .line 67
    invoke-virtual {p1}, Lo8/j;->f()B

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eq p1, v8, :cond_2

    .line 72
    .line 73
    if-ne p1, v7, :cond_1

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_1
    iget-object p0, v3, Lin/o;->c:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Lo8/j;

    .line 79
    .line 80
    const-string p1, "Expected end of the object or comma"

    .line 81
    .line 82
    invoke-static {p0, p1, v6, v4, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 83
    .line 84
    .line 85
    throw v4

    .line 86
    :cond_2
    move v6, p0

    .line 87
    move-object p0, v3

    .line 88
    goto :goto_1

    .line 89
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 92
    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0, v5}, Lo8/j;->g(B)B

    .line 101
    .line 102
    .line 103
    move-result p2

    .line 104
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-eq v3, v8, :cond_9

    .line 109
    .line 110
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 111
    .line 112
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 113
    .line 114
    .line 115
    move-object v10, p1

    .line 116
    move p1, p2

    .line 117
    :goto_1
    iget-object p2, p0, Lin/o;->c:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p2, Lo8/j;

    .line 120
    .line 121
    invoke-virtual {p2}, Lo8/j;->c()Z

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    if-eqz v3, :cond_6

    .line 126
    .line 127
    iget-boolean p1, p0, Lin/o;->b:Z

    .line 128
    .line 129
    if-eqz p1, :cond_5

    .line 130
    .line 131
    invoke-virtual {p2}, Lo8/j;->l()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    goto :goto_2

    .line 136
    :cond_5
    invoke-virtual {p2}, Lo8/j;->j()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    :goto_2
    const/4 v3, 0x5

    .line 141
    invoke-virtual {p2, v3}, Lo8/j;->g(B)B

    .line 142
    .line 143
    .line 144
    iput-object v10, v1, Lwz0/y;->d:Llx0/b;

    .line 145
    .line 146
    iput-object p0, v1, Lwz0/y;->e:Lin/o;

    .line 147
    .line 148
    iput-object v0, v1, Lwz0/y;->f:Ljava/util/LinkedHashMap;

    .line 149
    .line 150
    iput-object p1, v1, Lwz0/y;->g:Ljava/lang/String;

    .line 151
    .line 152
    iput v6, v1, Lwz0/y;->h:I

    .line 153
    .line 154
    iput v9, v1, Lwz0/y;->k:I

    .line 155
    .line 156
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    iput-object v1, v10, Llx0/b;->e:Lkotlin/coroutines/Continuation;

    .line 160
    .line 161
    return-object v2

    .line 162
    :cond_6
    move-object v3, p0

    .line 163
    :goto_3
    iget-object p0, v3, Lin/o;->c:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast p0, Lo8/j;

    .line 166
    .line 167
    if-ne p1, v5, :cond_7

    .line 168
    .line 169
    invoke-virtual {p0, v7}, Lo8/j;->g(B)B

    .line 170
    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_7
    if-eq p1, v8, :cond_8

    .line 174
    .line 175
    :goto_4
    new-instance p0, Lvz0/a0;

    .line 176
    .line 177
    invoke-direct {p0, v0}, Lvz0/a0;-><init>(Ljava/util/Map;)V

    .line 178
    .line 179
    .line 180
    return-object p0

    .line 181
    :cond_8
    const-string p1, "object"

    .line 182
    .line 183
    invoke-static {p0, p1}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw v4

    .line 187
    :cond_9
    const-string p0, "Unexpected leading comma"

    .line 188
    .line 189
    invoke-static {v0, p0, v6, v4, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 190
    .line 191
    .line 192
    throw v4
.end method

.method public static e(Ljava/util/ArrayList;ILin/y0;)I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    if-gez p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    iget-object p1, p2, Lin/a1;->b:Lin/w0;

    .line 10
    .line 11
    if-eq p0, p1, :cond_1

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_1
    invoke-interface {p1}, Lin/w0;->b()Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_3

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    check-cast p1, Lin/a1;

    .line 33
    .line 34
    if-ne p1, p2, :cond_2

    .line 35
    .line 36
    return v0

    .line 37
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_3
    :goto_1
    const/4 p0, -0x1

    .line 41
    return p0
.end method

.method public static g(Lin/c;)Ljava/util/ArrayList;
    .locals 9

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    :cond_0
    invoke-virtual {p0}, Li4/c;->q()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-nez v1, :cond_9

    .line 11
    .line 12
    iget-object v1, p0, Li4/c;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Ljava/lang/String;

    .line 15
    .line 16
    invoke-virtual {p0}, Li4/c;->q()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/4 v3, 0x0

    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    iget v2, p0, Li4/c;->b:I

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Ljava/lang/String;->charAt(I)C

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    const/16 v5, 0x7a

    .line 31
    .line 32
    const/16 v6, 0x61

    .line 33
    .line 34
    const/16 v7, 0x5a

    .line 35
    .line 36
    const/16 v8, 0x41

    .line 37
    .line 38
    if-lt v4, v8, :cond_2

    .line 39
    .line 40
    if-le v4, v7, :cond_3

    .line 41
    .line 42
    :cond_2
    if-lt v4, v6, :cond_7

    .line 43
    .line 44
    if-gt v4, v5, :cond_7

    .line 45
    .line 46
    :cond_3
    invoke-virtual {p0}, Li4/c;->h()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    :goto_0
    if-lt v3, v8, :cond_4

    .line 51
    .line 52
    if-le v3, v7, :cond_5

    .line 53
    .line 54
    :cond_4
    if-lt v3, v6, :cond_6

    .line 55
    .line 56
    if-gt v3, v5, :cond_6

    .line 57
    .line 58
    :cond_5
    invoke-virtual {p0}, Li4/c;->h()I

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    goto :goto_0

    .line 63
    :cond_6
    iget v3, p0, Li4/c;->b:I

    .line 64
    .line 65
    invoke-virtual {v1, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    goto :goto_1

    .line 70
    :cond_7
    iput v2, p0, Li4/c;->b:I

    .line 71
    .line 72
    :goto_1
    if-nez v3, :cond_8

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_8
    :try_start_0
    invoke-static {v3}, Lin/d;->valueOf(Ljava/lang/String;)Lin/d;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 80
    .line 81
    .line 82
    :catch_0
    invoke-virtual {p0}, Li4/c;->Q()Z

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    if-nez v1, :cond_0

    .line 87
    .line 88
    :cond_9
    :goto_2
    return-object v0
.end method

.method public static m(Lin/m;ILjava/util/ArrayList;ILin/y0;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lin/m;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lin/n;

    .line 8
    .line 9
    invoke-static {v0, p4}, Lin/o;->p(Lin/n;Lin/y0;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_0
    iget v0, v0, Lin/n;->a:I

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    if-ne v0, v1, :cond_3

    .line 20
    .line 21
    if-nez p1, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    :goto_0
    if-ltz p3, :cond_5

    .line 25
    .line 26
    add-int/lit8 p4, p1, -0x1

    .line 27
    .line 28
    invoke-static {p0, p4, p2, p3}, Lin/o;->o(Lin/m;ILjava/util/ArrayList;I)Z

    .line 29
    .line 30
    .line 31
    move-result p4

    .line 32
    if-eqz p4, :cond_2

    .line 33
    .line 34
    :goto_1
    return v1

    .line 35
    :cond_2
    add-int/lit8 p3, p3, -0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_3
    const/4 v2, 0x2

    .line 39
    if-ne v0, v2, :cond_4

    .line 40
    .line 41
    sub-int/2addr p1, v1

    .line 42
    invoke-static {p0, p1, p2, p3}, Lin/o;->o(Lin/m;ILjava/util/ArrayList;I)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    return p0

    .line 47
    :cond_4
    invoke-static {p2, p3, p4}, Lin/o;->e(Ljava/util/ArrayList;ILin/y0;)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-gtz v0, :cond_6

    .line 52
    .line 53
    :cond_5
    :goto_2
    const/4 p0, 0x0

    .line 54
    return p0

    .line 55
    :cond_6
    iget-object p4, p4, Lin/a1;->b:Lin/w0;

    .line 56
    .line 57
    invoke-interface {p4}, Lin/w0;->b()Ljava/util/List;

    .line 58
    .line 59
    .line 60
    move-result-object p4

    .line 61
    sub-int/2addr v0, v1

    .line 62
    invoke-interface {p4, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p4

    .line 66
    check-cast p4, Lin/y0;

    .line 67
    .line 68
    sub-int/2addr p1, v1

    .line 69
    invoke-static {p0, p1, p2, p3, p4}, Lin/o;->m(Lin/m;ILjava/util/ArrayList;ILin/y0;)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    return p0
.end method

.method public static n(Lin/m;Lin/y0;)Z
    .locals 5

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p1, Lin/a1;->b:Lin/w0;

    .line 7
    .line 8
    :goto_0
    const/4 v2, 0x0

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, v2, v1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    check-cast v1, Lin/a1;

    .line 15
    .line 16
    iget-object v1, v1, Lin/a1;->b:Lin/w0;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    const/4 v3, 0x1

    .line 24
    sub-int/2addr v1, v3

    .line 25
    iget-object v4, p0, Lin/m;->a:Ljava/util/ArrayList;

    .line 26
    .line 27
    if-nez v4, :cond_1

    .line 28
    .line 29
    move v4, v2

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    :goto_1
    if-ne v4, v3, :cond_2

    .line 36
    .line 37
    iget-object p0, p0, Lin/m;->a:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p0, Lin/n;

    .line 44
    .line 45
    invoke-static {p0, p1}, Lin/o;->p(Lin/n;Lin/y0;)Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0

    .line 50
    :cond_2
    iget-object v4, p0, Lin/m;->a:Ljava/util/ArrayList;

    .line 51
    .line 52
    if-nez v4, :cond_3

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_3
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    :goto_2
    sub-int/2addr v2, v3

    .line 60
    invoke-static {p0, v2, v0, v1, p1}, Lin/o;->m(Lin/m;ILjava/util/ArrayList;ILin/y0;)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    return p0
.end method

.method public static o(Lin/m;ILjava/util/ArrayList;I)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lin/m;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lin/n;

    .line 8
    .line 9
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lin/y0;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lin/o;->p(Lin/n;Lin/y0;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    iget v0, v0, Lin/n;->a:I

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-ne v0, v2, :cond_2

    .line 26
    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    if-lez p3, :cond_4

    .line 31
    .line 32
    add-int/lit8 v0, p1, -0x1

    .line 33
    .line 34
    add-int/lit8 p3, p3, -0x1

    .line 35
    .line 36
    invoke-static {p0, v0, p2, p3}, Lin/o;->o(Lin/m;ILjava/util/ArrayList;I)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    :goto_0
    return v2

    .line 43
    :cond_2
    const/4 v3, 0x2

    .line 44
    if-ne v0, v3, :cond_3

    .line 45
    .line 46
    sub-int/2addr p1, v2

    .line 47
    sub-int/2addr p3, v2

    .line 48
    invoke-static {p0, p1, p2, p3}, Lin/o;->o(Lin/m;ILjava/util/ArrayList;I)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    return p0

    .line 53
    :cond_3
    invoke-static {p2, p3, v1}, Lin/o;->e(Ljava/util/ArrayList;ILin/y0;)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-gtz v0, :cond_5

    .line 58
    .line 59
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 60
    return p0

    .line 61
    :cond_5
    iget-object v1, v1, Lin/a1;->b:Lin/w0;

    .line 62
    .line 63
    invoke-interface {v1}, Lin/w0;->b()Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    sub-int/2addr v0, v2

    .line 68
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    check-cast v0, Lin/y0;

    .line 73
    .line 74
    sub-int/2addr p1, v2

    .line 75
    invoke-static {p0, p1, p2, p3, v0}, Lin/o;->m(Lin/m;ILjava/util/ArrayList;ILin/y0;)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    return p0
.end method

.method public static p(Lin/n;Lin/y0;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lin/n;->b:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1}, Lin/a1;->o()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 10
    .line 11
    invoke-virtual {v1, v2}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object v0, p0, Lin/n;->c:Ljava/util/ArrayList;

    .line 23
    .line 24
    if-eqz v0, :cond_5

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_5

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Lin/b;

    .line 41
    .line 42
    iget-object v2, v1, Lin/b;->a:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v1, v1, Lin/b;->c:Ljava/lang/String;

    .line 45
    .line 46
    const-string v3, "id"

    .line 47
    .line 48
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    if-nez v3, :cond_4

    .line 53
    .line 54
    const-string v3, "class"

    .line 55
    .line 56
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-nez v2, :cond_2

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    iget-object v2, p1, Lin/y0;->g:Ljava/util/ArrayList;

    .line 64
    .line 65
    if-nez v2, :cond_3

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_3
    invoke-interface {v2, v1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_4
    iget-object v2, p1, Lin/y0;->c:Ljava/lang/String;

    .line 76
    .line 77
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v1

    .line 81
    if-nez v1, :cond_1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_5
    iget-object p0, p0, Lin/n;->d:Ljava/util/ArrayList;

    .line 85
    .line 86
    if-eqz p0, :cond_7

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    :cond_6
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    if-eqz v0, :cond_7

    .line 97
    .line 98
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    check-cast v0, Lin/e;

    .line 103
    .line 104
    invoke-interface {v0, p1}, Lin/e;->a(Lin/y0;)Z

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    if-nez v0, :cond_6

    .line 109
    .line 110
    :goto_0
    const/4 p0, 0x0

    .line 111
    return p0

    .line 112
    :cond_7
    const/4 p0, 0x1

    .line 113
    return p0
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lin/o;->b:Z

    .line 3
    .line 4
    return-void
.end method

.method public b()V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/appcompat/widget/ActionBarContextView;

    .line 4
    .line 5
    invoke-static {v0}, Landroidx/appcompat/widget/ActionBarContextView;->a(Landroidx/appcompat/widget/ActionBarContextView;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-boolean v0, p0, Lin/o;->b:Z

    .line 10
    .line 11
    return-void
.end method

.method public c()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lin/o;->b:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroidx/appcompat/widget/ActionBarContextView;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    iput-object v1, v0, Landroidx/appcompat/widget/ActionBarContextView;->i:Ld6/w0;

    .line 12
    .line 13
    iget p0, p0, Lin/o;->a:I

    .line 14
    .line 15
    invoke-static {v0, p0}, Landroidx/appcompat/widget/ActionBarContextView;->b(Landroidx/appcompat/widget/ActionBarContextView;I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public f(Ld01/x;Lin/c;)V
    .locals 10

    .line 1
    invoke-virtual {p2}, Lin/c;->U()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p2}, Li4/c;->R()V

    .line 6
    .line 7
    .line 8
    if-eqz v0, :cond_1e

    .line 9
    .line 10
    iget-boolean v1, p0, Lin/o;->b:Z

    .line 11
    .line 12
    const-string v2, "Invalid @media rule: expected \'}\' at end of rule set"

    .line 13
    .line 14
    const/16 v3, 0x7d

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    const/16 v5, 0x7b

    .line 18
    .line 19
    const/4 v6, 0x1

    .line 20
    if-nez v1, :cond_5

    .line 21
    .line 22
    const-string v1, "media"

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_5

    .line 29
    .line 30
    invoke-static {p2}, Lin/o;->g(Lin/c;)Ljava/util/ArrayList;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {p2, v5}, Li4/c;->m(C)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_4

    .line 39
    .line 40
    invoke-virtual {p2}, Li4/c;->R()V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Lin/o;->c:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lin/d;

    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-eqz v5, :cond_2

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    check-cast v5, Lin/d;

    .line 62
    .line 63
    sget-object v7, Lin/d;->d:Lin/d;

    .line 64
    .line 65
    if-eq v5, v7, :cond_1

    .line 66
    .line 67
    if-ne v5, v1, :cond_0

    .line 68
    .line 69
    :cond_1
    iput-boolean v6, p0, Lin/o;->b:Z

    .line 70
    .line 71
    invoke-virtual {p0, p2}, Lin/o;->i(Lin/c;)Ld01/x;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-virtual {p1, v0}, Ld01/x;->d(Ld01/x;)V

    .line 76
    .line 77
    .line 78
    iput-boolean v4, p0, Lin/o;->b:Z

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_2
    invoke-virtual {p0, p2}, Lin/o;->i(Lin/c;)Ld01/x;

    .line 82
    .line 83
    .line 84
    :goto_0
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-nez p0, :cond_1d

    .line 89
    .line 90
    invoke-virtual {p2, v3}, Li4/c;->m(C)Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-eqz p0, :cond_3

    .line 95
    .line 96
    goto/16 :goto_9

    .line 97
    .line 98
    :cond_3
    new-instance p0, Lin/a;

    .line 99
    .line 100
    invoke-direct {p0, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_4
    new-instance p0, Lin/a;

    .line 105
    .line 106
    const-string p1, "Invalid @media rule: missing rule set"

    .line 107
    .line 108
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_5
    iget-boolean p0, p0, Lin/o;->b:Z

    .line 113
    .line 114
    const/16 p1, 0x3b

    .line 115
    .line 116
    if-nez p0, :cond_19

    .line 117
    .line 118
    const-string p0, "import"

    .line 119
    .line 120
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result p0

    .line 124
    if-eqz p0, :cond_19

    .line 125
    .line 126
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    const/4 v0, 0x0

    .line 131
    if-eqz p0, :cond_6

    .line 132
    .line 133
    goto/16 :goto_7

    .line 134
    .line 135
    :cond_6
    iget p0, p2, Li4/c;->b:I

    .line 136
    .line 137
    const-string v1, "url("

    .line 138
    .line 139
    invoke-virtual {p2, v1}, Li4/c;->n(Ljava/lang/String;)Z

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    if-nez v1, :cond_7

    .line 144
    .line 145
    goto/16 :goto_7

    .line 146
    .line 147
    :cond_7
    invoke-virtual {p2}, Li4/c;->R()V

    .line 148
    .line 149
    .line 150
    invoke-virtual {p2}, Lin/c;->T()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v1

    .line 154
    if-nez v1, :cond_12

    .line 155
    .line 156
    iget-object v1, p2, Li4/c;->d:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v1, Ljava/lang/String;

    .line 159
    .line 160
    new-instance v3, Ljava/lang/StringBuilder;

    .line 161
    .line 162
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 163
    .line 164
    .line 165
    :cond_8
    :goto_1
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 166
    .line 167
    .line 168
    move-result v4

    .line 169
    if-nez v4, :cond_10

    .line 170
    .line 171
    iget v4, p2, Li4/c;->b:I

    .line 172
    .line 173
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    const/16 v5, 0x27

    .line 178
    .line 179
    if-eq v4, v5, :cond_10

    .line 180
    .line 181
    const/16 v5, 0x22

    .line 182
    .line 183
    if-eq v4, v5, :cond_10

    .line 184
    .line 185
    const/16 v5, 0x28

    .line 186
    .line 187
    if-eq v4, v5, :cond_10

    .line 188
    .line 189
    const/16 v5, 0x29

    .line 190
    .line 191
    if-eq v4, v5, :cond_10

    .line 192
    .line 193
    invoke-static {v4}, Li4/c;->z(I)Z

    .line 194
    .line 195
    .line 196
    move-result v5

    .line 197
    if-nez v5, :cond_10

    .line 198
    .line 199
    invoke-static {v4}, Ljava/lang/Character;->isISOControl(I)Z

    .line 200
    .line 201
    .line 202
    move-result v5

    .line 203
    if-eqz v5, :cond_9

    .line 204
    .line 205
    goto :goto_4

    .line 206
    :cond_9
    iget v5, p2, Li4/c;->b:I

    .line 207
    .line 208
    add-int/2addr v5, v6

    .line 209
    iput v5, p2, Li4/c;->b:I

    .line 210
    .line 211
    const/16 v5, 0x5c

    .line 212
    .line 213
    if-ne v4, v5, :cond_f

    .line 214
    .line 215
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    if-eqz v4, :cond_a

    .line 220
    .line 221
    goto :goto_1

    .line 222
    :cond_a
    iget v4, p2, Li4/c;->b:I

    .line 223
    .line 224
    add-int/lit8 v5, v4, 0x1

    .line 225
    .line 226
    iput v5, p2, Li4/c;->b:I

    .line 227
    .line 228
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 229
    .line 230
    .line 231
    move-result v4

    .line 232
    const/16 v5, 0xa

    .line 233
    .line 234
    if-eq v4, v5, :cond_8

    .line 235
    .line 236
    const/16 v5, 0xd

    .line 237
    .line 238
    if-eq v4, v5, :cond_8

    .line 239
    .line 240
    const/16 v5, 0xc

    .line 241
    .line 242
    if-ne v4, v5, :cond_b

    .line 243
    .line 244
    goto :goto_1

    .line 245
    :cond_b
    invoke-static {v4}, Lin/c;->S(I)I

    .line 246
    .line 247
    .line 248
    move-result v5

    .line 249
    const/4 v7, -0x1

    .line 250
    if-eq v5, v7, :cond_f

    .line 251
    .line 252
    move v4, v6

    .line 253
    :goto_2
    const/4 v8, 0x5

    .line 254
    if-gt v4, v8, :cond_e

    .line 255
    .line 256
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 257
    .line 258
    .line 259
    move-result v8

    .line 260
    if-eqz v8, :cond_c

    .line 261
    .line 262
    goto :goto_3

    .line 263
    :cond_c
    iget v8, p2, Li4/c;->b:I

    .line 264
    .line 265
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 266
    .line 267
    .line 268
    move-result v8

    .line 269
    invoke-static {v8}, Lin/c;->S(I)I

    .line 270
    .line 271
    .line 272
    move-result v8

    .line 273
    if-ne v8, v7, :cond_d

    .line 274
    .line 275
    goto :goto_3

    .line 276
    :cond_d
    iget v9, p2, Li4/c;->b:I

    .line 277
    .line 278
    add-int/2addr v9, v6

    .line 279
    iput v9, p2, Li4/c;->b:I

    .line 280
    .line 281
    mul-int/lit8 v5, v5, 0x10

    .line 282
    .line 283
    add-int/2addr v5, v8

    .line 284
    add-int/lit8 v4, v4, 0x1

    .line 285
    .line 286
    goto :goto_2

    .line 287
    :cond_e
    :goto_3
    int-to-char v4, v5

    .line 288
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 289
    .line 290
    .line 291
    goto :goto_1

    .line 292
    :cond_f
    int-to-char v4, v4

    .line 293
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    goto/16 :goto_1

    .line 297
    .line 298
    :cond_10
    :goto_4
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->length()I

    .line 299
    .line 300
    .line 301
    move-result v1

    .line 302
    if-nez v1, :cond_11

    .line 303
    .line 304
    move-object v1, v0

    .line 305
    goto :goto_5

    .line 306
    :cond_11
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v1

    .line 310
    :cond_12
    :goto_5
    if-nez v1, :cond_13

    .line 311
    .line 312
    iput p0, p2, Li4/c;->b:I

    .line 313
    .line 314
    goto :goto_7

    .line 315
    :cond_13
    invoke-virtual {p2}, Li4/c;->R()V

    .line 316
    .line 317
    .line 318
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 319
    .line 320
    .line 321
    move-result v3

    .line 322
    if-nez v3, :cond_15

    .line 323
    .line 324
    const-string v3, ")"

    .line 325
    .line 326
    invoke-virtual {p2, v3}, Li4/c;->n(Ljava/lang/String;)Z

    .line 327
    .line 328
    .line 329
    move-result v3

    .line 330
    if-eqz v3, :cond_14

    .line 331
    .line 332
    goto :goto_6

    .line 333
    :cond_14
    iput p0, p2, Li4/c;->b:I

    .line 334
    .line 335
    goto :goto_7

    .line 336
    :cond_15
    :goto_6
    move-object v0, v1

    .line 337
    :goto_7
    if-nez v0, :cond_16

    .line 338
    .line 339
    invoke-virtual {p2}, Lin/c;->T()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    :cond_16
    if-eqz v0, :cond_18

    .line 344
    .line 345
    invoke-virtual {p2}, Li4/c;->R()V

    .line 346
    .line 347
    .line 348
    invoke-static {p2}, Lin/o;->g(Lin/c;)Ljava/util/ArrayList;

    .line 349
    .line 350
    .line 351
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 352
    .line 353
    .line 354
    move-result p0

    .line 355
    if-nez p0, :cond_1d

    .line 356
    .line 357
    invoke-virtual {p2, p1}, Li4/c;->m(C)Z

    .line 358
    .line 359
    .line 360
    move-result p0

    .line 361
    if-eqz p0, :cond_17

    .line 362
    .line 363
    goto :goto_9

    .line 364
    :cond_17
    new-instance p0, Lin/a;

    .line 365
    .line 366
    invoke-direct {p0, v2}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    throw p0

    .line 370
    :cond_18
    new-instance p0, Lin/a;

    .line 371
    .line 372
    const-string p1, "Invalid @import rule: expected string or url()"

    .line 373
    .line 374
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 375
    .line 376
    .line 377
    throw p0

    .line 378
    :cond_19
    new-instance p0, Ljava/lang/StringBuilder;

    .line 379
    .line 380
    const-string v1, "Ignoring @"

    .line 381
    .line 382
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 386
    .line 387
    .line 388
    const-string v0, " rule"

    .line 389
    .line 390
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 391
    .line 392
    .line 393
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 394
    .line 395
    .line 396
    move-result-object p0

    .line 397
    const-string v0, "CSSParser"

    .line 398
    .line 399
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 400
    .line 401
    .line 402
    :cond_1a
    :goto_8
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 403
    .line 404
    .line 405
    move-result p0

    .line 406
    if-nez p0, :cond_1d

    .line 407
    .line 408
    invoke-virtual {p2}, Li4/c;->B()Ljava/lang/Integer;

    .line 409
    .line 410
    .line 411
    move-result-object p0

    .line 412
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 413
    .line 414
    .line 415
    move-result p0

    .line 416
    if-ne p0, p1, :cond_1b

    .line 417
    .line 418
    if-nez v4, :cond_1b

    .line 419
    .line 420
    goto :goto_9

    .line 421
    :cond_1b
    if-ne p0, v5, :cond_1c

    .line 422
    .line 423
    add-int/lit8 v4, v4, 0x1

    .line 424
    .line 425
    goto :goto_8

    .line 426
    :cond_1c
    if-ne p0, v3, :cond_1a

    .line 427
    .line 428
    if-lez v4, :cond_1a

    .line 429
    .line 430
    add-int/lit8 v4, v4, -0x1

    .line 431
    .line 432
    if-nez v4, :cond_1a

    .line 433
    .line 434
    :cond_1d
    :goto_9
    invoke-virtual {p2}, Li4/c;->R()V

    .line 435
    .line 436
    .line 437
    return-void

    .line 438
    :cond_1e
    new-instance p0, Lin/a;

    .line 439
    .line 440
    const-string p1, "Invalid \'@\' rule"

    .line 441
    .line 442
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    throw p0
.end method

.method public h(Ld01/x;Lin/c;)Z
    .locals 13

    .line 1
    invoke-virtual {p2}, Lin/c;->V()Ljava/util/ArrayList;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_d

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_d

    .line 12
    .line 13
    const/16 v1, 0x7b

    .line 14
    .line 15
    invoke-virtual {p2, v1}, Li4/c;->m(C)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_c

    .line 20
    .line 21
    invoke-virtual {p2}, Li4/c;->R()V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lin/s0;

    .line 25
    .line 26
    invoke-direct {v1}, Lin/s0;-><init>()V

    .line 27
    .line 28
    .line 29
    :cond_0
    invoke-virtual {p2}, Lin/c;->U()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {p2}, Li4/c;->R()V

    .line 34
    .line 35
    .line 36
    const/16 v3, 0x3a

    .line 37
    .line 38
    invoke-virtual {p2, v3}, Li4/c;->m(C)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_b

    .line 43
    .line 44
    invoke-virtual {p2}, Li4/c;->R()V

    .line 45
    .line 46
    .line 47
    iget-object v3, p2, Li4/c;->d:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v3, Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    const/4 v5, 0x1

    .line 56
    const/16 v6, 0x21

    .line 57
    .line 58
    const/16 v7, 0x7d

    .line 59
    .line 60
    const/16 v8, 0x3b

    .line 61
    .line 62
    const/4 v9, 0x0

    .line 63
    if-eqz v4, :cond_1

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_1
    iget v4, p2, Li4/c;->b:I

    .line 67
    .line 68
    invoke-virtual {v3, v4}, Ljava/lang/String;->charAt(I)C

    .line 69
    .line 70
    .line 71
    move-result v10

    .line 72
    move v11, v4

    .line 73
    :goto_0
    const/4 v12, -0x1

    .line 74
    if-eq v10, v12, :cond_4

    .line 75
    .line 76
    if-eq v10, v8, :cond_4

    .line 77
    .line 78
    if-eq v10, v7, :cond_4

    .line 79
    .line 80
    if-eq v10, v6, :cond_4

    .line 81
    .line 82
    const/16 v12, 0xa

    .line 83
    .line 84
    if-eq v10, v12, :cond_4

    .line 85
    .line 86
    const/16 v12, 0xd

    .line 87
    .line 88
    if-ne v10, v12, :cond_2

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    invoke-static {v10}, Li4/c;->z(I)Z

    .line 92
    .line 93
    .line 94
    move-result v10

    .line 95
    if-nez v10, :cond_3

    .line 96
    .line 97
    iget v10, p2, Li4/c;->b:I

    .line 98
    .line 99
    add-int/lit8 v11, v10, 0x1

    .line 100
    .line 101
    :cond_3
    invoke-virtual {p2}, Li4/c;->h()I

    .line 102
    .line 103
    .line 104
    move-result v10

    .line 105
    goto :goto_0

    .line 106
    :cond_4
    :goto_1
    iget v10, p2, Li4/c;->b:I

    .line 107
    .line 108
    if-le v10, v4, :cond_5

    .line 109
    .line 110
    invoke-virtual {v3, v4, v11}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v9

    .line 114
    goto :goto_2

    .line 115
    :cond_5
    iput v4, p2, Li4/c;->b:I

    .line 116
    .line 117
    :goto_2
    if-eqz v9, :cond_a

    .line 118
    .line 119
    invoke-virtual {p2}, Li4/c;->R()V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p2, v6}, Li4/c;->m(C)Z

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-eqz v3, :cond_7

    .line 127
    .line 128
    invoke-virtual {p2}, Li4/c;->R()V

    .line 129
    .line 130
    .line 131
    const-string v3, "important"

    .line 132
    .line 133
    invoke-virtual {p2, v3}, Li4/c;->n(Ljava/lang/String;)Z

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    if-eqz v3, :cond_6

    .line 138
    .line 139
    invoke-virtual {p2}, Li4/c;->R()V

    .line 140
    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_6
    new-instance p0, Lin/a;

    .line 144
    .line 145
    const-string p1, "Malformed rule set: found unexpected \'!\'"

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :cond_7
    :goto_3
    invoke-virtual {p2, v8}, Li4/c;->m(C)Z

    .line 152
    .line 153
    .line 154
    invoke-static {v1, v2, v9}, Lin/j2;->D(Lin/s0;Ljava/lang/String;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p2}, Li4/c;->R()V

    .line 158
    .line 159
    .line 160
    invoke-virtual {p2}, Li4/c;->q()Z

    .line 161
    .line 162
    .line 163
    move-result v2

    .line 164
    if-nez v2, :cond_8

    .line 165
    .line 166
    invoke-virtual {p2, v7}, Li4/c;->m(C)Z

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    if-eqz v2, :cond_0

    .line 171
    .line 172
    :cond_8
    invoke-virtual {p2}, Li4/c;->R()V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 176
    .line 177
    .line 178
    move-result-object p2

    .line 179
    :goto_4
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-eqz v0, :cond_9

    .line 184
    .line 185
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    check-cast v0, Lin/m;

    .line 190
    .line 191
    new-instance v2, Lin/l;

    .line 192
    .line 193
    iget v3, p0, Lin/o;->a:I

    .line 194
    .line 195
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 196
    .line 197
    .line 198
    iput-object v0, v2, Lin/l;->a:Lin/m;

    .line 199
    .line 200
    iput-object v1, v2, Lin/l;->b:Lin/s0;

    .line 201
    .line 202
    iput v3, v2, Lin/l;->c:I

    .line 203
    .line 204
    invoke-virtual {p1, v2}, Ld01/x;->a(Lin/l;)V

    .line 205
    .line 206
    .line 207
    goto :goto_4

    .line 208
    :cond_9
    return v5

    .line 209
    :cond_a
    new-instance p0, Lin/a;

    .line 210
    .line 211
    const-string p1, "Expected property value"

    .line 212
    .line 213
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    throw p0

    .line 217
    :cond_b
    new-instance p0, Lin/a;

    .line 218
    .line 219
    const-string p1, "Expected \':\'"

    .line 220
    .line 221
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p0

    .line 225
    :cond_c
    new-instance p0, Lin/a;

    .line 226
    .line 227
    const-string p1, "Malformed rule block: expected \'{\'"

    .line 228
    .line 229
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    throw p0

    .line 233
    :cond_d
    const/4 p0, 0x0

    .line 234
    return p0
.end method

.method public i(Lin/c;)Ld01/x;
    .locals 3

    .line 1
    new-instance v0, Ld01/x;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Ld01/x;-><init>(BI)V

    .line 6
    .line 7
    .line 8
    :goto_0
    :try_start_0
    invoke-virtual {p1}, Li4/c;->q()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-nez v1, :cond_3

    .line 13
    .line 14
    const-string v1, "<!--"

    .line 15
    .line 16
    invoke-virtual {p1, v1}, Li4/c;->n(Ljava/lang/String;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const-string v1, "-->"

    .line 24
    .line 25
    invoke-virtual {p1, v1}, Li4/c;->n(Ljava/lang/String;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    const/16 v1, 0x40

    .line 33
    .line 34
    invoke-virtual {p1, v1}, Li4/c;->m(C)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    invoke-virtual {p0, v0, p1}, Lin/o;->f(Ld01/x;Lin/c;)V

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :catch_0
    move-exception p0

    .line 45
    goto :goto_1

    .line 46
    :cond_2
    invoke-virtual {p0, v0, p1}, Lin/o;->h(Ld01/x;Lin/c;)Z

    .line 47
    .line 48
    .line 49
    move-result v1
    :try_end_0
    .catch Lin/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    return-object v0

    .line 54
    :goto_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 55
    .line 56
    const-string v1, "CSS parser terminated early due to error: "

    .line 57
    .line 58
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    const-string p1, "CSSParser"

    .line 73
    .line 74
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 75
    .line 76
    .line 77
    return-object v0
.end method

.method public j()Lvz0/n;
    .locals 9

    .line 1
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/j;

    .line 4
    .line 5
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x1

    .line 10
    if-ne v1, v2, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, v2}, Lin/o;->l(Z)Lvz0/e0;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    const/4 v3, 0x0

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v3}, Lin/o;->l(Z)Lvz0/e0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_1
    const/4 v4, 0x6

    .line 26
    const/4 v5, 0x0

    .line 27
    if-ne v1, v4, :cond_d

    .line 28
    .line 29
    iget v1, p0, Lin/o;->a:I

    .line 30
    .line 31
    add-int/2addr v1, v2

    .line 32
    iput v1, p0, Lin/o;->a:I

    .line 33
    .line 34
    const/16 v2, 0xc8

    .line 35
    .line 36
    if-ne v1, v2, :cond_5

    .line 37
    .line 38
    new-instance v0, Lwz0/x;

    .line 39
    .line 40
    invoke-direct {v0, p0, v5}, Lwz0/x;-><init>(Lin/o;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    sget-object v1, Llx0/a;->a:Lqx0/a;

    .line 44
    .line 45
    new-instance v1, Llx0/b;

    .line 46
    .line 47
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object v0, v1, Llx0/b;->d:Lwz0/x;

    .line 51
    .line 52
    iput-object v1, v1, Llx0/b;->e:Lkotlin/coroutines/Continuation;

    .line 53
    .line 54
    sget-object v2, Llx0/a;->a:Lqx0/a;

    .line 55
    .line 56
    iput-object v2, v1, Llx0/b;->f:Ljava/lang/Object;

    .line 57
    .line 58
    :cond_2
    :goto_0
    iget-object v0, v1, Llx0/b;->f:Ljava/lang/Object;

    .line 59
    .line 60
    iget-object v3, v1, Llx0/b;->e:Lkotlin/coroutines/Continuation;

    .line 61
    .line 62
    if-nez v3, :cond_3

    .line 63
    .line 64
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    check-cast v0, Lvz0/n;

    .line 68
    .line 69
    goto/16 :goto_4

    .line 70
    .line 71
    :cond_3
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_4

    .line 76
    .line 77
    :try_start_0
    iget-object v0, v1, Llx0/b;->d:Lwz0/x;

    .line 78
    .line 79
    const/4 v4, 0x3

    .line 80
    invoke-static {v4, v0}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    new-instance v4, Lwz0/x;

    .line 84
    .line 85
    iget-object v0, v0, Lwz0/x;->g:Lin/o;

    .line 86
    .line 87
    invoke-direct {v4, v0, v3}, Lwz0/x;-><init>(Lin/o;Lkotlin/coroutines/Continuation;)V

    .line 88
    .line 89
    .line 90
    iput-object v1, v4, Lwz0/x;->f:Llx0/b;

    .line 91
    .line 92
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    invoke-virtual {v4, v0}, Lwz0/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 98
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 99
    .line 100
    if-eq v0, v4, :cond_2

    .line 101
    .line 102
    invoke-interface {v3, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :catchall_0
    move-exception v0

    .line 107
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-interface {v3, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_0

    .line 115
    :cond_4
    iput-object v2, v1, Llx0/b;->f:Ljava/lang/Object;

    .line 116
    .line 117
    invoke-interface {v3, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_0

    .line 121
    :cond_5
    invoke-virtual {v0, v4}, Lo8/j;->g(B)B

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 126
    .line 127
    .line 128
    move-result v2

    .line 129
    const/4 v6, 0x4

    .line 130
    if-eq v2, v6, :cond_c

    .line 131
    .line 132
    new-instance v2, Ljava/util/LinkedHashMap;

    .line 133
    .line 134
    invoke-direct {v2}, Ljava/util/LinkedHashMap;-><init>()V

    .line 135
    .line 136
    .line 137
    :cond_6
    invoke-virtual {v0}, Lo8/j;->c()Z

    .line 138
    .line 139
    .line 140
    move-result v7

    .line 141
    const/4 v8, 0x7

    .line 142
    if-eqz v7, :cond_9

    .line 143
    .line 144
    iget-boolean v1, p0, Lin/o;->b:Z

    .line 145
    .line 146
    if-eqz v1, :cond_7

    .line 147
    .line 148
    invoke-virtual {v0}, Lo8/j;->l()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    goto :goto_1

    .line 153
    :cond_7
    invoke-virtual {v0}, Lo8/j;->j()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    :goto_1
    const/4 v7, 0x5

    .line 158
    invoke-virtual {v0, v7}, Lo8/j;->g(B)B

    .line 159
    .line 160
    .line 161
    invoke-virtual {p0}, Lin/o;->j()Lvz0/n;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    invoke-interface {v2, v1, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0}, Lo8/j;->f()B

    .line 169
    .line 170
    .line 171
    move-result v1

    .line 172
    if-eq v1, v6, :cond_6

    .line 173
    .line 174
    if-ne v1, v8, :cond_8

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_8
    const-string p0, "Expected end of the object or comma"

    .line 178
    .line 179
    invoke-static {v0, p0, v3, v5, v4}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 180
    .line 181
    .line 182
    throw v5

    .line 183
    :cond_9
    :goto_2
    if-ne v1, v4, :cond_a

    .line 184
    .line 185
    invoke-virtual {v0, v8}, Lo8/j;->g(B)B

    .line 186
    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_a
    if-eq v1, v6, :cond_b

    .line 190
    .line 191
    :goto_3
    new-instance v0, Lvz0/a0;

    .line 192
    .line 193
    invoke-direct {v0, v2}, Lvz0/a0;-><init>(Ljava/util/Map;)V

    .line 194
    .line 195
    .line 196
    :goto_4
    iget v1, p0, Lin/o;->a:I

    .line 197
    .line 198
    add-int/lit8 v1, v1, -0x1

    .line 199
    .line 200
    iput v1, p0, Lin/o;->a:I

    .line 201
    .line 202
    return-object v0

    .line 203
    :cond_b
    const-string p0, "object"

    .line 204
    .line 205
    invoke-static {v0, p0}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw v5

    .line 209
    :cond_c
    const-string p0, "Unexpected leading comma"

    .line 210
    .line 211
    invoke-static {v0, p0, v3, v5, v4}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 212
    .line 213
    .line 214
    throw v5

    .line 215
    :cond_d
    const/16 v2, 0x8

    .line 216
    .line 217
    if-ne v1, v2, :cond_e

    .line 218
    .line 219
    invoke-virtual {p0}, Lin/o;->k()Lvz0/f;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    return-object p0

    .line 224
    :cond_e
    invoke-static {v1}, Lwz0/p;->s(B)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    const-string v1, "Cannot read Json element because of unexpected "

    .line 229
    .line 230
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    invoke-static {v0, p0, v3, v5, v4}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 235
    .line 236
    .line 237
    throw v5
.end method

.method public k()Lvz0/f;
    .locals 8

    .line 1
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/j;

    .line 4
    .line 5
    invoke-virtual {v0}, Lo8/j;->f()B

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {v0}, Lo8/j;->x()B

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x0

    .line 14
    const/4 v4, 0x0

    .line 15
    const/4 v5, 0x4

    .line 16
    if-eq v2, v5, :cond_6

    .line 17
    .line 18
    new-instance v2, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    :cond_0
    :goto_0
    invoke-virtual {v0}, Lo8/j;->c()Z

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    const/16 v7, 0x9

    .line 28
    .line 29
    if-eqz v6, :cond_3

    .line 30
    .line 31
    invoke-virtual {p0}, Lin/o;->j()Lvz0/n;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Lo8/j;->f()B

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eq v1, v5, :cond_0

    .line 43
    .line 44
    if-ne v1, v7, :cond_1

    .line 45
    .line 46
    const/4 v6, 0x1

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    move v6, v3

    .line 49
    :goto_1
    iget v7, v0, Lo8/j;->b:I

    .line 50
    .line 51
    if-eqz v6, :cond_2

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    const-string p0, "Expected end of the array or comma"

    .line 55
    .line 56
    invoke-static {v0, p0, v7, v4, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    throw v4

    .line 60
    :cond_3
    const/16 p0, 0x8

    .line 61
    .line 62
    if-ne v1, p0, :cond_4

    .line 63
    .line 64
    invoke-virtual {v0, v7}, Lo8/j;->g(B)B

    .line 65
    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_4
    if-eq v1, v5, :cond_5

    .line 69
    .line 70
    :goto_2
    new-instance p0, Lvz0/f;

    .line 71
    .line 72
    invoke-direct {p0, v2}, Lvz0/f;-><init>(Ljava/util/List;)V

    .line 73
    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_5
    const-string p0, "array"

    .line 77
    .line 78
    invoke-static {v0, p0}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw v4

    .line 82
    :cond_6
    const-string p0, "Unexpected leading comma"

    .line 83
    .line 84
    const/4 v1, 0x6

    .line 85
    invoke-static {v0, p0, v3, v4, v1}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 86
    .line 87
    .line 88
    throw v4
.end method

.method public l(Z)Lvz0/e0;
    .locals 2

    .line 1
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lo8/j;

    .line 4
    .line 5
    iget-boolean p0, p0, Lin/o;->b:Z

    .line 6
    .line 7
    if-nez p0, :cond_1

    .line 8
    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {v0}, Lo8/j;->j()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    goto :goto_1

    .line 17
    :cond_1
    :goto_0
    invoke-virtual {v0}, Lo8/j;->l()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_1
    if-nez p1, :cond_2

    .line 22
    .line 23
    const-string v0, "null"

    .line 24
    .line 25
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    sget-object p0, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    new-instance v0, Lvz0/u;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-direct {v0, p0, p1, v1}, Lvz0/u;-><init>(Ljava/lang/Object;ZLsz0/g;)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public q(Ljava/lang/Object;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lin/o;->a:I

    .line 5
    .line 6
    add-int/lit8 v0, v0, 0x1

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lin/o;->r(I)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, [Ljava/lang/Object;

    .line 14
    .line 15
    iget v1, p0, Lin/o;->a:I

    .line 16
    .line 17
    add-int/lit8 v2, v1, 0x1

    .line 18
    .line 19
    iput v2, p0, Lin/o;->a:I

    .line 20
    .line 21
    aput-object p1, v0, v1

    .line 22
    .line 23
    return-void
.end method

.method public r(I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, [Ljava/lang/Object;

    .line 4
    .line 5
    array-length v1, v0

    .line 6
    const/4 v2, 0x0

    .line 7
    if-ge v1, p1, :cond_2

    .line 8
    .line 9
    shr-int/lit8 v3, v1, 0x1

    .line 10
    .line 11
    add-int/2addr v1, v3

    .line 12
    add-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    if-ge v1, p1, :cond_0

    .line 15
    .line 16
    add-int/lit8 p1, p1, -0x1

    .line 17
    .line 18
    invoke-static {p1}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    add-int v1, p1, p1

    .line 23
    .line 24
    :cond_0
    if-gez v1, :cond_1

    .line 25
    .line 26
    const v1, 0x7fffffff

    .line 27
    .line 28
    .line 29
    :cond_1
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iput-object p1, p0, Lin/o;->c:Ljava/lang/Object;

    .line 34
    .line 35
    iput-boolean v2, p0, Lin/o;->b:Z

    .line 36
    .line 37
    return-void

    .line 38
    :cond_2
    iget-boolean p1, p0, Lin/o;->b:Z

    .line 39
    .line 40
    if-eqz p1, :cond_3

    .line 41
    .line 42
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    check-cast p1, [Ljava/lang/Object;

    .line 47
    .line 48
    iput-object p1, p0, Lin/o;->c:Ljava/lang/Object;

    .line 49
    .line 50
    iput-boolean v2, p0, Lin/o;->b:Z

    .line 51
    .line 52
    :cond_3
    return-void
.end method

.method public s()Ljp/c0;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lin/o;->b:Z

    .line 3
    .line 4
    iget-object v0, p0, Lin/o;->c:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, [Ljava/lang/Object;

    .line 7
    .line 8
    iget p0, p0, Lin/o;->a:I

    .line 9
    .line 10
    sget-object v1, Ljp/y;->e:Ljp/w;

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    sget-object p0, Ljp/c0;->h:Ljp/c0;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance v1, Ljp/c0;

    .line 18
    .line 19
    invoke-direct {v1, v0, p0}, Ljp/c0;-><init>([Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    return-object v1
.end method
