.class public final La8/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public b:Z

.field public c:I

.field public d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public static b(La8/f;)V
    .locals 3

    .line 1
    iget v0, p0, La8/f;->k:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    move v0, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const/4 v0, 0x0

    .line 12
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 13
    .line 14
    .line 15
    iput v2, p0, La8/f;->k:I

    .line 16
    .line 17
    invoke-virtual {p0}, La8/f;->v()V

    .line 18
    .line 19
    .line 20
    :cond_1
    return-void
.end method

.method public static h(La8/f;)Z
    .locals 0

    .line 1
    iget p0, p0, La8/f;->k:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public static l(La8/f;J)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, La8/f;->q:Z

    .line 3
    .line 4
    instance-of v0, p0, Li8/e;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    check-cast p0, Li8/e;

    .line 9
    .line 10
    iget-boolean v0, p0, La8/f;->q:Z

    .line 11
    .line 12
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 13
    .line 14
    .line 15
    iput-wide p1, p0, Li8/e;->N:J

    .line 16
    .line 17
    :cond_0
    return-void
.end method


# virtual methods
.method public a(La8/f;La8/l;)V
    .locals 3

    .line 1
    iget-object v0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La8/f;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eq v0, p1, :cond_1

    .line 8
    .line 9
    iget-object p0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, La8/f;

    .line 12
    .line 13
    if-ne p0, p1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move p0, v1

    .line 17
    goto :goto_1

    .line 18
    :cond_1
    :goto_0
    move p0, v2

    .line 19
    :goto_1
    invoke-static {p0}, Lw7/a;->j(Z)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, La8/p1;->h(La8/f;)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-nez p0, :cond_2

    .line 27
    .line 28
    return-void

    .line 29
    :cond_2
    iget-object p0, p2, La8/l;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, La8/f;

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    if-ne p1, p0, :cond_3

    .line 35
    .line 36
    iput-object v0, p2, La8/l;->i:Ljava/lang/Object;

    .line 37
    .line 38
    iput-object v0, p2, La8/l;->h:Ljava/lang/Object;

    .line 39
    .line 40
    iput-boolean v2, p2, La8/l;->d:Z

    .line 41
    .line 42
    :cond_3
    invoke-static {p1}, La8/p1;->b(La8/f;)V

    .line 43
    .line 44
    .line 45
    iget p0, p1, La8/f;->k:I

    .line 46
    .line 47
    if-ne p0, v2, :cond_4

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_4
    move v2, v1

    .line 51
    :goto_2
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p1, La8/f;->f:Lb81/d;

    .line 55
    .line 56
    invoke-virtual {p0}, Lb81/d;->i()V

    .line 57
    .line 58
    .line 59
    iput v1, p1, La8/f;->k:I

    .line 60
    .line 61
    iput-object v0, p1, La8/f;->l:Lh8/y0;

    .line 62
    .line 63
    iput-object v0, p1, La8/f;->m:[Lt7/o;

    .line 64
    .line 65
    iput-boolean v1, p1, La8/f;->q:Z

    .line 66
    .line 67
    invoke-virtual {p1}, La8/f;->p()V

    .line 68
    .line 69
    .line 70
    iput-object v0, p1, La8/f;->t:Lh8/b0;

    .line 71
    .line 72
    return-void
.end method

.method public c()I
    .locals 1

    .line 1
    iget-object v0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La8/f;

    .line 4
    .line 5
    invoke-static {v0}, La8/p1;->h(La8/f;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object p0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, La8/f;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-static {p0}, La8/p1;->h(La8/f;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    :goto_0
    add-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public d(La8/w0;)La8/f;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_2

    .line 3
    .line 4
    iget-object p1, p1, La8/w0;->c:[Lh8/y0;

    .line 5
    .line 6
    iget v1, p0, La8/p1;->c:I

    .line 7
    .line 8
    aget-object p1, p1, v1

    .line 9
    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    iget-object v1, p0, La8/p1;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, La8/f;

    .line 16
    .line 17
    iget-object v2, v1, La8/f;->l:Lh8/y0;

    .line 18
    .line 19
    if-ne v2, p1, :cond_1

    .line 20
    .line 21
    return-object v1

    .line 22
    :cond_1
    iget-object p0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, La8/f;

    .line 25
    .line 26
    if-eqz p0, :cond_2

    .line 27
    .line 28
    iget-object v1, p0, La8/f;->l:Lh8/y0;

    .line 29
    .line 30
    if-ne v1, p1, :cond_2

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_2
    :goto_0
    return-object v0
.end method

.method public e(La8/w0;La8/f;)Z
    .locals 6

    .line 1
    iget p0, p0, La8/p1;->c:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-nez p2, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    iget-object v1, p1, La8/w0;->c:[Lh8/y0;

    .line 8
    .line 9
    aget-object v1, v1, p0

    .line 10
    .line 11
    iget-object v2, p2, La8/f;->l:Lh8/y0;

    .line 12
    .line 13
    if-eqz v2, :cond_4

    .line 14
    .line 15
    if-ne v2, v1, :cond_2

    .line 16
    .line 17
    if-eqz v1, :cond_4

    .line 18
    .line 19
    invoke-virtual {p2}, La8/f;->l()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-nez v1, :cond_4

    .line 24
    .line 25
    iget-object v1, p1, La8/w0;->m:La8/w0;

    .line 26
    .line 27
    iget-object v2, p1, La8/w0;->g:La8/x0;

    .line 28
    .line 29
    iget-boolean v2, v2, La8/x0;->g:Z

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    iget-boolean v2, v1, La8/w0;->e:Z

    .line 36
    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    instance-of v2, p2, Li8/e;

    .line 40
    .line 41
    if-nez v2, :cond_1

    .line 42
    .line 43
    instance-of v2, p2, Lg8/b;

    .line 44
    .line 45
    if-nez v2, :cond_1

    .line 46
    .line 47
    iget-wide v2, p2, La8/f;->p:J

    .line 48
    .line 49
    invoke-virtual {v1}, La8/w0;->e()J

    .line 50
    .line 51
    .line 52
    move-result-wide v4

    .line 53
    cmp-long v1, v2, v4

    .line 54
    .line 55
    if-ltz v1, :cond_2

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    return v0

    .line 59
    :cond_2
    iget-object p1, p1, La8/w0;->m:La8/w0;

    .line 60
    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    iget-object p1, p1, La8/w0;->c:[Lh8/y0;

    .line 64
    .line 65
    aget-object p0, p1, p0

    .line 66
    .line 67
    iget-object p1, p2, La8/f;->l:Lh8/y0;

    .line 68
    .line 69
    if-ne p0, p1, :cond_3

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    const/4 p0, 0x0

    .line 73
    return p0

    .line 74
    :cond_4
    :goto_0
    return v0
.end method

.method public f()Z
    .locals 1

    .line 1
    iget p0, p0, La8/p1;->d:I

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    if-eq p0, v0, :cond_2

    .line 5
    .line 6
    const/4 v0, 0x4

    .line 7
    if-ne p0, v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x3

    .line 11
    if-ne p0, v0, :cond_1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public g()Z
    .locals 2

    .line 1
    iget v0, p0, La8/p1;->d:I

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    if-eq v0, v1, :cond_2

    .line 7
    .line 8
    const/4 v1, 0x4

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object p0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, La8/f;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget p0, p0, La8/f;->k:I

    .line 20
    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return p0

    .line 27
    :cond_2
    :goto_0
    iget-object p0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, La8/f;

    .line 30
    .line 31
    invoke-static {p0}, La8/p1;->h(La8/f;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public i(Z)V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-eqz p1, :cond_1

    .line 4
    .line 5
    iget-boolean p1, p0, La8/p1;->a:Z

    .line 6
    .line 7
    if-eqz p1, :cond_3

    .line 8
    .line 9
    iget-object p1, p0, La8/p1;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p1, La8/f;

    .line 12
    .line 13
    iget v2, p1, La8/f;->k:I

    .line 14
    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p1, La8/f;->f:Lb81/d;

    .line 23
    .line 24
    invoke-virtual {v0}, Lb81/d;->i()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, La8/f;->t()V

    .line 28
    .line 29
    .line 30
    iput-boolean v1, p0, La8/p1;->a:Z

    .line 31
    .line 32
    return-void

    .line 33
    :cond_1
    iget-boolean p1, p0, La8/p1;->b:Z

    .line 34
    .line 35
    if-eqz p1, :cond_3

    .line 36
    .line 37
    iget-object p1, p0, La8/p1;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, La8/f;

    .line 40
    .line 41
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget v2, p1, La8/f;->k:I

    .line 45
    .line 46
    if-nez v2, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    move v0, v1

    .line 50
    :goto_1
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 51
    .line 52
    .line 53
    iget-object v0, p1, La8/f;->f:Lb81/d;

    .line 54
    .line 55
    invoke-virtual {v0}, Lb81/d;->i()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1}, La8/f;->t()V

    .line 59
    .line 60
    .line 61
    iput-boolean v1, p0, La8/p1;->b:Z

    .line 62
    .line 63
    :cond_3
    return-void
.end method

.method public j(La8/f;La8/w0;Lj8/s;La8/l;)I
    .locals 11

    .line 1
    iget-object v4, p0, La8/p1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v4, La8/f;

    .line 4
    .line 5
    iget v5, p0, La8/p1;->c:I

    .line 6
    .line 7
    const/4 v6, 0x1

    .line 8
    if-eqz p1, :cond_b

    .line 9
    .line 10
    iget v7, p1, La8/f;->k:I

    .line 11
    .line 12
    if-eqz v7, :cond_b

    .line 13
    .line 14
    if-ne p1, v4, :cond_1

    .line 15
    .line 16
    iget v7, p0, La8/p1;->d:I

    .line 17
    .line 18
    const/4 v8, 0x2

    .line 19
    if-eq v7, v8, :cond_0

    .line 20
    .line 21
    const/4 v8, 0x4

    .line 22
    if-ne v7, v8, :cond_1

    .line 23
    .line 24
    :cond_0
    return v6

    .line 25
    :cond_1
    iget-object v7, p0, La8/p1;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v7, La8/f;

    .line 28
    .line 29
    const/4 v8, 0x3

    .line 30
    if-ne p1, v7, :cond_2

    .line 31
    .line 32
    iget v7, p0, La8/p1;->d:I

    .line 33
    .line 34
    if-ne v7, v8, :cond_2

    .line 35
    .line 36
    return v6

    .line 37
    :cond_2
    iget-object v7, p1, La8/f;->l:Lh8/y0;

    .line 38
    .line 39
    iget-object v9, p2, La8/w0;->c:[Lh8/y0;

    .line 40
    .line 41
    aget-object v9, v9, v5

    .line 42
    .line 43
    const/4 v10, 0x0

    .line 44
    if-eq v7, v9, :cond_3

    .line 45
    .line 46
    move v7, v6

    .line 47
    goto :goto_0

    .line 48
    :cond_3
    move v7, v10

    .line 49
    :goto_0
    invoke-virtual {p3, v5}, Lj8/s;->b(I)Z

    .line 50
    .line 51
    .line 52
    move-result v9

    .line 53
    if-eqz v9, :cond_4

    .line 54
    .line 55
    if-nez v7, :cond_4

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_4
    iget-boolean v7, p1, La8/f;->q:Z

    .line 59
    .line 60
    if-nez v7, :cond_7

    .line 61
    .line 62
    iget-object v0, p3, Lj8/s;->c:[Lj8/q;

    .line 63
    .line 64
    aget-object v0, v0, v5

    .line 65
    .line 66
    if-eqz v0, :cond_5

    .line 67
    .line 68
    invoke-interface {v0}, Lj8/q;->length()I

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    goto :goto_1

    .line 73
    :cond_5
    move v3, v10

    .line 74
    :goto_1
    new-array v1, v3, [Lt7/o;

    .line 75
    .line 76
    :goto_2
    if-ge v10, v3, :cond_6

    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    invoke-interface {v0, v10}, Lj8/q;->a(I)Lt7/o;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    aput-object v4, v1, v10

    .line 86
    .line 87
    add-int/lit8 v10, v10, 0x1

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_6
    iget-object v0, p2, La8/w0;->c:[Lh8/y0;

    .line 91
    .line 92
    aget-object v0, v0, v5

    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p2}, La8/w0;->e()J

    .line 98
    .line 99
    .line 100
    move-result-wide v3

    .line 101
    iget-wide v5, p2, La8/w0;->p:J

    .line 102
    .line 103
    iget-object v2, p2, La8/w0;->g:La8/x0;

    .line 104
    .line 105
    iget-object v7, v2, La8/x0;->a:Lh8/b0;

    .line 106
    .line 107
    move-object v2, v0

    .line 108
    move-object v0, p1

    .line 109
    invoke-virtual/range {v0 .. v7}, La8/f;->z([Lt7/o;Lh8/y0;JJLh8/b0;)V

    .line 110
    .line 111
    .line 112
    return v8

    .line 113
    :cond_7
    invoke-virtual {p1}, La8/f;->m()Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_a

    .line 118
    .line 119
    invoke-virtual {p0, p1, p4}, La8/p1;->a(La8/f;La8/l;)V

    .line 120
    .line 121
    .line 122
    if-eqz v9, :cond_8

    .line 123
    .line 124
    invoke-virtual {p0}, La8/p1;->f()Z

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    if-eqz v2, :cond_b

    .line 129
    .line 130
    :cond_8
    if-ne p1, v4, :cond_9

    .line 131
    .line 132
    move v10, v6

    .line 133
    :cond_9
    invoke-virtual {p0, v10}, La8/p1;->i(Z)V

    .line 134
    .line 135
    .line 136
    return v6

    .line 137
    :cond_a
    return v10

    .line 138
    :cond_b
    :goto_3
    return v6
.end method

.method public k()V
    .locals 1

    .line 1
    iget-object v0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La8/f;

    .line 4
    .line 5
    invoke-static {v0}, La8/p1;->h(La8/f;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    invoke-virtual {p0, v0}, La8/p1;->i(Z)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, La8/f;

    .line 18
    .line 19
    if-eqz v0, :cond_2

    .line 20
    .line 21
    iget v0, v0, La8/f;->k:I

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    const/4 v0, 0x0

    .line 27
    invoke-virtual {p0, v0}, La8/p1;->i(Z)V

    .line 28
    .line 29
    .line 30
    :cond_2
    return-void
.end method

.method public m()V
    .locals 7

    .line 1
    iget-object v0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La8/f;

    .line 4
    .line 5
    iget v1, v0, La8/f;->k:I

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x1

    .line 10
    if-ne v1, v4, :cond_1

    .line 11
    .line 12
    iget v5, p0, La8/p1;->d:I

    .line 13
    .line 14
    const/4 v6, 0x4

    .line 15
    if-eq v5, v6, :cond_1

    .line 16
    .line 17
    if-ne v1, v4, :cond_0

    .line 18
    .line 19
    move v3, v4

    .line 20
    :cond_0
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 21
    .line 22
    .line 23
    iput v2, v0, La8/f;->k:I

    .line 24
    .line 25
    invoke-virtual {v0}, La8/f;->u()V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    iget-object v0, p0, La8/p1;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v0, La8/f;

    .line 32
    .line 33
    if-eqz v0, :cond_3

    .line 34
    .line 35
    iget v1, v0, La8/f;->k:I

    .line 36
    .line 37
    if-ne v1, v4, :cond_3

    .line 38
    .line 39
    iget p0, p0, La8/p1;->d:I

    .line 40
    .line 41
    const/4 v5, 0x3

    .line 42
    if-eq p0, v5, :cond_3

    .line 43
    .line 44
    if-ne v1, v4, :cond_2

    .line 45
    .line 46
    move v3, v4

    .line 47
    :cond_2
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 48
    .line 49
    .line 50
    iput v2, v0, La8/f;->k:I

    .line 51
    .line 52
    invoke-virtual {v0}, La8/f;->u()V

    .line 53
    .line 54
    .line 55
    :cond_3
    return-void
.end method
