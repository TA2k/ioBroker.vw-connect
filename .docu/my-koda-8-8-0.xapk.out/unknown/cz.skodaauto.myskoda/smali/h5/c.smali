.class public final Lh5/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/util/HashSet;

.field public b:I

.field public c:Z

.field public final d:Lh5/d;

.field public final e:I

.field public f:Lh5/c;

.field public g:I

.field public h:I

.field public i:La5/h;


# direct methods
.method public constructor <init>(Lh5/d;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lh5/c;->a:Ljava/util/HashSet;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    iput v0, p0, Lh5/c;->g:I

    .line 9
    .line 10
    const/high16 v0, -0x80000000

    .line 11
    .line 12
    iput v0, p0, Lh5/c;->h:I

    .line 13
    .line 14
    iput-object p1, p0, Lh5/c;->d:Lh5/d;

    .line 15
    .line 16
    iput p2, p0, Lh5/c;->e:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Lh5/c;I)V
    .locals 2

    .line 1
    const/high16 v0, -0x80000000

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, p1, p2, v0, v1}, Lh5/c;->b(Lh5/c;IIZ)Z

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final b(Lh5/c;IIZ)Z
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 5
    .line 6
    .line 7
    return v0

    .line 8
    :cond_0
    if-nez p4, :cond_1

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lh5/c;->i(Lh5/c;)Z

    .line 11
    .line 12
    .line 13
    move-result p4

    .line 14
    if-nez p4, :cond_1

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    return p0

    .line 18
    :cond_1
    iput-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 19
    .line 20
    iget-object p4, p1, Lh5/c;->a:Ljava/util/HashSet;

    .line 21
    .line 22
    if-nez p4, :cond_2

    .line 23
    .line 24
    new-instance p4, Ljava/util/HashSet;

    .line 25
    .line 26
    invoke-direct {p4}, Ljava/util/HashSet;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p4, p1, Lh5/c;->a:Ljava/util/HashSet;

    .line 30
    .line 31
    :cond_2
    iget-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 32
    .line 33
    iget-object p1, p1, Lh5/c;->a:Ljava/util/HashSet;

    .line 34
    .line 35
    if-eqz p1, :cond_3

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    :cond_3
    iput p2, p0, Lh5/c;->g:I

    .line 41
    .line 42
    iput p3, p0, Lh5/c;->h:I

    .line 43
    .line 44
    return v0
.end method

.method public final c(ILi5/o;Ljava/util/ArrayList;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh5/c;->a:Ljava/util/HashSet;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lh5/c;

    .line 20
    .line 21
    iget-object v0, v0, Lh5/c;->d:Lh5/d;

    .line 22
    .line 23
    invoke-static {v0, p1, p3, p2}, Li5/i;->b(Lh5/d;ILjava/util/ArrayList;Li5/o;)Li5/o;

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-void
.end method

.method public final d()I
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh5/c;->c:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget p0, p0, Lh5/c;->b:I

    .line 8
    .line 9
    return p0
.end method

.method public final e()I
    .locals 3

    .line 1
    iget-object v0, p0, Lh5/c;->d:Lh5/d;

    .line 2
    .line 3
    iget v0, v0, Lh5/d;->h0:I

    .line 4
    .line 5
    const/16 v1, 0x8

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    iget v0, p0, Lh5/c;->h:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    if-eq v0, v2, :cond_1

    .line 16
    .line 17
    iget-object v2, p0, Lh5/c;->f:Lh5/c;

    .line 18
    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    iget-object v2, v2, Lh5/c;->d:Lh5/d;

    .line 22
    .line 23
    iget v2, v2, Lh5/d;->h0:I

    .line 24
    .line 25
    if-ne v2, v1, :cond_1

    .line 26
    .line 27
    return v0

    .line 28
    :cond_1
    iget p0, p0, Lh5/c;->g:I

    .line 29
    .line 30
    return p0
.end method

.method public final f()Lh5/c;
    .locals 2

    .line 1
    iget v0, p0, Lh5/c;->e:I

    .line 2
    .line 3
    invoke-static {v0}, Lu/w;->o(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object p0, p0, Lh5/c;->d:Lh5/d;

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance p0, Ljava/lang/AssertionError;

    .line 13
    .line 14
    invoke-static {v0}, Lf2/m0;->y(I)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-direct {p0, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Lh5/d;->K:Lh5/c;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_1
    iget-object p0, p0, Lh5/d;->J:Lh5/c;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_2
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_3
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_4
    const/4 p0, 0x0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
    .end packed-switch
.end method

.method public final g()Z
    .locals 2

    .line 1
    iget-object p0, p0, Lh5/c;->a:Ljava/util/HashSet;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-nez p0, :cond_0

    .line 5
    .line 6
    return v0

    .line 7
    :cond_0
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_2

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lh5/c;

    .line 22
    .line 23
    invoke-virtual {v1}, Lh5/c;->f()Lh5/c;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-virtual {v1}, Lh5/c;->h()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_1

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_2
    return v0
.end method

.method public final h()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh5/c;->f:Lh5/c;

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

.method public final i(Lh5/c;)Z
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto/16 :goto_5

    .line 5
    .line 6
    :cond_0
    iget-object v1, p1, Lh5/c;->d:Lh5/d;

    .line 7
    .line 8
    iget p1, p1, Lh5/c;->e:I

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    iget v3, p0, Lh5/c;->e:I

    .line 12
    .line 13
    const/4 v4, 0x1

    .line 14
    if-ne p1, v3, :cond_1

    .line 15
    .line 16
    if-ne v3, v2, :cond_7

    .line 17
    .line 18
    iget-boolean p1, v1, Lh5/d;->F:Z

    .line 19
    .line 20
    if-eqz p1, :cond_9

    .line 21
    .line 22
    iget-object p0, p0, Lh5/c;->d:Lh5/d;

    .line 23
    .line 24
    iget-boolean p0, p0, Lh5/d;->F:Z

    .line 25
    .line 26
    if-nez p0, :cond_7

    .line 27
    .line 28
    goto :goto_5

    .line 29
    :cond_1
    invoke-static {v3}, Lu/w;->o(I)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    const/4 v5, 0x4

    .line 34
    const/4 v6, 0x2

    .line 35
    const/16 v7, 0x9

    .line 36
    .line 37
    const/16 v8, 0x8

    .line 38
    .line 39
    packed-switch p0, :pswitch_data_0

    .line 40
    .line 41
    .line 42
    new-instance p0, Ljava/lang/AssertionError;

    .line 43
    .line 44
    invoke-static {v3}, Lf2/m0;->y(I)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :pswitch_0
    if-eq p1, v2, :cond_9

    .line 53
    .line 54
    if-eq p1, v8, :cond_9

    .line 55
    .line 56
    if-eq p1, v7, :cond_9

    .line 57
    .line 58
    goto :goto_4

    .line 59
    :pswitch_1
    if-eq p1, v6, :cond_9

    .line 60
    .line 61
    if-ne p1, v5, :cond_7

    .line 62
    .line 63
    goto :goto_5

    .line 64
    :pswitch_2
    const/4 p0, 0x3

    .line 65
    if-eq p1, p0, :cond_3

    .line 66
    .line 67
    const/4 p0, 0x5

    .line 68
    if-ne p1, p0, :cond_2

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_2
    move p0, v0

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    :goto_0
    move p0, v4

    .line 74
    :goto_1
    instance-of v1, v1, Lh5/h;

    .line 75
    .line 76
    if-eqz v1, :cond_4

    .line 77
    .line 78
    if-nez p0, :cond_7

    .line 79
    .line 80
    if-ne p1, v7, :cond_9

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_4
    return p0

    .line 84
    :pswitch_3
    if-eq p1, v6, :cond_6

    .line 85
    .line 86
    if-ne p1, v5, :cond_5

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_5
    move p0, v0

    .line 90
    goto :goto_3

    .line 91
    :cond_6
    :goto_2
    move p0, v4

    .line 92
    :goto_3
    instance-of v1, v1, Lh5/h;

    .line 93
    .line 94
    if-eqz v1, :cond_8

    .line 95
    .line 96
    if-nez p0, :cond_7

    .line 97
    .line 98
    if-ne p1, v8, :cond_9

    .line 99
    .line 100
    :cond_7
    :goto_4
    return v4

    .line 101
    :cond_8
    return p0

    .line 102
    :cond_9
    :goto_5
    :pswitch_4
    return v0

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_4
        :pswitch_4
    .end packed-switch
.end method

.method public final j()V
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, v0, Lh5/c;->a:Ljava/util/HashSet;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 14
    .line 15
    iget-object v0, v0, Lh5/c;->a:Ljava/util/HashSet;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 24
    .line 25
    iput-object v1, v0, Lh5/c;->a:Ljava/util/HashSet;

    .line 26
    .line 27
    :cond_0
    iput-object v1, p0, Lh5/c;->a:Ljava/util/HashSet;

    .line 28
    .line 29
    iput-object v1, p0, Lh5/c;->f:Lh5/c;

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    iput v0, p0, Lh5/c;->g:I

    .line 33
    .line 34
    const/high16 v1, -0x80000000

    .line 35
    .line 36
    iput v1, p0, Lh5/c;->h:I

    .line 37
    .line 38
    iput-boolean v0, p0, Lh5/c;->c:Z

    .line 39
    .line 40
    iput v0, p0, Lh5/c;->b:I

    .line 41
    .line 42
    return-void
.end method

.method public final k()V
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/c;->i:La5/h;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, La5/h;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, v1}, La5/h;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lh5/c;->i:La5/h;

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    invoke-virtual {v0}, La5/h;->c()V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final l(I)V
    .locals 0

    .line 1
    iput p1, p0, Lh5/c;->b:I

    .line 2
    .line 3
    const/4 p1, 0x1

    .line 4
    iput-boolean p1, p0, Lh5/c;->c:Z

    .line 5
    .line 6
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lh5/c;->d:Lh5/d;

    .line 7
    .line 8
    iget-object v1, v1, Lh5/d;->i0:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ":"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget p0, p0, Lh5/c;->e:I

    .line 19
    .line 20
    invoke-static {p0}, Lf2/m0;->y(I)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
