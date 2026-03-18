.class public final Lbn/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbn/f;
.implements Li8/a;


# instance fields
.field public d:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    .line 6
    .line 7
    new-instance p1, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    new-instance p1, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance p1, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public a(J)Lhr/h0;
    .locals 4

    .line 1
    invoke-virtual {p0, p1, p2}, Lbn/c;->j(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lhr/h0;->e:Lhr/f0;

    .line 8
    .line 9
    sget-object p0, Lhr/x0;->h:Lhr/x0;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 13
    .line 14
    add-int/lit8 v0, v0, -0x1

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Ll9/a;

    .line 21
    .line 22
    iget-wide v0, p0, Ll9/a;->d:J

    .line 23
    .line 24
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    cmp-long v2, v0, v2

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    cmp-long p1, p1, v0

    .line 34
    .line 35
    if-gez p1, :cond_1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    sget-object p0, Lhr/h0;->e:Lhr/f0;

    .line 39
    .line 40
    sget-object p0, Lhr/x0;->h:Lhr/x0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_2
    :goto_0
    iget-object p0, p0, Ll9/a;->a:Lhr/h0;

    .line 44
    .line 45
    return-object p0
.end method

.method public b(J)J
    .locals 7

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    if-nez v0, :cond_7

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Ll9/a;

    .line 20
    .line 21
    iget-wide v3, v0, Ll9/a;->b:J

    .line 22
    .line 23
    cmp-long v0, p1, v3

    .line 24
    .line 25
    if-gez v0, :cond_0

    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_0
    const/4 v0, 0x1

    .line 29
    move v3, v0

    .line 30
    :goto_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-ge v3, v4, :cond_4

    .line 35
    .line 36
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    check-cast v4, Ll9/a;

    .line 41
    .line 42
    iget-wide v4, v4, Ll9/a;->b:J

    .line 43
    .line 44
    cmp-long v6, p1, v4

    .line 45
    .line 46
    if-nez v6, :cond_1

    .line 47
    .line 48
    return-wide v4

    .line 49
    :cond_1
    if-gez v6, :cond_3

    .line 50
    .line 51
    sub-int/2addr v3, v0

    .line 52
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Ll9/a;

    .line 57
    .line 58
    iget-wide v3, p0, Ll9/a;->d:J

    .line 59
    .line 60
    cmp-long v0, v3, v1

    .line 61
    .line 62
    if-eqz v0, :cond_2

    .line 63
    .line 64
    cmp-long p1, v3, p1

    .line 65
    .line 66
    if-gtz p1, :cond_2

    .line 67
    .line 68
    return-wide v3

    .line 69
    :cond_2
    iget-wide p0, p0, Ll9/a;->b:J

    .line 70
    .line 71
    return-wide p0

    .line 72
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_4
    invoke-static {p0}, Lhr/q;->h(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ll9/a;

    .line 80
    .line 81
    iget-wide v3, p0, Ll9/a;->d:J

    .line 82
    .line 83
    cmp-long v0, v3, v1

    .line 84
    .line 85
    if-eqz v0, :cond_6

    .line 86
    .line 87
    cmp-long p1, p1, v3

    .line 88
    .line 89
    if-gez p1, :cond_5

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_5
    return-wide v3

    .line 93
    :cond_6
    :goto_1
    iget-wide p0, p0, Ll9/a;->b:J

    .line 94
    .line 95
    return-wide p0

    .line 96
    :cond_7
    :goto_2
    return-wide v1
.end method

.method public c(Ll9/a;J)Z
    .locals 9

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-wide v0, p1, Ll9/a;->b:J

    .line 4
    .line 5
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    cmp-long v4, v0, v2

    .line 11
    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v6, 0x1

    .line 14
    if-eqz v4, :cond_0

    .line 15
    .line 16
    move v4, v6

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v4, v5

    .line 19
    :goto_0
    invoke-static {v4}, Lw7/a;->c(Z)V

    .line 20
    .line 21
    .line 22
    cmp-long v4, v0, p2

    .line 23
    .line 24
    if-gtz v4, :cond_2

    .line 25
    .line 26
    iget-wide v7, p1, Ll9/a;->d:J

    .line 27
    .line 28
    cmp-long v2, v7, v2

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    cmp-long v2, p2, v7

    .line 33
    .line 34
    if-gez v2, :cond_2

    .line 35
    .line 36
    :cond_1
    move v2, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_2
    move v2, v5

    .line 39
    :goto_1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    sub-int/2addr v3, v6

    .line 44
    :goto_2
    if-ltz v3, :cond_5

    .line 45
    .line 46
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Ll9/a;

    .line 51
    .line 52
    iget-wide v7, v4, Ll9/a;->b:J

    .line 53
    .line 54
    cmp-long v4, v0, v7

    .line 55
    .line 56
    if-ltz v4, :cond_3

    .line 57
    .line 58
    add-int/2addr v3, v6

    .line 59
    invoke-virtual {p0, v3, p1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return v2

    .line 63
    :cond_3
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    check-cast v4, Ll9/a;

    .line 68
    .line 69
    iget-wide v7, v4, Ll9/a;->b:J

    .line 70
    .line 71
    cmp-long v4, v7, p2

    .line 72
    .line 73
    if-gtz v4, :cond_4

    .line 74
    .line 75
    move v2, v5

    .line 76
    :cond_4
    add-int/lit8 v3, v3, -0x1

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_5
    invoke-virtual {p0, v5, p1}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    return v2
.end method

.method public clear()V
    .locals 0

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public d(J)J
    .locals 11

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const-wide/high16 v1, -0x8000000000000000L

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-wide v1

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    check-cast v3, Ll9/a;

    .line 18
    .line 19
    iget-wide v3, v3, Ll9/a;->b:J

    .line 20
    .line 21
    cmp-long v3, p1, v3

    .line 22
    .line 23
    if-gez v3, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ll9/a;

    .line 30
    .line 31
    iget-wide p0, p0, Ll9/a;->b:J

    .line 32
    .line 33
    return-wide p0

    .line 34
    :cond_1
    const/4 v0, 0x1

    .line 35
    move v3, v0

    .line 36
    :goto_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    if-ge v3, v4, :cond_4

    .line 46
    .line 47
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Ll9/a;

    .line 52
    .line 53
    iget-wide v7, v4, Ll9/a;->b:J

    .line 54
    .line 55
    iget-wide v9, v4, Ll9/a;->b:J

    .line 56
    .line 57
    cmp-long v4, p1, v7

    .line 58
    .line 59
    if-gez v4, :cond_3

    .line 60
    .line 61
    sub-int/2addr v3, v0

    .line 62
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ll9/a;

    .line 67
    .line 68
    iget-wide v0, p0, Ll9/a;->d:J

    .line 69
    .line 70
    cmp-long p0, v0, v5

    .line 71
    .line 72
    if-eqz p0, :cond_2

    .line 73
    .line 74
    cmp-long p0, v0, p1

    .line 75
    .line 76
    if-lez p0, :cond_2

    .line 77
    .line 78
    cmp-long p0, v0, v9

    .line 79
    .line 80
    if-gez p0, :cond_2

    .line 81
    .line 82
    return-wide v0

    .line 83
    :cond_2
    return-wide v9

    .line 84
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_4
    invoke-static {p0}, Lhr/q;->h(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    check-cast p0, Ll9/a;

    .line 92
    .line 93
    iget-wide v3, p0, Ll9/a;->d:J

    .line 94
    .line 95
    cmp-long p0, v3, v5

    .line 96
    .line 97
    if-eqz p0, :cond_5

    .line 98
    .line 99
    cmp-long p0, p1, v3

    .line 100
    .line 101
    if-gez p0, :cond_5

    .line 102
    .line 103
    return-wide v3

    .line 104
    :cond_5
    return-wide v1
.end method

.method public e(J)V
    .locals 5

    .line 1
    iget-object v0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lbn/c;->j(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    add-int/lit8 v1, p0, -0x1

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Ll9/a;

    .line 17
    .line 18
    iget-wide v1, v1, Ll9/a;->d:J

    .line 19
    .line 20
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    cmp-long v3, v1, v3

    .line 26
    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    cmp-long p1, v1, p1

    .line 30
    .line 31
    if-ltz p1, :cond_2

    .line 32
    .line 33
    :cond_1
    add-int/lit8 p0, p0, -0x1

    .line 34
    .line 35
    :cond_2
    const/4 p1, 0x0

    .line 36
    invoke-virtual {v0, p1, p0}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public f(Ljz0/k;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    instance-of v0, p1, Ljz0/n;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    instance-of v0, p1, Ljz0/f;

    .line 12
    .line 13
    if-eqz v0, :cond_2

    .line 14
    .line 15
    check-cast p1, Ljz0/f;

    .line 16
    .line 17
    iget-object p1, p1, Ljz0/f;->a:Ljava/util/List;

    .line 18
    .line 19
    check-cast p1, Ljava/lang/Iterable;

    .line 20
    .line 21
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Ljz0/n;

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    return-void

    .line 42
    :cond_2
    new-instance p0, La8/r0;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 45
    .line 46
    .line 47
    throw p0
.end method

.method public g(Ljava/util/List;)V
    .locals 8

    .line 1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 9
    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 18
    .line 19
    :cond_1
    iget-object v0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_2
    iget-object v0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    const/4 v1, 0x1

    .line 40
    sub-int/2addr v0, v1

    .line 41
    iget-object v2, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Lj11/w;

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    check-cast v3, Lj11/w;

    .line 55
    .line 56
    iget v4, v2, Lj11/w;->a:I

    .line 57
    .line 58
    iget v5, v3, Lj11/w;->a:I

    .line 59
    .line 60
    if-ne v4, v5, :cond_3

    .line 61
    .line 62
    iget v5, v2, Lj11/w;->b:I

    .line 63
    .line 64
    iget v2, v2, Lj11/w;->c:I

    .line 65
    .line 66
    add-int v6, v5, v2

    .line 67
    .line 68
    iget v7, v3, Lj11/w;->b:I

    .line 69
    .line 70
    if-ne v6, v7, :cond_3

    .line 71
    .line 72
    iget-object v6, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 73
    .line 74
    iget v3, v3, Lj11/w;->c:I

    .line 75
    .line 76
    add-int/2addr v2, v3

    .line 77
    new-instance v3, Lj11/w;

    .line 78
    .line 79
    invoke-direct {v3, v4, v5, v2}, Lj11/w;-><init>(III)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v6, v0, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 86
    .line 87
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    invoke-interface {p1, v1, v0}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :cond_3
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 102
    .line 103
    .line 104
    return-void
.end method

.method public h(Ljava/util/List;)V
    .locals 1

    .line 1
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lj11/s;

    .line 16
    .line 17
    invoke-virtual {v0}, Lj11/s;->d()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {p0, v0}, Lbn/c;->g(Ljava/util/List;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public i()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    :goto_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-ge v1, v2, :cond_1

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    const/16 v2, 0xa

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    :cond_0
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Lk11/b;

    .line 27
    .line 28
    iget-object v2, v2, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 29
    .line 30
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    add-int/lit8 v1, v1, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method

.method public isStatic()Z
    .locals 3

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-ne v0, v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lhn/a;

    .line 16
    .line 17
    invoke-virtual {p0}, Lhn/a;->c()Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    return v2

    .line 24
    :cond_0
    return v1
.end method

.method public j(J)I
    .locals 3

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    :goto_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-ge v0, v1, :cond_1

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    check-cast v1, Ll9/a;

    .line 15
    .line 16
    iget-wide v1, v1, Ll9/a;->b:J

    .line 17
    .line 18
    cmp-long v1, p1, v1

    .line 19
    .line 20
    if-gez v1, :cond_0

    .line 21
    .line 22
    return v0

    .line 23
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0
.end method

.method public k()Ljava/util/ArrayList;
    .locals 2

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Lk11/b;

    .line 23
    .line 24
    iget-object v1, v1, Lk11/b;->b:Lj11/w;

    .line 25
    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    return-object v0
.end method

.method public p()Lxm/e;
    .locals 2

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Lhn/a;

    .line 9
    .line 10
    invoke-virtual {v0}, Lhn/a;->c()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    new-instance v0, Lxm/h;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-direct {v0, p0, v1}, Lxm/h;-><init>(Ljava/util/List;I)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    new-instance v0, Lxm/k;

    .line 24
    .line 25
    invoke-direct {v0, p0}, Lxm/k;-><init>(Ljava/util/ArrayList;)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method

.method public q()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 2
    .line 3
    return-object p0
.end method
