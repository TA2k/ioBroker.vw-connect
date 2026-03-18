.class public final Li5/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Li5/p;

.field public b:Ljava/util/ArrayList;


# direct methods
.method public static a(Li5/g;J)J
    .locals 9

    .line 1
    iget-object v0, p0, Li5/g;->d:Li5/p;

    .line 2
    .line 3
    iget-object v1, p0, Li5/g;->k:Ljava/util/ArrayList;

    .line 4
    .line 5
    instance-of v2, v0, Li5/k;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    return-wide p1

    .line 10
    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/4 v3, 0x0

    .line 15
    move-wide v4, p1

    .line 16
    :goto_0
    if-ge v3, v2, :cond_3

    .line 17
    .line 18
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    check-cast v6, Li5/e;

    .line 23
    .line 24
    instance-of v7, v6, Li5/g;

    .line 25
    .line 26
    if-eqz v7, :cond_2

    .line 27
    .line 28
    check-cast v6, Li5/g;

    .line 29
    .line 30
    iget-object v7, v6, Li5/g;->d:Li5/p;

    .line 31
    .line 32
    if-ne v7, v0, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget v7, v6, Li5/g;->f:I

    .line 36
    .line 37
    int-to-long v7, v7

    .line 38
    add-long/2addr v7, p1

    .line 39
    invoke-static {v6, v7, v8}, Li5/m;->a(Li5/g;J)J

    .line 40
    .line 41
    .line 42
    move-result-wide v6

    .line 43
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 44
    .line 45
    .line 46
    move-result-wide v4

    .line 47
    :cond_2
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_3
    iget-object v1, v0, Li5/p;->i:Li5/g;

    .line 51
    .line 52
    iget-object v2, v0, Li5/p;->h:Li5/g;

    .line 53
    .line 54
    if-ne p0, v1, :cond_4

    .line 55
    .line 56
    invoke-virtual {v0}, Li5/p;->j()J

    .line 57
    .line 58
    .line 59
    move-result-wide v0

    .line 60
    sub-long/2addr p1, v0

    .line 61
    invoke-static {v2, p1, p2}, Li5/m;->a(Li5/g;J)J

    .line 62
    .line 63
    .line 64
    move-result-wide v0

    .line 65
    invoke-static {v4, v5, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    iget p0, v2, Li5/g;->f:I

    .line 70
    .line 71
    int-to-long v2, p0

    .line 72
    sub-long/2addr p1, v2

    .line 73
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->min(JJ)J

    .line 74
    .line 75
    .line 76
    move-result-wide p0

    .line 77
    return-wide p0

    .line 78
    :cond_4
    return-wide v4
.end method

.method public static b(Li5/g;J)J
    .locals 9

    .line 1
    iget-object v0, p0, Li5/g;->d:Li5/p;

    .line 2
    .line 3
    iget-object v1, p0, Li5/g;->k:Ljava/util/ArrayList;

    .line 4
    .line 5
    instance-of v2, v0, Li5/k;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    return-wide p1

    .line 10
    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/4 v3, 0x0

    .line 15
    move-wide v4, p1

    .line 16
    :goto_0
    if-ge v3, v2, :cond_3

    .line 17
    .line 18
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    check-cast v6, Li5/e;

    .line 23
    .line 24
    instance-of v7, v6, Li5/g;

    .line 25
    .line 26
    if-eqz v7, :cond_2

    .line 27
    .line 28
    check-cast v6, Li5/g;

    .line 29
    .line 30
    iget-object v7, v6, Li5/g;->d:Li5/p;

    .line 31
    .line 32
    if-ne v7, v0, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget v7, v6, Li5/g;->f:I

    .line 36
    .line 37
    int-to-long v7, v7

    .line 38
    add-long/2addr v7, p1

    .line 39
    invoke-static {v6, v7, v8}, Li5/m;->b(Li5/g;J)J

    .line 40
    .line 41
    .line 42
    move-result-wide v6

    .line 43
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->max(JJ)J

    .line 44
    .line 45
    .line 46
    move-result-wide v4

    .line 47
    :cond_2
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_3
    iget-object v1, v0, Li5/p;->h:Li5/g;

    .line 51
    .line 52
    iget-object v2, v0, Li5/p;->i:Li5/g;

    .line 53
    .line 54
    if-ne p0, v1, :cond_4

    .line 55
    .line 56
    invoke-virtual {v0}, Li5/p;->j()J

    .line 57
    .line 58
    .line 59
    move-result-wide v0

    .line 60
    add-long/2addr v0, p1

    .line 61
    invoke-static {v2, v0, v1}, Li5/m;->b(Li5/g;J)J

    .line 62
    .line 63
    .line 64
    move-result-wide p0

    .line 65
    invoke-static {v4, v5, p0, p1}, Ljava/lang/Math;->max(JJ)J

    .line 66
    .line 67
    .line 68
    move-result-wide p0

    .line 69
    iget p2, v2, Li5/g;->f:I

    .line 70
    .line 71
    int-to-long v2, p2

    .line 72
    sub-long/2addr v0, v2

    .line 73
    invoke-static {p0, p1, v0, v1}, Ljava/lang/Math;->max(JJ)J

    .line 74
    .line 75
    .line 76
    move-result-wide p0

    .line 77
    return-wide p0

    .line 78
    :cond_4
    return-wide v4
.end method
