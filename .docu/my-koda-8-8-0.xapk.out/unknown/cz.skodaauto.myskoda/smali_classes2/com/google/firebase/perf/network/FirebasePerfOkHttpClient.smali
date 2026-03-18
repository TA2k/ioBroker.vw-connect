.class public Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ld01/t0;Ltt/e;JJ)V
    .locals 5

    .line 1
    iget-object v0, p0, Ld01/t0;->d:Ld01/k0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v1, v0, Ld01/k0;->a:Ld01/a0;

    .line 7
    .line 8
    invoke-virtual {v1}, Ld01/a0;->k()Ljava/net/URL;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {p1, v1}, Ltt/e;->p(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v1, v0, Ld01/k0;->b:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {p1, v1}, Ltt/e;->i(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, v0, Ld01/k0;->d:Ld01/r0;

    .line 25
    .line 26
    const-wide/16 v1, -0x1

    .line 27
    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Ld01/r0;->contentLength()J

    .line 31
    .line 32
    .line 33
    move-result-wide v3

    .line 34
    cmp-long v0, v3, v1

    .line 35
    .line 36
    if-eqz v0, :cond_1

    .line 37
    .line 38
    invoke-virtual {p1, v3, v4}, Ltt/e;->k(J)V

    .line 39
    .line 40
    .line 41
    :cond_1
    iget-object v0, p0, Ld01/t0;->j:Ld01/v0;

    .line 42
    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    invoke-virtual {v0}, Ld01/v0;->b()J

    .line 46
    .line 47
    .line 48
    move-result-wide v3

    .line 49
    cmp-long v1, v3, v1

    .line 50
    .line 51
    if-eqz v1, :cond_2

    .line 52
    .line 53
    invoke-virtual {p1, v3, v4}, Ltt/e;->n(J)V

    .line 54
    .line 55
    .line 56
    :cond_2
    invoke-virtual {v0}, Ld01/v0;->d()Ld01/d0;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    if-eqz v0, :cond_3

    .line 61
    .line 62
    iget-object v0, v0, Ld01/d0;->a:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {p1, v0}, Ltt/e;->m(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_3
    iget p0, p0, Ld01/t0;->g:I

    .line 68
    .line 69
    invoke-virtual {p1, p0}, Ltt/e;->j(I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p1, p2, p3}, Ltt/e;->l(J)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, p4, p5}, Ltt/e;->o(J)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1}, Ltt/e;->h()V

    .line 79
    .line 80
    .line 81
    return-void
.end method

.method public static enqueue(Ld01/j;Ld01/k;)V
    .locals 6
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    new-instance v3, Lzt/h;

    .line 2
    .line 3
    invoke-direct {v3}, Lzt/h;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-wide v4, v3, Lzt/h;->d:J

    .line 7
    .line 8
    new-instance v0, Lh01/q;

    .line 9
    .line 10
    sget-object v2, Lyt/h;->v:Lyt/h;

    .line 11
    .line 12
    move-object v1, p1

    .line 13
    invoke-direct/range {v0 .. v5}, Lh01/q;-><init>(Ld01/k;Lyt/h;Lzt/h;J)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0, v0}, Ld01/j;->enqueue(Ld01/k;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public static execute(Ld01/j;)Ld01/t0;
    .locals 9
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .line 1
    sget-object v0, Lyt/h;->v:Lyt/h;

    .line 2
    .line 3
    new-instance v2, Ltt/e;

    .line 4
    .line 5
    invoke-direct {v2, v0}, Ltt/e;-><init>(Lyt/h;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Lzt/h;->m()J

    .line 9
    .line 10
    .line 11
    move-result-wide v3

    .line 12
    invoke-static {}, Lzt/h;->h()J

    .line 13
    .line 14
    .line 15
    move-result-wide v7

    .line 16
    :try_start_0
    invoke-interface {p0}, Ld01/j;->execute()Ld01/t0;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-static {}, Lzt/h;->m()J

    .line 21
    .line 22
    .line 23
    invoke-static {}, Lzt/h;->h()J

    .line 24
    .line 25
    .line 26
    move-result-wide v5

    .line 27
    sub-long/2addr v5, v7

    .line 28
    invoke-static/range {v1 .. v6}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->a(Ld01/t0;Ltt/e;JJ)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    .line 30
    .line 31
    return-object v1

    .line 32
    :catch_0
    move-exception v0

    .line 33
    invoke-interface {p0}, Ld01/j;->request()Ld01/k0;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    if-eqz p0, :cond_1

    .line 38
    .line 39
    iget-object v1, p0, Ld01/k0;->a:Ld01/a0;

    .line 40
    .line 41
    if-eqz v1, :cond_0

    .line 42
    .line 43
    invoke-virtual {v1}, Ld01/a0;->k()Ljava/net/URL;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v2, v1}, Ltt/e;->p(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_0
    iget-object p0, p0, Ld01/k0;->b:Ljava/lang/String;

    .line 55
    .line 56
    if-eqz p0, :cond_1

    .line 57
    .line 58
    invoke-virtual {v2, p0}, Ltt/e;->i(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    :cond_1
    invoke-virtual {v2, v3, v4}, Ltt/e;->l(J)V

    .line 62
    .line 63
    .line 64
    invoke-static {}, Lzt/h;->m()J

    .line 65
    .line 66
    .line 67
    invoke-static {}, Lzt/h;->h()J

    .line 68
    .line 69
    .line 70
    move-result-wide v3

    .line 71
    sub-long/2addr v3, v7

    .line 72
    invoke-virtual {v2, v3, v4}, Ltt/e;->o(J)V

    .line 73
    .line 74
    .line 75
    invoke-static {v2}, Lvt/g;->c(Ltt/e;)V

    .line 76
    .line 77
    .line 78
    throw v0
.end method
