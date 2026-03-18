.class public abstract Lkp/h8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lu01/k;Lu01/y;)V
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Lu01/k;->j(Lu01/y;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, p1, v0}, Lu01/k;->E(Lu01/y;Z)Lu01/f0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    :try_start_0
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    :catch_0
    return-void

    .line 16
    :catch_1
    move-exception p0

    .line 17
    throw p0

    .line 18
    :cond_0
    return-void
.end method

.method public static final b(Lu01/k;Lu01/y;)V
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Lu01/k;->k(Lu01/y;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p1
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_1

    .line 5
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const/4 v0, 0x0

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lu01/y;

    .line 21
    .line 22
    :try_start_1
    invoke-virtual {p0, v1}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    iget-boolean v2, v2, Li5/f;->c:Z

    .line 27
    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    invoke-static {p0, v1}, Lkp/h8;->b(Lu01/k;Lu01/y;)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :catch_0
    move-exception v1

    .line 35
    goto :goto_2

    .line 36
    :cond_1
    :goto_1
    invoke-virtual {p0, v1}, Lu01/k;->g(Lu01/y;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :goto_2
    if-nez v0, :cond_0

    .line 41
    .line 42
    move-object v0, v1

    .line 43
    goto :goto_0

    .line 44
    :cond_2
    if-nez v0, :cond_3

    .line 45
    .line 46
    return-void

    .line 47
    :cond_3
    throw v0

    .line 48
    :catch_1
    return-void
.end method

.method public static final c(Ll2/o;)Lqw/a;
    .locals 7

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, -0x2c187e7a

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->Z(I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v4}, Lhw/c;->a(Ll2/o;)Lhw/b;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget-wide v0, p0, Lhw/b;->d:J

    .line 15
    .line 16
    invoke-static {v0, v1}, Llp/d1;->c(J)Lpw/d;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object p0, Ltw/g;->d:Ltw/g;

    .line 21
    .line 22
    new-instance v2, Ltw/h;

    .line 23
    .line 24
    invoke-direct {v2, p0}, Ltw/h;-><init>(Ltw/g;)V

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    int-to-float v3, p0

    .line 29
    const/4 v5, 0x0

    .line 30
    const/4 v6, 0x0

    .line 31
    const/high16 v1, 0x3f800000    # 1.0f

    .line 32
    .line 33
    invoke-static/range {v0 .. v6}, Llp/fb;->b(Lpw/d;FLtw/l;FLl2/o;II)Lqw/a;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {v4, p0}, Ll2/t;->q(Z)V

    .line 38
    .line 39
    .line 40
    return-object v0
.end method

.method public static final d(Ll2/o;)Lqw/a;
    .locals 7

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, -0x26c22876

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->Z(I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v4}, Lhw/c;->a(Ll2/o;)Lhw/b;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget-wide v0, p0, Lhw/b;->d:J

    .line 15
    .line 16
    invoke-static {v0, v1}, Llp/d1;->c(J)Lpw/d;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v2, Ltw/k;->a:Lt0/c;

    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    int-to-float v3, p0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    const/high16 v1, 0x3f800000    # 1.0f

    .line 27
    .line 28
    invoke-static/range {v0 .. v6}, Llp/fb;->b(Lpw/d;FLtw/l;FLl2/o;II)Lqw/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v4, p0}, Ll2/t;->q(Z)V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method

.method public static final e(Ll2/o;)Lqw/a;
    .locals 7

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, -0x4480adbf

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->Z(I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v4}, Lhw/c;->a(Ll2/o;)Lhw/b;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget-wide v0, p0, Lhw/b;->d:J

    .line 15
    .line 16
    invoke-static {v0, v1}, Llp/d1;->c(J)Lpw/d;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v2, Ltw/k;->a:Lt0/c;

    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    int-to-float v3, p0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    const/high16 v1, 0x3f800000    # 1.0f

    .line 27
    .line 28
    invoke-static/range {v0 .. v6}, Llp/fb;->b(Lpw/d;FLtw/l;FLl2/o;II)Lqw/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v4, p0}, Ll2/t;->q(Z)V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method
