.class public final Lr11/p;
.super Lr11/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    :try_start_0
    iget-object p0, p0, Lr11/h;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p0, p4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0, p2, p3}, Ln11/a;->b(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {p0, p1}, Lr11/u;->b(ILjava/lang/StringBuilder;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    const p0, 0xfffd

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lr11/h;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p2, p0}, Lo11/b;->g(Ln11/b;)Z

    .line 4
    .line 5
    .line 6
    move-result p3

    .line 7
    const v0, 0xfffd

    .line 8
    .line 9
    .line 10
    if-eqz p3, :cond_0

    .line 11
    .line 12
    :try_start_0
    invoke-virtual {p2, p0}, Lo11/b;->b(Ln11/b;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-static {p0, p1}, Lr11/u;->b(ILjava/lang/StringBuilder;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :catch_0
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final e()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/h;->e:I

    .line 2
    .line 3
    return p0
.end method
