.class public abstract Llp/td;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Luw/b;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Luw/b;->f:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, " ("

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Luw/b;->b()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const/16 p0, 0x29

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public static final b(Ll2/o;)Lkn/c0;
    .locals 7

    .line 1
    move-object v3, p0

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p0, 0x19af6556

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p0}, Ll2/t;->Z(I)V

    .line 8
    .line 9
    .line 10
    sget-object p0, Lkn/f0;->f:Lkn/f0;

    .line 11
    .line 12
    sget-object v0, Lkn/u;->h:Lkn/u;

    .line 13
    .line 14
    invoke-static {v0, v3}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v6, 0x0

    .line 19
    new-array v1, v6, [Ljava/lang/Object;

    .line 20
    .line 21
    invoke-static {v1, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    sget-object v2, Lkn/d0;->g:Lkn/d0;

    .line 26
    .line 27
    sget-object v4, Lkn/u;->i:Lkn/u;

    .line 28
    .line 29
    move-object v5, v0

    .line 30
    move-object v0, v1

    .line 31
    new-instance v1, Lu2/l;

    .line 32
    .line 33
    invoke-direct {v1, v2, v4}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 34
    .line 35
    .line 36
    const v2, -0x5e64fbe

    .line 37
    .line 38
    .line 39
    invoke-virtual {v3, v2}, Ll2/t;->Z(I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-virtual {v3, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    or-int/2addr p0, v2

    .line 51
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    if-nez p0, :cond_0

    .line 56
    .line 57
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 58
    .line 59
    if-ne v2, p0, :cond_1

    .line 60
    .line 61
    :cond_0
    new-instance v2, Lkn/e0;

    .line 62
    .line 63
    const/4 p0, 0x0

    .line 64
    invoke-direct {v2, v5, p0}, Lkn/e0;-><init>(Ll2/b1;I)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v3, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_1
    check-cast v2, Lay0/a;

    .line 71
    .line 72
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 73
    .line 74
    .line 75
    const/16 v4, 0x48

    .line 76
    .line 77
    const/4 v5, 0x4

    .line 78
    invoke-static/range {v0 .. v5}, Lu2/m;->e([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;II)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lkn/c0;

    .line 83
    .line 84
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 85
    .line 86
    .line 87
    return-object p0
.end method
