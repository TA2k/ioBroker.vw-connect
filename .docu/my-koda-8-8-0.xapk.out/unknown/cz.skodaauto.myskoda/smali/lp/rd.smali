.class public abstract Llp/rd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ll2/o;I)Lkn/j0;
    .locals 10

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const p1, -0x20ca9d11

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ll2/t;->Z(I)V

    .line 7
    .line 8
    .line 9
    sget-object v2, Lx4/x;->d:Lx4/x;

    .line 10
    .line 11
    const p1, -0x53408f76

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ll2/t;->Z(I)V

    .line 15
    .line 16
    .line 17
    sget-object p1, Lw3/h1;->h:Ll2/u2;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    check-cast p1, Lt4/c;

    .line 24
    .line 25
    sget-object p1, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 26
    .line 27
    invoke-static {p0}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iget-object p1, p1, Lk1/r1;->e:Lk1/b;

    .line 32
    .line 33
    invoke-virtual {p1}, Lk1/b;->e()Ls5/b;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iget p1, p1, Ls5/b;->d:I

    .line 38
    .line 39
    const/4 v9, 0x0

    .line 40
    if-nez p1, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    sget-object p1, Lf2/h;->a:Ll2/u2;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    check-cast p1, Lf2/g;

    .line 50
    .line 51
    invoke-virtual {p1}, Lf2/g;->d()Z

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    if-eqz p1, :cond_1

    .line 56
    .line 57
    const/4 p1, 0x1

    .line 58
    move v4, p1

    .line 59
    goto :goto_1

    .line 60
    :cond_1
    :goto_0
    move v4, v9

    .line 61
    :goto_1
    invoke-virtual {p0, v9}, Ll2/t;->q(Z)V

    .line 62
    .line 63
    .line 64
    sget-wide v5, Le3/s;->h:J

    .line 65
    .line 66
    if-eqz v4, :cond_2

    .line 67
    .line 68
    move-wide v7, v5

    .line 69
    goto :goto_2

    .line 70
    :cond_2
    sget-wide v0, Le3/s;->b:J

    .line 71
    .line 72
    move-wide v7, v0

    .line 73
    :goto_2
    new-instance v0, Lkn/j0;

    .line 74
    .line 75
    const/4 v1, 0x1

    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-direct/range {v0 .. v8}, Lkn/j0;-><init>(ZLx4/x;IZJJ)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0, v9}, Ll2/t;->q(Z)V

    .line 81
    .line 82
    .line 83
    return-object v0
.end method

.method public static b(Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {p0}, Llp/rd;->c(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 9
    .line 10
    const-string v1, "Key \'"

    .line 11
    .line 12
    const-string v2, "\' is reserved for Keychain implementation."

    .line 13
    .line 14
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw v0
.end method

.method public static c(Ljava/lang/String;)Z
    .locals 1

    .line 1
    const-string v0, "com.wultra.PowerAuthKeychain.IsEncrypted"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const-string v0, "com.wultra.PowerAuthKeychain.EncryptionMode"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method
