.class public abstract Lc00/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final synthetic b:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const/16 v0, 0x12c

    .line 4
    .line 5
    sget-object v1, Lmy0/e;->g:Lmy0/e;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    sput-wide v0, Lc00/z1;->a:J

    .line 12
    .line 13
    return-void
.end method

.method public static final a(Lc00/x1;Lc00/v1;Lc00/w1;)I
    .locals 1

    .line 1
    iget-object p0, p0, Lc00/x1;->e:Lc00/w1;

    .line 2
    .line 3
    const-string v0, "seatState"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-eqz p1, :cond_4

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    if-eq p1, v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-ne p1, v0, :cond_1

    .line 19
    .line 20
    if-ne p0, p2, :cond_0

    .line 21
    .line 22
    const p0, 0x7f0805cb

    .line 23
    .line 24
    .line 25
    return p0

    .line 26
    :cond_0
    const p0, 0x7f0805d0

    .line 27
    .line 28
    .line 29
    return p0

    .line 30
    :cond_1
    new-instance p0, La8/r0;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_2
    if-ne p0, p2, :cond_3

    .line 37
    .line 38
    const p0, 0x7f0805cc

    .line 39
    .line 40
    .line 41
    return p0

    .line 42
    :cond_3
    const p0, 0x7f0805d1

    .line 43
    .line 44
    .line 45
    return p0

    .line 46
    :cond_4
    if-ne p0, p2, :cond_5

    .line 47
    .line 48
    const p0, 0x7f0805ca

    .line 49
    .line 50
    .line 51
    return p0

    .line 52
    :cond_5
    const p0, 0x7f0805cf

    .line 53
    .line 54
    .line 55
    return p0
.end method

.method public static final b(Lc00/x1;Lc00/v1;Z)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_4

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    if-eq p0, p1, :cond_2

    .line 9
    .line 10
    const/4 p1, 0x2

    .line 11
    if-ne p0, p1, :cond_1

    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    const p0, 0x7f0800b1

    .line 16
    .line 17
    .line 18
    return p0

    .line 19
    :cond_0
    const p0, 0x7f0800b0

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :cond_1
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_2
    if-eqz p2, :cond_3

    .line 30
    .line 31
    const p0, 0x7f0800b3

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :cond_3
    const p0, 0x7f0800b2

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :cond_4
    if-eqz p2, :cond_5

    .line 40
    .line 41
    const p0, 0x7f0800af

    .line 42
    .line 43
    .line 44
    return p0

    .line 45
    :cond_5
    const p0, 0x7f0800ae

    .line 46
    .line 47
    .line 48
    return p0
.end method

.method public static final c(Ljava/lang/Boolean;)Lc00/v1;
    .locals 1

    .line 1
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lc00/v1;->d:Lc00/v1;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    sget-object p0, Lc00/v1;->e:Lc00/v1;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    if-nez p0, :cond_2

    .line 24
    .line 25
    sget-object p0, Lc00/v1;->f:Lc00/v1;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_2
    new-instance p0, La8/r0;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public static final d(Lc00/x1;Lmb0/l;)Lc00/x1;
    .locals 12

    .line 1
    const-string v2, "originalSettings"

    .line 2
    .line 3
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p1, Lmb0/l;->a:Ljava/lang/Boolean;

    .line 7
    .line 8
    iget-object v3, p0, Lc00/x1;->a:Lc00/v1;

    .line 9
    .line 10
    invoke-static {v3}, Ljp/gc;->c(Lc00/v1;)Ljava/lang/Boolean;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x1

    .line 19
    const/4 v4, 0x0

    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    iget-object v2, p1, Lmb0/l;->b:Ljava/lang/Boolean;

    .line 23
    .line 24
    iget-object v5, p0, Lc00/x1;->b:Lc00/v1;

    .line 25
    .line 26
    invoke-static {v5}, Ljp/gc;->c(Lc00/v1;)Ljava/lang/Boolean;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-nez v2, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v2, v4

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    :goto_0
    move v2, v3

    .line 40
    :goto_1
    iget-object v5, p1, Lmb0/l;->c:Ljava/lang/Boolean;

    .line 41
    .line 42
    iget-object v6, p0, Lc00/x1;->c:Lc00/v1;

    .line 43
    .line 44
    const/4 v7, 0x0

    .line 45
    if-eqz v6, :cond_2

    .line 46
    .line 47
    invoke-static {v6}, Ljp/gc;->c(Lc00/v1;)Ljava/lang/Boolean;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move-object v6, v7

    .line 53
    :goto_2
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    if-eqz v5, :cond_5

    .line 58
    .line 59
    iget-object v1, p1, Lmb0/l;->d:Ljava/lang/Boolean;

    .line 60
    .line 61
    iget-object v5, p0, Lc00/x1;->d:Lc00/v1;

    .line 62
    .line 63
    if-eqz v5, :cond_3

    .line 64
    .line 65
    invoke-static {v5}, Ljp/gc;->c(Lc00/v1;)Ljava/lang/Boolean;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    :cond_3
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-nez v1, :cond_4

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_4
    move v1, v4

    .line 77
    goto :goto_4

    .line 78
    :cond_5
    :goto_3
    move v1, v3

    .line 79
    :goto_4
    if-nez v2, :cond_6

    .line 80
    .line 81
    if-eqz v1, :cond_7

    .line 82
    .line 83
    :cond_6
    iget-boolean v1, p0, Lc00/x1;->g:Z

    .line 84
    .line 85
    if-nez v1, :cond_7

    .line 86
    .line 87
    move v6, v3

    .line 88
    goto :goto_5

    .line 89
    :cond_7
    move v6, v4

    .line 90
    :goto_5
    const/4 v10, 0x0

    .line 91
    const/16 v11, 0x1df

    .line 92
    .line 93
    const/4 v1, 0x0

    .line 94
    const/4 v2, 0x0

    .line 95
    const/4 v3, 0x0

    .line 96
    const/4 v4, 0x0

    .line 97
    const/4 v5, 0x0

    .line 98
    const/4 v7, 0x0

    .line 99
    const-wide/16 v8, 0x0

    .line 100
    .line 101
    move-object v0, p0

    .line 102
    invoke-static/range {v0 .. v11}, Lc00/x1;->a(Lc00/x1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/v1;Lc00/w1;ZZJZI)Lc00/x1;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    return-object v0
.end method
