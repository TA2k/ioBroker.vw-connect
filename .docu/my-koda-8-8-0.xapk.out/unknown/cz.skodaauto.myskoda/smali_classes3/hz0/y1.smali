.class public final Lhz0/y1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljz0/j;


# instance fields
.field public final a:Ljz0/a;

.field public final b:Ljava/lang/Integer;

.field public final c:Ljava/lang/Integer;

.field public final d:Ljava/lang/Integer;

.field public final e:Lhz0/g1;


# direct methods
.method public constructor <init>(Lhz0/g1;)V
    .locals 5

    .line 1
    sget-object v0, Lhz0/c2;->a:Ljz0/l;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v2

    .line 8
    sget-object v3, Lhz0/g1;->e:Lhz0/g1;

    .line 9
    .line 10
    if-ne p1, v3, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v1, 0x1

    .line 14
    :goto_0
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    sget-object v3, Lhz0/g1;->f:Lhz0/g1;

    .line 19
    .line 20
    if-ne p1, v3, :cond_1

    .line 21
    .line 22
    move-object v3, v2

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    const/4 v3, 0x0

    .line 25
    :goto_1
    const-string v4, "field"

    .line 26
    .line 27
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lhz0/y1;->a:Ljz0/a;

    .line 34
    .line 35
    iput-object v1, p0, Lhz0/y1;->b:Ljava/lang/Integer;

    .line 36
    .line 37
    iput-object v3, p0, Lhz0/y1;->c:Ljava/lang/Integer;

    .line 38
    .line 39
    iput-object v2, p0, Lhz0/y1;->d:Ljava/lang/Integer;

    .line 40
    .line 41
    iput-object p1, p0, Lhz0/y1;->e:Lhz0/g1;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final a()Lkz0/c;
    .locals 4

    .line 1
    new-instance v0, Lkz0/a;

    .line 2
    .line 3
    new-instance v1, Lio/ktor/utils/io/g0;

    .line 4
    .line 5
    iget-object v1, p0, Lhz0/y1;->a:Ljz0/a;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljz0/a;->a()Ljz0/r;

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lhz0/y1;->b:Ljava/lang/Integer;

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v1, 0x0

    .line 20
    :goto_0
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    const-string v2, "The minimum number of digits ("

    .line 24
    .line 25
    if-ltz v1, :cond_3

    .line 26
    .line 27
    const/16 v3, 0x9

    .line 28
    .line 29
    if-gt v1, v3, :cond_2

    .line 30
    .line 31
    iget-object p0, p0, Lhz0/y1;->c:Ljava/lang/Integer;

    .line 32
    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    new-instance p0, Lkz0/a;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_1
    return-object v0

    .line 42
    :cond_2
    const-string p0, ") exceeds the length of an Int"

    .line 43
    .line 44
    invoke-static {v2, v1, p0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_3
    const-string p0, ") is negative"

    .line 59
    .line 60
    invoke-static {v2, v1, p0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw v0
.end method

.method public final b()Llz0/n;
    .locals 12

    .line 1
    iget-object v0, p0, Lhz0/y1;->a:Ljz0/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljz0/a;->a()Ljz0/r;

    .line 4
    .line 5
    .line 6
    move-result-object v4

    .line 7
    invoke-virtual {v0}, Ljz0/a;->c()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v5

    .line 11
    const-string v0, "setter"

    .line 12
    .line 13
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "name"

    .line 17
    .line 18
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 v6, 0x1

    .line 22
    iget-object v1, p0, Lhz0/y1;->b:Ljava/lang/Integer;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    iget-object v3, p0, Lhz0/y1;->c:Ljava/lang/Integer;

    .line 26
    .line 27
    invoke-static/range {v1 .. v6}, Lz4/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)Llz0/n;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    move-object v7, v2

    .line 32
    filled-new-array {v0}, [Llz0/n;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-static {v0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    iget-object v2, p0, Lhz0/y1;->d:Ljava/lang/Integer;

    .line 41
    .line 42
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 43
    .line 44
    if-eqz v2, :cond_0

    .line 45
    .line 46
    const/4 v6, 0x0

    .line 47
    invoke-static/range {v1 .. v6}, Lz4/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)Llz0/n;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    new-instance v8, Llz0/n;

    .line 55
    .line 56
    new-instance v9, Llz0/o;

    .line 57
    .line 58
    const-string v1, "+"

    .line 59
    .line 60
    invoke-direct {v9, v1}, Llz0/o;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    new-instance v10, Llz0/g;

    .line 64
    .line 65
    new-instance v1, Llz0/u;

    .line 66
    .line 67
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    const/4 v11, 0x1

    .line 72
    add-int/2addr v2, v11

    .line 73
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    move-object v3, v7

    .line 78
    invoke-direct/range {v1 .. v6}, Llz0/u;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)V

    .line 79
    .line 80
    .line 81
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-direct {v10, v1}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 86
    .line 87
    .line 88
    const/4 v1, 0x2

    .line 89
    new-array v1, v1, [Llz0/m;

    .line 90
    .line 91
    const/4 v2, 0x0

    .line 92
    aput-object v9, v1, v2

    .line 93
    .line 94
    aput-object v10, v1, v11

    .line 95
    .line 96
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    invoke-direct {v8, v1, p0}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_0
    move-object v2, v7

    .line 108
    const/4 v6, 0x0

    .line 109
    invoke-static/range {v1 .. v6}, Lz4/a;->a(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)Llz0/n;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    :goto_0
    new-instance v1, Llz0/n;

    .line 117
    .line 118
    invoke-direct {v1, p0, v0}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 119
    .line 120
    .line 121
    return-object v1
.end method

.method public final c()Ljz0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/y1;->a:Ljz0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lhz0/y1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lhz0/y1;

    .line 6
    .line 7
    iget-object p1, p1, Lhz0/y1;->e:Lhz0/g1;

    .line 8
    .line 9
    iget-object p0, p0, Lhz0/y1;->e:Lhz0/g1;

    .line 10
    .line 11
    if-ne p0, p1, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Lhz0/y1;->e:Lhz0/g1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    mul-int/lit8 p0, p0, 0x1f

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    add-int/2addr v0, p0

    .line 15
    return v0
.end method
