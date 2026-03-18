.class public final Luz0/f0;
.super Luz0/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final m:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Luz0/c0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, p2, v0}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 3
    .line 4
    .line 5
    iput-boolean v0, p0, Luz0/f0;->m:Z

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Luz0/f0;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    goto/16 :goto_2

    .line 11
    .line 12
    :cond_1
    move-object v0, p1

    .line 13
    check-cast v0, Lsz0/g;

    .line 14
    .line 15
    invoke-interface {v0}, Lsz0/g;->h()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget-object v3, p0, Luz0/d1;->a:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-nez v2, :cond_2

    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_2
    check-cast p1, Luz0/f0;

    .line 29
    .line 30
    iget-boolean v2, p1, Luz0/f0;->m:Z

    .line 31
    .line 32
    if-eqz v2, :cond_7

    .line 33
    .line 34
    iget-object v2, p0, Luz0/d1;->k:Ljava/lang/Object;

    .line 35
    .line 36
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, [Lsz0/g;

    .line 41
    .line 42
    iget-object p1, p1, Luz0/d1;->k:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-interface {p1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    check-cast p1, [Lsz0/g;

    .line 49
    .line 50
    invoke-static {v2, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    if-eqz p1, :cond_7

    .line 55
    .line 56
    invoke-interface {v0}, Lsz0/g;->d()I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    iget v2, p0, Luz0/d1;->c:I

    .line 61
    .line 62
    if-eq v2, p1, :cond_3

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    move p1, v1

    .line 66
    :goto_0
    if-ge p1, v2, :cond_6

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Luz0/d1;->g(I)Lsz0/g;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    invoke-interface {v3}, Lsz0/g;->h()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    invoke-interface {v0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    invoke-interface {v4}, Lsz0/g;->h()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-nez v3, :cond_4

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_4
    invoke-virtual {p0, p1}, Luz0/d1;->g(I)Lsz0/g;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-interface {v3}, Lsz0/g;->getKind()Lkp/y8;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    invoke-interface {v0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-interface {v4}, Lsz0/g;->getKind()Lkp/y8;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    if-nez v3, :cond_5

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_5
    add-int/lit8 p1, p1, 0x1

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_6
    :goto_1
    const/4 p0, 0x1

    .line 118
    return p0

    .line 119
    :cond_7
    :goto_2
    return v1
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    invoke-super {p0}, Luz0/d1;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-int/lit8 p0, p0, 0x1f

    .line 6
    .line 7
    return p0
.end method

.method public final isInline()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Luz0/f0;->m:Z

    .line 2
    .line 3
    return p0
.end method
