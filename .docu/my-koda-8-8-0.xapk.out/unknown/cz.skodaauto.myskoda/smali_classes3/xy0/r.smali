.class public final Lxy0/r;
.super Laz0/q;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lxy0/j;

.field public final synthetic i:Ljava/util/concurrent/atomic/AtomicReferenceArray;


# direct methods
.method public constructor <init>(JLxy0/r;Lxy0/j;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3, p5}, Laz0/q;-><init>(JLaz0/q;I)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lxy0/r;->h:Lxy0/j;

    .line 5
    .line 6
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 7
    .line 8
    sget p2, Lxy0/l;->b:I

    .line 9
    .line 10
    mul-int/lit8 p2, p2, 0x2

    .line 11
    .line 12
    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final g()I
    .locals 0

    .line 1
    sget p0, Lxy0/l;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public final h(ILpx0/g;)V
    .locals 4

    .line 1
    sget p2, Lxy0/l;->b:I

    .line 2
    .line 3
    if-lt p1, p2, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    if-eqz v0, :cond_1

    .line 9
    .line 10
    sub-int/2addr p1, p2

    .line 11
    :cond_1
    mul-int/lit8 p2, p1, 0x2

    .line 12
    .line 13
    iget-object v1, p0, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 14
    .line 15
    invoke-virtual {v1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    :cond_2
    :goto_1
    invoke-virtual {p0, p1}, Lxy0/r;->l(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    instance-of v1, p2, Lvy0/k2;

    .line 23
    .line 24
    iget-object v2, p0, Lxy0/r;->h:Lxy0/j;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    if-nez v1, :cond_9

    .line 28
    .line 29
    instance-of v1, p2, Lxy0/b0;

    .line 30
    .line 31
    if-eqz v1, :cond_3

    .line 32
    .line 33
    goto :goto_3

    .line 34
    :cond_3
    sget-object v1, Lxy0/l;->j:Lj51/i;

    .line 35
    .line 36
    if-eq p2, v1, :cond_8

    .line 37
    .line 38
    sget-object v1, Lxy0/l;->k:Lj51/i;

    .line 39
    .line 40
    if-ne p2, v1, :cond_4

    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_4
    sget-object v1, Lxy0/l;->g:Lj51/i;

    .line 44
    .line 45
    if-eq p2, v1, :cond_2

    .line 46
    .line 47
    sget-object v1, Lxy0/l;->f:Lj51/i;

    .line 48
    .line 49
    if-ne p2, v1, :cond_5

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_5
    sget-object p0, Lxy0/l;->i:Lj51/i;

    .line 53
    .line 54
    if-eq p2, p0, :cond_b

    .line 55
    .line 56
    sget-object p0, Lxy0/l;->d:Lj51/i;

    .line 57
    .line 58
    if-ne p2, p0, :cond_6

    .line 59
    .line 60
    goto :goto_5

    .line 61
    :cond_6
    sget-object p0, Lxy0/l;->l:Lj51/i;

    .line 62
    .line 63
    if-ne p2, p0, :cond_7

    .line 64
    .line 65
    goto :goto_5

    .line 66
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    new-instance p1, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const-string v0, "unexpected state: "

    .line 71
    .line 72
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_8
    :goto_2
    invoke-virtual {p0, p1, v3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    if-eqz v0, :cond_b

    .line 94
    .line 95
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :cond_9
    :goto_3
    if-eqz v0, :cond_a

    .line 100
    .line 101
    sget-object v1, Lxy0/l;->j:Lj51/i;

    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_a
    sget-object v1, Lxy0/l;->k:Lj51/i;

    .line 105
    .line 106
    :goto_4
    invoke-virtual {p0, p1, p2, v1}, Lxy0/r;->k(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    if-eqz p2, :cond_2

    .line 111
    .line 112
    invoke-virtual {p0, p1, v3}, Lxy0/r;->n(ILjava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    xor-int/lit8 p2, v0, 0x1

    .line 116
    .line 117
    invoke-virtual {p0, p1, p2}, Lxy0/r;->m(IZ)V

    .line 118
    .line 119
    .line 120
    if-eqz v0, :cond_b

    .line 121
    .line 122
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_b
    :goto_5
    return-void
.end method

.method public final k(ILjava/lang/Object;Ljava/lang/Object;)Z
    .locals 3

    .line 1
    mul-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    add-int/2addr p1, v0

    .line 5
    :cond_0
    iget-object v1, p0, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 6
    .line 7
    invoke-virtual {v1, p1, p2, p3}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->compareAndSet(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    return v0

    .line 14
    :cond_1
    invoke-virtual {v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    if-eq v1, p2, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final l(I)Ljava/lang/Object;
    .locals 0

    .line 1
    mul-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    add-int/lit8 p1, p1, 0x1

    .line 4
    .line 5
    iget-object p0, p0, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final m(IZ)V
    .locals 4

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    iget-object p2, p0, Lxy0/r;->h:Lxy0/j;

    .line 4
    .line 5
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sget v0, Lxy0/l;->b:I

    .line 9
    .line 10
    int-to-long v0, v0

    .line 11
    iget-wide v2, p0, Laz0/q;->f:J

    .line 12
    .line 13
    mul-long/2addr v2, v0

    .line 14
    int-to-long v0, p1

    .line 15
    add-long/2addr v2, v0

    .line 16
    invoke-virtual {p2, v2, v3}, Lxy0/j;->N(J)V

    .line 17
    .line 18
    .line 19
    :cond_0
    invoke-virtual {p0}, Laz0/q;->i()V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final n(ILjava/lang/Object;)V
    .locals 0

    .line 1
    mul-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final o(ILjava/lang/Object;)V
    .locals 0

    .line 1
    mul-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    add-int/lit8 p1, p1, 0x1

    .line 4
    .line 5
    iget-object p0, p0, Lxy0/r;->i:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 6
    .line 7
    invoke-virtual {p0, p1, p2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
