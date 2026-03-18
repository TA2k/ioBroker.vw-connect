.class public final Lv3/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt4/c;


# instance fields
.field public d:Z

.field public e:J

.field public f:J

.field public final synthetic g:Lv3/p0;


# direct methods
.method public constructor <init>(Lv3/p0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/m0;->g:Lv3/p0;

    .line 5
    .line 6
    const-wide v0, 0x7fffffff7fffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    iput-wide v0, p0, Lv3/m0;->e:J

    .line 12
    .line 13
    const-wide/16 v0, 0x0

    .line 14
    .line 15
    iput-wide v0, p0, Lv3/m0;->f:J

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/m0;->g:Lv3/p0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt4/c;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()Lt3/y;
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lv3/m0;->d:Z

    .line 3
    .line 4
    iget-object v0, p0, Lv3/m0;->g:Lv3/p0;

    .line 5
    .line 6
    invoke-virtual {v0}, Lv3/p0;->J0()Lt3/y;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-wide v2, p0, Lv3/m0;->e:J

    .line 11
    .line 12
    const-wide v4, 0x7fffffff7fffffffL

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    invoke-static {v2, v3, v4, v5}, Lt4/j;->b(JJ)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    const-wide/16 v2, 0x0

    .line 24
    .line 25
    invoke-interface {v1, v2, v3}, Lt3/y;->K(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide v2

    .line 29
    invoke-static {v2, v3}, Lkp/d9;->b(J)J

    .line 30
    .line 31
    .line 32
    move-result-wide v2

    .line 33
    iput-wide v2, p0, Lv3/m0;->e:J

    .line 34
    .line 35
    invoke-interface {v1}, Lt3/y;->h()J

    .line 36
    .line 37
    .line 38
    move-result-wide v2

    .line 39
    iput-wide v2, p0, Lv3/m0;->f:J

    .line 40
    .line 41
    :cond_0
    invoke-virtual {v0}, Lv3/p0;->M0()Lv3/h0;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 46
    .line 47
    invoke-virtual {p0}, Lv3/l0;->b()V

    .line 48
    .line 49
    .line 50
    return-object v1
.end method

.method public final c(Lt3/q;F)V
    .locals 5

    .line 1
    iget-object p0, p0, Lv3/m0;->g:Lv3/p0;

    .line 2
    .line 3
    iget-object v0, p0, Lv3/p0;->p:Lca/j;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Lca/j;

    .line 8
    .line 9
    invoke-direct {v0}, Lca/j;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lv3/p0;->p:Lca/j;

    .line 13
    .line 14
    :cond_0
    iget-object p0, v0, Lca/j;->b:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, [Lt3/q;

    .line 17
    .line 18
    invoke-static {p1, p0}, Lmx0/n;->D(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    const/4 v1, 0x1

    .line 23
    if-gez p0, :cond_2

    .line 24
    .line 25
    iget p0, v0, Lca/j;->a:I

    .line 26
    .line 27
    iget-object v2, v0, Lca/j;->b:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, [Lt3/q;

    .line 30
    .line 31
    array-length v3, v2

    .line 32
    if-ne p0, v3, :cond_1

    .line 33
    .line 34
    mul-int/lit8 v3, p0, 0x2

    .line 35
    .line 36
    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    const-string v4, "copyOf(...)"

    .line 41
    .line 42
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    check-cast v2, [Lt3/q;

    .line 46
    .line 47
    iput-object v2, v0, Lca/j;->b:Ljava/lang/Object;

    .line 48
    .line 49
    iget-object v2, v0, Lca/j;->c:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v2, [F

    .line 52
    .line 53
    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([FI)[F

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iput-object v2, v0, Lca/j;->c:Ljava/lang/Object;

    .line 61
    .line 62
    iget-object v2, v0, Lca/j;->d:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v2, [B

    .line 65
    .line 66
    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iput-object v2, v0, Lca/j;->d:Ljava/lang/Object;

    .line 74
    .line 75
    :cond_1
    iget-object v2, v0, Lca/j;->b:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v2, [Lt3/q;

    .line 78
    .line 79
    aput-object p1, v2, p0

    .line 80
    .line 81
    iget-object p1, v0, Lca/j;->d:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p1, [B

    .line 84
    .line 85
    const/4 v2, 0x3

    .line 86
    aput-byte v2, p1, p0

    .line 87
    .line 88
    iget-object p1, v0, Lca/j;->c:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p1, [F

    .line 91
    .line 92
    aput p2, p1, p0

    .line 93
    .line 94
    iget p0, v0, Lca/j;->a:I

    .line 95
    .line 96
    add-int/2addr p0, v1

    .line 97
    iput p0, v0, Lca/j;->a:I

    .line 98
    .line 99
    return-void

    .line 100
    :cond_2
    iget-object p1, v0, Lca/j;->c:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p1, [F

    .line 103
    .line 104
    aget v2, p1, p0

    .line 105
    .line 106
    cmpg-float v2, v2, p2

    .line 107
    .line 108
    if-nez v2, :cond_4

    .line 109
    .line 110
    iget-object p1, v0, Lca/j;->d:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast p1, [B

    .line 113
    .line 114
    aget-byte p2, p1, p0

    .line 115
    .line 116
    const/4 v0, 0x2

    .line 117
    if-ne p2, v0, :cond_3

    .line 118
    .line 119
    const/4 p2, 0x0

    .line 120
    aput-byte p2, p1, p0

    .line 121
    .line 122
    :cond_3
    return-void

    .line 123
    :cond_4
    aput p2, p1, p0

    .line 124
    .line 125
    iget-object p1, v0, Lca/j;->d:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p1, [B

    .line 128
    .line 129
    aput-byte v1, p1, p0

    .line 130
    .line 131
    return-void
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/m0;->g:Lv3/p0;

    .line 2
    .line 3
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
